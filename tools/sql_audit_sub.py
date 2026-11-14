#!/usr/bin/env python3
"""sql_audit subscriber tool — NATS side of the sql_audit extension.

Features:
  * subscribes to <subject> (records) and <subject>.anchor (chain-head anchors)
  * SQLASEG1 frame reassembly (segmented oversize messages), with a 5s
    incompleteness timeout — dangling partial groups are reported (L9)
  * optional HMAC re-verification of every record against the chain key
    (--keyfile, same file the writer uses) — independent tamper check
  * --reconcile <audit_dir>: compares the highest seq RECEIVED against the
    highest seq ON DISK locally — detects tail loss the writer could not
    detect itself (power-loss torn writes self-heal locally; the gap only
    shows up cross-end, L2)

Usage:
  python3 sql_audit_sub.py --url nats://localhost:4222 --subject sqlaudit \
      [--keyfile /secure/audit.key] [--reconcile /root/.duckdb/sql_audit] \
      [--duration 10] [--out received.jsonl]
"""
import argparse
import hashlib
import hmac as hmac_mod
import json
import os
import socket
import struct
import sys
import time

SEG_MAGIC = b"SQLASEG1"


class NatsSubscriber:
    def __init__(self, url, subject):
        host_port = url.replace("nats://", "")
        if ":" not in host_port:
            host_port += ":4222"
        self.sock = socket.create_connection(tuple(host_port.rsplit(":", 1)), timeout=5)
        self.buf = b""
        self._read_line()  # INFO
        self.sock.sendall(b'CONNECT {"verbose":false}\r\nSUB ' + subject.encode()
                          + b' 1\r\nSUB ' + subject.encode() + b'.anchor 2\r\nPING\r\n')
        while True:
            line = self._read_line(block_timeout=5.0)
            if line is None or "PONG" in line:
                break

    def _recv(self, block_timeout):
        """recv with timeout; returns bytes (b'' on EOF/timeout-ish)."""
        self.sock.settimeout(block_timeout)
        try:
            return self.sock.recv(65536)
        except socket.timeout:
            return None
        except OSError:
            return b""

    def _read_line(self, block_timeout=0.5):
        while b"\n" not in self.buf:
            data = self._recv(block_timeout)
            if data is None:
                return None  # timed out
            if data == b"":
                return ""    # EOF
            self.buf += data
        nl = self.buf.find(b"\n")
        line = self.buf[:nl].rstrip(b"\r").decode(errors="replace")
        self.buf = self.buf[nl + 1:]
        return line

    def _read_payload(self, size, block_timeout=0.5):
        need = size + 2  # payload + CRLF
        while len(self.buf) < need:
            data = self._recv(block_timeout)
            if data is None or data == b"":
                return None
            self.buf += data
        payload = self.buf[:size]
        self.buf = self.buf[need:]
        return payload

    def messages(self, deadline):
        """Yield (is_anchor, payload bytes) until the deadline."""
        while time.time() < deadline:
            line = self._read_line(block_timeout=0.5)
            if line is None:
                continue  # poll deadline
            if line == "":
                break     # EOF
            line = line.strip()
            if line.startswith("MSG "):
                parts = line.split()
                size = int(parts[3])
                payload = self._read_payload(size, block_timeout=2.0)
                if payload is None:
                    break
                yield parts[1].endswith(".anchor"), payload
            # INFO / PING / PONG / +OK / -ERR: ignored


class SegReassembler:
    """Groups SQLASEG1 frames by stream id; reports incomplete groups."""

    def __init__(self, timeout_s=5.0):
        self.groups = {}   # sid -> {"frames": {idx: bytes}, "total": n, "first_seen": t}
        self.timeout_s = timeout_s

    def feed(self, payload):
        """Returns reassembled bytes when a group completes, else None."""
        if payload[:8] != SEG_MAGIC:
            return None  # not a segment frame
        sid, idx, total = struct.unpack(">IHH", payload[8:16])
        g = self.groups.setdefault(sid, {"frames": {}, "total": total, "first_seen": time.time()})
        g["frames"][idx] = payload[16:]
        if len(g["frames"]) == g["total"]:
            del self.groups[sid]
            return b"".join(g["frames"][i] for i in range(1, g["total"] + 1))
        return None

    def sweep(self):
        """Drop groups older than the timeout; return them as (sid, total, got)."""
        now = time.time()
        stale = [sid for sid, g in self.groups.items()
                 if now - g["first_seen"] > self.timeout_s]
        out = [(sid, self.groups[sid]["total"], len(self.groups[sid]["frames"]))
               for sid in stale]
        for sid in stale:
            del self.groups[sid]
        return out


def load_key(path):
    data = open(path, "rb").read()
    if len(data) < 32:
        raise SystemExit("key file too short (min 32 bytes): %s" % path)
    return data


def verify_record_hmac(rec, key):
    """v5 canonical: seq|ts|record_type|principal|verdict|hash_field|prev_hash"""
    rt = rec.get("record_type")
    if rt == "CONN":
        hf = rec.get("token_fp", "")
    elif rt == "SYS":
        hf = rec.get("detail_sha256", "")
    else:
        hf = rec.get("query_sha256", "")
    canon = "%s|%s|%s|%s|%s|%s|%s" % (
        rec.get("seq"), rec.get("ts_ms"), rt, rec.get("principal", ""),
        rec.get("verdict", ""), hf, rec.get("prev_hash", ""))
    expect = hmac_mod.new(key, canon.encode(), hashlib.sha256).hexdigest()
    if expect != rec.get("entry_hmac"):
        return False
    if rt == "STMT":
        return hashlib.sha256(rec.get("query", "").encode()).hexdigest() == hf
    if rt == "SYS":
        return hashlib.sha256(rec.get("detail", "").encode()).hexdigest() == hf
    return True


def disk_max_seq(audit_dir):
    mx, n = 0, 0
    if not os.path.isdir(audit_dir):
        return mx, n
    for fn in sorted(os.listdir(audit_dir)):
        if fn.endswith(".jsonl"):
            for line in open(os.path.join(audit_dir, fn), encoding="utf-8", errors="replace"):
                if not line.strip():
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                n += 1
                mx = max(mx, r.get("seq", 0))
    return mx, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="nats://localhost:4222")
    ap.add_argument("--subject", default="sqlaudit")
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--keyfile")
    ap.add_argument("--reconcile")
    ap.add_argument("--out")
    args = ap.parse_args()

    key = load_key(args.keyfile) if args.keyfile else None
    sub = NatsSubscriber(args.url, args.subject)
    seg = SegReassembler()

    stats = {"records": 0, "anchors": 0, "seg_frames": 0, "seg_complete": 0,
             "hmac_ok": 0, "hmac_bad": 0, "incomplete_groups": []}
    max_seq = 0
    max_anchor = None
    out_fp = open(args.out, "a", encoding="utf-8") if args.out else None
    deadline = time.time() + args.duration
    next_sweep = time.time() + 1.0

    for is_anchor, payload in sub.messages(deadline):
        if payload[:8] == SEG_MAGIC:
            stats["seg_frames"] += 1
            data = seg.feed(payload)
            if data is None:
                continue  # waiting for the remaining frames of this group
            stats["seg_complete"] += 1
        else:
            data = payload  # normal single message
        if is_anchor:
            stats["anchors"] += 1
            try:
                a = json.loads(data)
                if max_anchor is None or a.get("seq", 0) > max_anchor.get("seq", 0):
                    max_anchor = a
            except Exception:
                pass
            continue
        try:
            rec = json.loads(data)
        except Exception:
            print("[sub] non-JSON payload (%d B) on record subject" % len(data), file=sys.stderr)
            continue
        stats["records"] += 1
        max_seq = max(max_seq, rec.get("seq", 0))
        if key is not None:
            if verify_record_hmac(rec, key):
                stats["hmac_ok"] += 1
            else:
                stats["hmac_bad"] += 1
                print("[sub] HMAC MISMATCH at seq=%s" % rec.get("seq"), file=sys.stderr)
        if out_fp:
            out_fp.write(json.dumps(rec) + "\n")

        if time.time() > next_sweep:
            for sid, total, got in seg.sweep():
                stats["incomplete_groups"].append({"sid": sid, "total": total, "got": got})
                print("[sub] INCOMPLETE segmented group sid=%s %d/%d frames "
                      "(missing frames are lost with the connection)" % (sid, got, total),
                      file=sys.stderr)
            next_sweep = time.time() + 1.0

    for sid, total, got in seg.sweep():
        stats["incomplete_groups"].append({"sid": sid, "total": total, "got": got})
        print("[sub] INCOMPLETE segmented group sid=%s %d/%d frames "
              "(missing frames are lost with the connection)" % (sid, got, total),
              file=sys.stderr)
    if out_fp:
        out_fp.close()

    print(json.dumps({
        "records": stats["records"],
        "max_seq_received": max_seq,
        "anchors": stats["anchors"],
        "max_anchor": max_anchor,
        "seg_frames": stats["seg_frames"],
        "seg_complete": stats["seg_complete"],
        "hmac_ok": stats["hmac_ok"],
        "hmac_bad": stats["hmac_bad"],
        "incomplete_groups": stats["incomplete_groups"],
    }, indent=2))

    if args.reconcile:
        dmx, dn = disk_max_seq(args.reconcile)
        gap = dmx - max_seq
        print(json.dumps({
            "reconcile_dir": args.reconcile,
            "disk_max_seq": dmx, "disk_records": dn,
            "received_max_seq": max_seq,
            "gap_disk_minus_received": gap,
            "verdict": ("OK: subscriber saw everything on disk"
                        if gap == 0 else
                        "TAIL LOSS: %d record(s) on disk never reached the subscriber"
                        % gap if gap > 0 else
                        "subscriber is AHEAD of disk by %d (writer flush lag or "
                        "dir mismatch)" % (-gap)),
        }, indent=2))
        sys.exit(0 if gap == 0 else 2)


if __name__ == "__main__":
    main()
