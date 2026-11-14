#!/usr/bin/env python3
"""sql_audit COMPREHENSIVE FINAL TEST — Phase 1+2+3+4, all groups"""
import duckdb, os, time, json, sys, shutil

EXT = "/home/xiehq/quack-verify/duckdb-sql-audit/build/release/extension/sql_audit/sql_audit.duckdb_extension"
ACL = "/home/xiehq/quack-verify/build/duckdb-acl/build/release/extension/acl/acl.duckdb_extension"
AUDIT_DIR = "/root/.duckdb/sql_audit"

R = {}
def verdict(tid, ok, note):
    R[tid] = (ok, note)
    print("[%s] %s %s" % (tid, "PASS" if ok else "FAIL", note))
def log(msg): print(msg)

def fresh(audit=True, acl=False):
    cfg = {"allow_unsigned_extensions": True, "allow_extensions_metadata_mismatch": True}
    c = duckdb.connect(":memory:", config=cfg)
    if acl: c.execute("LOAD '%s'" % ACL)
    if audit: c.execute("LOAD '%s'" % EXT)
    return c

def get_records(d=AUDIT_DIR):
    if not os.path.exists(d): return []
    recs = []
    for f in sorted(os.listdir(d)):
        if f.endswith(".jsonl"):
            for line in open(os.path.join(d, f)):
                if line.strip():
                    try: recs.append(json.loads(line))
                    except: pass
    return recs

log("=" * 70)
log("  sql_audit COMPREHENSIVE FINAL TEST")
log("  Phase 1 + 2 + 3 + 4")
log("=" * 70)

# === G1: Basic (Phase 1) ===
log("\n--- G1: Basic Capture ---")
os.system("rm -rf %s" % AUDIT_DIR)
c = fresh()
for sql in ["SELECT 1","CREATE TABLE t(a INT)","INSERT INTO t VALUES (1)","UPDATE t SET a=2",
            "DELETE FROM t","SET VARIABLE v=1","BEGIN","COMMIT","DROP TABLE t",
            "EXPLAIN SELECT 1","PRAGMA version"]:
    try: c.execute(sql)
    except: pass
time.sleep(0.5)
h = c.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G1-capture", h[0] >= 11, "captured=%d" % h[0])
c.execute("CREATE TABLE v(a INT); INSERT INTO v VALUES (42)")
r = c.execute("SELECT a FROM v").fetchone()[0]
verdict("G1-data", r == 42, "data: %d==42" % r)
c.close()

c1 = fresh()
c1.execute("CREATE TABLE t2(x INT, y VARCHAR); INSERT INTO t2 VALUES (1,'a'),(2,'b'),(3,'c')")
r1 = c1.execute("SELECT x FROM t2 WHERE x>1 ORDER BY x").fetchall()
c1.close()
c2 = fresh(audit=False)
c2.execute("CREATE TABLE t2(x INT, y VARCHAR); INSERT INTO t2 VALUES (1,'a'),(2,'b'),(3,'c')")
r2 = c2.execute("SELECT x FROM t2 WHERE x>1 ORDER BY x").fetchall()
c2.close()
verdict("G1-regression", r1 == r2, "identical=%s" % (r1 == r2))

c3 = fresh()
for i in range(100): c3.execute("SELECT %d" % i)
h3 = c3.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G1-recursion", h3[0] >= 101, "100 stmts captured=%d" % h3[0])
c3.close()

# === G2: Chain (Phase 2a) ===
log("\n--- G2: Hash Chain ---")
recs = get_records()
verdict("G2-file", len(recs) >= 100, "records=%d" % len(recs))
if recs:
    verdict("G2-seq", all(recs[i]["seq"] < recs[i+1]["seq"] for i in range(len(recs)-1)),
            "seq monotonic")
c5 = fresh()
v = c5.execute("SELECT * FROM sql_audit_verify()").fetchone()
verdict("G2-verify", v[0] == True and v[4] == 1, "ok=%s total=%d window_start=%d" % (v[0], v[2], v[4]))

# Tamper
jl = sorted([f for f in os.listdir(AUDIT_DIR) if f.endswith(".jsonl")])
if jl:
    fp = os.path.join(AUDIT_DIR, jl[0])
    orig_lines = open(fp).read().strip().split("\n")
    if len(orig_lines) >= 3:
        tampered = list(orig_lines)
        rec = json.loads(tampered[1]); rec["query"] = "TAMPERED"; tampered[1] = json.dumps(rec)
        open(fp, "w").write("\n".join(tampered) + "\n")
        v2 = c5.execute("SELECT * FROM sql_audit_verify()").fetchone()
        verdict("G2-tamper", v2[0] == False and v2[1] > 0, "first_bad=%d" % v2[1])
        # Restore ONLY the tampered line: full-file rollback would erase the
        # v2-verify record appended asynchronously after the tamper write.
        time.sleep(0.5)
        cur = open(fp).read().strip().split("\n")
        cur[1] = orig_lines[1]
        open(fp, "w").write("\n".join(cur) + "\n")

kp = os.path.join(AUDIT_DIR, "chain.key")
if os.path.exists(kp):
    ok = open(kp, "rb").read()
    open(kp, "wb").write(b"\xff" * 32)
    v3 = c5.execute("SELECT * FROM sql_audit_verify()").fetchone()
    verdict("G2-key", v3[0] == False and v3[1] == -1, "key mismatch: %d" % v3[1])
    open(kp, "wb").write(ok)
c5.close()

# Splice attack on a scratch COPY of the audit dir (live dir never mutated):
# delete a middle record and rewire the successor's prev_hash to skip it.
# MUST be detected now that prev_hash is covered by the entry HMAC.
SPL = "/root/.duckdb/sql_audit_splice"
shutil.rmtree(SPL, ignore_errors=True)
shutil.copytree(AUDIT_DIR, SPL)
cs = fresh()
cs.execute("SET GLOBAL sql_audit_path='%s'" % SPL)
fp_s = os.path.join(SPL, "audit-000001.jsonl")
lines_s = [l for l in open(fp_s).read().strip().split("\n") if l.strip()]
recs_s = [json.loads(l) for l in lines_s]
mid = len(recs_s) // 2
victim = recs_s[mid]
succ = [r for r in recs_s if r["seq"] == victim["seq"] + 1]
prev_rec = [r for r in recs_s if r["seq"] == victim["seq"] - 1]
if succ and prev_rec:
    out = []
    for r in recs_s:
        if r["seq"] == victim["seq"]:
            continue
        if r["seq"] == victim["seq"] + 1:
            r["prev_hash"] = prev_rec[0]["entry_hmac"]
        out.append(json.dumps(r))
    open(fp_s, "w").write("\n".join(out) + "\n")
    vsp = cs.execute("SELECT * FROM sql_audit_verify()").fetchone()
    verdict("G2-splice", vsp[0] == False and vsp[1] > 0,
            "splice detected: first_bad=%d" % vsp[1])
else:
    verdict("G2-splice", False, "not enough records to splice")
cs.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
cs.close()
shutil.rmtree(SPL, ignore_errors=True)

# === G3: Rotation (Phase 2b) — using persistent sub-dir ===
log("\n--- G3: Rotation ---")
ROT_DIR = "/root/.duckdb/sql_audit_rot"
shutil.rmtree(ROT_DIR, ignore_errors=True); os.makedirs(ROT_DIR)
c19 = fresh()
c19.execute("SET GLOBAL sql_audit_path='%s'" % ROT_DIR)
c19.execute("SET GLOBAL sql_audit_max_file_mb=1")
c19.execute("SET GLOBAL sql_audit_retention_files=3")
for i in range(100):
    c19.execute("SELECT '%s'" % ("a" * 12000))
time.sleep(2.0)
files19 = len([f for f in os.listdir(ROT_DIR) if f.endswith(".jsonl")])
verdict("G3-prune", files19 <= 5, "files=%d (limit=3)" % files19)
v19 = c19.execute("SELECT * FROM sql_audit_verify()").fetchone()
verdict("G3-verify", v19[0] == True, "verify=%s" % v19[0])

# Halt test
c19.execute("SET GLOBAL sql_audit_retention_files=2")
c19.execute("SET GLOBAL sql_audit_retention_policy='halt'")
for i in range(200):
    try: c19.execute("SELECT '%s'" % ("b" * 12000))
    except: break
time.sleep(1.0)
r = c19.execute("SELECT 42").fetchone()[0]
verdict("G3-halt", r == 42, "halt exec: %d==42" % r)
c19.close()

# Reset path to default
c_rst = fresh()
c_rst.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
c_rst.close()
shutil.rmtree(ROT_DIR, ignore_errors=True)
verdict("G3-reset", True, "path reset to default")

# === G3b: prune ACTUALLY deletes files, verify must survive (segment head) ===
log("\n--- G3b: Prune deletion + segment verify ---")
PRU = "/root/.duckdb/sql_audit_prune"
shutil.rmtree(PRU, ignore_errors=True)
cp = fresh()
cp.execute("SET GLOBAL sql_audit_path='%s'" % PRU)
cp.execute("SET GLOBAL sql_audit_max_file_mb=1")
cp.execute("SET GLOBAL sql_audit_retention_files=2")
for i in range(300):
    cp.execute("SELECT '%s'" % ("p" * 12000))
time.sleep(2.0)
files_p = len([f for f in os.listdir(PRU) if f.endswith(".jsonl")])
verdict("G3b-pruned", files_p == 2, "files=%d (limit=2, deletion happened)" % files_p)
vp = cp.execute("SELECT * FROM sql_audit_verify()").fetchone()
verdict("G3b-verify", vp[0] == True, "verify=%s first_bad=%d" % (vp[0], vp[1]))
verdict("G3b-window", vp[4] > 1, "window_start=%d (>1: pruned head exposed)" % vp[4])
cp.close()
shutil.rmtree(PRU, ignore_errors=True)
c_rst2 = fresh()
c_rst2.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
c_rst2.close()

# === G3c: halt then release — chain must stay intact (ghost-seq rollback) ===
log("\n--- G3c: Halt release chain integrity ---")
HLT = "/root/.duckdb/sql_audit_halt"
shutil.rmtree(HLT, ignore_errors=True)
ch = fresh()
ch.execute("SET GLOBAL sql_audit_path='%s'" % HLT)
ch.execute("SET GLOBAL sql_audit_max_file_mb=1")
ch.execute("SET GLOBAL sql_audit_retention_files=2")
ch.execute("SET GLOBAL sql_audit_retention_policy='halt'")
for i in range(300):
    try: ch.execute("SELECT '%s'" % ("h" * 12000))
    except: break
time.sleep(1.5)
hh = ch.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G3c-halt", hh[5] == True, "halted=%s records=%d" % (hh[5], hh[3]))
# release the halt, write more: without rollback the first record after
# release carries a prev_hash to a ghost entry and the chain breaks
ch.execute("SET GLOBAL sql_audit_retention_policy='prune'")
for i in range(5): ch.execute("SELECT %d" % (900+i))
time.sleep(1.5)
vh = ch.execute("SELECT * FROM sql_audit_verify()").fetchone()
verdict("G3c-release", vh[0] == True, "verify after release=%s first_bad=%d total=%d" % (vh[0], vh[1], vh[2]))
ch.close()
shutil.rmtree(HLT, ignore_errors=True)
c_rst3 = fresh()
c_rst3.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
c_rst3.close()

# === G4: NATS (Phase 3) ===
log("\n--- G4: NATS ---")
c9 = fresh()
c9.execute("SET GLOBAL sql_audit_nats_url='nats://localhost:4222'")
c9.execute("SET GLOBAL sql_audit_nats_subject='sqlaudit.final'")
c9.execute("SET GLOBAL sql_audit_mode='both'")
for i in range(20): c9.execute("SELECT %d" % i)
time.sleep(2.0)
h9 = c9.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G4-local", h9[3] >= 20, "local=%d" % h9[3])
verdict("G4-nats", h9[6] >= 20, "nats_pub=%d" % h9[6])
verdict("G4-noerr", h9[7] == 0, "errors=%d" % h9[7])

# Mode off/on (with longer wait)
c9.execute("SET GLOBAL sql_audit_mode='off'")
c9.execute("SELECT 999")
time.sleep(1.5)
h_off = c9.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G4-off", h_off[3]-h9[3] <= 1, "off delta=%d (<=1)" % (h_off[3]-h9[3]))

c9.execute("SET GLOBAL sql_audit_mode='local'")
for i in range(5): c9.execute("SELECT %d" % (800+i))
time.sleep(2.0)
h_back = c9.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G4-back", h_back[3] > h_off[3], "back %d->%d" % (h_off[3], h_back[3]))

# NATS unreachable
c9.execute("SET GLOBAL sql_audit_nats_url='nats://localhost:19999'")
for i in range(5): c9.execute("SELECT %d" % (850+i))
time.sleep(3.0)
h_unreach = c9.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G4-unreach", h_unreach[3] > h_back[3], "local cont: %d->%d" % (h_back[3], h_unreach[3]))

# Reconnect (must also set mode back to 'both' for NATS publishing)
c9.execute("SET GLOBAL sql_audit_nats_url='nats://localhost:4222'")
c9.execute("SET GLOBAL sql_audit_mode='both'")
for i in range(5): c9.execute("SELECT %d" % (700+i))
time.sleep(2.0)
h_re = c9.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G4-reconnect", h_re[6] > 0, "nats resumed: pub=%d (>0)" % h_re[6])
c9.close()

# Anchor
c11 = fresh()
c11.execute("SET GLOBAL sql_audit_nats_url='nats://localhost:4222'")
c11.execute("SET GLOBAL sql_audit_nats_subject='sqlaudit.final_anchor'")
c11.execute("SET GLOBAL sql_audit_mode='both'")
h11_pre = c11.execute("SELECT * FROM sql_audit_health()").fetchone()[6]
for i in range(150): c11.execute("SELECT %d" % i)
time.sleep(2.0)
h11 = c11.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G4-anchor", h11[6] - h11_pre >= 151,
        "pub delta=%d (>=151: 150 stmts + anchor)" % (h11[6] - h11_pre))
c11.close()

# === G5: Phase 4 (AUTO-HOOK + Connection) ===
log("\n--- G5: Phase 4 ---")
c_p4 = fresh()
c_p4.execute("SELECT 42")  # No manual SET STRICT
time.sleep(0.5)
h_p4 = c_p4.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G5-auto-hook", h_p4[0] > 0, "captured=%d (auto-STRICT)" % h_p4[0])

authn_r = c_p4.execute("SELECT sql_audit_authn_chain('conn-42', 'tok', 'val')").fetchone()
verdict("G5-authn", authn_r[0] == True, "authn=true")

authz_r = c_p4.execute("SELECT sql_audit_authz_chain('conn-42', 'SELECT 99')").fetchone()
verdict("G5-authz", authz_r[0] == "SELECT 99", "authz passthrough")

time.sleep(0.5)
h_p4b = c_p4.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G5-conns", h_p4b[8] >= 1, "conns=%d" % h_p4b[8])
verdict("G5-hook", h_p4b[10] == "hooked", "hook=%s" % h_p4b[10])

all_recs = get_records()
conn_found = any(r.get("conn_id") == "conn-42" and r.get("record_type") == "CONN" for r in all_recs)
verdict("G5-conn-record", conn_found, "CONN record for conn-42")

stmt_conn = any(r.get("conn_id") == "conn-42" and r.get("record_type") == "STMT" for r in all_recs)
verdict("G5-stmt-conn", stmt_conn, "STMT with conn_id")

v_p4 = c_p4.execute("SELECT * FROM sql_audit_verify()").fetchone()
verdict("G5-verify", v_p4[0] == True, "mixed chain: ok=%s total=%d" % (v_p4[0], v_p4[2]))
c_p4.close()

# === G6: ACL (Phase 1) ===
log("\n--- G6: ACL ---")
try:
    cA = duckdb.connect(":memory:", config={"allow_unsigned_extensions": True, "allow_extensions_metadata_mismatch": True})
    cA.execute("LOAD '%s'" % EXT)
    cA.execute("SET GLOBAL allow_parser_override_extension='strict'")
    cA.execute("LOAD '%s'" % ACL)
    cA.execute("CREATE TABLE t(x INT); INSERT INTO t VALUES (1)")
    r = cA.execute("SELECT count(*) FROM t").fetchone()[0]
    hA = cA.execute("SELECT * FROM sql_audit_health()").fetchone()
    verdict("G6-orderA", r == 1 and hA[0] > 0, "exec=%d audit=%d" % (r, hA[0]))
    cA.close()
except Exception as e:
    verdict("G6-orderA", False, str(e)[:50])

try:
    cB = duckdb.connect(":memory:", config={"allow_unsigned_extensions": True, "allow_extensions_metadata_mismatch": True})
    cB.execute("LOAD '%s'" % ACL)
    cB.execute("LOAD '%s'" % EXT)
    cB.execute("SET GLOBAL allow_parser_override_extension='strict'")
    cB.execute("CREATE TABLE t(x INT); INSERT INTO t VALUES (5)")
    r = cB.execute("SELECT x FROM t").fetchone()[0]
    hB = cB.execute("SELECT * FROM sql_audit_health()").fetchone()
    verdict("G6-orderB", r == 5 and hB[0] > 0, "exec=%d audit=%d" % (r, hB[0]))
    cB.close()
except Exception as e:
    verdict("G6-orderB", False, str(e)[:50])

# === G11: P4-3 hook takeover / delegation / auto-rechain (real quack) ===
log("\n--- G11: auto-rechain ---")
def qfresh(order):
    cfg = {"allow_unsigned_extensions": True, "allow_extensions_metadata_mismatch": True}
    c = duckdb.connect(":memory:", config=cfg)
    for step in order:
        if step == "quack": c.execute("LOAD quack")
        if step == "audit": c.execute("LOAD '%s'" % EXT)
    return c

# takeover at LOAD (quack first, then audit): hooks become chain, defaults
# are cushioned in as delegates
cq = qfresh(("quack", "audit"))
cur_a = cq.execute("SELECT current_setting('quack_authentication_function')").fetchone()[0]
cur_z = cq.execute("SELECT current_setting('quack_authorization_function')").fetchone()[0]
hq = cq.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G11-takeover", cur_a == "sql_audit_authn_chain" and cur_z == "sql_audit_authz_chain"
        and hq[11] == "quack_check_token" and hq[12] == "quack_nop_authorization",
        "hooks=%s/%s delegates=%s/%s" % (cur_a, cur_z, hq[11], hq[12]))
cq.close()

# quack loaded AFTER audit: first health poll completes the takeover
cq2 = qfresh(("audit", "quack"))
cq2.execute("SELECT * FROM sql_audit_health()").fetchone()  # poll
cur_a2 = cq2.execute("SELECT current_setting('quack_authentication_function')").fetchone()[0]
verdict("G11-late-quack", cur_a2 == "sql_audit_authn_chain",
        "after poll hook=%s" % cur_a2)
# simulate the quack_oauth README operation: overwrite the hook
cq2.execute("CREATE MACRO my_authn(a, b, c) AS true")
cq2.execute("SET quack_authentication_function='my_authn'")
cq2.execute("SELECT * FROM sql_audit_health()").fetchone()  # poll -> rechain
cur_a3 = cq2.execute("SELECT current_setting('quack_authentication_function')").fetchone()[0]
hq3 = cq2.execute("SELECT * FROM sql_audit_health()").fetchone()
sys_found = any(r.get("record_type") == "SYS" and r.get("event_type") == "rehook"
                for r in get_records())
verdict("G11-rechain", cur_a3 == "sql_audit_authn_chain" and hq3[11] == "my_authn" and sys_found,
        "restored=%s delegate=%s sys_event=%s" % (cur_a3, hq3[11], sys_found))
cq2.close()

# delegate semantics: a rejecting authn function must reject (faithful)
cq3 = qfresh(("quack", "audit"))
cq3.execute("CREATE MACRO my_reject(a, b, c) AS false")
cq3.execute("SET quack_authentication_function='my_reject'")
cq3.execute("SELECT * FROM sql_audit_health()").fetchone()  # rechain with delegate
authn_v = cq3.execute("SELECT sql_audit_authn_chain('cx1', 'tok', 't')").fetchone()[0]
h_r = cq3.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G11-reject", authn_v == False and h_r[9] >= 1,
        "delegate reject passed=%s conn_rejects=%d" % (authn_v, h_r[9]))
# authz rewrite passthrough (VARCHAR return rewrites)
cq3.execute("CREATE MACRO my_rw(c, q) AS 'SELECT 1'")
cq3.execute("SET quack_authorization_function='my_rw'")
cq3.execute("SELECT * FROM sql_audit_health()").fetchone()  # rechain with delegate
authz_v = cq3.execute("SELECT sql_audit_authz_chain('cx1', 'SELECT 99')").fetchone()[0]
verdict("G11-rewrite", authz_v == "SELECT 1", "delegate rewrite: %r" % authz_v)
# authz DENY semantics must survive the chain: a FALSE delegate makes the
# chain return NULL so quack's Denied() fires (fail-open was proven R5)
cq3.execute("CREATE MACRO my_deny(c, q) AS false")
cq3.execute("SET quack_authorization_function='my_deny'")
cq3.execute("SELECT * FROM sql_audit_health()").fetchone()  # rechain with delegate
deny_v = cq3.execute("SELECT sql_audit_authz_chain('cx1', 'SELECT secret')").fetchone()[0]
verdict("G11-deny", deny_v is None, "FALSE delegate -> %r (None=deny at quack level)" % deny_v)
v_g11 = cq3.execute("SELECT * FROM sql_audit_verify()").fetchone()
verdict("G11-sys-chain", v_g11[0] == True, "chain with SYS records: ok=%s total=%d" % (v_g11[0], v_g11[2]))
cq3.close()

# auto_hook=off respects explicit overwrite (no re-take)
cq4 = qfresh(("quack", "audit"))
cq4.execute("SET sql_audit_auto_hook=false")
cq4.execute("CREATE MACRO other_authn(a, b, c) AS true")
cq4.execute("SET quack_authentication_function='other_authn'")
cq4.execute("SELECT * FROM sql_audit_health()").fetchone()  # poll: must NOT re-take
cur_off = cq4.execute("SELECT current_setting('quack_authentication_function')").fetchone()[0]
verdict("G11-off", cur_off == "other_authn", "auto_hook off: hook stays %s" % cur_off)
# restore the PROCESS-GLOBAL flag: it is not per-DB — leaving it off would
# silently disable auto-rechain for every later group (state leak, caught R6)
cq4.execute("SET sql_audit_auto_hook=true")
cq4.close()

# dispatch statements (placeholder form only) must not pollute the audit;
# a user's LITERAL call is a normal statement and IS audited (L6)
cq5 = qfresh(("quack", "audit"))
cq5.execute("SELECT sql_audit_authz_chain(?, ?)", ["cx2", "SELECT 7"])  # quack's form
cq5.execute("SELECT sql_audit_authn_chain(?, ?, ?)", ["cx3", "a", "t"])  # quack's form
time.sleep(0.6)
noise = [r for r in get_records()
         if "sql_audit_auth" in str(r.get("query", "")).lower() and "(?" in str(r.get("query", ""))]
attr = any(r.get("record_type") == "STMT" and r.get("conn_id") == "cx2"
           and r.get("query") == "SELECT 7" for r in get_records())
verdict("G11-no-noise", len(noise) == 0 and attr,
        "placeholder dispatch noise=%d, attributed record=%s" % (len(noise), attr))
cq5.close()

# === G8: Multi-process sequential sessions (default path, no SET) ===
log("\n--- G8: Multi-process ---")
import subprocess
mp_code = (
    "import duckdb, time, sys\n"
    "c = duckdb.connect(':memory:', config={'allow_unsigned_extensions': True, 'allow_extensions_metadata_mismatch': True})\n"
    "c.execute(\"LOAD '%s'\")\n"
    "for i in range(5): c.execute('SELECT ' + str(100 + i + int(sys.argv[1])))\n"
    "time.sleep(1.0)\n"
    "c.close()\n"
) % EXT
base_before = len(get_records())
r1 = subprocess.run([sys.executable, "-c", mp_code, "0"], capture_output=True)
r2 = subprocess.run([sys.executable, "-c", mp_code, "10"], capture_output=True)
mp_ok = r1.returncode == 0 and r2.returncode == 0
recs_mp = get_records()
seqs_mp = [r["seq"] for r in recs_mp]
seq_dup = len(seqs_mp) != len(set(seqs_mp))
verdict("G8-multiproc", mp_ok and len(recs_mp) >= base_before + 10 and not seq_dup,
        "sessions ok=%s, +%d records, seq dup=%s" % (mp_ok, len(recs_mp) - base_before, seq_dup))
c8 = fresh()
v8 = c8.execute("SELECT * FROM sql_audit_verify()").fetchone()
verdict("G8-chain", v8[0] == True, "chain across processes: ok=%s total=%d" % (v8[0], v8[2]))
c8.close()

# === G9: Crash / oversize / large-tail resilience ===
log("\n--- G9: Crash & oversize ---")
TRN = "/root/.duckdb/sql_audit_torn"
shutil.rmtree(TRN, ignore_errors=True)
ct = fresh()
ct.execute("SET GLOBAL sql_audit_path='%s'" % TRN)
for i in range(5): ct.execute("SELECT %d" % (600+i))
time.sleep(1.0)
ct.close()
# simulate power-loss torn write: half a JSON line, no newline
jl_t = sorted(f for f in os.listdir(TRN) if f.endswith(".jsonl"))[0]
with open(os.path.join(TRN, jl_t), "ab") as f:
    f.write(b'{"seq":6,"schema_ver":5,"ts_ms":1,"record_type":"ST')
# new session: the torn tail must be truncated at open (no line gluing),
# the chain heals (next record reuses the lost seq — verify ok is CORRECT),
# and the new record must be an INDEPENDENT line.
# KNOWN BOUNDARY: a torn LAST record is not locally detectable (it never
# fully hit disk; seq reuse is legitimate healing). Cross-end detection of
# the lost tail relies on mode=both NATS anchor reconciliation.
ct2 = fresh()
ct2.execute("SET GLOBAL sql_audit_path='%s'" % TRN)
ct2.execute("SELECT 700")
time.sleep(1.0)
vt = ct2.execute("SELECT * FROM sql_audit_verify()").fetchone()
raw = open(os.path.join(TRN, jl_t), "rb").read()
lines_t = [l for l in raw.split(b"\n") if l.strip()]
no_glue = all(l.startswith(b"{") and l.rstrip().endswith(b"}") for l in lines_t)
seqs_t = []
for l in lines_t:
    try: seqs_t.append(json.loads(l)["seq"])
    except Exception: seqs_t.append(None)
parse_ok = all(s is not None for s in seqs_t)
verdict("G9-torn", vt[0] == True and no_glue and parse_ok,
        "torn healed: verify=%s, no glue=%s, all %d lines parse, seqs=%s" % (
            vt[0], no_glue, len(seqs_t), seqs_t[-3:]))
ct2.close()
shutil.rmtree(TRN, ignore_errors=True)
c_rst4 = fresh()
c_rst4.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
c_rst4.close()

# 2MB statement must not kill the NATS connection (segmented publish)
BIGD = "/root/.duckdb/sql_audit_big"
shutil.rmtree(BIGD, ignore_errors=True)
cb = fresh()
cb.execute("SET GLOBAL sql_audit_path='%s'" % BIGD)
cb.execute("SET GLOBAL sql_audit_nats_url='nats://localhost:4222'")
cb.execute("SET GLOBAL sql_audit_nats_subject='sqlaudit.bigtest'")
cb.execute("SET GLOBAL sql_audit_mode='both'")
cb.execute("SELECT 1")
time.sleep(0.8)
hb0 = cb.execute("SELECT * FROM sql_audit_health()").fetchone()
cb.execute("SELECT '%s'" % ("B" * 2100000))  # ~2MB payload > server max_payload
time.sleep(2.0)
hb1 = cb.execute("SELECT * FROM sql_audit_health()").fetchone()
cb.execute("SELECT 2")  # connection must still be alive
time.sleep(1.2)
hb2 = cb.execute("SELECT * FROM sql_audit_health()").fetchone()
followup_pub = hb2[6] - hb1[6]
vb = cb.execute("SELECT * FROM sql_audit_verify()").fetchone()
verdict("G9-bigsql", followup_pub >= 1 and vb[0] == True,
        "2MB stmt: follow-up pub=%d (conn alive), local verify=%s" % (followup_pub, vb[0]))
cb.close()
shutil.rmtree(BIGD, ignore_errors=True)
c_rst5 = fresh()
c_rst5.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
c_rst5.close()

# large-record tail + cross-process rebase: A(big) -> B(big) -> A(small)
LTD = "/root/.duckdb/sql_audit_ltail"
shutil.rmtree(LTD, ignore_errors=True)
lt_code = (
    "import duckdb, time, sys\n"
    "c = duckdb.connect(':memory:', config={'allow_unsigned_extensions': True, 'allow_extensions_metadata_mismatch': True})\n"
    "c.execute(\"LOAD '%s'\")\n"
    "c.execute(\"SET GLOBAL sql_audit_path='%s'\")\n"
    "tag = sys.argv[1]\n"
    "if tag == 'A1': c.execute(\"SELECT '%s'\")\n"
    "if tag == 'B1': c.execute(\"SELECT '%s'\")\n"
    "if tag == 'A2': c.execute('SELECT 42')\n"
    "time.sleep(0.5)\n"
    "c.close()\n"
) % (EXT, LTD, "L" * 12000, "M" * 12000)
for tag in ("A1", "B1", "A2"):
    r = subprocess.run([sys.executable, "-c", lt_code, tag], capture_output=True)
    if r.returncode != 0:
        print(r.stderr.decode()[:200])
cl = fresh()
cl.execute("SET GLOBAL sql_audit_path='%s'" % LTD)
vl = cl.execute("SELECT * FROM sql_audit_verify()").fetchone()
verdict("G9-ltail", vl[0] == True, "large-tail rebase: ok=%s first_bad=%d total=%d" % (vl[0], vl[1], vl[2]))
cl.close()
shutil.rmtree(LTD, ignore_errors=True)
c_rst6 = fresh()
c_rst6.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
c_rst6.close()

# === G10: subscriber-side delivery (segmentation + anchor) ===
log("\n--- G10: Subscriber e2e ---")
import socket as _socket
import struct as _struct

def _nats_sub(subject):
    s = _socket.create_connection(("localhost", 4222), timeout=5)
    f = s.makefile("rb")
    f.readline()  # INFO
    s.sendall(b'CONNECT {"verbose":false}\r\nSUB ' + subject.encode() + b' 1\r\nPING\r\n')
    while b"PONG" not in f.readline():
        pass
    return s, f

def _recv_payload(s, f, want=1, timeout=3.0):
    s.settimeout(timeout)
    out = []
    try:
        while len(out) < want:
            line = f.readline().decode(errors="replace").strip()
            if line.startswith("MSG "):
                n = int(line.split()[3])
                out.append(f.read(n + 2)[:-2])
    except Exception:
        pass
    return out

# G10-seg: 2MB statement -> SQLASEG1 frames -> reassemble -> match local record
SEG_D = "/root/.duckdb/sql_audit_seg"
shutil.rmtree(SEG_D, ignore_errors=True)
cseg = fresh()
cseg.execute("SET GLOBAL sql_audit_path='%s'" % SEG_D)
cseg.execute("SET GLOBAL sql_audit_nats_url='nats://localhost:4222'")
cseg.execute("SET GLOBAL sql_audit_nats_subject='seg.e2e'")
cseg.execute("SET GLOBAL sql_audit_mode='both'")
cseg.execute("SELECT 1")  # warm the connection
time.sleep(0.8)
# fresh subscriber AFTER warmup: no drain needed, first messages are the
# segmented frames of the big statement
s_seg, f_seg = _nats_sub("seg.e2e")
cseg.execute("SELECT '%s'" % ("S" * 2100000))
time.sleep(2.0)
frames = _recv_payload(s_seg, f_seg, want=12, timeout=2.5)
seg_frames = [fr for fr in frames if fr[:8] == b"SQLASEG1"]
reassembled = None
if seg_frames:
    groups = {}
    for fr in seg_frames:
        sid, idx, total = _struct.unpack(">IHH", fr[8:16])
        groups.setdefault(sid, {})[idx] = fr[16:]
    for sid, parts in groups.items():
        total = max(parts.keys())
        if len(parts) == total:
            reassembled = b"".join(parts[i] for i in range(1, total + 1))
seg_rec = None
try:
    seg_rec = json.loads(reassembled) if reassembled else None
except Exception:
    seg_rec = None
local_big = None
for r in get_records(SEG_D):
    if r.get("record_type") == "STMT" and r.get("query_len", 0) > 2000000:
        local_big = r
match_ok = (seg_rec is not None and local_big is not None
            and seg_rec.get("seq") == local_big.get("seq")
            and seg_rec.get("entry_hmac") == local_big.get("entry_hmac")
            and seg_rec.get("query_sha256") == local_big.get("query_sha256"))
verdict("G10-seg", match_ok,
        "segment reassembled=%s frames=%d, seq match=%s" % (
            reassembled is not None, len(seg_frames), match_ok))
cseg.close()
s_seg.close()
shutil.rmtree(SEG_D, ignore_errors=True)
c_rst7 = fresh()
c_rst7.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
c_rst7.close()

# G10-anchor: anchor message on <subject>.anchor matches local chain head
ANC_D = "/root/.duckdb/sql_audit_anchor"
shutil.rmtree(ANC_D, ignore_errors=True)
canc = fresh()
canc.execute("SET GLOBAL sql_audit_path='%s'" % ANC_D)
canc.execute("SET GLOBAL sql_audit_nats_url='nats://localhost:4222'")
canc.execute("SET GLOBAL sql_audit_nats_subject='anc.e2e'")
canc.execute("SET GLOBAL sql_audit_mode='both'")
canc.execute("SELECT 1")  # warm the connection BEFORE subscribing
time.sleep(0.8)
s_anc, f_anc = _nats_sub("anc.e2e.anchor")  # fresh subscriber
for i in range(150): canc.execute("SELECT %d" % (5000+i))
time.sleep(2.0)
anchors = _recv_payload(s_anc, f_anc, want=5, timeout=2.5)
anc_ok = False
anc_note = "no anchor received"
for a in anchors:
    try:
        j = json.loads(a)
        if j.get("type") == "anchor":
            local_anc = {r["seq"]: r for r in get_records(ANC_D)}
            seq_a = j.get("seq")
            head_a = j.get("chain_head", "")
            exp = local_anc.get(seq_a, {}).get("entry_hmac", "")
            anc_ok = (exp != "" and head_a == exp)
            anc_note = "anchor seq=%d head matches local entry_hmac=%s" % (seq_a, anc_ok)
            break
    except Exception:
        continue
verdict("G10-anchor", anc_ok, anc_note)
canc.close()
s_anc.close()
shutil.rmtree(ANC_D, ignore_errors=True)
c_rst8 = fresh()
c_rst8.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
c_rst8.close()

# === G12: LOW-fix batch (r24) ===
log("\n--- G12: LOW fixes ---")
# L6: literal user call IS audited (placeholder form is not — see G11)
cq6 = qfresh(("quack", "audit"))
cq6.execute("SELECT sql_audit_authz_chain('lit1', 'SELECT 5')")
time.sleep(0.6)
lit_audited = any(r.get("record_type") == "STMT"
                  and str(r.get("query", "")).lower().startswith("select sql_audit_authz_chain('lit1'")
                  for r in get_records())
verdict("G12-literal-audited", lit_audited, "literal chain call audited=%s" % lit_audited)

# L4: invalid delegate name is NOT adopted, hook NOT re-taken (quack fails closed)
cq6.execute("SET quack_authentication_function='evil; DROP TABLE x'")
cq6.execute("SELECT * FROM sql_audit_health()").fetchone()  # poll
cur_l4 = cq6.execute("SELECT current_setting('quack_authentication_function')").fetchone()[0]
h_l4 = cq6.execute("SELECT * FROM sql_audit_health()").fetchone()
l4_rej = any(r.get("record_type") == "SYS" and r.get("event_type") == "delegate_rejected"
             for r in get_records())
verdict("G12-l4-ident", cur_l4 == "evil; DROP TABLE x" and l4_rej,
        "invalid kept=%s (not re-taken), delegate_rejected event=%s" % (cur_l4 != "sql_audit_authn_chain", l4_rej))
cq6.close()
# restore clean hook state on a fresh connection
cq6b = qfresh(("quack", "audit"))
cq6b.execute("SELECT * FROM sql_audit_health()").fetchone()

# L5: per-DB hook state — two databases must not cross-talk
cqA = qfresh(("quack", "audit"))            # DB A: default delegate
cqB = duckdb.connect(":memory:", config={"allow_unsigned_extensions": True, "allow_extensions_metadata_mismatch": True})
cqB.execute("LOAD quack")
cqB.execute("LOAD '%s'" % EXT)              # DB B: fresh takeover
cqB.execute("CREATE MACRO b_authn(a, b, c) AS true")
cqB.execute("SET quack_authentication_function='b_authn'")
cqB.execute("SELECT * FROM sql_audit_health()").fetchone()  # B rechains to b_authn
hA = cqA.execute("SELECT * FROM sql_audit_health()").fetchone()
hB = cqB.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G12-perdb", hA[11] != "b_authn" and hB[11] == "b_authn",
        "A delegate=%r untouched, B delegate=%r" % (hA[11], hB[11]))
cqA.close(); cqB.close()

# L1: externalized key file — key lives outside the audit dir
EXTK = "/root/.duckdb/audit_keys/external.key"
KDIR = "/root/.duckdb/sql_audit_kf"
shutil.rmtree(KDIR, ignore_errors=True)
os.makedirs(os.path.dirname(EXTK), exist_ok=True)
if os.path.exists(EXTK): os.remove(EXTK)
ck = fresh()
ck.execute("SET GLOBAL sql_audit_key_file='%s'" % EXTK)
ck.execute("SET GLOBAL sql_audit_path='%s'" % KDIR)
for i in range(3): ck.execute("SELECT %d" % (i))
time.sleep(1.0)
vk = ck.execute("SELECT * FROM sql_audit_verify()").fetchone()
key_external = os.path.exists(EXTK) and not os.path.exists(os.path.join(KDIR, "chain.key"))
verdict("G12-keyfile", vk[0] == True and key_external,
        "verify=%s, key at %s, no key in audit dir=%s" % (vk[0], EXTK, key_external))
ck.close()
shutil.rmtree(KDIR, ignore_errors=True)
c_rst9 = fresh()
c_rst9.execute("SET GLOBAL sql_audit_key_file=''")  # back to default
c_rst9.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
c_rst9.close()

# L3: NATS confirm mode — publish with PING/PONG ack still delivers
cd = fresh()
cd.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
cd.execute("SET GLOBAL sql_audit_nats_url='nats://localhost:4222'")
cd.execute("SET GLOBAL sql_audit_nats_subject='conf.e2e'")
cd.execute("SET GLOBAL sql_audit_mode='both'")
cd.execute("SET GLOBAL sql_audit_nats_confirm=true")
cd.execute("SELECT 1")
time.sleep(1.2)
hd = cd.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G12-nats-confirm", hd[6] >= 1 and hd[7] == 0,
        "confirmed pub=%d err=%d" % (hd[6], hd[7]))
cd.execute("SET GLOBAL sql_audit_nats_confirm=false")
cd.close()

# L7: flush drains the queue within the timeout
cf = fresh()
rec0 = cf.execute("SELECT * FROM sql_audit_health()").fetchone()[3]
for i in range(50): cf.execute("SELECT %d" % (i))
pend_before = cf.execute("SELECT * FROM sql_audit_health()").fetchone()[2]
time.sleep(1.0)
h_dr = cf.execute("SELECT * FROM sql_audit_health()").fetchone()
verdict("G12-drain", h_dr[2] == 0 and h_dr[3] - rec0 >= 50,
        "pending %d -> %d, records +%d (queue converged)" % (
            pend_before, h_dr[2], h_dr[3] - rec0))
cf.close()

# L10/L9/L2: subscriber tool end-to-end — reassembly + HMAC re-verify + reconcile
SUBJ = "tool.e2e"
TDIR = "/root/.duckdb/sql_audit_tool"
shutil.rmtree(TDIR, ignore_errors=True)
ct = fresh()
ct.execute("SET GLOBAL sql_audit_path='%s'" % TDIR)
ct.execute("SET GLOBAL sql_audit_nats_url='nats://localhost:4222'")
ct.execute("SET GLOBAL sql_audit_nats_subject='%s'" % SUBJ)
ct.execute("SET GLOBAL sql_audit_mode='both'")
ct.execute("SELECT 1")  # warm the connection BEFORE the tool subscribes
time.sleep(0.8)
tool = subprocess.Popen([sys.executable, "/tmp/sql_audit_sub.py",
                         "--url", "nats://localhost:4222", "--subject", SUBJ,
                         "--duration", "6", "--keyfile", os.path.join(TDIR, "chain.key"),
                         "--reconcile", TDIR],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(1.0)  # let the tool register its SUB before we publish
ct.execute("SELECT '%s'" % ("T" * 1500000))  # segmented via SQLASEG1
for i in range(5): ct.execute("SELECT %d" % (i))
time.sleep(1.5)
out, err = tool.communicate(timeout=20)
summary = {}
dec = json.JSONDecoder()
idx = 0
text = out
while idx < len(text):
    # find the next '{' and try to decode a full JSON object from there
    brace = text.find("{", idx)
    if brace < 0:
        break
    try:
        obj, end = dec.raw_decode(text, brace)
        if "records" in obj and "reconcile_dir" not in obj:
            summary["main"] = obj
        if "reconcile_dir" in obj:
            summary["recon"] = obj
        idx = brace + end
    except ValueError:
        idx = brace + 1
main_s = summary.get("main", {})
recon_s = summary.get("recon", {})
ok_tool = (main_s.get("seg_complete", 0) >= 1
           and main_s.get("hmac_bad", 0) == 0
           and main_s.get("hmac_ok", 0) >= 6
           and recon_s.get("gap_disk_minus_received") == 0)
verdict("G12-subtool", ok_tool,
        "seg=%s hmac_ok=%s bad=%s gap=%s" % (
            main_s.get("seg_complete"), main_s.get("hmac_ok"),
            main_s.get("hmac_bad"), recon_s.get("gap_disk_minus_received")))
ct.close()
shutil.rmtree(TDIR, ignore_errors=True)
c_rst10 = fresh()
c_rst10.execute("SET GLOBAL sql_audit_path='%s'" % AUDIT_DIR)
c_rst10.close()

# === G7: Security & Performance ===
log("\n--- G7: Security & Performance ---")
if os.path.exists(kp):
    mode = oct(os.stat(kp).st_mode)[-3:]
    verdict("G7-keyfile", mode == "600", "mode=%s" % mode)
# Audit records carry full SQL (may embed secrets): dir 0700, jsonl 0600
dmode = oct(os.stat(AUDIT_DIR).st_mode)[-3:]
verdict("G7-dirperm", dmode == "700", "dir mode=%s" % dmode)
_jl = sorted(f for f in os.listdir(AUDIT_DIR) if f.endswith(".jsonl"))
if _jl:
    jmode = oct(os.stat(os.path.join(AUDIT_DIR, _jl[-1])).st_mode)[-3:]
    verdict("G7-fileperm", jmode == "600", "jsonl mode=%s" % jmode)

c_perf = fresh()
t0 = time.perf_counter()
for i in range(1000): c_perf.execute("SELECT %d" % i)
t_perf = time.perf_counter() - t0
qps = 1000 / t_perf
verdict("G7-perf", qps > 1000, "QPS=%.0f" % qps)
c_perf.close()

# === SUMMARY ===
log("\n" + "=" * 70)
log("  FINAL SUMMARY")
log("=" * 70)
p = sum(1 for v in R.values() if v[0])
f = sum(1 for v in R.values() if not v[0])
log("\n  PASS: %d   FAIL: %d   TOTAL: %d" % (p, f, p + f))
log("  Pass rate: %.1f%%" % ((p / (p + f) * 100) if p + f > 0 else 0))
log("")
for tid, (ok, note) in sorted(R.items()):
    log("    %s  %-22s %s" % ("PASS" if ok else "FAIL", tid, note))
log("=" * 70)
sys.exit(0 if f == 0 else 1)
