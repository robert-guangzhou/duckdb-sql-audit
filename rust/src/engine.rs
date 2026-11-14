use crate::chain::{AuditChain, sha256_hex};
use crate::sink_local::{LocalSink, SinkConfig, RetentionPolicy};
use crate::sink_nats::{NatsSink, NatsSinkConfig};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use crossbeam_channel::Receiver;

pub struct CaptureMsg {
    pub query: Vec<u8>,
    pub ts_ms: i64,
}

impl CaptureMsg {
    pub fn new(query: &[u8]) -> Self {
        Self { query: query.to_vec(), ts_ms: now_ms() }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum AuditMode { Local, Nats, Both, Off }

#[derive(Clone)]
pub struct EngineConfig {
    pub output_dir: String,
    pub max_file_mb: u64,
    pub retention_files: usize,
    pub retention_policy: RetentionPolicy,
    pub principal: String,
    pub nats_url: String,
    pub nats_subject: String,
    pub mode: AuditMode,
    /// Externalized chain key (L1): when set, HMAC key lives OUTSIDE the
    /// audit dir (different mount / vault export). Deployment-time option —
    /// runtime rotation is not supported (old records would stop verifying).
    pub key_file: Option<String>,
    /// NATS publish confirmation (L3): PING/PONG after every PUB.
    pub nats_confirm: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            output_dir: format!("{}/.duckdb/sql_audit", std::env::var("HOME").unwrap_or_default()),
            max_file_mb: 64, retention_files: 32,
            retention_policy: RetentionPolicy::Prune,
            principal: String::new(),
            nats_url: String::new(), nats_subject: "sqlaudit.test".to_string(),
            mode: AuditMode::Local,
            key_file: None,
            nats_confirm: false,
        }
    }
}

pub struct AuditEngine {
    config: Arc<Mutex<EngineConfig>>,
    chain: Arc<Mutex<Option<AuditChain>>>,
    sink: Arc<Mutex<Option<LocalSink>>>,
    nats_sink: Arc<Mutex<Option<NatsSink>>>,
    record_count: Arc<Mutex<u64>>,
    anchor_counter: Arc<Mutex<u64>>,
    conn_counter: Arc<Mutex<u64>>,
    conn_reject_counter: Arc<Mutex<u64>>,
}

impl AuditEngine {
    pub fn new(config: EngineConfig) -> Result<Self, String> {
        let dir = std::path::PathBuf::from(&config.output_dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("create dir: {}", e))?;
        // Resume the chain from existing records — a fresh process on the
        // default dir must continue the existing chain, not restart at seq 0
        // (proven broken: every new session forked the chain, 2026-11-13).
        let sink_probe = LocalSink::new(SinkConfig {
            dir: dir.clone(), max_file_mb: config.max_file_mb,
            retention_files: config.retention_files, retention_policy: config.retention_policy,
        })?;
        let (resume_seq, resume_prev) = resume_point(&sink_probe);
        let chain = new_chain(&config, &dir, resume_seq, resume_prev)?;
        let sink = sink_probe;
        let count = sink.existing_record_count();
        let nats_sink = if !config.nats_url.is_empty() {
            match NatsSink::new(NatsSinkConfig {
                url: config.nats_url.clone(), subject: config.nats_subject.clone(),
                confirm: config.nats_confirm, ..Default::default()
            }) {
                Ok(n) => { eprintln!("sql_audit: NATS connected"); Some(n) }
                Err(e) => { eprintln!("sql_audit: NATS connect failed: {}", e); None }
            }
        } else { None };
        Ok(Self {
            config: Arc::new(Mutex::new(config)),
            chain: Arc::new(Mutex::new(Some(chain))),
            sink: Arc::new(Mutex::new(Some(sink))),
            nats_sink: Arc::new(Mutex::new(nats_sink)),
            record_count: Arc::new(Mutex::new(count)),
            anchor_counter: Arc::new(Mutex::new(0)),
            conn_counter: Arc::new(Mutex::new(0)),
            conn_reject_counter: Arc::new(Mutex::new(0)),
        })
    }

    pub fn clone_handle(&self) -> Self {
        Self {
            config: self.config.clone(), chain: self.chain.clone(),
            sink: self.sink.clone(), nats_sink: self.nats_sink.clone(),
            record_count: self.record_count.clone(), anchor_counter: self.anchor_counter.clone(),
            conn_counter: self.conn_counter.clone(), conn_reject_counter: self.conn_reject_counter.clone(),
        }
    }

    pub fn set_output_dir(&self, path: &str) -> i32 {
        let dir = std::path::PathBuf::from(path);
        if let Err(_) = std::fs::create_dir_all(&dir) { return -1; }
        let (mb, rf, rp) = {
            let cfg = self.config.lock().unwrap();
            (cfg.max_file_mb, cfg.retention_files, cfg.retention_policy)
        };
        // Hold the dir flock from BEFORE sink creation (LocalSink::new runs
        // the torn-tail truncate) through the swap: a consumer-thread append
        // racing the switch could otherwise glue a record onto a torn tail
        // after the truncate already passed (proven in R3).
        let _dlock = crate::sink_local::DirLock::acquire(&dir);
        match LocalSink::new(SinkConfig { dir: dir.clone(), max_file_mb: mb, retention_files: rf, retention_policy: rp }) {
            Ok(sk) => {
                let (resume_seq, resume_prev) = resume_point(&sk);
                // Resume chain from existing records (prevents seq collision on path switch)
                let cfg = self.config.lock().unwrap().clone();
                match new_chain(&cfg, &dir, resume_seq, resume_prev) {
                    Ok(ch) => {
                        let c = sk.existing_record_count();
                        // Swap chain+sink under both locks (chain→sink, same
                        // order as emit_atomic) so a concurrent writer can
                        // never pair the new chain with the old sink.
                        {
                            let mut chain_g = self.chain.lock().unwrap();
                            let mut sink_g = self.sink.lock().unwrap();
                            *chain_g = Some(ch);
                            *sink_g = Some(sk);
                        }
                        *self.record_count.lock().unwrap() = c;
                        0
                    }
                    Err(_) => -1
                }
            }
            Err(_) => -1
        }
    }

    pub fn set_max_file_mb(&self, mb: u64) {
        if let Some(s) = self.sink.lock().unwrap().as_mut() { s.set_max_file_mb(mb); }
    }
    pub fn set_retention_files(&self, c: usize) {
        if let Some(s) = self.sink.lock().unwrap().as_mut() { s.set_retention_files(c); }
    }
    pub fn set_retention_policy(&self, p: RetentionPolicy) {
        if let Some(s) = self.sink.lock().unwrap().as_mut() { s.set_retention_policy(p); }
    }
    pub fn set_nats_url(&self, url: &str) {
        self.config.lock().unwrap().nats_url = url.to_string();
        self.reconnect_nats();
    }
    pub fn set_nats_subject(&self, s: &str) {
        // The subject is interpolated into the NATS wire line `PUB <subj> <n>`;
        // whitespace/CRLF would allow protocol injection. Reject and keep the
        // previous subject.
        if s.chars().any(|c| c.is_whitespace()) {
            eprintln!("sql_audit: invalid nats subject (whitespace/CRLF rejected): {:?}", s);
            return;
        }
        self.config.lock().unwrap().nats_subject = s.to_string();
    }

    /// Externalized chain key (L1). Takes effect for chain construction on
    /// the next path switch / engine init; runtime key rotation is NOT
    /// supported (records signed by the old key would fail verify).
    pub fn set_key_file(&self, path: &str) -> i32 {
        if path.is_empty() {
            self.config.lock().unwrap().key_file = None;
            return 0;
        }
        let pb = std::path::Path::new(path);
        match crate::chain::ChainKey::load_or_create_at(pb) {
            Ok(_) => {
                self.config.lock().unwrap().key_file = Some(path.to_string());
                0
            }
            Err(e) => {
                eprintln!("sql_audit: key file error: {}", e);
                -1
            }
        }
    }

    /// NATS publish confirmation (L3): PING/PONG after every PUB.
    pub fn set_nats_confirm(&self, on: bool) {
        self.config.lock().unwrap().nats_confirm = on;
        if let Some(n) = self.nats_sink.lock().unwrap().as_mut() {
            n.set_confirm(on);
        }
    }
    pub fn set_mode(&self, mode: &str) {
        let m = match mode {
            "nats" => AuditMode::Nats, "both" => AuditMode::Both, "off" => AuditMode::Off,
            _ => AuditMode::Local,
        };
        let needs_nats = (m == AuditMode::Nats) || (m == AuditMode::Both);
        self.config.lock().unwrap().mode = m;
        if needs_nats && self.nats_sink.lock().unwrap().is_none() { self.reconnect_nats(); }
    }

    fn reconnect_nats(&self) {
        let (url, subj, confirm) = {
            let cfg = self.config.lock().unwrap();
            (cfg.nats_url.clone(), cfg.nats_subject.clone(), cfg.nats_confirm)
        };
        if url.is_empty() { return; }
        match NatsSink::new(NatsSinkConfig { url, subject: subj, confirm, ..Default::default() }) {
            Ok(n) => { *self.nats_sink.lock().unwrap() = Some(n); }
            Err(e) => { eprintln!("sql_audit: NATS reconnect failed: {}", e); *self.nats_sink.lock().unwrap() = None; }
        }
    }

    pub fn nats_published(&self) -> i64 {
        self.nats_sink.lock().unwrap().as_ref().map(|n| n.get_published()).unwrap_or(0)
    }
    pub fn nats_errors(&self) -> i64 {
        self.nats_sink.lock().unwrap().as_ref().map(|n| n.get_errors()).unwrap_or(0)
    }
    pub fn is_halted(&self) -> bool {
        self.sink.lock().unwrap().as_ref().map(|s| s.is_halted()).unwrap_or(false)
    }
    pub fn file_count(&self) -> i64 {
        self.sink.lock().unwrap().as_ref().map(|s| s.file_count()).unwrap_or(0)
    }
    pub fn flush(&self, _: i64) -> i32 {
        if let Some(s) = self.sink.lock().unwrap().as_ref() { s.flush(); }
        0
    }
    pub fn record_count(&self) -> i64 { *self.record_count.lock().unwrap() as i64 }

    pub fn verify_chain(&self, head_out: Option<&mut [u8]>,
                        mut window_start_out: Option<&mut i64>,
                        disk_total_out: Option<&mut i64>) -> i64 {
        // Short locks only (emit_atomic holds chain→sink nested; never nest
        // them the other way here, and never read files under a lock — a
        // multi-GB verify must not stall the consumer thread).
        let dir = {
            let sink_g = self.sink.lock().unwrap();
            match sink_g.as_ref() { Some(s) => s.dir().to_path_buf(), None => return -2 }
        };
        let ckb = {
            let chain_g = self.chain.lock().unwrap();
            match chain_g.as_ref() { Some(c) => c.key_bytes(), None => return -2 }
        };
        // Key source follows the engine config (externalized key, L1).
        let key_path = self.config.lock().unwrap().key_file.clone();
        let dk = match resolve_key(&dir, key_path.as_deref()) { Ok(k) => k, Err(_) => return -2 };
        if dk.key_bytes() != ckb { return -1; }
        let records = {
            let mut attempt = match crate::sink_local::LocalSink::read_records_in_dir(&dir) {
                Ok(r) => r, Err(_) => return -2,
            };
            // A listed file vanished mid-walk (prune racing verify): re-read
            // once so the policy-pruned prefix converges to a clean window.
            // A gap that survives a stable re-read is a real deletion.
            if attempt.1 > 0 {
                attempt = match crate::sink_local::LocalSink::read_records_in_dir(&dir) {
                    Ok(r) => r, Err(_) => return -2,
                };
            }
            attempt.0
        };
        if let Some(o) = disk_total_out { *o = records.len() as i64; }
        // verify_entry is a pure function of the key, so a fresh chain (seq 0)
        // verifies stored entries without touching live chain state.
        let chain = match new_chain(&self.config.lock().unwrap().clone(), &dir, 0, None) {
            Ok(c) => c, Err(_) => return -2,
        };
        // Segment-head semantics: under retention prune the oldest files are
        // deleted by policy, so the first RETAINED record has no verifiable
        // predecessor. Its own prev_hash is trusted for its HMAC check and
        // exposed via window_start so an unexpected head gap is visible.
        let mut prev: Option<String> = None;
        let mut last_seq: Option<u64> = None;
        let mut ws_set = false;
        for rec in &records {
            let seq = rec.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
            let ts = rec.get("ts_ms").and_then(|v| v.as_i64()).unwrap_or(0);
            let rt = rec.get("record_type").and_then(|v| v.as_str()).unwrap_or("");
            let pr = rec.get("principal").and_then(|v| v.as_str()).unwrap_or("");
            let vd = rec.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
            let eh = rec.get("entry_hmac").and_then(|v| v.as_str()).unwrap_or("");
            let sp = rec.get("prev_hash").and_then(|v| v.as_str()).unwrap_or("");
            // seq continuity WITHIN the retained window: a gap means a record
            // was lost (power-loss torn write truncated at open) or deleted.
            // Without this check the loss was silent (verify said ok).
            if let Some(ls) = last_seq {
                if seq != ls + 1 { return seq as i64; }
            }
            if let Some(expected) = &prev {
                if sp != expected.as_str() { return seq as i64; }
            }
            let effective_prev = prev.clone().unwrap_or_else(|| sp.to_string());
            if !ws_set {
                if let Some(o) = window_start_out.as_deref_mut() { *o = seq as i64; }
                ws_set = true;
            }
            if rt == "CONN" {
                // CONN record: hash field is token_fp (no query)
                let tf = rec.get("token_fp").and_then(|v| v.as_str()).unwrap_or("");
                if !chain.verify_entry(seq, ts, rt, pr, vd, tf, &effective_prev, eh) { return seq as i64; }
                // C06 secondary check: sub integrity (r13 pattern, same as
                // STMT.query_sha256). Invariant: any stored sub is within
                // the 256-BYTE budget; untruncated subs recompute their
                // hash, truncated ones cannot (original text unavailable).
                if let Some(sha) = rec.get("sub_sha256").and_then(|v| v.as_str()) {
                    let sv = rec.get("sub").and_then(|v| v.as_str());
                    let trunc = rec.get("sub_truncated").and_then(|v| v.as_bool()).unwrap_or(false);
                    match (sv, trunc) {
                        (Some(s), false) => {
                            if s.len() > 256 || sha256_hex(s.as_bytes()) != sha { return seq as i64; }
                        }
                        (Some(s), true) => {
                            if s.len() > 256 { return seq as i64; }
                        }
                        (None, _) => { /* sub absent: sha must be absent too */ }
                    }
                }
            } else if rt == "SYS" {
                // SYS record: hash field is detail_sha256, verify detail text
                let dsha = rec.get("detail_sha256").and_then(|v| v.as_str()).unwrap_or("");
                if !chain.verify_entry(seq, ts, rt, pr, vd, dsha, &effective_prev, eh) { return seq as i64; }
                let ad = rec.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                if sha256_hex(ad.as_bytes()) != dsha { return seq as i64; }
            } else {
                // STMT record: hash field is query_sha256, verify query content
                let qs = rec.get("query_sha256").and_then(|v| v.as_str()).unwrap_or("");
                if !chain.verify_entry(seq, ts, rt, pr, vd, qs, &effective_prev, eh) { return seq as i64; }
                let aq = rec.get("query").and_then(|v| v.as_str()).unwrap_or("");
                if sha256_hex(aq.as_bytes()) != qs { return seq as i64; }
            }
            prev = Some(eh.to_string());
            last_seq = Some(seq);
        }
        if let Some(buf) = head_out {
            let h = prev.unwrap_or_else(|| "0".repeat(64));
            let hb = h.as_bytes();
            let l = buf.len().min(hb.len());
            buf[..l].copy_from_slice(&hb[..l]);
        }
        0
    }

    /// Atomically: build the chain entry and append it to the LOCAL sink.
    /// The chain advance and the disk append happen under one chain→sink
    /// lock span; if the sink rejects the record (halt policy) the chain is
    /// rolled back — otherwise records written after a halt release would
    /// carry a prev_hash pointing at a ghost entry that never hit disk
    /// (verified broken: first_bad=305, 2026-11-13).
    /// NATS publish (fire-and-forget) happens after, without the chain lock.
    /// Returns true when the record reached the local sink (or, in nats-only
    /// mode, was queued to NATS).
    fn emit_atomic<F>(&self, ts: i64, record_type: &str, verdict: &str,
                      hash_field: &str, mk_record: F) -> bool
    where F: FnOnce(u64, String, String) -> serde_json::Value {
        let (mode, subj, principal) = {
            let cfg = self.config.lock().unwrap();
            (cfg.mode.clone(), cfg.nats_subject.clone(), cfg.principal.clone())
        };
        if mode == AuditMode::Off { return false; }

        if mode == AuditMode::Nats {
            // nats-only: no local copy, chain advances in memory only
            let line = {
                let mut chain_g = self.chain.lock().unwrap();
                match chain_g.as_mut() {
                    Some(c) => {
                        let prev = c.chain_head().to_string();
                        let (seq, hmac) = c.build_entry(ts, record_type, &principal, verdict, hash_field);
                        serde_json::to_string(&mk_record(seq, prev, hmac)).unwrap_or_default()
                    }
                    None => return false,
                }
            };
            let mut nats = self.nats_sink.lock().unwrap();
            if let Some(n) = nats.as_mut() { n.publish(&subj, &line); }
            return true;
        }

        // Local / Both: chain advance + disk append must be atomic.
        // Cross-process: hold the dir flock across tail-rebase + build +
        // append so multiple OS processes sharing one audit dir keep the
        // chain linear instead of forking it.
        let (line, written) = {
            let mut chain_g = self.chain.lock().unwrap();
            let c = match chain_g.as_mut() { Some(c) => c, None => return false };
            let mut sink_g = self.sink.lock().unwrap();
            let dir = match sink_g.as_ref() { Some(s) => s.dir().to_path_buf(), None => return false };
            let dlock = crate::sink_local::DirLock::acquire(&dir);
            if let Some((tseq, thead)) = LocalSink::read_tail(&dir) {
                let stale = tseq > c.seq() || (tseq == c.seq() && thead != c.chain_head());
                if stale {
                    c.rebase(tseq, thead);
                    // also follow the disk tail's FILE: another process may
                    // have rotated under us (records must land in the file
                    // the reader expects by name order)
                    if let Some(s) = sink_g.as_mut() { s.reopen_tail(); }
                }
            }
            let saved_seq = c.seq();
            let saved_head = c.chain_head().to_string();
            let prev = saved_head.clone();
            let (seq, hmac) = c.build_entry(ts, record_type, &principal, verdict, hash_field);
            let record = mk_record(seq, prev, hmac);
            let line = serde_json::to_string(&record).unwrap_or_default();
            let ok = sink_g.as_mut().map(|s| s.append(&line)).unwrap_or(false);
            if !ok {
                if let Some(c) = chain_g.as_mut() { c.rollback(saved_seq, saved_head); }
            }
            drop(dlock);
            (line, ok)
        };
        if written {
            *self.record_count.lock().unwrap() += 1;
            if mode == AuditMode::Both {
                let mut nats = self.nats_sink.lock().unwrap();
                if let Some(n) = nats.as_mut() { n.publish(&subj, &line); }
            }
        }
        written
    }

    pub fn process_message(&self, msg: CaptureMsg) {
        let qs = sha256_hex(&msg.query);
        let qstr = String::from_utf8_lossy(&msg.query).to_string();
        let written = self.emit_atomic(msg.ts_ms, "STMT", "PASS", &qs, |seq, prev, hmac| {
            serde_json::json!({
                "seq": seq, "schema_ver": 5, "ts_ms": msg.ts_ms,
                "record_type": "STMT", "prev_hash": prev, "entry_hmac": hmac,
                "principal": self.config.lock().unwrap().principal,
                "verdict": "PASS", "query_sha256": qs,
                "query_len": msg.query.len(), "query": qstr,
            })
        });
        // Anchor (chain-head publication) — only when a record was actually
        // written and NATS output is active
        if written {
            let should = { let mut ac = self.anchor_counter.lock().unwrap(); *ac += 1; *ac % 100 == 0 };
            if should {
                let (mode, subj) = {
                    let cfg = self.config.lock().unwrap();
                    (cfg.mode.clone(), cfg.nats_subject.clone())
                };
                if mode == AuditMode::Nats || mode == AuditMode::Both {
                    let head = self.chain.lock().unwrap().as_ref().map(|c| c.chain_head().to_string()).unwrap_or_default();
                    let seq_now = self.chain.lock().unwrap().as_ref().map(|c| c.seq()).unwrap_or(0);
                    let anchor_subject = format!("{}.anchor", subj);
                    let mut nats = self.nats_sink.lock().unwrap();
                    if let Some(n) = nats.as_mut() { n.publish_anchor(&anchor_subject, &head, seq_now); }
                }
            }
        }
    }

    /// C04/C06/C07: rejected connections carry a reason classification and
    /// the client's self-reported identity (r13 semantics: sub/azp are
    /// UNVERIFIED echoes; the authoritative verdict is C03).
    /// reason: authoritative value from quack_oauth_audit_log (passed in);
    /// empty on reject -> local fallback via claims (expired / denied).
    pub fn conn_open(&self, conn_id: &str, token: &str, authn_result: &str, reason_in: &str) {
        let fp = crate::chain::sha256_hex(token.as_bytes())[..8].to_string();
        let ts = now_ms();
        let principal = self.config.lock().unwrap().principal.clone();

        // JWT claims decode (sub / azp / exp) — unverified echo, r13 C06/C07
        let mut sub: Option<String> = None;
        let mut azp: Option<String> = None;
        let mut expired = false;
        if let Some(claims) = decode_jwt_claims(token) {
            if let Some(s) = claims.get("sub").and_then(|v| v.as_str()) {
                sub = Some(s.to_string());
            }
            azp = claims.get("azp").and_then(|v| v.as_str()).map(|s| s.to_string())
                .or_else(|| claims.get("cid").and_then(|v| v.as_str()).map(|s| s.to_string()));
            if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
                expired = exp * 1000 < ts;
            }
        }
        // C06: sub cap 256 BYTES (attacker-controllable field, r13 boundary).
        // Truncate at a char boundary inside the byte budget — char-count
        // capping allowed 3-4x byte amplification via multi-byte subs.
        let mut sub_truncated = false;
        let mut sub_out: Option<String> = None;
        let mut sub_sha256: Option<String> = None;
        if let Some(s) = sub {
            sub_sha256 = Some(sha256_hex(s.as_bytes()));
            if s.len() > 256 {
                let mut budget = 0usize;
                let cut: String = s.chars().take_while(|c| {
                    if budget + c.len_utf8() <= 256 { budget += c.len_utf8(); true } else { false }
                }).collect();
                sub_out = Some(cut);
                sub_truncated = true;
            } else {
                sub_out = Some(s);
            }
        }
        // C02: rejection is a connection event of its own; C03 enum (impl
        // fact): ok | reject
        let event = if authn_result == "reject" { "conn_authn_reject" } else { "conn_open" };
        // C04 reason: authoritative or local fallback
        let reason = if authn_result != "reject" {
            String::new()
        } else if !reason_in.is_empty() {
            reason_in.to_string()
        } else if expired {
            "expired".to_string()
        } else {
            "denied".to_string()
        };

        let fp_ref = fp.clone();
        let written = self.emit_atomic(ts, "CONN", authn_result, &fp_ref, move |seq, prev, hmac| {
            serde_json::json!({
                "seq": seq, "schema_ver": 5, "ts_ms": ts,
                "record_type": "CONN", "prev_hash": prev, "entry_hmac": hmac,
                "principal": principal,
                "conn_id": conn_id, "event": event,
                "authn": authn_result, "verdict": authn_result, "token_fp": fp,
                "reason": reason,
                "sub": sub_out, "sub_truncated": sub_truncated,
                "sub_sha256": sub_sha256, "azp": azp,
            })
        });
        if written { *self.conn_counter.lock().unwrap() += 1; }
    }

    pub fn capture_with_conn(&self, conn_id: &str, query: &[u8]) {
        let qs = sha256_hex(query);
        let qstr = String::from_utf8_lossy(query).to_string();
        let ts = now_ms(); // capture once: HMAC and stored ts_ms must match
        let _ = self.emit_atomic(ts, "STMT", "PASS", &qs, |seq, prev, hmac| {
            serde_json::json!({
                "seq": seq, "schema_ver": 5, "ts_ms": ts,
                "record_type": "STMT", "prev_hash": prev, "entry_hmac": hmac,
                "principal": self.config.lock().unwrap().principal,
                "verdict": "PASS", "query_sha256": qs,
                "query_len": query.len(), "query": qstr,
                "conn_id": conn_id,
            })
        });
    }

    pub fn conn_count(&self) -> i64 { *self.conn_counter.lock().unwrap() as i64 }
    pub fn conn_reject_count(&self) -> i64 { *self.conn_reject_counter.lock().unwrap() as i64 }

    /// System event (hook takeover / rechain / config change): SYS record,
    /// hash field = sha256(detail) so the event text is tamper-covered.
    pub fn sys_event(&self, event_type: &str, detail: &str) {
        let ds = sha256_hex(detail.as_bytes());
        let ts = now_ms();
        let et = event_type.to_string();
        let dt = detail.to_string();
        let ds_ref = ds.clone();
        let principal = self.config.lock().unwrap().principal.clone();
        let _ = self.emit_atomic(ts, "SYS", "INFO", &ds_ref, move |seq, prev, hmac| {
            serde_json::json!({
                "seq": seq, "schema_ver": 5, "ts_ms": ts,
                "record_type": "SYS", "prev_hash": prev, "entry_hmac": hmac,
                "principal": principal,
                "verdict": "INFO", "event_type": et, "detail": dt, "detail_sha256": ds,
            })
        });
    }

    pub fn conn_reject(&self) { *self.conn_reject_counter.lock().unwrap() += 1; }
}

pub fn consumer_loop(rx: Receiver<CaptureMsg>, engine: &AuditEngine) {
    for msg in rx {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { engine.process_message(msg); }));
    }
    engine.flush(0);
}

/// Highest seq + last entry_hmac in a sink's existing records, for resuming
/// the chain on engine init and path switches (shared by both call sites).
fn resume_point(sink: &LocalSink) -> (u64, Option<String>) {
    match sink.read_all_records() {
        Ok(records) => {
            if let Some(last) = records.last() {
                let seq = last.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                let prev = last.get("entry_hmac").and_then(|v| v.as_str())
                    .unwrap_or("").to_string();
                (seq, if prev.is_empty() { None } else { Some(prev) })
            } else { (0, None) }
        }
        Err(_) => (0, None)
    }
}

/// Build a chain using the configured key source (external file or the
/// audit dir's default chain.key).
fn new_chain(cfg: &EngineConfig, dir: &std::path::Path,
             resume_seq: u64, resume_prev: Option<String>) -> Result<AuditChain, String> {
    match &cfg.key_file {
        Some(kf) => {
            let kp = std::path::Path::new(kf);
            AuditChain::new_with_key(kp, resume_seq, resume_prev)
        }
        None => AuditChain::new(dir, resume_seq, resume_prev),
    }
}

/// Load the chain key from the configured source (verify-side twin of
/// new_chain — both MUST resolve the same file or verification is meaningless).
fn resolve_key(dir: &std::path::Path, key_file: Option<&str>) -> Result<crate::chain::ChainKey, String> {
    match key_file {
        Some(kf) => crate::chain::ChainKey::load_or_create_at(std::path::Path::new(kf)),
        None => crate::chain::ChainKey::load_or_create(dir),
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Minimal JWT claims decoder: `header.payload.signature` -> payload JSON.
/// base64url without padding, hand-rolled (no new dependency, plan §8).
/// Any malformed input returns None — the audit side path must never panic
/// or block the connection flow.
fn decode_jwt_claims(token: &str) -> Option<serde_json::Value> {
    let mut parts = token.split('.');
    let _hdr = parts.next()?;
    let payload = parts.next()?;
    let _sig = parts.next()?;
    if payload.is_empty() { return None; }
    let bytes = base64url_decode(payload)?;
    let s = String::from_utf8(bytes).ok()?;
    serde_json::from_str(&s).ok()
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let input: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in &input {
        buf = (buf << 6) | val(b)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}
