// sql_audit: Rust core engine
// Phase 3: + NATS mode

#![allow(non_camel_case_types)]

mod engine;
mod chain;
mod sink_local;
mod sink_nats;

pub use chain::{AuditChain, ChainKey};
pub use engine::{AuditEngine, EngineConfig};
pub use sink_local::{LocalSink, SinkConfig, RetentionPolicy};
pub use sink_nats::{NatsSink, NatsSinkConfig};

use std::sync::atomic::{AtomicI64, AtomicBool, Ordering};
use std::sync::OnceLock;
use std::thread;
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SqlAuditVerdict {
    Pass = 0,
    Reject = 1,
    Degraded = 2,
}

static CAPTURED: AtomicI64 = AtomicI64::new(0);
static DROPPED: AtomicI64 = AtomicI64::new(0);
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static ENGINE: OnceLock<AuditEngine> = OnceLock::new();
const QUEUE_CAPACITY: usize = 8192;
static CHANNEL: OnceLock<(Sender<engine::CaptureMsg>, Receiver<engine::CaptureMsg>)> = OnceLock::new();

#[no_mangle]
pub extern "C" fn sql_audit_init() -> i32 {
    if INITIALIZED.load(Ordering::SeqCst) { return 0; }
    let (tx, rx) = bounded(QUEUE_CAPACITY);
    let _ = CHANNEL.set((tx, rx));
    let engine = match AuditEngine::new(EngineConfig::default()) {
        Ok(e) => e, Err(_) => return -1,
    };
    let _ = ENGINE.set(engine);
    let recv = CHANNEL.get().map(|(_, rx)| rx.clone()).unwrap();
    let eng = ENGINE.get().map(|e| e.clone_handle()).unwrap();
    thread::spawn(move || { engine::consumer_loop(recv, &eng); });
    INITIALIZED.store(true, Ordering::SeqCst);
    0
}

#[no_mangle]
pub extern "C" fn sql_audit_shutdown() {
    if !INITIALIZED.load(Ordering::SeqCst) { return; }
    INITIALIZED.store(false, Ordering::SeqCst);
}

#[no_mangle]
pub extern "C" fn sql_audit_capture(query_data: *const u8, query_len: i64) -> SqlAuditVerdict {
    let result = std::panic::catch_unwind(|| {
        if !INITIALIZED.load(Ordering::SeqCst) { return; }
        // Test hook (acceptance 5: panic containment): env-gated, panics
        // INSIDE the catch_unwind so the C boundary is never crossed.
        if std::env::var("SQL_AUDIT_INJECT_PANIC").as_deref() == Ok("1") {
            panic!("injected: capture path");
        }
        let slice = unsafe { std::slice::from_raw_parts(query_data, query_len as usize) };
        let msg = engine::CaptureMsg::new(slice);
        if let Some((tx, _)) = CHANNEL.get() {
            match tx.try_send(msg) {
                Ok(()) => { CAPTURED.fetch_add(1, Ordering::SeqCst); }
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                    DROPPED.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    });
    match result { Ok(()) => SqlAuditVerdict::Pass, Err(_) => SqlAuditVerdict::Degraded }
}

#[no_mangle]
pub extern "C" fn sql_audit_get_captured() -> i64 { CAPTURED.load(Ordering::SeqCst) }
#[no_mangle]
pub extern "C" fn sql_audit_get_dropped() -> i64 { DROPPED.load(Ordering::SeqCst) }
#[no_mangle]
pub extern "C" fn sql_audit_get_pending() -> i64 {
    CHANNEL.get().map(|(_, rx)| rx.len() as i64).unwrap_or(0)
}
#[no_mangle]
pub extern "C" fn sql_audit_flush(timeout_ms: i64) -> i32 {
    // L7: honor the timeout — drain the capture queue (10ms polling) until
    // empty or deadline, then sync the sink.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.max(0) as u64);
    while std::time::Instant::now() < deadline {
        let pending = CHANNEL.get().map(|(_, rx)| rx.len() as i64).unwrap_or(0);
        if pending == 0 { break; }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if let Some(eng) = ENGINE.get() { eng.flush(timeout_ms) } else { 0 }
}
#[no_mangle]
pub extern "C" fn sql_audit_set_path(path: *const u8, path_len: i64) -> i32 {
    let path_str = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(path, path_len as usize))
    };
    if let Some(eng) = ENGINE.get() { eng.set_output_dir(path_str) } else { -1 }
}

// Phase 2b config
#[no_mangle]
pub extern "C" fn sql_audit_set_max_file_mb(mb: i64) -> i32 {
    if let Some(eng) = ENGINE.get() { eng.set_max_file_mb(mb as u64); 0 } else { -1 }
}
#[no_mangle]
pub extern "C" fn sql_audit_set_retention_files(count: i64) -> i32 {
    if let Some(eng) = ENGINE.get() { eng.set_retention_files(count as usize); 0 } else { -1 }
}
#[no_mangle]
pub extern "C" fn sql_audit_set_retention_policy(halt: i32) -> i32 {
    if let Some(eng) = ENGINE.get() {
        let policy = if halt != 0 { RetentionPolicy::Halt } else { RetentionPolicy::Prune };
        eng.set_retention_policy(policy); 0
    } else { -1 }
}

// Phase 3: NATS config
#[no_mangle]
pub extern "C" fn sql_audit_set_nats_url(url: *const u8, url_len: i64) -> i32 {
    let url_str = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(url, url_len as usize))
    };
    if let Some(eng) = ENGINE.get() { eng.set_nats_url(url_str); 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn sql_audit_set_nats_subject(subject: *const u8, subject_len: i64) -> i32 {
    let subj_str = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(subject, subject_len as usize))
    };
    if let Some(eng) = ENGINE.get() { eng.set_nats_subject(subj_str); 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn sql_audit_set_mode(mode: *const u8, mode_len: i64) -> i32 {
    let mode_str = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(mode, mode_len as usize))
    };
    if let Some(eng) = ENGINE.get() { eng.set_mode(mode_str); 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn sql_audit_get_nats_published() -> i64 {
    if let Some(eng) = ENGINE.get() { eng.nats_published() } else { 0 }
}

#[no_mangle]
pub extern "C" fn sql_audit_get_nats_errors() -> i64 {
    if let Some(eng) = ENGINE.get() { eng.nats_errors() } else { 0 }
}

// Verify + misc
#[no_mangle]
pub extern "C" fn sql_audit_verify(out_head: *mut u8, head_len: i64,
                                   window_start: *mut i64, disk_total: *mut i64) -> i64 {
    if let Some(eng) = ENGINE.get() {
        let head_buf = if !out_head.is_null() && head_len > 0 {
            Some(unsafe { std::slice::from_raw_parts_mut(out_head, head_len as usize) })
        } else { None };
        let ws = if !window_start.is_null() {
            Some(unsafe { &mut *window_start })
        } else { None };
        let dt = if !disk_total.is_null() {
            Some(unsafe { &mut *disk_total })
        } else { None };
        eng.verify_chain(head_buf, ws, dt)
    } else { -2 }
}

#[no_mangle]
pub extern "C" fn sql_audit_get_record_count() -> i64 {
    if let Some(eng) = ENGINE.get() { eng.record_count() } else { 0 }
}

#[no_mangle]
pub extern "C" fn sql_audit_get_file_count() -> i64 {
    if let Some(eng) = ENGINE.get() { eng.file_count() } else { 0 }
}

#[no_mangle]
pub extern "C" fn sql_audit_get_halted() -> i32 {
    if let Some(eng) = ENGINE.get() {
        if eng.is_halted() { 1 } else { 0 }
    } else { 0 }
}

// Phase 4: Connection records + quack attribution (+ C04 reason, r28)
#[no_mangle]
pub extern "C" fn sql_audit_conn_open(conn_id: *const u8, conn_len: i64,
                                         token: *const u8, token_len: i64,
                                         authn_result: *const u8, result_len: i64,
                                         reason: *const u8, reason_len: i64) -> i32 {
    let result = std::panic::catch_unwind(|| {
        if let Some(eng) = ENGINE.get() {
            let cid = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(conn_id, conn_len as usize)) };
            let tok = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(token, token_len as usize)) };
            let res = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(authn_result, result_len as usize)) };
            let rsn = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(reason, reason_len as usize)) };
            eng.conn_open(cid, tok, res, rsn);
        }
    });
    match result { Ok(()) => 0, Err(_) => -1 }
}

#[no_mangle]
pub extern "C" fn sql_audit_capture_stmt(conn_id: *const u8, conn_len: i64,
                                            query: *const u8, query_len: i64) -> i32 {
    let result = std::panic::catch_unwind(|| {
        if let Some(eng) = ENGINE.get() {
            let cid = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(conn_id, conn_len as usize)) };
            let q = unsafe { std::slice::from_raw_parts(query, query_len as usize) };
            eng.capture_with_conn(cid, q);
        }
    });
    match result { Ok(()) => 0, Err(_) => -1 }
}

#[no_mangle]
pub extern "C" fn sql_audit_get_conn_count() -> i64 {
    if let Some(eng) = ENGINE.get() { eng.conn_count() } else { 0 }
}

#[no_mangle]
pub extern "C" fn sql_audit_get_conn_reject_count() -> i64 {
    if let Some(eng) = ENGINE.get() { eng.conn_reject_count() } else { 0 }
}

#[no_mangle]
pub extern "C" fn sql_audit_get_hook_state() -> i32 {
    // Honest minimal state from the Rust side: engine up or not.
    // Richer 3-state (strict_ok/registered/hooked) is computed in C++
    // where the STRICT SetOption result and override invocations live.
    if INITIALIZED.load(Ordering::SeqCst) { 1 } else { 0 }
}

// P4-3: auto-rechain support
#[no_mangle]
pub extern "C" fn sql_audit_sys_event(event_type: *const u8, type_len: i64,
                                      detail: *const u8, detail_len: i64) -> i32 {
    let result = std::panic::catch_unwind(|| {
        if let Some(eng) = ENGINE.get() {
            let et = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(event_type, type_len as usize)) };
            let dt = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(detail, detail_len as usize)) };
            eng.sys_event(et, dt);
        }
    });
    match result { Ok(()) => 0, Err(_) => -1 }
}

#[no_mangle]
pub extern "C" fn sql_audit_conn_reject_add() -> i32 {
    if let Some(eng) = ENGINE.get() { eng.conn_reject(); 0 } else { -1 }
}

// LOW-fix batch (r24)
#[no_mangle]
pub extern "C" fn sql_audit_set_key_file(path: *const u8, path_len: i64) -> i32 {
    let result = std::panic::catch_unwind(|| {
        let p = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(path, path_len as usize)) };
        if let Some(eng) = ENGINE.get() { eng.set_key_file(p) } else { -1 }
    });
    match result { Ok(r) => r, Err(_) => -1 }
}

#[no_mangle]
pub extern "C" fn sql_audit_set_nats_confirm(on: i32) -> i32 {
    if let Some(eng) = ENGINE.get() { eng.set_nats_confirm(on != 0); 0 } else { -1 }
}

