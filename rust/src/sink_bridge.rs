//! Bridge sink: publishes audit messages via the nats_rw extension
//! (replaces the hand-written raw TCP NatsSink).
//!
//! State machine:
//!   Connected → normal publish (via nats_rw through C++ bridge FFI)
//!   Degraded  → engine writes local fallback + 30s retry to recover

use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// C++ bridge FFI (implemented in sql_audit_bridge.cpp)
extern "C" {
    fn sql_audit_bridge_publish(
        subjects: *const *const std::os::raw::c_char,
        payloads: *const *const std::os::raw::c_char,
        count: i64,
        secret_name: *const std::os::raw::c_char,
        confirm: i32,
        timeout_sec: u32,
        err_buf: *mut std::os::raw::c_char,
        err_len: i64,
    ) -> i32;
    fn sql_audit_bridge_probe_function() -> i32;
    fn sql_audit_bridge_try_load_nats_rw() -> i32;
}

const BRIDGE_TIMEOUT_SEC: u32 = 30;
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum BridgeState {
    Connected,
    Degraded {
        since: Instant,
        last_retry: Instant,
        local_fallback_count: u64,
    },
}

pub struct BridgeSink {
    pub state: Mutex<BridgeState>,
    pub published: AtomicI64,
    pub errors: AtomicI64,
    pub secret_name: String,
    pub confirm: bool,
}

impl BridgeSink {
    pub fn new(secret_name: String, confirm: bool) -> Self {
        Self {
            state: Mutex::new(BridgeState::Connected),
            published: AtomicI64::new(0),
            errors: AtomicI64::new(0),
            secret_name,
            confirm,
        }
    }

    /// State machine entry: publish a batch (interface matches old NatsSink).
    /// Returns number successfully published (0 = all went to local fallback).
    pub fn publish_batch(&self, subjects: &[String], payloads: &[String]) -> usize {
        let mut state = self.state.lock().unwrap();
        match &mut *state {
            BridgeState::Connected => {
                match self.bridge_publish(subjects, payloads) {
                    Ok(count) => count,
                    Err(e) => {
                        eprintln!("sql_audit: NATS degraded ({}), falling back to local", e);
                        self.errors.fetch_add(1, Ordering::SeqCst);
                        *state = BridgeState::Degraded {
                            since: Instant::now(),
                            last_retry: Instant::now(),
                            local_fallback_count: 0,
                        };
                        0 // caller (engine) writes local fallback
                    }
                }
            }
            BridgeState::Degraded { last_retry, local_fallback_count, .. } => {
                *local_fallback_count += payloads.len() as u64;
                // Retry recovery at intervals
                if last_retry.elapsed() >= RETRY_INTERVAL {
                    *last_retry = Instant::now();
                    drop(state); // release lock before retry
                    if self.try_recover() {
                        eprintln!("sql_audit: NATS bridge recovered");
                        *self.state.lock().unwrap() = BridgeState::Connected;
                    }
                }
                0 // degraded: local fallback
            }
        }
    }

    /// Internal: call the C++ bridge FFI
    fn bridge_publish(&self, subjects: &[String], payloads: &[String]) -> Result<usize, String> {
        let count = subjects.len();
        if count == 0 { return Ok(0); }
        let mut subj_cstrs: Vec<CString> = Vec::with_capacity(count);
        let mut payload_cstrs: Vec<CString> = Vec::with_capacity(count);
        for i in 0..count {
            subj_cstrs.push(CString::new(subjects[i].clone())
                .map_err(|_| "subject contains NUL".to_string())?);
            payload_cstrs.push(CString::new(payloads[i].clone())
                .map_err(|_| "payload contains NUL".to_string())?);
        }
        let subj_ptrs: Vec<*const std::os::raw::c_char> =
            subj_cstrs.iter().map(|s| s.as_ptr()).collect();
        let payload_ptrs: Vec<*const std::os::raw::c_char> =
            payload_cstrs.iter().map(|s| s.as_ptr()).collect();
        let secret = CString::new(self.secret_name.clone())
            .map_err(|_| "secret_name contains NUL".to_string())?;
        let mut err_buf = vec![0u8; 1024];

        let rc = unsafe {
            sql_audit_bridge_publish(
                subj_ptrs.as_ptr(),
                payload_ptrs.as_ptr(),
                count as i64,
                secret.as_ptr(),
                if self.confirm { 1 } else { 0 },
                BRIDGE_TIMEOUT_SEC,
                err_buf.as_mut_ptr() as *mut std::os::raw::c_char,
                err_buf.len() as i64,
            )
        };

        if rc >= 0 {
            self.published.fetch_add(rc as i64, Ordering::SeqCst);
            Ok(rc as usize)
        } else {
            let msg = unsafe {
                CStr::from_ptr(err_buf.as_ptr() as *const std::os::raw::c_char)
                    .to_string_lossy().into_owned()
            };
            Err(msg)
        }
    }

    /// Internal: probe + try to load nats_rw
    fn try_recover(&self) -> bool {
        unsafe {
            // First check if the function is already available
            if sql_audit_bridge_probe_function() == 0 {
                return true;
            }
            // Try to auto-load nats_rw
            sql_audit_bridge_try_load_nats_rw() == 0
        }
    }

    // === Compatible interface with old NatsSink ===

    pub fn publish(&self, subject: &str, payload: &str) -> bool {
        self.publish_batch(&[subject.to_string()], &[payload.to_string()]) > 0
    }

    pub fn publish_anchor(&self, anchor_subject: &str, chain_head: &str, seq: u64) -> bool {
        let anchor = format!(
            r#"{{"type":"anchor","chain_head":"{}","seq":{}}}"#,
            chain_head, seq
        );
        self.publish(anchor_subject, &anchor)
    }

    pub fn is_connected(&self) -> bool {
        matches!(&*self.state.lock().unwrap(), BridgeState::Connected)
    }

    pub fn get_published(&self) -> i64 {
        self.published.load(Ordering::SeqCst)
    }

    pub fn get_errors(&self) -> i64 {
        self.errors.load(Ordering::SeqCst)
    }

    pub fn get_degraded_fallback_count(&self) -> u64 {
        match &*self.state.lock().unwrap() {
            BridgeState::Degraded { local_fallback_count, .. } => *local_fallback_count,
            BridgeState::Connected => 0,
        }
    }
}
