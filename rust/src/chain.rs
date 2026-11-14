use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use std::fs;
use std::path::{Path, PathBuf};
use std::io::Write;

pub struct ChainKey {
    key: Vec<u8>,
}

pub struct AuditChain {
    key: ChainKey,
    seq: u64,
    prev_hmac: String, // hex string of previous entry_hmac
}

type HmacSha256 = Hmac<Sha256>;

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl ChainKey {
    /// Default location: <audit_dir>/chain.key (same disk as records).
    pub fn load_or_create(dir: &Path) -> Result<Self, String> {
        Self::load_or_create_at(&dir.join("chain.key"))
    }

    /// Externalized key file (L1: key on a different mount/vault export than
    /// the audit records). Created with 0600 when missing (first-deploy
    /// convenience); rotating the key at runtime is NOT supported — old
    /// records would fail verification against the new key.
    pub fn load_or_create_at(key_path: &Path) -> Result<Self, String> {
        if key_path.exists() {
            let key = fs::read(key_path).map_err(|e| format!("read key file: {}", e))?;
            if key.len() < 32 {
                return Err("key file too short (min 32 bytes)".to_string());
            }
            Ok(Self { key })
        } else {
            // Generate random key
            let mut key = vec![0u8; 32];
            // Use /dev/urandom on Linux
            if let Ok(mut f) = fs::File::open("/dev/urandom") {
                use std::io::Read;
                f.read_exact(&mut key).map_err(|e| format!("urandom: {}", e))?;
            } else {
                // Fallback: hash of time + pid
                let mut hasher = Sha256::new();
                hasher.update(format!("{}:{}", std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos(),
                    std::process::id()).as_bytes());
                key = hasher.finalize().to_vec();
            }
            // Write with 0600 permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                if let Some(parent) = key_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                fs::OpenOptions::new()
                    .write(true).create_new(true).mode(0o600)
                    .open(key_path)
                    .and_then(|mut f| f.write_all(&key))
                    .map_err(|e| format!("create key file: {}", e))?;
            }
            #[cfg(not(unix))]
            {
                fs::write(key_path, &key).map_err(|e| format!("create key file: {}", e))?;
            }
            Ok(Self { key })
        }
    }

    pub fn hmac_hex(&self, data: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).unwrap();
        mac.update(data);
        hex_encode(&mac.finalize().into_bytes())
    }

    pub fn key_bytes(&self) -> &[u8] {
        &self.key
    }

    pub fn is_same_key(&self, other_dir: &Path) -> bool {
        let other = other_dir.join("chain.key");
        if let Ok(data) = fs::read(&other) {
            return data == self.key;
        }
        false
    }
}

impl AuditChain {
    pub fn new(dir: &Path, resume_seq: u64, resume_prev: Option<String>) -> Result<Self, String> {
        let key = ChainKey::load_or_create(dir)?;
        Ok(Self {
            key,
            seq: resume_seq,
            prev_hmac: resume_prev.unwrap_or_else(|| ZERO_HASH.to_string()),
        })
    }

    /// Chain with an externalized key file (L1). Same resume semantics.
    pub fn new_with_key(key_path: &Path, resume_seq: u64,
                        resume_prev: Option<String>) -> Result<Self, String> {
        let key = ChainKey::load_or_create_at(key_path)?;
        Ok(Self {
            key,
            seq: resume_seq,
            prev_hmac: resume_prev.unwrap_or_else(|| ZERO_HASH.to_string()),
        })
    }

    pub fn key_bytes(&self) -> Vec<u8> {
        self.key.key_bytes().to_vec()
    }

    pub fn seq(&self) -> u64 { self.seq }

    pub fn chain_head(&self) -> &str { &self.prev_hmac }

    /// Undo the last build_entry. Used when the local sink rejects the
    /// record (halt policy): without rollback the in-memory chain advances
    /// over a record that never reaches disk, and every record written
    /// after a halt release would carry a dangling prev_hash.
    pub fn rollback(&mut self, prev_seq: u64, prev_hmac: String) {
        self.seq = prev_seq;
        self.prev_hmac = prev_hmac;
    }

    /// Adopt an external chain position (disk tail written by another
    /// process). Cross-process writers rebase before building so the chain
    /// stays linear instead of forking.
    pub fn rebase(&mut self, seq: u64, prev_hmac: String) {
        self.seq = seq;
        self.prev_hmac = prev_hmac;
    }

    /// Build the next record in the chain.
    /// canonical = "seq|ts|record_type|principal|verdict|query_sha256|prev_hash"
    /// entry_hmac = HMAC(key, canonical)
    /// prev_hash MUST be inside the HMAC: otherwise an attacker can delete a
    /// record and rewire the successor's prev_hash field with all HMACs still
    /// verifying (splice attack, proven 2026-11-13).
    pub fn build_entry(&mut self, ts_ms: i64, record_type: &str,
                       principal: &str, verdict: &str,
                       query_sha256: &str) -> (u64, String) {
        self.seq += 1;
        let canonical = format!("{}|{}|{}|{}|{}|{}|{}",
            self.seq, ts_ms, record_type, principal, verdict, query_sha256, self.prev_hmac);
        let hmac = self.key.hmac_hex(canonical.as_bytes());
        let result = (self.seq, hmac.clone());
        self.prev_hmac = hmac;
        result
    }

    /// Verify a chain entry
    pub fn verify_entry(&self, seq: u64, ts_ms: i64, record_type: &str,
                        principal: &str, verdict: &str,
                        query_sha256: &str, prev_hash: &str,
                        entry_hmac: &str) -> bool {
        let canonical = format!("{}|{}|{}|{}|{}|{}|{}",
            seq, ts_ms, record_type, principal, verdict, query_sha256, prev_hash);
        let expected = self.key.hmac_hex(canonical.as_bytes());
        expected == entry_hmac
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

pub fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
