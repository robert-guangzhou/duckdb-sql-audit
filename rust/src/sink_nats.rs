use std::sync::atomic::{AtomicI64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

// NATS sink using a dedicated thread with synchronous client
// (avoid tokio runtime dependency for simplicity in Phase 3 MVP)

pub struct NatsSinkConfig {
    pub url: String,
    pub subject: String,
    pub batch_size: usize,
    pub batch_timeout_ms: u64,
    /// L3: PING/PONG confirmation after every PUB (server-side processing
    /// ACK). Off by default — costs one round trip per record.
    pub confirm: bool,
    /// Auth credentials (nats_rw-compatible six-param surface)
    pub auth: Option<NatsAuth>,
}

/// NATS authentication credentials — one of four methods
/// (mirrors nats_rw_secret.cpp's six-param surface).
#[derive(Clone, Debug)]
pub enum NatsAuth {
    Token(String),
    UserPass { user: String, pass: String },
    NKey { seed: String },
    Creds { jwt: String, seed: String },
}

impl Default for NatsSinkConfig {
    fn default() -> Self {
        Self {
            url: "nats://localhost:4222".to_string(),
            subject: "sqlaudit.test".to_string(),
            batch_size: 256,
            batch_timeout_ms: 500,
            confirm: false,
            auth: None,
        }
    }
}

// NATS protocol constants
const NATS_PUB: &str = "PUB";
const NATS_CONNECT: &str = "CONNECT";
const NATS_PING: &str = "PING";

/// Minimal synchronous NATS client using raw TCP
/// (avoid async-nats dependency for Phase 3 MVP — no tokio runtime needed)
pub struct NatsSink {
    config: NatsSinkConfig,
    connected: Arc<AtomicBool>,
    published: Arc<AtomicI64>,
    errors: Arc<AtomicI64>,
    stream: Option<std::net::TcpStream>,
    /// Server-advertised max PUB payload (from INFO); oversize PUBs are
    /// rejected AND the server drops the connection.
    max_payload: u64,
    /// L3: confirm each PUB with a PING/PONG round trip.
    confirm: bool,
    /// Counter for segmented-message stream ids.
    stream_id: Arc<std::sync::atomic::AtomicU32>,
    /// Monotonic-ish wall clock of the last reconnect ATTEMPT (ms).
    /// Without a cooldown, a dead server stalls the consumer thread
    /// ~3s per record (connect_timeout), overflowing the capture queue.
    last_attempt_ms: u64,
}

/// Minimum spacing between reconnect attempts; between attempts publish()
/// fails fast (counted as errors) instead of blocking the consumer.
const RECONNECT_COOLDOWN_MS: u64 = 5000;

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl NatsSink {
    pub fn new(config: NatsSinkConfig) -> Result<Self, String> {
        let confirm = config.confirm;
        let mut sink = Self {
            config,
            connected: Arc::new(AtomicBool::new(false)),
            published: Arc::new(AtomicI64::new(0)),
            errors: Arc::new(AtomicI64::new(0)),
            stream: None,
            max_payload: 1048576, // server default; refined from INFO
            confirm,
            stream_id: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            last_attempt_ms: 0,
        };
        sink.connect()?;
        sink.last_attempt_ms = wall_ms();
        Ok(sink)
    }

    fn connect(&mut self) -> Result<(), String> {
        // Parse URL: nats://host:port
        let url = self.config.url.trim_start_matches("nats://");
        let addr = if url.contains(':') {
            url.to_string()
        } else {
            format!("{}:4222", url)
        };

        use std::net::ToSocketAddrs;
        let sock_addr = addr.to_socket_addrs()
            .map_err(|e| format!("NATS resolve {}: {}", addr, e))?
            .next()
            .ok_or_else(|| format!("NATS resolve {}: no address", addr))?;
        let timeout = Duration::from_secs(3);
        let mut stream = std::net::TcpStream::connect_timeout(&sock_addr, timeout)
            .map_err(|e| format!("NATS connect {} (3s timeout): {}", addr, e))?;

        // Read INFO to get nonce (for NKey/JWT auth)
        use std::io::Read;
        let mut buf = [0u8; 2048];
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        let n = stream.read(&mut buf)
            .map_err(|e| format!("NATS read INFO: {}", e))?;
        let info = String::from_utf8_lossy(&buf[..n]).to_string();

        // Parse max_payload and nonce from INFO
        let mut nonce: Option<String> = None;
        if let Some(pos) = info.find("\"max_payload\"") {
            if let Some(rest) = info[pos..].split(':').nth(1) {
                if let Ok(v) = rest.trim().trim_end_matches(',').trim_end_matches('}').parse::<u64>() {
                    if v > 0 { self.max_payload = v; }
                }
            }
        }
        if info.contains("\"nonce\"") {
            if let Some(pos) = info.find("\"nonce\"") {
                let after = &info[pos + 8..];
                if let Some(q1) = after.find('"') {
                    if let Some(q2) = after[q1 + 1..].find('"') {
                        nonce = Some(after[q1 + 1..q1 + 1 + q2].to_string());
                    }
                }
            }
        }

        // Build CONNECT message with auth fields
        let connect_json = self.build_connect_json(&nonce)?;
        let connect_msg = format!("{} {}\r\n", NATS_CONNECT, connect_json);
        use std::io::Write;
        stream.write_all(connect_msg.as_bytes())
            .map_err(|e| format!("NATS CONNECT send: {}", e))?;
        stream.write_all(format!("{}\r\n", NATS_PING).as_bytes())
            .map_err(|e| format!("NATS PING send: {}", e))?;

        // Read response (expect PONG or -ERR)
        let mut buf2 = [0u8; 1024];
        let n = stream.read(&mut buf2).map_err(|e| format!("NATS read: {}", e))?;
        let response = String::from_utf8_lossy(&buf2[..n]);
        if response.contains("-ERR") {
            let err_msg = response.lines()
                .find(|l| l.contains("-ERR"))
                .unwrap_or("unknown error")
                .to_string();
            return Err(format!("NATS auth/connect rejected: {}", err_msg));
        }
        if !response.contains("PONG") && !response.contains("INFO") {
            return Err(format!("NATS unexpected response: {}", &response[..40.min(response.len())]));
        }

        self.stream = Some(stream);
        self.connected.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Build the CONNECT JSON with appropriate auth fields
    /// (nats_rw-compatible: token / user+pass / nkey / jwt+sig)
    fn build_connect_json(&self, nonce: &Option<String>) -> Result<String, String> {
        let base = "\"verbose\":false,\"pedantic\":false,\"tls_required\":false,\"name\":\"sql_audit\",\"headers\":false";
        match &self.config.auth {
            None => Ok(format!("{{{}}}", base)),
            Some(NatsAuth::Token(tok)) => {
                Ok(format!("{{{},{}}}", base, json_str_field("auth_token", tok)))
            }
            Some(NatsAuth::UserPass { user, pass }) => {
                Ok(format!("{{{},{},{}}}", base,
                    json_str_field("user", user),
                    json_str_field("pass", pass)))
            }
            Some(NatsAuth::NKey { seed }) => {
                let n = nonce.as_ref()
                    .ok_or_else(|| "NKey auth requires server nonce".to_string())?;
                let sig = sign_nonce(seed, n)?;
                let pub_key = nkey_public_from_seed(seed)?;
                Ok(format!("{{{},{},{}}}", base,
                    json_str_field("nkey", &pub_key),
                    json_str_field("sig", &sig)))
            }
            Some(NatsAuth::Creds { jwt, seed }) => {
                let n = nonce.as_ref()
                    .ok_or_else(|| "JWT/creds auth requires server nonce".to_string())?;
                let sig = sign_nonce(seed, n)?;
                Ok(format!("{{{},{},{}}}", base,
                    json_str_field("jwt", jwt),
                    json_str_field("sig", &sig)))
            }
        }
    }

    fn ensure_connected(&mut self) -> bool {
        if self.connected.load(Ordering::SeqCst) && self.stream.is_some() {
            return true;
        }
        // Cooldown: attempt a real reconnect at most once per window;
        // fail fast otherwise so the consumer thread never stalls per-record.
        let now = wall_ms();
        if self.last_attempt_ms != 0
            && now.saturating_sub(self.last_attempt_ms) < RECONNECT_COOLDOWN_MS {
            self.errors.fetch_add(1, Ordering::SeqCst); // dropped this publish
            return false;
        }
        self.last_attempt_ms = now;
        match self.connect() {
            Ok(()) => true,
            Err(e) => {
                self.errors.fetch_add(1, Ordering::SeqCst);
                eprintln!("sql_audit NATS reconnect: {}", e);
                false
            }
        }
    }

    /// Publish one logical message. Payloads larger than the server's
    /// max_payload are transparently segmented into binary frames instead
    /// of being rejected (a rejected oversize PUB kills the connection and
    /// every following message inside the reconnect cooldown is lost).
    pub fn publish(&mut self, subject: &str, payload: &str) -> bool {
        let limit = self.max_payload.saturating_sub(512) as usize;
        let sent = if payload.len() > limit {
            self.publish_segmented(subject, payload, limit)
        } else {
            self.send_pub_and_count(subject, payload.as_bytes())
        };
        if sent && self.confirm {
            // L3: server-processing ACK — without it a PUB sitting in a dead
            // peer's TCP buffer still counted as published.
            if !self.confirm_delivery() {
                self.errors.fetch_add(1, Ordering::SeqCst);
                return false;
            }
        }
        if !sent {
            self.errors.fetch_add(1, Ordering::SeqCst);
        }
        sent
    }

    pub fn set_confirm(&mut self, on: bool) { self.confirm = on; }

    /// PING → expect PONG within 200ms (server processed everything sent
    /// before the PING). On timeout the connection is marked dead.
    fn confirm_delivery(&mut self) -> bool {
        use std::io::{Read, Write};
        let Some(stream) = self.stream.as_mut() else { return false; };
        if stream.write_all(format!("{}\r\n", NATS_PING).as_bytes()).is_err() {
            self.connected.store(false, Ordering::SeqCst);
            self.stream = None;
            return false;
        }
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let mut buf = [0u8; 512];
        match stream.read(&mut buf) {
            Ok(n) if n > 0 && String::from_utf8_lossy(&buf[..n]).contains("PONG") => true,
            _ => {
                self.connected.store(false, Ordering::SeqCst);
                self.stream = None;
                false
            }
        }
    }

    /// Wire-level PUB with published-counter increment on success.
    fn send_pub_and_count(&mut self, subject: &str, payload: &[u8]) -> bool {
        if self.send_pub(subject, payload) {
            self.published.fetch_add(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    /// Wire-level PUB write (no counters).
    fn send_pub(&mut self, subject: &str, payload: &[u8]) -> bool {
        if !self.ensure_connected() {
            return false;
        }
        use std::io::Write;
        let mut msg = format!("{} {} {}\r\n", NATS_PUB, subject, payload.len()).into_bytes();
        msg.extend_from_slice(payload);
        msg.extend_from_slice(b"\r\n");
        if let Some(stream) = self.stream.as_mut() {
            match stream.write_all(&msg) {
                Ok(()) => true,
                Err(e) => {
                    self.connected.store(false, Ordering::SeqCst);
                    self.stream = None;
                    eprintln!("sql_audit NATS publish error: {}", e);
                    false
                }
            }
        } else {
            false
        }
    }

    /// Segmented publish for oversize payloads. Frame layout (binary):
    ///   "SQLASEG1" | stream_id u32 BE | idx u16 BE (1-based) | total u16 BE | chunk bytes
    /// Subscribers without SEG support keep receiving normal messages
    /// untouched; SEG-aware subscribers reassemble by (stream_id, idx).
    fn publish_segmented(&mut self, subject: &str, payload: &str, limit: usize) -> bool {
        const SEG_MAGIC: &[u8; 8] = b"SQLASEG1";
        let chunk = limit.min(256 * 1024).max(1024);
        let total = (payload.len() + chunk - 1) / chunk;
        if total > 65535 {
            self.errors.fetch_add(1, Ordering::SeqCst);
            eprintln!("sql_audit NATS: payload needs {} segments (max 65535)", total);
            return false;
        }
        let sid = self.stream_id.fetch_add(1, Ordering::SeqCst).wrapping_add(1) as u32;
        let bytes = payload.as_bytes();
        for idx in 0..total {
            let s = idx * chunk;
            let e = ((idx + 1) * chunk).min(bytes.len());
            let mut frame: Vec<u8> = Vec::with_capacity(SEG_MAGIC.len() + 8 + (e - s));
            frame.extend_from_slice(SEG_MAGIC);
            frame.extend_from_slice(&sid.to_be_bytes());
            frame.extend_from_slice(&((idx as u16 + 1).to_be_bytes()));
            frame.extend_from_slice(&(total as u16).to_be_bytes());
            frame.extend_from_slice(&bytes[s..e]);
            if !self.send_pub(subject, &frame) {
                self.errors.fetch_add(1, Ordering::SeqCst);
                return false;
            }
        }
        // one logical message, not one per frame
        self.published.fetch_add(1, Ordering::SeqCst);
        true
    }

    pub fn publish_batch(&mut self, records: &[String]) -> usize {
        let subject = self.config.subject.clone();
        let mut published = 0;
        for record in records {
            if self.publish(&subject, record) {
                published += 1;
            }
        }
        published
    }

    /// Anchor publication. The caller passes the FULL anchor subject
    /// (`<subject>.anchor` built from the engine's CURRENT config): this
    /// sink's own config.subject is a construction-time snapshot and goes
    /// stale after a subject switch (anchors silently went to the old
    /// subject — caught by G10-anchor, R4).
    pub fn publish_anchor(&mut self, anchor_subject: &str, chain_head: &str, seq: u64) -> bool {
        let anchor = format!(
            r#"{{"type":"anchor","chain_head":"{}","seq":{}}}"#,
            chain_head, seq
        );
        self.publish(anchor_subject, &anchor)
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    pub fn get_published(&self) -> i64 {
        self.published.load(Ordering::SeqCst)
    }

    pub fn get_errors(&self) -> i64 {
        self.errors.load(Ordering::SeqCst)
    }

    pub fn disconnect(&mut self) {
        self.connected.store(false, Ordering::SeqCst);
        self.stream = None;
    }
}

impl Drop for NatsSink {
    fn drop(&mut self) {
        self.disconnect();
    }
}

// ==== NATS NKey helpers (base32 + ed25519 nonce signing) ====

/// JSON-escape a string value and format as `"key":"value"`
fn json_str_field(key: &str, val: &str) -> String {
    let escaped = val
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    format!("\"{}\":\"{}\"", key, escaped)
}

/// RFC 4648 base32 (uppercase, no padding) decode
fn b32_decode(s: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::new();
    for c in s.bytes() {
        let idx = ALPHABET.iter().position(|&a| a == c)
            .ok_or_else(|| format!("invalid base32 char: {}", c as char))?;
        bits = (bits << 5) | idx as u32;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((bits >> nbits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// CRC-16/CCITT XModem (poly 0x1021, init 0, MSB-first) — nkeys checksum
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Decode an NKey seed string (starts with 'S') → raw 32-byte ed25519 private key
fn nkey_seed_to_raw(seed: &str) -> Result<[u8; 32], String> {
    let raw = b32_decode(seed)
        .map_err(|e| format!("nkey seed base32 decode: {}", e))?;
    // [prefix(1)] + [private_key(32)] + [crc(2)] = 35 bytes
    if raw.len() < 35 {
        return Err(format!("nkey seed too short: {} bytes", raw.len()));
    }
    // Verify CRC (little-endian: [crc_lo, crc_hi])
    let crc_stored = (raw[raw.len() - 1] as u16) << 8 | raw[raw.len() - 2] as u16;
    let crc_calc = crc16_ccitt(&raw[..raw.len() - 2]);
    if crc_stored != crc_calc {
        return Err("nkey seed CRC mismatch".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw[1..33]);
    Ok(key)
}

/// Derive the public key string from an NKey seed (for the CONNECT nkey field)
fn nkey_public_from_seed(seed: &str) -> Result<String, String> {
    let raw_priv = nkey_seed_to_raw(seed)?;
    // ed25519 public from private (no external crate — use compact ed25519 math)
    // For MVP, use a minimal scalar multiplication on curve25519
    let public = ed25519_public_key(&raw_priv)
        .map_err(|e| format!("ed25519 derive: {}", e))?;
    // Encode: [USER_PREFIX(160)] + [pub(32)] + [CRC(2)] → base32
    let prefix: u8 = 20 << 3; // User NKey prefix
    let mut out = Vec::with_capacity(35);
    out.push(prefix);
    out.extend_from_slice(&public);
    let crc = crc16_ccitt(&out);
    out.push((crc & 0xFF) as u8);       // little-endian
    out.push(((crc >> 8) & 0xFF) as u8);
    // base32 encode
    const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in &out {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            result.push(B32[((bits >> nbits) & 0x1F) as usize] as char);
        }
    }
    if nbits > 0 {
        result.push(B32[((bits << (5 - nbits)) & 0x1F) as usize] as char);
    }
    Ok(result)
}

/// Sign a server nonce with an NKey seed using ed25519
/// Returns base64-encoded signature
fn sign_nonce(seed: &str, nonce: &str) -> Result<String, String> {
    let raw_priv = nkey_seed_to_raw(seed)?;
    let sig = ed25519_sign(&raw_priv, nonce.as_bytes())
        .map_err(|e| format!("ed25519 sign: {}", e))?;
    // base64 standard encoding
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i + 2 < sig.len() {
        let n = ((sig[i] as u32) << 16) | ((sig[i + 1] as u32) << 8) | sig[i + 2] as u32;
        result.push(B64[((n >> 18) & 0x3F) as usize] as char);
        result.push(B64[((n >> 12) & 0x3F) as usize] as char);
        result.push(B64[((n >> 6) & 0x3F) as usize] as char);
        result.push(B64[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = sig.len() - i;
    if rem == 1 {
        let n = (sig[i] as u32) << 16;
        result.push(B64[((n >> 18) & 0x3F) as usize] as char);
        result.push(B64[((n >> 12) & 0x3F) as usize] as char);
        result.push_str("==");
    } else if rem == 2 {
        let n = ((sig[i] as u32) << 16) | ((sig[i + 1] as u32) << 8);
        result.push(B64[((n >> 18) & 0x3F) as usize] as char);
        result.push(B64[((n >> 12) & 0x3F) as usize] as char);
        result.push(B64[((n >> 6) & 0x3F) as usize] as char);
        result.push('=');
    }
    Ok(result)
}

// ==== ed25519 via ed25519-dalek (well-tested, audited) ====
// The previous inline implementation used X25519 Montgomery curve arithmetic
// for what needs Ed25519 Twisted Edwards curve — mathematically wrong,
// signatures always rejected by the server. Proper crypto needs a proper
// library (rolling your own crypto is a classic security antipattern).

mod ed25519 {
    use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey};

    /// Derive ed25519 public key from 32-byte seed (proper Edwards curve)
    pub fn public_key(seed: &[u8; 32]) -> Result<[u8; 32], String> {
        let sk = SigningKey::from_bytes(seed);
        Ok(sk.verifying_key().to_bytes())
    }

    /// Sign a message with ed25519 (proper EdDSA)
    /// Returns 64-byte signature (R || S)
    pub fn sign(seed: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], String> {
        let sk = SigningKey::from_bytes(seed);
        let sig = sk.sign(msg);
        Ok(sig.to_bytes())
    }

    /// Verify (for self-testing)
    #[allow(dead_code)]
    pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        let vk = match VerifyingKey::from_bytes(public) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let s = ed25519_dalek::Signature::from_bytes(sig);
        vk.verify(msg, &s).is_ok()
    }
}

/// Derive ed25519 public key from raw seed
pub fn ed25519_public_key(seed: &[u8; 32]) -> Result<[u8; 32], String> {
    ed25519::public_key(seed)
}

/// Sign a message with ed25519
pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], String> {
    ed25519::sign(seed, msg)
}
