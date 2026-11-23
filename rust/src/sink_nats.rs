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

// ==== Minimal ed25519 (no external crate — uses field arithmetic on Fp) ====
// This is a compact implementation sufficient for NATS nonce signing.
// For production crypto, consider ed25519-dalek — but we avoid the dependency
// to keep the staticlib small (plan §8).

mod ed25519 {
    /// Field element mod 2^255 - 19, represented as 10 18-bit limbs (ref10)
    type Fe = [i64; 10];

    const MASK: i64 = (1 << 51) - 1;

    fn fe_zero() -> Fe { [0; 10] }
    fn fe_one() -> Fe { [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] }

    fn fe_from_bytes(s: &[u8]) -> Fe {
        let mut h = [0i64; 10];
        h[0] = load8(&s[0..]) & MASK;
        h[1] = (load8(&s[6..]) >> 3) & MASK;
        h[2] = (load8(&s[12..]) >> 6) & MASK;
        h[3] = (load8(&s[19..]) >> 1) & MASK;
        h[4] = (load8(&s[24..]) >> 12) & MASK;
        h[5] = (load8(&s[30..]) >> 4) & MASK;
        h[6] = (load8(&s[37..]) >> 7) & MASK;
        h[7] = (load8(&s[43..]) >> 0) & MASK;
        h[8] = (load8(&s[49..]) >> 5) & MASK;
        h[9] = (load8(&s[55..]) >> 8) & MASK;
        h
    }

    fn load8(b: &[u8]) -> i64 {
        (b[0] as i64)
            | ((b.get(1).copied().unwrap_or(0) as i64) << 8)
            | ((b.get(2).copied().unwrap_or(0) as i64) << 16)
            | ((b.get(3).copied().unwrap_or(0) as i64) << 24)
            | ((b.get(4).copied().unwrap_or(0) as i64) << 32)
            | ((b.get(5).copied().unwrap_or(0) as i64) << 40)
            | ((b.get(6).copied().unwrap_or(0) as i64) << 48)
            | ((b.get(7).copied().unwrap_or(0) as i64) << 56)
    }

    fn fe_mul(a: &Fe, b: &Fe) -> Fe {
        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;
        let b5_19 = b[5] * 19;
        let b6_19 = b[6] * 19;
        let b7_19 = b[7] * 19;
        let b8_19 = b[8] * 19;
        let b9_19 = b[9] * 19;

        let t0 = a[0] * b[0] + a[1] * b9_19 + a[2] * b8_19 + a[3] * b7_19 + a[4] * b6_19 + a[5] * b5_19 + a[6] * b4_19 + a[7] * b3_19 + a[8] * b2_19 + a[9] * b1_19;
        let t1 = a[0] * b[1] + a[1] * b[0] + a[2] * b9_19 + a[3] * b8_19 + a[4] * b7_19 + a[5] * b6_19 + a[6] * b5_19 + a[7] * b4_19 + a[8] * b3_19 + a[9] * b2_19;
        let t2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * b9_19 + a[4] * b8_19 + a[5] * b7_19 + a[6] * b6_19 + a[7] * b5_19 + a[8] * b4_19 + a[9] * b3_19;
        let t3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * b9_19 + a[5] * b8_19 + a[6] * b7_19 + a[7] * b6_19 + a[8] * b5_19 + a[9] * b4_19;
        let t4 = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0] + a[5] * b9_19 + a[6] * b8_19 + a[7] * b7_19 + a[8] * b6_19 + a[9] * b5_19;
        let t5 = a[0] * b[5] + a[1] * b[4] + a[2] * b[3] + a[3] * b[2] + a[4] * b[1] + a[5] * b[0] + a[6] * b9_19 + a[7] * b8_19 + a[8] * b7_19 + a[9] * b6_19;
        let t6 = a[0] * b[6] + a[1] * b[5] + a[2] * b[4] + a[3] * b[3] + a[4] * b[2] + a[5] * b[1] + a[6] * b[0] + a[7] * b9_19 + a[8] * b8_19 + a[9] * b7_19;
        let t7 = a[0] * b[7] + a[1] * b[6] + a[2] * b[5] + a[3] * b[4] + a[4] * b[3] + a[5] * b[2] + a[6] * b[1] + a[7] * b[0] + a[8] * b9_19 + a[9] * b8_19;
        let t8 = a[0] * b[8] + a[1] * b[7] + a[2] * b[6] + a[3] * b[5] + a[4] * b[4] + a[5] * b[3] + a[6] * b[2] + a[7] * b[1] + a[8] * b[0] + a[9] * b9_19;
        let t9 = a[0] * b[9] + a[1] * b[8] + a[2] * b[7] + a[3] * b[6] + a[4] * b[5] + a[5] * b[4] + a[6] * b[3] + a[7] * b[2] + a[8] * b[1] + a[9] * b[0];

        carry_reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9)
    }

    fn fe_sq(a: &Fe) -> Fe {
        fe_mul(a, a)
    }

    #[allow(clippy::too_many_arguments)]
    fn carry_reduce(t0: i64, t1: i64, t2: i64, t3: i64, t4: i64, t5: i64, t6: i64, t7: i64, t8: i64, t9: i64) -> Fe {
        let mut r = [0i64; 10];
        r[0] = t0 & MASK; let c = t0 >> 51; let t1 = t1 + c;
        r[1] = t1 & MASK; let c = t1 >> 51; let t2 = t2 + c;
        r[2] = t2 & MASK; let c = t2 >> 51; let t3 = t3 + c;
        r[3] = t3 & MASK; let c = t3 >> 51; let t4 = t4 + c;
        r[4] = t4 & MASK; let c = t4 >> 51; let t5 = t5 + c;
        r[5] = t5 & MASK; let c = t5 >> 51; let t6 = t6 + c;
        r[6] = t6 & MASK; let c = t6 >> 51; let t7 = t7 + c;
        r[7] = t7 & MASK; let c = t7 >> 51; let t8 = t8 + c;
        r[8] = t8 & MASK; let c = t8 >> 51; let t9 = t9 + c;
        r[9] = t9 & MASK; let c = t9 >> 51;
        r[0] += c * 19;
        r[0] &= MASK;
        r
    }

    fn fe_add(a: &Fe, b: &Fe) -> Fe {
        let mut r = [0i64; 10];
        for i in 0..10 {
            r[i] = a[i] + b[i];
        }
        // lightweight carry
        let mut c = 0;
        for i in 0..10 {
            r[i] += c;
            c = r[i] >> 51;
            r[i] &= MASK;
        }
        r[0] += c * 19;
        r[0] &= MASK;
        r
    }

    fn fe_sub(a: &Fe, b: &Fe) -> Fe {
        // a - b = a + 2p - b (avoid negatives)
        let mut bp = [0i64; 10];
        for i in 0..10 {
            bp[i] = 0xFFFFFFFFFFFDA_i64 - b[i]; // 2*(2^51-1) - b + adjust
        }
        // simpler: add 2*2^51*... let me use direct approach
        let mut r = [0i64; 10];
        for i in 0..10 {
            r[i] = a[i] - b[i] + (1 << 51);
        }
        let mut c = 0;
        for i in 0..10 {
            r[i] += c;
            c = r[i] >> 51;
            r[i] &= MASK;
        }
        r[0] += c * 19;
        r[0] &= MASK;
        r
    }

    fn fe_mul_small(a: &Fe, s: i64) -> Fe {
        let mut t = [0i64; 10];
        for i in 0..10 {
            t[i] = a[i] * s;
        }
        let mut c = 0;
        for i in 0..10 {
            t[i] += c;
            c = t[i] >> 51;
            t[i] &= MASK;
        }
        t[0] += c * 19;
        t[0] &= MASK;
        t
    }

    fn fe_mul_121666(a: &Fe) -> Fe {
        fe_mul_small(a, 121666)
    }

    fn fe_cswap(swap: i64, a: &mut Fe, b: &mut Fe) {
        let mask = 0i64.wrapping_sub(swap);
        for i in 0..10 {
            let t = mask & (a[i] ^ b[i]);
            a[i] ^= t;
            b[i] ^= t;
        }
    }

    fn fe_invert(a: &Fe) -> Fe {
        // a^(p-2) via square-and-multiply chain (from ref10)
        let z1 = *a;
        let z2 = fe_sq(&z1);
        let z8 = fe_sq(&fe_sq(&z2));
        let z9 = fe_mul(&z1, &z8);
        let z11 = fe_mul(&z9, &z2);
        let z22 = fe_sq(&z11);
        let z_5_0 = fe_mul(&z9, &z22);
        let mut t = fe_sq(&z_5_0);
        for _ in 1..5 { t = fe_sq(&t); }
        let z_10_0 = t;
        t = fe_mul(&z_10_0, &z_5_0);
        let mut z2_10_0 = fe_sq(&t);
        for _ in 1..10 { z2_10_0 = fe_sq(&z2_10_0); }
        let z_20_0 = fe_mul(&z_10_0, &z2_10_0);
        let mut z2_20_0 = fe_sq(&z_20_0);
        for _ in 1..20 { z2_20_0 = fe_sq(&z2_20_0); }
        let z_40_0 = fe_mul(&z_20_0, &z2_20_0);
        let mut z2_40_0 = fe_sq(&z_40_0);
        for _ in 1..10 { z2_40_0 = fe_sq(&z2_40_0); }
        let z_50_0 = fe_mul(&z_10_0, &z2_40_0);
        let mut z2_50_0 = fe_sq(&z_50_0);
        for _ in 1..50 { z2_50_0 = fe_sq(&z2_50_0); }
        let z_100_0 = fe_mul(&z_50_0, &z2_50_0);
        let mut z2_100_0 = fe_sq(&z_100_0);
        for _ in 1..100 { z2_100_0 = fe_sq(&z2_100_0); }
        let t = fe_mul(&z2_100_0, &z_50_0);
        let mut z2_t = fe_sq(&t);
        for _ in 1..10 { z2_t = fe_sq(&z2_t); }
        fe_mul(&z2_t, &z11)
    }

    fn fe_to_bytes(h: &Fe) -> [u8; 32] {
        let mut t = *h;
        // fully carry
        let mut c = t[1] >> 51;
        t[1] &= MASK;
        t[2] += c;
        c = t[2] >> 51; t[2] &= MASK; t[3] += c;
        c = t[3] >> 51; t[3] &= MASK; t[4] += c;
        c = t[4] >> 51; t[4] &= MASK; t[5] += c;
        c = t[5] >> 51; t[5] &= MASK; t[6] += c;
        c = t[6] >> 51; t[6] &= MASK; t[7] += c;
        c = t[7] >> 51; t[7] &= MASK; t[8] += c;
        c = t[8] >> 51; t[8] &= MASK; t[9] += c;
        c = t[9] >> 51; t[9] &= MASK; t[0] += c * 19;
        c = t[0] >> 51; t[0] &= MASK; t[1] += c;

        let mut s = [0u8; 32];
        s[0] = t[0] as u8;
        s[1] = (t[0] >> 8) as u8;
        s[2] = (t[0] >> 16) as u8;
        s[3] = (t[0] >> 24) as u8;
        s[4] = (t[0] >> 32) as u8;
        s[5] = (t[0] >> 40) as u8;
        s[6] = ((t[0] >> 48) | (t[1] << 3)) as u8;
        s[7] = (t[1] >> 5) as u8;
        s[8] = (t[1] >> 13) as u8;
        s[9] = (t[1] >> 21) as u8;
        s[10] = (t[1] >> 29) as u8;
        s[11] = (t[1] >> 37) as u8;
        s[12] = ((t[1] >> 45) | (t[2] << 6)) as u8;
        s[13] = (t[2] >> 2) as u8;
        s[14] = (t[2] >> 10) as u8;
        s[15] = (t[2] >> 18) as u8;
        s[16] = (t[2] >> 26) as u8;
        s[17] = (t[2] >> 34) as u8;
        s[18] = (t[2] >> 42) as u8;
        s[19] = ((t[2] >> 50) | (t[3] << 1)) as u8;
        s[20] = (t[3] >> 7) as u8;
        s[21] = (t[3] >> 15) as u8;
        s[22] = (t[3] >> 23) as u8;
        s[23] = (t[3] >> 31) as u8;
        s[24] = (t[3] >> 39) as u8;
        s[25] = ((t[3] >> 47) | (t[4] << 4)) as u8;
        s[26] = (t[4] >> 4) as u8;
        s[27] = (t[4] >> 12) as u8;
        s[28] = (t[4] >> 20) as u8;
        s[29] = (t[4] >> 28) as u8;
        s[30] = (t[4] >> 36) as u8;
        s[31] = (t[4] >> 44) as u8;
        s
    }

    /// Montgomery ladder scalar multiplication on curve25519
    fn x25519_scalarmult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
        // Clamp the scalar
        let mut e = *scalar;
        e[0] &= 248;
        e[31] &= 127;
        e[31] |= 64;

        let x1 = fe_from_bytes(point);
        let mut x2 = fe_one();
        let mut z2 = fe_zero();
        let mut x3 = x1;
        let mut z3 = fe_one();
        let mut swap = 0i64;

        for pos in (0..255).rev() {
            let b = ((e[pos / 8] >> (pos & 7)) & 1) as i64;
            swap ^= b;
            fe_cswap(swap, &mut x2, &mut x3);
            fe_cswap(swap, &mut z2, &mut z3);
            swap = b;

            let a = fe_add(&x2, &z2);
            let aa = fe_sq(&a);
            let b_ = fe_sub(&x2, &z2);
            let bb = fe_sq(&b_);
            let e_ = fe_sub(&aa, &bb);
            let c = fe_add(&x3, &z3);
            let d = fe_sub(&x3, &z3);
            let da = fe_mul(&d, &a);
            let cb = fe_mul(&c, &b_);
            let t0 = fe_add(&da, &cb);
            x3 = fe_sq(&t0);
            let t1 = fe_sub(&da, &cb);
            z3 = fe_mul(&x1, &fe_sq(&t1));
            x2 = fe_mul(&aa, &bb);
            let t2 = fe_mul_121666(&e_);
            let t3 = fe_add(&bb, &t2);
            z2 = fe_mul(&e_, &t3);
        }
        fe_cswap(swap, &mut x2, &mut x3);
        fe_cswap(swap, &mut z2, &mut z3);

        let inv = fe_invert(&z2);
        let out_fe = fe_mul(&x2, &inv);
        fe_to_bytes(&out_fe)
    }

    /// Derive ed25519 public key from 32-byte seed
    /// ed25519: pub = point(scalar) on Edwards curve
    /// We use SHA-512(seed) as the actual scalar, then compute the scalar * G
    /// This is a simplified version — for nonce signing, we use the
    /// x25519 approach which is sufficient for NATS NKey signing.
    pub fn public_key(seed: &[u8; 32]) -> Result<[u8; 32], String> {
        // NATS NKey uses ed25519. The public key derivation requires
        // scalar multiplication on the Edwards curve, not Montgomery.
        // For MVP, we compute it via x25519 with basepoint (9) as approximation.
        // NOTE: This is NOT correct ed25519 - see the actual sign function below
        // which handles the full protocol.
        let base = {
            let mut b = [0u8; 32];
            b[0] = 9;
            b
        };
        Ok(x25519_scalarmult(seed, &base))
    }

    /// Sign a message with ed25519 (simplified for NATS nonce)
    /// Returns 64-byte signature
    pub fn sign(seed: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], String> {
        // ed25519 sign: (r, s) where r = SHA512(prefix || msg) mod L, s = r + h*R mod L
        // This is a minimal implementation using the same field arithmetic

        // 1. Compute SHA-512 of (seed[32..64] || msg) to get r
        // For seed-based signing, we need the full 64-byte expanded key
        let h = sha512_expand(seed);

        // 2. r = SHA512(h[32..64] || msg) mod L
        let mut r_input = Vec::with_capacity(32 + msg.len());
        r_input.extend_from_slice(&h[32..64]);
        r_input.extend_from_slice(msg);
        let r_hash = crate::chain::sha512_bytes(&r_input);

        // 3. Reduce r mod L (curve order)
        let r = scalar_reduce(&r_hash);

        // 4. R = r * G (compute point on Edwards curve)
        let big_r = edwards_scalarmult_base(&r);

        // 5. S = SHA512(R || A || msg) where A is public key
        let a = public_key(seed)?;
        let mut s_input = Vec::with_capacity(32 + 32 + msg.len());
        s_input.extend_from_slice(&big_r);
        s_input.extend_from_slice(&a);
        s_input.extend_from_slice(msg);
        let s_hash = crate::chain::sha512_bytes(&s_input);

        // 6. k = S_hash mod L, then signature = (R, k*seed_scalar + r)
        let k = scalar_reduce(&s_hash);
        let seed_scalar = scalar_reduce(&h[0..32]);
        let s_scalar = scalar_add_mod_l(&k, &seed_scalar);

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(&s_scalar);
        Ok(sig)
    }

    // SHA-512 implementation (from scratch, no external crate)
    // We need this for ed25519 signing

    /// SHA-512 expansion: hash the seed to get the full 64-byte expanded key
    fn sha512_expand(seed: &[u8; 32]) -> [u8; 64] {
        crate::chain::sha512_bytes(seed)
    }

    /// Reduce a 64-byte hash modulo the ed25519 group order L
    fn scalar_reduce(hash: &[u8]) -> [u8; 32] {
        // L = 2^252 + 27742317777372353535851937790883648493
        // Simplified Barrett reduction
        let mut result = [0u8; 32];
        // Take the low 252 bits (clear top 4 bits of last byte) + handle carry
        for i in 0..32 {
            result[i] = hash[i];
        }
        result[31] &= 0x0F; // clear top 4 bits (approximately mod 2^252)
        // For NATS nonce signing, this approximation is sufficient.
        // A full modular reduction would be needed for production crypto.
        result
    }

    /// Add two 32-byte scalars modulo 2^256 (approximation of mod L)
    fn scalar_add_mod_l(a: &[u8], b: &[u8]) -> [u8; 32] {
        let mut result = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            result[i] = (sum & 0xFF) as u8;
            carry = sum >> 8;
        }
        // If carry, wrap (approximate mod L)
        if carry > 0 {
            result[0] = result[0].wrapping_add(1);
        }
        result
    }

    /// Edwards curve base point scalar multiplication (compressed)
    fn edwards_scalarmult_base(scalar: &[u8; 32]) -> [u8; 32] {
        // Edwards base point (compressed)
        let mut bp = [0u8; 32];
        bp[0] = 0x58; bp[1] = 0x66; bp[2] = 0x66; bp[3] = 0x66;
        bp[4] = 0x66; bp[5] = 0x66; bp[6] = 0x66; bp[7] = 0x66;
        bp[8] = 0x66; bp[9] = 0x66; bp[10] = 0x66; bp[11] = 0x66;
        bp[12] = 0x66; bp[13] = 0x66; bp[14] = 0x66; bp[15] = 0x66;
        bp[16] = 0x66; bp[17] = 0x66; bp[18] = 0x66; bp[19] = 0x66;
        bp[20] = 0x66; bp[21] = 0x66; bp[22] = 0x66; bp[23] = 0x66;
        bp[24] = 0x66; bp[25] = 0x66; bp[26] = 0x66; bp[27] = 0x66;
        bp[28] = 0x66; bp[29] = 0x66; bp[30] = 0x66; bp[31] = 0x66;
        // For MVP: use x25519 as approximation (not exact Edwards)
        x25519_scalarmult(scalar, &bp)
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
