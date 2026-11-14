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
}

impl Default for NatsSinkConfig {
    fn default() -> Self {
        Self {
            url: "nats://localhost:4222".to_string(),
            subject: "sqlaudit.test".to_string(),
            batch_size: 256,
            batch_timeout_ms: 500,
            confirm: false,
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
        let stream = std::net::TcpStream::connect_timeout(&sock_addr, timeout)
            .map_err(|e| format!("NATS connect {} (3s timeout): {}", addr, e))?;

        // Send CONNECT (minimal)
        use std::io::Write;
        let mut stream = stream;
        let connect_msg = format!(
            "{} {{\"verbose\":false,\"pedantic\":false,\"tls_required\":false,\"name\":\"sql_audit\",\"headers\":false}}\r\n",
            NATS_CONNECT
        );
        stream.write_all(connect_msg.as_bytes())
            .map_err(|e| format!("NATS CONNECT send: {}", e))?;
        stream.write_all(format!("{}\r\n", NATS_PING).as_bytes())
            .map_err(|e| format!("NATS PING send: {}", e))?;

        // Read response (expect INFO + PONG)
        use std::io::Read;
        let mut buf = [0u8; 2048];
        let n = stream.read(&mut buf).map_err(|e| format!("NATS read: {}", e))?;
        let response = String::from_utf8_lossy(&buf[..n]);
        if !response.contains("PONG") && !response.contains("INFO") {
            return Err(format!("NATS unexpected response: {}", &response[..40.min(response.len())]));
        }
        // Parse advertised max_payload (oversize PUB is rejected AND the
        // server drops the connection — proven with a 2MB statement).
        if let Some(pos) = response.find("\"max_payload\"") {
            if let Some(rest) = response[pos..].split(':').nth(1) {
                let num: String = rest.chars()
                    .skip_while(|c| c.is_whitespace())
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if let Ok(v) = num.parse::<u64>() {
                    if v > 0 { self.max_payload = v; }
                }
            }
        }

        self.stream = Some(stream);
        self.connected.store(true, Ordering::SeqCst);
        Ok(())
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
