use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum RetentionPolicy {
    Prune, // Delete oldest files (default)
    Halt,  // Stop writing when limit reached
}

/// Open an audit file for append with 0600 permissions (unix).
fn open_append(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new().create(true).append(true).mode(0o600).open(path)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new().create(true).append(true).open(path)
    }
}

/// Truncate the file after its last PARSEABLE line. A trailing \n alone is
/// not sufficient: a torn line (power loss mid-write) can be glued to a
/// later record by an append racing the reopen, producing one damaged line
/// that ends with \n. Every line from the first unparseable one onward is
/// cut — conservative on corruption, and the gap surfaces via verify's
/// seq-continuity check instead of silently poisoning readers.
fn truncate_torn_tail(path: &Path) {
    let Ok(data) = fs::read(path) else { return };
    if data.is_empty() { return; }
    let mut good_end: u64 = 0; // end offset (incl \n) of last parseable line
    let mut off: u64 = 0;
    for piece in data.split(|&b| b == b'\n') {
        let piece_len = piece.len() as u64;
        let line_end = off + piece_len + 1;
        if !piece.is_empty() {
            let s = String::from_utf8_lossy(piece);
            if serde_json::from_str::<serde_json::Value>(&s).is_ok() {
                good_end = line_end;
            } else {
                break; // damaged line: cut from here
            }
        }
        off = line_end;
    }
    let total = data.len() as u64;
    if good_end < total {
        if let Ok(f) = OpenOptions::new().write(true).open(path) {
            let _ = f.set_len(good_end);
        }
    }
}

/// Inter-process exclusive lock over an audit dir (flock on `<dir>/.lock`).
/// Multiple OS processes can share one audit dir; without serialization each
/// holds its own in-memory chain and the on-disk chain forks. Writers hold
/// this lock across the tail-rebase + build + append span.
pub struct DirLock {
    _file: File,
}

#[cfg(unix)]
impl DirLock {
    pub fn acquire(dir: &Path) -> Option<DirLock> {
        use std::os::unix::io::AsRawFd;
        let path = dir.join(".lock");
        let file = OpenOptions::new().create(true).append(true).open(&path).ok()?;
        let fd = file.as_raw_fd();
        // blocking exclusive flock (EINTR-safe retry)
        loop {
            let r = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if r == 0 { return Some(DirLock { _file: file }); }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return None;
            }
        }
    }
}

#[cfg(windows)]
impl DirLock {
    pub fn acquire(dir: &Path) -> Option<DirLock> {
        use std::os::windows::io::AsRawHandle;
        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
        let path = dir.join(".lock");
        // plain write handle: append-only handles (FILE_APPEND_DATA) get
        // ERROR_ACCESS_DENIED from LockFileEx (proven: probe GetLastError=5)
        let file = OpenOptions::new().create(true).write(true).open(&path).ok()?;
        let handle = file.as_raw_handle() as isize; // windows-sys HANDLE = isize
        // LockFileEx (exclusive, blocking): kernel-released on process death,
        // semantics equivalent to flock(LOCK_EX). Lock byte range [0, 1).
        let mut overlapped: windows_sys::Win32::System::IO::OVERLAPPED = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if ok != 0 {
            Some(DirLock { _file: file })
        } else {
            None
        }
    }
}

#[cfg(not(any(unix, windows)))]
impl DirLock {
    pub fn acquire(_dir: &Path) -> Option<DirLock> {
        // No other targets are in the supported platform set
        None
    }
}

pub struct SinkConfig {
    pub dir: PathBuf,
    pub max_file_mb: u64,
    pub retention_files: usize,
    pub retention_policy: RetentionPolicy,
}

pub struct LocalSink {
    pub(crate) dir: PathBuf,
    pub(crate) max_file_bytes: u64,
    pub(crate) retention_files: usize,
    pub(crate) retention_policy: RetentionPolicy,
    pub(crate) halted: bool,
    /// Disk watermark guard: stop writing when free space < this pct (None=off)
    pub(crate) disk_free_pct: Option<i64>,
    current_file: Option<BufWriter<File>>,
    current_path: PathBuf,
    current_size: u64,
    file_counter: u64,
}

impl LocalSink {
    /// Reopen the sink on the highest-numbered audit file. Called after a
    /// cross-process rebase: another process rotated files under us, so our
    /// old file handle points at a file the reader sorts BEFORE the disk
    /// tail — correct chain values would land in the wrong file order.
    /// Must be called while holding the DirLock.
    pub fn reopen_tail(&mut self) {
        let mut max_counter = 0u64;
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(num) = name.strip_prefix("audit-") {
                    if let Some(num) = num.strip_suffix(".jsonl") {
                        if let Ok(n) = num.parse::<u64>() { max_counter = max_counter.max(n); }
                    }
                }
            }
        }
        if let Some(mut w) = self.current_file.take() { let _ = w.flush(); }
        let path = self.dir.join(format!("audit-{:06}.jsonl", max_counter));
        if let Ok(f) = open_append(&path) {
            let size = f.metadata().map(|m| m.len()).unwrap_or(0);
            self.current_file = Some(BufWriter::new(f));
            self.current_path = path;
            self.current_size = size;
            self.file_counter = max_counter;
        }
    }

    pub fn new(config: SinkConfig) -> Result<Self, String> {
        let dir = config.dir;
        fs::create_dir_all(&dir).map_err(|e| format!("create sink dir: {}", e))?;
        // Audit records contain full SQL text (which may embed secrets) —
        // dir 0700 / files 0600, same hardening as chain.key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        let mut max_counter = 0u64;
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(num) = name.strip_prefix("audit-") {
                    if let Some(num) = num.strip_suffix(".jsonl") {
                        if let Ok(n) = num.parse::<u64>() { max_counter = max_counter.max(n); }
                    }
                }
            }
        }
        // Crash recovery: a torn final line in the previous file (power
        // loss mid-write) would be silently skipped and glue to future
        // appends — truncate it so the gap is clean and detectable.
        if max_counter >= 1 {
            truncate_torn_tail(&dir.join(format!("audit-{:06}.jsonl", max_counter)));
        }
        let counter = max_counter + 1;
        let path = dir.join(format!("audit-{:06}.jsonl", counter));
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new().create(true).append(true).mode(0o600).open(&path)
                .map_err(|e| format!("open {}: {}", path.display(), e))?
        };
        #[cfg(not(unix))]
        let file = OpenOptions::new().create(true).append(true).open(&path)
            .map_err(|e| format!("open {}: {}", path.display(), e))?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            dir, max_file_bytes: config.max_file_mb * 1024 * 1024,
            retention_files: config.retention_files,
            retention_policy: config.retention_policy,
            halted: false,
            disk_free_pct: None,
            current_file: Some(BufWriter::new(file)),
            current_path: path, current_size: size, file_counter: counter,
        })
    }

    pub fn dir(&self) -> &Path { &self.dir }

    pub fn set_max_file_mb(&mut self, mb: u64) {
        self.max_file_bytes = mb * 1024 * 1024;
    }

    pub fn set_retention_files(&mut self, count: usize) {
        self.retention_files = count;
    }

    pub fn set_retention_policy(&mut self, policy: RetentionPolicy) {
        self.retention_policy = policy;
        if policy == RetentionPolicy::Prune { self.halted = false; }
    }

    pub fn set_disk_free_pct(&mut self, pct: Option<i64>) {
        self.disk_free_pct = pct;
    }

    /// Release a disk-guard halt (separate from retention release so causes
    /// can be distinguished if needed later)
    pub fn set_disk_guard_released(&mut self) {
        self.halted = false;
    }

    pub fn is_halted(&self) -> bool { self.halted }

    pub fn append(&mut self, line: &str) -> bool {
        if self.current_file.is_none() || self.halted { return false; }
        let bytes = line.len() as u64 + 1;
        let need_rotate = self.current_size + bytes > self.max_file_bytes;

        if need_rotate {
            // Check retention before rotating
            let file_count = self.count_files();
            match self.retention_policy {
                RetentionPolicy::Halt => {
                    if file_count >= self.retention_files {
                        self.halted = true;
                        return false; // Reject this record
                    }
                }
                RetentionPolicy::Prune => {
                    // Rotate will handle deletion
                }
            }
            self.rotate();
        }

        if let Some(w) = self.current_file.as_mut() {
            let _ = writeln!(w, "{}", line);
            let _ = w.flush();
            self.current_size += bytes;
            return true;
        }
        false
    }

    fn rotate(&mut self) {
        if let Some(mut w) = self.current_file.take() {
            let _ = w.flush();
            let _ = w.get_ref().sync_all();
        }
        // Disk watermark guard: stop writing if free space below threshold
        if let Some(min_pct) = self.disk_free_pct {
            if let Some(free_pct) = disk_free_percent_dir(&self.dir) {
                if (free_pct as i64) < min_pct {
                    self.halted = true;
                    eprintln!("sql_audit: disk guard (free={}%, threshold={}%) — audit halted, SQL continues",
                              free_pct, min_pct);
                    return;
                }
            }
        }
        // Prune old files if policy is Prune
        if self.retention_policy == RetentionPolicy::Prune {
            self.enforce_retention();
        }
        self.file_counter += 1;
        let path = self.dir.join(format!("audit-{:06}.jsonl", self.file_counter));
        #[cfg(unix)]
        let opened = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new().create(true).append(true).mode(0o600).open(&path)
        };
        #[cfg(not(unix))]
        let opened = OpenOptions::new().create(true).append(true).open(&path);
        if let Ok(f) = opened {
            self.current_file = Some(BufWriter::new(f));
            self.current_path = path;
            self.current_size = 0;
        }
    }

    fn enforce_retention(&self) {
        let mut files: Vec<(u64, PathBuf)> = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(num) = name.strip_prefix("audit-") {
                    if let Some(num) = num.strip_suffix(".jsonl") {
                        if let Ok(n) = num.parse::<u64>() { files.push((n, entry.path())); }
                    }
                }
            }
        }
        files.sort_by_key(|(n, _)| *n);
        // Keep at most retention_files - 1 old files (new file will be the Nth)
        let keep = self.retention_files.saturating_sub(1);
        let excess = files.len().saturating_sub(keep);
        for (_, path) in files.into_iter().take(excess) {
            let _ = fs::remove_file(&path);
        }
    }

    fn count_files(&self) -> usize {
        let mut count = 0;
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("audit-") && name.ends_with(".jsonl") { count += 1; }
            }
        }
        count
    }

    pub fn file_count(&self) -> i64 { self.count_files() as i64 }

    /// Last (seq, entry_hmac) on disk: the final complete JSON line of the
    /// highest-numbered non-empty file. Used by cross-process writers to
    /// rebase their in-memory chain before appending. The read window grows
    /// exponentially toward the file head: a single record can exceed any
    /// fixed window (multi-KB SQL is normal), and returning None on a large
    /// tail silently disables the rebase protection.
    pub fn read_tail(dir: &Path) -> Option<(u64, String)> {
        let mut files: Vec<PathBuf> = Vec::new();
        let entries = fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("audit-") && name.ends_with(".jsonl") { files.push(entry.path()); }
        }
        files.sort();
        for path in files.iter().rev() {
            let mut f = match File::open(path) { Ok(f) => f, Err(_) => continue };
            let len = match f.metadata() { Ok(m) => m.len(), Err(_) => continue };
            if len == 0 { continue; }
            use std::io::{Read, Seek, SeekFrom};
            let mut window: u64 = 8192;
            loop {
                let start = len.saturating_sub(window);
                if f.seek(SeekFrom::Start(start)).is_err() { break; }
                let mut bytes = Vec::new();
                if f.read_to_end(&mut bytes).is_err() { break; }
                // lossy: a window boundary may split a multi-byte char; the
                // damaged first line simply fails JSON parsing and is skipped
                let buf = String::from_utf8_lossy(&bytes);
                for line in buf.lines().rev() {
                    let line = line.trim();
                    if line.is_empty() { continue; }
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        let seq = v.get("seq").and_then(|x| x.as_u64())?;
                        let eh = v.get("entry_hmac").and_then(|x| x.as_str())?.to_string();
                        return Some((seq, eh));
                    }
                }
                if start == 0 { break; } // searched the whole file
                window = window.saturating_mul(4);
            }
        }
        None
    }

    pub fn flush(&self) {
        if let Some(w) = self.current_file.as_ref() { let _ = w.get_ref().sync_all(); }
    }

    pub fn existing_record_count(&self) -> u64 {
        self.read_all_records().map(|r| r.len() as u64).unwrap_or(0)
    }

    pub fn read_all_records(&self) -> Result<Vec<serde_json::Value>, String> {
        Self::read_records_in_dir(&self.dir).map(|(r, _)| r)
    }

    /// Read every record under an audit dir. Associated so verify can read a
    /// snapshot WITHOUT holding the sink lock (emit holds chain→sink; verify
    /// must never nest the two in the opposite order or block the consumer).
    /// Returns (records, failed_opens): a file that was listed but vanished
    /// before open (prune racing the walk) must be distinguished from a gap —
    /// the caller re-reads once so policy-prune converges to a clean window
    /// while an attack-deleted MIDDLE file still shows its gap.
    pub fn read_records_in_dir(dir: &Path) -> Result<(Vec<serde_json::Value>, usize), String> {
        let mut records = Vec::new();
        let mut failed = 0usize;
        let mut files: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("audit-") && name.ends_with(".jsonl") { files.push(entry.path()); }
            }
        }
        files.sort();
        for path in files {
            match File::open(&path) {
                Ok(f) => {
                    let reader = BufReader::new(f);
                    for line in reader.lines() {
                        let line = match line { Ok(l) => l, Err(_) => continue };
                        if line.trim().is_empty() { continue; }
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) { records.push(v); }
                    }
                }
                Err(_) => { failed += 1; }
            }
        }
        Ok((records, failed))
    }
}

/// Check free disk space percentage on a directory (platform-specific)
#[cfg(unix)]
pub fn disk_free_percent_dir(dir: &Path) -> Option<u64> {
    use std::ffi::CString;
    let c_path = CString::new(dir.to_str()?).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 || stat.f_blocks == 0 { return None; }
    Some((stat.f_bavail as u64 * 100) / stat.f_blocks as u64)
}

#[cfg(windows)]
pub fn disk_free_percent_dir(dir: &Path) -> Option<u64> {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = dir.to_str()?.encode_utf16().chain(std::iter::once(0)).collect();
    let mut free: u64 = 0;
    let mut total: u64 = 0;
    let mut _tf: u64 = 0;
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, &mut _tf) };
    if ok == 0 || total == 0 { return None; }
    Some((free * 100) / total)
}
