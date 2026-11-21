//! Queue persistence: atomic binary snapshot (write tmp + rename).
//! Format: u32 count, then per queue:
//!   u32 rcv_id_len, rcv_id, u32 snd_id_len, snd_id,
//!   32B rcv_auth_raw, u8 snd_auth_present + 32B, 32B rcv_dh_secret,
//!   u32 msg_count, per msg: u32 msg_id_len, msg_id, u32 body_len, body
//! All integers big-endian. Optional XFTP section and ALG1 auth-alg trailer follow.
//!
//! v0.20 hardening: when env `SMP_STORE_KEY` holds a 64-hex-char 32-byte key, the
//! snapshot is written as `SMP1` magic + 24B nonce + XSalsa20-Poly1305(key, nonce,
//! snapshot) — authenticated encryption (MAC built in). Without the key the legacy
//! plaintext format is written/read (backward compatible).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fs2::FileExt;

use crate::crypto::{random_bytes, secretbox_decrypt, secretbox_encrypt};
use crate::server::{Queue, ServerState};

const ENC_MAGIC: &[u8; 4] = b"SMP1";

/// Store encryption key from env `SMP_STORE_KEY` (hex-encoded 32 bytes).
pub fn store_key() -> Option<[u8; 32]> {
    env_key().ok().flatten()
}

/// SEC-10: if the env var is set but invalid, that is a config error — never silently plaintext.
fn env_key() -> Result<Option<[u8; 32]>, String> {
    match std::env::var("SMP_STORE_KEY") {
        Ok(hex_key) => {
            let bytes = hex::decode(hex_key.trim()).map_err(|e| format!("bad SMP_STORE_KEY hex: {e}"))?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| "SMP_STORE_KEY must be 32 bytes".to_string())?;
            Ok(Some(arr))
        }
        Err(_) => Ok(None),
    }
}

/// Encrypt with an explicitly supplied key (no process-global env lookup).
///
/// The env-driven `seal`/`unseal` are convenient for the server binary but unusable from
/// concurrent code: `SMP_STORE_KEY` is process-global state, so two threads saving with
/// different keys race each other. These variants take the key as an argument.
pub fn seal_with_key(plain: Vec<u8>, key: Option<[u8; 32]>) -> Result<Vec<u8>, String> {
    match key {
        Some(k) => {
            let nb = random_bytes(24);
            let nonce: [u8; 24] = nb.as_slice().try_into().unwrap_or([0u8; 24]);
            let mut out = Vec::with_capacity(4 + 24 + plain.len() + 16);
            out.extend_from_slice(ENC_MAGIC);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&secretbox_encrypt(&k, &nonce, &plain));
            Ok(out)
        }
        None => Ok(plain),
    }
}

/// Decrypt with an explicitly supplied key (no process-global env lookup).
pub fn unseal_with_key(buf: &[u8], key: Option<[u8; 32]>) -> Option<Vec<u8>> {
    if buf.len() >= 4 && &buf[..4] == ENC_MAGIC {
        let k = key?; // encrypted snapshot requires a key — no silent empty state
        if buf.len() < 4 + 24 {
            return None;
        }
        let nonce: [u8; 24] = buf[4..28].try_into().ok()?;
        secretbox_decrypt(&k, &nonce, &buf[28..])
    } else {
        // SEC-10: when a key is configured, a non-SMP1 file is a downgrade attempt — reject it.
        if key.is_some() {
            return None;
        }
        Some(buf.to_vec()) // legacy plaintext snapshot only when no key configured
    }
}

pub fn snapshot_bytes(st: &ServerState) -> Vec<u8> {
    let mut out = Vec::new();
    let qs: Vec<&Queue> = st.by_rcv.values().collect();
    out.extend_from_slice(&(qs.len() as u32).to_be_bytes());
    for q in &qs {
        put_bytes(&mut out, &q.rcv_id);
        put_bytes(&mut out, &q.snd_id);
        out.extend_from_slice(&q.rcv_auth_raw);
        match &q.snd_auth {
            Some(k) => {
                out.push(1);
                out.extend_from_slice(k);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&q.rcv_dh_secret);
        // ntf fields
        match &q.ntf_id {
            Some(nid) => { out.push(1); put_bytes(&mut out, nid); }
            None => out.push(0),
        }
        match &q.ntf_auth_raw {
            Some(k) => { out.push(1); out.extend_from_slice(k); }
            None => out.push(0),
        }
        match &q.rcv_ntf_dh_secret {
            Some(k) => { out.push(1); out.extend_from_slice(k); }
            None => out.push(0),
        }
        out.extend_from_slice(&(q.messages.len() as u32).to_be_bytes());
        for (mid, body) in &q.messages {
            put_bytes(&mut out, mid);
            put_bytes(&mut out, body);
        }
    }
    // XFTP packets (appended; old snapshots simply lack this section)
    out.extend_from_slice(&(st.xftp.len() as u32).to_be_bytes());
    for (pid, p) in &st.xftp {
        put_bytes(&mut out, pid);
        out.extend_from_slice(&p.size.to_be_bytes());
        put_bytes(&mut out, &p.digest);
        out.extend_from_slice(&p.sender_raw);
        out.extend_from_slice(&(p.chunks.len() as u32).to_be_bytes());
        for (off, ch) in &p.chunks {
            out.extend_from_slice(&off.to_be_bytes());
            put_bytes(&mut out, ch);
        }
    }
    // ALG1 trailer: per-queue auth algorithm (same order as `qs`), backward-compatible
    out.extend_from_slice(b"ALG1");
    out.extend_from_slice(&(qs.len() as u32).to_be_bytes());
    for q in &qs {
        out.push(if q.rcv_auth_x { 1 } else { 0 });
    }
    out
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<Vec<u8>> {
        let n = self.u32()? as usize;
        Some(self.take(n)?.to_vec())
    }
}

pub fn parse_snapshot(buf: &[u8]) -> Option<ServerState> {
    let mut r = Reader { buf, pos: 0 };
    let count = r.u32()? as usize;
    let mut st = ServerState::new();
    let mut order: Vec<Vec<u8>> = Vec::new(); // rcv_ids in snapshot order (for ALG1 trailer)
    for _ in 0..count {
        let rcv_id = r.bytes()?;
        let snd_id = r.bytes()?;
        let rcv_auth_raw: [u8; 32] = r.take(32)?.try_into().ok()?;
        let snd_auth = match r.take(1)?[0] {
            1 => Some(r.take(32)?.try_into().ok()?),
            _ => None,
        };
        let rcv_dh_secret: [u8; 32] = r.take(32)?.try_into().ok()?;
        let ntf_id = match r.take(1)?[0] {
            1 => Some(r.bytes()?),
            _ => None,
        };
        let ntf_auth_raw = match r.take(1)?[0] {
            1 => Some(r.take(32)?.try_into().ok()?),
            _ => None,
        };
        let rcv_ntf_dh_secret = match r.take(1)?[0] {
            1 => Some(r.take(32)?.try_into().ok()?),
            _ => None,
        };
        let nmsg = r.u32()? as usize;
        let mut messages = std::collections::VecDeque::new();
        for _ in 0..nmsg {
            let mid = r.bytes()?;
            let body = r.bytes()?;
            messages.push_back((mid, body));
        }
        if let Some(nid) = &ntf_id {
            st.by_ntf.insert(nid.clone(), rcv_id.clone());
        }
        st.by_snd.insert(snd_id.clone(), rcv_id.clone());
        order.push(rcv_id.clone());
        st.by_rcv.insert(
            rcv_id.clone(),
            Queue {
                rcv_id,
                snd_id,
                rcv_auth_raw,
                rcv_auth_x: false, // may be overridden by ALG1 trailer below
                snd_auth,
                rcv_dh_secret,
                messages,
                subscriber: None,
                ntf_id,
                ntf_auth_raw,
                rcv_ntf_dh_secret,
                ntf_subscriber: None,
            },
        );
    }
    // optional XFTP section (absent in older snapshots)
    if r.pos < buf.len() {
        let n = r.u32()? as usize;
        for _ in 0..n {
            let pid = r.bytes()?;
            let size = u64::from_be_bytes(r.take(8)?.try_into().ok()?);
            let digest = r.bytes()?;
            let sender_raw: [u8; 32] = r.take(32)?.try_into().ok()?;
            let nc = r.u32()? as usize;
            let mut chunks = std::collections::BTreeMap::new();
            for _ in 0..nc {
                let off = u32::from_be_bytes(r.take(4)?.try_into().ok()?);
                let ch = r.bytes()?;
                chunks.insert(off, ch);
            }
            st.xftp.insert(
                pid,
                crate::xftp::XftpPacket { size, digest, sender_raw, chunks },
            );
        }
    }
    // optional ALG1 trailer (absent in older snapshots): per-queue rcv_auth_x flags
    if r.pos + 4 <= buf.len() && &buf[r.pos..r.pos + 4] == b"ALG1" {
        r.pos += 4;
        let n = r.u32()? as usize;
        for i in 0..n {
            let flag = r.take(1)?[0];
            if let Some(rcv_id) = order.get(i) {
                if let Some(q) = st.by_rcv.get_mut(rcv_id) {
                    q.rcv_auth_x = flag == 1;
                }
            }
        }
    }
    Some(st)
}

/// Atomic save: write to `<path>.tmp` then rename.
pub fn save(path: &Path, st: &ServerState) -> std::io::Result<()> {
    save_with_key(path, st, env_key().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?)
}

/// Atomic save with an explicit key (does not read `SMP_STORE_KEY`).
pub fn save_with_key(path: &Path, st: &ServerState, key: Option<[u8; 32]>) -> std::io::Result<()> {
    let sealed = seal_with_key(snapshot_bytes(st), key).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // A unique name per write: two threads of the same process would
    // otherwise share the temp path and interleave their writes.
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "store".to_string());
    let tmp = path.with_file_name(format!(".{name}.tmp{}-{seq}", std::process::id()));
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&sealed)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

pub fn load(path: &Path) -> Option<ServerState> {
    load_with_key(path, env_key().ok().flatten())
}

/// Load with an explicit key (does not read `SMP_STORE_KEY`).
pub fn load_with_key(path: &Path, key: Option<[u8; 32]>) -> Option<ServerState> {
    let buf = fs::read(path).ok()?;
    parse_snapshot(&unseal_with_key(&buf, key)?)
}

pub fn default_store_path() -> PathBuf {
    PathBuf::from(std::env::var("SMP_STORE").unwrap_or_else(|_| "smp-queues.bin".to_string()))
}

/// Path of the lock file that guards `path`.
///
/// The lock lives in its own file, NOT in the store file: the store is
/// replaced by rename, which installs a NEW inode — a lock held on the old
/// inode would not protect the new file.
pub fn lock_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".lock");
    path.with_file_name(name)
}

/// Exclusive advisory lock over a store file.
///
/// The store is a whole-file snapshot, so a writer that read the state before
/// another writer saved will silently drop the other writer's queues. Holding
/// this lock across the load-mutate-save cycle closes that window.
///
/// The lock is released when the guard is dropped (or the process exits).
pub struct StoreLock {
    file: fs::File,
    path: PathBuf,
}

impl StoreLock {
    /// The lock file behind this lock.
    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // the fs2 trait method, not std's inherent File::unlock (Rust 1.89+;
        // the crate's MSRV is 1.87)
        let _ = FileExt::unlock(&self.file);
    }
}

fn open_lock_file(path: &Path) -> std::io::Result<fs::File> {
    let lp = lock_path(path);
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(lp)
}

/// Take the exclusive store lock, waiting for a concurrent holder.
///
/// Use this around a load-mutate-save cycle; see [`update_store`].
pub fn lock_store(path: &Path) -> std::io::Result<StoreLock> {
    let file = open_lock_file(path)?;
    file.lock_exclusive()?;
    Ok(StoreLock {
        file,
        path: lock_path(path),
    })
}

/// Take the exclusive store lock without waiting.
///
/// `Ok(None)` means another process holds it — the caller decides whether that
/// is an error (a second relay on the same store) or a normal condition.
pub fn try_lock_store(path: &Path) -> std::io::Result<Option<StoreLock>> {
    let file = open_lock_file(path)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(StoreLock {
            file,
            path: lock_path(path),
        })),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Atomic read-modify-write of the store, safe across processes.
///
/// The lock is held while the state is loaded, while `f` mutates it and while
/// the result is written, so a concurrent writer cannot lose its update (and
/// cannot interleave with ours).
///
/// `f` receives the current state; a missing store is an empty state.
pub fn update_store<F>(path: &Path, key: Option<[u8; 32]>, f: F) -> std::io::Result<()>
where
    F: FnOnce(&mut ServerState),
{
    let _lock = lock_store(path)?;
    let mut st = load_with_key(path, key).unwrap_or_default();
    f(&mut st);
    save_with_key(path, &st, key)
}
