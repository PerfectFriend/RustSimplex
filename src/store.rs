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

use crate::crypto::{random_bytes, secretbox_decrypt, secretbox_encrypt};
use crate::server::{Queue, ServerState};

const ENC_MAGIC: &[u8; 4] = b"SMP1";

/// Store encryption key from env `SMP_STORE_KEY` (hex-encoded 32 bytes).
pub fn store_key() -> Option<[u8; 32]> {
    let hex_key = std::env::var("SMP_STORE_KEY").ok()?;
    let bytes = hex::decode(hex_key.trim()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(arr)
}

fn seal(plain: Vec<u8>) -> Vec<u8> {
    match store_key() {
        Some(k) => {
            let nonce: [u8; 24] = random_bytes(24).try_into().unwrap();
            let mut out = Vec::with_capacity(4 + 24 + plain.len() + 16);
            out.extend_from_slice(ENC_MAGIC);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&secretbox_encrypt(&k, &nonce, &plain));
            out
        }
        None => plain,
    }
}

fn unseal(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() >= 4 && &buf[..4] == ENC_MAGIC {
        let k = store_key()?;
        if buf.len() < 4 + 24 {
            return None;
        }
        let nonce: [u8; 24] = buf[4..28].try_into().ok()?;
        secretbox_decrypt(&k, &nonce, &buf[28..])
    } else {
        Some(buf.to_vec()) // legacy plaintext snapshot
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
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&seal(snapshot_bytes(st)))?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

pub fn load(path: &Path) -> Option<ServerState> {
    let buf = fs::read(path).ok()?;
    parse_snapshot(&unseal(&buf)?)
}

pub fn default_store_path() -> PathBuf {
    PathBuf::from(std::env::var("SMP_STORE").unwrap_or_else(|_| "smp-queues.bin".to_string()))
}
