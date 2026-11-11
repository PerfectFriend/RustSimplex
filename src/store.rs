//! Queue persistence: atomic binary snapshot (write tmp + rename).
//! Format: u32 count, then per queue:
//!   u32 rcv_id_len, rcv_id, u32 snd_id_len, snd_id,
//!   32B rcv_auth_raw, u8 snd_auth_present + 32B, 32B rcv_dh_secret,
//!   u32 msg_count, per msg: u32 msg_id_len, msg_id, u32 body_len, body
//! All integers big-endian.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::server::{Queue, ServerState};

pub fn snapshot_bytes(st: &ServerState) -> Vec<u8> {
    let mut out = Vec::new();
    let qs: Vec<&Queue> = st.by_rcv.values().collect();
    out.extend_from_slice(&(qs.len() as u32).to_be_bytes());
    for q in qs {
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
        out.extend_from_slice(&(q.messages.len() as u32).to_be_bytes());
        for (mid, body) in &q.messages {
            put_bytes(&mut out, mid);
            put_bytes(&mut out, body);
        }
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
    for _ in 0..count {
        let rcv_id = r.bytes()?;
        let snd_id = r.bytes()?;
        let rcv_auth_raw: [u8; 32] = r.take(32)?.try_into().ok()?;
        let snd_auth = match r.take(1)?[0] {
            1 => Some(r.take(32)?.try_into().ok()?),
            _ => None,
        };
        let rcv_dh_secret: [u8; 32] = r.take(32)?.try_into().ok()?;
        let nmsg = r.u32()? as usize;
        let mut messages = std::collections::VecDeque::new();
        for _ in 0..nmsg {
            let mid = r.bytes()?;
            let body = r.bytes()?;
            messages.push_back((mid, body));
        }
        st.by_snd.insert(snd_id.clone(), rcv_id.clone());
        st.by_rcv.insert(
            rcv_id.clone(),
            Queue {
                rcv_id,
                snd_id,
                rcv_auth_raw,
                snd_auth,
                rcv_dh_secret,
                messages,
                subscriber: None,
            },
        );
    }
    Some(st)
}

/// Atomic save: write to `<path>.tmp` then rename.
pub fn save(path: &Path, st: &ServerState) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&snapshot_bytes(st))?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

pub fn load(path: &Path) -> Option<ServerState> {
    let buf = fs::read(path).ok()?;
    parse_snapshot(&buf)
}

pub fn default_store_path() -> PathBuf {
    PathBuf::from(std::env::var("SMP_STORE").unwrap_or_else(|_| "smp-queues.bin".to_string()))
}
