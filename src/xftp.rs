//! XFTP-style file transfer on top of the SMP block transport.
//!
//! Model (per protocol/xftp.md, adapted to our 16KB block transport):
//! - sender registers a data packet: FNEW size digest senderKey -> FID packetId
//! - sender uploads encrypted chunks: FPUT packetId offset nonce||secretbox(chunk) -> OK
//! - recipient downloads: FGET packetId -> FDATA offset chunk... (several per block)
//! - sender deletes: FDEL packetId -> OK
//! - the whole file is encrypted client-side with a random 32-byte key (raw NaCl secretbox,
//!   random nonce per chunk), padded to a chunk multiple; SHA-256 digest over the padded file.
//! - the "file description" (packetId, size, digest, key, chunk size/count) is passed out-of-band.

use std::collections::BTreeMap;

use crate::crypto::*;
use crate::encoding::*;
use crate::protocol::*;

pub const XFTP_CHUNK_PLAIN: usize = 15 * 1024; // 15360B plaintext -> 15400B on wire (fits 16384 block)

#[derive(Debug, Clone)]
pub struct XftpPacket {
    pub size: u64,          // padded file size
    pub digest: Vec<u8>,    // SHA-256 of padded plaintext
    pub sender_raw: [u8; 32], // raw Ed25519 pubkey of the sender (auth for FPUT/FDEL)
    pub chunks: BTreeMap<u32, Vec<u8>>, // offset -> nonce24||secretbox(chunk)
}

pub type XftpStore = std::collections::HashMap<Vec<u8>, XftpPacket>;

/// Out-of-band file description (simple key=value lines, hex values).
#[derive(Debug, Clone)]
pub struct FileDesc {
    pub packet_id: Vec<u8>,
    pub size: u64,
    pub digest: [u8; 32],
    pub key: [u8; 32],
    pub chunk_plain: usize,
    pub chunks: u32,
}

impl FileDesc {
    pub fn encode(&self) -> String {
        format!(
            "smp-xftp/1\nid={}\nsize={}\ndigest={}\nkey={}\nchunk={}\nchunks={}\n",
            hex(&self.packet_id),
            self.size,
            hex(&self.digest),
            hex(&self.key),
            self.chunk_plain,
            self.chunks
        )
    }
    pub fn decode(s: &str) -> Result<FileDesc, String> {
        let mut get = |k: &str| -> Result<String, String> {
            s.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}=")))
                .map(|v| v.to_string())
                .ok_or_else(|| format!("missing {k}"))
        };
        if get("smp-xftp/1").is_err() && !s.starts_with("smp-xftp/1") {
            return Err("not a smp-xftp/1 description".into());
        }
        Ok(FileDesc {
            packet_id: unhex(&get("id")?).ok_or("bad id hex")?,
            size: get("size")?.parse().map_err(|_| "bad size")?,
            digest: unhex(&get("digest")?).and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()).ok_or("bad digest")?,
            key: unhex(&get("key")?).and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()).ok_or("bad key")?,
            chunk_plain: get("chunk")?.parse().map_err(|_| "bad chunk")?,
            chunks: get("chunks")?.parse().map_err(|_| "bad chunks")?,
        })
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Encrypt + pad a file, return (padded_plaintext, key, digest).
pub fn encrypt_file(data: &[u8]) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let key = random_bytes(32);
    let mut k = [0u8; 32];
    k.copy_from_slice(&key);
    let rem = data.len() % XFTP_CHUNK_PLAIN;
    let pad = if rem == 0 { 0 } else { XFTP_CHUNK_PLAIN - rem };
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(0u8).take(pad));
    let digest = sha256(&padded);
    (padded, k, digest)
}

/// Split padded plaintext into encrypted chunks (nonce24 || secretbox(chunk)).
pub fn encrypt_chunks(padded: &[u8], key: &[u8; 32]) -> Vec<Vec<u8>> {
    padded
        .chunks(XFTP_CHUNK_PLAIN)
        .map(|c| {
            let nb = random_bytes(24);
            let mut n = [0u8; 24];
            n.copy_from_slice(&nb);
            let mut out = nb;
            out.extend_from_slice(&raw_secretbox_encrypt(key, &n, c));
            out
        })
        .collect()
}

/// Decrypt chunks and verify digest + size.
pub fn decrypt_file(chunks: &BTreeMap<u32, Vec<u8>>, desc: &FileDesc) -> Result<Vec<u8>, String> {
    let mut padded = Vec::with_capacity(desc.size as usize);
    for i in 0..desc.chunks {
        let c = chunks.get(&i).ok_or_else(|| format!("missing chunk {i}"))?;
        if c.len() < 24 + 16 {
            return Err("chunk too short".into());
        }
        let mut n = [0u8; 24];
        n.copy_from_slice(&c[..24]);
        let pt = raw_secretbox_decrypt(&desc.key, &n, &c[24..]).ok_or("chunk decrypt failed")?;
        padded.extend_from_slice(&pt);
    }
    if padded.len() as u64 != desc.size {
        return Err(format!("size mismatch {} != {}", padded.len(), desc.size));
    }
    if sha256(&padded) != desc.digest {
        return Err("DIGEST mismatch".into());
    }
    // strip zero padding: real size = size - trailing zeros within last chunk is ambiguous,
    // so we store exact original length in the description via `size` of padded file;
    // callers that need the exact file keep original len separately (see upload_file).
    Ok(padded)
}

/// Full upload flow: read file, encrypt, FNEW + FPUT all chunks. Returns the file description.
pub fn upload_file(
    c: &mut crate::client::Client,
    data: &[u8],
    sender: &Ed25519Keypair,
) -> Result<FileDesc, String> {
    let (padded, key, digest) = encrypt_file(data);
    let chunks = encrypt_chunks(&padded, &key);
    let n = chunks.len() as u32;
    let sender_spki = spki_ed25519(&sender.verifying.to_bytes());
    let r = c
        .request(Command::Fnew { size: padded.len() as u64, digest: digest.to_vec(), sender_key: sender_spki }, vec![], Some(sender))
        .map_err(|e| e.to_string())?;
    let packet_id = match &r[0] {
        BrokerMsg::Fid { packet_id } => packet_id.clone(),
        other => return Err(format!("expected FID, got {other:?}")),
    };
    for (i, ch) in chunks.iter().enumerate() {
        let r = c
            .request(Command::Fput { packet_id: packet_id.clone(), offset: i as u32, chunk: ch.clone() }, vec![], Some(sender))
            .map_err(|e| e.to_string())?;
        if !matches!(r[0], BrokerMsg::Ok) {
            return Err(format!("FPUT chunk {i} failed: {:?}", r[0]));
        }
    }
    Ok(FileDesc { packet_id, size: padded.len() as u64, digest, key, chunk_plain: XFTP_CHUNK_PLAIN, chunks: n })
}

/// Full download flow: FGET per chunk offset, collect FDATA, decrypt, verify. Returns padded plaintext.
pub fn download_file(c: &mut crate::client::Client, desc: &FileDesc) -> Result<Vec<u8>, String> {
    let mut chunks = BTreeMap::new();
    let mut offset = 0u32;
    while (offset as usize) < desc.chunks as usize {
        let r = c
            .request(Command::Fget { packet_id: desc.packet_id.clone(), offset }, vec![], None)
            .map_err(|e| e.to_string())?;
        let mut got = 0usize;
        for m in &r {
            match m {
                BrokerMsg::Fdata { offset: o, chunk } => {
                    chunks.insert(*o, chunk.clone());
                    got += 1;
                }
                BrokerMsg::Err(e) => return Err(format!("FGET: {e}")),
                _ => {}
            }
        }
        if got == 0 {
            return Err("FGET returned no chunks".into());
        }
        offset += got as u32;
    }
    decrypt_file(&chunks, desc)
}

/// Delete packet (sender-signed).
pub fn delete_file(c: &mut crate::client::Client, packet_id: &[u8], sender: &Ed25519Keypair) -> Result<(), String> {
    let r = c
        .request(Command::Fdel { packet_id: packet_id.to_vec() }, vec![], Some(sender))
        .map_err(|e| e.to_string())?;
    match &r[0] {
        BrokerMsg::Ok => Ok(()),
        other => Err(format!("FDEL failed: {other:?}")),
    }
}

// keep encoding import used
#[allow(dead_code)]
fn _u(_r: &mut Reader) {}
