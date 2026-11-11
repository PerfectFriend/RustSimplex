//! SMP wire-encoding primitives, faithful to the Haskell reference
//! (`simplexmq`, `Simplex.Messaging.Encoding`):
//!   - shortString  = 1-byte length + bytes        (Encoding ByteString)
//!   - largeString  = 2-byte BE length + bytes     (Large)
//!   - Maybe a      = "0" | "1" <> encode(a)
//!   - Bool         = "T" | "F"
//!   - Word16/Word32/Int64 = big-endian
//!   - pad(msg, N)  = word16BE(len) <> msg <> '#' * (N - len - 2)

pub const BLOCK_SIZE: usize = 16384;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeError(pub String);

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncodeError: {}", self.0)
    }
}
impl std::error::Error for EncodeError {}

pub fn w_short(out: &mut Vec<u8>, b: &[u8]) -> Result<(), EncodeError> {
    if b.len() > 255 {
        return Err(EncodeError(format!("shortString too long: {}", b.len())));
    }
    out.push(b.len() as u8);
    out.extend_from_slice(b);
    Ok(())
}

pub fn w_large(out: &mut Vec<u8>, b: &[u8]) -> Result<(), EncodeError> {
    if b.len() > u16::MAX as usize {
        return Err(EncodeError(format!("largeString too long: {}", b.len())));
    }
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

pub fn w_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
pub fn w_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
pub fn w_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_be_bytes());
}
pub fn w_bool(out: &mut Vec<u8>, b: bool) {
    out.push(if b { b'T' } else { b'F' });
}
/// Maybe a encoding: "0" or "1" <> inner
pub fn w_maybe(out: &mut Vec<u8>, inner: Option<&[u8]>) -> Result<(), EncodeError> {
    match inner {
        None => out.push(b'0'),
        Some(b) => {
            out.push(b'1');
            out.extend_from_slice(b);
        }
    }
    Ok(())
}

pub struct Reader<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}
impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { buf: b, pos: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], EncodeError> {
        if self.pos + n > self.buf.len() {
            return Err(EncodeError("eof".into()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, EncodeError> {
        Ok(self.take(1)?[0])
    }
    pub fn peek_u8(&self) -> Result<u8, EncodeError> {
        if self.pos >= self.buf.len() {
            return Err(EncodeError("eof".into()));
        }
        Ok(self.buf[self.pos])
    }
    pub fn u16(&mut self) -> Result<u16, EncodeError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn short(&mut self) -> Result<Vec<u8>, EncodeError> {
        let n = self.u8()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    pub fn large(&mut self) -> Result<Vec<u8>, EncodeError> {
        let n = self.u16()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
    pub fn bool(&mut self) -> Result<bool, EncodeError> {
        match self.u8()? {
            b'T' => Ok(true),
            b'F' => Ok(false),
            c => Err(EncodeError(format!("bad bool {c}"))),
        }
    }
    pub fn maybe_marker(&mut self) -> Result<bool, EncodeError> {
        match self.u8()? {
            b'0' => Ok(false),
            b'1' => Ok(true),
            c => Err(EncodeError(format!("bad maybe {c}"))),
        }
    }
}

/// pad(msg, total) = word16BE(len) <> msg <> '#' * (total - len - 2)
pub fn pad(msg: &[u8], total: usize) -> Result<Vec<u8>, EncodeError> {
    if msg.len() + 2 > total {
        return Err(EncodeError("pad overflow".into()));
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    let pad_len = total - msg.len() - 2;
    out.extend(std::iter::repeat(b'#').take(pad_len));
    Ok(out)
}

/// unpad: read word16BE len, take len bytes, ignore trailing '#'
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let mut r = Reader::new(padded);
    let len = r.u16()? as usize;
    Ok(r.take(len)?.to_vec())
}
