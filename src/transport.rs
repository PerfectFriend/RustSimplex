//! Transport: SMP handshake blocks + fixed-size block I/O over a byte stream.
//!
//! After (optional) TLS, the router sends `paddedRouterHello`, the client
//! answers `paddedClientHello`. Both are padded to 16384 bytes.
//!   routerHello = word16 minVer <> word16 maxVer <> shortString sessionId <> [routerCertKey] <> ignored
//!   clientHello = word16 version <> shortString keyHash <> [clientKey] <> 'T'/'F' proxy <> '0'/'1' service <> ignored
//! For plain TCP (no TLS) we omit the cert key and use sessionId = "".

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::encoding::*;

pub fn server_hello_block(min_v: u16, max_v: u16, session_id: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let mut c = Vec::new();
    w_u16(&mut c, min_v);
    w_u16(&mut c, max_v);
    w_short(&mut c, session_id)?;
    pad(&c, BLOCK_SIZE)
}

pub fn parse_server_hello(block: &[u8]) -> Result<(u16, u16, Vec<u8>), EncodeError> {
    let c = unpad(block)?;
    let mut r = Reader::new(&c);
    let min = r.u16()?;
    let max = r.u16()?;
    let sid = r.short()?;
    Ok((min, max, sid))
}

pub fn client_hello_block(version: u16, key_hash: &[u8], proxy: bool) -> Result<Vec<u8>, EncodeError> {
    let mut c = Vec::new();
    w_u16(&mut c, version);
    w_short(&mut c, key_hash)?;
    w_bool(&mut c, proxy);
    c.push(b'0'); // no client service
    pad(&c, BLOCK_SIZE)
}

pub fn parse_client_hello(block: &[u8]) -> Result<(u16, Vec<u8>, bool), EncodeError> {
    let c = unpad(block)?;
    let mut r = Reader::new(&c);
    let v = r.u16()?;
    let kh = r.short()?;
    let proxy = r.bool()?;
    Ok((v, kh, proxy))
}

pub fn write_block(w: &mut impl Write, block: &[u8]) -> std::io::Result<()> {
    w.write_all(block)?;
    w.flush()
}

pub fn read_block(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; BLOCK_SIZE];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn read_block_stream(s: &TcpStream) -> std::io::Result<Vec<u8>> {
    let mut s = s;
    read_block(&mut s)
}
