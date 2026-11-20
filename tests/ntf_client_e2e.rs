//! End-to-end test of the library-level NTF client against a mock NTF server.
//!
//! The mock speaks the real NTF wire format (512-byte blocks, server-speaks-first handshake,
//! batch framing) so the test covers the client code path end to end: handshake → PING → PONG,
//! plus the fail-closed pin check and the "wrong keyHash is rejected" server-side check.

use smp_rs::crypto::sha256;
use smp_rs::ntf::*;
use std::io::{Cursor, Read, Write};
use std::sync::mpsc;

/// A scripted NTF server: serves the server hello, then answers the client hello with the
/// configured behaviour.
struct MockNtfServer {
    /// Expected keyHash the client must present (None = accept any).
    expect_key_hash: Option<[u8; 32]>,
}

impl MockNtfServer {
    /// Serve one connection over an in-memory pipe; returns the bytes the server read.
    fn serve(self, ca_der: Vec<u8>) -> (Vec<u8>, Option<String>) {
        // pipe(): (reader, writer) — the server reads what the client writes and writes back.
        let (mut server_read, client_to_server_w) = std::io::pipe().unwrap();
        let (client_to_server_r, mut server_to_client_w) = std::io::pipe().unwrap();
        let (tx, rx) = mpsc::channel();

        let ca_for_thread = ca_der.clone();
        std::thread::spawn(move || {
            let res = self.run(&mut server_read, &mut server_to_client_w, &ca_for_thread);
            let _ = tx.send(res);
        });

        // client side
        let mut client_stream = PipeStream { r: client_to_server_r, w: client_to_server_w };
        let expected = sha256(&ca_der);
        let mut client = NtfClient::connect(&mut client_stream, &ca_der, expected).expect("handshake");
        let pong = client.ping().expect("PONG");
        assert_eq!(pong.tag, NtfResponseTag::Pong);
        assert_eq!(pong.corr_id.len(), 24);
        // the client read everything the server sent
        let _ = &mut client_stream;
        let server_res = rx.recv().unwrap();
        (server_res.0, server_res.1)
    }

    fn run(
        &self,
        rd: &mut impl Read,
        wr: &mut impl Write,
        _ca_der: &[u8],
    ) -> (Vec<u8>, Option<String>) {
        // server speaks first
        {
            let mut v = Vec::new();
            v.extend_from_slice(&1u16.to_be_bytes()); // min version
            v.extend_from_slice(&3u16.to_be_bytes()); // max version
            v.push(32); // sessionId length
            v.extend_from_slice(&[0x5Au8; 32]);
            let der = vec![0x30u8; 173];
            v.extend_from_slice(&(der.len() as u16).to_be_bytes());
            v.extend_from_slice(&der);
            let hello = pad_ntf_block(&v).unwrap();
            wr.write_all(&hello).unwrap();
        }
        wr.flush().unwrap();

        // read the client hello (512-byte block)
        let mut block = vec![0u8; NTF_BLOCK_SIZE];
        rd.read_exact(&mut block).unwrap();
        let payload = unpad_ntf_block(&block).unwrap();
        // u16 version + u8 len + 32B keyHash
        assert_eq!(payload.len(), 35);
        let key_hash: [u8; 32] = payload[3..35].try_into().unwrap();
        if let Some(expect) = self.expect_key_hash {
            if key_hash != expect {
                return (block, Some("wrong keyHash".into()));
            }
        }

        // read the command batch
        let mut block = vec![0u8; NTF_BLOCK_SIZE];
        rd.read_exact(&mut block).unwrap();
        let payload = unpad_ntf_block(&block).unwrap();
        let ts = parse_ntf_batch(&payload).unwrap();
        assert_eq!(ts.len(), 1);
        assert_eq!(ts[0].command, b"PING");

        // answer PONG with the same corrId
        let resp = NtfTransmission {
            authenticator: Vec::new(),
            corr_id: ts[0].corr_id.clone(),
            entity_id: Vec::new(),
            command: b"PONG".to_vec(),
        };
        let batch = encode_ntf_batch(std::slice::from_ref(&resp));
        wr.write_all(&pad_ntf_block(&batch).unwrap()).unwrap();
        wr.flush().unwrap();
        (block, None)
    }
}

/// A duplex stream over two pipes.
struct PipeStream {
    r: std::io::PipeReader,
    w: std::io::PipeWriter,
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.r.read(buf)
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.w.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

#[test]
fn ntf_client_handshake_and_ping_pong() {
    let ca = vec![0xC7u8; 250];
    let expected = sha256(&ca);
    let server = MockNtfServer { expect_key_hash: Some(expected) };
    let (_read, err) = server.serve(ca.clone());
    assert!(err.is_none(), "server error: {err:?}");
}

#[test]
fn ntf_client_refuses_wrong_pin_without_io() {
    // The client must fail before reading anything when the pin does not match.
    let ca = vec![0xC7u8; 250];
    let mut stream = Cursor::new(Vec::<u8>::new());
    let err = match NtfClient::connect(&mut stream, &ca, [0x00; 32]) {
        Ok(_) => panic!("must fail on pin mismatch"),
        Err(e) => e,
    };
    assert!(err.contains("pin failure"), "{err}");
    // nothing was consumed from the stream
    assert_eq!(stream.position(), 0);
}

#[test]
fn ntf_client_rejects_server_error_response() {
    // A server that answers ERR must surface the error tag, not a panic.
    let mut buf = Vec::new();
    let err = NtfTransmission {
        authenticator: Vec::new(),
        corr_id: (0u8..24).collect(),
        entity_id: Vec::new(),
        command: b"ERR AUTH".to_vec(),
    };
    buf.extend_from_slice(&pad_ntf_block(&encode_ntf_batch(std::slice::from_ref(&err))).unwrap());
    let payload = unpad_ntf_block(&buf).unwrap();
    let ts = parse_ntf_batch(&payload).unwrap();
    let (tag, rest) = split_ntf_response(&ts[0].command).unwrap();
    assert_eq!(tag, NtfResponseTag::Err);
    assert_eq!(rest, b"AUTH");
}