//! XFTP streaming upload/download — integration test for the streaming API.
//!
//! The streaming upload must be interchangeable with the buffered one: the same
//! file description, the same digest, and a byte-exact download that trims the
//! zero padding back to the original size.

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::server::{spawn_engine, Engine};
use smp_rs::xftp::*;

fn tmp_path(tag: &str) -> std::path::PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!("smp-rs-xftp-{tag}-{}-{n}.bin", std::process::id()));
    p
}

fn sample(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| (i % 251) as u8).collect()
}

/// A file whose size is NOT a multiple of the chunk size must round-trip
/// byte-exactly, and the description must describe the padded file.
#[test]
fn xftp_stream_upload_download_roundtrip() {
    let eng = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (addr, _st, _sd, _h) = spawn_engine(eng);
    let kh = [0xEFu8; 32];
    let sender = ed25519_keypair();

    // 40_000 B = 2 full chunks + 9_280 B -> the last chunk is partial
    let data = sample(40_000);
    let src = tmp_path("src");
    std::fs::write(&src, &data).unwrap();

    let mut up = Client::connect_plain(addr, &kh).unwrap();
    let mut calls = 0usize;
    let mut last = 0u64;
    let desc = upload_file_stream(&mut up, &src, &sender, |done, total| {
        calls += 1;
        assert_eq!(total, data.len() as u64, "progress total must be the original size");
        assert!(done >= last, "progress must not go backwards");
        last = done;
    })
    .expect("stream upload");

    // the description must describe the PADDED file: 3 chunks of 15_360 B
    assert_eq!(desc.chunks, 3, "chunk count must match the real chunk count");
    assert_eq!(desc.size, (3 * XFTP_CHUNK_PLAIN) as u64, "size must be the padded size");
    assert_eq!(desc.orig_size, data.len() as u64, "orig_size must be the original size");
    assert_eq!(calls, 3, "progress must fire once per chunk");
    assert_eq!(last, data.len() as u64, "progress must end at the original size");

    // the digest is over the padded plaintext, exactly like the buffered upload
    let (_padded, _key, digest) = encrypt_file(&data);
    assert_eq!(desc.digest, digest, "streaming digest must match the buffered digest");

    // stream download -> the exact original bytes
    let dst = tmp_path("dst");
    let mut up2 = Client::connect_plain(addr, &kh).unwrap();
    download_file_stream(&mut up2, &desc, &dst, |_done, _total| {})
        .expect("stream download");
    let got = std::fs::read(&dst).unwrap();
    assert_eq!(got.len(), data.len(), "download must be trimmed to the original size");
    assert_eq!(got, data, "content mismatch");

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}

/// A streamed upload must be readable by the buffered download API.
#[test]
fn xftp_stream_upload_is_readable_by_buffered_api() {
    let eng = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (addr, _st, _sd, _h) = spawn_engine(eng);
    let kh = [0xEFu8; 32];
    let sender = ed25519_keypair();

    let data = sample(20_000);
    let src = tmp_path("src2");
    std::fs::write(&src, &data).unwrap();

    let mut up = Client::connect_plain(addr, &kh).unwrap();
    let desc = upload_file_stream(&mut up, &src, &sender, |_d, _t| {}).expect("stream upload");

    let mut down = Client::connect_plain(addr, &kh).unwrap();
    let padded = download_file(&mut down, &desc).expect("buffered download of a streamed upload");
    assert_eq!(padded.len(), data.len());
    assert_eq!(padded, data);

    std::fs::remove_file(&src).ok();
}

/// A file that is an exact multiple of the chunk size has no padding at all.
#[test]
fn xftp_stream_exact_chunk_multiple() {
    let eng = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (addr, _st, _sd, _h) = spawn_engine(eng);
    let kh = [0xEFu8; 32];
    let sender = ed25519_keypair();

    let data = vec![0x5Au8; 2 * XFTP_CHUNK_PLAIN];
    let src = tmp_path("src3");
    std::fs::write(&src, &data).unwrap();

    let mut up = Client::connect_plain(addr, &kh).unwrap();
    let desc = upload_file_stream(&mut up, &src, &sender, |_d, _t| {}).expect("stream upload");
    assert_eq!(desc.chunks, 2);
    assert_eq!(desc.size, data.len() as u64);
    assert_eq!(desc.orig_size, data.len() as u64);

    let dst = tmp_path("dst3");
    let mut up2 = Client::connect_plain(addr, &kh).unwrap();
    download_file_stream(&mut up2, &desc, &dst, |_d, _t| {}).expect("stream download");
    assert_eq!(std::fs::read(&dst).unwrap(), data);

    std::fs::remove_file(&src).ok();
    std::fs::remove_file(&dst).ok();
}
