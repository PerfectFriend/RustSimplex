//! Audit #3, Sprint B: U-20b parser overflow, U-20 SOCKS5/dump hygiene, U-17 XFTP download integrity.

use smp_rs::client::Client;
use smp_rs::crypto::ed25519_keypair;
use smp_rs::encoding::Reader;
use smp_rs::server::Engine;
use smp_rs::transport::{connect_socks5, Socks5Config};
use smp_rs::xftp::{download_file_stream, upload_file};

#[test]
fn reader_take_overflow_is_err_not_panic() {
    let mut r = Reader::new(&[0u8; 4]);
    assert!(r.take(usize::MAX).is_err(), "usize::MAX must be Err, not panic");
    assert!(r.take(u32::MAX as usize).is_err());
    assert!(r.take(4).is_ok());
    assert!(r.take(1).is_err());
    // short/large lengths are u8/u16 — still must not panic on truncated buffers
    let mut r = Reader::new(&[0xff]);
    assert!(r.short().is_err());
    let mut r = Reader::new(&[0xff, 0xff, 0x00]);
    assert!(r.large().is_err());
}

#[test]
fn socks5_overlong_fields_rejected_before_network() {
    let cfg = Socks5Config { host: "127.0.0.1".into(), port: 1, user: Some("u".repeat(300)), pass: None };
    let e = connect_socks5(&cfg, "example.com", 443).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
    let cfg = Socks5Config { host: "127.0.0.1".into(), port: 1, user: None, pass: Some("p".repeat(256)) };
    assert_eq!(connect_socks5(&cfg, "example.com", 443).unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    let cfg = Socks5Config { host: "127.0.0.1".into(), port: 1, user: None, pass: None };
    assert_eq!(connect_socks5(&cfg, &"h".repeat(300), 443).unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
}

fn spawn_engine() -> std::net::SocketAddr {
    let e = Engine::bind_plain_with_strict("127.0.0.1:0", false).unwrap();
    let a = e.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = e.serve();
    });
    a
}

#[test]
fn xftp_download_verifies_digest_tmp_and_perms() {
    let addr = spawn_engine();
    let mut c = Client::connect_plain(addr, &[0u8; 32]).unwrap();
    let kp = ed25519_keypair();
    let data = b"hello xftp integrity check U-17".to_vec();
    let desc = upload_file(&mut c, &data, &kp).unwrap();

    let dir = std::env::temp_dir().join(format!("smp-u17-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("file.bin"); // tmp will be "file.part" (with_extension replaces)
    download_file_stream(&mut c, &desc, &out, |_, _| {}).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), data, "downloaded content must match");
    assert!(!dir.join("file.part").exists(), "temp file must be renamed away");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // tampered digest -> error, NO final file, NO leftover tmp
    let mut bad = desc.clone();
    bad.digest[0] ^= 0xff;
    let out2 = dir.join("bad.bin");
    let r = download_file_stream(&mut c, &bad, &out2, |_, _| {});
    assert!(r.is_err(), "tampered digest must fail: {r:?}");
    assert!(!out2.exists(), "unverified payload must never land at the final path");
    assert!(!dir.join("bad.part").exists(), "temp file must be cleaned up on error");

    // orig_size > size is a malformed descriptor
    let mut bad2 = desc.clone();
    bad2.orig_size = desc.size + 1;
    assert!(download_file_stream(&mut c, &bad2, &dir.join("x.bin"), |_, _| {}).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}
