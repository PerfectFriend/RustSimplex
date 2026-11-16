use smp_rs::transport::{connect_socks5, Socks5Config};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

#[test]
fn socks5_remote_dns_handshake() {
    // mock SOCKS5 server: expects greeting, no-auth, CONNECT with ATYP=0x03 domain
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let h = thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut g = [0u8; 3];
        s.read_exact(&mut g).unwrap();
        assert_eq!(&g[..], &[0x05, 0x01, 0x00]);
        s.write_all(&[0x05, 0x00]).unwrap();
        let mut req = [0u8; 5];
        s.read_exact(&mut req).unwrap();
        assert_eq!(req[3], 0x03, "domain ATYP expected (remote DNS)");
        let n = req[4] as usize;
        let mut dom = vec![0u8; n + 2];
        s.read_exact(&mut dom).unwrap();
        assert_eq!(&dom[..n], b"example.com");
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
    });
    let cfg = Socks5Config { host: "127.0.0.1".into(), port: addr.port(), user: None, pass: None };
    let _tcp = connect_socks5(&cfg, "example.com", 5223).unwrap();
    h.join().unwrap();
}
