//! XFTP e2e: upload encrypted file -> FNEW/FPUT chunks -> download via FGET -> decrypt -> digest match; FDEL removes.

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::server::{spawn_engine, Engine};
use smp_rs::xftp::*;

#[test]
fn xftp_file_roundtrip() {
    let eng = Engine::bind_plain("127.0.0.1:0").unwrap();
    let (addr, _st, _sd, _h) = spawn_engine(eng);
    let kh = [0xEFu8; 32];

    // ~40KB payload -> 3 chunks of 15KB
    let data: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();

    let sender = ed25519_keypair();
    let mut up = Client::connect_plain(addr, &kh).unwrap();
    let desc = upload_file(&mut up, &data, &sender).expect("upload");
    assert_eq!(desc.chunks, 3);
    let desc_text = desc.encode();
    let desc2 = FileDesc::decode(&desc_text).expect("desc roundtrip");
    assert_eq!(desc2.packet_id, desc.packet_id);
    assert_eq!(desc2.size, desc.size);

    // wrong sender key cannot delete
    let impostor = ed25519_keypair();
    let mut c2 = Client::connect_plain(addr, &kh).unwrap();
    let r = c2.request(
        smp_rs::protocol::Command::Fdel { packet_id: desc.packet_id.clone() },
        vec![],
        Some(&impostor),
    );
    assert!(matches!(r.unwrap()[0], smp_rs::protocol::BrokerMsg::Err(_)), "impostor FDEL must fail");

    // download from a fresh connection
    let mut down = Client::connect_plain(addr, &kh).unwrap();
    let padded = download_file(&mut down, &desc2).expect("download+decrypt+digest");
    assert_eq!(&padded[..data.len()], &data[..], "content mismatch");
    assert!(padded[data.len()..].iter().all(|b| *b == 0), "padding must be zeros");

    // sender deletes
    delete_file(&mut up, &desc.packet_id, &sender).expect("FDEL");
    let mut c3 = Client::connect_plain(addr, &kh).unwrap();
    let r = c3.request(
        smp_rs::protocol::Command::Fget { packet_id: desc.packet_id.clone(), offset: 0 },
        vec![],
        None,
    );
    assert!(matches!(r.unwrap()[0], smp_rs::protocol::BrokerMsg::Err(_)), "FGET after FDEL must fail");
}

#[test]
fn xftp_packets_survive_snapshot() {
    let mut st = smp_rs::server::ServerState::new();
    let pid = vec![7u8; 16];
    let mut chunks = std::collections::BTreeMap::new();
    chunks.insert(0u32, vec![1u8; 100]);
    chunks.insert(1u32, vec![2u8; 50]);
    st.xftp.insert(
        pid.clone(),
        XftpPacket { size: 46080, digest: vec![9u8; 32], sender_raw: [3u8; 32], chunks },
    );
    let snap = smp_rs::store::snapshot_bytes(&st);
    let st2 = smp_rs::store::parse_snapshot(&snap).expect("parse");
    let p = st2.xftp.get(&pid).expect("packet present after reload");
    assert_eq!(p.size, 46080);
    assert_eq!(p.digest, vec![9u8; 32]);
    assert_eq!(p.sender_raw, [3u8; 32]);
    assert_eq!(p.chunks.len(), 2);
    assert_eq!(p.chunks[&1], vec![2u8; 50]);
}
