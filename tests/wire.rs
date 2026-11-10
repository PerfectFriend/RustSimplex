//! Wire-format golden-vector tests — encode known structures and check exact bytes
//! against the Haskell reference encoding rules.

use smp_rs::crypto::*;
use smp_rs::encoding::*;
use smp_rs::protocol::*;

#[test]
fn short_and_large_string() {
    let mut o = Vec::new();
    w_short(&mut o, b"hi").unwrap();
    assert_eq!(o, vec![2, b'h', b'i']);
    let mut o = Vec::new();
    w_large(&mut o, b"abc").unwrap();
    assert_eq!(o, vec![0, 3, b'a', b'b', b'c']);
}

#[test]
fn maybe_and_bool() {
    let mut o = Vec::new();
    w_maybe(&mut o, None::<&[u8]>).unwrap();
    w_maybe(&mut o, Some(b"x")).unwrap();
    assert_eq!(o, vec![b'0', b'1', b'x']);
    let mut o = Vec::new();
    w_bool(&mut o, true);
    w_bool(&mut o, false);
    assert_eq!(o, vec![b'T', b'F']);
}

#[test]
fn pad_unpad_roundtrip_and_layout() {
    let msg = b"hello";
    let p = pad(msg, 16).unwrap();
    assert_eq!(p.len(), 16);
    // word16BE(len=5) <> "hello" <> '#'*(16-5-2=9)
    assert_eq!(&p[..2], &[0, 5]);
    assert_eq!(&p[2..7], b"hello");
    assert!(p[7..].iter().all(|&c| c == b'#'));
    assert_eq!(unpad(&p).unwrap(), b"hello");
}

#[test]
fn command_bytes_exact() {
    assert_eq!(encode_command(&Command::Ping).unwrap(), b"PING");
    assert_eq!(encode_command(&Command::Sub).unwrap(), b"SUB");
    assert_eq!(encode_command(&Command::Get).unwrap(), b"GET");
    assert_eq!(encode_command(&Command::Off).unwrap(), b"OFF");
    assert_eq!(encode_command(&Command::Del).unwrap(), b"DEL");
    assert_eq!(&encode_command(&Command::Ack(vec![0xAA; 16])).unwrap()[..4], &b"ACK "[..]);
    // SEND: "SEND" ' ' flags ' ' body
    let s = encode_command(&Command::Send { flags: false, body: b"XY".to_vec() }).unwrap();
    assert_eq!(&s[..6], &b"SEND F"[..]);
    assert_eq!(&s[7..], b"XY");
}

#[test]
fn spki_templates_are_44_bytes_with_right_oid() {
    let x = spki_x25519(&[7u8; 32]);
    let e = spki_ed25519(&[7u8; 32]);
    assert_eq!(x.len(), 44);
    assert_eq!(e.len(), 44);
    assert_eq!(&x[6..9], &[0x2b, 0x65, 0x6e]); // X25519 oid
    assert_eq!(&e[6..9], &[0x2b, 0x65, 0x70]); // Ed25519 oid
    let (alg, raw) = parse_spki(&x).unwrap();
    assert!(matches!(alg, AuthAlg::X25519));
    assert_eq!(raw, [7u8; 32]);
    let (alg2, _) = parse_spki(&e).unwrap();
    assert!(matches!(alg2, AuthAlg::Ed25519));
}

#[test]
fn secretbox_is_nacl_layout_tag_first() {
    let key = [1u8; 32];
    let nonce = [2u8; 24];
    let pt = b"secret message";
    let ct = secretbox_encrypt(&key, &nonce, pt);
    // NaCl: 16-byte MAC || ciphertext ; total = 16 + len
    assert_eq!(ct.len(), 16 + pt.len());
    let back = secretbox_decrypt(&key, &nonce, &ct).unwrap();
    assert_eq!(back, pt);
    // wrong key fails
    assert!(secretbox_decrypt(&[9u8; 32], &nonce, &ct).is_none());
}

#[test]
fn transmission_block_layout_single() {
    // one transmission: authenticator=empty, corr=24B, entity=empty, command="PING"
    let t = Transmission {
        authenticator: vec![],
        corr_id: vec![0x42; 24],
        entity_id: vec![],
        command: b"PING".to_vec(),
    };
    let wire = encode_transmission(&t).unwrap();
    // short("") <> short(24B) <> short("") <> "PING"
    let mut exp = vec![0u8];
    exp.push(24);
    exp.extend_from_slice(&[0x42; 24]);
    exp.push(0);
    exp.extend_from_slice(b"PING");
    assert_eq!(wire, exp);

    let blk = encode_block(&[wire.clone()]).unwrap();
    assert_eq!(blk.len(), BLOCK_SIZE);
    // outer pad: word16BE(content_len) ...
    let content = unpad(&blk).unwrap();
    assert_eq!(content[0], 1); // count
    let wires = decode_block(&blk).unwrap();
    assert_eq!(wires, vec![wire]);
}

#[test]
fn signed_transmission_verifies() {
    let kp = ed25519_keypair();
    let mut t = Transmission {
        authenticator: vec![],
        corr_id: random_bytes(24),
        entity_id: b"queue".to_vec(),
        command: b"SUB".to_vec(),
    };
    auth_sign(b"", &mut t, &kp).unwrap();
    assert_eq!(t.authenticator.len(), 64);
    assert!(verify_sign(b"", &t, &kp.verifying.to_bytes()));
    // tamper
    let mut t2 = t.clone();
    t2.command = b"DEL".to_vec();
    assert!(!verify_sign(b"", &t2, &kp.verifying.to_bytes()));
}
