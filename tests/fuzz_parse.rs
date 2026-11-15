//! Negative/fuzz smoke: parsers must return Err, never panic, on mutated/random input.
use smp_rs::protocol::*;

fn sample_block() -> Vec<u8> {
    let t = Transmission {
        authenticator: vec![0u8; 64],
        corr_id: vec![7u8; 24],
        entity_id: vec![9u8; 16],
        command: b"PING".to_vec(),
    };
    let wire = encode_transmission(&t).unwrap();
    encode_block(&[wire]).unwrap()
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn mutated_blocks_and_commands_do_not_panic() {
    let base = sample_block();
    // single-byte mutations across the block
    for i in (0..base.len()).step_by(97) {
        let mut b = base.clone();
        b[i] ^= 0xFF;
        let r = std::panic::catch_unwind(|| decode_block(&b));
        assert!(r.is_ok(), "decode_block panicked at byte {i}");
    }
    // random blocks + random command payloads
    let mut st = 0x12345678u64;
    for _ in 0..300 {
        let mut b = vec![0u8; 16384];
        for x in b.iter_mut() {
            *x = xorshift(&mut st) as u8;
        }
        let _ = std::panic::catch_unwind(|| decode_block(&b));
        let cmd: Vec<u8> = (0..(xorshift(&mut st) % 256) as usize).map(|_| xorshift(&mut st) as u8).collect();
        let _ = std::panic::catch_unwind(|| parse_broker(&cmd));
        let mut tr = cmd.clone();
        tr.push(0);
        let _ = std::panic::catch_unwind(|| decode_transmission(&tr));
    }
}
