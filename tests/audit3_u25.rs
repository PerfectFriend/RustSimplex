//! audit3 round 3 regression tests: per-IP conn cap, TTL/GC, FFI U-14, fuzz extension.
use smp_rs::agent_envelope;
use smp_rs::agent_link::AgentLink;
use smp_rs::ntf::parse_ntf_batch;
use smp_rs::pqdr::decode_ratchet_msg;
use smp_rs::protocol::{parse_broker, parse_command};
use smp_rs::proxy::handle_rfwd;
use smp_rs::server::{new_state, Engine, Queue, ServerState, MAX_CONNS_PER_IP, QUEUE_TTL_SECS, XFTP_TTL_SECS};
use smp_rs::store::parse_snapshot;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

fn mk_queue(rcv: &[u8], snd: &[u8]) -> Queue {
    Queue {
        rcv_id: rcv.to_vec(),
        snd_id: snd.to_vec(),
        rcv_auth_raw: [7u8; 32],
        rcv_auth_x: true,
        snd_auth: None,
        rcv_dh_secret: [9u8; 32],
        messages: VecDeque::new(),
        subscriber: None,
        ntf_id: None,
        ntf_auth_raw: None,
        rcv_ntf_dh_secret: None,
        ntf_subscriber: None,
    }
}

#[test]
fn per_ip_cap_drops_excess_from_one_host() {
    let mut e = Engine::bind_plain("127.0.0.1:0").unwrap();
    e.max_conns_per_ip = 2;
    let addr = e.local_addr().unwrap();
    let e = std::sync::Arc::new(e);
    let e2 = e.clone();
    std::thread::spawn(move || { let _ = e2.serve(); }); // serve(&self) blocks
    let mut streams = vec![];
    for _ in 0..4 {
        streams.push(std::net::TcpStream::connect(addr).unwrap());
    }
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert!(e.conns.load(std::sync::atomic::Ordering::Relaxed) <= 2, "per-IP cap not enforced: {}", e.conns.load(std::sync::atomic::Ordering::Relaxed));
    let m = e.per_ip.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(m.get(&std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)), Some(&2));
    drop(streams);
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert_eq!(e.conns.load(std::sync::atomic::Ordering::Relaxed), 0, "per-IP counter leaked after disconnect");
    drop(m);
    e.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn gc_reaps_only_idle_unsubscribed_entries() {
    let mut st = ServerState::new();
    let now = QUEUE_TTL_SECS + XFTP_TTL_SECS + 1_000_000u64;
    // idle queue (touch older than TTL) -> reaped
    st.by_rcv.insert(b"old".to_vec(), mk_queue(b"old", b"oldsnd"));
    st.by_snd.insert(b"oldsnd".to_vec(), b"old".to_vec());
    st.touches.insert(b"old".to_vec(), now - QUEUE_TTL_SECS - 1);
    // fresh queue -> kept
    st.by_rcv.insert(b"new".to_vec(), mk_queue(b"new", b"newsnd"));
    st.by_snd.insert(b"newsnd".to_vec(), b"new".to_vec());
    st.touches.insert(b"new".to_vec(), now);
    // idle but subscribed -> kept
    let (tx, _rx) = std::sync::mpsc::channel();
    let mut sub = mk_queue(b"sub", b"subsnd");
    sub.subscriber = Some(tx);
    st.by_rcv.insert(b"sub".to_vec(), sub);
    st.by_snd.insert(b"subsnd".to_vec(), b"sub".to_vec());
    st.touches.insert(b"sub".to_vec(), now - QUEUE_TTL_SECS - 1);
    // idle xftp packet -> reaped
    st.xftp.insert(b"pkt".to_vec(), smp_rs::xftp::XftpPacket { size: 0, digest: vec![0u8; 32], sender_raw: [0u8; 32], chunks: Default::default() });
    st.xftp_touch.insert(b"pkt".to_vec(), now - XFTP_TTL_SECS - 1);

    let removed = st.gc(now);
    assert_eq!(removed, 2, "expected old queue + old packet reaped, got {removed}");
    assert!(!st.by_rcv.contains_key(b"old".as_slice()));
    assert!(!st.by_snd.contains_key(b"oldsnd".as_slice()));
    assert!(st.by_rcv.contains_key(b"new".as_slice()));
    assert!(st.by_rcv.contains_key(b"sub".as_slice()));
    assert!(!st.xftp.contains_key(b"pkt".as_slice()));
    // second sweep is a no-op
    assert_eq!(st.gc(now), 0);
}

#[cfg(feature = "ffi")]
#[test]
fn ffi_with_agent_bad_handle_errors_without_holding_lock() {
    // two sequential calls must both fail fast (no deadlock on the global lock)
    let r1 = smp_rs::ffi::recv_agent_full(0xDEAD_BEEF);
    let r2 = smp_rs::ffi::recv_agent_full(0xDEAD_BEEF);
    assert!(r1.is_err() && r2.is_err());
    assert_eq!(r1.unwrap_err(), "bad handle");
}

// ---------- fuzz extension: mutated inputs must never panic any parser ----------
fn lcg(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *seed >> 11
}

fn mutate(base: &[u8], seed: &mut u64, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(base);
    let n = (lcg(seed) % 8) + 1;
    for _ in 0..n {
        if out.is_empty() { out.push(lcg(seed) as u8); continue; }
        match lcg(seed) % 4 {
            0 => { let i = (lcg(seed) as usize) % out.len(); out[i] = lcg(seed) as u8; }
            1 => { let i = (lcg(seed) as usize) % out.len(); out.remove(i); }
            2 => { let i = (lcg(seed) as usize) % (out.len() + 1); out.insert(i, lcg(seed) as u8); }
            _ => { let i = (lcg(seed) as usize) % out.len(); let j = (lcg(seed) as usize) % out.len(); out.swap(i, j); }
        }
    }
    if lcg(seed).is_multiple_of(3) { out.truncate((lcg(seed) as usize) % (out.len() + 1)); }
}

fn no_panic<T>(f: impl Fn(&[u8]) -> T, seeds: &[Vec<u8>], iters: usize, tag: &str) {
    let mut s = 0xC0FFEEu64;
    let mut buf = Vec::new();
    for base in seeds {
        for _ in 0..iters {
            mutate(base, &mut s, &mut buf);
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&buf)));
            assert!(r.is_ok(), "PANIC in {tag} on input {:?}", &buf[..buf.len().min(64)]);
        }
    }
    // pure random garbage too
    for _ in 0..iters {
        buf.clear();
        let n = (lcg(&mut s) % 300) as usize;
        for _ in 0..n { buf.push(lcg(&mut s) as u8); }
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&buf)));
        assert!(r.is_ok(), "PANIC in {tag} on random input");
    }
}

#[test]
fn fuzz_parsers_never_panic() {
    let sess = [3u8; 32];
    let eph = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let dispatch = |_t: &smp_rs::protocol::Transmission| -> Vec<smp_rs::protocol::Transmission> { vec![] };
    let rfwd = |b: &[u8]| {
        let _ = handle_rfwd(b, b"corr", &sess, &eph, b"destsid00000000000000000000", &dispatch);
    };
    let seeds = vec![
        b"SEND 1 abcdef\x00\x01\x02".to_vec(),
        b"RFWD 2 shortstr".to_vec(),
        b"SKEY 3 x25519base64==".to_vec(),
        b"FNEW 4 1024 aabb".to_vec(),
        b"MSG 5 rcvid msgid body".to_vec(),
        vec![0u8; 64],
    ];
    no_panic(|b| { let _ = parse_command(b); }, &seeds, 800, "parse_command");
    no_panic(|b| { let _ = parse_broker(b); }, &seeds, 800, "parse_broker");
    no_panic(|b| { let _ = decode_ratchet_msg(b); }, &seeds, 800, "decode_ratchet_msg");
    no_panic(|b| { let _ = parse_snapshot(b); }, &seeds, 800, "parse_snapshot");
    no_panic(|b| { let _ = agent_envelope::decode(b); }, &seeds, 800, "agent_envelope::decode");
    no_panic(|b| { let _ = AgentLink::parse(&String::from_utf8_lossy(b)); }, &seeds, 400, "AgentLink::parse");
    no_panic(|b| { let _ = parse_ntf_batch(b); }, &seeds, 800, "parse_ntf_batch");
    no_panic(rfwd, &seeds, 400, "handle_rfwd");
}

#[test]
fn engine_default_per_ip_const() {
    let st = new_state();
    let e = Engine::bind_plain("127.0.0.1:0").unwrap(); let _ = st;
    assert_eq!(e.max_conns_per_ip, MAX_CONNS_PER_IP);
    const { assert!(MAX_CONNS_PER_IP >= 1) };
    let _ = Mutex::new(HashMap::<u8, u8>::new()); // silence unused imports in some cfgs
}
