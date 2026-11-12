use smp_rs::crypto::*;

#[test]
fn pynacl_crosscheck() {
    let j = std::fs::read_to_string("/home/thomas/.hermes/cache/scratch/xcheck.json").unwrap();
    let v: serde_json::Value = serde_json::from_str(&j).unwrap();
    let hexd = |s: &str| -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() };
    let a_priv = hexd(v["a_priv"].as_str().unwrap());
    let b_pub = hexd(v["b_pub"].as_str().unwrap());
    let nonce = hexd(v["nonce"].as_str().unwrap());
    let ct = hexd(v["ct"].as_str().unwrap());
    let beforenm_k = hexd(v["beforenm_k"].as_str().unwrap());

    let sk = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(a_priv.as_slice()).unwrap());
    let pk = x25519_public(<[u8; 32]>::try_from(b_pub.as_slice()).unwrap());
    let shared = x25519_dh(&sk, &pk);
    let bk = hsalsa20_pub(&shared, &[0u8; 16]);
    assert_eq!(&bk[..], &beforenm_k[..], "beforenm mismatch");
    let n24: [u8; 24] = nonce[..24].try_into().unwrap();
    let pt = secretbox_decrypt(&shared, &n24, &ct).expect("decrypt failed");
    assert_eq!(pt.len(), 1024);
    println!("PyNaCl cross-check OK: beforenm + xsalsa decrypt matches");
}
