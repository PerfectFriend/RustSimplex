//! Demo client: connect, PING, create a queue (NEW), print the queue IDs.
//! Usage: smp-client <host:port>

use smp_rs::client::Client;
use smp_rs::crypto::*;
use smp_rs::protocol::*;

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:5223".into());
    let key_hash = [0xABu8; 32]; // plain-transport dummy router identity
    let mut c = Client::connect(&addr, &key_hash).expect("connect");

    let pongs = c.request(Command::Ping, vec![], None).expect("PING");
    println!("PING -> {:?}", pongs);

    let auth = ed25519_keypair();
    let dh = x25519_keypair();
    let auth_der = spki_ed25519(&auth.verifying.to_bytes());
    let dh_der = spki_x25519(&dh.public.to_bytes());

    let resp = c
        .request(
            Command::New {
                rcv_auth_key: auth_der,
                rcv_dh_key: dh_der,
                basic_auth: None,
                sub_mode: b'S',
                queue_req_data: None,
                ntf_creds: None,
            },
            vec![],
            Some(&auth),
        )
        .expect("NEW");
    match &resp[0] {
        BrokerMsg::Ids { rcv_id, snd_id, rcv_dh_key, .. } => {
            println!("queue created:");
            println!("  rcv_id = {}", base64url_nopad(rcv_id));
            println!("  snd_id = {}", base64url_nopad(snd_id));
            println!("  srv_dh = {}", base64url_nopad(rcv_dh_key));
            println!("  keyhash = {}", base64url_nopad(&key_hash));
            println!("  smp://{}@{}/{}#{}", base64url_nopad(&key_hash), addr, base64url_nopad(rcv_id), base64url_nopad(snd_id));
        }
        other => println!("unexpected: {other:?}"),
    }
}
