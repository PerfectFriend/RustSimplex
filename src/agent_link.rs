//! Official SimpleX agent link formats (queue URI + invitation/contact link).
//!
//! Sources (simplexmq 7.0.1.0, stable — the reference implementation):
//!   * spec/simplex-messaging.md "SMP queue URI"
//!   * spec/agent-protocol.md "Connection link: 1-time invitation and contact address"
//!   * simplexmq/src/Simplex/Messaging/Agent/Protocol.hs:1132-1213
//!   * simplexmq/src/Simplex/Messaging/Agent/Protocol.hs:1399-1434
//!
//! These are NOT the wire commands: the link is the out-of-band string the
//! mobile/desktop SimpleX client actually parses. Our earlier internal format
//! (`smp://kh@host:port#rcv?snd=..&ci=..`) is kept for back-compat parsing, but
//! anything meant for the real client must be produced in the official shape.

use crate::crypto::base64url_nopad;

/// base64url without padding, both directions (the official form is nopad).
pub fn b64url_nopad(s: &[u8]) -> String {
    base64url_nopad(s)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    // Streaming decoder: accumulate 6 bits per character, emit a byte as soon
    // as 8 bits are available. Padding and surrounding whitespace are allowed
    // (the reference parser accepts both padded and unpadded input), and the
    // leftover bits of the final group are simply dropped.
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        let v: u32 = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return Err(format!("bad base64url character {:?}", c as char)),
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if out.is_empty() && !s.trim().is_empty() {
        return Err("empty base64url decode".into());
    }
    Ok(out)
}

/// Percent-encode a URI query component the way the reference client does
/// (`QEscape`): keep unreserved characters, escape everything else.
pub fn url_encode_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || "-_.~".contains(c) {
            out.push(c);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

pub fn url_decode_component(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return Err("bad percent encoding".into());
            }
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).map_err(|_| "bad hex")?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| "bad hex")?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// SMP queue URI (one queue): the piece that goes into `smp=` of the link.
#[derive(Debug, Clone, PartialEq)]
pub struct QueueUri {
    pub key_hash: Vec<u8>, // 32B router identity (SHA-256 of CA SPKI)
    pub host: String,
    pub port: u16,
    pub sender_id: Vec<u8>, // queue id in the URI = sender queue id
    pub dh_pub: Vec<u8>,    // SPKI DER of the recipient DH key
    pub v_min: u16,
    pub v_max: u16,
    pub queue_mode: Option<char>, // 'm' = messaging, 'c' = contact
}

impl QueueUri {
    /// smp://<keyHashB64>@host[:port]/<senderIdB64>#/?v=<vrange>&dh=<x509B64>[&q=c]
    pub fn encode(&self) -> String {
        let port = if self.port == 5223 || self.port == 0 {
            String::new()
        } else {
            format!(":{}", self.port)
        };
        let vr = if self.v_min == self.v_max {
            format!("{}", self.v_min)
        } else {
            format!("{}-{}", self.v_min, self.v_max)
        };
        let mut q = format!("v={}&dh={}", vr, b64url_nopad(&self.dh_pub));
        if let Some(m) = self.queue_mode {
            q.push_str(&format!("&q={}", m));
        }
        format!(
            "smp://{}@{}{}/{}#/?{}",
            b64url_nopad(&self.key_hash),
            self.host,
            port,
            b64url_nopad(&self.sender_id),
            q
        )
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let rest = s.strip_prefix("smp://").ok_or("queue URI must start with smp://")?;
        let (authority, tail) = rest.split_once('/').ok_or("queue URI missing /<queueId>")?;
        let (kh, hostport) = authority.split_once('@').ok_or("queue URI missing @")?;
        let key_hash = b64url_decode(kh)?;
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), p.parse::<u16>().map_err(|_| "bad port")?)
            }
            _ => (hostport.to_string(), 5223),
        };
        let (qid_b64, frag) = tail.split_once('#').ok_or("queue URI missing #")?;
        let sender_id = b64url_decode(qid_b64.trim_end_matches('/'))?;
        let query = frag.trim_start_matches('/').trim_start_matches('?');
        let mut v_min = 0u16;
        let mut v_max = 0u16;
        let mut dh_pub = Vec::new();
        let mut queue_mode = None;
        for kv in query.split('&') {
            if let Some(v) = kv.strip_prefix("v=") {
                if let Some((lo, hi)) = v.split_once('-') {
                    v_min = lo.parse().map_err(|_| "bad version range")?;
                    v_max = hi.parse().map_err(|_| "bad version range")?;
                } else {
                    v_min = v.parse().map_err(|_| "bad version")?;
                    v_max = v_min;
                }
            } else if let Some(v) = kv.strip_prefix("dh=") {
                dh_pub = b64url_decode(v)?;
            } else if let Some(v) = kv.strip_prefix("q=") {
                queue_mode = v.chars().next();
            }
        }
        Ok(QueueUri { key_hash, host, port, sender_id, dh_pub, v_min, v_max, queue_mode })
    }
}

/// Official agent connection link: invitation (1-time) or contact (reusable).
#[derive(Debug, Clone, PartialEq)]
pub struct AgentLink {
    pub mode: String, // "invitation" | "contact"
    pub v_min: u16,
    pub v_max: u16,
    pub queues: Vec<QueueUri>,
    /// URL-encoded e2e params string, exactly as the reference emits it.
    pub e2e: Option<String>,
    pub client_data: Option<String>,
}

impl AgentLink {
    /// simplex:/invitation#/?v=<vrange>&smp=<urlencoded queueUri>[&e2e=..]
    pub fn encode(&self) -> String {
        let vr = if self.v_min == self.v_max {
            format!("{}", self.v_min)
        } else {
            format!("{}-{}", self.v_min, self.v_max)
        };
        let smp = self
            .queues
            .iter()
            .map(|q| q.encode())
            .collect::<Vec<_>>()
            .join(";");
        let mut out = format!(
            "simplex:/{}#/?v={}&smp={}",
            self.mode,
            vr,
            url_encode_component(&smp)
        );
        if let Some(e) = &self.e2e {
            out.push_str(&format!("&e2e={}", url_encode_component(e)));
        }
        if let Some(d) = &self.client_data {
            out.push_str(&format!("&data={}", url_encode_component(d)));
        }
        out
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let rest = s
            .strip_prefix("simplex:/")
            .or_else(|| s.strip_prefix("https://"))
            .ok_or("link must start with simplex:/ or https://")?;
        let (head, frag) = rest.split_once('#').ok_or("link missing #")?;
        let mode = head.trim_end_matches('/').to_string();
        let query = frag.trim_start_matches('/').trim_start_matches('?');
        let mut v_min = 0u16;
        let mut v_max = 0u16;
        let mut smp_raw = String::new();
        let mut e2e = None;
        let mut client_data = None;
        for kv in query.split('&') {
            if let Some(v) = kv.strip_prefix("v=") {
                if let Some((lo, hi)) = v.split_once('-') {
                    v_min = lo.parse().map_err(|_| "bad agent version range")?;
                    v_max = hi.parse().map_err(|_| "bad agent version range")?;
                } else {
                    v_min = v.parse().map_err(|_| "bad agent version")?;
                    v_max = v_min;
                }
            } else if let Some(v) = kv.strip_prefix("smp=") {
                let dec = url_decode_component(v)?;
                smp_raw = String::from_utf8(dec).map_err(|_| "smp= is not utf8")?;
            } else if let Some(v) = kv.strip_prefix("e2e=") {
                let dec = url_decode_component(v)?;
                e2e = Some(String::from_utf8(dec).map_err(|_| "e2e= is not utf8")?);
            } else if let Some(v) = kv.strip_prefix("data=") {
                let dec = url_decode_component(v)?;
                client_data = Some(String::from_utf8(dec).map_err(|_| "data= is not utf8")?);
            }
        }
        if smp_raw.is_empty() {
            return Err("link has no smp= parameter".into());
        }
        let queues = smp_raw
            .split(';')
            .map(QueueUri::parse)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AgentLink { mode, v_min, v_max, queues, e2e, client_data })
    }
}

/// The e2e parameter block in the official URI form: `v=1&x3dh=<k1>,<k2>`.
/// This is the SHAPE the official client expects; our PQDR params are a
/// separate encoding (see pq.rs) and are documented as incompatible.
pub fn encode_e2e_uri_params(v: u16, key1: &[u8], key2: &[u8], kem_key: Option<&[u8]>) -> String {
    let mut s = format!("v={}&x3dh={},{}", v, b64url_nopad(key1), b64url_nopad(key2));
    if let Some(k) = kem_key {
        s.push_str(&format!("&kem_key={}", b64url_nopad(k)));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_roundtrip_and_padding() {
        let v = [0u8, 1, 2, 3, 250, 251, 252];
        let e = b64url_nopad(&v);
        assert!(!e.contains('='));
        assert_eq!(b64url_decode(&e).unwrap(), v);
        // padded input is accepted too
        let padded = format!("{}=", e);
        assert!(b64url_decode(&padded).is_ok());
    }

    #[test]
    fn queue_uri_official_shape_roundtrip() {
        let q = QueueUri {
            key_hash: vec![7u8; 32],
            host: "smp11.simplex.im".into(),
            port: 5223,
            sender_id: vec![9u8; 24],
            dh_pub: vec![3u8; 44],
            v_min: 1,
            v_max: 1,
            queue_mode: Some('c'),
        };
        let s = q.encode();
        assert!(s.starts_with("smp://"), "got {s}");
        assert!(s.contains("#/?v=1&dh="), "got {s}");
        assert!(s.ends_with("&q=c"), "got {s}");
        // default port is omitted, as in the reference encoding
        assert!(!s.contains(":5223"), "got {s}");
        let back = QueueUri::parse(&s).expect("parse");
        assert_eq!(back, q);
    }

    #[test]
    fn queue_uri_custom_port_is_kept() {
        let q = QueueUri {
            key_hash: vec![1u8; 32],
            host: "127.0.0.1".into(),
            port: 5224,
            sender_id: vec![2u8; 16],
            dh_pub: vec![3u8; 44],
            v_min: 1,
            v_max: 2,
            queue_mode: None,
        };
        let s = q.encode();
        assert!(s.contains("127.0.0.1:5224"), "got {s}");
        assert!(s.contains("v=1-2"), "got {s}");
        assert_eq!(QueueUri::parse(&s).unwrap(), q);
    }

    #[test]
    fn invitation_link_is_url_escaped_and_roundtrips() {
        let q = QueueUri {
            key_hash: vec![7u8; 32],
            host: "smp11.simplex.im".into(),
            port: 5223,
            sender_id: vec![9u8; 24],
            dh_pub: vec![3u8; 44],
            v_min: 1,
            v_max: 1,
            queue_mode: Some('c'),
        };
        let e2e = encode_e2e_uri_params(1, &q.dh_pub, &q.dh_pub, None);
        let link = AgentLink {
            mode: "invitation".into(),
            v_min: 1,
            v_max: 1,
            queues: vec![q.clone()],
            e2e: Some(e2e),
            client_data: None,
        };
        let s = link.encode();
        assert!(s.starts_with("simplex:/invitation#/?v=1&smp="), "got {s}");
        // the smp= value must be escaped: no raw "smp://" inside the query
        assert!(!s.contains("&smp=smp://"), "got {s}");
        assert!(s.contains("%3A%2F%2F"), "got {s}");
        let back = AgentLink::parse(&s).expect("parse");
        assert_eq!(back, link);
        assert_eq!(back.queues[0].sender_id, q.sender_id);
    }

    #[test]
    fn contact_link_without_e2e_roundtrips() {
        let q = QueueUri {
            key_hash: vec![4u8; 32],
            host: "smp9.simplex.im".into(),
            port: 5223,
            sender_id: vec![5u8; 24],
            dh_pub: vec![6u8; 44],
            v_min: 2,
            v_max: 4,
            queue_mode: Some('m'),
        };
        let link = AgentLink {
            mode: "contact".into(),
            v_min: 2,
            v_max: 4,
            queues: vec![q],
            e2e: None,
            client_data: None,
        };
        let s = link.encode();
        assert!(s.starts_with("simplex:/contact#/?v=2-4&smp="), "got {s}");
        assert_eq!(AgentLink::parse(&s).unwrap(), link);
    }
}
