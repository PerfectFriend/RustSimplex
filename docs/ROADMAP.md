# ROADMAP — simplex-rs (post-audit)

## Done (v0.50–v0.61)
- SEC-01: strict cert pinning в rustls-path (pin = последний сертификат цепочки + проверка подписи leaf через rustls-webpki).
- SEC-14: length-prefixed pad в strict sb_chain блоках.
- SEC-10: store fail-closed (невалидный ключ — ошибка, no SMP1 downgrade, 0600 + fsync).
- SEC-04: channel binding primitives + TLS exporter binding в client handshake (при непустом sid).
- P1: proxy SSRF-guard (public IP only, порты 5223/443), bounded offline queue (1000, `ERR QUEUE_FULL`), 30s read/write timeouts.
- Live interop: public SMP v17..v23 OK, XFTP v4 PING/PONG OK. Default suite 60/60.

## Done (v0.62–v0.89)
- E2E PQDR default-on (`Agent::e2e = true`, fail-closed: no plaintext without ratchet);
  init_sender/init_receiver negotiated over HELLO/connInfo; chat_e2e + strict_e2e green.
- kem_encaps_pub/init_sender return Result (no panic on malformed peer KEM key) — audit CRITICAL fixed.
- Guarded indexing (qs[0]/r[0] -> first().ok_or) — no panics on empty D/IDS.
- recv_agent/recv_text ACK every delivered MSG via `Client::send_only` (fire-and-forget, no push swallowing).
- Server pump: pushed MSGs are greedy-chunked into multiple blocks — fixes `pad overflow` that killed
  connections (root cause of the chat flake, v0.89).
- SEC-01 negative MITM test: [evil_leaf, pinned_CA] rejected by leaf signature verification (tests/interop.rs).
- Live interop: public SMP v17..v23 round-trip OK (smp11.simplex.im:5223), XFTP v4 PING/PONG OK (xftp1).
- Suite 70/70, SMP_STRICT 3/3, clippy 0 (default + v71-probes).

## Next (backlog, by value)
1. sessionId: verify against real TLS 1.3 Finished verify_data (rustls exporter today).
2. NTF/proxy against live public relays (server-side currently disabled publicly; local tests cover it).
3. Remove remaining unwrap/expect in src (sb_chain 16, ffi 8, ...) — dispatch is catch_unwind-guarded meanwhile.
4. Onion routing over SMP proxy chains (the stated platform goal).
5. Async engine with auto-reconnect on top of async_client.rs.
6. External audit (Hydrogen / Grok / Sonnet) over docs/AUDIT-REPORT.md + multi-zone-security-audit skill.

## Caveats
- Probe bins (`smp-v71`, `xftp-h2-v71`) stay `NoVerify` by design — never ship them as clients.
- For public relays keyHash = SHA-256 of leaf SPKI (live-verified); local identity uses offline CA DER.
