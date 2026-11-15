# ROADMAP — simplex-rs (post-audit)

## Done (v0.50–v0.61)
- SEC-01: strict cert pinning в rustls-path (pin = последний сертификат цепочки + проверка подписи leaf через rustls-webpki).
- SEC-14: length-prefixed pad в strict sb_chain блоках.
- SEC-10: store fail-closed (невалидный ключ — ошибка, no SMP1 downgrade, 0600 + fsync).
- SEC-04: channel binding primitives + TLS exporter binding в client handshake (при непустом sid).
- P1: proxy SSRF-guard (public IP only, порты 5223/443), bounded offline queue (1000, `ERR QUEUE_FULL`), 30s read/write timeouts.
- Live interop: public SMP v17..v23 OK, XFTP v4 PING/PONG OK. Default suite 60/60.

## Next — E2E (настоящий PQDR в agent/chat)
1. `ConnInfo`/`ConnInfoReply` уже несут `pq_support`/`e2e` — договориться о PQ на уровне профилей.
2. При `pq_support=true`: joiner генерирует `(dh_s, kem_s)` и шлёт их в `D` connInfo; initiator делает `PqdrRatchet::init_sender(sk, ad, dh_r, kem_r)`, receiver — `init_receiver(...)`.
3. `AgentMsg::Msg.body` оборачивать в `ratchet.encrypt(body)`; на приёме `ratchet.decrypt` до парсинга `M`.
4. `A_RCVD`/hash считаем по plaintext msgHash, но доставляем только wire — роутер видит лишь метаданные.
5. Тест: два локальных serverа, две очереди, `pqdr_e2e.rs` — handshake + 20 сообщений в обе стороны + out-of-order/skip.

## Caveats
- Для public relay `sessionId` = TLS Finished verify_data; rustls даёт exporter — сверка с Finished в backlog.
- Probe-бины (`smp-v71`, `xftp-h2-v71`) остаются `NoVerify` по design.
