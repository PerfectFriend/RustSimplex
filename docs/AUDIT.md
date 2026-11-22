# AUDIT.md — как аудитировать smp-rs

## Быстрый старт

```bash
cd simplex-rs
export CARGO_HOME=$HOME/build/rust/cargo   # если toolchain в ~/build
cargo test --test-threads=1                # 148 тестов, все зелёные (2026-11-22)
cargo clippy --all-targets 2>/dev/null | tail # замечания не fatal
```

## Карта модулей → Haskell-источник (simplexmq stable, клон в ./simplexmq)

| Rust | Haskell | Что проверять в первую очередь |
|---|---|---|
| `src/encoding.rs` | `Simplex.Messaging.Encoding` | shortString/largeString/pad; golden-векторы в `tests/wire.rs` |
| `src/crypto.rs` | `Simplex.Messaging.Crypto` | HSalsa20 ручной (сверен с PyNaCl `crypto_box_beforenm`, `tests/xcheck.rs`); порядок байтов secretbox mac‖ct; SPKI шаблоны 44B |
| `src/protocol.rs` | `Protocol.hs` | transmission = short(auth) short(corrId) short(entityId) cmd; блок 16384 = pad(count‖large(tx)…) |
| `src/transport.rs` | `Transport.hs` | serverHello/clientHello; v≥7: authPubKey Maybe ('0' = Nothing, 0 байт!) |
| `src/server.rs` | `Server.hs` (SMP) | verify_sign/verify_box; MSG body = secretbox(rcvDhSecret, cbNonce(msgId), pad(body,16104)); rcvMeta = msgTs Int64 BE + flags + ' ' |
| `src/pq.rs` | `Crypto/SNTRUP761.hs` | kemHybridSecret = SHA3-256(dh‖kem) (KAT в tests/pqdr.rs против hashlib); kemParams '0'/'1P'/'1A' largeString |
| `src/xftp.rs`, `src/bin/xftp_h2.rs` | `FileTransfer/*`, `Transport/HTTP2` | блок = u16 len + payload + 0x23-pad до 16384; FILE tail-tag ct‖mac; tEncodeBatch1 |
| `src/agent.rs`, `src/chat.rs` | `protocol/agent-protocol.md` | decryptedAgentMessage I/D/M…; connInfo JSON + e2eRatchetParams |
| `src/pqdr.rs` | `Crypto/SNTRUP761.hs`, ratchet | rotation/reorder-window; SUPERCOP KAT в `tests/pqdr_supercop.rs` (эталон — `simplexmq/cbits/sntrup761.c`) |
| `src/ntf.rs` | `Simplex.Messaging.NtfServer` | подписанные `TNEW`/`SNEW` (Ed25519), CA-пин обязателен; локальный NTF-сервер e2e |
| `src/store.rs` | `Simplex.Messaging.Server` | версионированный формат (v1→v2), миграции с rollback, advisory-lock, single-instance |
| `src/reconnect.rs` | — | backoff-цикл, `ReconnectingClient` подключён к `Agent` через `SmpTransport` |
| `src/async_client.rs` | — | настоящий async-клиент (`tokio` + `tokio-rustls`), TLS 1.3, strict v23 |
| `src/ffi.rs`, `src/ffi/uniffi.rs` | — | uniffi-фасад; Kotlin-smoke — `scripts/ffi_smoke.sh` |

## Ключевые известные-answer тесты

- `tests/xcheck.rs` — cross-check NaCl crypto_box beforenm против PyNaCl.
- `tests/pqdr.rs` — SHA3-256 KAT (`127eebf5…`), kemParams golden-байты,
  tamper → decrypt fail.
- `tests/wire.rs` — 8 golden-векторов байтов.
- `tests/interop.rs` — e2e Rust↔Rust: NEW→IDS→SUB→SEND→MSG→decrypt→ACK→DEL,
  plus `ERR AUTH` при неверном ключе.

## Полный аудит-отчёт и готовность к релизу

- `docs/AUDIT-REPORT.md` — актуальный отчёт (ревизия 9, 2026-11-22): готовность по
  компонентам, гейты G1–G12, ограничения, команды-доказательства.
- `docs/AUDIT-REPORT-2026-11-12.md` — предыдущий отчёт (история; его числа устарели).
- `docs/RELEASE-READINESS.md` §0 — сводная готовность к релизу.

## Live interop (верифицировано против настоящих бинарников v6.5.0.17 и против публичной
инфраструктуры; лог прогона 2026-11-22 — `docs/live/live-interop-2026-11-22.log`)

- SMP: `smp-server :5223 --tls` → PING→PONG, NEW→IDS, SUB→SOK, SEND→MSG
  (decrypt OK), ACK, DEL; NKEY→NID, NSUB, SEND(notify)→NMSG.
- XFTP: `xftp-server` (порт 8443) → handshake v3, PING→PONG, FNEW→SIDS,
  FPUT 64KB→OK, FGET→FILE, decrypt байт-в-байт (sha256 fee47b1f…).

## На что обратить максимум внимания (см. также AUDITOR-LETTER.md)

1. **Порядок MAC/ciphertext** в secretbox vs tail-tag в XFTP FILE — место,
   где легко ошибиться.
2. **Maybe-кодирование** ('0' = 0 байт для v≥7 в authPubKey, а не один байт '0').
3. **sessionId в authorized bytes** — включён в подпись, но не в wire (v≥7).
4. **HSalsa20 ручная реализация** в crypto.rs — сверена с PyNaCl, но это
   рукописная криптография.
5. **sntrup761 crate** — сторонняя pure-Rust реализация; KAT против
   SUPERCOP-векторов — рекомендуемый дополнительный тест.
