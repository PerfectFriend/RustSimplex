# smp-rs — Rust-реализация протокола SimpleX Messaging Protocol (SMP)

Чистая Rust-реализация того wire-протокола, на котором работают **SimpleX Chat** и
**simplexmq server** (Haskell). Цель — доказуемая, протестированная реализация SMP:
кодирование, криптография, команды, транспортные блоки, роутер (server) и клиент.

Источник правды: репозиторий `simplex-chat/simplexmq` (ветка `stable`, клон в `./simplexmq`)
и спецификация `spec/simplex-messaging.md` (SMP v20, 2026-05-25).

## Что реализовано

| Слой | Модуль | Соответствие Haskell |
|---|---|---|
| Базовое кодирование | `src/encoding.rs` | `Simplex.Messaging.Encoding` — shortString (1B len), largeString (2B BE), Maybe `"0"/"1"`, Bool `"T"/"F"`, pad = `word16BE(len) <> msg <> '#'*n` |
| Крипто | `src/crypto.rs` | `Simplex.Messaging.Crypto` — X25519 DH, Ed25519 подписи, ключи как X.509 SPKI DER (фиксированные 44-байтные шаблоны), NaCl crypto_box = XSalsa20-Poly1305 secretbox (MAC \|\| ciphertext), CbNonce 24B, KeyHash = SHA-256 |
| Команды/сообщения | `src/protocol.rs` | `Protocol.hs` — NEW/IDS/SUB/SOK/SEND/MSG/ACK/KEY/SKEY/GET/OFF/DEL/PING + OK/ERR/PONG/END/DELD |
| Транспорт | `src/protocol.rs`, `src/transport.rs` | transmission = `short(auth) short(corrId) short(entityId) cmd`; блок 16384B = `pad( count <> concat(large(transmission)) )`; handshake routerHello/clientHello |
| Аутентификация | `src/protocol.rs` | Ed25519 signature поверх `short(sessionId) <> short(corrId) <> short(entityId) <> cmd` (v≥7: sessionId в хэше, но не в wire); X25519 crypto_box authenticator = `secretbox(dhSecret, cbNonce(corrId), sha512(authorized))` |
| Роутер | `src/server.rs` | in-memory очередь: NEW→IDS, SUB→SOK+push, SEND→store+push MSG, MSG body = `secretbox(rcvDhSecret, cbNonce(msgId), pad(body,16104))`, ACK, KEY/SKEY, DEL, PING |
| Клиент | `src/client.rs` | handshake + request/response по блокам |

Негoshiated версия: **SMP v17** (`newNtfCredsSMPVersion`) — «полная» форма, где все
опциональные поля NEW/IDS передаются как Maybe.

## Проверка

```
cargo test --test-threads=1   # 33 теста, все зелёные (2026-11-12)
```

- `tests/wire.rs` — 8 golden-векторов байтов (pad, SPKI OID offset 6, NaCl
  secretbox tag-first, блок 16384, подпись transmission).
- `tests/interop.rs` — e2e Rust-клиент↔Rust-сервер по TCP и по TLS 1.3.
- `tests/xcheck.rs` — cross-check crypto_box beforenm против PyNaCl.
- `tests/pqdr.rs` — SNTRUP761 KEM, SHA3-256 KAT гибридного секрета, kemParams.
- `tests/xftp.rs`, `tests/agent.rs`, `tests/chat.rs`, `tests/persist.rs`,
  `tests/ntf.rs`, `tests/proxy.rs` — e2e по слоям.
- Live interop верифицирован против настоящих simplexmq v6.5.0.17:
  SMP over TLS (`PING→PONG, NEW→IDS, SUB→SOK, SEND→MSG decrypt OK, ACK, DEL`,
  NTF `NKEY→NID, NSUB→NMSG`) и XFTP over HTTP/2 (`FNEW→SIDS, FPUT→OK,
  FGET→FILE`, расшифровка байт-в-байт). См. `docs/AUDIT.md`.

## намеченные отклонения / границы

- TLS 1.3 транспорт реализован (rustls, ALPN `smp/1`, pin по keyHash).
  sessionId = "" (tls-unique пуст для TLS 1.3, как в оригинале); клиентская
  assert-проверка sessionId (v0.16, `check_session_binding`) и X25519 box-auth
  для обычных очередей (v0.16, `request_box`/`verify_box` + ALG1 в снапшоте) —
  реализованы, покрыты e2e-тестом `tls_x25519_box_auth_roundtrip`.
- PQDR: KEM-слой SNTRUP761 + полный double ratchet (v0.17, `src/pqdr.rs`) — KDF как в
  оригинале (HKDF-SHA512, `SimpleXRootRatchet`/`SimpleXChainRatchet`), два KEM-раунда
  на DH-ratchet шаг; отклонения wire-формата задокументированы в SECURITY.md.
- `xftp-h2` — probe с permissive verify сертификата, не для production.
- Снапшот `--store`: при env `SMP_STORE_KEY` (hex 32B) шифруется XSalsa20-Poly1305
  (`SMP1` magic + nonce), без ключа — plaintext (legacy). Подробнее: `docs/SECURITY.md`.
- Для внешнего аудита: `docs/AUDIT.md` и `docs/AUDITOR-LETTER.md`.

## Структура

```
src/encoding.rs  src/crypto.rs  src/protocol.rs  src/transport.rs  src/server.rs  src/client.rs
src/bin/smp_server.rs  src/bin/smp_client.rs
tests/wire.rs  tests/interop.rs
spec/            спецификации SMP (simplex-messaging.md, agent-protocol.md, simplex-chat.md)
simplexmq/       Haskell reference (клон simplex-chat/simplexmq @ stable)
```
