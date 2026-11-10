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
cargo test        # 10 тестов, все зелёные
```

- `tests/wire.rs` — 8 golden-векторов: точные байты shortString/largeString/pad,
  SPKI-шаблоны (OID на offset 6), NaCl-формат secretbox, layout блока 16384B,
  подпись/верификация transmission.
- `tests/interop.rs` — 2 end-to-end теста Rust-клиент ↔ Rust-сервер по TCP:
  полный цикл `NEW→IDS, SUB→SOK, SEND→OK, push MSG→decrypt→ACK→OK, DEL→DELD`
  и отказ в авторизации при неверном ключе (`ERR AUTH`).

Живой запуск:

```
./smp-server 127.0.0.1:5599        # роутер
./smp-client 127.0.0.1:5599        # PING→PONG, NEW→IDS, печатает smp:// URI
```

## намеченные отклонения / границы

- Транспорт — plain TCP (sessionId = `""`, без TLS). Поэтому auth — Ed25519-подпись
  (ветка `TASignature`, поддерживается сервером). X25519 crypto_box-authenticator
  требует router session key из TLS-handshake — реализован (`auth_box`/`verify_box`),
  но в plain-режиме не используется.
- Ответ на `SEND` — `OK` (локальная договорённость для request/response; в Haskell
  ответ на SEND может отсутствовать).
- TLS 1.3 транспорт (ChaCha20-Poly1305, Ed25519, X25519, ALPN `smp/1`, проверка
  router identity по SHA-256 SPKI) — не реализован; для интероп с настоящим
  `smp-server` нужен этот слой (rustls + tls-unique как sessionId).

## Структура

```
src/encoding.rs  src/crypto.rs  src/protocol.rs  src/transport.rs  src/server.rs  src/client.rs
src/bin/smp_server.rs  src/bin/smp_client.rs
tests/wire.rs  tests/interop.rs
spec/            спецификации SMP (simplex-messaging.md, agent-protocol.md, simplex-chat.md)
simplexmq/       Haskell reference (клон simplex-chat/simplexmq @ stable)
```
