# smp-rs — Rust-реализация протокола SimpleX Messaging Protocol (SMP)

Чистая Rust-реализация wire-протоколов, на которых работают **SimpleX Chat** и
**simplexmq server** (Haskell): SMP (relay), XFTP (files), NTF (notifications), agent-протокол
и PQDR double-ratchet. Цель — доказуемо совместимая с официальными серверами реализация:
каждый заявленный «работает» подтверждён живым round-trip'ом против публичной инфраструктуры
или против Haskell-референса.

Источник правды: репозиторий `simplex-chat/simplexmq` (клон в `./simplexmq`) и спецификации
в `spec/`. При расхождении спецификации и реализации **побеждает реализация** (Haskell-код).

## Что реализовано

| Слой | Модуль | Соответствие Haskell |
|---|---|---|
| Базовое кодирование | `src/encoding.rs` | `Simplex.Messaging.Encoding` — shortString (1B len), largeString (2B BE), Maybe `"0"/"1"`, Bool `"T"/"F"`, pad = `word16BE(len) <> msg <> '#'*n` |
| Крипто | `src/crypto.rs` | `Simplex.Messaging.Crypto` — X25519 DH, Ed25519 подписи, X.509 SPKI DER, NaCl crypto_box = XSalsa20-Poly1305 (MAC \|\| ciphertext), CbNonce 24B, KeyHash = SHA-256 |
| Команды | `src/protocol.rs` | `Protocol.hs` — NEW/IDS/SUB/SOK/SEND/MSG/ACK/KEY/SKEY/GET/OFF/DEL/PING + OK/ERR/PONG/END/DELD |
| Транспорт | `src/transport.rs` | transmission = `short(auth) short(corrId) short(entityId) cmd`; блок 16384B = `pad( count <> concat(large(transmission)) )`; handshake routerHello/clientHello; TLS 1.3 + пиннинг по CA-fingerprint |
| Роутер | `src/server.rs` | in-memory очередь + push, NTF-креденшелы, XFTP-пакеты, snapshot с AEAD-шифрованием |
| Клиент | `src/client.rs`, `src/async_client.rs`, `src/reconnect.rs` | handshake, запрос/ответ по блокам, авто-reconnect с backoff, async-движок |
| **NTF** | `src/ntf.rs` | `Notifications/Transport.hs` — отдельный протокол: блок **512B**, свой handshake (`NtfServerHandshake`/`NtfClientHandshake`), свой тегсет команд (`TNEW/SNEW/PING`), batch-трансмиссии (`u8 count` + `Large`), `implySessId`. Публичный API: `NtfClient` (`connect` с обязательным пиннингом CA, `request`, `ping`) |
| E2E | `src/pqdr.rs` | `Ratchet.hs` — SNTRUP761 KEM + double ratchet, KDF HKDF-SHA512 (`SimpleXRootRatchet`/`SimpleXChainRatchet`) |
| Agent | `src/agent.rs`, `src/chat.rs` | agent-протокол v7..v20, PQDR E2E **включён по умолчанию** |

## Проверка

```bash
cargo test --offline -- --test-threads=1                     # 90 тестов, все зелёные
SMP_STRICT=1 cargo test --offline --test strict_e2e --test ntf --test proxy   # 3/3
cargo clippy --offline --all-targets                         # 0 warnings
cargo clippy --offline --features v71-probes --all-targets   # 0 warnings
```

Тесты обязаны запускаться с `--test-threads=1`: часть тестов мутирует process-wide env.

### Live-интероп (проверено против публичной инфраструктуры)

| Цель | Результат |
|---|---|
| `smp11.simplex.im:5223` (SMP v17–v23) | полный цикл `PING→PONG, NEW→IDS, SUB→SOK, SEND→MSG(decrypt), ACK→OK, DEL→OK` — все 7 версий |
| `xftp1.simplex.im:443` (XFTP v4) | `PING→PONG, FNEW→SIDS, FPUT 64KB→OK, FGET→FILE (byte-exact decrypt), FDEL→OK` |
| `ntf2.simplex.im:443` (NTF, ALPN `ntf/1`) | handshake принят, **`PING→PONG` через библиотечный `NtfClient`** (NTF v3, sessionId 32B, corrMatch=true); пин CA-fingerprint подтверждён отрицательным контролем (неверный пин → exit 3, ничего не отправляется) |
| onion routing поверх SMP proxy | 2-hop round-trip + отрицательный тест (неверный hop-key) |

Скрипты: `scripts/live_public_smp.sh`, `scripts/live_interop.sh`, `scripts/check.sh`.

## Границы и отклонения

- TLS 1.3 транспорт — rustls, ALPN `smp/1`, **пиннинг по fingerprint CA-сертификата** + проверка
  подписи leaf'а (два отрицательных MITM-теста в `tests/interop.rs`).
  Для публичных релеев и NTF используется openssl-слой (feature `v71-probes`): hs-tls требует
  ed448 в `signature_algorithms`, а rustls не умеет — это ограничение стека, не протокола.
- `src/bin/*` — диагностические бинарники (behind `v71-probes`), не для production.
- NTF: транспорт и `PING` доказаны вживую; подписанные команды (`SNEW`/`TNEW` с Ed25519-авторизацией)
  ещё не реализованы — см. `docs/RELEASE-READINESS.md`.
- Снапшот `--store`: при env `SMP_STORE_KEY` (hex 32B) шифруется XSalsa20-Poly1305
  (`SMP1` magic + nonce), без ключа — plaintext (legacy). Подробнее: `docs/SECURITY.md`.
- PQDR: отклонения wire-формата задокументированы в `docs/SECURITY.md`.

## Документы

- `docs/RELEASE-READINESS.md` — аудит и оценка готовности к релизу (проценты по слоям, гейты v1.0).
- `docs/AUDIT.md`, `docs/AUDITOR-LETTER.md`, `docs/SECURITY.md`, `docs/ROADMAP.md`.
- `docs/AUDIT-PROMPT.md` — промпт для внешнего аудитора.

## Структура

```
src/encoding.rs  src/crypto.rs  src/protocol.rs  src/transport.rs  src/server.rs  src/client.rs
src/ntf.rs  src/pqdr.rs  src/agent.rs  src/chat.rs  src/proxy.rs  src/onion.rs  src/xftp.rs
src/async_client.rs  src/reconnect.rs  src/store.rs  src/identity.rs  src/ffi.rs
src/bin/            диагностические бинарники (smp-server, smp-client, smp-v71, xftp-h2-v71, ntf-probe)
tests/              20 интеграционных наборов (wire, interop, agent, chat, ntf, proxy, onion, pqdr, ...)
spec/               спецификации SMP/agent/XFTP
simplexmq/          Haskell reference (клон simplex-chat/simplexmq)
```

## Лицензия

MIT (см. `LICENSE`).