# Письмо внешнему аудитору — проект smp-rs

Уважаемый аудитор,

ниже — краткое введение в проект, на что обратить максимум внимания и какие
тесты прогнать. Цель проекта — доказуемая Rust-реализация wire-протокола
SimpleX (SMP/XFTP/agent), полностью совместимая с Haskell-оригиналом
`simplex-chat/simplexmq` (клон в `./simplexmq`, ветка stable; спецификации в
`./spec/`).

## Что это

`smp-rs` — роутер (`smp-server`), клиент (`smp-client`), XFTP HTTP/2 probe
(`xftp-h2`), плюс библиотеки: кодирование, криптография, SMP-команды,
транспорт (plain TCP + TLS 1.3), персистентность очередей, NTF-нотификации,
SMP proxy, XFTP-пакеты, agent/chat слои, PQDR KEM-слой. Всё верифицировано
live против настоящих бинарников simplexmq v6.5.0.17 (SMP over TLS :5223,
XFTP over HTTP/2 :8443): handshake, PING→PONG, NEW→IDS, SUB→SOK, SEND→MSG с
расшифровкой тела, ACK, DEL, NKEY/NMSG, FNEW→SIDS, FPUT→OK, FGET→FILE с
байт-в-байт совпадением расшифровки.

## На что обратить максимум внимания

1. **Криптография в `src/crypto.rs`** — самая критичная часть. Ручная
   реализация HSalsa20 (сверена с PyNaCl `crypto_box_beforenm` в
   `tests/xcheck.rs`), порядок байтов secretbox (NaCl mac‖ct), SPKI-шаблоны.
   В XFTP тело FILE идёт с **tail-tag** (ct‖mac) — легко перепутать.
2. **Wire-форматы** (`encoding.rs`, `protocol.rs`, `transport.rs`): pad до
   16384 (u16 len + payload + '#'), Maybe-поля (для v≥7 `Nothing` = 0 байт,
   не тег '0'), sessionId входит в signed authorized bytes, но не в wire.
3. **Аутентификация**: Ed25519 подписи команд; pinning роутера по
   SHA-256(SPKI) в TLS; X25519 box-authenticator реализован.
4. **PQDR (`src/pq.rs`)**: SNTRUP761 через сторонний crate `sntrup761 0.4` —
   рекомендуется прогнать KAT против официальных SUPERCOP-векторов;
   гибридный секрет SHA3-256(dh‖kem) имеет KAT в `tests/pqdr.rs`.
5. **Известные ограничения** (честно задокументированы в `docs/SECURITY.md`):
   sessionId = "" (tls-unique пуст для TLS 1.3 — как в оригинале), box-auth
   для обычных очередей не включён, PQDR-ratchet не реализован (только
   KEM-слой), снапшот хранилища не шифруется, probe `xftp-h2` с permissive
   verify сертификата.

## Какие тесты провести

```bash
cargo test --test-threads=1        # 33 теста: golden-векторы, e2e, KAT, tamper
```

Ключевые: `tests/wire.rs` (8 golden-байтов), `tests/interop.rs` (e2e + ERR
AUTH), `tests/xcheck.rs` (cross-check с PyNaCl — нужен python3+pynacl),
`tests/pqdr.rs` (SHA3-256 KAT `127eebf5…`, kemParams golden, tamper),
`tests/xftp.rs`, `tests/agent.rs`, `tests/chat.rs`, `tests/persist.rs`,
`tests/ntf.rs`, `tests/proxy.rs`.

Live-регрессия (опционально, нужны бинарники simplexmq v6.5.0.17): поднять
`smp-server :5223 --tls` и прогнать `smp-client --tls` — ожидается полный
цикл NEW→IDS→SUB→SEND→MSG(decrypt)→ACK→DEL.

## Как читать проект

Точка входа: `README.md` → карта модулей → `docs/AUDIT.md` (модуль→Haskell
источник). Спецификации-истина: `spec/simplex-messaging.md`,
`spec/agent-protocol.md`, `spec/simplex-file-transfer.md` + Haskell-клон
`./simplexmq`. Коммиты идут по вехам v0.2…v0.15 с доказательствами в заметке
Obsidian `Notes/Projects/smp-rs-SimpleX-SMP-Rust.md`.

Спасибо за внимание. — владелец проекта
