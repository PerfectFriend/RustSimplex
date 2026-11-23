# Письмо внешнему аудитору — проект smp-rs

Уважаемый аудитор,

ниже — краткое введение в проект, на что обратить максимум внимания и какие
тесты прогнать. Цель проекта — доказуемая Rust-реализация wire-протокола SimpleX
(SMP/XFTP/agent), полностью совместимая с Haskell-оригиналом
`simplex-chat/simplexmq` (клон в `./simplexmq`, ветка stable; спецификации в
`./spec/`).

**Состояние на 2026-11-23:** готовность к релизу ~88% кода (LOC-взвешенно, 20 кодовых
компонентов, 6526 LOC) — разбор по компонентам с доказательствами в
`docs/RELEASE-READINESS.md` §0. Сюита: 162 теста (default), 0 падений; clippy — 0
предупреждений; `cargo audit` — 0 уязвимостей (4 известных advisory в allowlist).

Что изменилось за последний спринт (2026-11-23) — три крупные вещи, все с тестами:
1. **Официальный agent-envelope**: все agent-кадры идут в конверте
   (`agentVersion` + `"M"`/`"C"` + payload), и **payload теперь шифруется PQDR-речетом
   целиком** (`Agent::encrypt_frame`), а не только поле `Msg.body`.
2. **X448 (RFC 7748)** (`src/x448.rs`): keypair/DH/SPKI, golden-вектор сверен с
   OpenSSL (`python cryptography`) байт-в-байт; ключи обмениваются в agent-flow,
   обе стороны выводят одинаковый общий секрет (проверено e2e-тестом дуплекса).
3. **Publish-путь выполнен end-to-end**: после верификации email `cargo publish`
   прошёл — **v0.99.1 опубликован на crates.io** (2026-11-23, checksum
   `4ea568a937a22743d2bc98c5b7aa3f89c5fe29172a588b682531ba6178a96c09`), создан тег
   `v0.99.1` и GitHub Release. Изменения метаданных по пути: категория `protocols`
   не входит в список crates.io — заменена на пять валидных slug'ов.

## Что это

`smp-rs` — роутер (`smp-server`), клиент (`smp-client`), XFTP HTTP/2 probe
(`xftp-h2`), плюс библиотеки: кодирование, криптография, SMP-команды,
транспорт (plain TCP + TLS 1.3), персистентность очередей, NTF-нотификации,
SMP proxy, XFTP-пакеты, agent/chat слои, PQDR KEM-слой. Всё верифицировано
live против настоящих бинарников simplexmq v6.5.0.17 (SMP over TLS :5223,
XFTP over HTTP/2 :8443): handshake, PING→PONG, NEW→IDS, SUB→SOK, SEND→MSG с
расшифровкой тела, ACK, DEL, NKEY/NMSG, FNEW→SIDS, FPUT→OK, FGET→FILE с
байт-в-байт совпадением расшифровки.

Живой прогон от 2026-11-22 (лог в репозитории: `docs/live/live-interop-2026-11-22.log`,
exit 0): SMP v17…v23 — 7/7 OK; XFTP v4 полный цикл FNEW/FPUT 64KB/FGET(byte-match)/FDEL — OK;
chunked 1 MiB (sha256-сверка) — OK; NTF v3 `PING→PONG` через библиотечный `NtfClient`
(CA-пин) — OK; **PROXY → `ERR CMD SYNTAX`** — публичные релеи отключили proxy
серверной стороне, это подтверждённый факт, а не «не проверено».

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
4. **PQDR (`src/pq.rs`, `src/pqdr.rs`)** — **KAT уже прогнан против официальных
   SUPERCOP-векторов**: эталон — вендоренный с simplexmq `supercop-20201130`
   `cbits/sntrup761.c` (sha256 `54f135627eb965bc41f3296e206b593694186060e08256c2a039bf1966e3e017`),
   C-харнесс `scripts/supercop_sntrup761_kat.c`, векторы `tests/fixtures/sntrup761_kat.txt`,
   тест `tests/pqdr_supercop.rs`. Проверены **оба направления** (Rust декапсулирует
   эталонный ciphertext; эталон декапсулирует Rust-овский), плюс негативный контроль:
   искажение байта роняет тест. Пересборка — `scripts/supercop_kat_regen.sh`.
   Гибридный секрет SHA3-256(dh‖kem) имеет KAT в `tests/pqdr.rs`.
   Ротация ключей и reorder-окно реализованы (`tests/pqdr_rotation.rs`).
5. **Store** (`src/store.rs`): версионированный формат (v1 legacy → v2 с
   checksum), миграции с rollback (`store::migrate_store`), advisory-lock и
   single-instance guard (`store::update_store`, `smp-server`).
   **Известные ограничения (честно задокументированы в `docs/SECURITY.md`)**:
   sessionId = "" (tls-unique пуст для TLS 1.3 — как в оригинале), box-auth
   для обычных очередей не включён, legacy-проба `xftp-h2` (не `xftp-h2-v71`)
   использует permissive-проверку сертификата — рабочий `xftp-h2-v71` требует
   CA-пин и отказывается работать без него.

## Какие тесты провести

```bash
cargo test --offline                        # 148 тестов (default)
cargo test --offline --features v71-probes  # 150 тестов (probe-фичи)
cargo clippy --offline --all-targets -- -D warnings
bash scripts/ffi_smoke.sh                   # Kotlin -> uniffi -> JNA -> cdylib -> Rust
bash scripts/live_interop.sh                # живой прогон против публичных релеев
```

Ключевые: `tests/wire.rs` (8 golden-байтов), `tests/interop.rs` (e2e + ERR
AUTH), `tests/xcheck.rs` (cross-check с PyNaCl — нужен python3+pynacl),
`tests/pqdr.rs` (SHA3-256 KAT `127eebf5…`, kemParams golden, tamper),
`tests/pqdr_supercop.rs` (SUPERCOP KAT), `tests/pqdr_rotation.rs` (rotation/reorder),
`tests/store_migration.rs` (миграции + rollback), `tests/persist.rs` (multi-process
locking), `tests/xftp.rs`, `tests/agent.rs`, `tests/chat.rs`, `tests/ntf*.rs`,
`tests/proxy.rs`, `tests/onion.rs`.

Live-регрессия (опционально, нужны бинарники simplexmq v6.5.0.17): поднять
`smp-server :5223 --tls` и прогнать `smp-client --tls` — ожидается полный
цикл NEW→IDS→SUB→SEND→MSG(decrypt)→ACK→DEL.

## Как читать проект

Точка входа: `README.md` → карта модулей → `docs/AUDIT.md` (модуль→Haskell
источник) и `docs/RELEASE-READINESS.md` §0 (готовность по компонентам с
командами-доказательствами). Спецификации-истина: `spec/simplex-messaging.md`,
`spec/agent-protocol.md`, `spec/simplex-file-transfer.md` + Haskell-клон
`./simplexmq`. Коммиты идут по вехам v0.2…v0.99.1 с доказательствами в заметке
Obsidian `Notes/Projects/smp-rs-SimpleX-SMP-Rust.md`.

Спасибо за внимание. — владелец проекта
