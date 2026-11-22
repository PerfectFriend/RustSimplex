# AUDIT REPORT — smp-rs (RustSimplex)

**Дата аудита:** 2026-11-22 · **Ревизия:** 9 · **Дерево:** `origin/main` (`dd8187f`)
**Предыдущий отчёт:** [`AUDIT-REPORT-2026-11-12.md`](AUDIT-REPORT-2026-11-12.md) — ревизия на
коммите `4e28bd3`, 4 964 строки Rust, 33 теста. **Его числа устарели**; ниже — состояние
на текущем дереве.

**Метод:** тот же чек-лист, что в `docs/RELEASE-READINESS.md` §1b — пять частей
(корректность 35 / достижимость 25 / проверка против реальности 25 / эксплуатационность 10 /
гигиена 5), плюс исполняемая проверка: `cargo test`, `cargo clippy -- -D warnings`,
`cargo audit`, `cargo package`, живой прогон против публичной инфраструктуры,
кросс-реализационные KAT.

## 1. Вердикт

**Готовность к релизу v1.0: ~88%** (LOC-взвешенно по 19 кодовым компонентам; невзвешенно
по всем 23 — 85.4%). Готово для закрытой беты и для публикации библиотеки как v0.99.1;
**не готово** к публичному production-релизу: не заказан внешний аудит (G7), publish-путь
ни разу не выполнялся (G8), FFI-smoke не в CI, у async-клиента нет собственного reconnect.

Протокольное ядро (wire/crypto/protocol/transport/XFTP/NTF) — 85–95% и проверено живыми
раунд-трипами против публичной инфраструктуры. Дыры — в слоях вокруг протокола.

## 2. Готовность по компонентам

| Компонент | LOC | Готовность | Доказательство |
|---|---:|---:|---|
| `encoding` | 131 | 95% | `tests/wire.rs`, `tests/xcheck.rs` — golden-байты |
| `crypto` | 195 | 92% | 15 наборов; HKDF-вектор RFC5869; `OsRng` для всей случайности |
| `protocol` | 451 | 95% | все 17 вариантов `Command` обработаны сервером и отправляются клиентом (вариантный diff, не grep) |
| `transport` | 472 | 90% | `tests/interop.rs`: TLS round-trip, неверный keyHash, MITM evil-leaf |
| `server` | 926 | 90% | 14 наборов; `tests/strict_e2e.rs`, `tests/p0_delivery.rs` |
| `client` | 290 | 95% | `tests/interop.rs`; `Client::onion_send` (W3) |
| `store` | 433 | 95% | `tests/persist.rs` (multi-process locking), `tests/store_migration.rs` (v1→v2 + rollback) |
| `agent` | 538 | 82% | `tests/agent.rs`; contact-link create/join/accept |
| `pq` + `pqdr` | 718 | 92% | `tests/pqdr_supercop.rs` — **SUPERCOP KAT, оба направления**, `tests/pqdr_rotation.rs` |
| `xftp` | 278 | 90% | живой FNEW/FPUT 64KB/FGET(byte-match)/FDEL + chunked 1 MiB (sha256) |
| `ntf` | 583 | 85% | живой `PING→PONG` через библиотечный `NtfClient`; подписанные `TNEW`/`SNEW` (W2) + локальный NTF-сервер e2e |
| `sb_chain` | 179 | 70% | только inline-юнит-тесты |
| `proxy` | 171 | 70% | `tests/socks5.rs`, `tests/proxy.rs`; живой путь невозможен — релей отключил proxy |
| `onion` | 157 | 90% | `tests/onion.rs`: 2-хоп + 3-хоп (W3) + негативный тест hop-key |
| `chat` | 87 | 75% | `tests/chat.rs`, `tests/chat_e2e.rs` |
| `identity` | 64 | 85% | cert chain + fingerprint; нет проверки чужого CA |
| `ffi` | 56 | 80% | `scripts/ffi_smoke.sh` → **Kotlin вызывает Rust-фасад и получает типизированную ошибку**; uniffi-биндинги генерируются офлайн |
| `reconnect` | 242 | 85% | `tests/reconnect_e2e.rs`, `tests/reconnect_backoff.rs`; подключён к `Agent` |
| `async_client` | 303 | 78% | настоящий tokio-клиент: `tests/async_client.rs` (8 тестов, TLS 1.3, strict v23) |
| Packaging / crates.io | — | 88% | `cargo package` проходит; publish ни разу не выполнялся |
| CI matrix | — | 90% | default / v71-probes / ffi / no-default-features / strict / audit / fuzz / package / **probe-isolation** / **ffi-smoke** |
| Release pipeline | — | 75% | tag → version check → tests → clippy → package → **SBOM** → **provenance** → publish |
| Docs | — | 78% | README/ROADMAP/планы/письмо аудитору актуальны |

## 3. Гейты G1–G12

| # | Цель | Готовность | Комментарий |
|---|---|---:|---|
| G1 | Подписанные NTF `TNEW`/`SNEW` | 85% | закрыт локально (e2e + wire-векторы); публичный NTF не выдаёт токены сторонним клиентам |
| G2 | Onion routing поверх SMP proxy | 90% | 2+3 хопа e2e; live невозможен — релей отключил proxy (подтверждено 2026-11-22) |
| G3 | Async-движок с auto-reconnect | 78% / 85% | настоящий tokio-клиент + backoff; у async-клиента своего reconnect нет |
| G4 | sessionId ↔ TLS 1.3 Finished | 90% | ограничение rustls-exporter задокументировано |
| G5 | Чистка `unwrap`/`expect` в `src/` | 100% | нетестовых panic-site'ов 0; `scripts/check_no_unwrap.sh` |
| G6 | PQDR: rotation, reorder, KAT | 100% | KAT кросс-реализационный (Rust ↔ supercop-20201130) |
| G7 | Внешний аудит | 0% | **не заказан — блокер релиза**; письмо готово (`docs/AUDITOR-LETTER.md`) |
| G8 | Публикация v0.99.1 | 88% | нужен `CARGO_REGISTRY_TOKEN` и первый тег |
| G9 | CI: дефолтная сборка без probe-бинов | 50% | джоб `probe-isolation` добавлен; факт верен, локальная копия workflow не прогонялась в GitHub |
| G10 | FFI-фасад для Android | 80% | cdylib + uniffi + Kotlin-smoke (локально PASS); CI-джоб добавлен, ещё не прогонялся в GitHub |
| G11 | Live NTF/XFTP против публичных релеев | 85% | XFTP 1 MiB byte-exact, NTF PONG; NTF-токенов нет |
| G12 | Актуальная документация | 78% | этот отчёт + readiness §0; старый отчёт сохранён как история |

## 4. Что изменилось с отчёта 2026-11-12

- **Async-клиент переписан**: был sync-фасад в worker thread (35%, мёртвый код) — теперь
  настоящий `tokio` + `tokio-rustls` клиент с TLS 1.3, pinning и strict v23 (`tests/async_client.rs`).
- **Reconnect перестал быть мёртвым**: подключён к `Agent` через трейт `SmpTransport`,
  добавлен backoff-цикл с записываемыми задержками (`tests/reconnect_backoff.rs`).
- **PQDR верифицирован против SUPERCOP** (оба направления, негативный контроль), добавлены
  ротация ключей и reorder-окно.
- **Store**: версионированный формат + миграции с rollback, advisory-lock, single-instance guard,
  уникальные temp-имена.
- **FFI**: `crate-type = cdylib`, uniffi-обвязка, Kotlin-биндинги и **реально проходящий**
  Kotlin-smoke.
- **Live-прогоны**: SMP v17–v23, XFTP 1 MiB byte-exact, NTF PONG, proxy — отказ релея как
  подтверждённый факт (`docs/live/live-interop-2026-11-22.log`).
- **Релиз-пайплайн**: SBOM (CycloneDX) + attestation provenance.

## 5. Известные ограничения (честно)

1. `sessionId = ""` на обеих сторонах — как в Haskell-оригинале (tls-unique пуст в TLS 1.3).
2. Box-authenticator для обычных очередей не включён.
3. Legacy-проба `xftp-h2` использует permissive-проверку сертификата; рабочая `xftp-h2-v71`
   требует CA-пин и отказывается работать без него.
4. Публичные релеи отключили SMP proxy серверной стороне → живая проверка proxy невозможна.
5. Публичный NTF-сервер не выдаёт токены сторонним клиентам → G1 закрыт локально.
6. `xsalsa20poly1305` не поддерживается upstream (переименован, исправления нет).
7. Агентский слой не проверен настоящим мобильным клиентом SimpleX.

## 6. Команды-доказательства

```bash
cargo test --offline                        # 148/0
cargo test --offline --features v71-probes  # 150/0
cargo clippy --offline --all-targets -- -D warnings
bash scripts/check_no_unwrap.sh
bash scripts/ffi_smoke.sh
bash scripts/live_interop.sh
python3 scripts/sbom.py --output target/package/sbom.cdx.json
bash scripts/supercop_kat_regen.sh          # пересобрать SUPERCOP-векторы (нужен gcc+openssl)
```
