# ROADMAP — simplex-rs

> Актуальный бэклог и оценки готовности: **`docs/plans/2026-11-21_v1-evolution-plan.md`**
> (8 волн, 32 задачи) и **`docs/RELEASE-READINESS.md`** (аудит, ревизия 9).
> Этот файл — краткая история и указатель; правки вносятся вместе с планом.

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

## Done (v0.90–v0.99.1, аудит ревизия 9)
- Библиотечный `NtfClient` (`src/ntf.rs`): `connect` с **обязательным** CA-пином (fail-closed
  до любого I/O), `request`, `request_with_corr`, `ping`; живой `PING→PONG` против `ntf2.simplex.im`.
- `xftp-h2-v71`: обязательный CA-пин из argv/env, exit 3 при несовпадении **до** первого байта XFTP;
  живой полный цикл FNEW→SIDS→FPUT→FGET(byte-exact)→FDEL.
- Тегсет NTF (TNEW/SNEW/PING/TVFY/TCHK/TRPL/TDEL/TCRN/SCHK/SDEL) и batch-фрейминг (u8 count + Large).
- `store::save_with_key` / `load_with_key` — явный ключ вместо process-global `SMP_STORE_KEY`;
  устранена гонка в параллельных тестах (12 прогонов подряд, 0 падений).
- Аудит ревизии 9: 23 компонента оценены по единому чек-листу; **81.3% LOC-взвешенно**.
- CI: матрица default / v71-probes / ffi / no-default-features / strict / audit / fuzz / package —
  без `continue-on-error` и `|| true`.
- Release pipeline: 3 блокирующих дефекта исправлены (версия `Cargo.toml`, коммит changelog
  в неизменяемый tag-ref, публикация не из тегированного коммита).
- `cargo audit`: 0 уязвимостей; 1 предупреждение — `xsalsa20poly1305` переименован upstream
  в `crypto_secretbox` (исправленной версии нет).

## Next — план эволюции до v1.0 (100%)

Критический путь: **W0 → W1 → W2 → W4 → W5 → W6 → W7**.

| Волна | Содержание | Цели |
|---|---|---|
| **W0** | Убрать ложные утверждения из README/ROADMAP | — |
| **W1** ✅ | `async_client` удалён, `reconnect` подключён через трейт `SmpTransport`, shutdown-флаг сервера починен | G3 (частично) |
| **W2** | **NTF подписанные команды** `TNEW`/`SNEW` + локальный NTF-сервер для e2e | G1 |
| **W3** | `Client::onion_send`, 3+ хопов, sessionId ↔ TLS 1.3 Finished, live XFTP 1 MiB, `upload_file_stream` | G2, G4, G11 |
| **W4** | Настоящий async-клиент, backoff-цикл для мобильного | G3 |
| **W5** | `crate-type = cdylib` → uniffi → Kotlin smoke-test | G10 |
| **W6** | SUPERCOP KAT для sntrup761, key rotation + reorder window, multi-process locking в store, миграции store | G6, G11 |
| **W7** | CI-ассерт на probe-бины, регенерация `AUDIT-REPORT.md`, внешний аудит, `cargo publish`, SBOM, финальный аудит | G7, G8, G9, G12 |

Полный разбор: `docs/plans/2026-11-21_v1-evolution-plan.md`.

## Caveats
- Probe bins (`smp-v71`, `xftp-h2-v71`, `ntf-probe`) — за feature-флагом `v71-probes`, не для production.
- `src/async_client.rs` удалён (спринт W1): фасад над *синхронным* клиентом через
  `spawn_blocking`, ни одного вызывающего. Настоящий async-клиент с auto-reconnect —
  задача W4.
- `src/reconnect.rs` подключён (спринт W1): `Agent` обобщён над трейтом `SmpTransport`,
  `ReconnectingClient` реализует его; покрыт `tests/reconnect_e2e.rs`.
- Публичные релеи отключили SMP proxy серверной стороне — живая проверка proxy невозможна,
  покрытие локальное (`tests/onion.rs`, `tests/socks5.rs`).
- Публичный NTF-сервер не выдаёт токены сторонним клиентам — критерий G1: локальный e2e +
  golden-векторы против Haskell-эталона.
- Для публичных релеев keyHash = SHA-256 от DER **CA-сертификата**; local identity использует
  offline CA DER.

## Sprint log

### W1 — Dead-code removal & reconnect wiring (2026-11-21)

| Task | Result | Proof |
|---|---|---|
| W1.1 Удалить мёртвый `async_client` | ✅ | `tests/public_api.rs::async_client_is_not_exposed_while_dead` |
| W1.2 Подключить `reconnect` к живому пути | ✅ | `tests/reconnect_e2e.rs` (2 теста) |
| W1.3 Структурный инвариант «нет мёртвых `pub mod`» | ✅ | `tests/public_api.rs` (3 теста) |
| W1.4 Починить shutdown-флаг `Engine::serve` | ✅ | `Engine::serve` — non-blocking accept + poll |

**Найдено по ходу (не в плане):** `Engine::serve` проверял флаг `shutdown` *после*
блокирующего `accept()`, поэтому сервер без клиентов было невозможно остановить —
флаг не действовал никогда. Исправлено: non-blocking listener + опрос с паузой 20 мс.
Побочно выявлено, что общий `CARGO_TARGET_DIR` содержал протухший `rlib` —
`cargo` линковал старую сборку и показывал «Finished» без пересборки.
Верификация выполняется в чистом target-директории.

**Прогон:** 95 тестов, 0 падений (полный `cargo test`).
