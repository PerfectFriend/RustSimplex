# Внутренний аудит исполнения плана эволюции — 2026-11-25

**Объект:** `simplex-rs` @ `eeb4aae` (main, live-verified: `git ls-remote` == local HEAD).
**База аудита:** план `docs/plans/2026-11-25-evolution.md` (24 находки аудита #3, спринты A/B/C).
**Метод:** каждый пункт плана — один коммит с регрессионным тестом; после каждого шага
`cargo test --locked` (полный suite), `cargo clippy --locked --all-targets` (0 warnings),
`scripts/check_no_unwrap.sh`, `scripts/check-tree-hygiene.sh`, затем push и сверка remote.

## 1. Покрытие плана

| Пункт | Статус | Коммит(ы) |
|---|---|---|
| A: U-01 fail-closed E2E decode | done (был до сессии, проверен: ACK+drop для forged frames) | — |
| A: U-02 RFWD fixed-array try_into | done | — |
| A: U-04 SKEY by snd_id + mandatory sig; KEY→rcv_auth; RFWD keeps eph | **done в этой сессии** | `efed7fc` |
| A: U-05 persist race (revision + PERSIST_MUTEX, no ERR-triggered fsync) | **done** | `efed7fc` |
| A: U-06 store fail-closed | done (проверен) | — |
| A: U-07 x25519_dh_checked на всех call sites | done (проверен: 9 sites) | — |
| A: U-08 KEM ct обязателен на DH-ratchet | done (проверен: `pqdr.rs` CtPk-only) | — |
| A: U-09 NoVerify за feature-gate | done (проверен) | — |
| A: U-10 SSRF full ranges incl. IPv4-mapped v6, CGNAT, NAT64, Teredo, doc | **done + 10 тест-векторов** | `efed7fc` |
| A: U-11 strict fail-closed | **done** | `efed7fc` |
| A: U-12 ACK после decrypt, нет потери MSG в блоке | done (проверен в `agent.rs`) | — |
| A: U-13/U-19 conn cap, handshake timeout, квоты очередей/proxy/XFTP, валидация FNEW/FPUT | **done + tests `audit3_u13`** | `83b3652` |
| B: U-03/U-21 FFI pinned TLS + real msg_id/prev_hash | **done** (`create/join_contact_tls`, `recv_agent_full`) | `c1adfba` |
| B: U-15 proxy/onion TLS 1.3 + PinVerifier при реальном keyHash | **done** | `c1adfba` |
| B: U-16 TLS: пустой session binding = отказ | **done** | `1662d0e` |
| B: U-17 XFTP download: 0o600 tmp, verify sha256/size, atomic rename, cleanup | **done + tests `audit3_u20`** | `0aab515` |
| B: U-18 reconnect восстанавливает SUB | **done + test `audit3_u18`** | `1662d0e` |
| B: U-20 SOCKS5 u8-len поля до сети; SMP_DUMP_RAW за feature `debug-dump` + 0o600 | **done + tests** | `0aab515` |
| B: U-20b checked_add в `Reader::take` | **done + test** | `0aab515` |
| C: U-23 CI: no-unwrap job, MSRV 1.87 job | **done** | `eeb4aae` |
| C: U-24 hygiene: backup-bin удалён ранее, spec-stub заменён, CHANGELOG дедуп, скрипты без личных путей | **done** | `eeb4aae` |

## 2. Ошибки, допущенные в ходе исполнения (найдены и исправлены)

1. **U-19: неверная семантика `offset` в FPUT.** Я валидировал `offset + chunk.len() > size`,
   но в XFTP `offset` — это **индекс чанка (u32)**, не байтовое смещение. Это сломало легитимный
   upload (`FPUT chunk 0 failed: QUOTA offset` — поймал тест `audit3_u20`). Исправлено на cap по
   индексу; регрессия закрыта тестом.
2. **U-18: re-SUB через `request()` проглатывал pushed MSG.** Сервер шлёт SOK и MSG в одном
   блоке; `request()` забирал блок и терял MSG — тест завис на 60s с EAGAIN. Исправлено на
   `send_only`, MSG доходит следующим `recv_block`.
3. **Опечатка в патче U-04:** в доверенном месте остался буквальный `q.snd_auth=***` —
   E0614 при сборке, исправлено на `= Some(raw)`.
4. **Патч U-10 не применился с первой попытки** (несовпадение по пробелам); helper добавился,
   а замена match-ветки — нет. Поймано сверкой `grep`, применено вторым проходом по точному тексту.
5. **Патч struct Engine дважды не находил якорь** (сдвиг строк после ранних патчей + дубль поля
   в ConnCtx). Исправлено уникальным якорем по док-комментарию.
6. **Тестовые артефакты:** не-ASCII в байтовом литерале, move из `new_spki`, сравнение
   зашифрованного тела MSG с plaintext — исправлены по ошибкам компиляции/рантайма.

Все 6 пунктов пойманы либо компилятором, либо регрессионным тестом до push — в main ушёл
только зелёный код.

## 3. Финальная верификация (фактический вывод, не заявление)

- `cargo test --locked`: **193 passed, 0 failed** (в т.ч. `audit3_u13`, `audit3_u18`, `audit3_u20`).
- `cargo clippy --locked --all-targets`: **0 warnings/errors**; сборки `default` и `ffi` чистые.
- `scripts/check_no_unwrap.sh`: **OK** (no unwrap/expect в src/).
- `scripts/check-tree-hygiene.sh`: **OK**.
- Push: `eeb4aae` local == `eeb4aae` on `origin/main`.

## 4. Что осталось открытым (честно, не закрыто кодом)

- ~~**U-14**~~ **ЗАКРЫТО** (`e79c2ff`): FFI-операции переведены на take-out/reinsert
  (`with_agent`) — глобальный mutex не держится во время сетевых операций.
- ~~**Per-IP лимит**~~ **ЗАКРЫТ** (`e79c2ff`): `MAX_CONNS_PER_IP = 64` + счётчик per-IP в accept loop.
- ~~**TTL/GC**~~ **ЗАКРЫТ** (`e79c2ff`): `ServerState::gc()` — очереди 30d / xftp 7d,
  живые подписчики не жнутся; sweep каждые 30s в watcher; при load все записи штампуются now.
- **P0-7:** channel binding сейчас через TLS exporter, а не raw Finished verify_data
  (нужен openssl-sys TlsBackend) — задокументировано в коде.
- **`simplexmq/` — pełny 14M clone, не pinned submodule** (решение владельца).
- ~~**Fuzz-харнес**~~ **расширен** (`e79c2ff`, `tests/audit3_u25.rs::fuzz_parsers_never_panic`):
  8 парсеров (parse_command/parse_broker/decode_ratchet_msg/parse_snapshot/agent_envelope/
  AgentLink/parse_ntf_batch/handle_rfwd), мутационный фаззинг с catch_unwind — паник нет.
  **CI fuzz job и interop-CI против официального smp-server в Docker** остались нев добавлены
  (нужна сеть в CI).
- **U-25/U-26** — ADR-решения владельца (X3DH/X448 dual-mode, agent-mode CLI), не код.
- Косметика: комментарий в `scripts/ffi_smoke.sh:47` упоминает `$HOME/build`.
- README/SECURITY: числа тестов/версии не генерируются из CI.

## 5. Рекомендация

Sprint A (блокеры релиза) закрыт полностью и протестирован. Sprint B закрыт, кроме пунктов
раздела 4. Для публичного релиза рекомендую закрыть per-IP cap, TTL/GC и U-14 перед
release-gate; остальное — в roadmap.


## Continuation round 2026-11-26 (post-compaction)

- **SX448 parity increment (ADR D1(a) follow-up)**: `DhAlg::{X25519,X448}` + `DhKey`/`DhPub` in pqdr ratchet; header SPKI parses as X25519 or X448; cross-alg rejected; low-order X448 rejected via contributory check (U-07); AEAD-style `ad` binds header into message key with `PQDR_VERSION_AD` on the wire; snapshot format v2 (version byte, back-compat with legacy). Tests `audit3_sx448` (7 tests incl. negotiation) green. Self-found bug during the round: v2 snapshot initially omitted `dh_s.public` — caught by `pqdr_snapshot_restore_continues_chain`, fixed.
- **SMP version negotiation (plan item 15)**: `transport::negotiate_version(server_min, server_max, client_min, client_max) = min(client_max, server_max)` on overlap, `None` fail-closed otherwise; stored as `Client::negotiated_version` / `AsyncSmpClient::negotiated_version` from the server hello.
- **Live interop executed locally (D5 verification, not just CI plan)**: `scripts/live_interop.sh` against public relays — SMP v17..v23 OK, XFTP v4 transport PONG OK (full file cycle incl. 1MiB chunked verified in prior round), NTF v3 PING->PONG OK, all CA-pinned; proxy probe correctly refused server-side (`CMD SYNTAX`). Result recorded here; CI job remains (b) until Docker runners.
- State: 209/0 tests (ffi 210/0), clippy 0 warnings (lib+targets+ffi), gates `check_no_unwrap`/`check-tree-hygiene` OK, MSRV 1.87 CI job passing.
