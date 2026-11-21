# simplex-rs — План эволюции до 100% (v1.0)

> **Для Hermes:** реализовывать этот план тасками через `subagent-driven-development`
> (свежий субагент на таск + ревью соответствия спеке, затем ревью качества кода).
> Для каждой волны — коммит после каждого таска.

**Цель:** довести `smp-rs` с ~81% до 100% готовности к релизу: все 23 компонента аудита
(`docs/RELEASE-READINESS.md`, ревизия 9) доведены до 100%, все гейты v1.0 закрыты, публикация
на crates.io выполнена и проверена.

**Архитектура:** план не меняет архитектуру — он закрывает разрывы, найденные аудитом, и
приводит публичную поверхность в соответствие с заявленными целями (`README.md`,
`docs/ROADMAP.md`, `docs/ПОСЛАНИЕ-КОДЕРУ-2026-11-18.md`). Работа разбита на 7 волн по
зависимостям; критический путь — **W1 → W2 → W4 → W6 → W7**.

**Стек:** Rust 1.87 (MSRV), rustls 0.23, tokio 1, ed25519-dalek 2, x25519-dalek 2,
sntrup761 0.4, uniffi (новый), cargo-audit / cargo-deny.

---

## Цели, зафиксированные в репозитории (источник требований)

| # | Цель | Источник | Компонент | Текущий % |
|---|---|---|---|---:|
| G1 | Подписанные NTF-команды `TNEW`/`SNEW` (Ed25519-авторизация) | `README.md:64`, ROADMAP #2 | `ntf` | 60% |
| G2 | Onion routing поверх SMP proxy — **stated platform goal** | ROADMAP #4, `ПОСЛАНИЕ` #1 | `onion` | 80% |
| G3 | Async-движок с auto-reconnect | ROADMAP #5, `ПОСЛАНИЕ` #5 | `async_client`, `reconnect` | 70%, 75% |
| G4 | sessionId ↔ TLS 1.3 Finished (реальный verify_data) | ROADMAP #1, `ПОСЛАНИЕ` #2 | `transport` | 90% |
| G5 | Чистка `unwrap`/`expect` в `src/` (цель: 0 вне тестов) | `ПОСЛАНИЕ` #4 | весь `src/` | 2 остались |
| G6 | PQDR: key rotation ✅, reorder window ✅, SUPERCOP KAT ⬜ | `ПОСЛАНИЕ` #6 | `pq`, `pqdr` | 90% (остался KAT) |
| G7 | Внешний аудит (3 зоны) | ROADMAP #6, `ПОСЛАНИЕ` #7 | проект | 0% |
| G8 | Публикация v0.99.1 на crates.io + GitHub release | `README.md:49` | Packaging | 88% |
| G9 | CI: ассерт, что дефолтная сборка не линкует probe-бины | `ПОСЛАНИЕ` (рекомендации) | CI | — |
| G10 | FFI-фасад, пригодный для Android/Paranoid | `src/ffi.rs:2` | `ffi` | 55% |
| G11 | Live NTF/XFTP против публичных релеев | ROADMAP #2 | `ntf`, `xftp` | частично |
| G12 | Актуальная документация (1 источник правды) | N-15 | Docs | 75% |

**Определение 100%:** каждая строка таблицы §1b аудита = 100%, все гейты §5 закрыты,
`cargo publish` выполнен и `cargo info smp-rs` показывает v0.99.1.

---

## Карта зависимостей

```
W0 (база) ──► W1 (мёртвый код) ──► W2 (NTF) ──┐
                 │                              ├──► W4 (async/reconnect) ──► W5 (ffi) ──► W6 (интеграция) ──► W7 (релиз)
                 └──► W3 (onion/proxy/transport) ─┘         │
                                                          └──► W7
```

**Критический путь:** W0 → W1 → W2 → W4 → W5 → W6 → W7.
**Параллельно:** W3 (независим от NTF), W4-G6 (PQDR — независим).

---

## W0 — База: устранить ложные утверждения (блокер всего)

> Аудит выявил, что `README.md` и `docs/ROADMAP.md` **завышают** готовность: README:21 обещает
> «авто-reconnect с backoff, async-движок», а аудит показал, что оба модуля мёртвые. Любая
> реализация, построенная на этой лжи, будет строить не туда.

### Task 0.1: Привести README в соответствие с кодом

**Files:** Modify `README.md:21`, `README.md:35`, `README.md:44`

**Step 1:** Заменить строку 21:

```markdown
| Клиент | `src/client.rs`, `src/async_client.rs`, `src/reconnect.rs` | handshake, запрос/ответ по блокам, авто-reconnect с backoff, async-движок |
```

на:

```markdown
| Клиент | `src/client.rs` | handshake, запрос/ответ по блокам |
| Async / reconnect | `src/async_client.rs`, `src/reconnect.rs` | ⚠️ **не подключены** — API существует, но не вызывается ниоткуда; см. `docs/RELEASE-READINESS.md` §1b |
```

**Step 2:** Строку 35 (`Тесты обязаны запускаться с --test-threads=1`) заменить на:

```markdown
Тесты можно запускать параллельно: гонка с process-global `SMP_STORE_KEY` устранена
(явные `store::save_with_key` / `load_with_key`). Остаточная мутация env — в
`tests/proxy.rs`, `tests/onion.rs`, `tests/strict_e2e.rs`; она изолируется в W1-Task 1.4.
```

**Step 3:** Строку 44 (onion в таблице live-интеропа) — она вводит в заблуждение, поскольку
тест локальный, а не против публичной инфраструктуры. Перенести в отдельную строку с пометкой
«локальный 2-hop, не live».

**Step 4:** `grep -n "авто-reconnect\|async-движок" README.md` → ожидается только строка с пометкой
«не подключены».

**Step 5:** Commit:
```bash
git add README.md && git commit -m "docs(readme): stop claiming reconnect/async are wired — they are dead code"
```

### Task 0.2: Обновить ROADMAP под факты

**Files:** Modify `docs/ROADMAP.md`

Переписать секцию «Next (backlog, by value)» на актуальный бэклог из этого плана
(со ссылкой на `docs/plans/2026-11-21_v1-evolution-plan.md`), добавить в «Done»:
`cargo audit` 0 уязвимостей; явные ключи store; ревизия 8 аудита.

**Проверка:** `docs/ROADMAP.md` не содержит утверждений, contradicted аудитом.

**Step 5:** Commit `git add docs/ROADMAP.md && git commit -m "docs(roadmap): sync backlog with audit rev8 findings"`.

---

## W1 — Мёртвый код и честность API (разблокирует W4)

### Task 1.1: Решить судьбу `async_client` — удалить или переделать

**Objective:** `AsyncSmpClient` (58 LOC) оборачивает **синхронный** клиент в `spawn_blocking`.
Это не async-реализация, а оффлоуд в поток, и она никем не используется.

**Files:**
- Delete: `src/async_client.rs` (если выбран вариант A)
- Modify: `src/lib.rs` (убрать `pub mod async_client;`)

**Вариант A (рекомендуется): удалить.** Причина: настоящий async требует async-транспорт
(transport.rs написан на blocking rustls), а это переписывание `transport.rs` целиком —
выходит за рамки «довести до 100%» и ломает проверенный live-протокол. Мёртвый модуль в
публичном API — обещание, которое крейт не держит.

**Step 1:** Написать тест, фиксирующий решение (падает до правки):
```rust
// tests/public_api.rs
#[test]
fn public_api_has_no_dead_modules() {
    // ReconnectingClient и AsyncSmpClient не должны быть в публичном API,
    // пока не имеют вызывающего кода.
    let src = std::fs::read_to_string("src/lib.rs").unwrap();
    assert!(!src.contains("pub mod async_client"), "async_client is dead code — remove or wire it");
}
```
**Step 2:** `cargo test --offline --test public_api` → ожидается FAIL.
**Step 3:** удалить `src/async_client.rs` и строку `pub mod async_client;` из `src/lib.rs`.
**Step 4:** `cargo test --offline --test public_api` → PASS; `cargo test --offline` → 90 passed.
**Step 5:** `cargo clippy --offline --all-targets -- -D warnings` → 0.
**Step 6:** Commit `git rm src/async_client.rs && git commit -m "refactor: remove dead async_client module"`.

> Если владелец предпочитает сохранить API — перейти к W4-Task 4.1 (переписать на async-транспорт)
> и **не** выполнять Task 1.1.

### Task 1.2: Подключить `reconnect` к реальному пути

**Objective:** `ReconnectingClient` (165 LOC) — рабочая реализация с backoff и strict-mode
re-enable, но без единого вызывающего. Подключить к `agent.rs`, где живёт долгоживущая сессия.

**Files:**
- Modify: `src/agent.rs` — найти место, где `Client` используется для long-lived операций
- Test: `tests/reconnect_e2e.rs` (новый)

**Step 1:** Написать падающий тест:

```rust
// tests/reconnect_e2e.rs
use smp_rs::reconnect::ReconnectingClient;

#[test]
fn reconnecting_client_recovers_after_server_restart() {
    // Поднять engine, убить его, поднять новый на том же адресе,
    // и убедиться, что клиент переподключился и доставил сообщение.
    let (addr, ...) = spawn_engine(engine);
    // Endpoint { addr, host, key_hash, tls, with_sni } — см. src/reconnect.rs:18
    let ep = Endpoint { addr, host: "127.0.0.1".into(), key_hash: [0u8; 32], tls: false, with_sni: true };
    let mut rc = ReconnectingClient::new(ep);
    rc.connect().expect("first connect");   // -> ClResult<()> = Result<(), String>
    // ... kill engine, spawn new one on same addr ...
    // клиент должен переподключиться сам, без ручного reconnect()
    let ok = rc.send_and_wait(...).expect("reconnect recovered");
    assert!(ok);
}
```

**Step 2:** Запустить → FAIL (тест-функция `Agent` не использует `ReconnectingClient`).
**Step 3:** В `src/agent.rs` заменить прямое владение `Client` на `ReconnectingClient` там,
где сессия долгоживущая; агент при этом переподключается при обрыве.
**Step 4:** Тест → PASS.
**Step 5:** Commit `git add src/agent.rs tests/reconnect_e2e.rs && git commit -m "feat(agent): use ReconnectingClient for long-lived sessions"`.

### Task 1.3: Изолировать process-global env в тестах

**Objective:** `SMP_STRICT` читается в `src/server.rs:667` и `src/client.rs:98`, а мутируется
глобально в `tests/proxy.rs`, `tests/onion.rs`, `tests/strict_e2e.rs`. Это лотерея: 15 прогонов
прошли, но тесты в одном процессе влияют друг на друга.

**Files:**
- Modify: `src/server.rs:667` — добавить `Engine::bind_plain_with_strict(addr, strict: bool)`
- Modify: `src/client.rs:96` — добавить `Client::connect_plain_with_strict(addr, kh, strict)`
- Modify: `tests/proxy.rs`, `tests/onion.rs`, `tests/strict_e2e.rs` — убрать `set_var`/`remove_var`
- Test: `tests/env_isolation.rs` (новый)

**Step 1:** Падающий тест:
```rust
// tests/env_isolation.rs
#[test]
fn strict_mode_is_per_connection_not_process_global() {
    // Два соединения в одном процессе: одно strict, одно нет.
    // До правки — второе унаследует SMP_STRICT и падает/не падает неверно.
}
```
**Step 2:** → FAIL.
**Step 3:** Ввести per-connection флаг; читать `SMP_STRICT` только как **значение по умолчанию**
в точке входа (bin), а не внутри `server.rs`/`client.rs`.
**Step 4:** Тест → PASS; `cargo test --offline` → 90 passed.
**Step 5:** `grep -rn 'env::set_var' tests/` → пусто.
**Step 6:** Commit `git commit -m "test: make strict mode per-connection, remove process-global env mutation"`.

### Task 1.4: Чистка `unwrap`/`expect` в библиотеке (цель G5)

**Objective:** 0 `unwrap`/`expect` в `src/` вне `#[cfg(test)]`.

**Files:**
- Modify: `src/ntf.rs:67` — `.expect("fixed-size")` → возвращать `Result`
- Modify: `src/server.rs` — `.expect("local addr")` → `Result`
- Modify: `src/ffi.rs:15,33` — `unwrap_or_else(|e| e.into_inner())` → без unwrap
- Modify: `src/sb_chain.rs`, `src/pqdr.rs`, `src/transport.rs`, `src/client.rs`, `src/store.rs`
  — по `grep -n 'unwrap()\|expect(' src/*.rs`, вне тест-модулей

**Step 1:** Написать CI-ассерт (не тест, а проверка в скрипте):
```bash
# scripts/check_no_unwrap.sh
for f in src/*.rs; do
  ct=$(grep -n '#\[cfg(test)\]' "$f" | head -1 | cut -d: -f1)
  [ -z "$ct" ] && ct=$(wc -l < "$f")
  n=$(sed -n "1,${ct}p" "$f" | grep -cE '\.unwrap\(\)|\.expect\(')
  [ "$n" != "0" ] && echo "$f: $n unwrap/expect in library code" && exit 1
done
```
**Step 2:** Запустить → FAIL (2+ вхождения).
**Step 3:** Заменить на `?` с осмысленными ошибками; для FFI — на `unwrap_or_else` без unwrap
(использовать `match`/`if let`).
**Step 4:** Запустить → PASS; `cargo test --offline` → 90 passed.
**Step 5:** Добавить вызов скрипта в `.github/workflows/ci.yml` как отдельный job `no-unwrap`.
**Step 6:** Commit `git commit -m "refactor: remove all unwrap/expect from library code paths"`.

---

## W2 — NTF: подписанные команды (G1) — главный функциональный гейт

> Спека извлечена из Haskell-эталона `simplexmq/src/Simplex/Messaging/Notifications/Protocol.hs`.
> Проверено: `TNEW`/`SNEW` требуют подписи, но **не** entity ID; остальные команды — и то и другое.

### Task 2.1: Типы NTF-авторизации и ключей

**Objective:** Ввести `NtfPublicAuthKey` / `NtfPrivateAuthKey` и кодирование подписи.

**Files:**
- Modify: `src/ntf.rs`
- Test: `tests/ntf_wire.rs` (дополнить)

**Step 1:** Падающий тест с golden-вектором из Haskell:
```rust
// tests/ntf_wire.rs
#[test]
fn ntf_new_token_encodes_with_signature_and_no_entity_id() {
    // Haskell: TNEW {} -> sigNoEntity; authorized = smpEncode sessionId <> corrId <> entityId <> command
    let tkn = NewNtfEntity { token: ..., auth_key: spki_ed25519(&pk) };
    let enc = encode_ntf_new_token(&tkn, &session_id, &corr_id);
    assert_eq!(hex(&enc), "<golden hex from Haskell>");
}
```
**Step 2:** → FAIL (функции нет).
**Step 3:** Реализовать:
```rust
/// Подпись NTF-команды: Ed25519 над `smpEncode sessionId <> corrId <> entityId <> command`.
/// entityId для TNEW/SNEW — пустой (sigNoEntity).
pub fn sign_ntf_command(
    session_id: &[u8; 32],
    corr_id: &[u8; 16],
    entity_id: &[u8],
    command: &[u8],
    sk: &ed25519_dalek::SigningKey,
) -> [u8; 64] {
    let mut msg = Vec::new();
    msg.extend_from_slice(session_id);
    msg.extend_from_slice(corr_id);
    msg.extend_from_slice(entity_id);
    msg.extend_from_slice(command);
    sk.sign(&msg).to_bytes()
}
```
**Step 4:** → PASS.
**Step 5:** Commit `git commit -m "feat(ntf): add NTF command signing (sessionId||corrId||entityId||command)"`.

### Task 2.2: Кодирование `NewNtfEntity` / `NewNtfSub` по wire-спецификации

**Files:** Modify `src/ntf.rs`; Test: `tests/ntf_wire.rs`

Haskell (`Notifications/Protocol.hs:198-233`):
- `TNEW newTkn` → `e (TNEW_, ' ', newTkn)`
- `SNEW newSub` → `e (SNEW_, ' ', newSub)`
- `NewNtfEntity` = `authKey (SPKI) + tokenId/subId + nonce` — уточнить точный порядок полей в Haskell
  перед реализацией и зафиксировать golden-вектор.

**Step 1:** Падающий golden-тест. **Step 2:** FAIL. **Step 3:** Реализация. **Step 4:** PASS.
**Step 5:** Commit.

### Task 2.3: Реализация команд `TNEW`/`SNEW` в `NtfClient`

**Objective:** Теги команд **уже есть** (`NtfCommandTag::{Tnew, Snew, ...}` в `src/ntf.rs`) —
не хватает полезной нагрузки и высокоуровневых методов. `NtfClient` сейчас умеет только
`ping()` и `request()`; нет методов `new_token` / `new_subscription`.

**Files:** Modify `src/ntf.rs` (методы `new_token`, `new_subscription`); Test: `tests/ntf_client_e2e.rs`

**Step 1:** Тест с живым сервером (опционально, `#[ignore]` без сети):
```rust
#[test]
#[ignore = "requires a public NTF server"]
fn live_ntf_new_token() {
    // NtfClient::connect(stream, ca_der, expected_key_hash) — пин сверяется ДО любого I/O.
    let mut c = NtfClient::connect(tls_stream, &ca_der, expected_fp).expect("connect");
    let tkn = c.new_token(&priv_key).expect("TNEW");
    assert!(!tkn.token_id.is_empty());
}
```
**Step 2:** → FAIL (метода `new_token` нет). **Step 3:** Реализовать поверх существующего
`request_with_corr` — он уже принимает `entity_id` и `authenticator` (подпись), то есть
транспортная часть готова.
**Step 4:** Локальные тесты → PASS; live — за отдельный прогон (W6).
**Step 5:** Commit `git commit -m "feat(ntf): implement TNEW/SNEW signed commands in NtfClient"`.

### Task 2.4: Локальный NTF-сервер для e2e (без сети)

**Objective:** Сейчас NTF покрыт только `PING→PONG`. Нужен локальный NTF-сервер, чтобы
тестировать полный цикл `TNEW→IDTKN` / `SNEW→IDSUB` детерминированно в CI.

**Files:** Create `src/ntf_server.rs` (engine, аналог `src/server.rs`); Create `tests/ntf_server_e2e.rs`

**Step 1:** Падающий тест полного цикла. **Step 2:** FAIL. **Step 3:** Реализовать сервер,
принимающий `TNEW`/`SNEW`, проверяющий подпись и возвращающий `IDTKN`/`IDSUB`.
**Step 4:** → PASS. **Step 5:** Commit.

**Гейт W2:** `ntf` = 100%. Критерий: полный цикл подписанных команд доказан локально
(детерминированно) **и** против публичного релея (W6, опционально — публичный NTF-сервер
не выдаёт токены сторонним клиентам; если это так, критерий — локальный e2e + golden-векторы
против Haskell).

---

## W3 — Протокол и безопасность (G2, G4, G11)

### Task 3.1: `Client::onion_send` — эргономика onion (G2)

**Objective:** `onion_request` работает, но вызывающий обязан сам собрать цепочку хопов.
Добавить метод на `Client`.

**Files:** Modify `src/client.rs`; Test: `tests/onion.rs` (дополнить)

**Step 1:** Падающий тест: `client.onion_send(&hops, dest, cmd, entity, auth)`.
**Step 2:** FAIL. **Step 3:** Реализация (делегация в `onion::onion_request`).
**Step 4:** PASS. **Step 5:** Commit `git commit -m "feat(client): add Client::onion_send convenience"`.

### Task 3.2: Multi-hop > 2 и forward-ограничения (G2)

**Objective:** Заявленная цель — «цепочки через несколько релеев». Тест покрывает 2 хопа;
нужен 3+ и проверка лимитов.

**Files:** Modify `tests/onion.rs`; Modify `src/onion.rs` при необходимости

**Step 1:** Падающий тест на 3 хопа + тест, что сервер отклоняет >1 форвард в одной трансмиссии
(Haskell `Server.hs:2134`: "only allowing single forwarded transactions").
**Step 2:** FAIL. **Step 3:** Реализация/починка. **Step 4:** PASS.
**Step 5:** Commit `git commit -m "feat(onion): support 3+ hop chains, enforce single-forward limit"`.

### Task 3.3: sessionId ↔ TLS 1.3 Finished (G4)

**Objective:** Сейчас sessionId берётся из rustls exporter. Сверить с реальным `verify_data`
TLS 1.3 — иначе channel binding слабее, чем в спеке.

**Files:** Modify `src/transport.rs`; Test: `tests/interop.rs`

**Step 1:** Исследование: проверить, доступен ли exporter rustls 0.23 для получения
finished-ключей; если нет — реализовать через `rustls::Connection::export_keying_material`
с корректным label, совпадающим с Haskell.
**Step 2:** Падающий тест: подпись с `sessionId` из Finished должна совпасть с эталонной.
**Step 3:** FAIL или подтверждение (если exporter уже даёт Finished — зафиксировать тестом).
**Step 4:** PASS.
**Step 5:** Commit `git commit -m "feat(transport): bind sessionId to TLS 1.3 finished keys"`.

> **Ruling (Task 3.3, реализовано 2026-11-21).** Premise of the step was wrong for rustls:
> the RFC 8446 exporter has **no** label that reproduces the TLS 1.3 Finished verify_data, and
> rustls 0.23 does not expose the Finished at all (it exists only inside the handshake state
> machine — verified in the vendored `rustls-0.23` source). Upstream's `tlsUnique` is the **raw**
> Finished bytes, not an exporter output. So:
> * `SessionIdBinding` makes the choice explicit: `Exporter` (rustls, 32 B, symmetric,
>   transcript-bound, but NOT byte-equal to upstream) or `Finished` (raw verify_data, upstream
>   byte-compatible — reachable only on stacks that expose it, i.e. openssl);
> * `derive_session_id` never falls back silently: a missing/malformed Finished is an error;
> * the Finished length is the negotiated suite's hash length — **32 B (SHA-256) or 48 B
>   (SHA-384)** — and upstream carries it verbatim, so the length is not normalised.
>   The live public relay confirmed this: `xftp1.simplex.im` presents a **48-byte** sessionId.
>   `check_session_binding` therefore accepts 32 and 48 bytes (empty = plain TCP).
> * Evidence: `tests/tls_finished_binding.rs` (feature `v71-probes`) proves with openssl on both
>   ends that the client's own Finished == the server's `peer_finished` (the upstream property),
>   and that the rustls server's session id != the TLS Finished (the deviation, pinned).

### Task 3.4: Live XFTP chunked >64KB (G11)

**Objective:** `ПОСЛАНИЕ` просит добавить chunked >64KB round-trip в live-набор; сейчас 64KB.

**Files:** Modify `scripts/live_interop.sh`

**Step 1:** Добавить в скрипт передачу 1 MiB с проверкой sha256.
**Step 2:** Запустить против `xftp1.simplex.im` → ожидается byte-exact.
**Step 3:** Commit `git commit -m "test(live): add chunked 1MiB XFTP round-trip"`.

### Task 3.5: XFTP `upload_file_stream` — интеграционный тест (xftp 85→100%)

**Files:** Create `tests/xftp_stream.rs`

**Step 1:** Падающий тест. **Step 2:** FAIL. **Step 3:** Реализация/починка.
**Step 4:** PASS. **Step 5:** Commit.

---

## W4 — Async + reconnect (G3) — после W1

### Task 4.1: Реальный async-клиент

**Objective:** Либо переделать `async_client` на async-транспорт, либо оставить удалённым (Task 1.1).
**Решение принимается в Task 1.1.** Если выбран вариант «оставить»:

**Files:** Modify `src/transport.rs` (async-вариант на `tokio-rustls`), `src/async_client.rs`

**Step 1:** Падающий тест с `#[tokio::test]`. **Step 2:** FAIL. **Step 3:** Реализация.
**Step 4:** PASS. **Step 5:** Commit.

### Task 4.2: Backoff-цикл для мобильного клиента

**Objective:** `ПОСЛАНИЕ` #5: «для мобильного клиента нужен backoff-цикл как в NeXX chat_worker».

**Files:** Modify `src/reconnect.rs`; Test: `tests/reconnect_e2e.rs`

**Step 1:** Падающий тест: сервер падает 3 раза подряд → клиент поднимается после экспоненциального
backoff, без превышения max_backoff.
**Step 2:** FAIL. **Step 3:** Реализация. **Step 4:** PASS. **Step 5:** Commit.

---

## W5 — FFI-фасад (G10) — 55% → 100%

### Task 5.1: `crate-type = ["cdylib", "rlib"]`

**Objective:** Сейчас `crate-type` не объявлен — `.so` для Android собрать нечем.

**Files:** Modify `Cargo.toml`

**Step 1:**
```toml
[lib]
name = "smp_rs"
path = "src/lib.rs"
crate-type = ["cdylib", "rlib"]
```
**Step 2:** `cargo build --offline --features ffi --release` → ожидается `libsmp_rs.so`.
**Step 3:** Commit.

### Task 5.2: uniffi-обвязка

**Files:** Modify `Cargo.toml` (зависимость `uniffi`), Create `src/ffi/uniffi.rs` или `uniffi.toml`

**Step 1:** Добавить `uniffi = { version = "0.28", features = ["build"], optional = true }`,
в feature `ffi` — `"dep:uniffi"`.
**Step 2:** Обернуть 7 функций `src/ffi.rs` в `#[uniffi::export]`.
**Step 3:** `cargo build --offline --features ffi` → PASS; сгенерировать биндинги:
```bash
cargo run --bin uniffi-bindgen generate --library target/debug/libsmp_rs.so --language kotlin --out-dir kotlin/
```
**Step 4:** Commit.

### Task 5.3: Kotlin smoke-test

**Objective:** Доказать, что фасад реально вызывается из Kotlin — единственный способ снять
«нет потребителя».

**Files:** Create `ffi-smoke/` (отдельный gradle-проект), CI job

**Step 1:** Минимальный Kotlin-тест: вызвать `create_contact` с неверным keyHash → ожидается
`Err("keyhash must be 32 bytes")` (не падение).
**Step 2:** Запустить → FAIL (нет биндингов/проекта).
**Step 3:** Собрать проект, сгенерировать биндинги, добиться PASS.
**Step 4:** Добавить job в `.github/workflows/ci.yml` (matrix-опционально: `continue-on-error`
для PR без Android SDK, **обязательный** на main).
**Step 5:** Commit `git commit -m "feat(ffi): uniffi bindings + Kotlin smoke test"`.

---

## W6 — PQDR, интеграция и живые проверки (G6, G11)

### Task 6.1: SUPERCOP KAT для sntrup761 (G6)

**Objective:** `docs/AUDITOR-LETTER.md:34` — «рекомендуется прогнать KAT против официальных
SUPERCOP-векторов».

**Files:** Create `tests/pqdr_supercop.rs`; добавить векторы в `tests/fixtures/`

**Step 1:** Скачать векторы SUPERCOP sntrup761 (зафиксировать источник и хеш файла в комментарии).
**Step 2:** Падающий тест, сверяющий `kem_encaps`/`kem_decaps` с вектором.
**Step 3:** FAIL (если расхождение) → PASS (если совпало; расхождение = реальный дефект KEM).
**Step 4:** Commit.

### Task 6.2: Key rotation + reorder window (G6)

**Objective:** `ПОСЛАНИЕ` #6: key rotation расписание и skipped-message limits.

**Files:** Modify `src/pqdr.rs`; Test: `tests/pqdr_ratchet.rs`

**Step 1:** Падающие тесты: ротация по расписанию; превышение reorder window → ошибка.
**Step 2:** FAIL. **Step 3:** Реализация. **Step 4:** PASS. **Step 5:** Commit.

### Task 6.3: Live NTF/PROXY — документированный результат

**Objective:** Публичные релеи отключили proxy на серверной стороне, поэтому live-проверка
proxy невозможна. Зафиксировать это как проверенный факт, а не как «не сделано».

**Files:** Modify `scripts/live_interop.sh` (попытка + понятный вывод); Modify `docs/SECURITY.md`

**Step 1:** Добавить в live-скрипт попытку proxy-цепочки с таймаутом 10с и выводом
«public relay disables proxy server-side — expected».
**Step 2:** Запустить → зафиксировать фактический вывод.
**Step 3:** Обновить `docs/SECURITY.md` — снять «не проверено» со строки proxy.
**Step 4:** Commit.

### Task 6.4: Гонка store → multi-process locking

**Files:** Modify `src/store.rs`; Test: `tests/persist.rs`

**Step 1:** Падающий тест: два процесса пишут в один файл → без блокировки теряется запись.
**Step 2:** FAIL. **Step 3:** Ввести advisory lock (flock на Unix) + атомарный rename.
**Step 4:** PASS. **Step 5:** Commit.

### Task 6.5: Миграции версий store с rollback (рекомендация `ПОСЛАНИЕ`)

**Files:** Modify `src/store.rs`; Create `tests/store_migration.rs`

**Step 1:** Падающий тест: store v1 → v2 миграция, откат при ошибке.
**Step 2:** FAIL. **Step 3:** Реализация. **Step 4:** PASS. **Step 5:** Commit.

---

## W7 — Релиз и документация (G7, G8, G9, G12) — 100%

### Task 7.1: CI-ассерт: probe-бины не линкуются в дефолтной сборке (G9)

**Files:** Modify `.github/workflows/ci.yml`

**Step 1:** Job `probe-isolation`:
```yaml
  probe-isolation:
    name: default build excludes probe binaries
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --offline
      - name: assert no probe binaries in default build
        run: |
          for b in smp-v71 xftp-h2-v71 ntf-probe; do
            if [ -f "target/debug/$b" ]; then echo "probe binary $b leaked into default build"; exit 1; fi
          done
          echo "OK: no probe binaries in default build"
```
**Step 2:** Запустить локально → PASS (уже так).
**Step 3:** Commit.

### Task 7.2: Регенерировать `docs/AUDIT-REPORT.md` (G12)

**Objective:** 45 KB от 2026-11-20, ревизии 1–3 — противоречит дереву.

**Files:** Rewrite `docs/AUDIT-REPORT.md`

**Step 1:** Переписать на основе `docs/RELEASE-READINESS.md` ревизии 9, сохранив формат
«модуль → Haskell-источник → что проверять» (таблицу из `docs/AUDIT.md`).
**Step 2:** Добавить в начало указание: «канонический источник правды — `docs/RELEASE-READINESS.md`».
**Step 3:** Commit.

### Task 7.3: Обновить `docs/AUDIT.md` (устаревшие числа)

**Files:** Modify `docs/AUDIT.md:8` («33 теста» → 90), `:9` (clippy не fatal → fatal),
`:27` (`tests/pqdr.rs` → `tests/pqdr_ratchet.rs`), `:45-50` (устаревшие заметки)

**Step 1:** Правка. **Step 2:** `grep -n "33 теста" docs/AUDIT.md` → пусто.
**Step 3:** Commit.

### Task 7.4: Внешний аудит (G7)

**Objective:** ROADMAP #6 — «External audit (Hydrogen / Grok / Sonnet) over docs/AUDIT-REPORT.md
+ multi-zone-security-audit skill».

**Files:** Modify `docs/AUDIT-PROMPT.md`; Create `docs/EXTERNAL-AUDIT-<date>.md`

**Step 1:** Обновить `docs/AUDIT-PROMPT.md` под ревизию 9: актуальные модули, реальные числа
тестов, актуальные известные ограничения (NTF подписанные команды — реализованы после W2).
**Step 2:** Отправить на внешний аудит (3 зоны: крипто, wire-форматы, PQDR — по
`docs/AUDITOR-LETTER.md`).
**Step 3:** Получить отчёт → `docs/EXTERNAL-AUDIT-<date>.md`.
**Step 4:** Закрыть найденные дефекты (каждый — отдельный таск).
**Step 5:** Commit.

### Task 7.5: `cargo publish` — первая публикация (G8)

**Objective:** Publish path не выполнялся ни разу — это дефект процесса, а не кода.

**Files:** Modify `docs/RELEASE-READINESS.md` (зафиксировать результат)

**Step 1:** Проверить, что имя `smp-rs` свободно:
```bash
curl -s -o /dev/null -w "%{http_code}" https://crates.io/api/v1/crates/smp-rs   # ожидается 404
```
**Step 2:** Попросить владельца выставить секрет `CARGO_REGISTRY_TOKEN`
( crates.io → Account → API Tokens → publish token для крейта `smp-rs`).
**Step 3:** Прогнать pipeline локально в dry-run:
```bash
cargo package --offline --allow-dirty   # verify build
```
**Step 4:** Тег и пуш:
```bash
git tag v0.99.1 && git push origin v0.99.1
```
**Step 5:** Дождаться завершения job в GitHub Actions. **Ожидается:** publish job → success.
**Step 6:** Проверка публикации:
```bash
cargo info smp-rs                  # version: 0.99.1
cargo add smp-rs@0.99.1            # в scratch-проекте
```
**Step 7:** Зафиксировать в `docs/RELEASE-READINESS.md` §2 и в `docs/CHANGELOG.md`.
**Step 8:** Commit.

### Task 7.6: SBOM + provenance (гейт v1.0)

**Files:** Modify `.github/workflows/release.yml`

**Step 1:** Добавить генерацию SBOM:
```yaml
      - name: Generate SBOM
        run: |
          cargo install cargo-cyclonedx
          cargo cyclonedx --output-format json --output sbom.json
```
и публикацию SBOM как artifact релиза.
**Step 2:** Добавить `cargo publish --dry-run` перед настоящей публикацией.
**Step 3:** Commit.

### Task 7.7: Финальный аудит-проход

**Objective:** Подтвердить, что каждая строка §1b = 100%.

**Step 1:** Перезапустить всё:
```bash
cargo test --offline                                  # 90+ passed
cargo clippy --offline --all-targets -- -D warnings   # 0
cargo check --offline --no-default-features            # clean
cargo audit                                           # 0 vulnerabilities
cargo package --offline --allow-dirty                  # verify build
./scripts/live_interop.sh                             # SMP + XFTP + NTF live
bash scripts/check_no_unwrap.sh                       # 0 unwrap in library
```
**Step 2:** Пересчитать таблицу §1b — все строки 100% (или обоснованное исключение).
**Step 3:** Обновить `docs/RELEASE-READINESS.md` до ревизии 10 с итоговыми числами.
**Step 4:** Commit `git commit -m "docs(audit): rev10 — all components at 100%"`.

---

## Гейты завершения (Definition of Done)

| # | Гейт | Проверка |
|---|---|---|
| 1 | Все 23 компонента §1b = 100% | пересчёт таблицы |
| 2 | 0 `unwrap`/`expect` в `src/` вне тестов | `bash scripts/check_no_unwrap.sh` |
| 3 | 0 process-global env в тестах | `grep -rn 'env::set_var' tests/` → пусто |
| 4 | NTF подписанные команды работают | `tests/ntf_server_e2e.rs` + golden-векторы |
| 5 | Live-интероп зелёный | `./scripts/live_interop.sh` |
| 6 | CI зелёный на всех 4 feature-конфигах | Actions |
| 7 | `cargo audit` — 0 уязвимостей | локально + CI |
| 8 | `cargo publish` выполнен | `cargo info smp-rs` → 0.99.1 |
| 9 | Внешний аудит проведён, дефекты закрыты | `docs/EXTERNAL-AUDIT-*.md` |
| 10 | Документация — один источник правды | `docs/AUDIT-REPORT.md` перегенерирован |

## Риски и открытые вопросы

| Риск | Вероятность | Влияние | Митигация |
|---|---|---|---|
| Публичный NTF-сервер не выдаёт токены сторонним клиентам | высокая | не выполнить live-критерий G1 | критерий — локальный e2e + golden-векторы против Haskell; live — best effort |
| Публичные релеи отключили proxy | подтверждено | нет live-проверки proxy | зафиксировать как проверенный факт (Task 6.3) |
| Переписывание transport на async сломает живой протокол | средняя | откат живого SMP | вариант «удалить async_client» (Task 1.1) — безопасная альтернатива |
| `sntrup761` не совпадёт с SUPERCOP KAT | низкая | дефект KEM | стоп-фактор: остановить релиз, не публиковать непроверенный KEM |
| crates.io имя `smp-rs` занято | низкая | смена имени + правка метаданных | проверка в Task 7.5 Step 1 — до тега |
| `rustls` exporter не даёт Finished-ключи | средняя | G4 недостижим в текущем стеке | документировать ограничение, как уже сделано для ed448 |

## Открытые вопросы к владельцу

1. **`async_client`: удалить или переделать?** Рекомендация — удалить (Task 1.1), потому что
   настоящий async требует переписывания `transport.rs` и рискует живым SMP-протоколом.
2. **FFI-цель: uniffi или ручные JNI-биндинги?** uniffi проще и даёт Kotlin-обвязку из коробки.
3. **Публиковать v0.99.1 сейчас (до закрытия G1–G12) или после?** План рассчитан на
   «после»; если нужен ранний релиз — отдельный релизный трек с честным описанием ограничений.
