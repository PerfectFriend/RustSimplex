# Auditor brief — simplex-rs, внешний аудит #3 (три независимые модели)

**Аудируемая база:** ветка `main`, коммит `6cb00d4` (публичный репозиторий `PerfectFriend/RustSimplex`).
Коммиты поверх базы добавляют только этот пакет подготовки (гейт CI + доки) —
проверьте сами: `git diff --stat 6cb00d4..HEAD`.
**Дата:** 2026-11-23. **Версия crate:** 0.99.3 (crates.io).
**Форма раздачи:** публичный репозиторий на зафиксированном коммите + squash-tarball
(1 коммит, без истории), собираемый командой ниже; sha256 артефакта — в сообщении о вручении.

## 0. Как получить код

```bash
# вариант 1 — публичный репозиторий на зафиксированной базе
git clone https://github.com/PerfectFriend/RustSimplex.git && cd RustSimplex
git checkout 6cb00d4

# вариант 2 — squash-артефакт (1 коммит, без истории, без owner-only файлов)
mkdir squash && git archive 6cb00d4 | tar -x -C squash && cd squash
git init -q -b auditor-squash && git add -A
git -c user.name=auditor -c user.email=auditor@local commit -q -m "squash for external audit"
```

Свип секретов на момент вручения (вся история, все классы токенов по value-shape, плюс
magic-byte проверка key-value stores redb/sqlite/leveldb, плюс файлы >1 MiB):
**0 хитов / 0 store-файлов / 0 больших файлов**. Гейт, не дающий регрессии:
`scripts/check-tree-hygiene.sh` (запускается в CI job `tree-hygiene`, сканирует только
tracked-файлы). Owner-only материал (`docs/ПОСЛАНИЕ-КОДЕРУ*.md`, `docs/live/`) исключён из
артефакта через `.gitattributes export-ignore` и остаётся только в репозитории.

## 1. Состояние одной фразой

Rust-реализация стека SimpleX: SMP v17–v23 (клиент + relay-сервер), XFTP v4, NTF, SOCKS5-прокси,
PQDR/E2E ratchet поверх Curve448, FFI (uniffi) для мобильных клиентов. ~12,000 LOC в `src/`,
178 тестов зелёные, clippy 0, CI зелёный, live interop с публичными relay (SMP v17..v23, XFTP
PING/PONG) — см. `docs/live/live-interop-2026-11-22.log` и `scripts/live_interop.sh`.

## 2. Что изменилось с предыдущей аудируемой базы (v0.99.3)

```
287b62f fix(audit): P0-1/P0-2/P0-6 + fail-closed crypto, with regression tests
b2c7a31 style: silence the clippy lints introduced by the audit fixes
850197a feat(store): persistent router identity (P0-4) + encrypted-by-default store (P1-5)
6cb00d4 docs(audit): mark P0-4 done, P1-5 partial, P0-3 in progress
```
Ядро протокола не тронуто; изменения — в ratchet decrypt (staged commit после AEAD), стор сервера
(fail-closed + персистентная идентичность + шифрование по умолчанию), тесты регрессии.

## 3. Закрытые находки (с доказательствами)

| ID | Находка | Статус | Коммит | Чем проверено |
|----|---------|--------|--------|---------------|
| P0-1 | ratchet decrypt мутировал состояние до AEAD — replay/подделка ломали цепочку навсегда | CLOSED | 287b62f | `tests/p0_ratchet_atomicity.rs` (replay, forged dh, skipped-key tamper) |
| P0-2 | сервер стартовал с пустым стором при ошибке загрузки и затирал настоящий файл | CLOSED | 287b62f | `tests/p0_store_failclosed.rs` (`unreadable_store_is_never_overwritten`) |
| P0-6 | fail-open в crypto-negotiation | CLOSED | 287b62f | fail-closed тесты в `tests/audit_fixes.rs` |
| P0-4 | keyHash менялся при рестарте сервера | CLOSED | 850197a | `engine_restart_preserves_key_hash`, `init_router_store_is_stable_across_runs` |
| P1-5 (часть) | стор без ключа / ключ из env | PARTIAL | 850197a | ключ из файла (`SMP_STORE_KEY_FILE` > env), стор без ключа refused, `StoreKey` wiped on drop; открыт TLV-формат |
| RUSTSEC-2026-0387 | уязвимая зависимость `cx448` | CLOSED | до v0.99.3 | `x448` из RustCrypto; CI job `audit` (rustsec) зелёный |

Полная таблица по аудиту 2026-11-23 — `docs/AUDIT-RESPONSE.md`.

## 4. Приоритеты: на что смотреть в первую очередь

| Приоритет | Область | Почему | Как выглядит «сделано» |
|-----------|---------|--------|------------------------|
| P0-3 (остаток) | `src/server.rs` персистентность: `dirty` по типу команды, а не по факту мутации; нет debounce/WAL | потеря сообщений при крэше между fsync | счётчик `revision`, запись только при росте; WAL + снапшоты |
| P0-5 | `src/ffi.rs`, `src/ffi/uniffi.rs`: нет TLS-пиннинга, один глобальный `Mutex<HashMap<u64, Agent>>` на сетевом вызове | MITM мобильного клиента, блокировки UI | pinning + per-handle `Arc<Mutex<Agent>>` + типизированные FFI-ошибки |
| P0-7 | `sessionId` = TLS Finished vs exporter-binding; нет interop-CI с официальным smp-server | несовместимость с Haskell-relay на уровне сессии | `TlsBackend`-trait + interop-CI гейт |
| P1-1..P1-4 | сверка команд/ошибок с `Protocol.hs`, лимиты очередей, прокси private routing, дизайн E2E (PQDR vs «свой протокол») | целостность и честность позиционирования | по `docs/AUDIT-RESPONSE.md` |

Зоны и hunt-листы для трёх аудиторов — `docs/AUDIT-PROMPT.md`.

## 5. Что повторно проверять НЕ нужно

- **База аудита #1 (внутренний fan-out)**: `docs/AUDIT-REPORT.md`, все CLOSED-пункты.
- **Аудит #2 (внешний, 2026-11-23, два отчёта)**: закрытые пункты — таблица выше и `docs/AUDIT-RESPONSE.md`.
- **Секреты и дистрибуция**: свип чистый (п. 0), гейт в CI; история не раздаётся (squash).
- **Probe-бинарники** (`smp_v71`, `xftp_h2_v71`, `xftp_h2_v65_backup`, `ntf_probe`) с `NoVerify` —
  by design, CI `probe-isolation` следит, что их нет в default build.
- **Публичное поведение relay SimpleX** — мы клиент, это не наш баг.

## 6. Как проверить самому

```bash
export PATH="$HOME/build/bin:$PATH" CARGO_HOME=$HOME/build/rust/cargo
cd ~/Projects/simplex-rs && git checkout 6cb00d4
cargo test --locked -- --test-threads=1            # ожидается: 178 passed / 0 failed
cargo clippy --locked --all-targets -- -D warnings # ожидается: 0
cargo test --locked --features v71-probes -- --test-threads=1
cargo test --locked --features ffi -- --test-threads=1
SMP_STRICT=1 cargo test --locked --test strict_e2e -- --test-threads=1
bash scripts/check-tree-hygiene.sh                 # TREE-HYGIENE: OK
bash scripts/live_interop.sh                       # живые публичные relay, SMP v17..v23 + XFTP
```

## 7. Честные пробелы

- **Не сделано:** остаток P0-3 (revision-based dirty, WAL), P0-5 (FFI pinning/локи), P0-7
  (TlsBackend + interop-CI), P1-1..P1-4, TLV-формат стора (P1-5), часть P2/P3 hygiene.
- **Не проверено:** proof-level review человеком-специалистом по криптографии — три внешних
  прохода ловят больше, чем один, но не заменяют его. Live interop последний прогон:
  2026-11-22 (`docs/live/`), повторный — `scripts/live_interop.sh`.
- **Требует решения владельца:** дизайн E2E (настоящий PQDR vs честно названный собственный
  протокол — P1-4), удаление пустого `simplexmq/` vs submodule (P3).
