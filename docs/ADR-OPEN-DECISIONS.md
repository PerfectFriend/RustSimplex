# Открытые решения владельца (ADR) — что требуется выбрать

Дата: 2026-11-26. **СТАТУС: все пункты решены владельцем 2026-11-26, выполнены в `17dfc66`**
(тесты 202/0, clippy 0). Ниже — принятое решение по каждому пункту.

**Решено: (a) dual-mode** — `src/x3dh.rs` (X3DH/X25519 primitive, contributory DH, SPK sig); PQDR остаётся default. Полный wire-parity со stock — follow-up.

## D1. U-25 — протокол рукопожатия: interop vs честность
**Вопрос:** наш ratchet (PQDR/X448) сейчас позиционируется как «parity с SimpleX Chat».
**Варианты:**
- **(a) Dual-mode (рекомендовано планом):** реализовать настоящий X3DH/X448-handoff рядом с PQDR —
  тогда клиент совместим со stock SimpleX Chat. Стоимость: semanas работы, нужен SX448 wire-parity (AEAD-заголовок, `ad`).
- **(b) Честное переименование:** убрать «parity» из README/SECURITY/spec, назвать протокол своим именем.
  Стоимость: 1 коммит в доки, но теряем совместимость.
**Нужно от владельца:** a или b. После U-25 идёт PQDR wire-parity (SX448, AEAD header, ad).

**Решено: (b)** — auto-reconnect в `async_client.rs`: remembered SUB + `reconnect()` + `request_retry()` (re-SUB через send_only, U-18).

## D2. U-26 — agent-mode CLI
**Вопрос:** нужен ли нам CLI-сценарий invitation → join → E2E chat поверх agent API?
**Варианты:**
- **(a) Да, полный:** CLI + auto-reconnect в `async_client` + подписанные NTF на публичном сервере
  (но NTF на публичном сервере — ограничение инфраструктуры, может не взлететь).
- **(b) Только auto-reconnect в async_client** (reconnect.rs уже частично), CLI позже.
- **(c) Нет**, FFI/Kotlin хватает.
**Нужно:** a/b/c + приоритет относительно D1.

**Решено: (b)** — channel binding = TLS exporter, задокументировано в SECURITY.md; P0-7 (raw Finished) — follow-up.

## D3. P0-7 — TLS channel binding
**Вопрос:** сейчас session binding идёт через TLS exporter; «настоящий» binding —
raw Finished verify_data (нужен TlsBackend на openssl-sys).
**Варианты:**
- **(a) Реализовать P0-7** (добавляет зависимость/код извлечения verify_data; усиливает привязку к TLS-сессии).
- **(b) Оставить exporter** и явно задокументировать в SECURITY.md, что binding = exporter-based.
**Нужно:** a или b. Влияет на формулировки в SECURITY.md.

**Решено: (a)** — клон `simplexmq/` удалён из репозитория.

## D4. `simplexmq/` — пустая директория vs pinned submodule
**Варианты:** (a) удалить пустую директорию; (b) submodule с пином конкретного коммита.
**Нужно:** a или b (+ если b — какой коммит пинить).

**Решено: (b)** — interop/fuzz CI-джобы остаются локальными скриптами до появления раннеров с Docker+сеть.

## D5. CI-джобы, которым нужна сеть/Docker
- interop-CI job против официального `smp-server` (Docker) библиотечным клиентом;
- nightly live-interop; fuzz job (cargo-fuzz) в CI.
**Вопрос:** есть ли у тебя раннеры с Docker+сеть? (a) включить джобы, (b) оставить локальные скрипты (`scripts/live_interop.sh`, `live_public_smp.sh`).
**Нужно:** a или b.

**Решено: (a)** — `scripts/sync_docs.sh` + CI job `docs-sync` (CHECK-режим); README синкнут до 202 тестов.

## D6. README/SECURITY: цифры из CI
**Вопрос:** генерировать версию/число тестов в README/SECURITY шагом CI (badge/commits) или синхронизировать руками?
**Нужно:** a или b.

**Решено: частично** — responsible disclosure в SECURITY.md, MSRV+1 (1.88) job; SHA-pin actions и cargo-deny отложены.

## D7. Процессы (опционально)
- responsible-disclosure в SECURITY.md (контакт/ SLA);
- `cargo-deny`/`machete` в CI (лицензии/лишние зависимости);
- SHA-pinning для GitHub Actions в release.yml; `env:` вместо `${{ inputs.* }}`;
- MSRV+1 job (сейчас только 1.87).
**Нужно:** принять всё / частично / нет.

## Что я могу сделать без решения
Расширение fuzz-покрытия в CI-локально, негативные тесты, доки — уже сделано/в процессе.
Всё из D1–D7 ждёт твоего выбора.
