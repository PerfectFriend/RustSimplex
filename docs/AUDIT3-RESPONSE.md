# Ответ на внешний аудит #3 (три независимых отчёта, 2026-11-25)

**Аудируемая база:** `main` @ `5812f83` (squash-артефакт `simplex-rs-audit-squash.tar.gz`, sha256 в handoff).
**Отчёты:** `RustSimplex_Audit_Report.md` (report-1: продуктовый), `RUSTSIMPLEX_AUDIT.md` (report-2: F-01..F-23),
`Аудит smp-rs v0.99.3 — отчёт кодеру.md` (report-3: C1/H1..H12/M1..M14/L1..L10).
**Метод:** parent re-verified КАЖДУЮ headline-находку grep+чтением на `5812f83` перед включением в план
(per external-audit-handoff: «open in report ≠ open in HEAD»). Все перечисленные ниже находки
**подтверждены в коде на 5812f83** — file:line в таблице.

## Сводная арбитражная таблица (dedup трёх отчётов, parent arbitrates severity)

| Unified ID | Из отчётов | Severity | Где подтверждено (HEAD 5812f83) | Статус | Спринт |
|---|---|---|---|---|---|
| U-01 E2E downgrade bypass | F-01 = C1 | CRITICAL | `agent.rs:809-821,856-868`, `chat.rs:80-92` — `_ => (false, pt.clone())` пропускает ratchet | OPEN | A |
| U-02 RFWD remote panic | F-02 = H11(part) | CRITICAL | `proxy.rs:147,158` (`copy_from_slice`, также `:57,111`) | OPEN | A |
| U-03 FFI plain TCP, no pin | F-03 = H7(part) | CRITICAL | `ffi.rs:32,43` `Client::connect_plain(addr,&kh)` — kh игнорируется | OPEN | B |
| U-04 SKEY/KEY authz broken | F-06 = H12 | HIGH | `server.rs:470-489` — SKEY ищет по `by_rcv`, `.unwrap_or(true)`, SPKI-ошибка → `Ok` | OPEN | A |
| U-05 store write race + dirty-by-cmd | F-07 = H1+H2 | HIGH | `server.rs:253-272` — статический `dirty`, запись вне локa без revision | OPEN | A |
| U-06 `update_store` затирает нечитаемый стор | H5 = F-17(part) | HIGH | `store.rs:676` `load_with_key(..).unwrap_or_default()` | OPEN | A |
| U-07 X25519 без contributory-check | F-04 = M3 | HIGH | `crypto.rs:86` `x25519_dh` — 9 call sites | OPEN | A |
| U-08 KEM опционален на new_dh | F-05 | HIGH | `pqdr.rs:533-559` `KemParams::Pk → kem_ss=None` | OPEN | A |
| U-09 NoVerify в default-сборке | F-10 = H9 | HIGH | `transport.rs:320-390` pub без cfg; `Cargo.toml` `xftp-h2` без required-features | OPEN | A |
| U-10 SSRF-guard обход | F-08 = H11(part) | HIGH | `server.rs:1180-1201` — нет `to_ipv4_mapped`, CGNAT и др. | OPEN | A |
| U-11 strict тихо деградирует | F-13 | HIGH | `server.rs:781-786` — `Err/None → (None,None)` | OPEN | A |
| U-12 потеря/ACK-до-decrypt в chat+handshake | F-14 = H6 | HIGH | `chat.rs:76-99` ACK до `r.decrypt`, `return` теряет остальные MSG; `agent.rs` handshake без ACK-цикла | OPEN | A |
| U-13 DoS: no limits/timeouts | F-12 = H3+H4 | HIGH | `server.rs:1141` spawn без лимита; handshake без таймаута; нет квот by_rcv/xftp/proxies/ntf | OPEN | A/B |
| U-14 FFI global mutex on net I/O | F-16 = H7(part) | HIGH | `ffi.rs:10-13` | OPEN | B |
| U-15 proxy/onion plaintext, no pin | F-09 = H11(part) | HIGH | `proxy.rs:42-59`, `onion.rs:36-55`, `server.rs:583-585` `dest_kh=[0;32]` | OPEN | B |
| U-16 channel-binding skip on empty sid | F-11 = H10(part) | HIGH | `client.rs:64-66`, `async_client.rs:359-364` — `if !sid.is_empty()` | OPEN | B |
| U-17 XFTP: запись до проверки digest, OOM, orig_size | F-15 | HIGH | `xftp.rs:293-333` | OPEN | B |
| U-18 reconnect теряет SUB; `[0]`-паники; outbox | F-18 | MEDIUM | `reconnect.rs:243-277`, `agent.rs:369,544-549,616-618,776,898-900`, `xftp.rs:158,166,205,271,286` | OPEN | B |
| U-19 Fnew/Fput/New без валидации | F-19 = H4(part) | MEDIUM | `server.rs:305-309,514-543` | OPEN | A/B |
| U-20 store/encoding/pqdr parserы | F-17(rest) = H8(part) | MEDIUM | `store.rs:215,488,573`, `encoding.rs:75`, `pqdr.rs:670,752-753` | OPEN | B/C |
| U-21 SOCKS5 усечение; SMP_DUMP_RAW | F-20 = M7/M8(part) | MEDIUM | `transport.rs:548-551`, `client.rs:289-299` | OPEN | B |
| U-22 FFI теряет msg_id/prev_hash | F-21 = H7(part) | MEDIUM | `ffi.rs:61-64` | OPEN | B |
| U-23 CI/supply-chain пробелы | F-22 = M9(part),M13 | MEDIUM | `check_no_unwrap.sh` не в CI; нет sha256 для JAR/zip; fuzz покрытие узкое | OPEN | C |
| U-24 hygiene: дубль bin, пустой simplexmq, версии в доках | F-23 = L1-L10 | LOW | `xftp_h2_v65_backup.rs`, `simplexmq/`, README/SECURITY версии | OPEN | C |
| U-25 X3DH vs own-ratchet позиционирование | report-1 P0-1 = audit#2 P1-4 | DECISION (owner) | `agent.rs:355-379` — x448_shared вычисляется, в ratchet не подаётся | owner decision | roadmap |
| U-26 agent-mode CLI, async auto-reconnect, nightly interop | report-1 P0/P1 | FEATURE | — | roadmap | roadmap |
| — внешний аудит заказан | report-1 P0-2 (G7) | DONE | этот аудит #3, 3 отчёта | CLOSED | — |

## Что НЕ будем делать (и почему)

- **Не «чиним» U-25 кодом**: это дизайн-решение владельца (настоящий X3DH/X448-handoff vs честно
  названный собственный ratchet). ADR draft — в плане, реализация после решения владельца.
- Report-3 «ничего не компилировалось» — их environment limitation, не находка; все их находки
  перепроверены нами на HEAD с запуском тестов.

## Критерии приёмки (per external-audit-handoff)

Каждый пункт — отдельный коммит, regression-тест **падает на старом коде** (RED → GREEN),
`cargo test --locked` 0 FAILED, `clippy --all-targets -- -D warnings` 0, push верифицирован
`git ls-remote origin main == git rev-parse HEAD`. CI зелёный.
