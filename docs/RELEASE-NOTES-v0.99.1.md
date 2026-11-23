# smp-rs v0.99.1 — closed beta

Релиз библиотеки и бинарей SimpleX Messaging Protocol stack на Rust: SMP-роутер,
SMP-клиент, XFTP-файлы, NTF-нотификации и agent/chat-слой с PQDR E2E-речетом.

- crates.io: `smp-rs = "0.99.1"` · docs.rs: https://docs.rs/smp-rs/0.99.1
- checksum: `4ea568a937a22743d2bc98c5b7aa3f89c5fe29172a588b682531ba6178a96c09`
- репозиторий: https://github.com/PerfectFriend/RustSimplex

## Что внутри

| Слой | Состояние |
|---|---|
| SMP v17–v23 (шифрованные очереди, TLS 1.3) | проверено live против публичных релеев |
| XFTP v4 (FNEW/FPUT/FGET/FDEL, chunked 1 MiB byte-exact) | проверено live |
| NTF v3 (`PING→PONG`) | проверено live |
| Agent-протокол (official envelope `C`/`M`/`I`/`R`, v=7) | payload шифруется PQDR-речетом на уровне всего кадра |
| X448 (RFC 7748) | keypair/DH/SPKI, golden-вектор сверен с OpenSSL; ключи обмениваются в agent-flow |
| PQDR (X25519 + SNTRUP761) | KAT прогнан против SUPERCOP-векторов |
| FFI (uniffi → JNA → cdylib) | Kotlin→Rust smoke-тест проходит (`FFI SMOKE: OK`) |

## Проверки на релиз

- `cargo test` — 162 теста, 0 падений
- `cargo clippy --all-targets` — 0 предупреждений
- `cargo audit` — 0 уязвимостей (4 известных advisory в allowlist)
- `cargo publish --dry-run` — OK
- SBOM: CycloneDX 1.5, 219 компонент

## Что честно не сделано (closed beta, не 1.0)

- **X3DH-речет на X448** не реализован: наш agent-flow использует PQDR, поэтому
  стоковый SimpleX-клиент наш ciphertext не расшифрует. Это главный блокер
  полной мобильной интероперабельности.
- `smp-client` не имеет agent-mode CLI (нет автоматизации contact-link + double-ratchet).
- У async-клиента нет собственного auto-reconnect.
- Внешний аудит (G7) не подписан — письмо аудитору лежит в `docs/AUDITOR-LETTER.md`.

Детали и доказательства: `docs/RELEASE-READINESS.md` (ревизия 10),
`docs/AUDITOR-LETTER.md`, живой прогон — `docs/live/live-interop-2026-11-22.log`.
