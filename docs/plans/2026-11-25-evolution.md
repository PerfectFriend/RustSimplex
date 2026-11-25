# План эволюции simplex-rs — 2026-11-25 (после внешнего аудита #3)

База: `main` @ `5812f83`. Аудит #3 дал 24 объединённых находки (см. `docs/AUDIT3-RESPONSE.md`,
каждая parent-verified на `5812f83`). Ниже — план эволюции: три спринта + roadmap решений владельца.

## Спринт A — «закрыть дыры» (блокирует любой публичный релиз)

Порядок: U-01 → U-02 → U-04 → U-05 → U-06 → U-07 → U-08 → U-09 → U-10 → U-11 → U-12 → U-13/U-19 (квоты+таймауты+валидация).

1. **U-01 E2E fail-closed recv**: единый `Agent::process_incoming` — при `e2e && ratchet.is_some()`
   принимать только `Envelope::Msg` с успешным `ratchet.decrypt`; остальное — классифицировать
   (дубль/мусор → ACK + drop, иначе Err без ACK, чтобы очередь не заклинило). `chat.rs` строить
   поверх `recv_agent_all` (убрать копипасту). Тест: инъекция raw `M…`-кадра в E2E-очередь → Err/ACK, сообщения нет в выдаче.
2. **U-02 RFWD lengths**: `<[u8;24]>::try_from` вместо `copy_from_slice` во всех 4 местах `proxy.rs`; негативные тесты в fuzz-харнес.
3. **U-04 SKEY/KEY**: `SKEY` по `by_snd`, обязательная подпись (старый ключ при ротации / новый при первичном),
   `AuthAlg::Ed25519` check, `ERR CMD SYNTAX` на плохой SPKI, `RFWD` прокидывает `server_eph_priv`.
4. **U-05 store race**: `revision: u64` в `ServerState` (++ только при реальной мутации),
   `persist_mutex`, запись только если `revision > last_written`, единый writer. Тест гонки: 8 потоков × N команд → файл == финал.
5. **U-06 `update_store`**: `load_checked_with_key(...)?`; тест «неверный ключ не меняет файл байт-в-байт».
6. **U-07 `x25519_dh_checked`** (`was_contributory()` / не all-zero) во все 9 call sites.
7. **U-08**: в установленной PQDR-сессии `new_dh` требует `KemParams::CtPk`.
8. **U-09**: `#[cfg(feature = "v71-probes")]` на `NoVerify`/`*_noverify`; `xftp-h2` под `required-features`; удалить `xftp_h2_v65_backup.rs`; CI проверяет весь список бинарников + отсутствие `NoVerify` в default lib.
9. **U-10 SSRF**: `to_ipv4_mapped` → IPv4-валидатор; блок CGNAT `100.64.0.0/10`, `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, `240.0.0.0/4`, broadcast, doc ranges, NAT64/Teredo; при DNS — резолв → проверка IP → connect по проверенному `SocketAddr`.
10. **U-11 strict**: при `strict==true` и отсутствии/ошибке `sess_secret` — немедленно закрыть соединение.
11. **U-12 chat/handshake**: ACK после успешной обработки; цикл `recv_block` с `Ack` в `accept_contact`/`await_hello`; `check_send_ok` во всех `SEND`.
12. **U-13/U-19**: лимит соединений (семафор + per-IP), таймаут handshake ДО TLS/read, `thread::Builder::spawn` с обработкой ошибки, квоты/TTL на `by_rcv`/`xftp`/`proxies`/NTF, валидация `Fnew/Fput` (`offset*chunk<=size`, лимиты) и `AuthAlg::X25519` в `New`.

## Спринт B — «честность и совместимость»

13. **U-03/U-14/U-21 FFI**: `connect_tls_sni` + обязательный `PinVerifier` по keyHash + DNS-резолв;
    `HashMap<u64, Arc<Mutex<Agent>>>` (глобальный лок только на lookup); типизированный `FfiError`;
    `recv_agent_hex` → uniffi Record с реальными `msg_id`/`prev_hash`; `save_state/load_state` шифрованно.
14. **U-15 proxy/onion TLS**: `open_proxy_session`/`fetch_hop`/`onion_request` на TLS 1.3 + pin по keyHash из команды/конфига.
15. **U-16/U-11 H10**: убрать `if !sid.is_empty()` — пустой sid в TLS-режиме = отказ; `TlsBackend`-trait (openssl Finished verify_data) — P0-7; согласование версии `min(client_max, server_max)`; interop-CI job против официального `smp-server` (Docker) **библиотечным** клиентом.
16. **U-17 XFTP download**: `orig_size <= size`, временный файл 0o600, запись после проверки sha256, удаление tmp при ошибке, без полного буферизации в RAM.
17. **U-18**: `ReconnectingClient` восстанавливает `SUB`; `[0]` → `.first().ok_or()`; `flush_outbox` удаляет по одному после `check_send_ok`, ошибки не глотать.
18. **U-20**: SOCKS5 `len<=255` check; `SMP_DUMP_RAW` под feature-gate, файл 0o600.
19. **U-20b parsers**: `checked_add` во всех `Reader::take`; лимит `nskip` в `restore`; `cfg(unix)` на `OpenOptionsExt`; `store_version` парсит заголовок без расшифровки.

## Спринт C — «гигиена и процесс»

20. **U-23 CI**: `check_no_unwrap.sh` в CI (расширить на `src/**`, `unwrap_used`/`indexing_slicing` clippy-lints для src); fuzz-харнес расширить на `parse_command`, `handle_rfwd`, `decode_ratchet_msg`, `parse_snapshot`, `parse_agent`, `agent_envelope::decode`, `AgentLink::parse`, `ntf::parse_ntf_batch`; sha256-проверка для kotlin zip / JNA JAR; MSRV job (`+1.87`); SHA-pinning для actions в release.yml; `env:` вместо интерполяции `${ inputs.tag }`.
21. **U-24 hygiene**: удалить `xftp_h2_v65_backup.rs`, пустой `simplexmq/` (или submodule с пином), битую `spec/simplex-file-transfer.md` (14 байт 404), синхронизировать версии/числа тестов в README/SECURITY (генерировать из CI), починить CHANGELOG (дубль v0.99.3, порядок), убрать личные пути окружения из скриптов/тестов (`$HOME/build`, IP, hermes scratch).
22. Процессы: formal responsible-disclosure (SECURITY.md), nightly live-interop job, `cargo-deny`/`machete`.

## Roadmap — решения владельца (ADR, не код)

- **U-25**: настоящий X3DH/X448-handoff для совместимости со stock SimpleX Chat vs честное
  переименование собственного ratchet (убрать «PQDR/Ratchet.hs parity» из доков). Рекомендация ADR: dual-mode.
- **U-26**: agent-mode CLI (invitation → join → E2E chat), auto-reconnect в `async_client`,
  подписанные NTF на публичном сервере (ограничение инфраструктуры).
- PQDR wire-parity (SX448, AEAD-заголовок, `ad` в AEAD) — после U-25.

## Правила исполнения (от владельца)

Три раза думай — один раз делай. Сделал — сразу проверяй (RED→GREEN тест, полный suite, clippy,
push live-verified). Нашёл ошибку — не правь точечно, а переделывай заново всю неработающую часть.
Один коммит на пункт, каждый с регрессионным тестом.
