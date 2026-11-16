# SECURITY.md — smp-rs: модель угроз, границы, известные ограничения

> **Scope note (обновлено, 2026-11-16, v0.86):** репозиторий — interop-клиент/библиотека SMP/XFTP + исследовательский server. **E2E PQDR включён по умолчанию** (`Agent::e2e = true`; plaintext-режим — явно `agent.e2e = false`, env-гейтов в lib нет, FFI-путь env-free). Joiner буферизует исходящие A_MSG в outbox до первого входящего ratchet-кадра (double-ratchet rule), flush в `recv_agent`/`recv_text`. Покрыто тестами `chat_e2e_over_pqdr_default_on` + `chat_e2e_concurrent_first_send` (65/65). Store шифруется `SMP1` при наличии `SMP_STORE_KEY` (fail-closed).

## Что защищает протокол (и наша реализация)

- **Конфиденциальность сообщений**: тело MSG шифруется NaCl crypto_box
  (HSalsa20(shared, 0^16) → XSalsa20-Poly1305, nonce = cbNonce(msgId)) между
  DH-ключами очереди отправителя и роутера. Роутер видит только метаданные.
- **Аутентификация команд**: Ed25519-подпись над
  `short(sessionId)|short(corrId)|short(entityId)|command` (SMP v≥7).
  X25519 crypto_box-authenticator (`auth_box`/`verify_box`, secretbox над
  SHA-512(authorized), nonce = cbNonce(corrId)) реализован и протестирован.
- **Аутентификация роутера**: TLS 1.3, клиент пинит роутер по
  keyHash = SHA-256(SPKI DER сертификата) — `PinVerifier`, чужой сертификат →
  `UnknownIssuer` (тест `tls_wrong_keyhash_rejected`).
- **XFTP**: TLS 1.3 + ALPN `xftp/1`, router keyHash в clientHello; FILE-тело —
  потоковый XSalsa20-Poly1305 с ключом crypto_box beforenm от DH(rPriv, sDhPub)
  и tail-tag (проверено байт-в-байт против живого xftp-server v6.5.0.17).
- **PQDR (v0.15)**: SNTRUP761 KEM + гибридный секрет SHA3-256(dh‖kem)
  (`kemHybridSecret` по SNTRUP761.hs), `kemParams` wire-формат, kcb-шифрование.

## Модель угроз

| Угроза | Защита | Примечание |
|---|---|---|
| Пассивный слушатель на пути клиент↔роутер | TLS 1.3 transport + router→recipient crypto_box; по умолчанию ещё и PQDR поверх | без E2E (e2e=false) роутер видит только метаданные SMP, но agent-demo body — нет |
| MITM с чужим сертификатом | pin по keyHash | см. ниже про sessionId |
| Подделка команд третьей стороной | Ed25519/X25519 authenticator | |
| Роутер-имитатор очереди | по умолчанию PQDR ratchet, ключ только у концов; иначе только router-level box | plaintext только при явном e2e=false |
| Постквантовый сбор трафика | PQDR KEM+ratchet (SNTRUP761), snapshot/restore, zeroize on drop | **default-on (v0.86)**, chat concurrent-first-send покрыт тестом |

## Намеренные отклонения и известные ограничения (честно)

1. **sessionId = "" на обеих сторонах** (plain и TLS 1.3). По RFC 5929
   tls-unique для TLS 1.3 пуст, и Haskell-имплементация simplexmq ведёт себя
   так же; привязка к каналу обеспечивается pinning сертификата, а не
   tls-unique. **Реализовано в v0.16**: клиентская assert-проверка
   `check_session_binding(serverHello.sessionId)` (должен быть пуст) и
   X25519 box-auth для обычных очередей: authenticator =
   `secretbox(dhSecret, cbNonce(corrId), sha512(authorized))`, где
   `dhSecret = DH(queue auth priv, server per-connection eph pub)` из
   server hello (C.cbVerify / C.cbAuthenticate). Тест:
   `tls_x25519_box_auth_roundtrip`, `session_binding_rejects_nonempty_sid`.
2. **PQDR**: реализован KEM-слой (SNTRUP761, гибридный секрет, wire-формат
   kemParams/e2eRatchetParams) **и полный double ratchet v0.17** (`src/pqdr.rs`):
   KDF дословно из `Ratchet.hs` (HKDF-SHA512, info `"SimpleXRootRatchet"` /
   `"SimpleXChainRatchet"`, 96 байт → RK/CK/NHK и CK/MK/IV), DH-ratchet +
   "parallel ping-pong" из двух KEM-раундов на каждый шаг (KEM #1 encaps, KEM #2
   decaps), skipped message keys. **Отклонение от wire-спеки** (задокументировано):
   X25519 вместо Curve448, хедер в plaintext (не AES-256-GCM), тело —
   XSalsa20-Poly1305 вместо AES-GCM. Тесты: `tests/pqdr_ratchet.rs` (8 тестов).
3. **`xftp-h2` probe-бинарник** использует permissive проверку сертификата
   (только для локального интероп-теста). Не для production.
4. **In-memory + опциональный снапшот** (`--store`): снапшот пишется
   atomic (tmp+rename), но не шифруется и не защищён от tamper (нет MAC).
5. **Тесты чувствительны к таймингам** при параллельном прогоне
   (`cargo test` запускает test-бинарники параллельно; poll-pump 50 мс).
   Замечен один флак `chat_text_over_agent_connection` под нагрузкой; повторные
   прогоны зелёные. Рекомендуется `--test-threads=1` для аудита.
6. Ответ на `SEND` — `OK` (в Haskell ответ может отсутствовать) — локальная
   договорённость request/response.

## Как сообщать об уязвимостях

Проект локальный/исследовательский. Пишите владельцу напрямую; вülle
публичных ключей/секретов в репозитории нет (проверено grep-сканом).
