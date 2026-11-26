<p align="center">
  <img src="https://img.shields.io/badge/SMP-v23-2f6feb?style=flat-square" alt="SMP v23" />
  <img src="https://img.shields.io/badge/rust-1.87%2B-b7410e?style=flat-square" alt="Rust 1.87+" />
  <img src="https://img.shields.io/badge/license-MIT-2ea44f?style=flat-square" alt="MIT" />
  <img src="https://img.shields.io/badge/tests-202%20passed-2ea44f?style=flat-square" alt="162 tests" />
  <img src="https://img.shields.io/badge/clippy-0%20warnings-2ea44f?style=flat-square" alt="clippy clean" />
</p>

<h1 align="center">smp-rs</h1>

<p align="center">
  <b>Rust implementation of the SimpleX Messaging Protocol stack</b><br />
  <i>SMP relay · XFTP files · NTF notifications · agent protocol · PQDR & X448 E2E ratchets</i>
</p>

<p align="center">
  <a href="#ru">🇷🇺 Русский</a> &nbsp;·&nbsp;
  <a href="#en">🇬🇧 English</a> &nbsp;·&nbsp;
  <a href="#es">🇪🇸 Español</a>
</p>

<p align="center">
  <a href="https://crates.io/crates/smp-rs"><img src="https://img.shields.io/crates/v/smp-rs.svg?style=flat" alt="crates.io" /></a>
  <a href="https://docs.rs/smp-rs"><img src="https://img.shields.io/docsrs/smp-rs.svg?style=flat" alt="docs.rs" /></a>
  <a href="https://github.com/PerfectFriend/RustSimplex/releases"><img src="https://img.shields.io/github/release/PerfectFriend/RustSimplex.svg?style=flat" alt="release" /></a>
  <img src="https://img.shields.io/badge/published-crates.io-0.99.1-c4742e?style=flat-square" alt="published" />
</p>

---

<a id="ru"></a>

## 🇷🇺 Русский

**smp-rs** — чистая Rust-реализация wire-протоколов, на которых работают **SimpleX Chat**
и Haskell-роутер **simplexmq**: SMP (релей очередей), XFTP (файлы), NTF (уведомления),
agent-протокол и E2E-речеты (PQDR + X448).

Источник правды — репозиторий `simplex-chat/simplexmq` (клон в `./simplexmq`) и спецификации
в `spec/`. При расхождении спецификации и кода **побеждает код** (Haskell-референс).

> **Честный принцип проекта:** каждое заявленное «работает» подтверждается либо живым
> round-trip'ом против публичной инфраструктуры SimpleX, либо кросс-имплементационной
> сверкой с эталоном (OpenSSL, SUPERCOP, `python cryptography`).

### Что реализовано

| Слой | Модули | Соответствие Haskell-референсу |
|---|---|---|
| Кодирование | `encoding.rs` | `Simplex.Messaging.Encoding` — shortString (1B len), largeString (2B BE), Maybe `"0"/"1"`, pad = `word16BE(len) <> msg <> '#'*n` |
| Криптография | `crypto.rs` | X25519 DH, Ed25519, SPKI DER, NaCl `crypto_box` = XSalsa20-Poly1305 (`MAC ‖ ct`), CbNonce 24B, KeyHash = SHA-256 |
| Команды | `protocol.rs` | `Protocol.hs` — NEW/IDS/SUB/SOK/SEND/MSG/ACK/KEY/SKEY/GET/OFF/DEL/PING + OK/ERR/PONG/END/DELD |
| Транспорт | `transport.rs` | transmission = `short(auth) short(corrId) short(entityId) cmd`, блок 16384 B, handshake router/client hello, TLS 1.3 + пиннинг CA-fingerprint |
| Роутер | `server.rs` | in-memory очереди + push, NTF-креденшелы, XFTP-пакеты, snapshot с AEAD |
| XFTP | `xftp.rs` | `FileTransfer.hs` — FNEW/FPUT/FGET/FDEL, chunked-стрим, byte-exact содержимое |
| NTF | `ntf.rs`, `ntf_server.rs` | отдельный протокол: блок **512 B**, свой handshake, тегсет `TNEW/SNEW/PING`, `implySessId` |
| E2E PQDR | `pq.rs`, `pqdr.rs` | `Ratchet.hs` — SNTRUP761 KEM + double ratchet, KDF HKDF-SHA512, rotation + reorder window |
| X448 | `x448.rs` | RFC 7748 Curve448: keypair / DH / SPKI; golden-вектор сверен с OpenSSL |
| Agent | `agent.rs`, `agent_envelope.rs`, `agent_link.rs` | официальный `agentMsgEnvelope` (v=7): `"M"`/`"C"`/`"I"`/`"R"`, payload шифруется PQDR-речетом **на уровне всего кадра** |
| Ссылки | `agent_link.rs` | официальная форма `simplex:/invitation#/?v=…&smp=…&e2e=…` по ABNF `simplexmq` 7.0.1.0 |
| Proxy / onion | `proxy.rs`, `onion.rs` | 2- и 3-хоповые цепочки через SMP proxy |
| Прочее | `async_client.rs`, `reconnect.rs`, `store.rs`, `identity.rs`, `sb_chain.rs`, `ffi.rs` | async-клиент, backoff-reconnect, store с AEAD, FFI-фасад (uniffi) |

### Быстрый старт

```bash
# библиотека
cargo add smp-rs

# бинарники (роутер, клиент, XFTP/ NTF-проберы)
cargo install smp-rs --version 0.99.1

# локальный роутер
smp-server --bind 127.0.0.1:5223 --store /tmp/smp-store

# клиент к роутеру (plain) / к публичному релею (TLS + keyHash)
smp-client 127.0.0.1:5223
smp-client --tls smp11.simplex.im "$(base64 -w0 < keyhash.bin)" smp11.simplex.im:5223
```

```toml
# Cargo.toml
[dependencies]
smp-rs = "0.99.1"
```

### Проверка

```bash
cargo test                    # 202 теста, 0 падений
cargo clippy --all-targets    # 0 предупреждений
cargo audit                   # 0 неallowlisted advisory (4 известных — в allowlist)
cargo publish --dry-run       # OK
```

| Проверка | Результат |
|---|---|
| Модульные + интеграционные тесты | **202 passed / 0 failed** |
| clippy (`--all-targets`, оба feature-конфига) | **0 warnings** |
| `cargo audit` | 0 новых advisory; 4 известных (RUSTSEC-2023-0037, -2024-0436, -2025-0141, -2026-0374) — в allowlist |
| PQDR KAT | сверено с SUPERCOP-векторами `supercop-20201130` |
| X448 | golden-вектор сверен с OpenSSL (`python cryptography`) — байт-в-байт |
| FFI | Kotlin → uniffi → JNA → cdylib → Rust: smoke проходит (`FFI SMOKE: OK`) |
| SBOM | CycloneDX 1.5, 219 компонент |

### Live-интероп (против публичной инфраструктуры)

| Цель | Результат |
|---|---|
| `smp11.simplex.im:5223` (SMP v17–v23) | полный цикл `PING→PONG, NEW→IDS, SUB→SOK, SEND→MSG(decrypt), ACK→OK, DEL→OK` — 7/7 версий |
| `xftp1.simplex.im:443` (XFTP v4) | `FNEW→SIDS, FPUT 64 KB→OK, FGET→FILE (byte-exact), FDEL→OK`; chunked 1 MiB — sha256 совпал |
| `ntf2.simplex.im:443` (NTF v3, ALPN `ntf/1`) | handshake принят, `PING→PONG` через библиотечный `NtfClient`; пининг CA подтверждён отрицательным контролем |
| SMP proxy | публичные релеи отключили proxy серверной стороной: живая попытка → `ERR CMD SYNTAX` (подтверждённый факт, лог: `docs/live/live-interop-2026-11-22.log`) |

### Релиз

`v0.99.1` опубликован на crates.io (2026-11-23, checksum `4ea568a9…`), создан GitHub Release.
Тег `vX.Y.Z` запускает `.github/workflows/release.yml`: сверка версии с `Cargo.toml` → тесты +
clippy + `cargo package` → changelog → публикация **ровно тегированного** коммита (`--locked`)
на crates.io + GitHub release. Требуется секрет `CARGO_REGISTRY_TOKEN`.

### Границы (что честно не сделано)

- **X3DH-речет на X448 не реализован**: наш agent-flow использует PQDR, поэтому стоковый
  SimpleX-клиент наш ciphertext не расшифрует. Это главный блокер полной мобильной интероперабельности.
- У `smp-client` нет agent-mode CLI (автоматизация contact-link + double-ratchet).
- У async-клиента нет собственного auto-reconnect (есть backoff-цикл у `reconnect`).
- Подписанные NTF-команды (`SNEW`/`TNEW` с Ed25519-авторизацией) не реализованы.
- Внешний аудит (G7) не подписан — письмо лежит в `docs/AUDITOR-LETTER.md`.

### Документы

`docs/RELEASE-READINESS.md` (аудит готовности) · `docs/AUDITOR-LETTER.md` · `docs/SECURITY.md` ·
`docs/ROADMAP.md` · `docs/RELEASE-NOTES-v0.99.1.md` · `docs/live/` (живые логи)

---

<a id="en"></a>

## 🇬🇧 English

**smp-rs** is a pure-Rust implementation of the wire protocols behind **SimpleX Chat** and the
Haskell **simplexmq** relay: SMP (message queues), XFTP (files), NTF (notifications), the agent
protocol, and E2E ratchets (PQDR + X448).

The source of truth is the `simplex-chat/simplexmq` repository (cloned into `./simplexmq`) plus the
specifications in `spec/`. When spec and code disagree, **the code wins** (the Haskell reference).

> **Honest-project rule:** every "it works" claim is backed either by a live round-trip against
> the public SimpleX infrastructure or by a cross-implementation check against a reference
> (OpenSSL, SUPERCOP, `python cryptography`).

### What's implemented

| Layer | Modules | Haskell reference parity |
|---|---|---|
| Encoding | `encoding.rs` | `Simplex.Messaging.Encoding` — shortString (1B len), largeString (2B BE), Maybe `"0"/"1"`, pad = `word16BE(len) <> msg <> '#'*n` |
| Crypto | `crypto.rs` | X25519 DH, Ed25519, SPKI DER, NaCl `crypto_box` = XSalsa20-Poly1305 (`MAC ‖ ct`), CbNonce 24B, KeyHash = SHA-256 |
| Commands | `protocol.rs` | `Protocol.hs` — NEW/IDS/SUB/SOK/SEND/MSG/ACK/KEY/SKEY/GET/OFF/DEL/PING + OK/ERR/PONG/END/DELD |
| Transport | `transport.rs` | transmission = `short(auth) short(corrId) short(entityId) cmd`, 16384 B blocks, router/client hello handshake, TLS 1.3 + CA-fingerprint pinning |
| Relay | `server.rs` | in-memory queues + push, NTF credentials, XFTP packets, AEAD-encrypted snapshots |
| XFTP | `xftp.rs` | `FileTransfer.hs` — FNEW/FPUT/FGET/FDEL, chunked streaming, byte-exact payloads |
| NTF | `ntf.rs`, `ntf_server.rs` | separate protocol: **512 B** blocks, own handshake, `TNEW/SNEW/PING` tag set, `implySessId` |
| E2E PQDR | `pq.rs`, `pqdr.rs` | `Ratchet.hs` — SNTRUP761 KEM + double ratchet, HKDF-SHA512 KDF, rotation + reorder window |
| X448 | `x448.rs` | RFC 7748 Curve448: keypair / DH / SPKI; golden vector cross-checked against OpenSSL |
| Agent | `agent.rs`, `agent_envelope.rs`, `agent_link.rs` | official `agentMsgEnvelope` (v=7): `"M"`/`"C"`/`"I"`/`"R"`; the payload is PQDR-encrypted **at whole-frame level** |
| Links | `agent_link.rs` | official `simplex:/invitation#/?v=…&smp=…&e2e=…` shape per the `simplexmq` 7.0.1.0 ABNF |
| Proxy / onion | `proxy.rs`, `onion.rs` | 2- and 3-hop chains over the SMP proxy |
| Extras | `async_client.rs`, `reconnect.rs`, `store.rs`, `identity.rs`, `sb_chain.rs`, `ffi.rs` | async client, backoff reconnect, AEAD store, uniffi FFI facade |

### Quick start

```bash
# library
cargo add smp-rs

# binaries (relay, client, XFTP/NTF probes)
cargo install smp-rs --version 0.99.1

# local relay
smp-server --bind 127.0.0.1:5223 --store /tmp/smp-store

# client against a relay (plain) / against the public relay (TLS + keyHash)
smp-client 127.0.0.1:5223
smp-client --tls smp11.simplex.im "$(base64 -w0 < keyhash.bin)" smp11.simplex.im:5223
```

```toml
# Cargo.toml
[dependencies]
smp-rs = "0.99.1"
```

### Verification

```bash
cargo test                    # 202 tests, 0 failures
cargo clippy --all-targets    # 0 warnings
cargo audit                   # 0 non-allowlisted advisories (4 known ones are allowlisted)
cargo publish --dry-run       # OK
```

| Check | Result |
|---|---|
| Unit + integration tests | **202 passed / 0 failed** |
| clippy (`--all-targets`, both feature configs) | **0 warnings** |
| `cargo audit` | 0 new advisories; 4 known (RUSTSEC-2023-0037, -2024-0436, -2025-0141, -2026-0374) allowlisted |
| PQDR KAT | checked against the SUPERCOP `supercop-20201130` vectors |
| X448 | golden vector checked against OpenSSL (`python cryptography`) — byte-exact |
| FFI | Kotlin → uniffi → JNA → cdylib → Rust smoke passes (`FFI SMOKE: OK`) |
| SBOM | CycloneDX 1.5, 219 components |

### Live interoperability (public infrastructure)

| Target | Result |
|---|---|
| `smp11.simplex.im:5223` (SMP v17–v23) | full cycle `PING→PONG, NEW→IDS, SUB→SOK, SEND→MSG(decrypt), ACK→OK, DEL→OK` — 7/7 versions |
| `xftp1.simplex.im:443` (XFTP v4) | `FNEW→SIDS, FPUT 64 KB→OK, FGET→FILE (byte-exact), FDEL→OK`; chunked 1 MiB sha256 matched |
| `ntf2.simplex.im:443` (NTF v3, ALPN `ntf/1`) | handshake accepted, `PING→PONG` via the library `NtfClient`; CA pinning confirmed by a negative control |
| SMP proxy | public relays disabled proxy server-side: live attempt → `ERR CMD SYNTAX` (recorded fact, log: `docs/live/live-interop-2026-11-22.log`) |

### Release

`v0.99.1` is published on crates.io (2026-11-23, checksum `4ea568a9…`) with a GitHub Release.
A `vX.Y.Z` tag triggers `.github/workflows/release.yml`: version cross-check against `Cargo.toml` →
tests + clippy + `cargo package` → changelog → publish of **exactly the tagged commit** (`--locked`)
to crates.io + GitHub release. Requires the `CARGO_REGISTRY_TOKEN` secret.

### Boundaries (honestly not done yet)

- **The X3DH ratchet on X448 is not implemented**: our agent flow uses PQDR, so the stock SimpleX
  client cannot decrypt our ciphertext. This is the main blocker for full mobile interoperability.
- `smp-client` has no agent-mode CLI (contact-link + double-ratchet automation).
- The async client has no auto-reconnect of its own (the `reconnect` module provides a backoff loop).
- Signed NTF commands (`SNEW`/`TNEW` with Ed25519 authorization) are not implemented.
- The external audit (G7) is not signed off — the letter is ready in `docs/AUDITOR-LETTER.md`.

### Docs

`docs/RELEASE-READINESS.md` (readiness audit) · `docs/AUDITOR-LETTER.md` · `docs/SECURITY.md` ·
`docs/ROADMAP.md` · `docs/RELEASE-NOTES-v0.99.1.md` · `docs/live/` (live logs)

---

<a id="es"></a>

## 🇪🇸 Español

**smp-rs** es una implementación en Rust puro de los protocolos de cable sobre los que funcionan
**SimpleX Chat** y el relé Haskell **simplexmq**: SMP (colas de mensajes), XFTP (archivos),
NTF (notificaciones), el protocolo de agente y los trinquetes E2E (PQDR + X448).

La fuente de verdad es el repositorio `simplex-chat/simplexmq` (clonado en `./simplexmq`) más las
especificaciones de `spec/`. Cuando la especificación y el código discrepan, **manda el código**
(la referencia en Haskell).

> **Regla honesta del proyecto:** cada «funciona» está respaldado por un round-trip real contra
> la infraestructura pública de SimpleX o por una comprobación cruzada frente a una referencia
> (OpenSSL, SUPERCOP, `python cryptography`).

### Qué está implementado

| Capa | Módulos | Equivalencia con la referencia Haskell |
|---|---|---|
| Codificación | `encoding.rs` | `Simplex.Messaging.Encoding` — shortString (1B len), largeString (2B BE), Maybe `"0"/"1"`, pad = `word16BE(len) <> msg <> '#'*n` |
| Criptografía | `crypto.rs` | X25519 DH, Ed25519, SPKI DER, NaCl `crypto_box` = XSalsa20-Poly1305 (`MAC ‖ ct`), CbNonce 24B, KeyHash = SHA-256 |
| Comandos | `protocol.rs` | `Protocol.hs` — NEW/IDS/SUB/SOK/SEND/MSG/ACK/KEY/SKEY/GET/OFF/DEL/PING + OK/ERR/PONG/END/DELD |
| Transporte | `transport.rs` | transmission = `short(auth) short(corrId) short(entityId) cmd`, bloques de 16384 B, handshake router/client hello, TLS 1.3 + pinning por huella CA |
| Relé | `server.rs` | colas en memoria + push, credenciales NTF, paquetes XFTP, instantáneas cifradas con AEAD |
| XFTP | `xftp.rs` | `FileTransfer.hs` — FNEW/FPUT/FGET/FDEL, streaming por bloques, contenido byte-exacto |
| NTF | `ntf.rs`, `ntf_server.rs` | protocolo aparte: bloques de **512 B**, handshake propio, conjunto `TNEW/SNEW/PING`, `implySessId` |
| E2E PQDR | `pq.rs`, `pqdr.rs` | `Ratchet.hs` — KEM SNTRUP761 + double ratchet, KDF HKDF-SHA512, rotación + ventana de reordenación |
| X448 | `x448.rs` | RFC 7748 Curve448: keypair / DH / SPKI; vector dorado contrastado con OpenSSL |
| Agente | `agent.rs`, `agent_envelope.rs`, `agent_link.rs` | `agentMsgEnvelope` oficial (v=7): `"M"`/`"C"`/`"I"`/`"R"`; la carga útil se cifra con PQDR **a nivel de fotograma completo** |
| Enlaces | `agent_link.rs` | forma oficial `simplex:/invitation#/?v=…&smp=…&e2e=…` según el ABNF de `simplexmq` 7.0.1.0 |
| Proxy / onion | `proxy.rs`, `onion.rs` | cadenas de 2 y 3 saltos sobre el proxy SMP |
| Extras | `async_client.rs`, `reconnect.rs`, `store.rs`, `identity.rs`, `sb_chain.rs`, `ffi.rs` | cliente async, reconexión con backoff, almacén con AEAD, fachada FFI (uniffi) |

### Inicio rápido

```bash
# biblioteca
cargo add smp-rs

# binarios (relé, cliente, sondas XFTP/NTF)
cargo install smp-rs --version 0.99.1

# relé local
smp-server --bind 127.0.0.1:5223 --store /tmp/smp-store

# cliente contra un relé (plain) / contra el relé público (TLS + keyHash)
smp-client 127.0.0.1:5223
smp-client --tls smp11.simplex.im "$(base64 -w0 < keyhash.bin)" smp11.simplex.im:5223
```

```toml
# Cargo.toml
[dependencies]
smp-rs = "0.99.1"
```

### Verificación

```bash
cargo test                    # 162 pruebas, 0 fallos
cargo clippy --all-targets    # 0 avisos
cargo audit                   # 0 avisos no permitidos (4 conocidos, en la lista blanca)
cargo publish --dry-run       # OK
```

| Comprobación | Resultado |
|---|---|
| Pruebas unitarias + de integración | **162 correctas / 0 fallidas** |
| clippy (`--all-targets`, ambas configuraciones de features) | **0 avisos** |
| `cargo audit` | 0 avisos nuevos; 4 conocidos (RUSTSEC-2023-0037, -2024-0436, -2025-0141, -2026-0374) en lista blanca |
| KAT de PQDR | contrastado con los vectores SUPERCOP `supercop-20201130` |
| X448 | vector dorado contrastado con OpenSSL (`python cryptography`) — byte a byte |
| FFI | Kotlin → uniffi → JNA → cdylib → Rust: el smoke pasa (`FFI SMOKE: OK`) |
| SBOM | CycloneDX 1.5, 219 componentes |

### Interoperabilidad real (infraestructura pública)

| Objetivo | Resultado |
|---|---|
| `smp11.simplex.im:5223` (SMP v17–v23) | ciclo completo `PING→PONG, NEW→IDS, SUB→SOK, SEND→MSG(descifrado), ACK→OK, DEL→OK` — 7/7 versiones |
| `xftp1.simplex.im:443` (XFTP v4) | `FNEW→SIDS, FPUT 64 KB→OK, FGET→FILE (byte-exacto), FDEL→OK`; 1 MiB por bloques con sha256 coincidente |
| `ntf2.simplex.im:443` (NTF v3, ALPN `ntf/1`) | handshake aceptado, `PING→PONG` con el `NtfClient` de la biblioteca; pinning CA confirmado con un control negativo |
| Proxy SMP | los relés públicos desactivaron el proxy del lado del servidor: intento real → `ERR CMD SYNTAX` (hecho registrado, log: `docs/live/live-interop-2026-11-22.log`) |

### Publicación

`v0.99.1` ya está publicado en crates.io (2026-11-23, checksum `4ea568a9…`) con su GitHub Release.
Una etiqueta `vX.Y.Z` dispara `.github/workflows/release.yml`: contraste de versión con
`Cargo.toml` → pruebas + clippy + `cargo package` → changelog → publicación **exactamente del
commit etiquetado** (`--locked`) en crates.io + release de GitHub. Requiere el secreto
`CARGO_REGISTRY_TOKEN`.

### Límites (lo que honestamente falta)

- **El trinquete X3DH sobre X448 no está implementado**: nuestro flujo de agente usa PQDR, así que
  el cliente oficial de SimpleX no puede descifrar nuestro texto cifrado. Este es el bloqueo
  principal para la interoperabilidad móvil completa.
- `smp-client` no tiene modo agente por CLI (automatización de contact-link + double-ratchet).
- El cliente async no tiene reconexión automática propia (el módulo `reconnect` aporta el backoff).
- Los comandos NTF firmados (`SNEW`/`TNEW` con autorización Ed25519) no están implementados.
- La auditoría externa (G7) no está firmada: la carta está lista en `docs/AUDITOR-LETTER.md`.

### Documentación

`docs/RELEASE-READINESS.md` (auditoría de preparación) · `docs/AUDITOR-LETTER.md` ·
`docs/SECURITY.md` · `docs/ROADMAP.md` · `docs/RELEASE-NOTES-v0.99.1.md` · `docs/live/` (registros reales)

---

## Лицензия / License / Licencia

MIT — см. `LICENSE`.
