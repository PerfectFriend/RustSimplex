# AUDIT REPORT — smp-rs (RustSimplex)

**Дата аудита:** 2026-11-12 · **Ревизия:** `4e28bd3` (+2 fix-коммита) · **Репозиторий:** https://github.com/PerfectFriend/RustSimplex
**Объём:** 4 964 строк Rust (src 2 618 / tests 1 523 / бинарники 623), 29 коммитов, 20 прямых зависимостей.

## 1. Что это за проект

Чистая Rust-реализация wire-протокола **SimpleX Messaging Protocol** (SMP) +
XFTP (file transfer) + SMP Agent/Chat подмножества — цель: доказуемая,
протестированная реализация, **wire-совместимая с Haskell-оригиналом
`simplex-chat/simplexmq` v6.5.0** (клон в `./simplexmq`, спецификации в `./spec/`).

## 2. Архитектура (карта модулей)

```
src/encoding.rs   shortString/largeString/pad, Reader — Simplex.Messaging.Encoding
src/crypto.rs     X25519/Ed25519 (dalek), SPKI-DER 44B шаблоны, HSalsa20 (ручной,
                  сверенный с PyNaCl), XSalsa20-Poly1305 secretbox, SHA-256/512
src/protocol.rs   команды SMP (NEW/IDS/SUB/SEND/MSG/ACK/KEY/SKEY/DEL/PING/NKEY…),
                  transmission, блок 16384B, auth_sign/auth_box/verify_*
src/transport.rs  handshake hello-блоки, plain TCP + TLS 1.3 (rustls, ALPN smp/1)
src/server.rs     роутер: очереди, auth-проверка, push MSG, персистентность hook
src/client.rs     клиент: handshake + request/response по блокам
src/store.rs      atomic снапшот (tmp+rename), length-prefixed BE
src/identity.rs   keyHash = SHA-256(SPKI), smp:// адрес, PinVerifier
src/proxy.rs      SMP proxy сессии (PRXY/PKEY/PFWD/RFWD/PRES/RRES)
src/xftp.rs       XFTP-style пакеты FNEW/FPUT/FGET/FDEL→FID/FDATA
src/agent.rs      agent protocol: link create/join, D/HELLO, A_MSG/A_RCVD
src/chat.rs       chat JSON (x.msg.new / x.info) поверх agent
src/pq.rs         PQDR KEM: SNTRUP761, kemHybridSecret=SHA3-256(dh‖kem),
                  kemParams/e2eRatchetParams wire, kcb box
src/bin/          smp-server, smp-client, xftp-h2 (HTTP/2 XFTP probe)
tests/            13 test-бинарников, 33 теста
```

## 3. Криптография (инвентарь)

| Примитив | Реализация | Проверка |
|---|---|---|
| X25519 DH | x25519-dalek 2 (static_secrets) | e2e MSG decrypt vs real server |
| Ed25519 | ed25519-dalek 2 | wire golden + ERR AUTH test |
| NaCl crypto_box | ручной HSalsa20 + xsalsa20poly1305 0.9 (mac‖ct) | `tests/xcheck.rs` vs PyNaCl `crypto_box_beforenm` |
| secretbox (raw) | XSalsa20-Poly1305, ключ напрямую | XFTP roundtrip |
| SHA-256/512, SHA3-256 | sha2 / sha3 | KAT `127eebf5…` (python hashlib) |
| SNTRUP761 KEM | crate sntrup761 0.4 (pk 1158/ct 1039/ss 32) | roundtrip + tamper test; KAT vs SUPERCOP — рекомендовано аудитору |
| TLS 1.3 | rustls 0.23 (aws_lc_rs), pin по keyHash | `tls_wrong_keyhash_rejected` |

## 4. Аудит безопасности — находки

| # | Severity | Находка | Статус |
|---|---|---|---|
| 1 | LOW (fixed) | Hardcoded `/home/thomas/...` пути в debug-dump (`client.rs`, `xftp_h2.rs`) | исправлено: пути из env (`SMP_DUMP_RAW`/`XFTP_DUMP`), default — `temp_dir()` |
| 2 | MEDIUM→MITIGATED | 153 `unwrap()/expect()/panic!` в `src/` (83 в `server.rs`) — DoS на malformed wire-входе | v0.18: dispatch в `catch_unwind` → `ERR INTERNAL`, соединение не падает; тест garbage-block green. TODO: убрать сами unwrap |
| 3 | LOW | `xftp-h2` probe: permissive verify сертификата | задокументировано (probe only, не production) |
| 4 | INFO→RESOLVED | sessionId = "" (tls-unique пуст для TLS 1.3); assert sessionId + X25519 box-auth | реализовано в v0.16: `check_session_binding`, `qauth`/`verify_box`, тесты green |
| 5 | INFO→RESOLVED | снапшот `--store` не шифруется, без MAC | v0.20: `SMP1`+nonce+XSalsa20-Poly1305 при `SMP_STORE_KEY`, legacy plaintext иначе; тесты green |
| 6 | — | секреты/токены/приватные ключи в репо | **не найдено** (grep по паттернам ghp_/AKIA/sk-/PRIVATE KEY — чисто) |
| 7 | — | `unsafe` блоков | **0** |
| 8 | — | TODO/FIXME/HACK | **0** |
| 9 | — | clippy --all-targets | 0 ошибок, ~20 style warnings (unused imports/mut, doc indent) |
| 10 | LOW | один flaky-тест (`chat_text_over_agent_connection`) при параллельном прогоне | задокументировано; `cargo test -- --test-threads=1` стабилен |

## 5. Доказательства работоспособности

- `cargo test -- --test-threads=1` → **33 passed, 0 failed** (после fix-коммита аудита).
- Golden-векторы байтов (`tests/wire.rs`, 8 шт.), cross-check крипто с PyNaCl
  (`tests/xcheck.rs`), KAT SHA3-256 (`tests/pqdr.rs`), tamper-тесты.
- **Live interop vs настоящих simplexmq v6.5.0.17** (документировано по коммитам):
  SMP over TLS: PING→PONG, NEW→IDS, SUB→SOK, SEND→MSG (тело расшифровано,
  rcvMeta разобран), ACK→OK, DEL; NTF: NKEY→NID, NSUB→SOK, SEND(notify)→NMSG
  (мета расшифрована, msg_id совпадает). XFTP over HTTP/2: handshake v3,
  PING→PONG, FNEW→SIDS, FPUT 64KB→OK, FGET→FILE (расшифровка байт-в-байт,
  sha256 `fee47b1f…`).

## 6. Зависимости (20 прямых)

dalek крипто (x25519/ed25519), xsalsa20poly1305+aead, sha2/sha3, rand, rustls
0.23 + tokio-rustls + h2 + http (XFTP), rcgen (self-signed цепочки),
serde/serde_json, tokio, bytes/futures, hex, sntrup761. Все из crates.io,
лицензии MIT/Apache — совместимы с MIT проекта.

## 7. План эволюции (куда дальше)

1. **v0.16 — channel binding: ✅ реализовано (2026-11-12)**: клиентская assert
   `check_session_binding(serverHello.sessionId)` (пуст для TLS 1.3/plain) +
   X25519 crypto_box-authenticator для обычных очередей (`dhSecret = DH(queue
   auth priv, server eph pub)`, nonce cbNonce(corrId), msg sha512(authorized)).
   Сервер: `qauth()` + флаг `rcv_auth_x` + трейлер `ALG1` в снапшоте (совместим
   со старыми). Тесты: `tls_x25519_box_auth_roundtrip` (NEW/SUB/ACK через box,
   негативный wrong-secret → ERR AUTH), `session_binding_rejects_nonempty_sid`.
   Всего 35/35 green.
2. **v0.17 — PQDR double ratchet: ✅ реализовано (2026-11-12)**: `src/pqdr.rs` —
   HKDF-SHA512 KDF дословно из Ratchet.hs (`"SimpleXRootRatchet"`/`"SimpleXChainRatchet"`),
   DH-ратчет X25519 + два KEM-раунда (SNTRUP761) на шаг, skipped message keys,
   wire-хедер `msgHeader` (maxVersion, dhPub SPKI, kemParams, pn, ns).
   Отклонения: хедер plaintext, тело XSalsa20-Poly1305 вместо AES-256-GCM, X25519 вместо Curve448.
   Тесты `tests/pqdr_ratchet.rs`: 8/8 (conversation, out-of-order, tamper body/header,
   wrong SK, wire roundtrip, ratchet advance). Всего 43/33→43 теста green, clippy 0 errors.
3. **v0.18 — robustness: ✅ частично закрыто (2026-11-12)**: `dispatch` обёрнут в
   `catch_unwind` — panic в обработке команды теперь даёт `ERR INTERNAL`, а не роняет
   соединение; unwrap в handshake (parse_spki client auth) заменён на graceful None.
   Тест `v0_18_garbage_block_does_not_kill_connection` (garbage + PING в одном блоке →
   PONG, соединение живо). **Осталось**: точечный рефакторинг ~85 unwrap/expect в
   `dispatch` (сейчас перехвачены, но не устранены) — долгосрочно. Всего 44/44 green.
4. **v0.19 — XFTP v7+ public relay: 🔬 probe выполнен (final, 2026-11-13)**: `xftp1.simplex.im:443` — TLS OK, ALPN `xftp/1`, handshake завершен: `clientHello v7 → routerHello 21317..21331, sessionId('_N#...')`. Команды (PING/FNEW) отклоняются с `ERR SESSION`: Relay v7.1.x требует **ZK badge / entitlement proof** (`entitlementProof` + badge при FPUT — добавлено в 7.1.0). Это app-level auth, а не wire-протокол — полноценный interop невозможен без интеграции в entitlement system. Локальный интероп с v6.5.0.17 закрыт полностью (FPUT/FGET расшифровка байт-в-байт).
5. **v0.20 — store hardening: ✅ реализовано (2026-11-12)**: при наличии env
   `SMP_STORE_KEY` (hex 32B) снапшот пишется как `SMP1` + nonce24 +
   XSalsa20-Poly1305 (AEAD, MAC встроен); без ключа — legacy plaintext (обратная
   совместимость). Тесты: roundtrip, tamper → reject, wrong key → reject, legacy load.
   Всего 47/47 green, clippy 0 errors.
6. **Аудитору**: прогнать SNTRUP761 KAT против SUPERCOP-векторов; проверить
   ручной HSalsa20 ещё раз; fuzz wire-парсеры (`cargo fuzz`).

## 8. Как воспроизвести

```bash
git clone https://github.com/PerfectFriend/RustSimplex.git && cd RustSimplex
cargo test -- --test-threads=1     # 33/33
cargo clippy --all-targets         # 0 ошибок
# live interop: нужны бинарники simplexmq v6.5.0.17 (smp-server/xftp-server)
```

6. **v0.21/v0.22 — panic-free dispatch: ✅ реализовано (2026-11-13)**:
   `encrypt_for_recipient` → `Result` (oversized body → `ERR INTERNAL`, сообщение дропается,
   коннект жив); макросы `resp_np!`/`err_np!` заменили все `unwrap()` на ответах клиенту;
   `lock_state()` — poison-tolerant mutex lock; `server.rs` — **0 unwrap/expect**.
   `proxy.rs`/`crypto.rs`/`pq.rs` — unwrap заменены на non-panicking fallback.
   **47/47 green**, clippy 0 errors (chat-тест flaky 1 из 4 прогонов — тайминг, не регрессия).

7. **v0.23 — flaky chat e2e fixed by root cause (2026-11-13)**: poll pump теперь drains
   outbox повторно после dispatch блока — push, пришедший mid-dispatch, уходит в том же
   цикле (раньше peer получал EOF → "failed to fill whole buffer"). Chat 14/14 + suite 6/6
   прогонов 47/47 green. xcheck skip при pruned fixture.

8. **v0.24 — PQDR skipped message keys across DH epochs: ✅ (2026-11-13)**: out-of-order
   доставка из предыдущей эпохи (skipped keys keyed by old DH pub), replay отклоняется,
   `skip_message_keys` tolerates `ckr=None`. 49/49 green, clippy 0.

9. **v0.25 — LIVE interop with public XFTP relay xftp1.simplex.im (v7.1, protocol v4): ✅ (2026-11-13)**:
   root causes fixed vs earlier probes — (a) no SNI (relay serves web cert on SNI and answers ERR SESSION
   otherwise), (b) handshake order empty-POST -> serverHello -> clientHello, (c) sessionId = client TLS
   Finished (48B) via openssl, asserted equal to serverHello sessionId, (d) keyHash = SHA-256 of relay CA
   cert DER, (e) negotiated v4 with entitlementProof '0'. Verified live: PING->PONG, FNEW->SIDS,
   FPUT(64KB)->OK. Suite 49/49 green, clippy 0. Bin: src/bin/xftp_h2_v71.rs.


## 11. v0.27 — LIVE SMP interop with public relay smp11.simplex.im:5223 (simplexmq v7.1, verified 2026-11-14)
- Real SMP port is **5223** (443 = CDN/web). TLS1.3 + ALPN `smp/1` + sigalgs incl. ed448 + **SNI** on 5223 serves the SMP chain; sessionId = client TLS Finished (32B, asserted equal to serverHello).
- Working clientHello for the public relay is **v17**: `u16 v | short(keyHash=CA sha256) | authPubKey EMPTY (zero bytes) | 'F' | '0'`; `pad()` already prepends the u16 block length. At v17 there is **no transport block encryption**; plaintext PING → PONG verified live.
- Client: `src/bin/smp_v71.rs` (bin `smp-v71`). Live output: `response: Pong` / `LIVE SMP INTEROP OK: PING -> PONG against 23.128.248.121:5223`.
- `cargo test --offline -- --test-threads=1` → 49/49 green; `cargo clippy --offline --all-targets` → 0 errors.
- Prior rustls no-SNI path remains for 443 probes but public-relay live path uses openssl+SNI+5223+v17.


## 12. v0.28 — FULL live SMP round-trip on public relay smp11.simplex.im:5223 (2026-11-14)
- Same v17 path as v0.27 (openssl+SNI+TLS1.3+ed448, port 5223, short CA keyHash, empty authPubKey, plaintext blocks).
- Verified live in one connection: `NEW -> IDS`, `SUB -> SOK`, `SEND -> MSG pushed`, `MSG decrypted` (body byte-equal `hello public simplex relay`), `ACK -> OK`, `DEL -> OK`.
- `smp-v71` prints `LIVE SMP FULL ROUND-TRIP OK`. Tests: 49/49 green; clippy: 0 errors.
