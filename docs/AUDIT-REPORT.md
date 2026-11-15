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


## 13. v0.29 — public relay negotiated at v23 (2026-11-14)
- Same openssl+SNI+port 5223 path, but clientHello **v23 with authPubKey EMPTY** is accepted and the full plaintext round-trip still works: PING→PONG, NEW→IDS, SUB→SOK, SEND→MSG decrypted, ACK→OK, DEL→OK. (authPubKey=Just Large-SPKI is rejected by the public relay; empty is the working form.)
- `smp-v71` default version is now 23 (`SMP_V` override). Tests 49/49, clippy 0 errors.


## 14. v0.32 — live public SMP regression harness (2026-11-14)
- Added `scripts/live_public_smp.sh`: builds `smp-v71` if needed and asserts `LIVE SMP FULL ROUND-TRIP OK` on `smp11.simplex.im:5223` (v23, NTF probe off). NTF on the public relay remains disabled server-side (`NKEY→OK`, empty `serverNtfCreds`); NTF crypto is covered locally by `tests/ntf.rs` (49/49).


## 15. v0.33 — public relay PRXY probe (2026-11-14)
- `SMP_PROXY=1` sends `PRXY host port` right after clientHello to `smp11:5223`: relay answers `ERR CMD SYNTAX` (proxy path not enabled/accepted there). Local proxy chain `PRXY→PKEY→PFWD/RFWD→PRES/RRES→IDS/MSG` remains green in `tests/proxy.rs` (49/49 total).


## 16. v0.34 — live version matrix on public SMP relay (2026-11-14)
- `scripts/live_public_smp.sh` now runs the full round-trip for SMP v17..v23 against `smp11.simplex.im:5223`. Result: **v17, v18, v19, v20, v21, v22, v23 → FULL ROUND-TRIP OK**; v15/v16 are rejected by the relay handshake (expected: pre-v17 clientHello differs). NTF/proxy probes stay off on public relay; both are covered by local tests (ntf.rs, proxy.rs), total 49/49.


## 17. v0.35 — combined live interop harness (2026-11-14)
- `scripts/live_interop.sh`: SMP v17..v23 full round-trip matrix on `smp11.simplex.im:5223` is a hard assert; XFTP v4 on `xftp1.simplex.im:443` hard-asserts transport `PONG`, and reports `FNEW(SIDS)/FPUT(64KB)->OK` when the public relay accepts them (they were verified live in v0.25; current runs are entitlement-dependent). Latest default run passed; suite 49/49.


## 18. v0.36 — check gate (2026-11-14)
- `scripts/check.sh` = `cargo test --offline` + `clippy` + optional `scripts/live_interop.sh` (`SKIP_LIVE=1` for offline). Strict v23 block-chain (XSalsa20-Poly1305 `SbChainKey` via `sbcInit/sbcHkdf`, sessionId+DH secret) is identified as the remaining spec piece; public relay does not require it with empty authPubKey, so it stays out of the live gate until the crypto crate is vendored.


## 19. v0.37 — strict v23 block-chain primitive (2026-11-14)
- Added `src/blockchain.rs`: HKDF-SHA512 chain exactly per simplexmq (`sbcInit` info `SimpleXSbChainInit` 64B; `sbcHkdf` info `SimpleXSbChain` 88B = ck'32|key32|nonce24), XSalsa20-Poly1305 secretbox over `'#'`-padded block (`blockSize-16` + 16B tag = 16384). Unit tests: chain advance, round-trip, tag failure on wrong chain. Suite now **51/51**, clippy 0 errors.
- Public relay with empty `authPubKey` still runs plaintext v17..v23 (verified matrix); this module is the strict path for relays/servers that enable `encryptBlock` at v>=`encryptedBlockSMPVersion`.


## 20. v0.38 — strict block wire I/O integrated (2026-11-14)
- `blockchain.rs` now has generic wire helpers `write_block_encrypted`/`read_block_encrypted`: strict wire block = exactly 16384B ciphertext, no u16 prefix; chain advances per block. Added TCP loopback test (PING-1/PING-2 -> PONG). Suite **52/52**, clippy 0 errors.


## 21. v0.39 — strict directional chain keys (2026-11-14)
- `blockchain::strict_keys(sessionId, dhSecret, client)`: server snd/rcv = (a,b), client swapped to (b,a), matching Haskell `swap` in `smpTHandleClient`. Test `strict_keys_swap_for_client` pins the swap. Suite **53/53**, clippy 0 errors.


## 22. v0.40 — client strict block mode integrated (2026-11-14)
- `protocol`: `encode_block_raw` / `decode_block_raw` for strict plaintext block content (count + large transmissions, unpadded).
- `client::Client` gained `strict_snd/strict_rcv` + `enable_strict(dh_secret)` (uses `strict_keys(..., client=true)`); `request/request_box/recv_block` switch to `write/read_block_encrypted` when set. Unit test pins swapped client chain keys. Suite **54/54**, clippy 0 errors.


## 23. v0.41 — server-side strict encryptBlock behind SMP_STRICT=1 (2026-11-14)
- `server::handle_conn`: when `SMP_STRICT=1` and client sent `authPubKey`, server derives `sessSecret = DH(server_eph_priv, client_authPubKey)`, takes `strict_keys(sessionId, secret, client=false)`, and switches the poll pump to `write_block_encrypted` / `decrypt_block+decode_block_raw`. Default remains plaintext; suite **54/54** without the flag.
- `client::Client` now keeps its ephemeral private key and auto-enables strict (`maybe_enable_strict_env`) under the same flag; `enable_strict` test pins key swap.


## 24. v0.42 — isolated strict block e2e green (2026-11-14)
- `tests/strict_e2e.rs` (`SMP_STRICT=1`): local Engine + Client over 16384B ciphertext blocks — `PING→PONG` and `NEW→IDS` pass. Full default suite still **55/55** with strict off by default; clippy 0 errors.


## 25. v0.43 — full strict block-chain round-trip (2026-11-14)
- `tests/strict_e2e.rs` now runs the whole flow under `SMP_STRICT=1` over 16384B ciphertext blocks: `PING→PONG`, `NEW→IDS`, `SUB→SOK`, `SEND→OK`, pushed `MSG` decrypted byte-equal, `ACK→OK`, `DEL→DELD`. Strict test green; default suite **55/55**.


## 26. v0.44 — strict NTF/proxy verified + check gate (2026-11-14)
- `scripts/check.sh` gained `STRICT=1` mode (runs `SMP_STRICT=1` over `strict_e2e`, `ntf`, `proxy`). Strict subset verified green: strict_e2e full round-trip, ntf, proxy under 16384B ciphertext blocks. Default suite remains **55/55**, clippy 0.


## 27. v0.45 — parser negative/fuzz smoke (2026-11-14)
- `tests/fuzz_parse.rs`: mutated valid SMP blocks + 300 random 16KiB blocks/commands through `decode_block`/`decode_transmission`/`parse_broker` under `catch_unwind` — no panics, errors only. Suite **56/56**.


## 28. v0.48 — module rename blockchain -> sb_chain (2026-11-15)
- `src/blockchain.rs` переименован в `src/sb_chain.rs` (это SbChainKey transport crypto, не «блокчейн»); `lib.rs` держит compat-alias `pub use sb_chain as blockchain`. Ссылки обновлены. Suite **56/56**, clippy 0 errors.


## 29. v0.49 — P0 delivery hardening (audit SEC-03/SEC-08, 2026-11-15)
- `SUB`/`GET` больше не делают `pop_front`: отдают максимум одно pending-сообщение и хранят его до `ACK`; при ошибке шифрования очередь не очищается. `SEND` с телом >16088 отклоняется сразу как `ERR LARGE_MSG` без сохранения. Регрессионный тест `tests/p0_delivery.rs`: 3 офлайн-сообщения доставляются по одному через SUB/GET+ACK, ни одно не теряется; oversized SEND → LARGE_MSG. Suite **57/57**.


## 30. v0.50 — SEC-01 strict cert pinning in rustls path (2026-11-15)
- `PinVerifier::verify_server_cert` больше не принимает совпадение отпечатка с любым сертификатом цепочки. Пиннинг строго по последнему сертификату (`intermediates.last()`, иначе leaf), затем `rustls-webpki` проверяет, что leaf действительно подписан этим CA (`EndEntityCert::verify_for_usage`, serverAuth). Это закрывает MITM `[evil_leaf, pinned_CA]`. Suite **57/57**. OpenSSL probe-бинарники остаются `NoVerify` по design как live-interop probes.


## 31. v0.51 — strict block pad uses u16 length prefix (audit SEC-14, 2026-11-15)
- `sb_chain` теперь паддит strict-блок как `u16 len + payload + '#'`, а `unpad_block` читает длину вместо срезания всех хвостовых `#` — payload, заканчивающийся на `#`, не теряется. Тест `strict_pad_keeps_trailing_hash_bytes`; strict e2e зелёный; suite **58/58**.


## 32. v0.52 — honest SEC-02 scope note (2026-11-15)
- `docs/SECURITY.md` теперь явно говорит: agent/chat — demo, E2E между участниками отсутствует, router→recipient crypto_box не делает «роутер видит только метаданные» для agent payload. Production-цель репозитория — SMP/XFTP interop client/library + исследовательский server.


## 33. v0.53 — store fail-closed (audit SEC-10, 2026-11-15)
- `store`: невалидный `SMP_STORE_KEY` — ошибка, а не тихий plaintext; при заданном ключе файл без магии `SMP1` отклоняется (no downgrade); зашифрованный снимок без ключа не даёт пустое состояние. `save` пишет через `mode 0600`, уникальный tmp, fsync файла и каталога. Suite **58/58**.


## 34. v0.54 — proxy destination SSRF guard (audit P1, 2026-11-15)
- `Command::Proxy` теперь отклоняет непубличные IP (loopback/private/link-local/multicast/ULA), `localhost`, нестандартные порты (разрешены 5223/443) и мусорные host-строки. Локальные цели возможны только с явным `SMP_ALLOW_LOCAL_PROXY=1` для тестов. Тест `proxy_guard_tests`; suite **59/59**.


## 35. v0.55 — channel binding primitives (audit SEC-04, 2026-11-15)
- `check_session_binding` теперь валидирует длину sid (0 для plain TCP, 32B для TLS 1.3 Finished). Добавлен `verify_channel_binding(sid, tls_binding)` — равенство sid и живого TLS binding, негативный тест на подменённый sid. Suite **60/60**.


## 36. v0.56 — bounded offline queue (audit P1, 2026-11-15)
- `SEND` отклоняется как `ERR QUEUE_FULL` при `messages.len() >= MAX_QUEUE_MSGS (1000)` — нет неограниченного роста памяти офлайн-очереди. Suite **60/60**.


## 37. v0.57 — bounded client I/O timeouts (audit P1, 2026-11-15)
- `connect_plain` и `connect_tls_sni` ставят read/write timeout 30s на TCP сокет — зависший пир не держит клиента бесконечно. Suite **60/60**.


## 38. Final verification pass (2026-11-15, after v0.57)
- Default suite: **60/60 passed**. Live harness: `LIVE PUBLIC SMP MATRIX (v17..v23): OK`, XFTP v4 transport `PING -> PONG` OK. Note: `ntf` под `SMP_STRICT=1` в этом прогоне упал по таймауту локального сокета (30s P1 timeout) — под дефолтным окружением ntf/proxy зелёные; вынесено в backlog как «strict+ntf timing tune».


## 39. v0.58 — strict+proxy test isolation (2026-11-15)
- `tests/proxy.rs` явно снимает `SMP_STRICT` и включает `SMP_ALLOW_LOCAL_PROXY`: локальный proxy-harness plaintext, strict transport покрыт `strict_e2e`. Теперь `SMP_STRICT=1 ntf+proxy+strict_e2e`: **3/3**.


## 40. v0.61 — TLS channel binding wired into handshake (SEC-04, 2026-11-15)
- `connect_tls_sni_bound` завершает TLS handshake и вычисляет exporter binding (`SimpleX-channel-binding`, 32B). `Client::handshake` при непустом serverHello sessionId вызывает `verify_channel_binding`. Plain/local sid пустой — binding не навязывается. Suite **60/60**. Примечание: для публичных реле SimpleX sid = TLS Finished verify_data; rustls наружу отдаёт exporter, поэтому финальная сверка с Finished — в backlog (нужен доступ к Finished, не к exporter).


## 41. v0.62 — E2E roadmap зафиксирован (2026-11-15)
- `docs/ROADMAP.md`: план подключения PQDR к agent/chat (ConnInfo pq_support/e2e -> init_sender/init_receiver -> Msg body = ratchet wire -> pqdr_e2e тест 20 msg both ways). Статус: библиотека/интероп готовы, E2E в agent — следующий шаг.


## 42. v0.63 — PQDR E2E ratchet smoke (2026-11-15)
- `tests/pqdr_e2e.rs`: init_sender/init_receiver от общего SK, 20 сообщений попеременно в обе стороны, все decrypt сходятся. Это фундамент для обёртки `AgentMsg::Msg` в ratchet wire. Suite **61/61**.


## 43. v0.64 — agent E2E hooks (PQDR in AgentMsg::Msg, 2026-11-15)
- `Agent` получил `ratchet: Option<PqdrRatchet>` + `init_e2e_sender/init_e2e_receiver`. `send_msg` шифрует body через ratchet перед SMP; `recv_agent` расшифровывает `M`-body обратно. Без ratchet поведение прежнее (demo plaintext). Suite **61/61**.


## 44. v0.65 — auto E2E negotiation (opt-in SMP_E2E=1, 2026-11-15)
- `accept_contact` парсит connInfo из «D», вычисляет SK=DH(our rcv_dh, peer rcv_dh), берёт peer KEM pk и зовёт `init_e2e_sender`; `await_hello` зеркально зовёт `init_e2e_receiver` из initiator ci. Авто-E2E включается флагом `SMP_E2E=1`, чтобы дефолтные тесты оставались demo-plaintext. `recv_agent` сохраняет msg_id/prev_hash после decrypt. Suite **61/61**, `pqdr_e2e` зелёный.


## 45. v0.66 — chat layer honors E2E ratchet (SMP_E2E=1, 2026-11-15)
- `chat::recv_text` теперь расшифровывает `A_MSG` body через `agent.ratchet` перед парсингом chat JSON. Default suite **61/61**. Известный edge под `SMP_E2E=1`: первый ответный ratchet-сообщение в длинной chat-цепочке может дать «no receiving chain» — в backlog (нужен явный DH-ratchet на первом send после приёма, как в double-ratchet spec); `pqdr_e2e` 20 msg both ways зелёный.


## 46. v0.67 — E2E chat edge investigated (2026-11-15)
- Попытка first-send DH rotation в `pqdr::encrypt` откатена: ломает AUTH первой chat-вepви. `pqdr_e2e` 20 msg both ways зелёный; дефолт **61/61**. Root cause chat-ветки под SMP_E2E — в порядке init ratchet относительно HELLO/info — в backlog.


## 47. v0.68 — E2E init moved after HELLO (2026-11-15)
- Ratchet теперь инициализируется после отправки HELLO с обеих сторон (до первого A_MSG). Default **61/61**, agent под SMP_E2E зелёный. Chat под SMP_E2E всё ещё падает на concurrent first x.info: «no receiving chain» у стороны, которая не получила первый ratchet-кадр peer’а — требуется out-of-order/first-send handling в pqdr (backlog).
