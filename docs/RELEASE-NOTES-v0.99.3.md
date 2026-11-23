# smp-rs v0.99.3 — security: X448 без уязвимого crypto-bigint

## Что изменилось

### Security (RUSTSEC-2026-0387)

Зависимость `cx448` 0.1.1 жёстко тянет `crypto-bigint ^0.5.5`, который затронут
RUSTSEC-2026-0387: в ряде операций, задуманных как constant-time, выполнялись
ветвления, зависящие от секрета (вычитание, подсчёт нулей, деление, умножение
Монтгомери; `UintRef`-равенство завершалось на первом несовпавшем лимбе; ветвление
в `BoxedMontyForm::invert`). Фикс — в `crypto-bigint >= 0.7.6`, а `cx448` с таким
релизом не существует.

Замена: RustCrypto `x448` (`=0.14.0-pre.12`, feature `static_secrets`) — в его дереве
`crypto-bigint 0.7.11` (пропатченная). Модуль `src/x448.rs` переписан на новый API;
публичный API модуля не изменился.

**Проверка:** золотой вектор, сверенный с OpenSSL (`python cryptography`), совпадает
байт-в-байт; тест round-trip двух ключей — зелёный; отклонение low-order точки — зелёное.

### Починен CI-пайплайн

7 из 11 job'ов падали. Исправлено:
- `ci.yml`: `--features` стоял после `--`, поэтому cargo передавал его тест-бинарнику
  («Unrecognized option: features»);
- `ci.yml`: strict-job передавал `--test` трижды («Option 'test' given more than once»);
- `ci.yml`: fuzz-job использовал `--offline` без вендоренного реестра;
- `ci.yml`: audit-job не имел прав, нужных `rustsec/audit-check`;
- `release.yml`: `cargo test/clippy --offline` на свежем раннере (нет vendor-каталога);
- `scripts/ffi_smoke.sh`: неинициализированный `CARGO_TARGET_DIR` при `set -u`;
- `Cargo.toml`: убран лишний `homepage` и неиспользуемая зависимость `futures`.

### Прочее

- Добавлен `audit.toml` — allowlist из 4 известных advisory «unmaintained» (фиксов нет,
  это не memory-safety и не криптографические проблемы); любые новые advisory по-прежнему
  роняют job.
- `cargo audit`: 0 уязвимостей, 4 разрешённых предупреждения.
- Тесты: 162 (default) / 164 (`v71-probes`), clippy — чисто.
