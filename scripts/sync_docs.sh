#!/usr/bin/env bash
# sync_docs.sh — синхронизирует число тестов и версию в README.md / docs/SECURITY.md
# из реального прогона `cargo test` и Cargo.toml (ADR D6(a)).
# Режимы:  CHECK=1 — только проверить, что доки в синке (для CI, exit 1 при рассинхроне);
#          иначе — обновить файлы на месте.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(awk '/^version/{gsub(/"/,""); print $3; exit}' Cargo.toml)
TESTS=$(cargo test --locked 2>/dev/null | grep -E '^test result:' | awk -F'[ ;]' '{p+=$4} END {print p+0}')
FAILED=$(cargo test --locked 2>/dev/null | grep -E '^test result:' | awk -F'[ ;]' '{f+=$6} END {print f+0}')
echo "version=$VERSION tests=$TESTS failed=$FAILED"
[ "$FAILED" = "0" ] || { echo "tests failing — refusing to sync docs"; exit 1; }

sync_file() {
    local f=$1
    [ -f "$f" ] || return 0
    sed -i -E \
        -e "s/tests-[0-9]+%20passed/tests-${TESTS}%20passed/g" \
        -e "s/\*\*[0-9]+ passed \/ 0 failed\*\*/**${TESTS} passed \/ 0 failed**/g" \
        -e "s/# [0-9]+ (теста|tests), 0 (падений|failures)/# ${TESTS} \1, 0 \2/g" \
        "$f"
}
sync_file README.md
sync_file docs/SECURITY.md

if [ "${CHECK:-0}" = "1" ]; then
    if ! git diff --quiet -- README.md docs/SECURITY.md; then
        echo "DOCS OUT OF SYNC — run scripts/sync_docs.sh and commit"; exit 1
    fi
    echo "docs in sync ($TESTS tests, v$VERSION)"
else
    echo "docs updated to $TESTS tests, v$VERSION"
fi
