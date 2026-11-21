#!/bin/bash
# CI assert: no unwrap/expect in library code paths (goal G5).
#
# Test modules (#[cfg(test)]) are allowed to unwrap — a failing assertion there
# is the intended way to signal a broken test. Everything before the first
# #[cfg(test)] marker in a library source file is production code and must not
# panic on unexpected input.
set -u
cd "$(dirname "$0")/.."
fail=0
for f in src/*.rs; do
  ct=$(grep -n '#\[cfg(test)\]' "$f" | head -1 | cut -d: -f1)
  [ -z "$ct" ] && ct=$(wc -l < "$f")
  n=$(sed -n "1,${ct}p" "$f" | grep -cE '\.unwrap\(\)|\.expect\(')
  if [ "$n" != "0" ]; then
    echo "$f: $n unwrap/expect in library code"
    sed -n "1,${ct}p" "$f" | grep -nE '\.unwrap\(\)|\.expect\(' | sed 's/^/    /'
    fail=1
  fi
done
if [ "$fail" != "0" ]; then
  echo "FAIL: library code must not unwrap/expect"
  exit 1
fi
echo "OK: no unwrap/expect in library code"
