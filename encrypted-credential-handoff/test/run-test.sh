#!/bin/bash
# Known-answer interop test for the encrypted credential handoff.
#
# Verifies, against the reference implementation (../consume.py and
# ../handoff.sh):
#   1. decrypt direction: blob.txt decrypts to expected.json's values,
#      and --check output matches expected-check.txt exactly;
#   2. the child's stdin passes through consume.py untouched (a stdio
#      child's stdin is its transport; the blob must not consume it);
#   3. encrypt direction: a fresh blob produced by ../handoff.sh (with
#      the dummy public key embedded in a scratch copy) decrypts
#      through ../consume.py to the same values;
#   4. the refusals the docs claim: purpose mismatch, a payload with no
#      known credential field, --check combined with a command.
#
# A port or variant implementation passes the interop bar by reproducing
# steps 1-2 against these vectors with its own decrypt side, and step 3
# with its own encrypt side feeding the reference decrypt side.
set -euo pipefail
cd "$(dirname "$0")"

# consume.py refuses group/other-readable keys on principle; the repo copy
# of the dummy key is world-readable by design (it's a published vector),
# so work on a locked-down temp copy. Both temp paths exist BEFORE the
# trap is set: a trap that expands an unassigned variable under `set -u`
# aborts itself and leaves the key copy behind.
TMPKEY=$(mktemp)
TMPHAND=$(mktemp)
trap 'rm -f "$TMPKEY" "$TMPHAND"' EXIT
cp test-dummy-priv.pem "$TMPKEY"
chmod 600 "$TMPKEY"
export HANDOFF_PRIVKEY="$TMPKEY"

expect_fail() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: $desc — expected refusal, got success" >&2
    exit 1
  fi
  echo "ok (refused: $desc)"
}

echo "== 1a. reference decrypt, --check output =="
../consume.py --label example --check --blob-file blob.txt | diff - expected-check.txt
echo "ok"

echo "== 1b. reference decrypt, injected environment =="
out=$(../consume.py --label example --blob-file blob.txt -- python3 -c '
import os
print(os.environ["SERVICE_USERNAME"])
print(os.environ["SERVICE_PASSWORD"])
')
[ "$out" = "test
test" ] || { echo "FAIL: unexpected env values" >&2; exit 1; }
echo "ok"

echo "== 1c. per-invocation --env mapping =="
out=$(../consume.py --label example --blob-file blob.txt --env username=CUSTOM_USER -- python3 -c '
import os
print(os.environ["CUSTOM_USER"])
')
[ "$out" = "test" ] || { echo "FAIL: --env mapping not applied" >&2; exit 1; }
echo "ok"

echo "== 2. child stdin passes through untouched =="
out=$(printf 'hello-stdin' | ../consume.py --label example --blob-file blob.txt -- python3 -c '
import os, sys
print(os.environ["SERVICE_USERNAME"])
print(sys.stdin.read())
')
[ "$out" = "test
hello-stdin" ] || { echo "FAIL: child stdin was consumed or altered" >&2; exit 1; }
echo "ok"

echo "== 3. reference encrypt (handoff.sh) -> reference decrypt =="
python3 - "$TMPHAND" <<'PYEOF'
import re, sys
src = open("../handoff.sh").read()
pub = open("test-dummy-pub.pem").read().strip()
block = re.search(r"read -r -d '' PUBKEY <<'EOF' \|\| true\n(.*?)EOF", src, re.S).group(1)
open(sys.argv[1], "w").write(src.replace(block, pub + "\n"))
PYEOF
chmod +x "$TMPHAND"
blob2=$("$TMPHAND" < expected.json 2>/dev/null)
out2=$(HANDOFF_BLOB="$blob2" ../consume.py --label example -- python3 -c '
import os
print(os.environ["SERVICE_USERNAME"])
print(os.environ["SERVICE_PASSWORD"])
')
[ "$out2" = "test
test" ] || { echo "FAIL: handoff.sh blob did not round-trip" >&2; exit 1; }
echo "ok"

echo "== 4. refusals =="
expect_fail "purpose mismatch" \
  ../consume.py --label other --check --blob-file blob.txt
expect_fail "no known credential field" \
  ../consume.py --label example --check --blob-file blob-unknown.txt
expect_fail "--check with a command" \
  ../consume.py --label example --check --blob-file blob.txt -- true

echo "ALL INTEROP CHECKS PASSED"
