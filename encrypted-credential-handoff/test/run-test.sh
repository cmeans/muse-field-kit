#!/bin/bash
# Known-answer interop test for the encrypted credential handoff.
#
# Verifies, against the reference implementation (../consume.py and
# ../handoff.sh):
#   1. decrypt direction: blob.txt decrypts to expected.json's values,
#      and --check output matches expected-check.txt exactly;
#   2. encrypt direction: a fresh blob produced by ../handoff.sh (with the
#      dummy public key embedded in a scratch copy) decrypts through
#      ../consume.py to the same values.
#
# A port or variant implementation passes the interop bar by reproducing
# step 1 against these vectors with its own decrypt side, and step 2 with
# its own encrypt side feeding the reference decrypt side.
set -euo pipefail
cd "$(dirname "$0")"

# consume.py refuses group/other-readable keys on principle; the repo copy
# of the dummy key is world-readable by design (it's a published vector),
# so work on a locked-down temp copy.
TMPKEY=$(mktemp)
trap 'rm -f "$TMPKEY" "$TMPHAND"' EXIT
cp test-dummy-priv.pem "$TMPKEY"
chmod 600 "$TMPKEY"
export HANDOFF_PRIVKEY="$TMPKEY"

echo "== 1a. reference decrypt, --check output =="
../consume.py --label example --check < blob.txt | diff - expected-check.txt
echo "ok"

echo "== 1b. reference decrypt, injected environment =="
out=$(../consume.py --label example -- python3 -c '
import os
print(os.environ["SERVICE_USERNAME"])
print(os.environ["SERVICE_PASSWORD"])
' < blob.txt)
[ "$out" = "test
test" ] || { echo "FAIL: unexpected env values" >&2; exit 1; }
echo "ok"

echo "== 2. reference encrypt (handoff.sh) -> reference decrypt =="
TMPHAND=$(mktemp)
python3 - "$TMPHAND" <<'PYEOF'
import re, sys
src = open("../handoff.sh").read()
pub = open("test-dummy-pub.pem").read().strip()
block = re.search(r"read -r -d '' PUBKEY <<'EOF' \|\| true\n(.*?)EOF", src, re.S).group(1)
open(sys.argv[1], "w").write(src.replace(block, pub + "\n"))
PYEOF
chmod +x "$TMPHAND"
blob2=$("$TMPHAND" < expected.json 2>/dev/null)
out2=$(printf '%s' "$blob2" | ../consume.py --label example -- python3 -c '
import os
print(os.environ["SERVICE_USERNAME"])
print(os.environ["SERVICE_PASSWORD"])
')
[ "$out2" = "test
test" ] || { echo "FAIL: handoff.sh blob did not round-trip" >&2; exit 1; }
echo "ok"

echo "ALL INTEROP CHECKS PASSED"
