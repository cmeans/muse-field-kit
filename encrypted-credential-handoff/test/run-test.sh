#!/bin/bash
# Known-answer interop test for the encrypted credential handoff.
#
# Verifies, against the reference implementation (../consume.py,
# ../handoff.sh and ../agent-setup.sh):
#   1. decrypt direction: blob.txt decrypts to expected.json's values, the
#      --check output matches expected-check.txt exactly, and the helper's
#      OWN stdout and stderr never carry a dummy value;
#   2. the child's stdin passes through consume.py untouched (a stdio
#      child's stdin is its transport; the blob must not consume it), and
#      the helper execs the command, so a TERM sent to the helper reaches
#      the command and leaves no credentialed process behind;
#   3. encrypt direction: a fresh blob produced by ../handoff.sh (with the
#      dummy public key embedded in a scratch copy) decrypts through
#      ../consume.py to the same values;
#   4. fingerprints agree: agent-setup.sh --fingerprint (on the key that
#      $HANDOFF_PRIVKEY names) equals handoff.sh --fingerprint, for the
#      dummy key and for a freshly generated one;
#   5. the refusals the docs claim, each by its exit code and message,
#      with nothing on stdout, no traceback and no dummy value in the
#      output.
#
# A port or variant implementation passes the interop bar by reproducing
# steps 1-2 against these vectors with its own decrypt side, and step 3
# with its own encrypt side feeding the reference decrypt side.
#
# The scripts are run through python3 / bash explicitly, so the test
# doesn't depend on their execute bits surviving a download.
set -euo pipefail
cd "$(dirname "$0")"

# The dummy values in expected.json / blob.txt. Distinct on purpose: a test
# that can't tell the username from the password can't catch a swap.
U=dummy-user-Qx7
P=dummy-pass-K3z9w

# consume.py refuses group/other-readable keys on principle; the repo copy
# of the dummy key is world-readable by design (it's a published vector),
# so work on a locked-down copy. The scratch directory exists BEFORE the
# trap is set: a trap that expands an unassigned variable under `set -u`
# aborts itself and leaves the key copy behind.
S=$(mktemp -d)
trap 'rm -rf "$S"' EXIT
TMPKEY="$S/dummy-priv.pem"
cp test-dummy-priv.pem "$TMPKEY"
chmod 600 "$TMPKEY"
export HANDOFF_PRIVKEY="$TMPKEY"

fail() { echo "FAIL: $*" >&2; exit 1; }

consume() { python3 ../consume.py "$@"; }

# Neither the username nor the password may appear in the given files.
no_dummy_in() {
  local f
  for f in "$@"; do
    if grep -qF -e "$U" -e "$P" "$f"; then
      fail "a dummy credential value appeared in the helper's own output ($(basename "$f"))"
    fi
  done
}

# expect_refusal DESC EXIT_CODE MESSAGE CMD...
# The command must exit with exactly EXIT_CODE, print MESSAGE on stderr,
# print nothing on stdout, not crash with a traceback, and not leak a dummy
# value. Any other failure (a crash, a missing key, a non-executable script)
# is not the refusal under test, and fails the test.
expect_refusal() {
  local desc="$1" want_rc="$2" want_msg="$3" rc=0
  shift 3
  "$@" >"$S/out" 2>"$S/err" || rc=$?
  [ "$rc" = "$want_rc" ] \
    || { cat "$S/err" >&2; fail "$desc: exit $rc, expected $want_rc"; }
  grep -qF -- "$want_msg" "$S/err" \
    || { cat "$S/err" >&2; fail "$desc: stderr lacks \"$want_msg\""; }
  [ ! -s "$S/out" ] || fail "$desc: refusal printed to stdout"
  ! grep -q Traceback "$S/err" || fail "$desc: traceback instead of a clean refusal"
  no_dummy_in "$S/out" "$S/err"
  echo "ok (refused: $desc)"
}

# Write a copy of ../handoff.sh with the public key in $1 embedded, to $2.
embed_pub() {
  python3 - "$1" "$2" <<'PYEOF'
import re, sys
src = open("../handoff.sh").read()
pub = open(sys.argv[1]).read().strip()
block = re.search(r"read -r -d '' PUBKEY <<'EOF' \|\| true\n(.*?)EOF", src, re.S).group(1)
open(sys.argv[2], "w").write(src.replace(block, pub + "\n"))
PYEOF
}

# Encrypt the JSON text in $1 to the dummy public key, straight through
# openssl (no validation), for payloads handoff.sh would never produce.
enc() {
  printf '%s' "$1" | openssl pkeyutl -encrypt -pubin -inkey test-dummy-pub.pem \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 | openssl base64 -A
}

echo "== 1a. reference decrypt, --check output =="
consume --label example --check --blob-file blob.txt >"$S/out" 2>"$S/err"
diff "$S/out" expected-check.txt || fail "--check output differs from expected-check.txt"
[ ! -s "$S/err" ] || fail "--check wrote to stderr"
no_dummy_in "$S/out"
echo "ok"

# The child writes what it received to a file, and prints nothing, so
# anything on stdout or stderr came from the helper itself.
echo "== 1b. reference decrypt, injected environment, nothing from the helper =="
consume --label example --blob-file blob.txt -- python3 -c '
import os, sys
open(sys.argv[1], "w").write(os.environ["SERVICE_USERNAME"] + "\n" + os.environ["SERVICE_PASSWORD"] + "\n")
' "$S/child" >"$S/out" 2>"$S/err"
[ "$(cat "$S/child")" = "$U
$P" ] || fail "unexpected env values"
[ ! -s "$S/out" ] && [ ! -s "$S/err" ] || fail "the helper printed something in run mode"
echo "ok"

echo "== 1c. per-invocation --env mapping =="
out=$(consume --label example --blob-file blob.txt --env username=CUSTOM_USER -- python3 -c '
import os
print(os.environ["CUSTOM_USER"])
print("SERVICE_USERNAME" in os.environ)
print(os.environ["SERVICE_PASSWORD"] == os.environ.get("CUSTOM_USER"))
')
[ "$out" = "$U
False
False" ] || fail "--env mapping not applied as expected"
echo "ok"

echo "== 1d. mapped variables come from the payload only =="
# A payload without a password must not run with one inherited from the
# caller's environment.
out=$(SERVICE_PASSWORD=inherited CUSTOM_PASS=inherited consume --label example \
  --blob "$(enc '{"svc":"example","username":"only-user"}')" --env password=CUSTOM_PASS -- python3 -c '
import os
print(os.environ["SERVICE_USERNAME"], os.environ.get("CUSTOM_PASS"), os.environ.get("SERVICE_PASSWORD"))
')
[ "$out" = "only-user None inherited" ] || fail "an inherited mapped variable reached the command: $out"
echo "ok"

echo "== 2a. child stdin passes through untouched =="
out=$(printf 'hello-stdin' | consume --label example --blob-file blob.txt -- python3 -c '
import os, sys
print(os.environ["SERVICE_USERNAME"] == sys.argv[1])
print(sys.stdin.read())
' "$U")
[ "$out" = "True
hello-stdin" ] || fail "child stdin was consumed or altered"
echo "ok"

echo "== 2b. the helper execs the command; TERM leaves nothing running =="
# python3 directly, not the consume() function: a backgrounded function
# runs in a forked subshell, and $! would be that subshell's PID.
python3 ../consume.py --label example --blob-file blob.txt -- python3 -c '
import os, time
print(os.getpid(), flush=True)
time.sleep(60)
' >"$S/pid" &
helper=$!
for _ in $(seq 100); do [ -s "$S/pid" ] && break; sleep 0.1; done
child=$(cat "$S/pid")
[ -n "$child" ] || { kill "$helper" 2>/dev/null; fail "command never started"; }
if [ "$child" != "$helper" ]; then
  kill "$child" "$helper" 2>/dev/null || true
  fail "the command runs as a separate child ($child) of the helper ($helper), not in its place"
fi
kill -TERM "$helper"
rc=0; wait "$helper" || rc=$?
[ "$rc" = 143 ] || fail "TERM: exit $rc, expected 143"
! kill -0 "$child" 2>/dev/null || fail "a process with the credential is still running"
echo "ok"

echo "== 3. reference encrypt (handoff.sh) -> reference decrypt =="
embed_pub test-dummy-pub.pem "$S/handoff-dummy.sh"
bash "$S/handoff-dummy.sh" < expected.json >"$S/blob2" 2>"$S/err"
grep -q '^pubkey SHA256:' "$S/err" || fail "handoff.sh printed no fingerprint"
no_dummy_in "$S/blob2" "$S/err"
out=$(HANDOFF_BLOB="$(cat "$S/blob2")" consume --label example -- python3 -c '
import os
print(os.environ["SERVICE_USERNAME"])
print(os.environ["SERVICE_PASSWORD"])
')
[ "$out" = "$U
$P" ] || fail "handoff.sh blob did not round-trip"
out=$(HANDOFF_BLOB="$(cat "$S/blob2")" consume --label example -- python3 -c '
import os
print("HANDOFF_BLOB" in os.environ)
')
[ "$out" = "False" ] || fail "the blob was passed on to the command's environment"
# 190 bytes is the RSA-2048/OAEP-SHA256 ceiling: exactly that must work.
max=$(python3 -c 'import json; print(json.dumps({"svc": "example", "password": "y" * 159}, separators=(",", ":")), end="")')
[ "${#max}" = 190 ] || fail "test setup: maximum payload is ${#max} bytes, not 190"
bash "$S/handoff-dummy.sh" <<<"$max" >"$S/blob3" 2>/dev/null || fail "handoff.sh refused a 190-byte payload"
out=$(HANDOFF_BLOB="$(cat "$S/blob3")" consume --label example -- python3 -c '
import os
print(len(os.environ["SERVICE_PASSWORD"]))
')
[ "$out" = 159 ] || fail "the 190-byte payload did not round-trip"
echo "ok"

echo "== 4a. fingerprints agree on the dummy key; --fingerprint reads \$HANDOFF_PRIVKEY =="
want=$(bash "$S/handoff-dummy.sh" --fingerprint)
# HANDOFF_KEY_DIR points somewhere with no key: the fingerprint must come
# from $HANDOFF_PRIVKEY, the key the consume side actually uses.
got=$(HANDOFF_KEY_DIR="$S/no-such-dir" bash ../agent-setup.sh --fingerprint 2>"$S/err")
[ "$got" = "$want" ] || fail "agent-setup.sh --fingerprint ($got) != handoff.sh --fingerprint ($want)"
grep -qxF "key file: $TMPKEY" "$S/err" || fail "--fingerprint did not name the key file it read"
got=$(env -u HANDOFF_PRIVKEY bash ../agent-setup.sh --fingerprint "$TMPKEY" 2>/dev/null)
[ "$got" = "$want" ] || fail "agent-setup.sh --fingerprint KEY gave $got"
# With HANDOFF_PRIVKEY unset, it falls back to consume.py's default, not to
# $HANDOFF_KEY_DIR: the two must name the same key.
mkdir -p "$S/home/.config/handoff"
cp "$TMPKEY" "$S/home/.config/handoff/handoff-priv.pem"
got=$(env -u HANDOFF_PRIVKEY HOME="$S/home" HANDOFF_KEY_DIR="$S/no-such-dir" bash ../agent-setup.sh --fingerprint 2>"$S/err")
if [ "$got" != "$want" ] || ! grep -qxF "key file: $S/home/.config/handoff/handoff-priv.pem" "$S/err"; then
  fail "--fingerprint's default is not consume.py's default ($got; $(cat "$S/err"))"
fi
echo "ok"

echo "== 4b. a freshly generated key: setup output, --fingerprint and handoff.sh agree =="
HANDOFF_KEY_DIR="$S/agent" bash ../agent-setup.sh >"$S/setup-out" 2>"$S/setup-err" \
  || { cat "$S/setup-err" >&2; fail "agent-setup.sh failed"; }
[ "$(stat -c %a "$S/agent/handoff-priv.pem")" = 600 ] || fail "new key is not mode 600"
sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' "$S/setup-out" > "$S/agent-pub.pem"
printed=$(sed -n 's/^public key fingerprint: //p' "$S/setup-out")
embed_pub "$S/agent-pub.pem" "$S/handoff-agent.sh"
from_handoff=$(bash "$S/handoff-agent.sh" --fingerprint)
from_key=$(HANDOFF_PRIVKEY="$S/agent/handoff-priv.pem" bash ../agent-setup.sh --fingerprint 2>/dev/null)
[ -n "$printed" ] && [ "$printed" = "$from_handoff" ] && [ "$from_key" = "$from_handoff" ] \
  || fail "fingerprints disagree: setup $printed, handoff.sh $from_handoff, --fingerprint $from_key"
[ "$from_handoff" != "$want" ] || fail "the new key has the dummy key's fingerprint"
echo "ok"

echo "== 5. refusals =="
expect_refusal "purpose mismatch (--check)" 1 "purpose mismatch" \
  consume --label other --check --blob-file blob.txt
expect_refusal "purpose mismatch (run mode)" 1 "purpose mismatch" \
  consume --label other --blob-file blob.txt -- true
# The payload's own svc ("example") is unauthenticated text: never echoed.
! grep -q example "$S/err" || fail "the mismatch message echoed the payload's svc"
expect_refusal "no known credential field" 1 "no known credential field" \
  consume --label example --check --blob-file blob-unknown.txt
# Unknown fields are counted, never named: blob-unknown.txt's is "note".
grep -qF "ignoring 1 unknown field" "$S/err" || fail "unknown field not counted"
! grep -qw note "$S/err" || fail "an unknown field's name was echoed"
expect_refusal "--check with a command" 1 "--check takes no command" \
  consume --label example --check --blob-file blob.txt -- true
expect_refusal "no command and no --check" 1 "no command given" \
  consume --label example --blob-file blob.txt
expect_refusal "no --label" 1 "--label is required" \
  consume --check --blob-file blob.txt
expect_refusal "input not base64" 1 "not valid base64" \
  consume --label example --check --blob '!!not base64!!'
expect_refusal "damaged blob" 1 "decryption failed" \
  consume --label example --check --blob "$(cat "$S/blob2" | tr 'A-Za-z' 'B-ZAb-za')"
cp test-dummy-priv.pem "$S/loose.pem"; chmod 644 "$S/loose.pem"
expect_refusal "group/other-readable key" 1 "must be owner-only" \
  env HANDOFF_PRIVKEY="$S/loose.pem" python3 ../consume.py --label example --check --blob-file blob.txt
expect_refusal "missing key" 1 "cannot read private key" \
  env HANDOFF_PRIVKEY="$S/no-such-key.pem" python3 ../consume.py --label example --check --blob-file blob.txt
expect_refusal "--env PATH" 1 "would change how the command starts" \
  consume --label example --blob-file blob.txt --env password=PATH -- true
expect_refusal "--env LD_PRELOAD" 1 "would change how the command starts" \
  consume --label example --blob-file blob.txt --env password=LD_PRELOAD -- true
expect_refusal "--env PYTHONSTARTUP" 1 "would change how the command starts" \
  consume --label example --blob-file blob.txt --env password=PYTHONSTARTUP -- true
expect_refusal "--env BASH_ENV" 1 "would change how the command starts" \
  consume --label example --blob-file blob.txt --env password=BASH_ENV -- true
for name in GIT_SSH_COMMAND JDK_JAVA_OPTIONS _JAVA_OPTIONS DYLD_INSERT_LIBRARIES HOME IFS ENV GCONV_PATH HANDOFF_PRIVKEY HANDOFF_BLOB; do
  expect_refusal "--env $name" 1 "would change how the command starts" \
    consume --label example --blob-file blob.txt --env "password=$name" -- true
done
expect_refusal "--env not a variable name" 1 "not a valid variable name" \
  consume --label example --blob-file blob.txt --env 'password=A B' -- true
expect_refusal "--env two fields, one target" 1 "same environment variable" \
  consume --label example --blob-file blob.txt --env username=SERVICE_PASSWORD -- true
expect_refusal "command not found" 127 "cannot run" \
  consume --label example --blob-file blob.txt -- "$S/no-such-command"
printf '#!/bin/sh\n' > "$S/not-executable"; chmod 644 "$S/not-executable"
expect_refusal "command not executable" 126 "cannot run" \
  consume --label example --blob-file blob.txt -- "$S/not-executable"
expect_refusal "empty command" 1 "no command given" \
  consume --label example --blob-file blob.txt -- ""
expect_refusal "NUL in a credential (run mode)" 1 "contains a NUL byte" \
  consume --label example --blob "$(enc '{"svc":"example","password":"a\u0000b"}')" -- true
expect_refusal "NUL in a credential (--check)" 1 "contains a NUL byte" \
  consume --label example --check --blob "$(enc '{"svc":"example","password":"a\u0000b"}')"
expect_refusal "lone surrogate in a credential (run mode)" 1 "not valid UTF-8" \
  consume --label example --blob "$(enc '{"svc":"example","password":"a\ud800b"}')" -- true
expect_refusal "lone surrogate in a credential (--check)" 1 "not valid UTF-8" \
  consume --label example --check --blob "$(enc '{"svc":"example","password":"a\ud800b"}')"
! grep -q 'ud800\|position' "$S/err" || fail "the surrogate refusal quoted the payload"
expect_refusal "agent-setup.sh re-run over an existing key" 1 "refusing to overwrite existing key" \
  env HANDOFF_KEY_DIR="$S/agent" bash ../agent-setup.sh
expect_refusal "agent-setup.sh unknown argument" 2 "usage: agent-setup.sh" \
  env HANDOFF_KEY_DIR="$S/typo" bash ../agent-setup.sh --fingerprnt
[ ! -e "$S/typo" ] || fail "agent-setup.sh created a key directory for an unknown argument"
expect_refusal "agent-setup.sh --fingerprint, no key" 1 "no key file at" \
  env HANDOFF_PRIVKEY="$S/no-such-key.pem" bash ../agent-setup.sh --fingerprint
expect_refusal "agent-setup.sh --fingerprint, two keys" 2 "usage: agent-setup.sh --fingerprint" \
  bash ../agent-setup.sh --fingerprint "$TMPKEY" "$TMPKEY"
expect_refusal "agent-setup.sh --fingerprint, empty KEY" 2 "empty KEY" \
  bash ../agent-setup.sh --fingerprint ""
expect_refusal "agent-setup.sh --fingerprint, a public key" 1 "could not read key" \
  bash ../agent-setup.sh --fingerprint test-dummy-pub.pem
[ "$(grep -c . "$S/err")" -le 3 ] || fail "--fingerprint on a public key printed more than one openssl error"
long=$(python3 -c 'import json; print(json.dumps({"svc": "example", "password": "x" * 160}, separators=(",", ":")), end="")')
[ "${#long}" = 191 ] || fail "test setup: oversize payload is ${#long} bytes, not 191"
expect_refusal "handoff.sh 191-byte payload" 1 "payload is 191 bytes" \
  bash "$S/handoff-dummy.sh" <<<"$long"
if command -v jq >/dev/null; then
  expect_refusal "handoff.sh non-object payload" 1 "must be a single JSON object" \
    bash "$S/handoff-dummy.sh" <<<'["example"]'
  expect_refusal "handoff.sh two concatenated objects" 1 "must be a single JSON object" \
    bash "$S/handoff-dummy.sh" <<<'{"svc":"example","password":"x"}{"svc":"example"}'
  expect_refusal "handoff.sh payload without svc" 1 "must be a single JSON object" \
    bash "$S/handoff-dummy.sh" <<<'{"password":"x"}'
else
  echo "skip: jq not installed, handoff.sh shape refusals not tested"
fi
rc=0; bash ../handoff.sh --fingerprint >"$S/out" 2>/dev/null || rc=$?
[ "$rc" != 0 ] && [ ! -s "$S/out" ] \
  || fail "handoff.sh --fingerprint with the placeholder key: exit $rc, stdout $(cat "$S/out")"
echo "ok (refused: handoff.sh --fingerprint with the placeholder key)"

echo "ALL INTEROP CHECKS PASSED"
