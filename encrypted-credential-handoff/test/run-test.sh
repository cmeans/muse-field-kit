#!/bin/bash
# Known-answer interop test for the encrypted credential handoff.
#
# Verifies, against the reference implementation (../consume.py,
# ../handoff.sh and ../agent-setup.sh):
#   1. decrypt direction: blob.txt decrypts to expected.json's values, the
#      --check output matches expected-check.txt exactly, and the helper's
#      OWN stdout and stderr never carry a dummy value;
#   2. the command's stdin passes through consume.py untouched (a stdio
#      server's stdin is its transport; the blob must not consume it), and
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
# The scripts are run through python3 / bash / sh explicitly, so the test
# doesn't depend on their execute bits surviving a download.
set -Eeuo pipefail
# A failing command substitution (got=$(...)) stops the script under set -e
# before its own check can say why: name the line instead.
# Only in the top-level shell: with set -E a failure inside $(...) would
# otherwise be reported twice.
trap '[ "$BASH_SUBSHELL" = 0 ] && echo "FAIL: line $LINENO: $BASH_COMMAND" >&2' ERR
cd "$(dirname "$0")"

# The dummy values in expected.json / blob.txt. Distinct on purpose: a test
# that can't tell the username from the password can't catch a swap.
U=dummy-user-Qx7
P=dummy-pass-K3z9w
# Every value the test crafts itself (enc, unknown.json) carries this marker,
# so the leak check covers them too.
MK=mk-Zq9

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

# The real interpreter, for the restricted-PATH tests: `command -v python3`
# can be a pyenv/asdf shim (#!/usr/bin/env bash) that can't run there.
PY=$(python3 -c 'import sys; print(sys.executable)')

# Neither the username nor the password may appear in the given files.
no_dummy_in() {
  local f
  for f in "$@"; do
    if grep -qF -e "$U" -e "$P" -e "$MK" "$f"; then
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

# The command writes what it received to a file, and prints nothing, so
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
# An inherited SERVICE_USERNAME must not survive the remapping either.
out=$(SERVICE_USERNAME=inherited consume --label example --blob-file blob.txt --env username=CUSTOM_USER -- python3 -c '
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
# Nor one under a remapped default name (SERVICE_PASSWORD, with password
# mapped to CUSTOM_PASS): a nested wrapper's parent may have set it for
# another service.
out=$(SERVICE_PASSWORD=inherited CUSTOM_PASS=inherited consume --label example \
  --blob "$(enc '{"svc":"example","username":"mk-Zq9-only-user"}')" --env password=CUSTOM_PASS -- python3 -c '
import os
print(os.environ["SERVICE_USERNAME"], os.environ.get("CUSTOM_PASS"), os.environ.get("SERVICE_PASSWORD"))
')
[ "$out" = "mk-Zq9-only-user None None" ] || fail "an inherited credential variable reached the command: $out"
echo "ok"

echo "== 2a. the command's stdin passes through untouched =="
out=$(printf 'hello-stdin' | consume --label example --blob-file blob.txt -- python3 -c '
import os, sys
print(os.environ["SERVICE_USERNAME"] == sys.argv[1])
print(sys.stdin.read())
' "$U")
[ "$out" = "True
hello-stdin" ] || fail "the command's stdin was consumed or altered"
echo "ok"

echo "== 2b. the helper execs the command; TERM leaves nothing running =="
# Both entry points: python3 directly, and the sh launcher on lines 1-3
# (what ./consume.py runs), which must exec Python in its own place too.
# Called directly, not through consume(): a backgrounded function runs in a
# forked subshell, and $! would be that subshell's PID.
for launcher in python3 sh; do
  : >"$S/pid"
  "$launcher" ../consume.py --label example --blob-file blob.txt -- python3 -c '
import os, time
print(os.getpid(), flush=True)
time.sleep(60)
' >"$S/pid" &
  helper=$!
  for _ in $(seq 100); do [ -s "$S/pid" ] && break; sleep 0.1; done
  child=$(cat "$S/pid")
  [ -n "$child" ] || { kill "$helper" 2>/dev/null; fail "command never started ($launcher)"; }
  if [ "$child" != "$helper" ]; then
    kill "$child" "$helper" 2>/dev/null || true
    fail "via $launcher, the command runs as a separate child ($child) of the helper ($helper), not in its place"
  fi
  kill -TERM "$helper"
  rc=0; wait "$helper" || rc=$?
  [ "$rc" = 143 ] || fail "TERM via $launcher: exit $rc, expected 143"
  ! kill -0 "$child" 2>/dev/null || fail "a process with the credential is still running ($launcher)"
done
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
print("HANDOFF_BLOB" in os.environ, "HANDOFF_PRIVKEY" in os.environ)
')
[ "$out" = "False False" ] || fail "the blob or the key's path was passed on to the command's environment: $out"
# The command gets SIGPIPE and SIGXFSZ at their defaults (Python ignores
# both at startup, and an ignored signal stays ignored across exec).
if [ -r /proc/self/status ]; then
  ign=$(HANDOFF_BLOB="$(cat "$S/blob2")" consume --label example -- sh -c 'grep "^SigIgn:" /proc/self/status' | awk '{print $2}')
  mask=$((16#$ign))
  [ $(( (mask >> 12) & 1 )) = 0 ] && [ $(( (mask >> 24) & 1 )) = 0 ] \
    || fail "the command inherited SIGPIPE or SIGXFSZ ignored (SigIgn $ign)"
else
  echo "skip: no /proc, signal dispositions not checked"
fi
# 190 bytes is the RSA-2048/OAEP-SHA256 ceiling: exactly that must work.
max=$(python3 -c 'import json; print(json.dumps({"svc": "example", "password": "mk-Zq9" + "y" * 153}, separators=(",", ":")), end="")')
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
# ...and consume.py really decrypts with that default, unset or empty.
for privkey in unset empty; do
  if [ "$privkey" = unset ]; then
    env -u HANDOFF_PRIVKEY HOME="$S/home" python3 ../consume.py --label example --check --blob-file blob.txt >"$S/out"
  else
    HANDOFF_PRIVKEY='' HOME="$S/home" python3 ../consume.py --label example --check --blob-file blob.txt >"$S/out"
  fi
  diff -q "$S/out" expected-check.txt >/dev/null || fail "consume.py's default key (HANDOFF_PRIVKEY $privkey) is not ~/.config/handoff/handoff-priv.pem"
done
got=$(HANDOFF_PRIVKEY='' HOME="$S/home" bash ../agent-setup.sh --fingerprint 2>/dev/null)
[ "$got" = "$want" ] || fail "agent-setup.sh with an empty HANDOFF_PRIVKEY gave $got"
# A literal ~ (as an MCP client's JSON env passes it) is expanded by both.
# shellcheck disable=SC2088
HANDOFF_PRIVKEY='~/.config/handoff/handoff-priv.pem' HOME="$S/home" python3 ../consume.py --label example --check --blob-file blob.txt >"$S/out" \
  || fail "consume.py did not expand a literal ~ in HANDOFF_PRIVKEY"
# shellcheck disable=SC2088
got=$(HANDOFF_PRIVKEY='~/.config/handoff/handoff-priv.pem' HOME="$S/home" bash ../agent-setup.sh --fingerprint 2>/dev/null)
[ "$got" = "$want" ] || fail "agent-setup.sh did not expand a literal ~ in HANDOFF_PRIVKEY"
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
# A relative HANDOFF_KEY_DIR is reported as an absolute path.
mkdir -p "$S/cwd"
here=$PWD
(cd "$S/cwd" && HANDOFF_KEY_DIR=rel bash "$here/../agent-setup.sh" >"$S/setup-out" 2>/dev/null) \
  || fail "agent-setup.sh with a relative HANDOFF_KEY_DIR failed"
grep -qxF "this key lives at: $S/cwd/rel/handoff-priv.pem" "$S/setup-out" \
  || fail "agent-setup.sh printed a relative key path: $(grep 'lives at' "$S/setup-out")"
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
printf '\377\376' > "$S/not-text.txt"
expect_refusal "blob file not text" 1 "as text" \
  consume --label example --check --blob-file "$S/not-text.txt"
mkdir -p "$S/py-only"; ln -sf "$PY" "$S/py-only/python3"
expect_refusal "openssl not installed" 1 "openssl not found" \
  env PATH="$S/py-only" python3 ../consume.py --label example --check --blob-file blob.txt
expect_refusal "input not base64" 1 "not valid base64" \
  consume --label example --check --blob '!!not base64!!'
expect_refusal "damaged blob" 1 "stop and report it to the user (SETUP.md, stop conditions)" \
  consume --label example --check --blob "$(cat "$S/blob2" | tr 'A-Za-z' 'B-ZAb-za')"
cp test-dummy-priv.pem "$S/loose.pem"; chmod 644 "$S/loose.pem"
expect_refusal "group/other-readable key" 1 "must be owner-only" \
  env HANDOFF_PRIVKEY="$S/loose.pem" python3 ../consume.py --label example --check --blob-file blob.txt
cp test-dummy-pub.pem "$S/pub-as-key.pem"; chmod 600 "$S/pub-as-key.pem"
expect_refusal "a key that doesn't load (a public key)" 1 "cannot load the private key" \
  env HANDOFF_PRIVKEY="$S/pub-as-key.pem" python3 ../consume.py --label example --check --blob-file blob.txt
! grep -q "made for another key" "$S/err" || fail "a key that doesn't load was blamed on the blob"
! grep -q ":error:" "$S/err" || fail "the key-load refusal shows openssl's internal error line, not its readable one"
# An encrypted key is refused, and never takes a passphrase from stdin (the
# command's transport): the passphrase is right there on stdin.
openssl pkey -in test-dummy-priv.pem -aes256 -passout pass:mk-Zq9-pass -out "$S/enc-key.pem" 2>/dev/null
chmod 600 "$S/enc-key.pem"
# shellcheck disable=SC2016  # $1 is the inner shell's argument
expect_refusal "an encrypted key, passphrase on stdin" 1 "cannot load the private key" \
  bash -c 'echo mk-Zq9-pass | HANDOFF_PRIVKEY="$1" python3 ../consume.py --label example --check --blob-file blob.txt' _ "$S/enc-key.pem"
# shellcheck disable=SC2016  # $1 is the inner shell's argument
expect_refusal "agent-setup.sh --fingerprint, an encrypted key" 1 "could not read key" \
  bash -c 'echo mk-Zq9-pass | bash ../agent-setup.sh --fingerprint "$1"' _ "$S/enc-key.pem"
# Only RSA-2048 keys: an Ed25519 or P-256 key loads but isn't this protocol's.
openssl genpkey -algorithm ED25519 -out "$S/ed25519.pem" 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$S/p256.pem" 2>/dev/null
# A 2052-bit RSA key has the same 294-byte public key as a 2048-bit one, and
# an RSA-2048 key with e = 3 differs only in its exponent: both refused too.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2052 -out "$S/rsa2052.pem" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3 -out "$S/rsa-e3.pem" 2>/dev/null
chmod 600 "$S/ed25519.pem" "$S/p256.pem" "$S/rsa2052.pem" "$S/rsa-e3.pem"
for k in ed25519 p256 rsa2052 rsa-e3; do
  expect_refusal "a $k key (consume.py)" 1 "is not an RSA-2048 key" \
    env HANDOFF_PRIVKEY="$S/$k.pem" python3 ../consume.py --label example --check --blob-file blob.txt
  expect_refusal "a $k key (agent-setup.sh --fingerprint)" 1 "is not an RSA-2048 key" \
    bash ../agent-setup.sh --fingerprint "$S/$k.pem"
  ! grep -q "could not read key" "$S/err" || fail "agent-setup.sh said it couldn't read a $k key it did read"
done
# An unreadable key file is reported as unreadable, not as oversized (root
# can read anything, so skip it there).
if [ "$(id -u)" != 0 ]; then
  cp "$TMPKEY" "$S/noread.pem"; chmod 000 "$S/noread.pem"
  expect_refusal "agent-setup.sh --fingerprint, an unreadable key file" 1 "cannot read key file at" \
    bash ../agent-setup.sh --fingerprint "$S/noread.pem"
  ! grep -q "over 16384" "$S/err" || fail "an unreadable key file was reported as oversized"
fi
# A key file over 16384 bytes is refused before openssl sees it (its decoder
# is very slow on large junk).
head -c 20000 /dev/zero | tr '\0' 'A' > "$S/big-key.pem"; chmod 600 "$S/big-key.pem"
expect_refusal "an oversized key file (consume.py)" 1 "over 16384" \
  timeout 20 env HANDOFF_PRIVKEY="$S/big-key.pem" python3 ../consume.py --label example --check --blob-file blob.txt
expect_refusal "an oversized key file (agent-setup.sh --fingerprint)" 1 "over 16384 bytes" \
  timeout 20 bash ../agent-setup.sh --fingerprint "$S/big-key.pem"
# Under a terminal (a pseudo-terminal from script), an encrypted key still
# isn't prompted for: no "Enter pass phrase", and no hang.
if command -v script >/dev/null; then
  out=$(HANDOFF_PRIVKEY="$S/enc-key.pem" timeout 20 script -qec "python3 ../consume.py --label example --check --blob-file blob.txt" /dev/null 2>&1) || true
  case "$out" in
    *"Enter pass phrase"*) fail "the helper prompted for a key passphrase on a terminal" ;;
    *"cannot load the private key"*) echo "ok (refused: an encrypted key under a terminal, no prompt)" ;;
    *) fail "an encrypted key under a terminal: unexpected output: $out" ;;
  esac
else
  echo "skip: script(1) missing, the terminal prompt check didn't run"
fi
expect_refusal "missing key" 1 "cannot read private key" \
  env HANDOFF_PRIVKEY="$S/no-such-key.pem" python3 ../consume.py --label example --check --blob-file blob.txt
# A key file owned by another user is refused, even at mode 0600. It needs a
# file this account doesn't own, so: $HANDOFF_TEST_OTHER_OWNER_KEY if set (CI
# makes a root-owned 0600 copy of the dummy key), else a root-owned,
# owner-only system file such as Fedora's /etc/shadow (mode 0000: its
# metadata is readable, its contents aren't, and the refusal comes before
# any read). Skipped as root, or where neither exists.
other_owner=""
if [ "$(id -u)" != 0 ]; then
  for f in "${HANDOFF_TEST_OTHER_OWNER_KEY-}" /etc/shadow /etc/gshadow; do
    if [ -z "$f" ] || [ ! -f "$f" ]; then continue; fi
    [ "$(stat -c %u "$f")" != "$(id -u)" ] || continue
    case "$(stat -c %a "$f")" in 0|[0-7]00) other_owner=$f; break ;; esac
  done
fi
if [ -n "$other_owner" ]; then
  expect_refusal "a key owned by another user ($other_owner)" 1 "is not owned by this user" \
    env HANDOFF_PRIVKEY="$other_owner" python3 ../consume.py --label example --check --blob-file blob.txt
else
  echo "skip: no owner-only file owned by another user, the key-owner refusal wasn't tested"
fi
expect_refusal "--env PATH" 1 "is on the refused list" \
  consume --label example --blob-file blob.txt --env password=PATH -- true
expect_refusal "--env LD_PRELOAD" 1 "is on the refused list" \
  consume --label example --blob-file blob.txt --env password=LD_PRELOAD -- true
expect_refusal "--env PYTHONSTARTUP" 1 "is on the refused list" \
  consume --label example --blob-file blob.txt --env password=PYTHONSTARTUP -- true
expect_refusal "--env BASH_ENV" 1 "is on the refused list" \
  consume --label example --blob-file blob.txt --env password=BASH_ENV -- true
# Every refused name, in upper and lower case, and every refused prefix.
# The list is written out here, not read from consume.py, so dropping an
# entry there fails the test.
refused_names="ALL_PROXY BASHOPTS BASH_ENV CLASSPATH CURL_CA_BUNDLE CURL_HOME DOCKER_HOST
  EDITOR ENV FTP_PROXY GCONV_PATH GLIBC_TUNABLES HANDOFF_BLOB HANDOFF_LABEL HANDOFF_PRIVKEY HOME
  HOSTALIASES HTTPS_PROXY HTTP_PROXY IFS JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS KUBECONFIG
  LUA_INIT NODE_EXTRA_CA_CERTS NODE_OPTIONS NODE_PATH NO_PROXY PAGER PATH PERL5DB
  PERL5LIB PERL5OPT PERLLIB PROMPT_COMMAND PS4 REQUESTS_CA_BUNDLE RUBYLIB RUBYOPT
  SHELLOPTS SSH_ASKPASS SSH_AUTH_SOCK SSLKEYLOGFILE SSL_CERT_DIR SSL_CERT_FILE VISUAL
  WGETRC XDG_CONFIG_HOME ZDOTDIR _JAVA_OPTIONS"
refused_prefixes="LD_ DYLD_ PYTHON BASH_FUNC_ GIT_ LUA_INIT_ OPENSSL_ NPM_CONFIG_ PIP_"
n=0
for name in $refused_names; do
  for v in "$name" "$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"; do
    expect_refusal "--env $v" 1 "is on the refused list" \
      consume --label example --blob-file blob.txt --env "password=$v" -- true >/dev/null
    n=$((n + 1))
  done
done
for prefix in $refused_prefixes; do
  expect_refusal "--env ${prefix}X" 1 "is on the refused list" \
    consume --label example --blob-file blob.txt --env "password=${prefix}X" -- true >/dev/null
  n=$((n + 1))
done
echo "ok (refused: $n --env targets, every listed name in both cases and every prefix)"
expect_refusal "--env unknown field (a typo)" 1 "not a known credential field" \
  consume --label example --blob-file blob.txt --env pasword=APP_PASS -- true
expect_refusal "--env wrong-case field" 1 "not a known credential field" \
  consume --label example --blob-file blob.txt --env Password=APP_PASS -- true
expect_refusal "--env one field twice" 1 "maps 'password' twice" \
  consume --label example --blob-file blob.txt --env password=A_P --env password=B_P -- true
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
  consume --label example --blob "$(enc '{"svc":"example","password":"mk-Zq9\u0000b"}')" -- true
expect_refusal "NUL in a credential (--check)" 1 "contains a NUL byte" \
  consume --label example --check --blob "$(enc '{"svc":"example","password":"mk-Zq9\u0000b"}')"
expect_refusal "lone surrogate in a credential (run mode)" 1 "not valid UTF-8" \
  consume --label example --blob "$(enc '{"svc":"example","password":"mk-Zq9\ud800b"}')" -- true
expect_refusal "lone surrogate in a credential (--check)" 1 "not valid UTF-8" \
  consume --label example --check --blob "$(enc '{"svc":"example","password":"mk-Zq9\ud800b"}')"
! grep -q 'ud800\|position' "$S/err" || fail "the surrogate refusal quoted the payload"
expect_refusal "payload without svc" 1 "no 'svc' field" \
  consume --label example --check --blob "$(enc '{"username":"mk-Zq9-user"}')"
expect_refusal "payload not JSON" 1 "not valid JSON" \
  consume --label example --check --blob "$(enc 'mk-Zq9 not json')"
expect_refusal "payload not a JSON object" 1 "not a JSON object" \
  consume --label example --check --blob "$(enc '["mk-Zq9"]')"
expect_refusal "credential not a string" 1 "not a string" \
  consume --label example --check --blob "$(enc '{"svc":"example","password":9817263}')"
! grep -q 9817263 "$S/err" || fail "the non-string refusal echoed the value"
expect_refusal "empty credential" 1 "is empty" \
  consume --label example --blob "$(enc '{"svc":"example","username":"mk-Zq9-user","password":""}')" -- true
expect_refusal "empty blob" 1 "the blob is empty" \
  consume --label example --check --blob ''
expect_refusal "short blob" 1 "decodes to 10 bytes, not 256" \
  consume --label example --check --blob "$(head -c 10 /dev/zero | base64)"
python3 -c 'print("A" * 9000)' > "$S/big-blob.txt"
expect_refusal "oversized blob file" 1 "over 8192 characters" \
  consume --label example --check --blob-file "$S/big-blob.txt"
expect_refusal "no blob supplied" 1 "no blob supplied" \
  consume --label example --check
expect_refusal "two blob sources" 1 "more than one blob source" \
  consume --label example --check --blob "$(cat blob.txt)" --blob-file blob.txt
expect_refusal "blob option and \$HANDOFF_BLOB" 1 "more than one blob source" \
  env HANDOFF_BLOB="$(cat blob.txt)" python3 ../consume.py --label example --check --blob-file blob.txt
expect_refusal "--label twice" 1 "--label given twice" \
  consume --label other --label example --check --blob-file blob.txt
expect_refusal "--env without =" 1 "--env takes field=NAME" \
  consume --label example --blob-file blob.txt --env password -- true
expect_refusal "option without its value" 1 "--label needs a value" \
  consume --label
expect_refusal "unrecognized argument" 1 "unrecognized argument" \
  consume --label example --check --blob-file blob.txt --verbose
mkdir -p "$S/fake-ssl"; ln -sf "$PY" "$S/fake-ssl/python3"
printf '#!/bin/sh\necho "LibreSSL 3.8.2"\n' > "$S/fake-ssl/openssl"; chmod 755 "$S/fake-ssl/openssl"
expect_refusal "not OpenSSL 3 or 4" 1 "requires OpenSSL 3 or 4" \
  env PATH="$S/fake-ssl" python3 ../consume.py --label example --check --blob-file blob.txt
[ "$(uname -s)" = Darwin ] || ! grep -q Homebrew "$S/err" || fail "the macOS hint showed off macOS"
# ~/ is expanded, ~user is refused, and both scripts agree on each.
mkdir -p "$S/home2"; cp blob.txt "$S/home2/b.txt"
# shellcheck disable=SC2088
HOME="$S/home2" consume --label example --check --blob-file '~/b.txt' >"$S/out" \
  || fail "--blob-file did not expand ~/"
# shellcheck disable=SC2088
expect_refusal "~user in HANDOFF_PRIVKEY (consume.py)" 1 "only ~/ is expanded" \
  env HANDOFF_PRIVKEY='~root/k.pem' python3 ../consume.py --label example --check --blob-file blob.txt
# shellcheck disable=SC2088
expect_refusal "~user in HANDOFF_PRIVKEY (agent-setup.sh)" 1 "only ~/ is expanded" \
  env HANDOFF_PRIVKEY='~root/k.pem' bash ../agent-setup.sh --fingerprint
# shellcheck disable=SC2088
expect_refusal "~user in HANDOFF_KEY_DIR" 1 "only ~/ is expanded" \
  env HANDOFF_KEY_DIR='~root/kd' bash ../agent-setup.sh
expect_refusal "agent-setup.sh without HOME, default key" 1 "HOME is not set" \
  env -u HOME -u HANDOFF_PRIVKEY bash ../agent-setup.sh --fingerprint
# ...but HOME isn't needed with an absolute key or key directory.
env -u HOME bash ../agent-setup.sh --fingerprint >/dev/null 2>&1 \
  || fail "agent-setup.sh --fingerprint with an absolute HANDOFF_PRIVKEY needed HOME"
env -u HOME HANDOFF_KEY_DIR="$S/nohome-key" bash ../agent-setup.sh >/dev/null 2>&1 \
  || fail "agent-setup.sh with an absolute HANDOFF_KEY_DIR needed HOME"
# ~/ and a bare ~ in HANDOFF_KEY_DIR are expanded.
mkdir -p "$S/home3"
# shellcheck disable=SC2088
HOME="$S/home3" HANDOFF_KEY_DIR='~/kd' bash ../agent-setup.sh >/dev/null 2>&1 \
  && [ -f "$S/home3/kd/handoff-priv.pem" ] || fail "HANDOFF_KEY_DIR='~/kd' did not land in \$HOME/kd"
mkdir -p "$S/home4"
HOME="$S/home4" HANDOFF_KEY_DIR='~' bash ../agent-setup.sh >/dev/null 2>&1 \
  && [ -f "$S/home4/handoff-priv.pem" ] || fail "HANDOFF_KEY_DIR='~' did not land in \$HOME"
# shellcheck disable=SC2088
expect_refusal "~user in --fingerprint's KEY" 1 "agent-setup.sh: KEY '~root/k.pem'" \
  bash ../agent-setup.sh --fingerprint '~root/k.pem'
expect_refusal "--check twice" 1 "--check given twice" \
  consume --label example --check --check --blob-file blob.txt
expect_refusal "blob file missing" 1 "No such file or directory" \
  consume --label example --check --blob-file "$S/no-such-blob.txt"
# A blob file saved with a byte-order mark still works.
printf '\357\273\277' > "$S/bom.txt"; cat blob.txt >> "$S/bom.txt"
consume --label example --check --blob-file "$S/bom.txt" >/dev/null || fail "a blob file with a BOM was refused"
# OpenSSL 4 passes the gate (a wrapper that reports 4.0.0 and passes the rest on).
mkdir -p "$S/ssl4"; ln -sf "$PY" "$S/ssl4/python3"
# shellcheck disable=SC2016  # $1 and $@ belong to the generated script
printf '#!/bin/sh\nif [ "$1" = version ]; then echo "OpenSSL 4.0.0 1 Jan 2027"; else exec %s "$@"; fi\n' "$(command -v openssl)" > "$S/ssl4/openssl"
chmod 755 "$S/ssl4/openssl"
PATH="$S/ssl4" python3 ../consume.py --label example --check --blob-file blob.txt >/dev/null \
  || fail "consume.py refused OpenSSL 4"
expect_refusal "agent-setup.sh, not OpenSSL 3 or 4" 1 "requires OpenSSL 3 or 4" \
  env PATH="$S/fake-ssl:/usr/bin:/bin" bash ../agent-setup.sh --fingerprint
[ "$(uname -s)" = Darwin ] || ! grep -q Homebrew "$S/err" || fail "the macOS hint showed off macOS"
# Run as ./consume.py, the helper is isolated: a planted sitecustomize on
# PYTHONPATH doesn't run.
mkdir -p "$S/pp"
printf 'open(%s, "w").close()\n' "'$S/pp/HIT'" > "$S/pp/sitecustomize.py"
# Through sh, which is what a #!/bin/sh launch does, so the test doesn't
# need the execute bit.
PYTHONPATH="$S/pp" sh ../consume.py --label example --check --blob-file blob.txt >/dev/null 2>"$S/launch-err" \
  || fail "consume.py's sh launcher failed to run"
[ ! -e "$S/pp/HIT" ] || fail "consume.py's launcher ran the caller's sitecustomize (not isolated)"
# ...and silent: a reformatted line 2 (""" ":) makes sh print an error on
# every run while still working.
[ ! -s "$S/launch-err" ] || fail "consume.py's launcher wrote to stderr: $(cat "$S/launch-err")"
# The OpenSSL 4 wrapper passes agent-setup.sh's and handoff.sh's gates too.
[ "$(PATH="$S/ssl4:/usr/bin:/bin" bash ../agent-setup.sh --fingerprint 2>/dev/null)" = "$want" ] \
  || fail "agent-setup.sh refused OpenSSL 4"
[ "$(PATH="$S/ssl4:/usr/bin:/bin" bash "$S/handoff-dummy.sh" --fingerprint)" = "$want" ] \
  || fail "handoff.sh refused OpenSSL 4"
expect_refusal "agent-setup.sh generation, not OpenSSL 3 or 4" 1 "requires OpenSSL 3 or 4" \
  env PATH="$S/fake-ssl:/usr/bin:/bin" HANDOFF_KEY_DIR="$S/libressl-key" bash ../agent-setup.sh
[ "$(uname -s)" = Darwin ] || ! grep -q Homebrew "$S/err" || fail "the macOS hint showed off macOS"
[ ! -e "$S/libressl-key" ] || fail "agent-setup.sh created a key directory under LibreSSL"
mkdir -p "$S/libressl"
printf '#!/bin/sh\necho "LibreSSL 3.8.2"\n' > "$S/libressl/openssl"; chmod 755 "$S/libressl/openssl"
expect_refusal "handoff.sh, not OpenSSL 3 or 4" 1 "requires OpenSSL 3 or 4" \
  env PATH="$S/libressl:/usr/bin:/bin" bash "$S/handoff-dummy.sh" --fingerprint
[ "$(uname -s)" = Darwin ] || ! grep -q Homebrew "$S/err" || fail "the macOS hint showed off macOS"
expect_refusal "handoff.sh encrypting, not OpenSSL 3 or 4" 1 "requires OpenSSL 3 or 4" \
  env PATH="$S/libressl:/usr/bin:/bin" bash "$S/handoff-dummy.sh" <<<'{"svc":"example","password":"mk-Zq9"}'
[ "$(uname -s)" = Darwin ] || ! grep -q Homebrew "$S/err" || fail "the macOS hint showed off macOS"
# An openssl version that fails silently is reported, not a bare exit.
mkdir -p "$S/silent-ssl"; ln -sf "$PY" "$S/silent-ssl/python3"
printf '#!/bin/sh\nexit 1\n' > "$S/silent-ssl/openssl"; chmod 755 "$S/silent-ssl/openssl"
expect_refusal "agent-setup.sh, openssl version fails silently" 1 "openssl version failed" \
  env PATH="$S/silent-ssl:/usr/bin:/bin" bash ../agent-setup.sh --fingerprint
expect_refusal "handoff.sh, openssl version fails silently" 1 "openssl version failed" \
  env PATH="$S/silent-ssl:/usr/bin:/bin" bash "$S/handoff-dummy.sh" --fingerprint
# handoff.sh runs in the user's shell, so its hint doesn't mention wrappers.
expect_refusal "handoff.sh hint off wrappers" 1 "Put one first on your PATH" \
  env PATH="$S/libressl:/usr/bin:/bin" bash "$S/handoff-dummy.sh" --fingerprint
! grep -q "wrapper" "$S/err" || fail "handoff.sh's hint mentions wrappers"
# An openssl version that prints nothing but exits 0: "no version output",
# in all three scripts.
mkdir -p "$S/empty-ssl"; ln -sf "$PY" "$S/empty-ssl/python3"
printf '#!/bin/sh\nexit 0\n' > "$S/empty-ssl/openssl"; chmod 755 "$S/empty-ssl/openssl"
expect_refusal "agent-setup.sh, empty openssl version" 1 "found: no version output" \
  env PATH="$S/empty-ssl:/usr/bin:/bin" bash ../agent-setup.sh --fingerprint
expect_refusal "handoff.sh, empty openssl version" 1 "found: no version output" \
  env PATH="$S/empty-ssl:/usr/bin:/bin" bash "$S/handoff-dummy.sh" --fingerprint
expect_refusal "consume.py, empty openssl version" 1 "found: no version output" \
  env PATH="$S/empty-ssl" python3 ../consume.py --label example --check --blob-file blob.txt
# openssl's error text: silent (no reason, no traceback), the readable line
# picked over openssl's hex-prefixed internal lines, the first of two
# readable lines, and a long line cut short.
mkdir -p "$S/reason-ssl"; ln -sf "$PY" "$S/reason-ssl/python3"
printf '#!/bin/sh\nexit 1\n' > "$S/reason-ssl/openssl"; chmod 755 "$S/reason-ssl/openssl"
expect_refusal "consume.py, openssl version fails silently" 1 "openssl version failed" \
  env PATH="$S/reason-ssl" python3 ../consume.py --label example --check --blob-file blob.txt
grep -qx "consume.py: openssl version failed" "$S/err" || fail "a silent openssl failure got a reason: $(cat "$S/err")"
printf '#!/bin/sh\nprintf "00AB12CD:error:0A000086:SSL routines::internal\\nfirst readable reason\\nsecond readable reason\\n" >&2\nexit 1\n' > "$S/reason-ssl/openssl"
expect_refusal "consume.py, openssl's readable line" 1 "openssl version failed: first readable reason" \
  env PATH="$S/reason-ssl" python3 ../consume.py --label example --check --blob-file blob.txt
# Only openssl's internal lines: the last one is shown.
printf '#!/bin/sh\nprintf "00AB12CD:error:first internal\\n00AB12CD:error:second internal\\n" >&2\nexit 1\n' > "$S/reason-ssl/openssl"
expect_refusal "consume.py, only internal openssl lines" 1 "openssl version failed: 00AB12CD:error:second internal" \
  env PATH="$S/reason-ssl" python3 ../consume.py --label example --check --blob-file blob.txt
printf '#!/bin/sh\nhead -c 5000 /dev/zero | tr "\\0" x >&2\nexit 1\n' > "$S/reason-ssl/openssl"
expect_refusal "consume.py, a long openssl error" 1 "openssl version failed: xxx" \
  env PATH="$S/reason-ssl:/usr/bin:/bin" python3 ../consume.py --label example --check --blob-file blob.txt
[ "$(wc -c < "$S/err")" -lt 400 ] || fail "a long openssl error came back whole ($(wc -c < "$S/err") bytes)"
# On macOS the hint names Homebrew's openssl@3: OSTYPE (which bash takes
# from the environment) and sys.platform are faked to say darwin.
ln -sf "$PY" "$S/libressl/python3"
expect_refusal "agent-setup.sh hint on macOS" 1 "on macOS, Homebrew's openssl@3" \
  env PATH="$S/libressl:/usr/bin:/bin" OSTYPE=darwin23 bash ../agent-setup.sh --fingerprint
expect_refusal "handoff.sh hint on macOS" 1 "on macOS, Homebrew's openssl@3" \
  env PATH="$S/libressl:/usr/bin:/bin" OSTYPE=darwin23 bash "$S/handoff-dummy.sh" --fingerprint
expect_refusal "consume.py hint on macOS" 1 "on macOS, Homebrew's openssl@3" \
  env PATH="$S/libressl" python3 -I -c '
import sys
sys.platform = "darwin"
sys.argv = ["consume.py", "--label", "example", "--check", "--blob-file", "blob.txt"]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
'

# shellcheck disable=SC2088
expect_refusal "agent-setup.sh, ~ without HOME" 1 "a ~ in HANDOFF_KEY_DIR needs it" \
  env -u HOME HANDOFF_KEY_DIR='~/kd' bash ../agent-setup.sh
expect_refusal "consume.py default key without HOME" 1 "the default key path needs it" \
  env -u HOME -u HANDOFF_PRIVKEY python3 ../consume.py --label example --check --blob-file blob.txt
# A key at the default location isn't reported as non-default, even with a
# trailing slash on HOME.
for h in "$S/home5" "$S/home6/"; do
  mkdir -p "$h"
  env -u HANDOFF_KEY_DIR HOME="$h" bash ../agent-setup.sh >"$S/setup-out" 2>/dev/null \
    || fail "agent-setup.sh at the default location failed (HOME=$h)"
  ! grep -q "non-default" "$S/setup-out" || fail "the default location was reported as non-default (HOME=$h)"
done
# A blob file that isn't a regular file (a pipe on stdin) would take the
# command's stdin: refused.
expect_refusal "blob file on a pipe" 1 "is not a regular file" \
  bash -c 'cat blob.txt | python3 ../consume.py --label example --check --blob-file /dev/stdin'
# Devices and an empty path are refused (the FIFO test below checks the
# refusal comes before any open).
expect_refusal "blob file is a device" 1 "is not a regular file" \
  consume --label example --check --blob-file /dev/null
expect_refusal "empty --blob-file" 1 "--blob-file is empty" \
  consume --label example --check --blob-file ''
# ...and refused without being opened: a writer blocked opening a FIFO is
# released only if the helper opens the read end.
mkfifo "$S/probe.fifo"
( exec 3>"$S/probe.fifo"; touch "$S/fifo-released" ) &
writer=$!
expect_refusal "blob file is a FIFO with a writer waiting" 1 "is not a regular file" \
  timeout 20 python3 ../consume.py --label example --check --blob-file "$S/probe.fifo"
sleep 0.3
released=no; [ ! -e "$S/fifo-released" ] || released=yes
kill "$writer" 2>/dev/null || true; wait "$writer" 2>/dev/null || true
[ "$released" = no ] || fail "the helper opened the FIFO before refusing it"
# A caller's OPENSSL_CONF doesn't reach the helper's own openssl (it could
# load a provider module into the process that reads the private key).
printf 'openssl_conf = init\n[init]\nproviders = prov\n[prov]\nevil = evil\n[evil]\nmodule = %s/no-such-provider.so\nactivate = 1\n' "$S" > "$S/evil.cnf"
OPENSSL_CONF="$S/evil.cnf" consume --label example --check --blob-file blob.txt >"$S/out" 2>"$S/err" \
  || fail "a caller's OPENSSL_CONF reached the helper's openssl: $(cat "$S/err")"
# No OPENSSL_* variable, in any case, reaches the helper's openssl: a fake
# openssl first on PATH fails if it sees one, and passes the rest on.
mkdir -p "$S/ssl-env"; ln -sf "$PY" "$S/ssl-env/python3"
# Absolute paths inside the fake: it runs with only $S/ssl-env on PATH.
printf '#!/bin/sh\nif %s | %s -qi "^openssl_"; then echo "OPENSSL_ variable reached openssl" >&2; exit 9; fi\nexec %s "$@"\n' \
  "$(command -v env)" "$(command -v grep)" "$(command -v openssl)" > "$S/ssl-env/openssl"
chmod 755 "$S/ssl-env/openssl"
env PATH="$S/ssl-env" OPENSSL_MODULES="$S/nowhere" openssl_x=1 python3 ../consume.py --label example --check --blob-file blob.txt >/dev/null 2>"$S/err" \
  || fail "an OPENSSL_* variable reached the helper's openssl: $(cat "$S/err")"
# agent-setup.sh and handoff.sh drop every OPENSSL_* variable too, in any
# case: through the fake openssl that fails on one...
[ "$(env PATH="$S/ssl-env:/usr/bin:/bin" OPENSSL_MODULES="$S/nowhere" openssl_x=1 bash ../agent-setup.sh --fingerprint 2>/dev/null)" = "$want" ] \
  || fail "an OPENSSL_* variable reached agent-setup.sh's openssl"
[ "$(env PATH="$S/ssl-env:/usr/bin:/bin" OPENSSL_MODULES="$S/nowhere" openssl_x=1 bash "$S/handoff-dummy.sh" --fingerprint 2>/dev/null)" = "$want" ] \
  || fail "an OPENSSL_* variable reached handoff.sh's openssl"
# ...and a caller's OPENSSL_CONF that would break them.
[ "$(OPENSSL_CONF="$S/evil.cnf" bash ../agent-setup.sh --fingerprint 2>/dev/null)" = "$want" ] \
  || fail "a caller's OPENSSL_CONF reached agent-setup.sh's openssl"
[ "$(OPENSSL_CONF="$S/evil.cnf" bash "$S/handoff-dummy.sh" --fingerprint)" = "$want" ] \
  || fail "a caller's OPENSSL_CONF reached handoff.sh's openssl"
# The fstat re-check: a path that passed the stat check but is a FIFO by the
# time it's opened (os.stat patched to report a regular file) is still
# refused, without hanging (O_NONBLOCK).
mkfifo "$S/swap.fifo"
expect_refusal "blob file swapped to a FIFO after the stat check" 1 "is not a regular file" \
  timeout 20 python3 -I -c '
import os, sys
regular, fifo = sys.argv[1], sys.argv[2]
real_stat = os.stat
hits = {"stat": 0, "open": 0}
def fake_stat(p, *a, **k):
    if p == fifo:
        hits["stat"] += 1
        return real_stat(regular, *a, **k)
    return real_stat(p, *a, **k)
os.stat = fake_stat
real_open = os.open
def counting_open(p, *a, **k):
    if p == fifo:
        hits["open"] += 1
    return real_open(p, *a, **k)
os.open = counting_open
sys.argv = ["consume.py", "--label", "example", "--check", "--blob-file", fifo]
import atexit
# The patch must have been hit and the FIFO opened, or the test proves
# nothing about the fstat re-check (a refactor to lstat, say).
atexit.register(lambda: hits["stat"] and hits["open"] or os._exit(7))
src = open("../consume.py").read()
exec(compile(src, "consume.py", "exec"), {"__name__": "__main__"})
' blob.txt "$S/swap.fifo"
# The same swap to a terminal: the helper, a session leader with no
# controlling terminal (setsid), opens the blob file with O_NOCTTY, so a
# terminal swapped in after the stat check is refused without becoming its
# controlling terminal (which /dev/tty would then open).
if command -v setsid >/dev/null && [ -e /dev/ptmx ]; then
  expect_refusal "blob file swapped to a terminal after the stat check" 1 "is not a regular file" \
    timeout 20 setsid -w python3 -I -c '
import atexit, os, pty, sys
regular = sys.argv[1]
master, slave = pty.openpty()
tty = os.ttyname(slave)
os.close(slave)
real_stat = os.stat
hits = {"stat": 0, "open": 0}
def fake_stat(p, *a, **k):
    if p == tty:
        hits["stat"] += 1
        return real_stat(regular, *a, **k)
    return real_stat(p, *a, **k)
os.stat = fake_stat
real_open = os.open
def counting_open(p, *a, **k):
    if p == tty:
        hits["open"] += 1
    return real_open(p, *a, **k)
os.open = counting_open
def check():
    if not (hits["stat"] and hits["open"]):
        os._exit(7)  # the swap never happened: the test proves nothing
    try:
        os.close(real_open("/dev/tty", os.O_RDONLY | os.O_NOCTTY))
    except OSError:
        return  # no controlling terminal, as it should be
    sys.stderr.write("the blob-file open took a controlling terminal\n")
    sys.stderr.flush()
    os._exit(8)
atexit.register(check)
sys.argv = ["consume.py", "--label", "example", "--check", "--blob-file", tty]
src = open("../consume.py").read()
exec(compile(src, "consume.py", "exec"), {"__name__": "__main__"})
' blob.txt
else
  echo "skip: setsid or /dev/ptmx missing, the O_NOCTTY check didn't run"
fi
# A FIFO with no writer is refused, not waited on (timeout catches a hang).
mkfifo "$S/blob.fifo"
expect_refusal "blob file is a FIFO" 1 "is not a regular file" \
  timeout 20 python3 ../consume.py --label example --check --blob-file "$S/blob.fifo"
# openssl output that isn't UTF-8 is a clean refusal, not a traceback.
printf '#!/bin/sh\nprintf "bad \\351 byte\\n" >&2\nexit 1\n' > "$S/fake-ssl/openssl"
expect_refusal "openssl version, undecodable stderr" 1 "openssl version failed" \
  env PATH="$S/fake-ssl" python3 ../consume.py --label example --check --blob-file blob.txt
printf '#!/bin/sh\necho "openssl: error loading config" >&2\nexit 1\n' > "$S/fake-ssl/openssl"
expect_refusal "openssl version failing" 1 "openssl version failed: openssl: error loading config" \
  env PATH="$S/fake-ssl" python3 ../consume.py --label example --check --blob-file blob.txt
expect_refusal "agent-setup.sh re-run over an existing key" 1 "refusing to overwrite existing key" \
  env HANDOFF_KEY_DIR="$S/agent" bash ../agent-setup.sh
# Its hint names the key to rotate: HANDOFF_KEY_DIR doesn't apply to --rotate.
grep -qF "run HANDOFF_PRIVKEY=$S/agent/handoff-priv.pem agent-setup.sh --rotate" "$S/err" \
  || fail "the overwrite refusal's hint doesn't name the key to rotate"
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
# Only the first openssl stage's error (it reads the file) and "could not
# read key": the next stage reads stdin, so an error naming stdin means it
# ran too. (Checked by content, not line count: OpenSSL 3.0 repeats a line.)
! grep -qi "stdin" "$S/err" || fail "--fingerprint on a public key printed the second openssl stage's error too"
long=$(python3 -c 'import json; print(json.dumps({"svc": "example", "password": "mk-Zq9" + "x" * 154}, separators=(",", ":")), end="")')
[ "${#long}" = 191 ] || fail "test setup: oversize payload is ${#long} bytes, not 191"
expect_refusal "handoff.sh 191-byte payload" 1 "payload is 191 bytes" \
  bash "$S/handoff-dummy.sh" <<<"$long"
if command -v jq >/dev/null; then
  expect_refusal "handoff.sh non-object payload" 1 "must be a single JSON object" \
    bash "$S/handoff-dummy.sh" <<<'["mk-Zq9"]'
  expect_refusal "handoff.sh two concatenated objects" 1 "must be a single JSON object" \
    bash "$S/handoff-dummy.sh" <<<'{"svc":"example","password":"mk-Zq9"}{"svc":"example"}'
  expect_refusal "handoff.sh payload without svc" 1 "must be a single JSON object" \
    bash "$S/handoff-dummy.sh" <<<'{"password":"mk-Zq9"}'
else
  echo "skip: jq not installed, handoff.sh shape refusals not tested"
fi
rc=0; bash ../handoff.sh --fingerprint >"$S/out" 2>/dev/null || rc=$?
[ "$rc" != 0 ] && [ ! -s "$S/out" ] \
  || fail "handoff.sh --fingerprint with the placeholder key: exit $rc, stdout $(cat "$S/out")"
echo "ok (refused: handoff.sh --fingerprint with the placeholder key)"

echo "== 6. rotation: --rotate, the previous key, --rewrap, --retire =="
# A copy of the dummy key, so blob.txt is a blob made for the key that
# --rotate turns into the previous one.
R="$S/rot"; mkdir -p "$R"
cp "$TMPKEY" "$R/k.pem"
rk() { env HANDOFF_PRIVKEY="$R/k.pem" "$@"; }
rk bash ../agent-setup.sh --rotate >"$R/out" 2>"$R/err" || { cat "$R/err" >&2; fail "--rotate failed"; }
if [ ! -f "$R/k.pem.previous" ] || [ "$R/k.pem.previous" -ef "$R/k.pem" ]; then
  fail "--rotate didn't leave the old key as k.pem.previous beside a new k.pem"
fi
[ "$(stat -c %a "$R/k.pem")" = 600 ] || fail "the rotated key is not mode 600"
old_fp=$(rk bash ../agent-setup.sh --fingerprint "$R/k.pem.previous" 2>/dev/null)
[ "$old_fp" = "$want" ] || fail "k.pem.previous is not the old key"
new_fp=$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)
[ "$new_fp" != "$want" ] || fail "--rotate kept the old key as the current one"
grep -qxF "new public key fingerprint: $new_fp" "$R/out" || fail "--rotate printed another fingerprint than the new key's"
# The new public key it prints is the one handoff.sh embeds.
sed -n '/-----BEGIN PUBLIC KEY-----/,/-----END PUBLIC KEY-----/p' "$R/out" > "$R/pub.pem"
embed_pub "$R/pub.pem" "$R/handoff.sh"
[ "$(bash "$R/handoff.sh" --fingerprint)" = "$new_fp" ] || fail "--rotate's public key isn't the new key's"
! compgen -G "$R/.handoff-new*" >/dev/null || fail "--rotate left a temporary key file"
# An old blob still opens, through the previous key; run mode says to rewrap it.
rk python3 ../consume.py --label example --check --blob-file blob.txt >"$R/out" 2>"$R/err"
diff "$R/out" expected-check.txt || fail "--check through the previous key differs"
out=$(rk python3 ../consume.py --label example --blob-file blob.txt -- python3 -c '
import os
print(os.environ["SERVICE_PASSWORD"])
' 2>"$R/err")
[ "$out" = "$P" ] || fail "an old blob didn't run through the previous key"
grep -qF "label 'example' decrypted with the previous key; rewrap it" "$R/err" || fail "run mode didn't say to rewrap: $(cat "$R/err")"
no_dummy_in "$R/err"
# --rewrap prints a new blob for the current key, and only that.
rk python3 ../consume.py --label example --rewrap --blob-file blob.txt >"$R/new.txt" 2>"$R/err"
grep -qxF "consume.py: rewrapped to the current key $R/k.pem; the blob was for the previous key ($R/k.pem.previous)" "$R/err" || fail "--rewrap didn't say the blob was for the previous key, naming both: $(cat "$R/err")"
if [ "$(wc -l < "$R/new.txt")" != 1 ] || ! grep -qxE '[A-Za-z0-9+/]{342}==' "$R/new.txt"; then
  fail "--rewrap printed something other than one blob"
fi
no_dummy_in "$R/new.txt" "$R/err"
# The new blob opens with the current key alone, to the same payload.
mv "$R/k.pem.previous" "$R/held.pem"
rk python3 ../consume.py --label example --check --blob-file "$R/new.txt" >"$R/out" \
  || fail "the rewrapped blob doesn't open with the current key"
diff "$R/out" expected-check.txt || fail "the rewrapped payload differs"
out=$(rk python3 ../consume.py --label example --blob-file "$R/new.txt" -- python3 -c '
import os
print(os.environ["SERVICE_USERNAME"], os.environ["SERVICE_PASSWORD"])
')
[ "$out" = "$U $P" ] || fail "the rewrapped blob's values differ"
mv "$R/held.pem" "$R/k.pem.previous"
rk python3 ../consume.py --label example --rewrap --blob-file "$R/new.txt" >/dev/null 2>"$R/err"
grep -qxF "consume.py: rewrapped to the current key $R/k.pem; the blob was for the current key ($R/k.pem)" "$R/err" || fail "--rewrap of a current blob didn't say so"
# A blob made for neither key (for 4b's freshly generated one): one message,
# nothing about which key failed or why.
enc_other() { printf '%s' "$1" | openssl pkeyutl -encrypt -pubin -inkey "$S/agent-pub.pem" \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 | openssl base64 -A; }
expect_refusal "a blob for neither key" 1 "decryption failed with the current key and with the previous key" \
  rk python3 ../consume.py --label example --check --blob "$(enc_other '{"svc":"example","password":"mk-Zq9"}')"
! grep -q "Public Key operation\|error" "$S/err" || fail "the two-key refusal shows openssl's reason"
# The previous key is held to the current key's rules.
chmod 644 "$R/k.pem.previous"
expect_refusal "a group-readable previous key" 1 "k.pem.previous is mode 644" \
  rk python3 ../consume.py --label example --check --blob-file blob.txt
chmod 600 "$R/k.pem.previous"
cp "$S/ed25519.pem" "$R/ed.pem"
mv "$R/k.pem.previous" "$R/held.pem"; ln -s "$R/ed.pem" "$R/k.pem.previous"
expect_refusal "a previous key that isn't RSA-2048" 1 "k.pem.previous is not an RSA-2048 key" \
  rk python3 ../consume.py --label example --check --blob-file blob.txt
rm "$R/k.pem.previous"; mv "$R/held.pem" "$R/k.pem.previous"
# A blob the current key opens never reaches the previous key: a broken
# previous key doesn't matter then.
chmod 644 "$R/k.pem.previous"
rk python3 ../consume.py --label example --check --blob-file "$R/new.txt" >/dev/null \
  || fail "a current blob was refused over the previous key"
chmod 600 "$R/k.pem.previous"
# --rewrap is refused with anything that changes the payload or runs a command.
expect_refusal "--rewrap with --check" 1 "--check and --rewrap can't be combined" \
  rk python3 ../consume.py --label example --rewrap --check --blob-file blob.txt
expect_refusal "--rewrap with a command" 1 "--rewrap takes no command" \
  rk python3 ../consume.py --label example --rewrap --blob-file blob.txt -- true
expect_refusal "--rewrap with --env" 1 "--rewrap takes no --env" \
  rk python3 ../consume.py --label example --rewrap --env password=APP_PASS --blob-file blob.txt
expect_refusal "--rewrap twice" 1 "--rewrap given twice" \
  rk python3 ../consume.py --label example --rewrap --rewrap --blob-file blob.txt
expect_refusal "--rewrap, purpose mismatch" 1 "purpose mismatch" \
  rk python3 ../consume.py --label other --rewrap --blob-file blob.txt
# --rewrap checks its new blob opens with the current key before printing
# it: an openssl whose -encrypt output is 256 random bytes is caught.
mkdir -p "$S/badenc"; ln -sf "$PY" "$S/badenc/python3"
# shellcheck disable=SC2016  # $@ belongs to the generated script
printf '#!/bin/sh\nfor a; do [ "$a" = -encrypt ] && { cat >/dev/null; head -c 256 /dev/urandom; exit 0; }; done\nexec %s "$@"\n' "$(command -v openssl)" > "$S/badenc/openssl"
chmod 755 "$S/badenc/openssl"
expect_refusal "--rewrap whose new blob doesn't open" 1 "the new blob doesn't open with the current key" \
  rk env PATH="$S/badenc:/usr/bin:/bin" python3 ../consume.py --label example --rewrap --blob-file blob.txt
# The self-check compares payloads, not just that the new blob opens: an
# openssl whose -encrypt encrypts another valid payload is caught too.
mkdir -p "$S/swapenc"; ln -sf "$PY" "$S/swapenc/python3"
# shellcheck disable=SC2016  # $a and $@ belong to the generated script
printf '#!/bin/sh\nfor a; do [ "$a" = -encrypt ] && { cat >/dev/null; printf %%s %s | %s "$@"; exit $?; }; done\nexec %s "$@"\n' \
  "'{\"svc\":\"example\",\"password\":\"mk-Zq9-other\"}'" "$(command -v openssl)" "$(command -v openssl)" > "$S/swapenc/openssl"
chmod 755 "$S/swapenc/openssl"
expect_refusal "--rewrap whose new blob opens to another payload" 1 "to the same payload" \
  rk env PATH="$S/swapenc:/usr/bin:/bin" python3 ../consume.py --label example --rewrap --blob-file blob.txt
# A new blob that can't be written is a refusal, not a "rewrapped" line.
if [ -w /dev/full ]; then
  rc=0; rk python3 ../consume.py --label example --rewrap --blob-file blob.txt >/dev/full 2>"$R/err" || rc=$?
  [ "$rc" = 1 ] || { cat "$R/err" >&2; fail "--rewrap to a full disk: exit $rc, expected 1"; }
  grep -qF "could not write the new blob" "$R/err" || fail "--rewrap to a full disk didn't say so"
  ! grep -qF "rewrapped" "$R/err" || fail "--rewrap reported success to a full disk"
  ! grep -q Traceback "$R/err" || fail "--rewrap to a full disk: traceback"
  echo "ok (refused: --rewrap to a full disk)"
else
  echo "skip: no writable /dev/full, the rewrap write failure wasn't tested"
fi
# One rotation at a time: during one, --rotate rotates nothing, exits 0, and
# shows the current (new) key's public key and fingerprint again.
rc=0; rk bash ../agent-setup.sh --rotate >"$R/out" 2>"$R/err" || rc=$?
[ "$rc" = 0 ] || fail "--rotate during a rotation: exit $rc, expected 0 (it only shows the key)"
if ! grep -qF "a rotation is under way" "$R/err" || ! grep -qF "nothing rotated" "$R/err"; then
  fail "--rotate during a rotation didn't say so"
fi
grep -qxF "current (new) public key fingerprint: $new_fp" "$R/out" || fail "--rotate during a rotation didn't show the new key's fingerprint"
grep -qF -- "-----BEGIN PUBLIC KEY-----" "$R/out" || fail "--rotate during a rotation didn't show the new public key"
[ "$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)" = "$new_fp" ] || fail "a refused --rotate changed the key"
# A symlinked key path is refused by --rotate and --retire.
ln -s "$R/k.pem" "$R/link.pem"
expect_refusal "--rotate through a symlink" 1 "is a symlink" \
  env HANDOFF_PRIVKEY="$R/link.pem" bash ../agent-setup.sh --rotate
expect_refusal "--retire through a symlink" 1 "is a symlink" \
  env HANDOFF_PRIVKEY="$R/link.pem" bash ../agent-setup.sh --retire
[ -e "$R/k.pem.previous" ] || fail "a refused --retire deleted the previous key"
rm "$R/link.pem"
# --retire deletes the previous key; old blobs stop opening, new ones don't.
rk bash ../agent-setup.sh --retire >"$R/out" 2>"$R/err" || { cat "$R/err" >&2; fail "--retire failed"; }
[ ! -e "$R/k.pem.previous" ] || fail "--retire left the previous key"
expect_refusal "an old blob after --retire" 1 "decryption failed" \
  rk python3 ../consume.py --label example --check --blob-file blob.txt
rk python3 ../consume.py --label example --check --blob-file "$R/new.txt" >/dev/null || fail "the rewrapped blob stopped opening after --retire"
expect_refusal "--retire with no rotation" 1 "no rotation to retire" \
  rk bash ../agent-setup.sh --retire
# An interrupted --rotate (stopped after keeping the old key, before the new
# one replaced it): both names are the old key. --retire refuses, and a
# re-run of --rotate finishes it.
ln "$R/k.pem" "$R/k.pem.previous"
expect_refusal "--retire before an interrupted rotation finished" 1 "the rotation didn't finish" \
  rk bash ../agent-setup.sh --retire
[ -e "$R/k.pem.previous" ] || fail "a refused --retire deleted the previous key"
rk bash ../agent-setup.sh --rotate >"$R/out" 2>"$R/err" || { cat "$R/err" >&2; fail "a re-run --rotate failed"; }
grep -qF "resuming an interrupted rotation" "$R/err" || fail "a re-run --rotate didn't say it resumed"
[ ! "$R/k.pem.previous" -ef "$R/k.pem" ] || fail "a re-run --rotate didn't make a new key"
[ "$(rk bash ../agent-setup.sh --fingerprint "$R/k.pem.previous" 2>/dev/null)" = "$new_fp" ] \
  || fail "a re-run --rotate lost the key it was rotating from"
rk bash ../agent-setup.sh --retire >/dev/null 2>&1 || fail "--retire after the resumed rotation failed"
# A key generation that fails leaves the old key in place and no temporary
# file: a fake openssl that fails genpkey and passes everything else on.
mkdir -p "$S/nogen"; ln -sf "$PY" "$S/nogen/python3"
# shellcheck disable=SC2016  # $1 and $@ belong to the generated script
printf '#!/bin/sh\nif [ "$1" = genpkey ]; then echo "genpkey: simulated failure" >&2; exit 1; fi\nexec %s "$@"\n' "$(command -v openssl)" > "$S/nogen/openssl"
chmod 755 "$S/nogen/openssl"
before=$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)
expect_refusal "--rotate whose key generation fails" 1 "key generation failed; the old key is unchanged" \
  rk env PATH="$S/nogen:/usr/bin:/bin" bash ../agent-setup.sh --rotate
[ "$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)" = "$before" ] || fail "a failed --rotate changed the current key"
! compgen -G "$R/.handoff-new*" >/dev/null || fail "a failed --rotate left a temporary key file"
# It did keep the old key as the previous one: a re-run resumes from there.
[ "$R/k.pem.previous" -ef "$R/k.pem" ] || fail "a failed --rotate didn't leave the resumable state"
rm "$R/k.pem.previous"
expect_refusal "--rotate with no key" 1 "no key file at" \
  env HANDOFF_PRIVKEY="$R/none.pem" bash ../agent-setup.sh --rotate
expect_refusal "--rotate, two keys" 2 "usage: agent-setup.sh --rotate" \
  bash ../agent-setup.sh --rotate "$R/k.pem" "$R/k.pem"
# A key generation that exits 0 after a short write (a full disk) is caught
# before it replaces anything, in --rotate and at first setup.
mkdir -p "$S/shortgen"; ln -sf "$PY" "$S/shortgen/python3"
# shellcheck disable=SC2016  # $1, $a and $@ belong to the generated script
printf '#!/bin/sh\nif [ "$1" = genpkey ]; then prev=; for a; do [ "$prev" = -out ] && head -c 1024 /dev/zero > "$a"; prev=$a; done; exit 0; fi\nexec %s "$@"\n' "$(command -v openssl)" > "$S/shortgen/openssl"
chmod 755 "$S/shortgen/openssl"
before=$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)
expect_refusal "--rotate whose genpkey writes a short file" 1 "the new key didn't check out" \
  rk env PATH="$S/shortgen:/usr/bin:/bin" bash ../agent-setup.sh --rotate
[ "$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)" = "$before" ] || fail "a short genpkey write replaced the current key"
! compgen -G "$R/.handoff-new*" >/dev/null || fail "a short genpkey write left a temporary key file"
openssl pkey -in "$R/k.pem" -pubout -out "$R/cur-pub.pem" 2>/dev/null
cur_blob=$(printf '%s' '{"svc":"example","password":"mk-Zq9-cur"}' | openssl pkeyutl -encrypt -pubin -inkey "$R/cur-pub.pem" \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 | openssl base64 -A)
rk python3 ../consume.py --label example --check --blob "$cur_blob" >/dev/null || fail "the current key stopped working after a short genpkey write"
rm "$R/k.pem.previous"
expect_refusal "first setup whose genpkey writes a short file" 1 "nothing was written" \
  env PATH="$S/shortgen:/usr/bin:/bin" HANDOFF_KEY_DIR="$S/short-setup" bash ../agent-setup.sh
[ ! -e "$S/short-setup/handoff-priv.pem" ] || fail "first setup left a short key file at the key path"
! compgen -G "$S/short-setup/.handoff-new*" >/dev/null || fail "first setup left a temporary key file"
# A failing DER export is "could not read", not "another key type".
mkdir -p "$S/noder"; ln -sf "$PY" "$S/noder/python3"
# shellcheck disable=SC2016  # $a and $@ belong to the generated script
printf '#!/bin/sh\nfor a; do [ "$a" = -pubin ] && exit 1; done\nexec %s "$@"\n' "$(command -v openssl)" > "$S/noder/openssl"
chmod 755 "$S/noder/openssl"
expect_refusal "--fingerprint whose DER export fails" 1 "could not read key" \
  rk env PATH="$S/noder:/usr/bin:/bin" bash ../agent-setup.sh --fingerprint
! grep -q "not an RSA-2048" "$S/err" || fail "a failing DER export was reported as another key type"
# --rewrap runs only during a rotation, at the key the wrappers use: with no
# previous key, or pointed at the previous key itself, it refuses.
expect_refusal "--rewrap with no rotation under way" 1 "no rotation under way at $R/k.pem" \
  rk python3 ../consume.py --label example --rewrap --blob-file "$R/new.txt"
rk bash ../agent-setup.sh --rotate >/dev/null 2>&1 || fail "--rotate for the rewrap checks failed"
expect_refusal "--rewrap pointed at the previous key" 1 "no rotation under way at $R/k.pem.previous" \
  env HANDOFF_PRIVKEY="$R/k.pem.previous" python3 ../consume.py --label example --rewrap --blob-file "$R/new.txt"
# A blob neither key opens: stop and report, never another HANDOFF_PRIVKEY.
expect_refusal "--rewrap of a blob neither key opens" 1 "stop and report it to the user" \
  rk python3 ../consume.py --label example --rewrap --blob "$(enc_other '{"svc":"example","password":"mk-Zq9"}')"
! grep -q "check that HANDOFF_PRIVKEY" "$S/err" || fail "the decrypt refusal still invites trying another key"
# --rewrap redirected onto its own --blob-file says what happened.
cp "$R/new.txt" "$R/self.txt"
rc=0
# shellcheck disable=SC2094  # reading and writing the same file is the case under test
rk python3 ../consume.py --label example --rewrap --blob-file "$R/self.txt" >"$R/self.txt" 2>"$R/err" || rc=$?
if [ "$rc" != 1 ] || ! grep -qF "redirected to its own --blob-file" "$R/err"; then
  fail "--rewrap onto its own --blob-file: exit $rc, $(cat "$R/err")"
fi
# A copied (not hard-linked) .previous holding the current key resumes and
# rotates, read by fingerprint; one holding another key is a rotation under way.
rk bash ../agent-setup.sh --retire >/dev/null 2>&1 || fail "--retire for the copy checks failed"
cur=$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)
cp -p "$R/k.pem" "$R/k.pem.previous"
rk bash ../agent-setup.sh --rotate >"$R/out" 2>"$R/err" || { cat "$R/err" >&2; fail "--rotate with a copied .previous failed"; }
grep -qF "resuming an interrupted rotation" "$R/err" || fail "a copied .previous holding the current key didn't resume"
[ "$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)" != "$cur" ] || fail "a copied .previous made --rotate rotate nothing"
[ "$(rk bash ../agent-setup.sh --fingerprint "$R/k.pem.previous" 2>/dev/null)" = "$cur" ] || fail "the copied .previous isn't the old key after --rotate"
cp -p "$R/k.pem" "$R/k.pem.previous"
expect_refusal "--retire with a .previous holding the current key" 1 "holds the current key: the rotation didn't finish" \
  rk bash ../agent-setup.sh --retire
rm "$R/k.pem.previous"; mkdir "$R/k.pem.previous"
expect_refusal "--rotate with a directory at .previous" 1 "is not a regular file" \
  rk bash ../agent-setup.sh --rotate
expect_refusal "--retire with a directory at .previous" 1 "is not a regular file" \
  rk bash ../agent-setup.sh --retire
rmdir "$R/k.pem.previous"
# One --rotate or --retire at a time: a held lock refuses, and a temporary key
# a killed run left is removed by the next one.
mkdir "$R/.handoff-lock"
expect_refusal "--rotate while another holds the lock" 1 "another --rotate or --retire is running" \
  rk bash ../agent-setup.sh --rotate
[ ! -e "$R/k.pem.previous" ] || fail "a refused --rotate made a previous key"
rmdir "$R/.handoff-lock"
printf 'leftover\n' > "$R/.handoff-new.Leftov"
rk bash ../agent-setup.sh --rotate >/dev/null 2>"$R/err" || { cat "$R/err" >&2; fail "--rotate with a leftover temporary key failed"; }
grep -qF "removed a temporary key a killed --rotate left behind: $R/.handoff-new.Leftov" "$R/err" || fail "the leftover temporary key wasn't reported"
[ ! -e "$R/.handoff-new.Leftov" ] || fail "the leftover temporary key wasn't removed"
[ ! -e "$R/.handoff-lock" ] || fail "--rotate left its lock behind"
rk bash ../agent-setup.sh --retire >/dev/null 2>&1 || fail "--retire after the lock checks failed"
[ ! -e "$R/.handoff-lock" ] || fail "--retire left its lock behind"
# A key path that starts with "-" is a path, not an option.
mkdir -p "$R/dash"; cp "$TMPKEY" "$R/dash/-k.pem"
(cd "$R/dash" && env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --rotate -k.pem >/dev/null 2>&1 \
  && env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --retire -k.pem >/dev/null 2>&1) \
  || fail "--rotate / --retire on a key path starting with - failed"
[ ! -e "$R/dash/-k.pem.previous" ] || fail "--retire on a key path starting with - left the previous key"
# --help prints the usage and exits 0.
consume --help >"$S/out" 2>&1 || fail "consume.py --help failed"
grep -qF -- "--rewrap" "$S/out" || fail "consume.py --help doesn't show the usage"
echo "ok"

echo "== 7. nesting: \$HANDOFF_LABEL =="
out=$(consume --label example --blob-file blob.txt -- python3 -c '
import os
print(os.environ["HANDOFF_LABEL"])
')
[ "$out" = example ] || fail "the command didn't get HANDOFF_LABEL=example: $out"
expect_refusal "a consume.py started by another one's command" 1 "wrappers never nest" \
  consume --label example --blob-file blob.txt -- python3 ../consume.py --label example --check --blob-file blob.txt
expect_refusal "HANDOFF_LABEL set by the caller" 1 "\$HANDOFF_LABEL is set" \
  env HANDOFF_LABEL=mk-Zq9-outer python3 ../consume.py --label example --check --blob-file blob.txt
expect_refusal "HANDOFF_LABEL set, empty" 1 "\$HANDOFF_LABEL is set" \
  env HANDOFF_LABEL= python3 ../consume.py --label example --check --blob-file blob.txt
echo "ok"

echo "ALL INTEROP CHECKS PASSED"
