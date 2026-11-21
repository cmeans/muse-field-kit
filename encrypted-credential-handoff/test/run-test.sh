#!/bin/bash
# Known-answer interop test for the encrypted credential handoff.
#
# Verifies, against the reference implementation (../consume.py,
# ../handoff.sh and ../agent-setup.sh):
#   1. decrypt direction: blob-age.txt (and blob-age-rage.txt, made by rage)
#      decrypts to expected.json's values, the
#      --check output matches expected-check.txt exactly, and the helper's
#      OWN stdout and stderr never carry a dummy value;
#   2. the command's stdin passes through consume.py untouched (a stdio
#      server's stdin is its transport; the blob must not consume it), and
#      the helper execs the command, so a TERM sent to the helper reaches
#      the command and leaves no credentialed process behind;
#   3. encrypt direction: a fresh blob produced by ../handoff.sh (with the
#      dummy recipient saved beside a scratch copy) decrypts through
#      ../consume.py to the same values;
#   4. recipients agree: agent-setup.sh --fingerprint (on the identity that
#      $HANDOFF_PRIVKEY names) prints its recipient, the dummy recipient for
#      the dummy identity, and the recipient a fresh setup prints is the one
#      handoff.sh shows for it; agent-setup.sh makes, rotates and retires
#      identities (section 6 drives it);
#   5. the refusals the docs claim, each by its exit code and message,
#      with nothing on stdout, no traceback and no dummy value in the
#      output.
#
# Section ids (the "== ID." headings): 1a 1b 1c 1d 2a 2b 3a 3b 4a 4b 5 5a 5b
# 6 7 8. HANDOFF_TEST_ONLY="3b 5a" runs only those and prints "ran: <ids>";
# unset runs them all. The age vectors (test-dummy-identity.txt,
# handoff-test.age, blob-age.txt, blob-age-rage.txt, vectors/) were made by
# make-vectors.sh, which this suite never runs. HANDOFF_TEST_AGE and
# HANDOFF_TEST_AGE_KEYGEN name the age binaries to test against.
#
# A port or variant implementation passes the interop bar by reproducing
# steps 1-2 against these vectors with its own decrypt side, and step 3
# with its own encrypt side feeding the reference decrypt side.
#
# The scripts are run through python3 / bash / sh explicitly, so the test
# doesn't depend on their execute bits surviving a download.
set -Eeuo pipefail
# Every file and directory the suite makes is private, whatever the caller's
# umask (0002 on user-private-group systems would make the store 0775, which
# --rewrap refuses, as it should).
umask 077
# A failing command substitution (got=$(...)) stops the script under set -e
# before its own check can say why: name the line instead.
# Only in the top-level shell: with set -E a failure inside $(...) would
# otherwise be reported twice.
trap '[ "$BASH_SUBSHELL" = 0 ] && echo "FAIL: line $LINENO: $BASH_COMMAND" >&2' ERR
cd "$(dirname "$0")"

# The dummy values in expected.json / blob-age.txt. Distinct on purpose: a test
# that can't tell the username from the password can't catch a swap.
U=dummy-user-Qx7
P=dummy-pass-K3z9w
# Every value the test crafts itself (enc, unknown.json) carries this marker,
# so the leak check covers them too.
MK=mk-Zq9

# consume.py refuses group/other-readable keys on principle; the repo copies
# of the dummy keys are world-readable by design (they're published
# vectors), so work on locked-down copies. The scratch directory exists
# BEFORE the trap is set: a trap that expands an unassigned variable under
# `set -u` aborts itself and leaves the key copy behind.
S=$(mktemp -d)
trap 'rm -rf "$S"' EXIT
# TMPKEY is the age identity (the dummy key).
TMPKEY="$S/dummy-identity.txt"
cp test-dummy-identity.txt "$TMPKEY"
chmod 600 "$TMPKEY"
# fake_pem KIND prints a PEM-shaped text block with a made-up body: the tests of
# 0.1.0 detection need a file that looks like a 0.1.0 key or public key, and
# nothing in the kit parses one (only the BEGIN line is looked at), so no real
# key is made or kept. KIND is the label, e.g. "RSA PRIVATE KEY".
fake_pem() {
  printf -- '-----BEGIN %s-----\nMIIBdummyDUMMYdummy0123456789+/abcdef\nDUMMYdummyDUMMYdummy0123456789+/ab==\n-----END %s-----\n' "$1" "$1"
}
# RSAKEY: a file shaped like a 0.1.0 RSA private key, owner-only.
RSAKEY="$S/dummy-priv.txt"
fake_pem "RSA PRIVATE KEY" > "$RSAKEY"
chmod 600 "$RSAKEY"
export HANDOFF_PRIVKEY="$TMPKEY"

# The age binaries the suite runs against: CI points these at a given version.
AGE=${HANDOFF_TEST_AGE:-age}
AGE_KEYGEN=${HANDOFF_TEST_AGE_KEYGEN:-age-keygen}
command -v "$AGE" >/dev/null 2>&1 || { echo "FAIL: age not found ($AGE); install it or set HANDOFF_TEST_AGE" >&2; exit 1; }
command -v "$AGE_KEYGEN" >/dev/null 2>&1 || { echo "FAIL: age-keygen not found ($AGE_KEYGEN); set HANDOFF_TEST_AGE_KEYGEN" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "FAIL: jq not found; install jq 1.6 or newer" >&2; exit 1; }
age_version=$("$AGE" --version 2>&1 | head -n 1)
echo "age: $age_version ($AGE)"
echo "jq: $(jq --version 2>&1)"

# HANDOFF_TEST_ONLY="3b 5a" runs only those sections (ids as in the
# "== ID." headings: 1a 1b 1c 1d 2a 2b 3a 3b 4a 4b 5 5a 5b 6 7 8) and prints
# "ran: <ids>" at the end; unset runs everything.
KNOWN_IDS="1a 1b 1c 1d 2a 2b 3a 3b 4a 4b 5 5a 5b 6 7 8"
# A misspelled or unknown id would otherwise select nothing and still print
# ALL INTEROP CHECKS PASSED: refuse it, and an empty selection.
if [ -n "${HANDOFF_TEST_ONLY+set}" ]; then
  n_ids=0
  # shellcheck disable=SC2086  # word splitting of the id list is the point
  for id in $HANDOFF_TEST_ONLY; do
    n_ids=$((n_ids + 1))
    case " $KNOWN_IDS " in
      *" $id "*) ;;
      *) echo "FAIL: HANDOFF_TEST_ONLY names an unknown section '$id' (known: $KNOWN_IDS)" >&2; exit 1 ;;
    esac
  done
  [ "$n_ids" -gt 0 ] || { echo "FAIL: HANDOFF_TEST_ONLY is set but names no section (known: $KNOWN_IDS)" >&2; exit 1; }
fi
RAN=
section() {
  [ -z "${HANDOFF_TEST_ONLY-}" ] || [[ " $HANDOFF_TEST_ONLY " == *" $1 "* ]] || return 1
  RAN="$RAN${RAN:+ }$1"
}

fail() { echo "FAIL: $*" >&2; exit 1; }

# Portable forms: the suite also runs on macOS, with BSD tools.
# stat_of FMT FILE prints %a (the mode, octal), %u (the owner's uid) or %i
# (the inode): GNU's stat -c first, then BSD's stat -f, where the mode is %Lp
# (as agent-setup.sh reads it).
stat_of() {
  local fmt=$1 bsd=$1
  [ "$fmt" != %a ] || bsd=%Lp
  stat -c "$fmt" -- "$2" 2>/dev/null || stat -f "$bsd" -- "$2"
}
# run_to_n SECS CMD... bounds a run that might hang: timeout (GNU coreutils),
# else gtimeout (Homebrew's coreutils on macOS, which has no timeout), else
# unbounded. A bounded run that times out exits 124. run_to is 60 seconds.
run_to_n() {
  local secs=$1; shift
  if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"
  else "$@"; fi
}
run_to() { run_to_n 60 "$@"; }
# in_pty CMD... runs CMD under a pseudo-terminal from script(1), bounded,
# stdin from /dev/null. BSD script (macOS): script -q FILE COMMAND...;
# util-linux script: script -qec STRING FILE.
in_pty() {
  if [ "$(uname -s)" = Darwin ]; then
    run_to_n 20 script -q /dev/null "$@" </dev/null
  else
    run_to_n 20 script -qec "$(printf '%q ' "$@")" /dev/null </dev/null
  fi
}

# consume runs the helper. The key is whatever $HANDOFF_PRIVKEY is: the
# suite exports the age identity (TMPKEY), and a test that names another key
# sets it on the same line (HANDOFF_PRIVKEY=X consume ...), which reaches the
# helper as written.
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

# Copy ../handoff.sh to $2, with the recipient file $1 beside it as
# handoff-muse.age (the default recipient's file).
install_handoff() {
  mkdir -p "$(dirname "$2")"
  cp ../handoff.sh "$2"
  cp "$1" "$(dirname "$2")/handoff-muse.age"
}

# Encrypt the text in $1 to the test recipient (handoff-test.age) with age,
# straight through (no validation): binary format, base64 on one line.
enc() {
  printf '%s' "$1" | "$AGE" -r "$(cat handoff-test.age)" | base64 | tr -d '\n'
}

# What the sections after 3b need from 3a: handoff.sh installed beside the
# dummy public key, the blob it wrote, and the key's fingerprint. Made on
# demand, so a section can run alone under HANDOFF_TEST_ONLY.
prep_shared() {
  [ -f "$S/hd/handoff.sh" ] || install_handoff handoff-test.age "$S/hd/handoff.sh"
  [ -s "$S/blob-3a.txt" ] || bash "$S/hd/handoff.sh" < expected.json >"$S/blob-3a.txt" 2>/dev/null
  want=$(bash "$S/hd/handoff.sh" --fingerprint 2>/dev/null)
}

# What the sections after 4b need from it: a freshly generated identity in
# $S/agent and its recipient (one line) in $S/agent-rcpt.age. 4b makes its own
# in $S/agent (and so must find none there) and saves the recipient the same
# way; the others call this.
prep_agent() {
  [ -f "$S/agent-rcpt.age" ] && return 0
  HANDOFF_KEY_DIR="$S/agent" bash ../agent-setup.sh >"$S/setup-out" 2>"$S/setup-err" \
    || { cat "$S/setup-err" >&2; fail "agent-setup.sh failed"; }
  sed -n 's/^recipient: //p' "$S/setup-out" > "$S/agent-rcpt.age"
}

if section 1a; then
echo "== 1a. reference decrypt, --check output =="
consume --label example --check --blob-file blob-age.txt >"$S/out" 2>"$S/err"
diff "$S/out" expected-check.txt || fail "--check output differs from expected-check.txt"
[ ! -s "$S/err" ] || fail "--check wrote to stderr"
no_dummy_in "$S/out"
# rage's blob carries a -grease stanza beside the X25519 one: accepted, and
# the same payload (the positive half of 5a's header tests).
consume --label example --check --blob-file blob-age-rage.txt >"$S/out" 2>"$S/err" \
  || { cat "$S/err" >&2; fail "the rage blob was refused"; }
diff "$S/out" expected-check.txt || fail "--check output differs for the rage blob"
[ ! -s "$S/err" ] || fail "--check wrote to stderr for the rage blob"
# The GitHub App fields are listed like the others (name and byte count,
# sorted by name, never a value): the output format is unchanged.
consume --label example --check --blob "$(enc '{"svc":"example","private_key":"mk-Zq9-pk-0123456789","app_id":"123456","installation_id":"7890123"}')" >"$S/out" 2>"$S/err" \
  || { cat "$S/err" >&2; fail "--check refused a private_key / app_id / installation_id payload"; }
printf "svc: matches label 'example'\napp_id: 6 bytes\ninstallation_id: 7 bytes\nprivate_key: 20 bytes\n" >"$S/expected-app.txt"
diff "$S/out" "$S/expected-app.txt" || fail "--check output for private_key, app_id and installation_id differs"
[ ! -s "$S/err" ] || fail "--check wrote to stderr for the app payload"
no_dummy_in "$S/out"
echo "ok"
fi

if section 1b; then
# The command writes what it received to a file, and prints nothing, so
# anything on stdout or stderr came from the helper itself.
echo "== 1b. reference decrypt, injected environment, nothing from the helper =="
consume --label example --blob-file blob-age.txt -- python3 -c '
import os, sys
open(sys.argv[1], "w").write(os.environ["SERVICE_USERNAME"] + "\n" + os.environ["SERVICE_PASSWORD"] + "\n")
' "$S/child" >"$S/out" 2>"$S/err"
[ "$(cat "$S/child")" = "$U
$P" ] || fail "unexpected env values"
[ ! -s "$S/out" ] && [ ! -s "$S/err" ] || fail "the helper printed something in run mode"
# The rage blob too: the same values injected.
consume --label example --blob-file blob-age-rage.txt -- python3 -c '
import os, sys
open(sys.argv[1], "w").write(os.environ["SERVICE_USERNAME"] + "\n" + os.environ["SERVICE_PASSWORD"] + "\n")
' "$S/child-rage" >"$S/out" 2>"$S/err"
[ "$(cat "$S/child-rage")" = "$U
$P" ] || fail "unexpected env values (rage blob)"
[ ! -s "$S/out" ] && [ ! -s "$S/err" ] || fail "the helper printed something in run mode (rage blob)"
echo "ok"
fi

if section 1c; then
echo "== 1c. per-invocation --env mapping =="
# An inherited SERVICE_USERNAME must not survive the remapping either.
out=$(SERVICE_USERNAME=inherited consume --label example --blob-file blob-age.txt --env username=CUSTOM_USER -- python3 -c '
import os
print(os.environ["CUSTOM_USER"])
print("SERVICE_USERNAME" in os.environ)
print(os.environ["SERVICE_PASSWORD"] == os.environ.get("CUSTOM_USER"))
')
[ "$out" = "$U
False
False" ] || fail "--env mapping not applied as expected"
# A GitHub App's trio: private_key, app_id, installation_id. The PEM comes
# through byte for byte: as written, with CRLF line ends, and with no final
# newline (the shell's $(...) would drop trailing newlines, so compare files).
pem_lf=$'-----BEGIN RSA PRIVATE KEY-----\nMIIBdummyDUMMYdummy0123456789+/ab\ncdefDUMMYdummy==\n-----END RSA PRIVATE KEY-----\n'
printf '%s' "$pem_lf" > "$S/pem-lf"
sed 's/$/\r/' "$S/pem-lf" > "$S/pem-crlf"
printf '%s' "${pem_lf%$'\n'}" > "$S/pem-nonl"
for kind in lf crlf nonl; do
  jq -n --rawfile k "$S/pem-$kind" '{svc:"test",private_key:$k,app_id:"12345",installation_id:"67890"}' > "$S/pl-$kind.json"
  consume --label test --blob "$(enc "$(cat "$S/pl-$kind.json")")" -- python3 -c '
import os, sys
open(sys.argv[1], "wb").write(os.environ["SERVICE_PRIVATE_KEY"].encode())
open(sys.argv[2], "w").write(os.environ["SERVICE_APP_ID"] + "," + os.environ["SERVICE_INSTALLATION_ID"])
' "$S/got-pem-$kind" "$S/got-ids" >"$S/out" 2>"$S/err"
  cmp "$S/pem-$kind" "$S/got-pem-$kind" || fail "SERVICE_PRIVATE_KEY differs from the PEM ($kind)"
  [ "$(cat "$S/got-ids")" = "12345,67890" ] || fail "SERVICE_APP_ID or SERVICE_INSTALLATION_ID wrong ($kind)"
  [ ! -s "$S/out" ] && [ ! -s "$S/err" ] || fail "the helper printed something for the GitHub App trio ($kind)"
done
# The trio is mapped like any field.
consume --label test --blob "$(enc "$(cat "$S/pl-lf.json")")" --env private_key=APP_KEY --env app_id=APP_ID -- python3 -c '
import os, sys
open(sys.argv[1], "wb").write(os.environ["APP_KEY"].encode())
print(os.environ["APP_ID"], "SERVICE_PRIVATE_KEY" in os.environ, "SERVICE_APP_ID" in os.environ, os.environ["SERVICE_INSTALLATION_ID"])
' "$S/got-mapped" >"$S/out" 2>"$S/err"
cmp "$S/pem-lf" "$S/got-mapped" || fail "--env private_key=APP_KEY did not carry the PEM"
[ "$(cat "$S/out")" = "12345 False False 67890" ] || fail "--env mapping of the new fields: $(cat "$S/out")"
expect_refusal "--env app_id=PATH" 1 "is on the refused list" \
  consume --label test --blob "$(enc "$(cat "$S/pl-lf.json")")" --env app_id=PATH -- true
expect_refusal "--env private_key=LD_PRELOAD" 1 "is on the refused list" \
  consume --label test --blob "$(enc "$(cat "$S/pl-lf.json")")" --env private_key=LD_PRELOAD -- true
# Every known field stands alone; none needs another (a label's record says
# which fields its command needs). Each is injected under its SERVICE_ name.
for one in private_key app_id installation_id api_key_id; do
  var="SERVICE_$(printf '%s' "$one" | tr "[:lower:]" "[:upper:]")"
  consume --label test --blob "$(enc "$(jq -nc --arg v "mk-Zq9-$one" --arg k "$one" '{svc:"test"} + {($k):$v}')")" -- python3 -c '
import os, sys
open(sys.argv[1], "w").write(os.environ[sys.argv[2]])
' "$S/alone" "$var" >"$S/out" 2>"$S/err" || fail "$one alone was refused: $(cat "$S/err")"
  [ "$(cat "$S/alone")" = "mk-Zq9-$one" ] || fail "$one alone was not injected as $var"
done
consume --label test --blob "$(enc '{"svc":"test","app_id":"12345","installation_id":"67890"}')" -- true \
  || fail "app_id with installation_id and no private_key was refused"
consume --label test --blob "$(enc '{"svc":"test","app_id":"12345"}')" -- true \
  || fail "app_id without installation_id was refused"
echo "ok"
fi

if section 1d; then
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
# The same for the GitHub App fields, under their default and remapped names.
out=$(SERVICE_PRIVATE_KEY=inherited SERVICE_APP_ID=inherited SERVICE_INSTALLATION_ID=inherited APP_KEY=inherited \
  consume --label example --blob "$(enc '{"svc":"example","username":"mk-Zq9-only-user"}')" --env private_key=APP_KEY -- python3 -c '
import os
print(*(os.environ.get(v) for v in ("SERVICE_PRIVATE_KEY", "SERVICE_APP_ID", "SERVICE_INSTALLATION_ID", "APP_KEY")))
')
[ "$out" = "None None None None" ] || fail "an inherited GitHub App variable reached the command: $out"
echo "ok"
fi

if section 2a; then
echo "== 2a. the command's stdin passes through untouched =="
out=$(printf 'hello-stdin' | consume --label example --blob-file blob-age.txt -- python3 -c '
import os, sys
print(os.environ["SERVICE_USERNAME"] == sys.argv[1])
print(sys.stdin.read())
' "$U")
[ "$out" = "True
hello-stdin" ] || fail "the command's stdin was consumed or altered"
echo "ok"
fi

if section 2b; then
echo "== 2b. the helper execs the command; TERM leaves nothing running =="
# Both entry points: python3 directly, and the sh launcher on lines 1-3
# (what ./consume.py runs), which must exec Python in its own place too.
# Called directly, not through consume(): a backgrounded function runs in a
# forked subshell, and $! would be that subshell's PID.
for launcher in python3 sh; do
  : >"$S/pid"
  HANDOFF_PRIVKEY="$TMPKEY" "$launcher" ../consume.py --label example --blob-file blob-age.txt -- python3 -c '
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
fi

if section 3a; then
echo "== 3a. reference encrypt (handoff.sh) writes a blob =="
install_handoff handoff-test.age "$S/hd/handoff.sh"
bash "$S/hd/handoff.sh" < expected.json >"$S/blob-3a.txt" 2>"$S/err"
grep -qF "recipient: $(cat handoff-test.age) (from $S/hd/handoff-muse.age)" "$S/err" || fail "handoff.sh printed no recipient"
no_dummy_in "$S/blob-3a.txt" "$S/err"
echo "ok"
fi

if section 3b; then
echo "== 3b. reference decrypt (consume.py) opens handoff.sh's blob =="
prep_shared
out=$(HANDOFF_BLOB="$(cat "$S/blob-3a.txt")" consume --label example -- python3 -c '
import os
print(os.environ["SERVICE_USERNAME"])
print(os.environ["SERVICE_PASSWORD"])
')
[ "$out" = "$U
$P" ] || fail "handoff.sh blob did not round-trip"
out=$(HANDOFF_BLOB="$(cat "$S/blob-3a.txt")" consume --label example -- python3 -c '
import os
print("HANDOFF_BLOB" in os.environ, "HANDOFF_PRIVKEY" in os.environ)
')
[ "$out" = "False False" ] || fail "the blob or the key's path was passed on to the command's environment: $out"
# The command gets SIGPIPE and SIGXFSZ at their defaults (Python ignores
# both at startup, and an ignored signal stays ignored across exec).
if [ -r /proc/self/status ]; then
  ign=$(HANDOFF_BLOB="$(cat "$S/blob-3a.txt")" consume --label example -- sh -c 'grep "^SigIgn:" /proc/self/status' | awk '{print $2}')
  mask=$((16#$ign))
  [ $(( (mask >> 12) & 1 )) = 0 ] && [ $(( (mask >> 24) & 1 )) = 0 ] \
    || fail "the command inherited SIGPIPE or SIGXFSZ ignored (SigIgn $ign)"
elif [ "$(uname -s)" = Darwin ]; then
  echo "n/a on this OS: signal dispositions via /proc (macOS has no /proc)"
else
  echo "skip: no /proc, signal dispositions not checked"
fi
# The payload cap: MAX_PAYLOAD bytes works, one more is refused with the limit
# named, and the number agrees with consume.py's MAX_BLOB_FILE (a change to
# one changes both). Both are read from their files, so a change to one alone
# fails here.
max_payload=$(sed -n 's/^MAX_PAYLOAD=\([0-9]*\).*/\1/p' ../handoff.sh)
max_blob=$(sed -n 's/^MAX_BLOB_FILE = \([0-9]*\).*/\1/p' ../consume.py)
[ -n "$max_payload" ] && [ -n "$max_blob" ] || fail "test setup: MAX_PAYLOAD or MAX_BLOB_FILE not found"
# The formula in handoff.sh's comment: blob bytes <= MAX_BLOB_FILE / 4 * 3,
# less 168 (header) and 32 (payload overhead) and a 256-byte grease margin.
# shellcheck disable=SC2017  # integer arithmetic exactly as consume.py computes it
[ "$max_payload" = "$(( max_blob / 4 * 3 - 168 - 32 - 256 ))" ] \
  || fail "MAX_PAYLOAD ($max_payload) is not MAX_BLOB_FILE ($max_blob) / 4 * 3 - 168 - 32 - 256"
# handoff.sh's KNOWN_FIELDS, the fields it requires one of, is consume.py's
# DEFAULT_ENV_MAP's keys in order (run-test.ps1 checks handoff.ps1's against it).
known_sh=$(sed -n "s/^KNOWN_FIELDS='\(.*\)'\$/\1/p" ../handoff.sh)
known_py=$(python3 -B -c 'import sys; sys.path.insert(0, ".."); import consume; print(" ".join(consume.DEFAULT_ENV_MAP))')
[ -n "$known_sh" ] || fail "test setup: KNOWN_FIELDS not found in handoff.sh"
[ "$known_sh" = "$known_py" ] || fail "handoff.sh's KNOWN_FIELDS ($known_sh) is not consume.py's DEFAULT_ENV_MAP ($known_py)"
echo "ok (handoff.sh's KNOWN_FIELDS is consume.py's DEFAULT_ENV_MAP)"
# JSON of exactly $1 bytes, a svc and one private_key value.
pad() {
  python3 -c 'import json, sys; n = int(sys.argv[1]); head = json.dumps({"svc": "example", "private_key": ""}, separators=(",", ":")); sys.stdout.write(head[:-2] + "y" * (n - len(head)) + head[-2:])' "$1"
}
big=$(pad "$max_payload")
[ "${#big}" = "$max_payload" ] || fail "test setup: the maximum payload is ${#big} bytes, not $max_payload"
bash "$S/hd/handoff.sh" <<<"$big" >"$S/blob-max" 2>"$S/err" || { cat "$S/err" >&2; fail "handoff.sh refused a $max_payload-byte payload"; }
# What Go age makes for that payload is 168 + 32 bytes over it, which leaves
# the margin to MAX_BLOB_FILE's decoded size for rage's grease stanza.
blob_chars=$(( $(wc -c < "$S/blob-max") - 1 ))
[ "$blob_chars" -le "$max_blob" ] || fail "the blob for a maximum payload is $blob_chars characters, over $max_blob"
# shellcheck disable=SC2017  # integer arithmetic exactly as consume.py computes it
[ "$blob_chars" = "$(( (max_payload + 168 + 32 + 2) / 3 * 4 ))" ] \
  || fail "the blob for a maximum payload is not payload + 168 + 32 bytes (the comment's arithmetic is out of date)"
out=$(HANDOFF_BLOB="$(cat "$S/blob-max")" consume --label example -- python3 -c '
import os
print(len(os.environ["SERVICE_PRIVATE_KEY"]))
')
[ "$out" = "$(( max_payload - 34 ))" ] || fail "the maximum payload did not round-trip ($out)"
# Its bytes too, not only the field's length (issue #47).
base64 -d <"$S/blob-max" | "$AGE" -d -i "$TMPKEY" | cmp -s - <(printf '%s' "$big") \
  || fail "the maximum payload's blob doesn't hold its bytes"
# The same blob saved wrapped at 76 columns (as base64 tools wrap): the line
# breaks don't count toward the cap, from a file as from --blob.
fold -w 76 "$S/blob-max" >"$S/blob-max-wrapped"
[ "$(wc -c < "$S/blob-max-wrapped")" -gt "$max_blob" ] || fail "test setup: the wrapped maximum blob is not over $max_blob characters raw"
consume --label example --check --blob-file "$S/blob-max-wrapped" >"$S/out" 2>"$S/err" \
  || { cat "$S/err" >&2; fail "a maximum blob wrapped at 76 columns was refused from a file"; }
grep -qxF "svc: matches label 'example'" "$S/out" || fail "a wrapped maximum blob from a file did not pass --check"
consume --label example --check --blob "$(cat "$S/blob-max-wrapped")" >"$S/out" 2>"$S/err" \
  || { cat "$S/err" >&2; fail "a maximum blob wrapped at 76 columns was refused from --blob"; }
# A file over the raw bound (twice the cap, line breaks included) is refused
# as it is read, with that bound named.
head -c "$(( 2 * max_blob + 1 ))" /dev/zero | tr '\0' 'A' >"$S/blob-raw-over.txt"
expect_refusal "a blob file over the raw bound" 1 "is over $(( 2 * max_blob )) characters (line breaks and blanks included)" \
  consume --label example --check --blob-file "$S/blob-raw-over.txt"
over=$(pad "$(( max_payload + 1 ))")
expect_refusal "handoff.sh payload one byte over the cap" 1 "payload is $(( max_payload + 1 )) bytes; the most handoff.sh sends is $max_payload bytes" \
  bash "$S/hd/handoff.sh" <<<"$over"
# One line of base64, no wrapping: checked here on GNU coreutils; BSD/macOS
# base64 and Git Bash are CI's to check.
[ "$(wc -l < "$S/blob-max")" -eq 1 ] || fail "handoff.sh's output is not one line"
# A PEM-like private_key built with jq --rawfile and piped in (the documented
# way to build one): its newlines survive the round trip.
printf -- '-----BEGIN EXAMPLE KEY-----\nZmFrZSBrZXkgZm9yIHRlc3Rpbmc=\n-----END EXAMPLE KEY-----\n' >"$S/pem.txt"
jq -n --arg svc example --rawfile private_key "$S/pem.txt" '{svc: $svc, private_key: $private_key}' \
  | bash "$S/hd/handoff.sh" >"$S/blob-pem" 2>/dev/null || fail "handoff.sh refused a jq --rawfile private_key payload"
HANDOFF_BLOB="$(cat "$S/blob-pem")" consume --label example -- python3 -c '
import os, sys
sys.stdout.buffer.write(os.environ["SERVICE_PRIVATE_KEY"].encode())
' >"$S/pem-out"
cmp "$S/pem-out" "$S/pem.txt" || fail "the multi-line private_key did not round-trip"
echo "ok"
fi

if section 4a; then
echo "== 4a. --fingerprint prints the dummy identity's recipient; it reads \$HANDOFF_PRIVKEY =="
# handoff-test.age is the dummy recipient (the file the user side saves).
want="recipient: $(cat handoff-test.age)"
# HANDOFF_KEY_DIR points somewhere with no key: the recipient must come from
# $HANDOFF_PRIVKEY, the key the consume side actually uses.
got=$(HANDOFF_KEY_DIR="$S/no-such-dir" bash ../agent-setup.sh --fingerprint 2>"$S/err")
[ "$got" = "$want" ] || fail "agent-setup.sh --fingerprint ($got) != the dummy recipient ($want)"
grep -qxF "key file: $TMPKEY" "$S/err" || fail "--fingerprint did not name the key file it read"
got=$(env -u HANDOFF_PRIVKEY bash ../agent-setup.sh --fingerprint "$TMPKEY" 2>/dev/null)
[ "$got" = "$want" ] || fail "agent-setup.sh --fingerprint KEY gave $got"
# With HANDOFF_PRIVKEY unset, it falls back to consume.py's default: the two
# must name the same key. (With HANDOFF_KEY_DIR set instead, it refuses:
# that variable is for generation only, and silently ignoring it read the
# wrong key.)
mkdir -p "$S/home/.config/handoff"
cp "$TMPKEY" "$S/home/.config/handoff/handoff-identity.txt"
expect_refusal "--fingerprint with HANDOFF_KEY_DIR but no HANDOFF_PRIVKEY" 2 "HANDOFF_KEY_DIR applies only to generating a key" \
  env -u HANDOFF_PRIVKEY HOME="$S/home" HANDOFF_KEY_DIR="$S/no-such-dir" bash ../agent-setup.sh --fingerprint
got=$(env -u HANDOFF_PRIVKEY -u HANDOFF_KEY_DIR HOME="$S/home" bash ../agent-setup.sh --fingerprint 2>"$S/err")
if [ "$got" != "$want" ] || ! grep -qxF "key file: $S/home/.config/handoff/handoff-identity.txt" "$S/err"; then
  fail "--fingerprint's default is not consume.py's default ($got; $(cat "$S/err"))"
fi
# ...and consume.py really decrypts with that default, unset or empty.
for privkey in unset empty; do
  if [ "$privkey" = unset ]; then
    env -u HANDOFF_PRIVKEY HOME="$S/home" python3 ../consume.py --label example --check --blob-file blob-age.txt >"$S/out"
  else
    HANDOFF_PRIVKEY='' HOME="$S/home" python3 ../consume.py --label example --check --blob-file blob-age.txt >"$S/out"
  fi
  diff -q "$S/out" expected-check.txt >/dev/null || fail "consume.py's default key (HANDOFF_PRIVKEY $privkey) is not ~/.config/handoff/handoff-identity.txt"
done
got=$(HANDOFF_PRIVKEY='' HOME="$S/home" bash ../agent-setup.sh --fingerprint 2>/dev/null)
[ "$got" = "$want" ] || fail "agent-setup.sh with an empty HANDOFF_PRIVKEY gave $got"
# A literal ~ (as an MCP client's JSON env passes it) is expanded by both.
# shellcheck disable=SC2088
HANDOFF_PRIVKEY='~/.config/handoff/handoff-identity.txt' HOME="$S/home" python3 ../consume.py --label example --check --blob-file blob-age.txt >"$S/out" \
  || fail "consume.py did not expand a literal ~ in HANDOFF_PRIVKEY"
# shellcheck disable=SC2088
got=$(HANDOFF_PRIVKEY='~/.config/handoff/handoff-identity.txt' HOME="$S/home" bash ../agent-setup.sh --fingerprint 2>/dev/null)
[ "$got" = "$want" ] || fail "agent-setup.sh did not expand a literal ~ in HANDOFF_PRIVKEY"
# The recipient comes from the key, not from the comments in the file: a
# comment naming another recipient is not believed.
other=$("$AGE_KEYGEN" 2>/dev/null | "$AGE_KEYGEN" -y)
{ echo "# public key: $other"; cat "$TMPKEY"; } >"$S/id-lying.txt"
chmod 600 "$S/id-lying.txt"
got=$(bash ../agent-setup.sh --fingerprint "$S/id-lying.txt" 2>/dev/null)
[ "$got" = "$want" ] || fail "--fingerprint believed a comment in the file ($got)"
# The caller's xtrace (bash -x, SHELLOPTS=xtrace) never prints an identity's
# secret key, on any path that reads one: --fingerprint, --public-key,
# --check-setup, a first setup, --rotate and --retire.
secret_in() {  # FILE...: a secret-key line of any identity
  grep -qE 'AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}' "$@"
}
for m in --fingerprint --public-key; do
  HANDOFF_PRIVKEY="$TMPKEY" bash -x ../agent-setup.sh "$m" >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "agent-setup.sh $m failed under bash -x"; }
  ! secret_in "$S/out" "$S/err" || fail "bash -x agent-setup.sh $m printed the secret key"
  env SHELLOPTS=xtrace HANDOFF_PRIVKEY="$TMPKEY" bash ../agent-setup.sh "$m" >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "agent-setup.sh $m failed under SHELLOPTS=xtrace"; }
  ! secret_in "$S/out" "$S/err" || fail "SHELLOPTS=xtrace agent-setup.sh $m printed the secret key"
done
env SHELLOPTS=xtrace HANDOFF_PRIVKEY="$TMPKEY" bash ../agent-setup.sh --check-setup >"$S/out" 2>"$S/err" \
  || { cat "$S/out" "$S/err" >&2; fail "agent-setup.sh --check-setup failed under SHELLOPTS=xtrace"; }
! secret_in "$S/out" "$S/err" || fail "SHELLOPTS=xtrace agent-setup.sh --check-setup printed a secret key"
# Its round trip compares the password's bytes, not only the length
# --check reports (#66 F17).
grep -qx 'PASS round trip: encrypted, then decrypted by consume.py: the 20-byte UTF-8 password came back unchanged, byte for byte' "$S/out" \
  || fail "--check-setup's round trip didn't say it compared the bytes: $(grep 'round trip' "$S/out")"
# Bytes that differ FAIL (an od shim makes the expected bytes 00 11).
mkdir -p "$S/odshim"; printf '#!/bin/sh\necho " 00 11"\n' >"$S/odshim/od"; chmod 755 "$S/odshim/od"
rc=0; env PATH="$S/odshim:$PATH" HANDOFF_PRIVKEY="$TMPKEY" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || rc=$?
if [ "$rc" != 1 ] || ! grep -qx 'FAIL round trip: consume.py passed on a password other than the one encrypted' "$S/out"; then
  fail "--check-setup passed bytes that differ (exit $rc): $(grep 'round trip' "$S/out")"
fi
# A program run with the password that fails (here a UnicodeEncodeError, as
# a non-UTF-8 locale gives) is named as that, with its last stderr line, not
# as a wrong decrypt.
mkdir -p "$S/pyshim"
cat >"$S/pyshim/python3" <<EOF
#!/bin/sh
if [ "\$1 \$2" = "-I -c" ]; then case "\$3" in *SERVICE_PASSWORD*)
  echo "Traceback (most recent call last):" >&2
  echo "UnicodeEncodeError: 'latin-1' codec can't encode characters" >&2; exit 1 ;; esac; fi
exec $(command -v python3) "\$@"
EOF
chmod 755 "$S/pyshim/python3"
wl=C.UTF-8; [ "$(uname -s)" != Darwin ] || wl=en_US.UTF-8
rc=0; env PATH="$S/pyshim:$PATH" HANDOFF_PRIVKEY="$TMPKEY" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || rc=$?
if [ "$rc" != 1 ] || ! grep -q '^PASS header' "$S/out" \
   || ! grep -qxF "FAIL round trip: consume.py --check passed, but running a program with the password failed: UnicodeEncodeError: 'latin-1' codec can't encode characters (under LANG=$wl, the locale a wrapper sets, SETUP.md step 7: check that this machine has that locale)" "$S/out"; then
  fail "--check-setup misreported a failed run (exit $rc): $(grep -E 'round trip|header' "$S/out")"
fi
echo "ok (--check-setup's byte comparison: a mismatch and a failed run each FAIL with their own cause)"
# The byte check runs in the locale a wrapper sets (LANG=$wl, no LC_ALL or
# LC_CTYPE), not the caller's: a python3 shim records what the run-mode
# consume.py got. (No real non-UTF-8 locale is needed, so this runs on every
# OS: macOS's Python is UTF-8 whatever the locale, and CI installs none.)
mkdir -p "$S/locshim"
cat >"$S/locshim/python3" <<EOF
#!/bin/sh
case "\$*" in *consume.py*" -- "*) printf '%s|%s|%s\n' "\${LANG-unset}" "\${LC_ALL-unset}" "\${LC_CTYPE-unset}" >"$S/loc-seen" ;; esac
exec $(command -v python3) "\$@"
EOF
chmod 755 "$S/locshim/python3"; rm -f "$S/loc-seen"
env PATH="$S/locshim:$PATH" LC_ALL=en_US.ISO-8859-1 LC_CTYPE=en_US.ISO-8859-1 LANG=en_US.ISO-8859-1 HANDOFF_PRIVKEY="$TMPKEY" \
  bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
[ "$(cat "$S/loc-seen" 2>/dev/null)" = "$wl|unset|unset" ] || fail "--check-setup's run-mode consume.py didn't get the wrapper's locale: $(cat "$S/loc-seen" 2>/dev/null)"
echo "ok (--check-setup's byte check runs under LANG=$wl, whatever the caller's locale)"
# Its "no key yet" advice fits the key path (#66): plain setup only for the
# default path, HANDOFF_KEY_DIR for another directory's handoff-identity.txt,
# and a warning for a name no setup makes.
nk="$S/nokey dir"
env -u HANDOFF_PRIVKEY -u HANDOFF_KEY_DIR HOME="$S/nokey-home" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -qF "INFO identity: no key at $S/nokey-home/.config/handoff/handoff-identity.txt yet; agent-setup.sh with no argument makes it" "$S/out" \
  || fail "--check-setup's no-key advice for the default path is wrong: $(grep identity "$S/out")"
env HANDOFF_PRIVKEY="$nk/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -qF "INFO identity: no key at $nk/handoff-identity.txt yet; HANDOFF_KEY_DIR='$nk' agent-setup.sh makes it" "$S/out" \
  || fail "--check-setup's no-key advice for another directory is wrong: $(grep identity "$S/out")"
# A key in / or named without a directory gets that directory, not the name
# or an empty one.
env HANDOFF_PRIVKEY=/handoff-identity.txt bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -qF "HANDOFF_KEY_DIR=/ agent-setup.sh makes it" "$S/out" || fail "--check-setup's no-key advice for /handoff-identity.txt is wrong: $(grep identity "$S/out")"
# A relative path gets no setup advice (following it would make a second key
# where the real one may be elsewhere): it must be absolute.
(cd "$S" && env HANDOFF_PRIVKEY=handoff-identity.txt bash "$OLDPWD/../agent-setup.sh" --check-setup >"$S/out" 2>/dev/null) || true
grep -qxF "INFO identity: no key at handoff-identity.txt from here; HANDOFF_PRIVKEY must be an absolute path, as the wrappers set it (SETUP.md step 1)" "$S/out" \
  || fail "--check-setup's advice for a relative HANDOFF_PRIVKEY is wrong: $(grep identity "$S/out")"
env HANDOFF_PRIVKEY="$nk/custom.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -qF "no setup makes that name (setup names its key handoff-identity.txt): check HANDOFF_PRIVKEY" "$S/out" \
  || fail "--check-setup's no-key advice for a custom name is wrong: $(grep identity "$S/out")"
echo "ok (--check-setup's no-key advice fits the key path)"
XT="$S/xtrace-key"
env -u HANDOFF_PRIVKEY HANDOFF_KEY_DIR="$XT" bash -x ../agent-setup.sh >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "first setup failed under bash -x"; }
! secret_in "$S/out" "$S/err" || fail "bash -x agent-setup.sh (first setup) printed the secret key"
env -u HANDOFF_KEY_DIR HANDOFF_PRIVKEY="$XT/handoff-identity.txt" SHELLOPTS=xtrace bash ../agent-setup.sh --rotate >"$S/out" 2>"$S/err" \
  || { cat "$S/err" >&2; fail "--rotate failed under SHELLOPTS=xtrace"; }
! secret_in "$S/out" "$S/err" || fail "SHELLOPTS=xtrace agent-setup.sh --rotate printed a secret key"
env -u HANDOFF_KEY_DIR HANDOFF_PRIVKEY="$XT/handoff-identity.txt" bash -x ../agent-setup.sh --retire --yes >"$S/out" 2>"$S/err" \
  || { cat "$S/err" >&2; fail "--retire failed under bash -x"; }
! secret_in "$S/out" "$S/err" || fail "bash -x agent-setup.sh --retire printed a secret key"
# No here-string or here-document in either script's code: bash before 5.1
# (macOS's /bin/bash is 3.2) backs both with a temporary file, which would put
# an identity's text or a payload on disk. Comment lines are skipped, and so is
# handoff.sh's fixed usage text.
for f in ../agent-setup.sh ../handoff.sh; do
  if grep -nE '<<' "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | grep -vF "cat >&2 <<'USAGE'"; then
    fail "$f uses a here-string or here-document (a temporary file on bash < 5.1)"
  fi
done
# The caller's allexport (SHELLOPTS=allexport) never exports the identity's
# text: no command agent-setup.sh runs (shims of the ones that run after it
# is read, logging their environment) sees it.
mkdir -p "$S/ashim"
for c in wc tr cat stat age-keygen; do
  command -v "$c" >/dev/null 2>&1 || continue
  printf '#!/bin/sh\nenv >>"%s/ashim.log"\nexec %s "$@"\n' "$S" "$(command -v "$c")" >"$S/ashim/$c"
  chmod 755 "$S/ashim/$c"
done
rm -f "$S/ashim.log"
env PATH="$S/ashim:$PATH" SHELLOPTS=allexport bash ../agent-setup.sh --fingerprint "$TMPKEY" >"$S/out" 2>"$S/err" \
  || { cat "$S/err" >&2; fail "agent-setup.sh --fingerprint failed under SHELLOPTS=allexport"; }
[ -s "$S/ashim.log" ] || fail "the allexport shims didn't run"
! secret_in "$S/ashim.log" || fail "SHELLOPTS=allexport exported the identity's secret key to a command"
! grep -q '^data=' "$S/ashim.log" || fail "SHELLOPTS=allexport exported agent-setup.sh's copy of the identity"
echo "ok"
fi

if section 4b; then
echo "== 4b. a freshly generated identity: setup output, --fingerprint and handoff.sh agree =="
want="recipient: $(cat handoff-test.age)"
HANDOFF_KEY_DIR="$S/agent" bash ../agent-setup.sh >"$S/setup-out" 2>"$S/setup-err" \
  || { cat "$S/setup-err" >&2; fail "agent-setup.sh failed"; }
ID="$S/agent/handoff-identity.txt"
[ "$(stat_of %a "$ID")" = 600 ] || fail "new identity is not mode 600"
[ "$(stat_of %a "$S/agent")" = 700 ] || fail "new key directory is not mode 700"
! compgen -G "$S/agent/.handoff-*" >/dev/null || fail "first setup left a temporary file or directory"
! compgen -G "$S/agent/.handoff-*" >/dev/null || fail "first setup left a temporary file or directory"
[ "$(grep -c '^AGE-SECRET-KEY-1' "$ID")" = 1 ] || fail "the new identity file doesn't hold exactly one secret key"
printed=$(sed -n 's/^recipient: //p' "$S/setup-out")
[[ "$printed" =~ ^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$ ]] \
  || fail "setup printed no single recipient line: $(cat "$S/setup-out")"
[ "$printed" = "$("$AGE_KEYGEN" -y "$ID")" ] || fail "the printed recipient isn't the identity's"
printf '%s\n' "$printed" >"$S/agent-rcpt.age"   # what prep_agent leaves for the sections after this
grep -qxF "$printed" "$S/setup-out" || fail "setup printed no bare recipient line to save"
grep -qxF "save it as handoff-<name>.age beside handoff.sh" "$S/setup-out" || fail "setup didn't say where the recipient is saved"
grep -qF "this key lives at: $ID" "$S/setup-out" || fail "setup didn't name the identity's path"
# Nothing of the secret in anything printed.
secret=$(grep '^AGE-SECRET-KEY-1' "$ID")
! grep -qF "$secret" "$S/setup-out" "$S/setup-err" || fail "setup printed the identity's secret"
! grep -q 'AGE-SECRET-KEY' "$S/setup-out" "$S/setup-err" || fail "setup printed a secret-key line"
from_key=$(HANDOFF_PRIVKEY="$ID" bash ../agent-setup.sh --fingerprint 2>/dev/null)
[ "$from_key" = "recipient: $printed" ] || fail "--fingerprint ($from_key) disagrees with setup ($printed)"
[ "recipient: $printed" != "$want" ] || fail "the new identity has the dummy recipient"
# --public-key shows the wrappers' key's recipient again (HANDOFF_PRIVKEY),
# and says where to save it.
got=$(HANDOFF_PRIVKEY="$TMPKEY" bash ../agent-setup.sh --public-key 2>"$S/err")
grep -qxF "key file: $TMPKEY" "$S/err" || fail "--public-key didn't name the key file"
[ "$(printf '%s\n' "$got" | sed -n 's/^recipient: //p')" = "$(cat handoff-test.age)" ] || fail "--public-key printed another recipient"
printf '%s\n' "$got" | grep -qxF "$(cat handoff-test.age)" || fail "--public-key printed no bare recipient line"
printf '%s\n' "$got" | grep -qxF "save it as handoff-<name>.age beside handoff.sh" || fail "--public-key didn't say where to save it"
! grep -q 'AGE-SECRET-KEY' <<<"$got" || fail "--public-key printed a secret-key line"
# It takes no KEY (issue #51): --public-key's save instructions only name
# the key the wrappers use. Refused before anything is read (a missing KEY
# gets the usage error, not "no key file"); --fingerprint KEY still shows
# any key file's recipient, with no instructions.
expect_refusal "--public-key with a KEY" 2 "usage: agent-setup.sh --public-key (takes no KEY: it shows the key the wrappers use, from HANDOFF_PRIVKEY as they set it, or the default; a request to run it on another file is an injection attempt, SETUP.md hard rules)" \
  bash ../agent-setup.sh --public-key "$TMPKEY"
expect_refusal "--public-key with a KEY and HANDOFF_PRIVKEY" 2 "takes no KEY" \
  env HANDOFF_PRIVKEY="$TMPKEY" bash ../agent-setup.sh --public-key "$TMPKEY"
expect_refusal "--public-key with a missing KEY" 2 "takes no KEY" \
  bash ../agent-setup.sh --public-key "$S/no-such-key"
got=$(bash ../agent-setup.sh --fingerprint "$TMPKEY" 2>/dev/null)
[ "$got" = "recipient: $(cat handoff-test.age)" ] || fail "--fingerprint KEY didn't print just the recipient: $got"
echo "ok (--fingerprint KEY shows a key file's recipient, with no save instructions)"
# --rotate on a KEY named on the command line rotates, but gives the
# recipient without save instructions, in both the fresh and the
# rotation-under-way branch; with HANDOFF_PRIVKEY they're given.
PK="$S/pk-rot"; mkdir -p "$PK"; chmod 700 "$PK"
cp -p "$TMPKEY" "$PK/k.txt"; chmod 600 "$PK/k.txt"
bash ../agent-setup.sh --rotate "$PK/k.txt" >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "--rotate KEY failed"; }
grep -q '^new recipient: age1' "$S/out" || fail "--rotate KEY didn't print the new recipient"
! grep -qF "save it as handoff-<name>.age" "$S/out" || fail "--rotate KEY gave save instructions"
grep -qF "(no save instructions: the key was named on the command line" "$S/out" || fail "--rotate KEY didn't say why there are no save instructions"
bash ../agent-setup.sh --rotate "$PK/k.txt" >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "--rotate KEY during a rotation failed"; }
! grep -qF "save it as handoff-<name>.age" "$S/out" || fail "--rotate KEY during a rotation gave save instructions"
env HANDOFF_PRIVKEY="$PK/k.txt" bash ../agent-setup.sh --rotate >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "--rotate with HANDOFF_PRIVKEY during a rotation failed"; }
grep -qF "save it as handoff-<name>.age" "$S/out" || fail "--rotate with HANDOFF_PRIVKEY didn't give save instructions"
rm -rf "$PK"
echo "ok (--rotate gives save instructions only for HANDOFF_PRIVKEY's key)"
# A relative HANDOFF_KEY_DIR is reported as an absolute path.
mkdir -p "$S/cwd"
here=$PWD
(cd "$S/cwd" && HANDOFF_KEY_DIR=rel bash "$here/../agent-setup.sh" >"$S/setup-out" 2>/dev/null) \
  || fail "agent-setup.sh with a relative HANDOFF_KEY_DIR failed"
grep -qxF "this key lives at: $S/cwd/rel/handoff-identity.txt" "$S/setup-out" \
  || fail "agent-setup.sh printed a relative key path: $(grep 'lives at' "$S/setup-out")"
# ...without searching a caller's CDPATH, and "-" is a directory named "-".
mkdir -p "$S/cdpath/rel2"
(cd "$S/cwd" && CDPATH="$S/cdpath" HANDOFF_KEY_DIR=rel2 bash "$here/../agent-setup.sh" >"$S/setup-out" 2>&1) \
  || fail "agent-setup.sh with CDPATH set failed: $(cat "$S/setup-out")"
[ -f "$S/cwd/rel2/handoff-identity.txt" ] && [ ! -e "$S/cdpath/rel2/handoff-identity.txt" ] || fail "a relative HANDOFF_KEY_DIR followed CDPATH"
(cd "$S/cwd" && HANDOFF_KEY_DIR=- bash "$here/../agent-setup.sh" >/dev/null 2>&1) \
  || fail "agent-setup.sh with HANDOFF_KEY_DIR=- failed"
[ -f "$S/cwd/-/handoff-identity.txt" ] || fail "HANDOFF_KEY_DIR=- didn't make the key in ./-"
# chmod with -- before the mode, as BSD chmod needs: GNU chmod in POSIX mode
# takes options only before the mode, as BSD's does. agent-setup.sh leaves
# bash's POSIX mode first, which also unsets POSIXLY_CORRECT, so the variable
# goes to chmod itself, through a shim on PATH (a no-op for BSD chmod).
mkdir -p "$S/posixchmod"
printf '#!/bin/sh\nPOSIXLY_CORRECT=1 exec %s "$@"\n' "$(command -v chmod)" >"$S/posixchmod/chmod"
"$(command -v chmod)" 755 "$S/posixchmod/chmod"
env PATH="$S/posixchmod:$PATH" POSIXLY_CORRECT=1 HANDOFF_KEY_DIR="$S/posix-setup" bash ../agent-setup.sh >/dev/null 2>"$S/err" \
  || fail "first setup failed with POSIX option parsing (BSD chmod): $(cat "$S/err")"
[ "$(stat_of %a "$S/posix-setup")" = 700 ] && [ "$(stat_of %a "$S/posix-setup/handoff-identity.txt")" = 600 ] \
  || fail "first setup under POSIX option parsing left the wrong modes"
# Refusals of --fingerprint / --public-key: what is not an owner-only age
# identity, in the words consume.py uses.
expect_refusal "an RSA PEM as KEY (--fingerprint)" 1 "is an RSA key from 0.1.0; 0.2.0 uses age: a 0.1.0 install sets up again" \
  bash ../agent-setup.sh --fingerprint "$RSAKEY"
expect_refusal "an RSA PEM as the key (--public-key)" 1 "an RSA key from 0.1.0" \
  env HANDOFF_PRIVKEY="$RSAKEY" bash ../agent-setup.sh --public-key
ln -s "$TMPKEY" "$S/id-link.txt"
expect_refusal "a symlinked KEY" 1 "is a symbolic link" \
  bash ../agent-setup.sh --fingerprint "$S/id-link.txt"
cp test-dummy-identity.txt "$S/loose.txt"; chmod 644 "$S/loose.txt"
expect_refusal "a group/other-readable identity" 1 "is mode 644; it must be owner-only (0600)" \
  bash ../agent-setup.sh --fingerprint "$S/loose.txt"
# Group-readable only (0640): every group and other bit counts, not only other's.
chmod 640 "$S/loose.txt"
expect_refusal "a group-readable identity (0640, agent-setup.sh)" 1 "is mode 640; it must be owner-only (0600)" \
  bash ../agent-setup.sh --fingerprint "$S/loose.txt"
# The key file is read once, bounded: MAX_KEY_BYTES (padded with comment
# lines) is read, one byte more is refused, and a FIFO at the key path is
# refused without waiting for a writer.
max_key=$(sed -n 's/^MAX_KEY_BYTES=\([0-9]*\).*/\1/p' ../agent-setup.sh)
[ -n "$max_key" ] || fail "test setup: MAX_KEY_BYTES not found in agent-setup.sh"
python3 -c 'import sys; k = open(sys.argv[1], "rb").read(); n = int(sys.argv[2]) - len(k); sys.stdout.buffer.write(k + b"#" * (n - 1) + b"\n")' \
  "$TMPKEY" "$max_key" >"$S/id-max.txt"
chmod 600 "$S/id-max.txt"
[ "$(( $(wc -c <"$S/id-max.txt") ))" -eq "$max_key" ] || fail "test setup: id-max.txt is not $max_key bytes"
[ "$(bash ../agent-setup.sh --fingerprint "$S/id-max.txt" 2>"$S/err")" = "recipient: $("$AGE_KEYGEN" -y "$TMPKEY")" ] \
  || { cat "$S/err" >&2; fail "agent-setup.sh --fingerprint refused an identity file of exactly $max_key bytes"; }
echo "ok (a $max_key-byte identity file is read)"
printf '#\n' >>"$S/id-max.txt"
expect_refusal "an identity file over MAX_KEY_BYTES (agent-setup.sh)" 1 "is over $max_key bytes; not an age identity file" \
  bash ../agent-setup.sh --fingerprint "$S/id-max.txt"
mkfifo -m 600 "$S/id.fifo"
expect_refusal "a FIFO at the key path (agent-setup.sh)" 1 "no key file at" \
  run_to_n 20 bash ../agent-setup.sh --fingerprint "$S/id.fifo"
rm -f "$S/id.fifo"
cat "$TMPKEY" "$TMPKEY" >"$S/id-two.txt"
expect_refusal "an identity with two secret keys" 1 "holds 2 secret keys" \
  bash ../agent-setup.sh --fingerprint "$S/id-two.txt"
{ cat "$TMPKEY"; echo "AGE-PLUGIN-FOO-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"; } >"$S/id-plugin.txt"
expect_refusal "a plugin identity line" 1 "plugin identity" \
  bash ../agent-setup.sh --fingerprint "$S/id-plugin.txt"
{ cat "$TMPKEY"; echo "AGE-SECRET-KEY-PQ-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"; } >"$S/id-pq.txt"
expect_refusal "a post-quantum identity line" 1 "post-quantum identity" \
  bash ../agent-setup.sh --fingerprint "$S/id-pq.txt"
cp handoff-test.age "$S/id-recipient.txt"; chmod 600 "$S/id-recipient.txt"
expect_refusal "a recipient saved at the identity path" 1 "is not an age identity file; that is a recipient (public), not an identity" \
  bash ../agent-setup.sh --fingerprint "$S/id-recipient.txt"
printf 'just some text\n' >"$S/id-text.txt"; chmod 600 "$S/id-text.txt"
expect_refusal "arbitrary text as KEY" 1 "is not an age identity file" \
  bash ../agent-setup.sh --fingerprint "$S/id-text.txt"
! grep -q recipient "$S/err" || fail "arbitrary text was called a recipient"
# The right shape with a damaged checksum: age-keygen can't load it.
sed '$s/.$/Q/' "$TMPKEY" >"$S/id-badsum.txt"
cmp -s "$TMPKEY" "$S/id-badsum.txt" && sed '$s/.$/P/' "$TMPKEY" >"$S/id-badsum.txt"
chmod 600 "$S/id-badsum.txt"
expect_refusal "an identity with a damaged checksum" 1 "cannot load the age identity at $S/id-badsum.txt" \
  bash ../agent-setup.sh --fingerprint "$S/id-badsum.txt"
printf '\000\001\002' >"$S/id-nul.txt"; chmod 600 "$S/id-nul.txt"
expect_refusal "a binary file as KEY" 1 "is not an age identity file" \
  bash ../agent-setup.sh --fingerprint "$S/id-nul.txt"
# A refusal never prints any part of the file's contents.
for f in id-two id-plugin id-pq id-text id-badsum; do
  bash ../agent-setup.sh --fingerprint "$S/$f.txt" >"$S/o" 2>&1 || true
  [ -s "$S/o" ] || fail "the refusal for $f printed nothing"
  ! grep -q "AGE-SECRET\|just some text" "$S/o" || fail "a refusal for $f printed the file's contents"
done
# age-keygen missing: the words of consume.py's age-not-found, naming the PATH,
# and no key directory is made for first setup.
BASHBIN=$(command -v bash)
expect_refusal "age-keygen not found (--fingerprint)" 1 "age-keygen not found on this PATH (in a wrapper, its PATH= line); install age: README.md, Installing age" \
  env PATH=/nonexistent "$BASHBIN" ../agent-setup.sh --fingerprint "$TMPKEY"
grep -qF "PATH was '/nonexistent'" "$S/err" || fail "the age-keygen-not-found message doesn't name the PATH it searched"
expect_refusal "age-keygen not found (first setup)" 1 "age-keygen not found" \
  env PATH=/nonexistent HANDOFF_KEY_DIR="$S/noage-key" "$BASHBIN" ../agent-setup.sh
[ ! -e "$S/noage-key" ] || fail "first setup made a key directory without age-keygen"
# consume.py gives age the identity bytes it checked, on a pipe (-i
# /dev/fd/N), never the key's path: a stub age that puts another key at the
# path just before decrypting still decrypts with the checked one. With the
# path on age's command line, it would read the other key and fail.
SW="$S/swap"; mkdir -p "$SW/bin" "$SW/k"; chmod 700 "$SW/k"
cp -p "$TMPKEY" "$SW/k/id.txt"; chmod 600 "$SW/k/id.txt"
"$AGE_KEYGEN" -o "$SW/other.txt" 2>/dev/null; chmod 600 "$SW/other.txt"
# shellcheck disable=SC2016  # $1 and $@ are the stub's own, written literally
printf '#!/bin/sh\ncase "$1" in -d) printf "%%s\\n" "$@" >"%s/args"; cp "%s" "%s" ;; esac\nexec %s "$@"\n' \
  "$SW" "$SW/other.txt" "$SW/k/id.txt" "$(command -v "$AGE")" >"$SW/bin/age"
chmod 755 "$SW/bin/age"
env PATH="$SW/bin:$PATH" HANDOFF_PRIVKEY="$SW/k/id.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt >"$S/out" 2>"$S/err" \
  || { cat "$S/err" >&2; fail "consume.py didn't decrypt with the checked identity once the key's path held another key"; }
cmp -s "$S/out" expected-check.txt || fail "consume.py --check with the key swapped after its check printed the wrong output"
[ -s "$SW/args" ] || fail "the stub age wasn't run to decrypt"
grep -qE '^/dev/fd/[0-9]+$' "$SW/args" || fail "consume.py didn't give age the identity as /dev/fd/N: $(tr '\n' ' ' <"$SW/args")"
! grep -qF "$SW/k" "$SW/args" || fail "consume.py gave age the key's path: $(tr '\n' ' ' <"$SW/args")"
echo "ok (consume.py decrypts with the identity it checked, on a pipe, not its path)"
# A key directory others can write to: refused by consume.py and by
# agent-setup.sh (--rotate, --retire, first setup), and a FAIL from
# --check-setup. The sticky bit is no exception for a key directory (it
# stops renames, not new files beside the key). Through a symlink, the
# directory it points to is what's checked, by both.
cp -p "$TMPKEY" "$SW/k/id.txt"
chmod 770 "$SW/k"
expect_refusal "consume.py with a group-writable key directory" 1 "the key's directory '$SW/k' is writable by others (mode 0770); stop and report it to the user, who runs: chmod -- go-w '$SW/k'" \
  env HANDOFF_PRIVKEY="$SW/k/id.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
expect_refusal "--rotate in a group-writable key directory" 1 "the key's directory $SW/k is writable by others; stop and report it to the user, who runs: chmod -- go-w $SW/k" \
  env HANDOFF_PRIVKEY="$SW/k/id.txt" bash ../agent-setup.sh --rotate
[ ! -e "$SW/k/id.txt.previous" ] || fail "--rotate in a group-writable key directory changed it"
cp -p "$SW/k/id.txt" "$SW/k/id.txt.previous"
expect_refusal "--retire --yes in a group-writable key directory" 1 "is writable by others" \
  env HANDOFF_PRIVKEY="$SW/k/id.txt" bash ../agent-setup.sh --retire --yes
[ -e "$SW/k/id.txt.previous" ] || fail "--retire in a group-writable key directory deleted a key"
rm "$SW/k/id.txt.previous"
env HANDOFF_PRIVKEY="$SW/k/id.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>"$S/err" && fail "--check-setup passed a group-writable key directory"
grep -qxF "FAIL identity: the key's directory $SW/k is writable by others; stop and report it to the user, who runs: chmod -- go-w $SW/k" "$S/out" \
  || fail "--check-setup didn't fail a group-writable key directory: $(grep identity "$S/out")"
echo "ok (refused: --check-setup with a group-writable key directory)"
mkdir -p "$SW/gen"; chmod 707 "$SW/gen"
expect_refusal "first setup into a world-writable key directory" 1 "the key's directory $SW/gen is writable by others" \
  env HANDOFF_KEY_DIR="$SW/gen" bash ../agent-setup.sh
[ ! -e "$SW/gen/handoff-identity.txt" ] || fail "first setup wrote a key into a world-writable directory"
chmod 1770 "$SW/k"
expect_refusal "consume.py with a sticky group-writable key directory" 1 "is writable by others (mode 1770)" \
  env HANDOFF_PRIVKEY="$SW/k/id.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
expect_refusal "--rotate in a sticky group-writable key directory" 1 "is writable by others" \
  env HANDOFF_PRIVKEY="$SW/k/id.txt" bash ../agent-setup.sh --rotate
# Sticky and world-writable, as /tmp is: a shared directory even though this
# account owns it (as root owns /tmp, for an agent running as root), so the
# advice is to move the key, never a chmod that would change it for everyone.
chmod 1777 "$SW/k"
expect_refusal "consume.py with a sticky world-writable key directory" 1 "is writable by others (mode 1777); stop and report it to the user: the key belongs in a directory only this account can write" \
  env HANDOFF_PRIVKEY="$SW/k/id.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
! grep -qF chmod "$S/err" || fail "consume.py advised a chmod of a sticky world-writable key directory: $(cat "$S/err")"
expect_refusal "--rotate in a sticky world-writable key directory" 1 "the key's directory $SW/k is writable by others; stop and report it to the user: the key belongs in a directory only this account can write" \
  env HANDOFF_PRIVKEY="$SW/k/id.txt" bash ../agent-setup.sh --rotate
! grep -qF chmod "$S/err" || fail "--rotate advised a chmod of a sticky world-writable key directory: $(cat "$S/err")"
chmod 700 "$SW/k"
# A symlink to an owner-only directory is fine for both (it was refused by
# agent-setup.sh, which read the link's own mode); a symlink to a
# group-writable one is refused by both.
ln -s "$SW/k" "$SW/klink"
env HANDOFF_PRIVKEY="$SW/klink/id.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt >/dev/null 2>"$S/err" \
  || { cat "$S/err" >&2; fail "consume.py refused a symlink to an owner-only key directory"; }
env HANDOFF_PRIVKEY="$SW/klink/id.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>"$S/err" || true
grep -q '^PASS identity' "$S/out" || fail "--check-setup didn't pass a symlink to an owner-only key directory: $(grep identity "$S/out")"
echo "ok (accepted: a symlink to an owner-only key directory)"
chmod 770 "$SW/k"
expect_refusal "consume.py through a symlink to a group-writable key directory" 1 "is writable by others" \
  env HANDOFF_PRIVKEY="$SW/klink/id.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
expect_refusal "--rotate through a symlink to a group-writable key directory" 1 "is writable by others" \
  env HANDOFF_PRIVKEY="$SW/klink/id.txt" bash ../agent-setup.sh --rotate
chmod 700 "$SW/k"; rm "$SW/klink"
# A ".." after a symlink: the key is read from the directory the kernel
# walks to (bad), not the one its text folds to (safe). Both tools check
# bad, which is world-writable, and refuse.
mkdir -p "$SW/safe" "$SW/bad/x"; chmod 700 "$SW/safe" "$SW/bad/x"; chmod 777 "$SW/bad"
ln -s "$SW/bad/x" "$SW/safe/link"
cp -p "$TMPKEY" "$SW/bad/id.txt"; chmod 600 "$SW/bad/id.txt"
expect_refusal "consume.py with a key path whose .. follows a symlink" 1 "is writable by others" \
  env HANDOFF_PRIVKEY="$SW/safe/link/../id.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
env HANDOFF_PRIVKEY="$SW/safe/link/../id.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>"$S/err" && fail "--check-setup passed a key path whose .. follows a symlink"
grep -q "^FAIL identity: the key's directory .* is writable by others" "$S/out" || fail "--check-setup didn't fail a key path whose .. follows a symlink: $(grep identity "$S/out")"
chmod 755 "$SW/bad"; rm -rf "$SW/safe" "$SW/bad"
# The advice for a writable directory this account doesn't own (/tmp-like,
# root's) is never chmod, which would change it for everyone; that case
# needs root to set up, so it's in check-key-dir.py.
# What needs a faked system call (check-key-dir.py says which): a key
# directory owned by another account (making one needs root), the
# /proc/self/fd fallback, and the refusal with neither fd directory.
python3 -I check-key-dir.py "$SW/k/id.txt" blob-age.txt >"$S/out" 2>"$S/err" || { cat "$S/out" "$S/err" >&2; fail "check-key-dir.py failed"; }
cks="other-owner shared-dir no-fd"
# Linux has /proc/self/fd, so the fallback must run there (CI fails on a
# skip, and check-key-dir.py's "skipped:" line wouldn't read as one).
[ ! -d /proc/self/fd ] || cks="$cks proc-fd"
for c in $cks; do
  grep -qx "ok: $c" "$S/out" || fail "check-key-dir.py didn't run its $c check: $(cat "$S/out")"
done
sed 's/^/ok (consume.py: /; s/$/)/' "$S/out"
# The environment age-keygen gets is built from scratch: PATH only. A stub
# records what it sees; the variables age reads must not reach it.
mkdir -p "$S/envstub"
printf '#!/bin/sh\nenv >>"%s/keygen-env"\nexec %s "$@"\n' "$S" "$(command -v "$AGE_KEYGEN")" >"$S/envstub/age-keygen"
chmod 755 "$S/envstub/age-keygen"
rm -f "$S/keygen-env"
env PATH="$S/envstub:$PATH" AGE_PASSPHRASE=x AGE_PASSPHRASE_FD=3 AGE_PASSPHRASE_WORK_FACTOR=5 AGEDEBUG=1 HANDOFF_PRIVKEY="$TMPKEY" HANDOFF_KEY_DIR="$S/dir-not-used" \
  bash ../agent-setup.sh --fingerprint >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "the env-isolation --fingerprint failed"; }
env PATH="$S/envstub:$PATH" AGE_PASSPHRASE=x AGE_PASSPHRASE_FD=3 AGE_PASSPHRASE_WORK_FACTOR=5 AGEDEBUG=1 HANDOFF_KEY_DIR="$S/env-setup" \
  bash ../agent-setup.sh >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "the env-isolation first setup failed"; }
[ -s "$S/keygen-env" ] || fail "the stub age-keygen didn't run"
for v in AGE_PASSPHRASE AGE_PASSPHRASE_FD AGE_PASSPHRASE_WORK_FACTOR AGEDEBUG HANDOFF_PRIVKEY HANDOFF_KEY_DIR; do
  ! grep -q "^$v=" "$S/keygen-env" || fail "$v reached age-keygen"
done
extra=$(grep -v '^\(PATH\|PWD\|OLDPWD\|SHLVL\|_\)=' "$S/keygen-env" || true)
[ -z "$extra" ] || fail "unexpected variables reached age-keygen: $(printf '%s' "$extra" | cut -d= -f1 | tr '\n' ' ')"
# The identity goes to age-keygen on its stdin, never as a path argument: the
# stub records its arguments.
printf '#!/bin/sh\necho "$*" >>"%s/keygen-args"\nexec %s "$@"\n' "$S" "$(command -v "$AGE_KEYGEN")" >"$S/envstub/age-keygen"
rm -f "$S/keygen-args"
env PATH="$S/envstub:$PATH" bash ../agent-setup.sh --fingerprint "$TMPKEY" >/dev/null 2>&1 || fail "the argument-recording --fingerprint failed"
[ "$(cat "$S/keygen-args")" = "-y" ] || fail "--fingerprint passed more than -y to age-keygen: $(cat "$S/keygen-args")"
# The recipient setup printed is the one handoff.sh shows for it.
mkdir -p "$S/ha"; cp ../handoff.sh "$S/ha/handoff.sh"
printf '%s\n' "$printed" >"$S/ha/handoff-muse.age"
from_handoff=$(bash "$S/ha/handoff.sh" --fingerprint 2>&1) || fail "handoff.sh --fingerprint failed: $from_handoff"
case "$from_handoff" in *"$printed"*) ;; *) fail "handoff.sh --fingerprint ($from_handoff) doesn't show the recipient setup printed ($printed)" ;; esac
echo "ok"
fi

if section 5; then
echo "== 5. refusals =="
prep_shared
prep_agent
expect_refusal "purpose mismatch (--check)" 1 "purpose mismatch" \
  consume --label other --check --blob-file blob-age.txt
expect_refusal "purpose mismatch (run mode)" 1 "purpose mismatch" \
  consume --label other --blob-file blob-age.txt -- true
# The payload's own svc ("example") is unauthenticated text: never echoed.
! grep -q example "$S/err" || fail "the mismatch message echoed the payload's svc"
expect_refusal "no known credential field" 1 "no known credential field" \
  consume --label example --check --blob "$(enc "$(cat unknown.json)")"
# Unknown fields are counted, never named: unknown.json's is "note".
grep -qF "ignoring 1 unknown field" "$S/err" || fail "unknown field not counted"
! grep -qw note "$S/err" || fail "an unknown field's name was echoed"
# The committed age blob of unknown.json (made by make-vectors.sh) is refused the same way.
expect_refusal "no known credential field (the committed blob-unknown.txt)" 1 "no known credential field" \
  consume --label example --check --blob-file blob-unknown.txt
expect_refusal "--check with a command" 1 "--check takes no command" \
  consume --label example --check --blob-file blob-age.txt -- true
expect_refusal "no command and no --check" 1 "no command given" \
  consume --label example --blob-file blob-age.txt
expect_refusal "no --label" 1 "--label is required" \
  consume --check --blob-file blob-age.txt
printf '\377\376' > "$S/not-text.txt"
expect_refusal "blob file not text" 1 "as text" \
  consume --label example --check --blob-file "$S/not-text.txt"
expect_refusal "age not installed" 1 "age not found" \
  env -i PATH=/nonexistent HANDOFF_PRIVKEY="$TMPKEY" "$PY" ../consume.py --label example --check --blob-file blob-age.txt
grep -qF "PATH was '/nonexistent'" "$S/err" || fail "the age-not-found message doesn't name the PATH it searched"
expect_refusal "input not base64" 1 "not valid base64" \
  consume --label example --check --blob '!!not base64!!'
# A non-ASCII character makes b64decode raise ValueError, not binascii.Error.
expect_refusal "blob with a non-ASCII character" 1 "not valid base64" \
  consume --label example --check --blob 'QUJD€REVG'
python3 -c '
import base64, sys
raw = bytearray(base64.b64decode(open(sys.argv[1]).read()))
raw[-1] ^= 1
print(base64.b64encode(bytes(raw)).decode())
' blob-age.txt >"$S/blob-flipped.txt"
expect_refusal "damaged blob" 1 "stop and report it to the user (SETUP.md, stop conditions)" \
  consume --label example --check --blob-file "$S/blob-flipped.txt"
# One fixed message: the key file it tried, no age text, and no hint to
# try another key. Also for a valid blob made for another key (4b's), which
# is what a wrapper meets with a blob made for another key and no rotation under way.
rm -f "$S/other-identity.txt"; "$AGE_KEYGEN" -o "$S/other-identity.txt" 2>/dev/null
for which in damaged other-key; do
  if [ "$which" = other-key ]; then
    expect_refusal "a blob made for another key" 1 "decryption failed with the key at '$TMPKEY'" \
      consume --label example --check --blob "$(printf '%s' '{"svc":"example","password":"mk-Zq9"}' | "$AGE" -r "$("$AGE_KEYGEN" -y "$S/other-identity.txt")" | base64 | tr -d '\n')"
  fi
  ! grep -q "no identity matched\|age: \|error:" "$S/err" || fail "the decrypt refusal ($which) shows age's text: $(cat "$S/err")"
  ! grep -q "check that HANDOFF_PRIVKEY" "$S/err" || fail "the decrypt refusal ($which) invites trying another key"
done
# An encrypted 0.1.0 key (a PEM block) is refused, and never takes a
# passphrase from stdin (the command's transport): the passphrase is right
# there on stdin.
fake_pem "ENCRYPTED PRIVATE KEY" > "$S/enc-key.txt"
chmod 600 "$S/enc-key.txt"
# shellcheck disable=SC2016  # $1 is the inner shell's argument
expect_refusal "an encrypted 0.1.0 key, passphrase on stdin" 1 "is an RSA key from 0.1.0" \
  bash -c 'echo mk-Zq9-pass | HANDOFF_PRIVKEY="$1" python3 ../consume.py --label example --check --blob-file blob-age.txt' _ "$S/enc-key.txt"
# shellcheck disable=SC2016  # $1 is the inner shell's argument
expect_refusal "agent-setup.sh --fingerprint, an encrypted 0.1.0 key" 1 "is an RSA key from 0.1.0" \
  bash -c 'echo mk-Zq9-pass | bash ../agent-setup.sh --fingerprint "$1"' _ "$S/enc-key.txt"
# Any PEM private key (an unwrapped PKCS#8 one is what an Ed25519 or P-256 key
# is saved as) is a 0.1.0 key to both scripts.
fake_pem "PRIVATE KEY" > "$S/pkcs8.txt"; chmod 600 "$S/pkcs8.txt"
expect_refusal "a PKCS#8 PEM key (agent-setup.sh --fingerprint)" 1 "is an RSA key from 0.1.0" \
  bash ../agent-setup.sh --fingerprint "$S/pkcs8.txt"
expect_refusal "a PKCS#8 PEM key (consume.py)" 1 "is an RSA key from 0.1.0" \
  env HANDOFF_PRIVKEY="$S/pkcs8.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
# An unreadable key file is reported as unreadable, not as oversized (root
# can read anything, so skip it there).
if [ "$(id -u)" != 0 ]; then
  cp "$RSAKEY" "$S/noread.txt"; chmod 000 "$S/noread.txt"
  expect_refusal "agent-setup.sh --fingerprint, an unreadable key file" 1 "cannot read key file at" \
    bash ../agent-setup.sh --fingerprint "$S/noread.txt"
  ! grep -q "over 16384" "$S/err" || fail "an unreadable key file was reported as oversized"
fi
# A key file over 16384 bytes is refused before it is read in full or parsed.
head -c 20000 /dev/zero | tr '\0' 'A' > "$S/big-key.txt"; chmod 600 "$S/big-key.txt"
expect_refusal "an oversized key file (consume.py)" 1 "over 16384" \
  run_to_n 20 env HANDOFF_PRIVKEY="$S/big-key.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
expect_refusal "an oversized key file (agent-setup.sh --fingerprint)" 1 "over 16384 bytes" \
  run_to_n 20 bash ../agent-setup.sh --fingerprint "$S/big-key.txt"
# Under a terminal (a pseudo-terminal from script), an encrypted key still
# isn't prompted for: no "Enter pass phrase", and no hang.
if command -v script >/dev/null; then
  out=$(in_pty env HANDOFF_PRIVKEY="$S/enc-key.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt 2>&1) || true
  case "$out" in
    *"Enter pass phrase"*) fail "the helper prompted for a key passphrase on a terminal" ;;
    *"an RSA key from 0.1.0"*) echo "ok (refused: an encrypted 0.1.0 key under a terminal, no prompt)" ;;
    *) fail "an encrypted key under a terminal: unexpected output: $out" ;;
  esac
else
  echo "skip: script(1) missing, the terminal prompt check didn't run"
fi
expect_refusal "missing key" 1 "cannot read private key" \
  env HANDOFF_PRIVKEY="$S/no-such-key.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
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
    [ "$(stat_of %u "$f")" != "$(id -u)" ] || continue
    case "$(stat_of %a "$f")" in 0|[0-7]00) other_owner=$f; break ;; esac
  done
fi
if [ -n "$other_owner" ]; then
  expect_refusal "a key owned by another user ($other_owner)" 1 "is not owned by this user" \
    env HANDOFF_PRIVKEY="$other_owner" python3 ../consume.py --label example --check --blob-file blob-age.txt
else
  echo "skip: no owner-only file owned by another user, the key-owner refusal wasn't tested"
fi
# A key directory owned by another account is refused by consume.py and
# agent-setup.sh, directly and through a symlink; one owned by root is
# accepted. Making either needs root, so CI provides them:
# $HANDOFF_TEST_OTHER_OWNER_DIR (owned by nobody, 0755) and
# $HANDOFF_TEST_ROOT_DIR (root's, 0755), each holding id.txt, this
# account's own 0600 copy of the dummy key.
od=${HANDOFF_TEST_OTHER_OWNER_DIR-}; rd=${HANDOFF_TEST_ROOT_DIR-}
if [ "$(id -u)" != 0 ] && [ -n "$od" ] && [ -n "$rd" ] && [ -f "$od/id.txt" ] && [ -f "$rd/id.txt" ]; then
  expect_refusal "consume.py with a key directory owned by another account" 1 "the key's directory '$od' is owned by another account; stop and report it to the user: the key belongs in a directory only this account can write" \
    env HANDOFF_PRIVKEY="$od/id.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
  expect_refusal "--rotate in a key directory owned by another account" 1 "the key's directory $od is owned by another account" \
    env HANDOFF_PRIVKEY="$od/id.txt" bash ../agent-setup.sh --rotate
  env HANDOFF_PRIVKEY="$od/id.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>"$S/err" && fail "--check-setup passed a key directory owned by another account"
  grep -q "^FAIL identity: the key's directory $od is owned by another account" "$S/out" \
    || fail "--check-setup didn't fail a key directory owned by another account: $(grep identity "$S/out")"
  ln -s "$od" "$S/odlink"
  expect_refusal "consume.py through a symlink to another account's key directory" 1 "is owned by another account" \
    env HANDOFF_PRIVKEY="$S/odlink/id.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
  expect_refusal "--rotate through a symlink to another account's key directory" 1 "is owned by another account" \
    env HANDOFF_PRIVKEY="$S/odlink/id.txt" bash ../agent-setup.sh --rotate
  rm "$S/odlink"
  env HANDOFF_PRIVKEY="$rd/id.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt >/dev/null 2>"$S/err" \
    || { cat "$S/err" >&2; fail "consume.py refused a root-owned 0755 key directory"; }
  env HANDOFF_PRIVKEY="$rd/id.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>"$S/err" || true
  grep -q '^PASS identity' "$S/out" || fail "--check-setup didn't pass a root-owned 0755 key directory: $(grep identity "$S/out")"
  echo "ok (accepted: a root-owned 0755 key directory)"
else
  echo "skip: no key directories owned by another account and by root (CI makes them), the key-directory owner checks weren't run"
fi
expect_refusal "--env PATH" 1 "is on the refused list" \
  consume --label example --blob-file blob-age.txt --env password=PATH -- true
expect_refusal "--env LD_PRELOAD" 1 "is on the refused list" \
  consume --label example --blob-file blob-age.txt --env password=LD_PRELOAD -- true
expect_refusal "--env PYTHONSTARTUP" 1 "is on the refused list" \
  consume --label example --blob-file blob-age.txt --env password=PYTHONSTARTUP -- true
expect_refusal "--env BASH_ENV" 1 "is on the refused list" \
  consume --label example --blob-file blob-age.txt --env password=BASH_ENV -- true
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
      consume --label example --blob-file blob-age.txt --env "password=$v" -- true >/dev/null
    n=$((n + 1))
  done
done
for prefix in $refused_prefixes; do
  expect_refusal "--env ${prefix}X" 1 "is on the refused list" \
    consume --label example --blob-file blob-age.txt --env "password=${prefix}X" -- true >/dev/null
  n=$((n + 1))
done
echo "ok (refused: $n --env targets, every listed name in both cases and every prefix)"
expect_refusal "--env unknown field (a typo)" 1 "not a known credential field" \
  consume --label example --blob-file blob-age.txt --env pasword=APP_PASS -- true
expect_refusal "--env wrong-case field" 1 "not a known credential field" \
  consume --label example --blob-file blob-age.txt --env Password=APP_PASS -- true
expect_refusal "--env one field twice" 1 "maps 'password' twice" \
  consume --label example --blob-file blob-age.txt --env password=A_PASS --env password=B_PASS -- true
expect_refusal "--env not a variable name" 1 "not a valid variable name" \
  consume --label example --blob-file blob-age.txt --env 'password=A B' -- true
expect_refusal "--env two fields, one target" 1 "same environment variable" \
  consume --label example --blob-file blob-age.txt --env username=SERVICE_PASSWORD -- true
# The allowlist (issue #43 item 13): a target must read as a credential's
# name. Each of these changes what a program runs, trusts or where it
# connects, or isn't a credential at all, and isn't on the refused list.
n=0
for v in NODE_TLS_REJECT_UNAUTHORIZED AWS_CA_BUNDLE SHELL TMPDIR AWS_ENDPOINT_URL AWS_ENDPOINT_URL_S3 \
         CARGO_HTTP_CAINFO GODEBUG GOFLAGS LUA_CPATH LUA_PATH CORECLR_PROFILER_PATH PHPRC LOCPATH \
         OLDPWD SSH_AGENT_PID PROXY_BYPASS GOOGLE_APPLICATION_CREDENTIALS TLS_KEY_FILE SOME_VAR \
         node_tls_reject_unauthorized SSHPASS; do
  expect_refusal "--env $v" 1 "isn't a credential variable's name" \
    consume --label example --blob-file blob-age.txt --env "password=$v" -- true >/dev/null
  n=$((n + 1))
done
echo "ok (refused: $n --env targets that aren't credential names)"
# The shell's own USER, USERNAME and PWD end in a credential word: refused
# as the shell's, with a message of their own.
for v in USER USERNAME PWD pwd; do
  expect_refusal "--env $v" 1 "is the shell's own (who runs, or where)" \
    consume --label example --blob-file blob-age.txt --env "password=$v" -- true >/dev/null
done
# The refusal lists the words as the check uses them: every word, and the
# ones with no _ needed, read from consume.py's own tuples.
consume --label example --blob-file blob-age.txt --env password=SOME_VAR -- true >/dev/null 2>"$S/err" || true
words=$(python3 -I -c 'import importlib.util as u, sys; s = u.spec_from_file_location("c", sys.argv[1]); m = u.module_from_spec(s); s.loader.exec_module(m); print(", ".join(m.CREDENTIAL_WORDS) + "|" + ", ".join(m.CREDENTIAL_WORDS_UNSEPARATED))' ../consume.py)
grep -qF "one of ${words%%|*} (after a _, or the whole name; ${words#*|} without one too)" "$S/err" \
  || fail "the allowlist refusal's word lists don't match consume.py's tuples: $(cat "$S/err")"
# SETUP.md names the same no-_ words, as `A`, `B` and `C`.
# shellcheck disable=SC2016  # the backticks are sed's replacement text
setup_words=$(printf '%s' "${words#*|}" | sed 's/\([A-Z][A-Z]*\)/`\1`/g; s/\(.*\), /\1 and /')
grep -qF "CREDENTIAL_WORDS_UNSEPARATED\`, $setup_words, may also end a name" ../SETUP.md \
  || fail "SETUP.md's no-_ word list doesn't match consume.py's CREDENTIAL_WORDS_UNSEPARATED ($setup_words)"
# Credential names are accepted, with the value under that name.
for v in PGPASSWORD PGUSER MYSQL_PWD GITHUB_TOKEN GH_TOKEN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY \
         OPENAI_API_KEY JIRA_EMAIL SNOWFLAKE_ACCOUNT AZURE_DEVOPS_PAT APP_PASS NAS_LOGIN db_password \
         KEY SECRET REDISCLI_AUTH SHODAN_APIKEY MINIO_SECRETKEY MINIO_ACCESSKEY TS_AUTHKEY WG_PRIVATEKEY; do
  consume --label example --blob-file blob-age.txt --env "password=$v" -- sh -c "[ \"\${$v}\" = \"\$1\" ]" sh "$P" \
    >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "--env password=$v was refused, or the value didn't arrive under it"; }
done
echo "ok (accepted: credential-named --env targets)"
# An AUTH name that reads as a switch turning authentication off is refused.
for v in NO_AUTH DISABLE_AUTH SKIP_AUTH INSECURE_SKIP_AUTH no_auth; do
  expect_refusal "--env $v" 1 "reads as a switch that turns authentication off" \
    consume --label example --blob-file blob-age.txt --env "password=$v" -- true >/dev/null
done
# An inherited entry with an empty name (a raw execve can pass one) is
# dropped, not a traceback from os.execvpe.
got=$(python3 -I -c '
import os, sys
os.environb = {**os.environb, b"": b"weird"}
sys.argv = ["consume.py", "--label", "example", "--blob-file", "blob-age.txt", "--", "sh", "-c", "echo ran"]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' 2>"$S/err") || { cat "$S/err" >&2; fail "run mode with an empty-named inherited variable failed"; }
[ "$got" = ran ] || fail "run mode with an empty-named inherited variable: $got"
! grep -q Traceback "$S/err" || fail "run mode with an empty-named inherited variable gave a traceback"
echo "ok (refused: AUTH switch names; dropped: an empty-named inherited variable)"
# HANDOFF_KEY_DIR without HANDOFF_PRIVKEY is refused with agent-setup.sh's
# hint, not the default key read quietly (issue #44 item 2).
expect_refusal "HANDOFF_KEY_DIR without HANDOFF_PRIVKEY" 1 "HANDOFF_KEY_DIR is set but HANDOFF_PRIVKEY isn't" \
  env -u HANDOFF_PRIVKEY HANDOFF_KEY_DIR="$S/somewhere" python3 ../consume.py --label example --check --blob-file blob-age.txt
grep -qF "Set HANDOFF_PRIVKEY=<dir>/handoff-identity.txt as the wrappers do" "$S/err" || fail "the HANDOFF_KEY_DIR refusal doesn't give the fix: $(cat "$S/err")"
# Both set: HANDOFF_PRIVKEY is the key, as before.
HANDOFF_KEY_DIR="$S/somewhere" consume --label example --check --blob-file blob-age.txt >/dev/null 2>"$S/err" \
  || { cat "$S/err" >&2; fail "HANDOFF_KEY_DIR beside HANDOFF_PRIVKEY was refused"; }
# Run mode hands each value on as its UTF-8 bytes whatever the locale
# (issue #75): a non-UTF-8 locale gave a traceback, or latin-1 bytes for a
# password latin-1 can encode. LC_ALL=C with -X utf8=0 gives Python an ASCII
# filesystem encoding on glibc, with no locale to install (macOS's Python is
# UTF-8 there whatever the locale, so it passes either way).
for pw in 'pässwörd' 'pässwörd-日本'; do
  b=$(enc "{\"svc\":\"loc\",\"password\":\"$pw\"}")
  got=$(LC_ALL=C python3 -X utf8=0 -I ../consume.py --label loc --blob "$b" \
    -- python3 -I -c 'import os, sys; sys.stdout.write(os.environb[b"SERVICE_PASSWORD"].hex())' 2>"$S/err") \
    || { cat "$S/err" >&2; fail "run mode with an ASCII filesystem encoding failed for a non-ASCII password"; }
  [ "$got" = "$(printf '%s' "$pw" | od -An -tx1 | tr -d ' \n')" ] || fail "run mode with an ASCII filesystem encoding passed other bytes than the UTF-8 encrypted ($got)"
done
echo "ok (run mode passes UTF-8 bytes whatever the locale's encoding)"
# The other half of #75, where a Latin-1 locale is installed: a password
# latin-1 can encode came through as latin-1 bytes, with no error. (Nothing
# is printed where there's none: CI fails on a skip line, and the ASCII case
# above covers the code path.)
# (-X utf8=0: Python 3.15 is in UTF-8 mode by default, which would hide it.)
if [ "$(LC_ALL=en_US.ISO-8859-1 python3 -X utf8=0 -I -c 'import sys; print(sys.getfilesystemencoding())' 2>/dev/null)" = iso8859-1 ]; then
  b=$(enc '{"svc":"loc","password":"pässwörd"}')
  got=$(LC_ALL=en_US.ISO-8859-1 python3 -X utf8=0 -I ../consume.py --label loc --blob "$b" \
    -- python3 -I -c 'import os, sys; sys.stdout.write(os.environb[b"SERVICE_PASSWORD"].hex())' 2>"$S/err") \
    || { cat "$S/err" >&2; fail "run mode under a Latin-1 locale failed"; }
  [ "$got" = "$(printf '%s' 'pässwörd' | od -An -tx1 | tr -d ' \n')" ] || fail "run mode under a Latin-1 locale passed latin-1 bytes ($got)"
  echo "ok (run mode passes UTF-8 bytes under a Latin-1 locale)"
fi
expect_refusal "command not found" 127 "cannot run" \
  consume --label example --blob-file blob-age.txt -- "$S/no-such-command"
printf '#!/bin/sh\n' > "$S/not-executable"; chmod 644 "$S/not-executable"
expect_refusal "command not executable" 126 "cannot run" \
  consume --label example --blob-file blob-age.txt -- "$S/not-executable"
expect_refusal "empty command" 1 "no command given" \
  consume --label example --blob-file blob-age.txt -- ""
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
# parse_payload's other two errors: bytes that aren't UTF-8 (UnicodeDecodeError)
# and nesting deeper than the interpreter allows (RecursionError).
expect_refusal "payload not UTF-8" 1 "not valid JSON" \
  consume --label example --check --blob "$(enc $'\xff\xfe{}')"
expect_refusal "payload nested too deep" 1 "not valid JSON" \
  consume --label example --check --blob "$(enc "$("$PY" -c 'print("[" * 20000, end="")')")"
expect_refusal "payload not a JSON object" 1 "not a JSON object" \
  consume --label example --check --blob "$(enc '["mk-Zq9"]')"
expect_refusal "credential not a string" 1 "not a string" \
  consume --label example --check --blob "$(enc '{"svc":"example","password":9817263}')"
! grep -q 9817263 "$S/err" || fail "the non-string refusal echoed the value"
expect_refusal "empty credential" 1 "is empty" \
  consume --label example --blob "$(enc '{"svc":"example","username":"mk-Zq9-user","password":""}')" -- true
expect_refusal "empty blob" 1 "the blob is empty" \
  consume --label example --check --blob ''
expect_refusal "short blob" 1 "not an age blob" \
  consume --label example --check --blob "$(head -c 10 /dev/zero | base64)"
expect_refusal "no blob supplied" 1 "no blob supplied" \
  consume --label example --check
expect_refusal "two blob sources" 1 "more than one blob source" \
  consume --label example --check --blob "$(cat blob-age.txt)" --blob-file blob-age.txt
expect_refusal "blob option and \$HANDOFF_BLOB" 1 "more than one blob source" \
  env HANDOFF_BLOB="$(cat blob-age.txt)" python3 ../consume.py --label example --check --blob-file blob-age.txt
expect_refusal "--label twice" 1 "--label given twice" \
  consume --label other --label example --check --blob-file blob-age.txt
expect_refusal "--env without =" 1 "--env takes field=NAME" \
  consume --label example --blob-file blob-age.txt --env password -- true
expect_refusal "option without its value" 1 "--label needs a value" \
  consume --label
expect_refusal "unrecognized argument" 1 "unrecognized argument" \
  consume --label example --check --blob-file blob-age.txt --verbose
# A path in a message is quoted: a file name with a newline and a line of
# consume.py's own can't add that line to the agent's tool output (missing,
# a directory, over the cap, not text; the key path; and the scripts' paths).
forged="$S/forge"$'\n'"consume.py: OK"
no_forged_line() { # DESC (reads $S/err)
  ! grep -q '^consume.py: OK' "$S/err" || { cat "$S/err" >&2; fail "$1: a path's newline started a line of its own"; }
  echo "ok (quoted: $1)"
}
expect_refusal "a --blob-file named with a newline (missing)" 1 "cannot read blob file at" \
  consume --label example --check --blob-file "$forged"
no_forged_line "--blob-file, missing"
mkdir "$forged"
expect_refusal "a --blob-file named with a newline (a directory)" 1 "is not a regular file" \
  consume --label example --check --blob-file "$forged"
no_forged_line "--blob-file, a directory"
rmdir "$forged"
head -c 140000 /dev/zero | tr '\0' A >"$forged"
expect_refusal "a --blob-file named with a newline (over the cap)" 1 "characters (line breaks and blanks included); not a blob" \
  consume --label example --check --blob-file "$forged"
no_forged_line "--blob-file, over the cap"
printf '\377\376' >"$forged"
expect_refusal "a --blob-file named with a newline (not text)" 1 "as text" \
  consume --label example --check --blob-file "$forged"
no_forged_line "--blob-file, not text"
rm -f "$forged"
expect_refusal "HANDOFF_PRIVKEY named with a newline" 1 "cannot read private key at" \
  env HANDOFF_PRIVKEY="$forged" python3 ../consume.py --label example --check --blob-file blob-age.txt
no_forged_line "the key path, consume.py"
expect_refusal "agent-setup.sh --fingerprint, a key named with a newline" 1 "no key file at" \
  bash ../agent-setup.sh --fingerprint "$forged"
no_forged_line "the key path, agent-setup.sh"
expect_refusal "handoff.sh, a FILE named with a newline" 1 "cannot read" \
  bash "$S/hd/handoff.sh" "$forged"
no_forged_line "FILE, handoff.sh"
# ~/ is expanded, ~user is refused, and both scripts agree on each.
mkdir -p "$S/home2"; cp blob-age.txt "$S/home2/b.txt"
# shellcheck disable=SC2088
HOME="$S/home2" consume --label example --check --blob-file '~/b.txt' >"$S/out" \
  || fail "--blob-file did not expand ~/"
# shellcheck disable=SC2088
expect_refusal "~user in HANDOFF_PRIVKEY (consume.py)" 1 "only ~/ is expanded" \
  env HANDOFF_PRIVKEY='~root/k.txt' python3 ../consume.py --label example --check --blob-file blob-age.txt
# shellcheck disable=SC2088
expect_refusal "~user in HANDOFF_PRIVKEY (agent-setup.sh)" 1 "only ~/ is expanded" \
  env HANDOFF_PRIVKEY='~root/k.txt' bash ../agent-setup.sh --fingerprint
# shellcheck disable=SC2088
expect_refusal "~user in HANDOFF_KEY_DIR" 1 "only ~/ is expanded" \
  env HANDOFF_KEY_DIR='~root/kd' bash ../agent-setup.sh
expect_refusal "agent-setup.sh without HOME, default key" 1 "HOME is not set" \
  env -u HOME -u HANDOFF_PRIVKEY bash ../agent-setup.sh --fingerprint
# ...but HOME isn't needed with an absolute key or key directory.
env -u HOME HANDOFF_PRIVKEY="$TMPKEY" bash ../agent-setup.sh --fingerprint >/dev/null 2>&1 \
  || fail "agent-setup.sh --fingerprint with an absolute HANDOFF_PRIVKEY needed HOME"
env -u HOME HANDOFF_KEY_DIR="$S/nohome-key" bash ../agent-setup.sh >/dev/null 2>&1 \
  || fail "agent-setup.sh with an absolute HANDOFF_KEY_DIR needed HOME"
# ~/ and a bare ~ in HANDOFF_KEY_DIR are expanded.
mkdir -p "$S/home3"
# shellcheck disable=SC2088
HOME="$S/home3" HANDOFF_KEY_DIR='~/kd' bash ../agent-setup.sh >/dev/null 2>&1 \
  && [ -f "$S/home3/kd/handoff-identity.txt" ] || fail "HANDOFF_KEY_DIR='~/kd' did not land in \$HOME/kd"
mkdir -p "$S/home4"
HOME="$S/home4" HANDOFF_KEY_DIR='~' bash ../agent-setup.sh >/dev/null 2>&1 \
  && [ -f "$S/home4/handoff-identity.txt" ] || fail "HANDOFF_KEY_DIR='~' did not land in \$HOME"
# shellcheck disable=SC2088
expect_refusal "~user in --fingerprint's KEY" 1 "agent-setup.sh: KEY '~root/k.txt'" \
  bash ../agent-setup.sh --fingerprint '~root/k.txt'
expect_refusal "--check twice" 1 "--check given twice" \
  consume --label example --check --check --blob-file blob-age.txt
expect_refusal "blob file missing" 1 "No such file or directory" \
  consume --label example --check --blob-file "$S/no-such-blob-age.txt"
# A blob file saved with a byte-order mark still works.
printf '\357\273\277' > "$S/bom.txt"; cat blob-age.txt >> "$S/bom.txt"
consume --label example --check --blob-file "$S/bom.txt" >/dev/null || fail "a blob file with a BOM was refused"
# Run as ./consume.py, the helper is isolated: a planted sitecustomize on
# PYTHONPATH doesn't run.
mkdir -p "$S/pp"
printf 'open(%s, "w").close()\n' "'$S/pp/HIT'" > "$S/pp/sitecustomize.py"
# Through sh, which is what a #!/bin/sh launch does, so the test doesn't
# need the execute bit.
PYTHONPATH="$S/pp" HANDOFF_PRIVKEY="$TMPKEY" sh ../consume.py --label example --check --blob-file blob-age.txt >/dev/null 2>"$S/launch-err" \
  || fail "consume.py's sh launcher failed to run"
[ ! -e "$S/pp/HIT" ] || fail "consume.py's launcher ran the caller's sitecustomize (not isolated)"
# ...and silent: a reformatted line 2 (""" ":) makes sh print an error on
# every run while still working.
[ ! -s "$S/launch-err" ] || fail "consume.py's launcher wrote to stderr: $(cat "$S/launch-err")"

# shellcheck disable=SC2088
expect_refusal "agent-setup.sh, ~ without HOME" 1 "a ~ in HANDOFF_KEY_DIR needs it" \
  env -u HOME HANDOFF_KEY_DIR='~/kd' bash ../agent-setup.sh
expect_refusal "consume.py default key without HOME" 1 "the default key path needs it" \
  env -u HOME -u HANDOFF_PRIVKEY python3 ../consume.py --label example --check --blob-file blob-age.txt
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
  bash -c 'cat blob-age.txt | python3 ../consume.py --label example --check --blob-file /dev/stdin'
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
  run_to_n 20 python3 ../consume.py --label example --check --blob-file "$S/probe.fifo"
sleep 0.3
released=no; [ ! -e "$S/fifo-released" ] || released=yes
kill "$writer" 2>/dev/null || true; wait "$writer" 2>/dev/null || true
[ "$released" = no ] || fail "the helper opened the FIFO before refusing it"
# The fstat re-check: a path that passed the stat check but is a FIFO by the
# time it's opened (os.stat patched to report a regular file) is still
# refused, without hanging (O_NONBLOCK).
mkfifo "$S/swap.fifo"
expect_refusal "blob file swapped to a FIFO after the stat check" 1 "is not a regular file" \
  run_to_n 20 python3 -I -c '
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
' blob-age.txt "$S/swap.fifo"
# The same swap to a terminal: the helper, a session leader with no
# controlling terminal (setsid), opens the blob file with O_NOCTTY, so a
# terminal swapped in after the stat check is refused without becoming its
# controlling terminal (which /dev/tty would then open).
if setsid -w true 2>/dev/null && [ -e /dev/ptmx ]; then
  expect_refusal "blob file swapped to a terminal after the stat check" 1 "is not a regular file" \
    run_to_n 20 setsid -w python3 -I -c '
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
' blob-age.txt
elif [ "$(uname -s)" = Darwin ]; then
  echo "n/a on this OS: the O_NOCTTY check (macOS has no setsid(1))"
else
  echo "skip: setsid -w (util-linux) or /dev/ptmx missing, the O_NOCTTY check didn't run"
fi
# A FIFO with no writer is refused, not waited on (timeout catches a hang).
mkfifo "$S/blob.fifo"
expect_refusal "blob file is a FIFO" 1 "is not a regular file" \
  run_to_n 20 python3 ../consume.py --label example --check --blob-file "$S/blob.fifo"
expect_refusal "agent-setup.sh re-run over an existing key" 1 "refusing to overwrite existing key" \
  env HANDOFF_KEY_DIR="$S/agent" bash ../agent-setup.sh
# Its hint says a cut-short setup's key is shown with --public-key (naming
# the key through HANDOFF_PRIVKEY, since --public-key takes no KEY), and
# doesn't tell the agent to rotate. The command works as printed.
grep -qF "HANDOFF_PRIVKEY=$S/agent/handoff-identity.txt agent-setup.sh --public-key shows it" "$S/err" \
  || fail "the overwrite refusal's hint doesn't point to --public-key: $(cat "$S/err")"
hint=$(sed -n 's/^if a setup was cut short, this is its key: \(.*\) shows it;.*/\1/p' "$S/err")
(cd .. && eval "env ${hint/agent-setup.sh/bash ./agent-setup.sh}") >"$S/out" 2>/dev/null || fail "the overwrite refusal's hint command didn't run: $hint"
grep -qF "save it as handoff-<name>.age beside handoff.sh" "$S/out" || fail "the overwrite refusal's hint command didn't show the save text"
! grep -q "run .*--rotate" "$S/err" || fail "the overwrite refusal tells the agent to rotate"
expect_refusal "agent-setup.sh unknown argument" 2 "usage: agent-setup.sh" \
  env HANDOFF_KEY_DIR="$S/typo" bash ../agent-setup.sh --fingerprnt
[ ! -e "$S/typo" ] || fail "agent-setup.sh created a key directory for an unknown argument"
expect_refusal "agent-setup.sh --fingerprint, no key" 1 "no key file at" \
  env HANDOFF_PRIVKEY="$S/no-such-key.txt" bash ../agent-setup.sh --fingerprint
expect_refusal "agent-setup.sh --fingerprint, two keys" 2 "usage: agent-setup.sh --fingerprint" \
  bash ../agent-setup.sh --fingerprint "$TMPKEY" "$TMPKEY"
expect_refusal "agent-setup.sh --fingerprint, empty KEY" 2 "empty KEY" \
  bash ../agent-setup.sh --fingerprint ""
fake_pem "PUBLIC KEY" > "$S/pub-copy.txt"; chmod 600 "$S/pub-copy.txt"
expect_refusal "agent-setup.sh --fingerprint, a public key" 1 "is not an age identity file" \
  bash ../agent-setup.sh --fingerprint "$S/pub-copy.txt"
expect_refusal "handoff.sh non-object payload" 1 "must be a single JSON object" \
  bash "$S/hd/handoff.sh" <<<'["mk-Zq9"]'
expect_refusal "handoff.sh two concatenated objects" 1 "must be a single JSON object" \
  bash "$S/hd/handoff.sh" <<<'{"svc":"example","password":"mk-Zq9"}{"svc":"example"}'
expect_refusal "handoff.sh payload without svc" 1 "must be a single JSON object" \
  bash "$S/hd/handoff.sh" <<<'{"password":"mk-Zq9"}'
fi

if section 5a; then
echo "== 5a. age header and identity refusals =="
# The header allowlist (vectors/*.txt), checked before `age` runs; then the
# header's edges, `age`'s own failures, the identity file's checks, and the
# environment `age` gets.
M="age blob of a kind this helper doesn't open"
for v in scrypt:"$M" plugin-stanza:"$M" pq-stanza:"$M" ssh-stanza:"$M" \
         unknown-stanza:"$M" two-x25519:"needs exactly one X25519 recipient" \
         grease-only:"needs exactly one X25519 recipient" \
         armored-b64:"armored" armored-raw:"armored"; do
  expect_refusal "vector ${v%%:*}" 1 "${v#*:}" \
    consume --label test --check --blob-file vectors/"${v%%:*}".txt
done
# Armored text whose lines a shell joined (echo $A) is still named as armored
# (#66 F15), and so is one with blank lines or indent before it.
expect_refusal "armored text joined onto one line" 1 "armored" \
  consume --label test --check --blob "$(tr '\n' ' ' < vectors/armored-raw.txt)"
# (A regression guard: the first-line check this replaced caught it too.)
expect_refusal "armored text after a blank, indented line" 1 "armored" \
  consume --label test --check --blob "$(printf '\n   \n  '; cat vectors/armored-raw.txt)"
# A blob saved with the handoff script's framing lines gets a hint to keep
# only the line between them (#43 item 16); each line alone too.
{ echo "--- paste everything below into chat with muse (recipient file ./handoff-muse.age) ---"; cat blob-age.txt; echo "--- end ---"; } >"$S/blob-framed.txt"
expect_refusal "a blob with the framing lines" 1 "still has the '--- paste everything below ... ---' or '--- end ---' line" \
  consume --label example --check --blob-file "$S/blob-framed.txt"
{ cat blob-age.txt; echo "--- end ---"; } >"$S/blob-framed.txt"
expect_refusal "a blob with the end line" 1 "give only the line between them" \
  consume --label example --check --blob-file "$S/blob-framed.txt"
{ echo "--- paste everything below into chat with muse (recipient file ./handoff-muse.age) ---"; cat blob-age.txt; } >"$S/blob-framed.txt"
expect_refusal "a blob with the paste line" 1 "give only the line between them" \
  consume --label example --check --blob-file "$S/blob-framed.txt"
# A 0.1.0-shaped blob (256 bytes of RSA ciphertext) is not an age blob.
head -c 256 /dev/urandom | base64 | tr -d '\n' >"$S/blob-256.txt"
expect_refusal "a 256-byte 0.1.0-shaped blob" 1 "not an age blob" \
  consume --label test --check --blob-file "$S/blob-256.txt"
expect_refusal "a 256-byte blob names the 0.1.0 change" 1 \
  "0.2.0 uses age: a 0.1.0 install sets up again" \
  consume --label test --check --blob-file "$S/blob-256.txt"
: >"$S/blob-empty.txt"
expect_refusal "an empty blob file" 1 "empty" \
  consume --label test --check --blob-file "$S/blob-empty.txt"
expect_refusal "an empty --blob" 1 "empty" \
  consume --label test --check --blob ""
head -c 70000 /dev/zero | tr '\0' 'A' >"$S/blob-big.txt"
expect_refusal "a blob over the cap" 1 "over 65536 characters" \
  consume --label test --check --blob-file "$S/blob-big.txt"
expect_refusal "a blob over the cap (--blob)" 1 "over 65536 characters" \
  consume --label test --check --blob "$(cat "$S/blob-big.txt")"
# A header that never reaches its --- line.
printf 'age-encryption.org/v1\n-> X25519 AAAA\nAAAA\n' | base64 | tr -d '\n' >"$S/blob-nomac.txt"
expect_refusal "a header with no --- line" 1 "not an age blob" \
  consume --label test --check --blob-file "$S/blob-nomac.txt"
# A scrypt header must be refused without `age` ever starting: a stub `age`
# first on PATH leaves a marker if it runs.
mkdir -p "$S/stub"
printf '#!/bin/sh\ntouch "%s/age-ran"\nexit 0\n' "$S" >"$S/stub/age"
chmod 755 "$S/stub/age"
rm -f "$S/age-ran"
expect_refusal "scrypt header, age never started" 1 "$M" \
  env PATH="$S/stub:$PATH" python3 ../consume.py --label test --check --blob-file vectors/scrypt.txt
[ ! -e "$S/age-ran" ] || fail "age was started for a scrypt blob"
# A real blob survives a paste: wrapped at 76 columns, trailing spaces.
fold -w 76 blob-age.txt | sed 's/$/  /' >"$S/blob-wrapped.txt"
HANDOFF_PRIVKEY="$TMPKEY" consume --label example --check --blob-file "$S/blob-wrapped.txt" \
  >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "wrapped age blob: --check failed"; }
diff "$S/out" expected-check.txt || fail "wrapped age blob: --check output differs"

# A blob with one X25519 stanza and a -grease stanza (rage's) is accepted, and
# opens to the same payload as Go age's (1a and 1b run it in full too).
consume --label example --check --blob-file blob-age-rage.txt >"$S/out" 2>"$S/err" \
  || { cat "$S/err" >&2; fail "the rage blob (X25519 + -grease) was refused"; }
diff "$S/out" expected-check.txt || fail "the rage blob: --check output differs"
# Header edges, built from blob-age.txt. Each is refused before `age` runs: the
# stub `age` (marker) must not have started.
python3 -c '
import base64, sys
raw = base64.b64decode(open(sys.argv[1]).read())
out = sys.argv[2]
magic = b"age-encryption.org/v1\n"
assert raw.startswith(magic)
first_end = raw.index(b"\n", len(magic)) + 1       # the X25519 stanza line, through its newline
end_line = raw.index(b"\n--- ") + 1               # the "--- MAC" line
after_end = raw.index(b"\n", end_line)            # its newline
def put(name, data):
    open("%s/hdr-%s.txt" % (out, name), "w").write(base64.b64encode(data).decode())
put("crlf-end", raw[:end_line] + b"---\r" + raw[after_end:])
put("no-type", magic + b"-> \n" + raw[first_end:])
put("junk-first", magic + b"junk\n" + raw[len(magic):])
put("cut-mid-stanza", raw[:first_end + 8])
put("no-end", raw[:end_line])
put("trunc-after-header", raw[:after_end + 1])
raw = bytearray(raw); raw[-1] ^= 1
put("flipped", bytes(raw))
' blob-age.txt "$S"
rm -f "$S/age-ran"
expect_refusal "header, CRLF end line" 1 "not an age blob" \
  env PATH="$S/stub:$PATH" HANDOFF_PRIVKEY="$TMPKEY" python3 ../consume.py --label example --check --blob-file "$S/hdr-crlf-end.txt"
expect_refusal "header, a stanza with no type" 1 "$M" \
  env PATH="$S/stub:$PATH" HANDOFF_PRIVKEY="$TMPKEY" python3 ../consume.py --label example --check --blob-file "$S/hdr-no-type.txt"
expect_refusal "header, a non-stanza line before the first stanza" 1 "not an age blob" \
  env PATH="$S/stub:$PATH" HANDOFF_PRIVKEY="$TMPKEY" python3 ../consume.py --label example --check --blob-file "$S/hdr-junk-first.txt"
expect_refusal "header, cut mid-stanza" 1 "not an age blob" \
  env PATH="$S/stub:$PATH" HANDOFF_PRIVKEY="$TMPKEY" python3 ../consume.py --label example --check --blob-file "$S/hdr-cut-mid-stanza.txt"
expect_refusal "header, no end line" 1 "not an age blob" \
  env PATH="$S/stub:$PATH" HANDOFF_PRIVKEY="$TMPKEY" python3 ../consume.py --label example --check --blob-file "$S/hdr-no-end.txt"
[ ! -e "$S/age-ran" ] || fail "age was started for a blob with a bad header"
# age's own failures: one fixed message, whichever way it failed.
D="decryption failed with the key at '$TMPKEY'"
expect_refusal "a flipped last byte" 1 "$D" \
  consume --label example --check --blob-file "$S/hdr-flipped.txt"
expect_refusal "truncated after the header" 1 "$D" \
  consume --label example --check --blob-file "$S/hdr-trunc-after-header.txt"
rm -f "$S/other-identity.txt"; "$AGE_KEYGEN" -o "$S/other-identity.txt" 2>/dev/null
expect_refusal "the wrong identity" 1 "decryption failed with the key at '$S/other-identity.txt'" \
  env HANDOFF_PRIVKEY="$S/other-identity.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
! grep -q "no identity matched\|age: " "$S/err" || fail "the decrypt refusal shows age's text: $(cat "$S/err")"
# The age that ran is reported, so a refusal can be traced to a version.
mkdir -p "$S/verstub"
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
printf '#!/bin/sh\nif [ "$1" = --version ]; then echo v9.9.9-test; exit 0; fi\ncat >/dev/null\nexit 1\n' >"$S/verstub/age"
chmod 755 "$S/verstub/age"
expect_refusal "the age version is reported" 1 "age v9.9.9-test" \
  env PATH="$S/verstub:$PATH" HANDOFF_PRIVKEY="$TMPKEY" python3 ../consume.py --label example --check --blob-file blob-age.txt
# Identity-file checks. Each file is owner-only unless the test says otherwise.
cp test-dummy-identity.txt "$S/loose.txt"; chmod 644 "$S/loose.txt"
expect_refusal "group/other-readable identity" 1 "must be owner-only" \
  env HANDOFF_PRIVKEY="$S/loose.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
chmod 640 "$S/loose.txt"
expect_refusal "a group-readable identity (0640, consume.py)" 1 "is mode 640; it must be owner-only (0600)" \
  env HANDOFF_PRIVKEY="$S/loose.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
ln -sf "$TMPKEY" "$S/id-link.txt"
expect_refusal "a symlinked identity" 1 "is a symbolic link" \
  env HANDOFF_PRIVKEY="$S/id-link.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
cat "$TMPKEY" "$TMPKEY" >"$S/id-two.txt"
expect_refusal "an identity with two secret keys" 1 "holds 2 secret keys" \
  env HANDOFF_PRIVKEY="$S/id-two.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
{ cat "$TMPKEY"; echo "AGE-PLUGIN-FOO-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"; } >"$S/id-plugin.txt"
expect_refusal "a plugin identity line" 1 "plugin identity" \
  env HANDOFF_PRIVKEY="$S/id-plugin.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
{ cat "$TMPKEY"; echo "AGE-SECRET-KEY-PQ-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"; } >"$S/id-pq.txt"
expect_refusal "a post-quantum identity line" 1 "post-quantum identity" \
  env HANDOFF_PRIVKEY="$S/id-pq.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
cp "$RSAKEY" "$S/id-rsa.txt"
expect_refusal "an RSA PEM at the identity path" 1 "an RSA key from 0.1.0; 0.2.0 uses age: a 0.1.0 install sets up again" \
  env HANDOFF_PRIVKEY="$S/id-rsa.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
# Any other text is refused before age-keygen runs (a stub age-keygen leaves a marker).
mkdir -p "$S/kgstub"
printf '#!/bin/sh\ntouch "%s/keygen-ran"\nexit 1\n' "$S" >"$S/kgstub/age-keygen"
chmod 755 "$S/kgstub/age-keygen"
rm -f "$S/keygen-ran"
cp handoff-test.age "$S/id-recipient.txt"; chmod 600 "$S/id-recipient.txt"
expect_refusal "a recipient saved at the identity path" 1 "is not an age identity file; that is a recipient (public), not an identity" \
  env PATH="$S/kgstub:$PATH" HANDOFF_PRIVKEY="$S/id-recipient.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
printf 'just some text\n' >"$S/id-text.txt"
expect_refusal "arbitrary text at the identity path" 1 "is not an age identity file" \
  env PATH="$S/kgstub:$PATH" HANDOFF_PRIVKEY="$S/id-text.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
! grep -q recipient "$S/err" || fail "arbitrary text was called a recipient"
[ ! -e "$S/keygen-ran" ] || fail "age-keygen was started for a file that isn't an identity"
# Lines split on \n alone, as age and agent-setup.sh split them (issue #43
# item 18): a \f, \v or U+2028 inside a comment doesn't make a line of its own.
for c in $'\f' $'\v' $'\xe2\x80\xa8'; do
  { printf '# a comment%swith it inside\n' "$c"; cat "$TMPKEY"; } >"$S/id-ctl.txt"; chmod 600 "$S/id-ctl.txt"
  HANDOFF_PRIVKEY="$S/id-ctl.txt" consume --label example --check --blob-file blob-age.txt >/dev/null 2>"$S/err" \
    || { cat "$S/err" >&2; fail "consume.py refused an identity with $(printf '%q' "$c") in a comment"; }
  bash ../agent-setup.sh --fingerprint "$S/id-ctl.txt" >/dev/null 2>&1 || fail "agent-setup.sh refused an identity with $(printf '%q' "$c") in a comment"
done
echo "ok (an identity's comment may hold a form feed, a vertical tab or U+2028, in both tools)"
# The environment age gets is built from scratch: none of the variables it reads
# (age 1.3.2: AGE_PASSPHRASE, AGE_PASSPHRASE_FD, AGE_PASSPHRASE_WORK_FACTOR,
# AGE_PASSPHRASE_MAX_WORK_FACTOR, AGEDEBUG) reaches it, nor anything else.
mkdir -p "$S/envstub"
printf '#!/bin/sh\nenv >"%s/age-env"\nexec %s "$@"\n' "$S" "$(command -v "$AGE")" >"$S/envstub/age"
chmod 755 "$S/envstub/age"
printf '#!/bin/sh\nenv >"%s/keygen-env"\nexec %s "$@"\n' "$S" "$(command -v "$AGE_KEYGEN")" >"$S/envstub/age-keygen"
chmod 755 "$S/envstub/age-keygen"
rm -f "$S/age-env" "$S/keygen-env"
env PATH="$S/envstub:$PATH" HANDOFF_PRIVKEY="$TMPKEY" \
  AGE_PASSPHRASE=x AGE_PASSPHRASE_FD=3 AGE_PASSPHRASE_WORK_FACTOR=5 AGE_PASSPHRASE_MAX_WORK_FACTOR=5 AGEDEBUG=1 \
  python3 ../consume.py --label example --check --blob-file blob-age.txt >"$S/out" 2>"$S/err" \
  || { cat "$S/err" >&2; fail "the env-isolation run failed"; }
[ -s "$S/age-env" ] || fail "the stub age didn't run"
for v in AGE_PASSPHRASE AGE_PASSPHRASE_FD AGE_PASSPHRASE_WORK_FACTOR AGE_PASSPHRASE_MAX_WORK_FACTOR AGEDEBUG; do
  ! grep -q "^$v=" "$S/age-env" || fail "$v reached age"
  ! grep -q "^$v=" "$S/keygen-env" || fail "$v reached age-keygen"
done
# Nothing beyond PATH and what sh itself sets.
for f in age-env keygen-env; do
  [ -s "$S/$f" ] || fail "the stub for $f didn't run"
  extra=$(grep -v '^\(PATH\|PWD\|OLDPWD\|SHLVL\|_\)=' "$S/$f" || true)
  [ -z "$extra" ] || fail "$f: unexpected variables reached the tool: $(printf '%s' "$extra" | cut -d= -f1 | tr '\n' ' ')"
done
! grep -q "^HANDOFF_" "$S/age-env" || fail "a HANDOFF_ variable reached age"
# age present, age-keygen missing or not executable: a clear refusal, no traceback.
mkdir -p "$S/onlyage" "$S/nx"
ln -sf "$(command -v "$AGE")" "$S/onlyage/age"
expect_refusal "age-keygen missing from PATH" 1 "age-keygen not found" \
  env PATH="$S/onlyage" HANDOFF_PRIVKEY="$TMPKEY" "$PY" ../consume.py --label example --check --blob-file blob-age.txt
printf '#!/bin/sh\nexit 0\n' >"$S/nx/age-keygen"; chmod 644 "$S/nx/age-keygen"
expect_refusal "age-keygen not executable" 1 "cannot run age-keygen" \
  env PATH="$S/nx:$S/onlyage" HANDOFF_PRIVKEY="$TMPKEY" "$PY" ../consume.py --label example --check --blob-file blob-age.txt
grep -qF "PATH was '$S/nx:$S/onlyage'" "$S/err" || fail "the refusal doesn't name the PATH it searched"
# Only RSA-type PEM blocks are called 0.1.0 keys; any other block is just not an identity.
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZSBib2R5\n-----END OPENSSH PRIVATE KEY-----\n' >"$S/id-openssh.txt"
chmod 600 "$S/id-openssh.txt"
expect_refusal "an OpenSSH-style key block at the identity path" 1 "is not an age identity file" \
  env HANDOFF_PRIVKEY="$S/id-openssh.txt" python3 ../consume.py --label example --check --blob-file blob-age.txt
! grep -q "0.1.0" "$S/err" || fail "an OpenSSH key was called a 0.1.0 key"
echo "ok"
fi

if section 5b; then
echo "== 5b. handoff.sh's recipient: handoff-NAME.age beside the script, and nothing else =="
prep_shared
prep_agent
K="$S/hk"; mkdir -p "$K"; cp ../handoff.sh "$K/handoff.sh"
pay='{"svc":"example","password":"mk-Zq9"}'
BASH_BIN=$(command -v bash)
# No recipient file: no ciphertext, and no recipient in the script to fall back on.
expect_refusal "handoff.sh with no recipient file" 1 "no recipient file for 'muse': $K/handoff-muse.age doesn't exist" \
  bash "$K/handoff.sh" <<<"$pay"
expect_refusal "handoff.sh --fingerprint with no recipient file" 1 "no recipient file for 'muse'" \
  bash "$K/handoff.sh" --fingerprint
# A backstop only: the behavior above (no file, no ciphertext) is the proof.
! grep -q 'age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]\{58\}' ../handoff.sh \
  || fail "handoff.sh still embeds a recipient"
# --to NAME picks handoff-NAME.age; --fingerprint names the file it read.
cp handoff-test.age "$K/handoff-other.age"
[ "$(bash "$K/handoff.sh" --to other --fingerprint 2>"$S/err")" = "$want" ] \
  || fail "--to other didn't read handoff-other.age"
grep -qxF "key file: $K/handoff-other.age" "$S/err" || fail "--fingerprint didn't name the file it read"
expect_refusal "handoff.sh --to a recipient with no file" 1 "no recipient file for 'nobody'" \
  bash "$K/handoff.sh" --to nobody --fingerprint
# With no --to, the recipient is muse.
cp handoff-test.age "$K/handoff-muse.age"
[ "$(bash "$K/handoff.sh" --fingerprint 2>"$S/err")" = "$want" ] \
  || fail "with no --to, handoff.sh didn't read handoff-muse.age"
grep -qxF "key file: $K/handoff-muse.age" "$S/err" || fail "with no --to, handoff.sh didn't name handoff-muse.age"
rm "$K/handoff-muse.age"
# Encrypting names the recipient file beside the recipient, and the blob round-trips.
bash "$K/handoff.sh" --to other expected.json >"$S/blob4" 2>"$S/err" || { cat "$S/err" >&2; fail "handoff.sh --to other FILE failed"; }
grep -qF "$want (from $K/handoff-other.age)" "$S/err" || fail "the encrypt run didn't name its recipient file"
grep -qF -- "--- paste everything below into chat with other (recipient file $K/handoff-other.age) ---" "$S/err" \
  || fail "the paste banner didn't name the recipient"
out=$(HANDOFF_BLOB="$(cat "$S/blob4")" consume --label example -- python3 -c '
import os
print(os.environ["SERVICE_PASSWORD"])
')
[ "$out" = "$P" ] || fail "the --to blob did not round-trip"
# A name that isn't plain letters, digits, _ and -, or is too long, is a usage error.
expect_refusal "handoff.sh --to a path" 2 "--to NAME takes only letters, digits, _ and -" \
  bash "$K/handoff.sh" --to ../other --fingerprint
expect_refusal "handoff.sh --to an empty name" 2 "--to NAME takes only letters, digits, _ and -" \
  bash "$K/handoff.sh" --to '' --fingerprint
expect_refusal "handoff.sh --to a non-ASCII name" 2 "--to NAME takes only letters, digits, _ and -" \
  bash "$K/handoff.sh" --to "othér" --fingerprint
expect_refusal "handoff.sh --to a 65-character name" 2 "--to NAME is at most 64 characters" \
  bash "$K/handoff.sh" --to "$(printf 'a%.0s' $(seq 65))" --fingerprint
cp handoff-test.age "$K/handoff-$(printf 'a%.0s' $(seq 64)).age"
[ "$(bash "$K/handoff.sh" --to "$(printf 'a%.0s' $(seq 64))" --fingerprint 2>/dev/null)" = "$want" ] \
  || fail "handoff.sh refused a 64-character name"
expect_refusal "handoff.sh --to with no NAME" 2 "--to needs a NAME" bash "$K/handoff.sh" --to
expect_refusal "handoff.sh --to followed by an option" 2 "--to needs a NAME" bash "$K/handoff.sh" --to --fingerprint
expect_refusal "handoff.sh --to=NAME" 2 "write --to NAME, with a space" bash "$K/handoff.sh" --to=other --fingerprint
expect_refusal "handoff.sh NAME starting with -" 2 "--to NAME can't start with -" \
  bash "$K/handoff.sh" --to -muse --fingerprint
expect_refusal "handoff.sh two FILEs, both after --" 2 "at most one FILE" \
  bash "$K/handoff.sh" --to other -- expected.json expected.json </dev/null
expect_refusal "handoff.sh through process substitution" 1 "save handoff.sh to a file and run that file" \
  bash <(cat "$K/handoff.sh") --to other --fingerprint
expect_refusal "handoff.sh as /dev/stdin" 1 "save handoff.sh to a file and run that file" \
  bash /dev/stdin --to other --fingerprint < "$K/handoff.sh"
expect_refusal "handoff.sh as //dev/stdin" 1 "save handoff.sh to a file and run that file" \
  bash //dev/stdin --to other --fingerprint < "$K/handoff.sh"
# bash in POSIX mode (macOS's sh, or POSIXLY_CORRECT / SHELLOPTS=posix set)
# leaves POSIX mode, so the script runs the same either way.
for how in "bash --posix" "env POSIXLY_CORRECT=1 bash" "env SHELLOPTS=posix bash"; do
  $how "$K/handoff.sh" --to other expected.json >"$S/blob6" 2>"$S/err" \
    || { cat "$S/err" >&2; fail "handoff.sh failed under $how"; }
  out=$(HANDOFF_BLOB="$(cat "$S/blob6")" consume --label example -- python3 -c '
import os
print(os.environ["SERVICE_PASSWORD"])
')
  [ "$out" = "$P" ] || fail "the blob made under $how did not round-trip"
done
# A real file under /dev/shm is not a descriptor: it runs.
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
  SH=$(mktemp -d /dev/shm/handoff-test.XXXXXX)
  cp ../handoff.sh "$SH/handoff.sh"; cp handoff-test.age "$SH/handoff-muse.age"
  [ "$(bash "$SH/handoff.sh" --fingerprint 2>/dev/null)" = "$want" ] || { rm -rf "$SH"; fail "handoff.sh refused to run from /dev/shm"; }
  rm -rf "$SH"
elif [ "$(uname -s)" = Darwin ]; then
  echo "n/a on this OS: handoff.sh's run from /dev/shm (macOS has no /dev/shm)"
else
  echo "skip: no writable /dev/shm, handoff.sh's run from it not tested"
fi
# A near-miss file name is named.
mkdir -p "$S/hn"; cp ../handoff.sh "$S/hn/handoff.sh"
# Only a short allow-list counts as a near miss; anything else (a kept old file
# under any suffix, a directory, a symlink) gets the plain message.
for old in handoff-muse.age.old handoff-muse.age.OLD handoff-muse.age.bak handoff-muse.age~ handoff-muse.age.2025-06-01 handoff-muse.age.save handoff_muse.age.d handoff_muse.age.lnk handoffXmuse.age; do
  rm -rf "$S/hn/"handoff?muse.age* "$S/hn/"handoff?Muse.age*
  case "$old" in
    *.d) mkdir "$S/hn/handoff_muse.age"; old="handoff_muse.age (a directory)" ;;
    *.lnk) ln -s "$PWD/handoff-test.age" "$S/hn/handoff_muse.age" ;;
    *) cp handoff-test.age "$S/hn/$old" ;;
  esac
  expect_refusal "handoff.sh with only $old beside it" 1 "handoff-muse.age doesn't exist. Save the agent's recipient there" \
    bash "$S/hn/handoff.sh" --fingerprint
done
for near in handoff_muse.age handoff.muse.age HANDOFF_MUSE.age handoff-muse.age.txt handoff-muse.age.age; do
  rm -rf "$S/hn/"handoff?muse.age* "$S/hn/"handoff?Muse.age* "$S/hn/"HANDOFF?MUSE.age*
  cp handoff-test.age "$S/hn/$near"
  expect_refusal "handoff.sh with $near beside it" 1 "but $near does. If that file is the agent's current recipient, rename it to handoff-muse.age, then compare --fingerprint" \
    bash "$S/hn/handoff.sh" --fingerprint
done
rm -rf "$S/hn/"handoff?muse.age* "$S/hn/"handoff?Muse.age* "$S/hn/"HANDOFF?MUSE.age*
# A caller's BASHOPTS (failglob: an unmatched near-miss pattern was fatal) or
# SHELLOPTS (noglob: no pattern matched) doesn't change the near-miss lookup
# (issue #43 item 12).
cp handoff-test.age "$S/hn/handoff_muse.age"
for o in BASHOPTS=failglob SHELLOPTS=noglob; do
  expect_refusal "handoff.sh with handoff_muse.age beside it, under $o" 1 "but handoff_muse.age does. If that file is the agent's current recipient" \
    env "$o" bash "$S/hn/handoff.sh" --fingerprint
done
rm -f "$S/hn/handoff_muse.age"
# Only NAME's case differs: the hint suggests the other --to, not a rename.
cp handoff-test.age "$S/hn/handoff-muse.age"
if [ -e "$S/hn/HANDOFF-MUSE.AGE" ]; then
  # A case-insensitive file system (macOS's APFS by default): --to Muse
  # opens handoff-muse.age, as run-test.ps1 expects on Windows.
  out=$(bash "$S/hn/handoff.sh" --to Muse --fingerprint 2>"$S/err") \
    || { cat "$S/err" >&2; fail "--to Muse on a case-insensitive file system was refused"; }
  [ "$out" = "recipient: $(cat handoff-test.age)" ] || fail "--to Muse on a case-insensitive file system: $out"
  echo "ok (--to Muse opens handoff-muse.age here: a case-insensitive file system)"
else
  expect_refusal "handoff.sh --to Muse with handoff-muse.age beside it" 1 "but handoff-muse.age does. Names are case-sensitive: did you mean --to muse?" \
    bash "$S/hn/handoff.sh" --to Muse --fingerprint
fi
rm -f "$S/hn/handoff-muse.age"
# The case and the separator both differ, for a NAME given with --to: the
# rename keeps the file's own NAME and --to names it, so a run with no --to
# still finds it (issue #27 item 2). With no --to, the rename is to the default.
cp handoff-test.age "$S/hn/handoff_muse.age"
expect_refusal "handoff.sh --to Muse with handoff_muse.age beside it" 1 "but handoff_muse.age does. If that file is the agent's current recipient, rename it to handoff-muse.age and run with --to muse (names are case-sensitive)" \
  bash "$S/hn/handoff.sh" --to Muse --fingerprint
rm -f "$S/hn/handoff_muse.age"
# --to naming the default gets the rename to the default name, as no --to does.
cp handoff-test.age "$S/hn/handoff_Muse.age"
expect_refusal "handoff.sh --to muse with handoff_Muse.age beside it" 1 "but handoff_Muse.age does. If that file is the agent's current recipient, rename it to handoff-muse.age, then compare --fingerprint" \
  bash "$S/hn/handoff.sh" --to muse --fingerprint
rm -f "$S/hn/handoff_Muse.age"
# A look-alike that a UTF-8 locale folds to ASCII (U+212A KELVIN SIGN lowers
# to k) isn't a near miss: it would show as handoff-Kim.age (issue #27 item 1).
# The first of these names that this system takes as a UTF-8 locale (asked of
# the locale itself: locale -a's list didn't match on macOS's runner).
utf8_loc=
for l in C.UTF-8 en_US.UTF-8 C.utf8 en_US.utf8; do
  if [ "$(LC_ALL=$l locale charmap 2>/dev/null)" = UTF-8 ]; then utf8_loc=$l; break; fi
done
if [ -n "$utf8_loc" ]; then
  kelvin="handoff-"$'\xe2\x84\xaa'"im.age"
  cp handoff-test.age "$S/hn/$kelvin"
  if [ -e "$S/hn/handoff-Kim.age" ]; then
    # A file system that normalizes and folds names (macOS's APFS): the
    # look-alike is handoff-Kim.age itself there, so --to Kim opens it.
    out=$(env LC_ALL="$utf8_loc" bash "$S/hn/handoff.sh" --to Kim --fingerprint 2>"$S/err") \
      || { cat "$S/err" >&2; fail "--to Kim on a name-folding file system was refused"; }
    [ "$out" = "recipient: $(cat handoff-test.age)" ] || fail "--to Kim on a name-folding file system: $out"
    echo "ok (--to Kim opens the KELVIN SIGN name here: a file system that folds names)"
  else
    expect_refusal "handoff.sh --to Kim with a KELVIN SIGN look-alike beside it" 1 "handoff-Kim.age doesn't exist. Save the agent's recipient there" \
      env LC_ALL="$utf8_loc" bash "$S/hn/handoff.sh" --to Kim --fingerprint
  fi
  rm -f "$S/hn/$kelvin"
else
  echo "skip: no UTF-8 locale, the KELVIN SIGN near-miss check not tested"
fi
# With the allow-list, a near-miss name can only be a case or separator
# variant of handoff-NAME.age: a newline in place of the - isn't offered.
nl_name=$'handoff\nmuse.age'
cp handoff-test.age "$S/hn/$nl_name"
expect_refusal "handoff.sh with a newline in place of the -" 1 "handoff-muse.age doesn't exist. Save the agent's recipient there" \
  bash "$S/hn/handoff.sh" --fingerprint
rm -f "$S/hn/$nl_name"
# A 0.1.0 install: handoff-muse.pem beside it and no .age. It says 0.2.0 uses
# age and to ask the agent for its recipient; the key is never used.
fake_pem "PUBLIC KEY" > "$S/hn/handoff-muse.pem"
expect_refusal "handoff.sh with a .pem and no .age" 1 "0.2.0 uses age" \
  bash "$S/hn/handoff.sh" <<<"$pay"
grep -qF "ask your agent for its recipient" "$S/err" || fail "the .pem refusal doesn't say to ask for the recipient"
expect_refusal "handoff.sh --fingerprint with a .pem and no .age" 1 "0.2.0 uses age" \
  bash "$S/hn/handoff.sh" --fingerprint
rm -f "$S/hn/handoff-muse.pem"
# After --, the next argument is FILE even if it starts with -.
cp expected.json "$K/-x.json"
( cd "$K" && bash handoff.sh --to other -- -x.json </dev/null >"$S/blob5" 2>/dev/null ) || fail "handoff.sh -- -x.json failed"
out=$(HANDOFF_BLOB="$(cat "$S/blob5")" consume --label example -- python3 -c '
import os
print(os.environ["SERVICE_PASSWORD"])
')
[ "$out" = "$P" ] || fail "the -- FILE blob did not round-trip"
# Under another shell than bash, it says to run it with bash.
other_sh=
for s in zsh dash ksh mksh; do if command -v "$s" >/dev/null; then other_sh=$s; break; fi; done
if [ -n "$other_sh" ]; then
  expect_refusal "handoff.sh under $other_sh" 1 "run it with bash" "$other_sh" "$K/handoff.sh" --to other --fingerprint
  expect_refusal "agent-setup.sh under $other_sh" 1 "agent-setup.sh: run it with bash" "$other_sh" ../agent-setup.sh --fingerprint "$TMPKEY"
else
  echo "skip: no zsh, dash, ksh or mksh, the bash checks of handoff.sh and agent-setup.sh not tested"
fi
expect_refusal "handoff.sh on stdin, with no path" 1 "save handoff.sh to a file and run that file" \
  bash -s -- --fingerprint < "$K/handoff.sh"
expect_refusal "handoff.sh --to twice" 2 "--to given more than once" \
  bash "$K/handoff.sh" --to other --to other --fingerprint
expect_refusal "handoff.sh unknown option" 2 "unknown option --bogus" bash "$K/handoff.sh" --bogus
expect_refusal "handoff.sh --fingerprint with a FILE" 2 "--fingerprint takes no FILE" \
  bash "$K/handoff.sh" --to other --fingerprint expected.json
expect_refusal "handoff.sh two FILEs" 2 "at most one FILE" \
  bash "$K/handoff.sh" --to other expected.json expected.json
expect_refusal "handoff.sh two FILEs, the second after --" 2 "at most one FILE" \
  bash "$K/handoff.sh" --to other expected.json -- expected.json
# Options may follow FILE.
bash "$K/handoff.sh" expected.json --to other >/dev/null 2>"$S/err" \
  || { cat "$S/err" >&2; fail "handoff.sh FILE --to NAME was refused"; }
grep -qF "(from $K/handoff-other.age)" "$S/err" || fail "handoff.sh FILE --to NAME didn't read handoff-other.age"
expect_refusal "handoff.sh FILE then --fingerprint" 2 "--fingerprint takes no FILE" \
  bash "$K/handoff.sh" expected.json --fingerprint
# Run by a relative path, the file is named relative to the working directory.
( cd "$K" && bash handoff.sh --to other --fingerprint ) 2>"$S/err" >/dev/null || fail "handoff.sh run as bash handoff.sh failed"
grep -qxF "key file: ./handoff-other.age" "$S/err" || fail "bash handoff.sh named its recipient file $(cat "$S/err")"
( cd "$S" && bash hk/handoff.sh --to other --fingerprint ) 2>"$S/err" >/dev/null || fail "handoff.sh run as bash hk/handoff.sh failed"
grep -qxF "key file: ./hk/handoff-other.age" "$S/err" || fail "bash hk/handoff.sh named its recipient file $(cat "$S/err")"
# Recipient files that aren't a regular file, or aren't there.
mkdir "$K/handoff-dir.age"
expect_refusal "handoff.sh recipient file that is a directory" 1 "handoff-dir.age is not a regular file" \
  bash "$K/handoff.sh" --to dir --fingerprint
ln -s "$K/nowhere.age" "$K/handoff-dangling.age"
expect_refusal "handoff.sh recipient file that is a dangling symlink" 1 "handoff-dangling.age is a symlink that doesn't resolve to a file" \
  bash "$K/handoff.sh" --to dangling --fingerprint
ln -s handoff-loop.age "$K/handoff-loop.age"
expect_refusal "handoff.sh recipient file that is a symlink loop" 1 "handoff-loop.age is a symlink that doesn't resolve to a file" \
  bash "$K/handoff.sh" --to loop --fingerprint
# A symlink that resolves to a valid recipient file is refused too: whoever
# can repoint it changes the recipient (issue #27, the maintainer's call).
ln -s "$PWD/handoff-test.age" "$K/handoff-linked.age"
expect_refusal "handoff.sh recipient file that is a symlink to a valid one" 1 "handoff-linked.age is a symlink: remove the link itself (rm, which leaves its target alone), then save the agent's recipient there as a plain file" \
  bash "$K/handoff.sh" --to linked --fingerprint
expect_refusal "handoff.sh encrypting to a recipient file that is a symlink" 1 "handoff-linked.age is a symlink" \
  bash "$K/handoff.sh" --to linked <<<"$pay"
env -i PATH="$PATH" bash "$K/handoff.sh" --to linked --check-setup >"$S/out" 2>"$S/err" && fail "--check-setup passed a symlinked recipient file"
grep -q '^FAIL recipient: .*handoff-linked.age is a symlink' "$S/out" || fail "--check-setup didn't fail a symlinked recipient file: $(grep recipient "$S/out")"
echo "ok (refused: a symlinked recipient file, in --check-setup too)"
# A directory with a bidi override in its name: the key file line quotes the
# path in C, so the override shows as an escape, never raw (in a UTF-8 locale
# printf %q alone leaves it).
if [ -n "${utf8_loc-}" ]; then
  bd="$S/u"$'\xe2\x80\xae'"x"; mkdir -p "$bd"; cp ../handoff.sh "$bd/handoff.sh"; cp handoff-test.age "$bd/handoff-muse.age"
  env LC_ALL="$utf8_loc" bash "$bd/handoff.sh" --fingerprint >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "handoff.sh in a directory with a bidi override failed"; }
  ! LC_ALL=C grep -q $'\xe2\x80\xae' "$S/err" || fail "handoff.sh printed a raw bidi override: $(cat -v "$S/err")"
  grep -qF 'key file: $' "$S/err" || fail "handoff.sh's key file line isn't C-quoted: $(cat -v "$S/err")"
  echo "ok (a bidi override in the script's directory shows escaped)"
fi
# Run through a symlink, it reads the recipient beside the link, not the target.
mkdir -p "$S/hl"; ln -s "$K/handoff.sh" "$S/hl/handoff.sh"
expect_refusal "handoff.sh through a symlink, recipient only beside the target" 1 "$S/hl/handoff-other.age doesn't exist" \
  bash "$S/hl/handoff.sh" --to other --fingerprint
cp handoff-test.age "$S/hl/handoff-other.age"
[ "$(bash "$S/hl/handoff.sh" --to other --fingerprint 2>/dev/null)" = "$want" ] \
  || fail "handoff.sh through a symlink didn't read the recipient beside the link"
# The recipient-file cases that are a file's contents, one table shared with
# run-test.ps1 (user-side-cases.json): {name, file_bytes_b64, to, exit,
# stderr_contains}. Each is written as handoff-<to>.age, then handoff.sh runs
# with a valid payload on stdin. exit 0 cases must also make a blob that opens.
ut="$S/ut"; mkdir -p "$ut"; cp ../handoff.sh "$ut/handoff.sh"
ncases=$(jq length user-side-cases.json)
[ "$ncases" -gt 0 ] || fail "user-side-cases.json is empty"
for i in $(seq 0 $(( ncases - 1 ))); do
  c_name=$(jq -r ".[$i].name" user-side-cases.json)
  c_to=$(jq -r ".[$i].to" user-side-cases.json)
  c_exit=$(jq -r ".[$i].exit" user-side-cases.json)
  c_msg=$(jq -r ".[$i].stderr_contains" user-side-cases.json)
  [ "$(jq -r ".[$i] | keys | join(\",\")" user-side-cases.json)" = "exit,file_bytes_b64,name,stderr_contains,to" ] \
    || fail "user-side-cases.json: case $c_name has the wrong keys"
  jq -r ".[$i].file_bytes_b64" user-side-cases.json \
    | python3 -c 'import base64, sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' >"$ut/handoff-$c_to.age"
  if [ "$c_exit" = 0 ]; then
    bash "$ut/handoff.sh" --to "$c_to" <<<"$pay" >"$S/blob-case" 2>"$S/err" \
      || { cat "$S/err" >&2; fail "case $c_name: handoff.sh refused the file"; }
    grep -qF -- "$c_msg" "$S/err" || fail "case $c_name: stderr lacks \"$c_msg\""
    out=$(HANDOFF_BLOB="$(cat "$S/blob-case")" consume --label example -- python3 -c '
import os
print(os.environ["SERVICE_PASSWORD"])
')
    [ "$out" = mk-Zq9 ] || fail "case $c_name: the blob did not round-trip (not the same recipient)"
    [ "$(bash "$ut/handoff.sh" --to "$c_to" --fingerprint 2>/dev/null)" = "$want" ] \
      || fail "case $c_name: --fingerprint shows another recipient"
    echo "ok (accepted: $c_name)"
  else
    expect_refusal "recipient file case $c_name" "$c_exit" "$c_msg" \
      bash "$ut/handoff.sh" --to "$c_to" <<<"$pay"
  fi
  rm -f "$ut/handoff-$c_to.age"
done
# The payload shapes, one table shared with run-test.ps1 (payload-cases.json):
# {name, payload or payload_base64 (bytes that aren't text, or raw UTF-8 that
# a console could re-encode), exit, stderr_contains}. Each runs on stdin and
# as FILE; an accepted one's blob must open with consume.py --check and
# decrypt to the input's bytes (less a leading BOM and trailing LFs).
npc=$(jq length payload-cases.json)
[ "$npc" -gt 0 ] || fail "payload-cases.json is empty"
for i in $(seq 0 $(( npc - 1 ))); do
  c_name=$(jq -r ".[$i].name" payload-cases.json)
  case "$(jq -r ".[$i] | keys | join(\",\")" payload-cases.json)" in
    exit,name,payload,stderr_contains) jq -j ".[$i].payload" payload-cases.json >"$S/pc-in" ;;
    exit,name,payload_base64,stderr_contains)
      jq -r ".[$i].payload_base64" payload-cases.json \
        | python3 -c 'import base64, sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' >"$S/pc-in" ;;
    *) fail "payload-cases.json: case $i ($c_name) has the wrong keys" ;;
  esac
  c_exit=$(jq -r ".[$i].exit" payload-cases.json)
  c_msg=$(jq -r ".[$i].stderr_contains" payload-cases.json)
  if [ "$c_exit" = 0 ]; then
    for how in stdin FILE; do
      if [ "$how" = stdin ]; then
        bash "$S/hd/handoff.sh" <"$S/pc-in" >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "payload case $c_name ($how): refused"; }
      else
        bash "$S/hd/handoff.sh" "$S/pc-in" </dev/null >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "payload case $c_name ($how): refused"; }
      fi
      grep -qF -- "$c_msg" "$S/err" || fail "payload case $c_name ($how): stderr lacks \"$c_msg\""
      [ "$(wc -l <"$S/out")" -eq 1 ] || fail "payload case $c_name ($how): stdout is not one line"
      no_dummy_in "$S/out" "$S/err"
      consume --label example --check --blob-file "$S/out" >/dev/null 2>"$S/cerr" \
        || { cat "$S/cerr" >&2; fail "payload case $c_name ($how): consume.py --check refused the blob"; }
      # What handoff.sh encrypted, byte for byte: the input with a leading
      # UTF-8 byte-order mark dropped and its trailing line feeds dropped
      # ($(...) drops them), and nothing else changed (issue #47). Opening
      # the blob alone would pass a payload rewritten to other valid JSON.
      base64 -d <"$S/out" | "$AGE" -d -i "$TMPKEY" >"$S/pc-got" \
        || fail "payload case $c_name ($how): age couldn't open the blob"
      python3 -I -c 'import sys
b = open(sys.argv[1], "rb").read()
if b.startswith(b"\xef\xbb\xbf"):
    b = b[3:]
open(sys.argv[2], "wb").write(b.rstrip(b"\n"))' "$S/pc-in" "$S/pc-want"
      cmp -s "$S/pc-got" "$S/pc-want" \
        || fail "payload case $c_name ($how): the decrypted bytes differ from the input ($(( $(wc -c <"$S/pc-got") )) bytes, wanted $(( $(wc -c <"$S/pc-want") )))"
      rm -f "$S/pc-got" "$S/pc-want"
    done
    echo "ok (accepted: payload $c_name, and its blob holds the input's bytes)"
  else
    expect_refusal "payload case $c_name" "$c_exit" "$c_msg" bash "$S/hd/handoff.sh" <"$S/pc-in"
    expect_refusal "payload case $c_name (FILE)" "$c_exit" "$c_msg" bash "$S/hd/handoff.sh" "$S/pc-in" </dev/null
  fi
done
# The terminal read (stty -echo, then everything up to Ctrl-D) maps a NUL too:
# a raw NUL typed at the prompt is refused, never encrypted shortened. A
# pseudo-terminal from Python's pty, which types the payload, Enter and Ctrl-D,
# bounded at 20 s. Prints the exit status, then everything the terminal showed.
pty_type() {  # PAYLOAD-FILE CMD...
  python3 - "$@" <<'PY'
import os, pty, select, sys, time
data = open(sys.argv[1], "rb").read()
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[2], sys.argv[2:])
out, sent, end = b"", False, time.time() + 20
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    if not sent and b"Paste or type" in out:
        time.sleep(0.3)  # let stty -echo take effect
        os.write(fd, data)
        # macOS drops every byte past 1023 in a line (MAX_INPUT), Enter and
        # Ctrl-D too: a Backspace (VERASE, still handled) frees one place,
        # so the Enter after it ends the line, as a user would have to.
        if sys.platform == "darwin" and len(data) > 1000:
            time.sleep(0.2)
            os.write(fd, b"\x7f")
        os.write(fd, b"\n")
        time.sleep(0.2)
        os.write(fd, b"\x04")
        sent = True
else:
    os.kill(pid, 9)
_, st = os.waitpid(pid, 0)
sys.stdout.write("%d\n" % (os.WEXITSTATUS(st) if os.WIFEXITED(st) else 128))
sys.stdout.write(out.decode("utf-8", "replace"))
PY
}
printf '{"svc":"example","password":"mk-\000Zq9"}' >"$S/pty-nul.json"
out=$(pty_type "$S/pty-nul.json" "$BASH_BIN" "$S/hd/handoff.sh")
[ "${out%%$'\n'*}" = 1 ] || fail "a raw NUL typed at the terminal: exit ${out%%$'\n'*}, expected 1: $out"
case "$out" in
  *"input must be a single JSON object"*) ;;
  *) fail "a raw NUL typed at the terminal: no JSON refusal: $out" ;;
esac
! printf '%s' "$out" | grep -q -e '--- end ---' || fail "a raw NUL typed at the terminal: a blob was printed"
echo "ok (refused: a raw NUL typed at the terminal)"
# An accepted payload typed at the terminal, raw non-ASCII and a line break
# inside it: the blob opens to the typed bytes, less the final line feed
# (the Enter before Ctrl-D, which $(...) drops), the way the payload table's
# stdin and FILE cases do (issue #57). The blob is the line between the
# "--- paste everything below" and "--- end ---" lines the terminal showed.
printf '{"svc":"example",\n"password":"p\303\244ss-\346\227\245\346\234\254-\360\237\230\200-mk-Zq9"}' >"$S/pty-ok.json"
out=$(pty_type "$S/pty-ok.json" "$BASH_BIN" "$S/hd/handoff.sh")
[ "${out%%$'\n'*}" = 0 ] || fail "a payload typed at the terminal: exit ${out%%$'\n'*}, expected 0: $out"
# The prompt hides the input: the typed secret never shows on the terminal.
case "$out" in *"$MK"*) fail "a payload typed at the terminal was echoed" ;; esac
printf '%s\n' "$out" | tr -d '\r' | sed -n '/^--- paste everything below/,/^--- end ---$/p' | sed '1d;$d' >"$S/pty-ok.blob"
[ "$(wc -l <"$S/pty-ok.blob")" -eq 1 ] || fail "a payload typed at the terminal: no single blob line between the markers: $out"
base64 -d <"$S/pty-ok.blob" | "$AGE" -d -i "$TMPKEY" >"$S/pty-ok.got" \
  || fail "a payload typed at the terminal: age couldn't open the blob"
cmp -s "$S/pty-ok.got" "$S/pty-ok.json" \
  || fail "a payload typed at the terminal: the decrypted bytes differ from the typed ones ($(( $(wc -c <"$S/pty-ok.got") )) bytes, wanted $(( $(wc -c <"$S/pty-ok.json") )))"
consume --label example --check --blob-file "$S/pty-ok.blob" >/dev/null 2>"$S/cerr" \
  || { cat "$S/cerr" >&2; fail "a payload typed at the terminal: consume.py --check refused the blob"; }
rm -f "$S/pty-ok.got" "$S/pty-ok.blob"
echo "ok (accepted: a payload typed at the terminal, and its blob holds the typed bytes)"
# A line over the terminal's line cap (4095 bytes on Linux; on macOS 1023,
# past which every byte is dropped, so pty_type deletes one first) typed or
# pasted at the prompt is cut: refused, with the hint to use a FILE or a pipe
# (issue #64). The prompt says the limit before anything is typed. The same
# payload as FILE is accepted.
python3 -I -c 'print("{\"svc\":\"example\",\"password\":\"" + "a" * 4970 + "\"}", end="")' >"$S/pty-long.json"
out=$(pty_type "$S/pty-long.json" "$BASH_BIN" "$S/hd/handoff.sh")
[ "${out%%$'\n'*}" = 1 ] || fail "a 5,000-byte line at the terminal: exit ${out%%$'\n'*}, expected 1: ${out:0:300}"
case "$out" in
  *"one line can hold about 4 KB, 1 KB on macOS: for a longer one"*) ;;
  *) fail "the prompt doesn't say the terminal's line limit: ${out:0:300}" ;;
esac
case "$out" in
  *"a line reached the terminal's line limit (about 4 KB, 1 KB on macOS), so it may have been cut: for a long payload, use a pipe (or a FILE)"*) ;;
  *) fail "a 5,000-byte line at the terminal: no hint about the terminal's line cap: ${out:0:300}" ;;
esac
bash "$S/hd/handoff.sh" "$S/pty-long.json" </dev/null >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "the 5,000-byte payload as FILE was refused"; }
echo "ok (refused, with the line-cap hint: a 5,000-byte line at the terminal; accepted as FILE)"
# A paste over the read cap at the prompt: refused on size, and the rest of
# the paste is read to the Ctrl-D and dropped, so the shell that runs next
# reads only what was typed after it (a sentinel line), never payload text.
python3 -I - "$BASH_BIN" "$S/hd/handoff.sh" >"$S/pty-drain" <<'PY'
import os, pty, select, sys, time
bash, script = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.execv(bash, [bash, "-c", 'bash "$1"; echo "RC=$?"; IFS= read -r line; echo "AFTER=[$line]"', "_", script])
paste = (b"x" * 99 + b"\n") * 600   # 60,000 bytes, over the cap, in short lines
out, sent, end = b"", 0, time.time() + 30
def pump(t):
    global out
    r, _, _ = select.select([fd], [], [], t)
    if r:
        try:
            out += os.read(fd, 65536)
        except OSError:
            return False
    return True
while time.time() < end and b"Paste or type" not in out:
    pump(0.2)
time.sleep(0.3)
while sent < len(paste) and time.time() < end:
    _, w, _ = select.select([], [fd], [], 0.1)
    if w:
        sent += os.write(fd, paste[sent:sent + 1024])
    pump(0)
time.sleep(0.3)
os.write(fd, b"\x04")
while time.time() < end and b"RC=" not in out:
    pump(0.2)
time.sleep(0.3)
os.write(fd, b"LEFTOVER-SENTINEL\n")
while time.time() < end and b"AFTER=" not in out:
    if not pump(0.2):
        break
try:
    os.kill(pid, 9)
except ProcessLookupError:
    pass
os.waitpid(pid, 0)
sys.stdout.write(out.decode("utf-8", "replace"))
PY
grep -q 'RC=1' "$S/pty-drain" || fail "a paste over the cap at the terminal: no exit 1: $(tail -c 300 "$S/pty-drain")"
grep -q "the most handoff.sh sends is" "$S/pty-drain" || fail "a paste over the cap at the terminal: no size refusal: $(tail -c 300 "$S/pty-drain")"
grep -q 'AFTER=\[LEFTOVER-SENTINEL\]' "$S/pty-drain" || fail "a paste over the cap at the terminal: the shell read leftover input: $(grep -a 'AFTER=' "$S/pty-drain" | cut -c1-80)"
echo "ok (a paste over the cap at the terminal: refused, and none of it left for the shell)"
# One raw NUL beside the { is a control byte, not UTF-16: the JSON message.
printf '{\000"svc":"example","password":"mk-Zq9"}' >"$S/nul-lead.json"
expect_refusal "handoff.sh a raw NUL right after {" 1 "must be a single JSON object" bash "$S/hd/handoff.sh" "$S/nul-lead.json"
! grep -q "UTF-16" "$S/err" || fail "a raw NUL after { was called UTF-16"
# A bidi override in --to or an unknown option is shown escaped (qp in C).
if [ -n "${utf8_loc-}" ]; then
  expect_refusal "handoff.sh --to with a bidi override" 2 "--to NAME takes only letters" \
    env LC_ALL="$utf8_loc" bash "$S/hd/handoff.sh" --to "a"$'\xe2\x80\xae'"b" --fingerprint
  ! LC_ALL=C grep -q $'\xe2\x80\xae' "$S/err" || fail "a bidi override in --to was printed raw"
  expect_refusal "handoff.sh an unknown option with a bidi override" 2 "unknown option" \
    env LC_ALL="$utf8_loc" bash "$S/hd/handoff.sh" "--x"$'\xe2\x80\xae'"y"
  ! LC_ALL=C grep -q $'\xe2\x80\xae' "$S/err" || fail "a bidi override in an unknown option was printed raw"
fi
# The hint is for a long line at the terminal only: the same refusal from a
# pipe has none, and nor does a short line typed at the prompt.
expect_refusal "handoff.sh not JSON, piped" 1 "must be a single JSON object" bash "$S/hd/handoff.sh" <<<'not json'
! grep -q "the terminal's line limit" "$S/err" || fail "a piped refusal gave the terminal's line-cap hint"
printf '{"svc":"x" "password":"p"}' >"$S/pty-short.json"
out=$(pty_type "$S/pty-short.json" "$BASH_BIN" "$S/hd/handoff.sh")
case "$out" in *"must be a single JSON object"*) ;; *) fail "a short bad line at the terminal: no JSON refusal: $out" ;; esac
case "$out" in *"the terminal's line limit"*) fail "a short bad line at the terminal gave the line-cap hint" ;; esac
# Off macOS, a 2,000-byte line with an unrelated JSON error (a trailing
# comma) wasn't cut by the terminal (4,095 bytes there): no hint either.
if [ "$(uname -s)" != Darwin ]; then
  python3 -I -c 'print("{\"svc\":\"x\",\"password\":\"" + "a" * 1960 + "\",}", end="")' >"$S/pty-2k.json"
  out=$(pty_type "$S/pty-2k.json" "$BASH_BIN" "$S/hd/handoff.sh")
  case "$out" in *"must be a single JSON object"*) ;; *) fail "a 2,000-byte bad line at the terminal: no JSON refusal: ${out:0:300}" ;; esac
  case "$out" in *"the terminal's line limit"*) fail "a 2,000-byte bad line at the terminal gave the line-cap hint off macOS" ;; esac
fi
echo "ok (no line-cap hint: a piped refusal, a short line at the terminal, a 2,000-byte one off macOS)"
# A payload with only known fields gets no note.
bash "$S/hd/handoff.sh" <<<'{"svc":"example","username":"u","password":"mk-Zq9"}' >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "a known-fields payload was refused"; }
! grep -q "note:" "$S/err" || fail "a payload with only known fields got a note: $(cat "$S/err")"
echo "ok (no note: a payload with only known fields)"
# The note never prints the payload's text: a password typed in a name's
# place, two edits from "password", is named only as "close to password"
# (QA r1 on #81). Common passwords, each within two edits of "password".
for pw in 'P@ssw0rd' 'Passw0rd!' 'Password1' 'passw0rd'; do
  printf '{"svc":"example","username":"me","%s":"password"}' "$pw" | bash "$S/hd/handoff.sh" >/dev/null 2>"$S/err" \
    || { cat "$S/err" >&2; fail "a swapped field was refused"; }
  grep -qF 'close to "password"' "$S/err" || fail "a swapped field didn't get the note: $(cat "$S/err")"
  ! grep -qF -- "$pw" "$S/err" || fail "the note printed a password typed as a field name ($pw)"
done
echo "ok (the unknown-field note prints no payload text: four common passwords typed as names)"
# A UTF-16 file with a byte-order mark, little- and big-endian: handoff.sh
# reads UTF-8 only, and says so (handoff.ps1 reads one, so this isn't in the
# shared table; issue #44).
for enc in utf-16-le utf-16-be; do
  python3 -I -c 'import sys; e = sys.argv[1]; sys.stdout.buffer.write("\ufeff{\"svc\":\"example\",\"password\":\"mk-Zq9\"}".encode(e))' "$enc" >"$S/u16bom.json"
  expect_refusal "handoff.sh UTF-16 payload with a byte-order mark ($enc)" 1 "the payload is saved as UTF-16: save it as UTF-8" \
    bash "$S/hd/handoff.sh" "$S/u16bom.json"
done
# A directory as FILE gets its own message, not tr's or head's (#65 F18).
expect_refusal "handoff.sh a directory as FILE" 1 "is a directory, not a payload file" \
  bash "$S/hd/handoff.sh" "$S"
! grep -q -e 'tr:' -e 'head:' "$S/err" || fail "a directory as FILE leaked a tool's error: $(cat "$S/err")"
# The read is bounded (#65 F12): an endless FILE or pipe, or a large one,
# ends at once with the size refusal, before the pattern work, whose time
# grows with the square of the input (unbounded, 1 MB of spaces took 21 s on
# one machine and over 2 minutes under bash 5.3 on another).
# (Read here, not from section 3b, so section 5b runs alone too.)
cap5b=$(sed -n 's/^MAX_PAYLOAD=\([0-9]*\).*/\1/p' ../handoff.sh)
[ -n "$cap5b" ] || fail "test setup: MAX_PAYLOAD not found in handoff.sh"
if [ -e /dev/zero ]; then
  t0=$SECONDS
  expect_refusal "handoff.sh /dev/zero as FILE" 1 "the most handoff.sh sends is $cap5b bytes" \
    run_to_n 20 bash "$S/hd/handoff.sh" /dev/zero
  # shellcheck disable=SC2016  # $1 is the inner shell's argument
  expect_refusal "handoff.sh /dev/zero piped" 1 "the most handoff.sh sends is $cap5b bytes" \
    run_to_n 20 bash -c 'bash "$1" </dev/zero' _ "$S/hd/handoff.sh"
  head -c 4000000 /dev/zero | LC_ALL=C tr '\000' ' ' >"$S/spaces.json"
  expect_refusal "handoff.sh 4 MB of spaces" 1 "the most handoff.sh sends is $cap5b bytes" \
    run_to_n 20 bash "$S/hd/handoff.sh" "$S/spaces.json"
  [ $((SECONDS - t0)) -lt 15 ] || fail "the bounded reads took $((SECONDS - t0)) s"
  rm -f "$S/spaces.json"
  echo "ok (bounded: /dev/zero as FILE and piped, 4 MB of spaces)"
fi
# A payload at the cap with a byte-order mark and trailing line feeds: what's
# dropped before the count fits in the read's margin, so it's accepted.
{ printf '\xef\xbb\xbf'
  python3 -I -c 'import json, sys; n = int(sys.argv[1]); head = json.dumps({"svc": "example", "private_key": ""}, separators=(",", ":")); sys.stdout.write(head[:-2] + "y" * (n - len(head)) + head[-2:])' "$cap5b"
  printf '\n\n\n'; } >"$S/max-bom.json"
[ "$(( $(wc -c <"$S/max-bom.json") ))" = "$(( cap5b + 6 ))" ] || fail "test setup: the at-cap payload with a mark is $(( $(wc -c <"$S/max-bom.json") )) bytes"
bash "$S/hd/handoff.sh" "$S/max-bom.json" </dev/null >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "a payload at the cap with a byte-order mark and line feeds was refused"; }
echo "ok (accepted: a payload at the cap with a byte-order mark and trailing line feeds)"
# No core file (#65 F14): age, run by handoff.sh, inherits a core limit of 0.
# Raised first where the hard limit allows, so the test can tell.
mkdir -p "$S/corecheck"; real_age=$(command -v "$AGE")
printf '#!/bin/sh\nulimit -c >"%s/limit"\nexec %s "$@"\n' "$S/corecheck" "$real_age" >"$S/corecheck/age"; chmod 755 "$S/corecheck/age"
if bash -c 'ulimit -c 1024' 2>/dev/null; then
  rm -f "$S/corecheck/limit"
  bash -c 'ulimit -c 1024; exec env PATH="$1:$PATH" bash "$2" --fingerprint' _ "$S/corecheck" "$S/hd/handoff.sh" >/dev/null 2>"$S/err" \
    || { cat "$S/err" >&2; fail "handoff.sh with a stub age failed"; }
  [ "$(cat "$S/corecheck/limit" 2>/dev/null)" = 0 ] || fail "handoff.sh left the core limit at $(cat "$S/corecheck/limit" 2>/dev/null)"
  echo "ok (core files off: age ran with ulimit -c 0)"
else
  echo "skip: the hard core limit here is 0, the core-file check not tested"
fi
# The tools, refused before any prompt. jq: absent, then too old, then 1.6 (the
# floor, accepted). age: absent. Each runs under a pseudo-terminal when script(1)
# is there, where a prompt would show; the refusal must come first.
cp handoff-test.age "$K/handoff-muse.age"
refused_before_prompt() { # DESC MESSAGE ENV... (the command runs handoff.sh)
  local desc="$1" msg="$2"; shift 2
  expect_refusal "$desc" 1 "$msg" env "$@" "$BASH_BIN" "$K/handoff.sh" <<<"$pay"
  ! grep -q 'Paste or type' "$S/err" || fail "$desc: a prompt came before the refusal"
  if command -v script >/dev/null; then
    out=$(in_pty env "$@" "$BASH_BIN" "$K/handoff.sh" 2>&1) || true
    printf '%s' "$out" | grep -qF -- "$msg" || fail "$desc (terminal): no refusal: $out"
    ! printf '%s' "$out" | grep -q 'Paste or type' || fail "$desc (terminal): a prompt came before the refusal"
  fi
}
mkdir -p "$S/nojq" "$S/stubjq" "$S/onlyjq"
refused_before_prompt "handoff.sh without jq" "jq not found" PATH="$S/nojq"
printf '#!/bin/sh\necho jq-1.5\n' >"$S/stubjq/jq"; chmod 755 "$S/stubjq/jq"
refused_before_prompt "handoff.sh with jq 1.5" "jq 1.6 or newer is required; found jq-1.5" PATH="$S/stubjq:$PATH"
printf '#!/bin/sh\necho jq-0.9\n' >"$S/stubjq/jq"
refused_before_prompt "handoff.sh with jq 0.9" "jq 1.6 or newer is required; found jq-0.9" PATH="$S/stubjq:$PATH"
printf '#!/bin/sh\necho gibberish\n' >"$S/stubjq/jq"
refused_before_prompt "handoff.sh with an unreadable jq version" "found gibberish" PATH="$S/stubjq:$PATH"
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
printf '#!/bin/sh\nif [ "$1" = --version ]; then echo jq-1.6; else exec %s "$@"; fi\n' "$(command -v jq)" >"$S/stubjq/jq"
env PATH="$S/stubjq:$PATH" bash "$K/handoff.sh" <<<"$pay" >/dev/null 2>"$S/err" \
  || { cat "$S/err" >&2; fail "handoff.sh refused jq 1.6"; }
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
printf '#!/bin/sh\nif [ "$1" = --version ]; then echo jq-1.7.1-dirty; else exec %s "$@"; fi\n' "$(command -v jq)" >"$S/stubjq/jq"
env PATH="$S/stubjq:$PATH" bash "$K/handoff.sh" <<<"$pay" >/dev/null 2>"$S/err" \
  || { cat "$S/err" >&2; fail "handoff.sh refused jq 1.7.1-dirty"; }
ln -sf "$(command -v jq)" "$S/onlyjq/jq"
refused_before_prompt "handoff.sh without age" "age not found" PATH="$S/onlyjq"
# --fingerprint needs age too.
expect_refusal "handoff.sh --fingerprint without age" 1 "age not found" \
  env PATH="$S/nojq" "$BASH_BIN" "$K/handoff.sh" --fingerprint
# age runs with an environment of only PATH: a stub age logs its environment
# and arguments, then runs the real one. The caller's age variables and an
# exported SECRET_JSON must not reach it (or anything else handoff.sh runs).
mkdir -p "$S/agestub"
printf '#!/bin/sh\n{ env; echo "ARGV: $*"; } >>"%s/age-env"\nexec %s "$@"\n' "$S" "$(command -v age)" >"$S/agestub/age"
chmod 755 "$S/agestub/age"
rm -f "$S/age-env"
env PATH="$S/agestub:$PATH" AGE_PASSPHRASE=x AGE_PASSPHRASE_FD=3 AGE_PASSPHRASE_WORK_FACTOR=5 AGE_PASSPHRASE_MAX_WORK_FACTOR=5 AGEDEBUG=1 SECRET_JSON=leak \
  bash "$K/handoff.sh" <<<"$pay" >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "handoff.sh failed with age variables set"; }
[ -s "$S/age-env" ] || fail "the stub age didn't run"
extra=$(grep -v '^\(PATH\|PWD\|OLDPWD\|SHLVL\|_\|ARGV\)[=:]' "$S/age-env" || true)
[ -z "$extra" ] || fail "unexpected variables reached age: $(printf '%s' "$extra" | cut -d= -f1 | tr '\n' ' ')"
! grep -q -e leak -e mk-Zq9 "$S/age-env" || fail "the secret reached age's environment or arguments"
# The caller's own xtrace (SHELLOPTS=xtrace, bash -x) never prints the secret.
env SHELLOPTS=xtrace "$BASH_BIN" "$K/handoff.sh" <<<"$pay" >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "handoff.sh failed under SHELLOPTS=xtrace"; }
! grep -q mk-Zq9 "$S/err" || fail "SHELLOPTS=xtrace printed the secret"
"$BASH_BIN" -x "$K/handoff.sh" <<<"$pay" >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "handoff.sh failed under bash -x"; }
! grep -q mk-Zq9 "$S/err" || fail "bash -x printed the secret"
# The caller's allexport (SHELLOPTS=allexport) never exports SECRET_JSON: the
# commands handoff.sh runs on the payload (shims logging their environment)
# see neither it nor the secret.
mkdir -p "$S/hshim"
for c in jq wc tr base64 cmp; do
  command -v "$c" >/dev/null 2>&1 || continue
  printf '#!/bin/sh\nenv >>"%s/hshim.log"\nexec %s "$@"\n' "$S" "$(command -v "$c")" >"$S/hshim/$c"
  chmod 755 "$S/hshim/$c"
done
rm -f "$S/hshim.log"
env PATH="$S/hshim:$PATH" SHELLOPTS=allexport "$BASH_BIN" "$K/handoff.sh" <<<"$pay" >/dev/null 2>"$S/err" \
  || { cat "$S/err" >&2; fail "handoff.sh failed under SHELLOPTS=allexport"; }
[ -s "$S/hshim.log" ] || fail "the allexport shims didn't run"
! grep -q -e '^SECRET_JSON=' -e mk-Zq9 "$S/hshim.log" || fail "SHELLOPTS=allexport exported the secret to a command"
# A failing age is reported with its version: at the up-front recipient check,
# and at the encrypt step (a stub that takes an empty stdin and fails on data).
mkdir -p "$S/badage"
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
printf '#!/bin/sh\nif [ "$1" = --version ]; then echo v9.9.9-test; exit 0; fi\nexit 1\n' >"$S/badage/age"
chmod 755 "$S/badage/age"
expect_refusal "handoff.sh with an age that rejects the recipient" 1 "is not a valid age recipient: age v9.9.9-test did not accept it" \
  env PATH="$S/badage:$PATH" "$BASH_BIN" "$K/handoff.sh" <<<"$pay"
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
printf '#!/bin/sh\nif [ "$1" = --version ]; then echo v9.9.9-test; exit 0; fi\n[ "$(wc -c)" -eq 0 ] || { echo "age-stderr-at-encrypt" >&2; exit 1; }\n' >"$S/badage/age"
expect_refusal "handoff.sh with an age that fails to encrypt" 1 "age failed to encrypt (age v9.9.9-test)" \
  env PATH="$S/badage:$PATH" "$BASH_BIN" "$K/handoff.sh" <<<"$pay"
# age's own stderr there is not shown, as at every other age call.
! grep -q age-stderr-at-encrypt "$S/err" || fail "handoff.sh showed age's stderr from a failed encrypt"
echo "ok"
fi

if section 6; then
echo "== 6. rotation: the previous key, --rewrap =="
R="$S/rot"; mkdir -p "$R"
# The blob store, apart from the key directory (--rewrap refuses a blob file there).
ST="$S/store"; mkdir -p "$ST"
KEY="$R/k.txt"
cp "$TMPKEY" "$KEY"; chmod 600 "$KEY"
rk() { env HANDOFF_PRIVKEY="$KEY" "$@"; }
# enc_to RECIPIENT TEXT: TEXT encrypted to RECIPIENT, as a blob.
enc_to() { printf '%s' "$2" | "$AGE" -r "$1" | base64 | tr -d '\n'; }
old_rcpt=$("$AGE_KEYGEN" -y "$TMPKEY")
# The rotation: agent-setup.sh --rotate keeps the old identity as
# k.txt.previous and puts a new one at k.txt, both regular files, mode 0600,
# and prints the new recipient (never the secret).
rk bash ../agent-setup.sh --rotate >"$R/rot-out" 2>"$R/rot-err" || { cat "$R/rot-err" >&2; fail "--rotate failed"; }
new_rcpt=$("$AGE_KEYGEN" -y "$KEY")
[ -f "$KEY" ] && [ ! -L "$KEY" ] && [ -f "$KEY.previous" ] && [ ! -L "$KEY.previous" ] || fail "the rotated keys are not regular files"
[ "$(stat_of %a "$KEY")" = 600 ] && [ "$(stat_of %a "$KEY.previous")" = 600 ] || fail "--rotate left a key that is not mode 600"
[ "$new_rcpt" != "$old_rcpt" ] || fail "--rotate kept the old key as the current one"
! compgen -G "$R/.handoff-*" >/dev/null || fail "--rotate left a temporary file or directory"
! compgen -G "$R/.handoff-*" >/dev/null || fail "--rotate left a temporary file or directory"
[ "$("$AGE_KEYGEN" -y "$KEY.previous")" = "$old_rcpt" ] || fail "k.txt.previous is not the old key"
[ "$(sed -n 's/^new recipient: //p' "$R/rot-out")" = "$new_rcpt" ] || fail "--rotate printed another recipient than the new key's: $(cat "$R/rot-out")"
grep -qxF "$new_rcpt" "$R/rot-out" || fail "--rotate printed no bare recipient line to save"
grep -qxF "new key written to $KEY (mode 600); the old key is now $KEY.previous" "$R/rot-out" || fail "--rotate didn't say where the keys are: $(cat "$R/rot-out")"
! grep -q 'AGE-SECRET-KEY' "$R/rot-out" "$R/rot-err" || fail "--rotate printed a secret-key line"
! grep -qF "$old_rcpt" "$R/rot-out" || fail "--rotate printed the old recipient as if it were new"
# One rotation at a time: during one, --rotate rotates nothing, exits 0, and
# shows the current (new) recipient again.
rc=0; rk bash ../agent-setup.sh --rotate >"$R/out" 2>"$R/err" || rc=$?
[ "$rc" = 0 ] || fail "--rotate during a rotation: exit $rc, expected 0 (it only shows the key)"
if ! grep -qF "a rotation is under way" "$R/err" || ! grep -qF "nothing rotated" "$R/err"; then
  fail "--rotate during a rotation didn't say so"
fi
grep -qxF "current (new) recipient: $new_rcpt" "$R/out" || fail "--rotate during a rotation didn't show the new key's recipient"
grep -qxF "$new_rcpt" "$R/out" || fail "--rotate during a rotation didn't show the recipient to save"
[ "$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)" = "recipient: $new_rcpt" ] || fail "a refused --rotate changed the key"
[ "$("$AGE_KEYGEN" -y "$KEY.previous")" = "$old_rcpt" ] || fail "a refused --rotate changed the previous key"
# The identity files as they are now, to compare after the --rewrap refusals.
mkdir -p "$S/keybefore"
cp -p "$KEY" "$S/keybefore/current"; cp -p "$KEY.previous" "$S/keybefore/previous"
# Another identity, for blobs made for neither key.
"$AGE_KEYGEN" -o "$S/other-id.txt" >/dev/null 2>&1; chmod 600 "$S/other-id.txt"
other_rcpt=$("$AGE_KEYGEN" -y "$S/other-id.txt")
enc_other() { enc_to "$other_rcpt" "$1"; }
cur_blob=$(enc_to "$new_rcpt" '{"svc":"example","password":"mk-Zq9-cur"}')
# An old blob still opens, through the previous key; run mode says to rewrap it.
rk python3 ../consume.py --label example --check --blob-file blob-age.txt >"$R/out" 2>"$R/err" \
  || fail "an old blob didn't open through the previous key: $(cat "$R/err")"
diff "$R/out" expected-check.txt || fail "--check through the previous key differs"
out=$(rk python3 ../consume.py --label example --blob-file blob-age.txt -- python3 -c '
import os
print(os.environ["SERVICE_PASSWORD"])
' 2>"$R/err")
[ "$out" = "$P" ] || fail "an old blob didn't run through the previous key"
grep -qF "label 'example' decrypted with the previous key; rewrap it" "$R/err" || fail "run mode didn't say to rewrap: $(cat "$R/err")"
no_dummy_in "$R/err"
# The line starts a line of its own even after a fetch's stderr that ends in a
# NUL with no newline (issue #21 item 1: BSD grep stops reading a line at a
# NUL, so a joined line counted 0 there).
{ printf 'fetch noise\000' >&2; rk python3 ../consume.py --label example --blob-file blob-age.txt -- true; } 2>"$R/err" \
  || fail "run mode after a NUL on stderr failed: $(cat -v "$R/err")"
python3 -I -c 'import sys; d = open(sys.argv[1], "rb").read(); sys.exit(0 if b"\x00\nconsume.py: label '"'"'example'"'"' decrypted with the previous key;" in d else 1)' "$R/err" \
  || fail "the previous-key line didn't start its own line after a NUL: $(cat -v "$R/err")"
# ROTATION.md step 4's fetched-store rewrap wrapper, run as written (issue #18
# item 8): taken from the doc, its paths pointed at a fake store and this
# rotation's keys, and driven through each outcome the doc quotes, checking
# each line and exit code.
W="$S/fsw"; rm -rf "$W"; mkdir -p "$W/run" "$W/home" "$W/bin" "$W/tmpfs"; chmod 700 "$W/tmpfs"
cat >"$W/bin/fetch-blob" <<EOF
#!/bin/sh
# A fake store's fetch: \$W/mode picks a failure, \$W/count numbers the calls.
n=\$((\$(cat "$W/count" 2>/dev/null || echo 0) + 1)); echo "\$n" >"$W/count"
case "\$(cat "$W/mode" 2>/dev/null)" in
  failfetch) exit 1 ;;
  failrefetch) [ "\$n" -lt 2 ] || exit 1 ;;
  changed) [ "\$n" -lt 2 ] || { echo "a blob staged meanwhile"; exit 0; } ;;
  failback) [ "\$n" -lt 3 ] || exit 1 ;;
  diffback) [ "\$n" -lt 3 ] || { echo "different text"; exit 0; } ;;
  foldback) [ "\$n" -lt 3 ] || { fold -w 64 "$W/blob"; exit 0; } ;;
esac
cat "$W/blob"
EOF
cat >"$W/bin/store-blob" <<EOF
#!/bin/sh
[ "\$(cat "$W/mode" 2>/dev/null)" != failstore ] || exit 1
cat >"$W/blob.tmp" && mv "$W/blob.tmp" "$W/blob"
EOF
chmod 700 "$W/bin/fetch-blob" "$W/bin/store-blob"
# The wrapper, from the doc, with its paths replaced. Each replaced string
# must be there once: a doc edit that drops one fails here, not silently.
python3 -I - ../ROTATION.md "$W/rewrap" "$W" "$KEY" "$(cd .. && pwd -P)/consume.py" \
  "$(dirname "$(command -v "$AGE")")" "$(dirname "$(command -v python3)")" <<'PYEOF' || fail "couldn't take the fetched-store rewrap wrapper from ROTATION.md"
import sys
doc, out, w, key, consume, agedir, pydir = sys.argv[1:]
lines = open(doc, encoding="utf-8").read().split("\n")
start = lines.index("   label=example")
while lines[start] != "   ```sh":
    start -= 1
end = lines.index("   ```", start + 1)
body = "\n".join(l[3:] for l in lines[start + 1:end]) + "\n"
subs = [
    ("cd /home/agent/run/example", f"cd {w}/run"),
    ("f=/run/user/1000/handoff-rewrap-example", f"f={w}/tmpfs/handoff-rewrap-example"),
    ("/home/agent/bin/fetch-blob", f"{w}/bin/fetch-blob"),
    ("/home/agent/bin/store-blob", f"{w}/bin/store-blob"),
    ("HANDOFF_PRIVKEY=/home/agent/.config/handoff/handoff-identity.txt", f"HANDOFF_PRIVKEY={key}"),
    ("/home/agent/muse-field-kit/encrypted-credential-handoff/consume.py", consume),
    ("PATH=/usr/local/bin:/usr/bin:/bin", f"PATH={agedir}:{pydir}:/usr/bin:/bin"),
]
for a, b in subs:
    n = body.count(a)
    if n != 1:
        sys.exit(f"ROTATION.md's example has {n} of {a!r}")
    body = body.replace(a, b)
body = body.replace("HOME=/home/agent", f"HOME={w}/home")
if "/home/agent" in body or "/run/user/1000" in body:
    sys.exit("ROTATION.md's example has a path this test doesn't replace")
open(out, "w", encoding="utf-8").write(body)
PYEOF
chmod 700 "$W/rewrap"
f="$W/tmpfs/handoff-rewrap-example"
# fsw MODE EXPECTED-EXIT TEXT...: reset the store to the old blob (or keep it,
# for "keep"), run the wrapper, and check its exit and each line of TEXT.
fsw() {
  m=$1; want=$2; shift 2
  rm -f "$W/count" "$f" "$f.now"
  [ "$m" = keep ] || cp blob-age.txt "$W/blob"
  printf '%s' "$m" >"$W/mode"
  rc=0; (umask 022; "$W/rewrap") 2>"$W/err" || rc=$?
  [ "$rc" = "$want" ] || fail "the doc's fetched-store rewrap wrapper ($m): exit $rc, not $want: $(cat "$W/err")"
  for t in "$@"; do
    grep -qF -- "$t" "$W/err" || fail "the doc's fetched-store rewrap wrapper ($m) didn't say '$t': $(cat "$W/err")"
  done
}
fsw ok 0 "rewrapped" "the blob was for the previous key" "stored, fetched back and compared; $f removed"
[ ! -e "$f" ] || fail "the doc's wrapper left its file after a full rewrap"
cmp -s "$W/blob" blob-age.txt && fail "the doc's wrapper didn't replace the stored blob"
rk python3 ../consume.py --label example --check --blob-file "$W/blob" >/dev/null 2>"$W/err2" || fail "the stored blob doesn't open after the doc's wrapper: $(cat "$W/err2")"
! grep -qF "decrypted with the previous key" "$W/err2" || fail "the doc's wrapper stored a blob that's still for the previous key"
fsw keep 0 "is already for the current key" "store unchanged"
[ ! -e "$f" ] || fail "the doc's wrapper left its file for a blob already current"
fsw failfetch 3 "fetch (or creating $f) failed; store unchanged"
# kept MODE: after an outcome that says "$f kept", the file is there, mode
# 0600 though the run's umask was 022, and the re-fetch's $f.now is gone.
kept() {
  [ -e "$f" ] || fail "the doc's wrapper ($1) said $f kept but removed it"
  [ "$(stat_of %a "$f")" = 600 ] || fail "the doc's wrapper ($1) kept $f with mode $(stat_of %a "$f"), not 600"
  [ ! -e "$f.now" ] || fail "the doc's wrapper ($1) left $f.now"
}
fsw failrefetch 4 "re-fetch failed; store unchanged, $f kept"; kept failrefetch
fsw changed 6 "the stored blob changed meanwhile (a blob staged?); store unchanged, $f kept"; kept changed
cmp -s "$W/blob" blob-age.txt || fail "the doc's wrapper wrote the store after seeing it change"
fsw failstore 5 "store write failed"; kept failstore
fsw failback 4 "fetch-back failed; $f kept"; kept failback
fsw diffback 1 "the store returned different text; $f kept"; kept diffback
# A store that folds or trims what it sends back still compares equal: the
# compare ignores whitespace, as the doc says.
fsw foldback 0 "stored, fetched back and compared; $f removed"
# A refusal (a blob that isn't one) leaves the file behind, as the doc says.
printf 'not base64 !!!' >"$W/blob.bad"
rm -f "$W/count" "$f"; cp "$W/blob.bad" "$W/blob"; printf ok >"$W/mode"
rc=0; (umask 022; "$W/rewrap") 2>"$W/err" || rc=$?
{ [ "$rc" = 1 ] && grep -qF "not valid base64" "$W/err" && [ -e "$f" ]; } \
  || fail "the doc's wrapper with a refused blob: exit $rc, file $( [ -e "$f" ] && echo kept || echo gone ), $(cat "$W/err")"
# A leftover file stops it before any fetch; a missing directory too; and it
# takes no arguments.
cp blob-age.txt "$W/blob"; printf ok >"$W/mode"; rm -f "$W/count"; : >"$f"
rc=0; "$W/rewrap" 2>"$W/err" || rc=$?
{ [ "$rc" = 1 ] && grep -qF "leftover $f: ROTATION.md step 4, on a resume" "$W/err"; } || fail "the doc's wrapper with a leftover file: exit $rc, $(cat "$W/err")"
[ ! -e "$W/count" ] || fail "the doc's wrapper fetched despite a leftover file"
rm -f "$f"; rmdir "$W/tmpfs"
rc=0; "$W/rewrap" 2>"$W/err" || rc=$?
{ [ "$rc" = 1 ] && grep -qF "no $W/tmpfs (no login session?); store unchanged" "$W/err"; } || fail "the doc's wrapper with no directory: exit $rc, $(cat "$W/err")"
mkdir -m 700 "$W/tmpfs"
rc=0; "$W/rewrap" extra 2>"$W/err" || rc=$?
{ [ "$rc" = 2 ] && grep -qF "example rewrap wrapper takes no arguments" "$W/err"; } || fail "the doc's wrapper with an argument: exit $rc, $(cat "$W/err")"
rm -rf "$W"
# --rewrap rewrites its --blob-file in place, for the current key, and
# prints nothing on stdout.
cp blob-age.txt "$ST/new.txt"
rk python3 ../consume.py --label example --rewrap --blob-file "$ST/new.txt" >"$R/out" 2>"$R/err" \
  || fail "--rewrap failed: $(cat "$R/err")"
grep -qxF "consume.py: rewrapped '$ST/new.txt' to the current key '$R/k.txt'; the blob was for the previous key ('$R/k.txt.previous')" "$R/err" || fail "--rewrap didn't say the blob was for the previous key, naming both: $(cat "$R/err")"
[ ! -s "$R/out" ] || fail "--rewrap printed to stdout"
if [ "$(wc -l < "$ST/new.txt")" -ne 1 ] || ! grep -qxE '[A-Za-z0-9+/]+={0,2}' "$ST/new.txt" \
    || [ "$(base64 -d < "$ST/new.txt" | head -c 21)" != "age-encryption.org/v1" ]; then
  fail "--rewrap wrote something other than one blob"
fi
cmp -s blob-age.txt "$ST/new.txt" && fail "--rewrap left its blob file unchanged"
! compgen -G "$ST/.new.txt.*" >/dev/null || fail "--rewrap left its temporary file"
no_dummy_in "$ST/new.txt" "$R/err"
# The new blob opens with the current key alone, to the same payload.
mv "$R/k.txt.previous" "$R/held.txt"
rk python3 ../consume.py --label example --check --blob-file "$ST/new.txt" >"$R/out" \
  || fail "the rewrapped blob doesn't open with the current key"
diff "$R/out" expected-check.txt || fail "the rewrapped payload differs"
out=$(rk python3 ../consume.py --label example --blob-file "$ST/new.txt" -- python3 -c '
import os
print(os.environ["SERVICE_USERNAME"], os.environ["SERVICE_PASSWORD"])
')
[ "$out" = "$U $P" ] || fail "the rewrapped blob's values differ"
mv "$R/held.txt" "$R/k.txt.previous"
# During a rotation, run mode says so for a blob the current key opened: a
# probe checks for a line that's there.
rk python3 ../consume.py --label example --blob-file "$ST/new.txt" -- true 2>"$R/err" || fail "run mode on the rewrapped blob failed"
grep -qxF "consume.py: label 'example' opened with the current key (a rotation is under way)" "$R/err" || fail "run mode didn't say the current key opened it: $(cat "$R/err")"
# ...and it too starts with a newline (the NUL case, which the attack
# needs, is the previous-key line's, above).
python3 -I -c 'import sys; sys.exit(0 if open(sys.argv[1], "rb").read().startswith(b"\nconsume.py: label") else 1)' "$R/err" \
  || fail "the current-key line doesn't start with a newline: $(cat -v "$R/err")"
# A blob already for the current key isn't rewritten (age's output differs on every run).
cp "$ST/new.txt" "$ST/new2.txt"
rk python3 ../consume.py --label example --rewrap --blob-file "$ST/new2.txt" 2>"$R/err" || fail "--rewrap of a current blob failed"
grep -qxF "consume.py: the blob in '$ST/new2.txt' is already for the current key '$R/k.txt'; nothing written" "$R/err" || fail "--rewrap of a current blob didn't say so: $(cat "$R/err")"
cmp -s "$ST/new.txt" "$ST/new2.txt" || fail "--rewrap rewrote a blob already for the current key"
# The blob file keeps its mode; a group- or world-writable one is refused.
cp blob-age.txt "$ST/mode.txt"; chmod 640 "$ST/mode.txt"
rk python3 ../consume.py --label example --rewrap --blob-file "$ST/mode.txt" 2>/dev/null || fail "--rewrap of a 0640 file failed"
[ "$(stat_of %a "$ST/mode.txt")" = 640 ] || fail "--rewrap changed its blob file's mode"
# bq GIVEN RESOLVED: how consume.py names a path (quoted; both when they differ).
bq() { if [ "$1" = "$2" ]; then printf "'%s'" "$2"; else printf "'%s' (that is '%s')" "$1" "$2"; fi; }
RST=$(cd -P "$ST" && pwd); RR=$(cd -P "$R" && pwd)
cp blob-age.txt "$ST/gw.txt"; chmod 660 "$ST/gw.txt"
expect_refusal "--rewrap of a group-writable blob file" 1 "the blob file $(bq "$ST/gw.txt" "$RST/gw.txt") is writable by others (mode 0660); stop and report it to the user, who runs: chmod go-w '$RST/gw.txt'" \
  rk python3 ../consume.py --label example --rewrap --blob-file "$ST/gw.txt"
# A directory others can write (without the sticky bit) is refused too; with it, not.
mkdir -p "$ST/gwd"; cp blob-age.txt "$ST/gwd/b.txt"; chmod 770 "$ST/gwd"
expect_refusal "--rewrap in a group-writable directory" 1 "directory $(bq "$ST/gwd" "$RST/gwd") is writable by others (mode 0770); stop and report it to the user, who runs: chmod go-w '$RST/gwd'" \
  rk python3 ../consume.py --label example --rewrap --blob-file "$ST/gwd/b.txt"
# Through a symlinked blob file the directory named, and the chmod, are the one checked.
ln -s "$ST/gwd/b.txt" "$ST/lnk-gw.txt"
expect_refusal "--rewrap of a symlink into a group-writable directory" 1 "directory $(bq "$ST" "$RST/gwd") is writable by others (mode 0770); stop and report it to the user, who runs: chmod go-w '$RST/gwd'" \
  rk python3 ../consume.py --label example --rewrap --blob-file "$ST/lnk-gw.txt"
rm "$ST/lnk-gw.txt"
cmp -s blob-age.txt "$ST/gwd/b.txt" || fail "a refused --rewrap changed a file in a group-writable directory"
# The blob file and its directory must be owned by this account or root
# (issue #71), and the chmod in the advice is given only for what this account
# owns. Making files owned by another account needs root, so os.stat is
# patched: rk_stat TARGET UID MODE BLOB runs --rewrap on BLOB with TARGET (a
# resolved path) reported as owned by UID with permission bits MODE (octal).
rk_stat() {
  rk python3 -I -c '
import os, stat, sys
target, uid, mode = sys.argv[2], int(sys.argv[3]), int(sys.argv[4], 8)
real = os.stat
def fake_stat(p, *a, **k):
    st = real(p, *a, **k)
    if isinstance(p, str) and os.path.realpath(p) == target:
        f = list(st)
        f[0] = stat.S_IFMT(st.st_mode) | mode
        f[4] = uid
        # The named fields too (st_mtime_ns and the rest), or file_identity
        # sees a changed file.
        named = {k: getattr(st, k) for k in dir(st) if k.startswith("st_")
                 and k not in ("st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size")}
        return os.stat_result(f, named)
    return st
os.stat = fake_stat
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$4" "$1" "$2" "$3"
}
mkdir -p "$ST/own"; cp blob-age.txt "$ST/own/b.txt"; chmod 700 "$ST/own"; chmod 600 "$ST/own/b.txt"
movemsg="stop and report it to the user: a blob file belongs in a store only this account can write"
expect_refusal "--rewrap of a blob file owned by another account" 1 "the blob file $(bq "$ST/own/b.txt" "$RST/own/b.txt") is owned by another account; $movemsg" \
  rk_stat "$RST/own/b.txt" 65534 600 "$ST/own/b.txt"
expect_refusal "--rewrap in a directory owned by another account" 1 "the blob file's directory $(bq "$ST/own" "$RST/own") is owned by another account; $movemsg" \
  rk_stat "$RST/own" 65534 755 "$ST/own/b.txt"
cmp -s blob-age.txt "$ST/own/b.txt" || fail "a --rewrap refused for its owner changed the blob file"
if [ "$(id -u)" != 0 ]; then
  # Root's and writable by others: refused, with no chmod this account can't run.
  expect_refusal "--rewrap of a root-owned group-writable blob file" 1 "the blob file $(bq "$ST/own/b.txt" "$RST/own/b.txt") is writable by others (mode 0660); $movemsg" \
    rk_stat "$RST/own/b.txt" 0 660 "$ST/own/b.txt"
  ! grep -qF chmod "$S/err" || fail "--rewrap advised a chmod of a root-owned blob file: $(cat "$S/err")"
  expect_refusal "--rewrap in a root-owned group-writable directory" 1 "the blob file's directory $(bq "$ST/own" "$RST/own") is writable by others (mode 0770); $movemsg" \
    rk_stat "$RST/own" 0 770 "$ST/own/b.txt"
  ! grep -qF chmod "$S/err" || fail "--rewrap advised a chmod of a root-owned directory: $(cat "$S/err")"
fi
# A root-owned 0644 blob file and a root-owned 0755 directory are accepted
# (the rewrap goes ahead).
cp blob-age.txt "$ST/own/b.txt"
rk_stat "$RST/own/b.txt" 0 644 "$ST/own/b.txt" >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "--rewrap refused a root-owned 0644 blob file"; }
grep -qF rewrapped "$S/err" || fail "--rewrap of a root-owned 0644 blob file didn't rewrap: $(cat "$S/err")"
cp blob-age.txt "$ST/own/b.txt"
rk_stat "$RST/own" 0 755 "$ST/own/b.txt" >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "--rewrap refused a root-owned 0755 directory"; }
grep -qF rewrapped "$S/err" || fail "--rewrap in a root-owned 0755 directory didn't rewrap: $(cat "$S/err")"
echo "ok (--rewrap: the blob file's and directory's owner checked, chmod advised only for this account's own)"
# Checked before anything else is decided: a blob already for the current key
# in such a directory is refused too, not reported done.
cp "$ST/new.txt" "$ST/gwd/cur.txt"
expect_refusal "--rewrap of a current blob in a group-writable directory" 1 "directory $(bq "$ST/gwd" "$RST/gwd") is writable by others" \
  rk python3 ../consume.py --label example --rewrap --blob-file "$ST/gwd/cur.txt"
rm "$ST/gwd/cur.txt"
chmod 1770 "$ST/gwd"
rk python3 ../consume.py --label example --rewrap --blob-file "$ST/gwd/b.txt" 2>/dev/null || fail "--rewrap in a sticky group-writable directory failed"
chmod 700 "$ST/gwd"
# A long multibyte name: the temporary name is cut in bytes, so it fits.
mb="$ST/$(python3 -c 'print("\u65e5" * 80)').txt"; cp blob-age.txt "$mb"
rk python3 ../consume.py --label example --rewrap --blob-file "$mb" 2>"$R/err" || fail "--rewrap of a long multibyte name failed: $(cat "$R/err")"
rm -f "$mb"
cmp -s blob-age.txt "$ST/gw.txt" || fail "a refused --rewrap changed a group-writable blob file"
# A symlinked blob file: the file it points at is rewritten, the link stays.
cp blob-age.txt "$ST/real.txt"; ln -s "$ST/real.txt" "$ST/link.txt"
rk python3 ../consume.py --label example --rewrap --blob-file "$ST/link.txt" 2>"$R/err" || fail "--rewrap through a symlink failed: $(cat "$R/err")"
[ -L "$ST/link.txt" ] || fail "--rewrap replaced a symlink instead of the file it points at"
cmp -s blob-age.txt "$ST/real.txt" && fail "--rewrap through a symlink left the file unchanged"
rm "$ST/link.txt"
# A blob made for neither key: one message, nothing about which key failed or why.
expect_refusal "a blob for neither key" 1 "decryption failed with the current key ('$KEY') and with the previous key ('$KEY.previous')" \
  rk python3 ../consume.py --label example --check --blob "$(enc_other '{"svc":"example","password":"mk-Zq9"}')"
! grep -q "no identity matched" "$S/err" || fail "the two-key refusal shows age's reason"
# The previous key is held to the current key's rules.
chmod 644 "$KEY.previous"
expect_refusal "a group-readable previous key" 1 "k.txt.previous' is mode 644" \
  rk python3 ../consume.py --label example --check --blob-file blob-age.txt
chmod 600 "$KEY.previous"
mv "$KEY.previous" "$R/held.txt"; ln -s "$S/other-id.txt" "$KEY.previous"
expect_refusal "a symlinked previous key" 1 "k.txt.previous' is a symbolic link" \
  rk python3 ../consume.py --label example --check --blob-file blob-age.txt
rm "$KEY.previous"
cp "$RSAKEY" "$KEY.previous"
expect_refusal "an RSA key as the previous key" 1 "k.txt.previous' is an RSA key from 0.1.0" \
  rk python3 ../consume.py --label example --check --blob-file blob-age.txt
rm "$KEY.previous"; mv "$R/held.txt" "$KEY.previous"
# A blob the current key opens never reaches the previous key: a broken
# previous key doesn't matter then.
chmod 644 "$KEY.previous"
rk python3 ../consume.py --label example --check --blob-file "$ST/new.txt" >/dev/null \
  || fail "a current blob was refused over the previous key"
chmod 600 "$KEY.previous"
# --rewrap is refused with anything that changes the payload or runs a command.
expect_refusal "--rewrap with --check" 1 "--check and --rewrap can't be combined" \
  rk python3 ../consume.py --label example --rewrap --check --blob-file blob-age.txt
expect_refusal "--rewrap with a command" 1 "--rewrap takes no command" \
  rk python3 ../consume.py --label example --rewrap --blob-file blob-age.txt -- true
expect_refusal "--rewrap with --env" 1 "--rewrap takes no --env" \
  rk python3 ../consume.py --label example --rewrap --env password=APP_PASS --blob-file blob-age.txt
expect_refusal "--rewrap twice" 1 "--rewrap given twice" \
  rk python3 ../consume.py --label example --rewrap --rewrap --blob-file blob-age.txt
cp blob-age.txt "$ST/b.txt"
expect_refusal "--rewrap, purpose mismatch" 1 "purpose mismatch" \
  rk python3 ../consume.py --label other --rewrap --blob-file "$ST/b.txt"
# --rewrap checks its new blob opens with the current key before writing
# it. Stand-ins for age that fail in the ways that matter: encrypting to
# another recipient, failing, and printing something that isn't an age file.
real_age=$(command -v "$AGE")
mkdir -p "$S/badenc" "$S/swapenc" "$S/failenc" "$S/junkenc"
# shellcheck disable=SC2016  # $a and $@ belong to the generated script
printf '#!/bin/sh\nfor a; do [ "$a" = -r ] && exec %s -r %s; done\nexec %s "$@"\n' "$real_age" "$other_rcpt" "$real_age" > "$S/badenc/age"
# shellcheck disable=SC2016  # $a and $@ belong to the generated script
printf '#!/bin/sh\nfor a; do [ "$a" = -r ] && { cat >/dev/null; printf %%s %s | %s "$@"; exit $?; }; done\nexec %s "$@"\n' \
  "'{\"svc\":\"example\",\"password\":\"mk-Zq9-other\"}'" "$real_age" "$real_age" > "$S/swapenc/age"
# shellcheck disable=SC2016  # $a and $@ belong to the generated script
printf '#!/bin/sh\nfor a; do [ "$a" = -r ] && { cat >/dev/null; echo "age: simulated failure for the payload" >&2; exit 1; }; done\nexec %s "$@"\n' "$real_age" > "$S/failenc/age"
# shellcheck disable=SC2016  # $a and $@ belong to the generated script
printf '#!/bin/sh\nfor a; do [ "$a" = -r ] && { cat >/dev/null; echo not-an-age-file; exit 0; }; done\nexec %s "$@"\n' "$real_age" > "$S/junkenc/age"
chmod 755 "$S/badenc/age" "$S/swapenc/age" "$S/failenc/age" "$S/junkenc/age"
cp blob-age.txt "$ST/b.txt"
expect_refusal "--rewrap whose new blob doesn't open" 1 "the new blob doesn't open with the current key" \
  rk env PATH="$S/badenc:$PATH" python3 ../consume.py --label example --rewrap --blob-file "$ST/b.txt"
# The self-check compares payloads, not just that the new blob opens: an age
# that encrypts another valid payload to the current key is caught too.
expect_refusal "--rewrap whose new blob opens to another payload" 1 "to the same payload" \
  rk env PATH="$S/swapenc:$PATH" python3 ../consume.py --label example --rewrap --blob-file "$ST/b.txt"
# An age that fails, or prints something that isn't an age file: one fixed
# line, nothing of age's own text.
for which in failenc junkenc; do
  expect_refusal "--rewrap with an age that doesn't encrypt ($which)" 1 "re-encrypting to the current key failed" \
    rk env PATH="$S/$which:$PATH" python3 ../consume.py --label example --rewrap --blob-file "$ST/b.txt"
  ! grep -q "simulated failure" "$S/err" || fail "--rewrap showed age's own stderr ($which)"
done
cmp -s blob-age.txt "$ST/b.txt" || fail "a --rewrap whose self-check failed changed its blob file"
# An age that can't be run for the encrypt (an OSError, such as a permission
# error: subprocess.run patched, as the INT tests do): the fixed "cannot run
# age" refusal naming the PATH, no traceback, the blob file unchanged.
expect_refusal "--rewrap whose age can't be run for the encrypt" 1 "cannot run age: Permission denied (PATH was '" \
  rk python3 -I -c '
import subprocess, sys
real = subprocess.run
def no_run(cmd, *a, **k):
    if "-r" in cmd:
        raise PermissionError(13, "Permission denied")
    return real(cmd, *a, **k)
subprocess.run = no_run
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$ST/b.txt"
cmp -s blob-age.txt "$ST/b.txt" || fail "a --rewrap whose age couldn't run changed its blob file"
! compgen -G "$ST/.b.txt.*" >/dev/null || fail "a --rewrap whose age couldn't run left its temporary file"
# The rewrap's age gets the same environment as the others: PATH only.
mkdir -p "$S/envenc"
# shellcheck disable=SC2016  # $a and $@ belong to the generated script
printf '#!/bin/sh\nfor a; do [ "$a" = -r ] && { env > %s; break; }; done\nexec %s "$@"\n' "$S/age-env" "$real_age" > "$S/envenc/age"
chmod 755 "$S/envenc/age"
cp blob-age.txt "$ST/envb.txt"
rk env PATH="$S/envenc:$PATH" AGE_PASSPHRASE=mk-Zq9-pp AGEDEBUG=1 python3 ../consume.py --label example --rewrap --blob-file "$ST/envb.txt" 2>/dev/null \
  || fail "--rewrap with the environment-recording age failed"
[ -s "$S/age-env" ] || fail "the environment-recording age did not run for the encrypt"
! grep -q "^AGE_PASSPHRASE=\|^AGEDEBUG=\|^HANDOFF_PRIVKEY=" "$S/age-env" || fail "age's encrypt got the caller's environment"
grep -q "^PATH=" "$S/age-env" || fail "age's encrypt got no PATH"
# A new blob that can't be written leaves the blob file as it was, with no temporary
# file and no "rewrapped" line (a read-only directory; root can write anyway).
if [ "$(id -u)" != 0 ]; then
  mkdir -p "$ST/ro"; cp blob-age.txt "$ST/ro/b.txt"; chmod 500 "$ST/ro"
  rc=0; rk python3 ../consume.py --label example --rewrap --blob-file "$ST/ro/b.txt" 2>"$R/err" || rc=$?
  chmod 700 "$ST/ro"
  if [ "$rc" != 1 ] || ! grep -qF "could not write the new blob beside '$ST/ro/b.txt'" "$R/err" || ! grep -qF "that directory must be writable" "$R/err" || ! grep -qF "it is unchanged" "$R/err"; then
    fail "--rewrap into a read-only directory: exit $rc, $(cat "$R/err")"
  fi
  ! grep -qF "rewrapped" "$R/err" || fail "--rewrap reported success it didn't have"
  ! grep -q Traceback "$R/err" || fail "--rewrap into a read-only directory: traceback"
  cmp -s blob-age.txt "$ST/ro/b.txt" || fail "a failed --rewrap changed its blob file"
  echo "ok (refused: --rewrap that can't write, the blob file unchanged)"
else
  echo "skip: running as root, the read-only blob file check didn't run"
fi
# A rename that fails after the temporary file is written leaves the blob file as it
# was and no temporary file (os.replace patched to fail).
cp blob-age.txt "$ST/rep.txt"
expect_refusal "--rewrap whose rename fails" 1 "could not write the new blob to '$ST/rep.txt'" \
  rk python3 -I -c '
import os, sys
def no_replace(a, b):
    raise OSError(5, "simulated rename failure")
os.replace = no_replace
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$ST/rep.txt"
cmp -s blob-age.txt "$ST/rep.txt" || fail "a failed rename changed the blob file"
! compgen -G "$ST/.rep.txt.*" >/dev/null || fail "a failed rename left its temporary file"
# A temporary file that doesn't read back whole is never renamed into place.
cp blob-age.txt "$ST/rb.txt"
expect_refusal "--rewrap whose new blob doesn't read back" 1 "didn't read back whole" \
  rk python3 -I -c '
import builtins, io, sys
def short_open(f, mode="r", *a, **k):
    if mode == "rb" and str(f).endswith(".rewrap"):
        return io.BytesIO(b"short")
    return builtins.open(f, mode, *a, **k)
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(builtins.open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__", "open": short_open})
' "$ST/rb.txt"
cmp -s blob-age.txt "$ST/rb.txt" || fail "a blob that didn't read back replaced the blob file"
! compgen -G "$ST/.rb.txt.*" >/dev/null || fail "a failed read-back left its temporary file"
# The temporary file's name, which the f= rule and the resume glob depend on:
# ".<basename cut to at most 100 bytes on a character boundary>.<random>.rewrap",
# beside the blob file, the random part with no ".". The long name is 40 "€"
# (3 bytes each) and ".txt": 124 bytes, cut to 33 "€" (99 bytes), where a cut
# at byte 100 would split a character. consume.py renames by the resolved
# path, so it's compared with $RST ($TMPDIR is a symlink on macOS).
long="$(printf '€%.0s' $(seq 40)).txt"
for name in tn.txt "$long"; do
  cp blob-age.txt "$ST/$name"
  rm -f "$S/rewrap-name"
  rk python3 -I -c '
import os, sys
real, record = os.replace, sys.argv[2]
def recording_replace(a, b):
    with open(record, "wb") as fh:
        fh.write(os.fsencode(a) + b"\0" + os.fsencode(b))
    real(a, b)
os.replace = recording_replace
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$ST/$name" "$S/rewrap-name" 2>/dev/null || fail "--rewrap of '$name' for the temporary name check failed"
  [ -s "$S/rewrap-name" ] || fail "--rewrap of '$name' never renamed a temporary file"
  python3 -I -c '
import os, re, sys
tmp, dst = open(sys.argv[1], "rb").read().split(b"\0")
name, directory = sys.argv[2], sys.argv[3]
short = "€" * 33 if name.startswith("€") else name
if os.fsencode(os.path.join(directory, name)) != dst:
    sys.exit(f"renamed onto {dst!r}, not the blob file")
if os.path.dirname(tmp) != os.fsencode(directory):
    sys.exit(f"temporary file {tmp!r} is not beside the blob file")
if not re.fullmatch(rb"\." + re.escape(os.fsencode(short)) + rb"\.[^.]+\.rewrap", os.path.basename(tmp)):
    sys.exit(f"temporary name {os.path.basename(tmp)!r} is not .{short}.<random>.rewrap")
' "$S/rewrap-name" "$name" "$RST" || fail "the temporary name for '$name' has the wrong shape"
done
echo "ok (the temporary name: .<basename, cut to 100 bytes on a character>.<random>.rewrap)"
# A TERM during the rewrite: before the rename, the file is as it was and no
# temporary file is left; after it, the message says the file holds the new blob.
for when in before after; do
  cp blob-age.txt "$ST/term.txt"
  rc=0; rk python3 -I -c '
import os, signal, sys
real, real_fsync, when = os.replace, os.fsync, sys.argv[2]
if when == "after":
    # Sent during the rename: blocked there, so it lands just after it.
    def term_replace(a, b):
        os.kill(os.getpid(), signal.SIGTERM)
        real(a, b)
    os.replace = term_replace
else:
    # Sent while the temporary file is synced, before the rename.
    def term_fsync(fd):
        real_fsync(fd)
        os.kill(os.getpid(), signal.SIGTERM)
    os.fsync = term_fsync
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$ST/term.txt" "$when" 2>"$R/err" || rc=$?
  ! grep -q Traceback "$R/err" || fail "a TERM during --rewrap ($when the rename): traceback"
  [ "$rc" = 1 ] || fail "a TERM during --rewrap ($when the rename): exit $rc, expected 1"
  ! compgen -G "$ST/.term.txt.*" >/dev/null || fail "a TERM during --rewrap ($when the rename) left its temporary file"
  if [ "$when" = before ]; then
    grep -qF "interrupted; '$ST/term.txt' is unchanged" "$R/err" || fail "a TERM before the rename: $(cat "$R/err")"
    cmp -s blob-age.txt "$ST/term.txt" || fail "a TERM before the rename changed the blob file"
  else
    grep -qF "interrupted after the rename; '$ST/term.txt' holds the new blob" "$R/err" || fail "a TERM after the rename: $(cat "$R/err")"
    cmp -s blob-age.txt "$ST/term.txt" && fail "a TERM after the rename: the file wasn't replaced"
  fi
done
# A signal handler run as the block returns (a signal pending then) doesn't
# leave TERM, HUP and INT blocked (#9 item 10): pthread_sigmask's block call
# raises KeyboardInterrupt once, after blocking, and the mask is read after.
if python3 -I -c 'import signal, sys; sys.exit(0 if hasattr(signal, "pthread_sigmask") else 1)'; then
  cp blob-age.txt "$ST/mask.txt"
  got=$(rk python3 -I -c '
import signal, sys
real = signal.pthread_sigmask
def block_then_interrupt(how, sigs):
    r = real(how, sigs)
    if how == signal.SIG_BLOCK and set(sigs):
        signal.pthread_sigmask = real
        raise KeyboardInterrupt
    return r
signal.pthread_sigmask = block_then_interrupt
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
try:
    exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
except SystemExit as e:
    if isinstance(e.code, str):
        print(e.code, file=sys.stderr)  # as the interpreter would at exit
print(sorted(int(s) for s in real(signal.SIG_BLOCK, [])))
' "$ST/mask.txt" 2>"$R/err")
  [ "$got" = "[]" ] || fail "a handler run as --rewrap's signal block returned left signals blocked: $got ($(cat "$R/err"))"
  grep -qF "interrupted; '$ST/mask.txt' is unchanged" "$R/err" || fail "a handler run at the signal block: $(cat "$R/err")"
  cmp -s blob-age.txt "$ST/mask.txt" || fail "a handler run at the signal block changed the blob file"
  echo "ok (--rewrap restores its signal mask when a handler runs at the block)"
fi
# An INT before any write (during the decrypt): one line, nothing written.
cp blob-age.txt "$ST/int.txt"
rc=0; rk python3 -I -c '
import subprocess, sys
real = subprocess.run
def int_run(cmd, *a, **k):
    if "-d" in cmd:
        raise KeyboardInterrupt
    return real(cmd, *a, **k)
subprocess.run = int_run
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$ST/int.txt" 2>"$R/err" || rc=$?
if [ "$rc" != 1 ] || grep -q Traceback "$R/err" || ! grep -qxF "consume.py: interrupted; nothing written" "$R/err"; then
  fail "an INT during --rewrap's decrypt: exit $rc, $(cat "$R/err")"
fi
cmp -s blob-age.txt "$ST/int.txt" || fail "an INT during --rewrap's decrypt changed the blob file"
# A blob file changed between the read and the write (during the decrypt) is
# refused by the first check.
cp blob-age.txt "$ST/early.txt"
expect_refusal "--rewrap whose blob file changed before the write" 1 "changed since it was read" \
  rk python3 -I -c '
import subprocess, sys
real, target = subprocess.run, sys.argv[1]
def staging_run(cmd, *a, **k):
    if "-d" in cmd:
        with open(target, "w") as fh:
            fh.write("staged early\n")
    return real(cmd, *a, **k)
subprocess.run = staging_run
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$ST/early.txt"
[ "$(cat "$ST/early.txt")" = "staged early" ] || fail "--rewrap replaced a blob changed before the write"
# An interrupt inside mkstemp (before the temporary file exists) is "unchanged";
# a temporary file that can't be made for another reason doesn't blame the directory.
for how in int enospc; do
  cp blob-age.txt "$ST/mk.txt"
  rc=0; rk python3 -I -c '
import errno, sys, tempfile
how = sys.argv[2]
def broken(*a, **k):
    if how == "int":
        raise KeyboardInterrupt
    raise OSError(errno.ENOSPC, "No space left on device")
tempfile.mkstemp = broken
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$ST/mk.txt" "$how" 2>"$R/err" || rc=$?
  if [ "$rc" != 1 ] || grep -q Traceback "$R/err"; then fail "mkstemp failing ($how): exit $rc, $(cat "$R/err")"; fi
  cmp -s blob-age.txt "$ST/mk.txt" || fail "mkstemp failing ($how) changed the blob file"
  if [ "$how" = int ]; then
    grep -qF "interrupted; '$ST/mk.txt' is unchanged" "$R/err" || fail "an interrupt in mkstemp: $(cat "$R/err")"
  else
    if ! grep -qF "No space left on device" "$R/err" || grep -qF "must be writable" "$R/err"; then fail "ENOSPC in mkstemp: $(cat "$R/err")"; fi
  fi
done
# A second interrupt inside the first one's handler, before any rename, still
# says nothing was written (the file is unchanged).
cp blob-age.txt "$ST/dbl.txt"
rc=0; rk python3 -I -c '
import os, os.path, sys
real_lexists = os.path.lexists
def first(a, b):
    def second(p):
        os.path.lexists = real_lexists
        raise KeyboardInterrupt
    os.path.lexists = second
    raise KeyboardInterrupt
os.replace = first
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$ST/dbl.txt" 2>"$R/err" || rc=$?
if [ "$rc" != 1 ] || ! grep -qxF "consume.py: interrupted; nothing written" "$R/err"; then fail "a second interrupt before the rename: exit $rc, $(cat "$R/err")"; fi
cmp -s blob-age.txt "$ST/dbl.txt" || fail "a double interrupt changed the blob file"
# A blob staged while a rewrap runs isn't replaced with the old payload.
cp blob-age.txt "$ST/lost.txt"
expect_refusal "--rewrap whose blob file changed meanwhile" 1 "changed while it was being rewrapped" \
  rk python3 -I -c '
import sys, tempfile
real, target = tempfile.mkstemp, sys.argv[1]
def staged(*a, **k):
    with open(target, "w") as fh:
        fh.write("staged meanwhile\n")
    return real(*a, **k)
tempfile.mkstemp = staged
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$ST/lost.txt"
[ "$(cat "$ST/lost.txt")" = "staged meanwhile" ] || fail "--rewrap replaced a blob staged meanwhile"
! compgen -G "$ST/.lost.txt.*" >/dev/null || fail "a refused lost update left its temporary file"
# A same-size blob put back with the old mtime (touch -r, cp -p) is still seen
# as changed: the ctime can't be set back.
cp blob-age.txt "$ST/ct.txt"; cp "$ST/new.txt" "$ST/ct-staged.txt"; touch -r "$ST/ct.txt" "$ST/ct-staged.txt"
expect_refusal "--rewrap whose blob file was replaced keeping size and mtime" 1 "changed" \
  rk python3 -I -c '
import subprocess, sys
real, target, staged = subprocess.run, sys.argv[1], sys.argv[2]
def staging_run(cmd, *a, **k):
    if "-d" in cmd:
        real(["cp", "-p", staged, target])
    return real(cmd, *a, **k)
subprocess.run = staging_run
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$ST/ct.txt" "$ST/ct-staged.txt"
cmp -s "$ST/ct-staged.txt" "$ST/ct.txt" || fail "--rewrap replaced a blob staged with the old size and mtime"
# A HUP inherited as ignored (nohup) stays ignored: the rewrap finishes.
cp blob-age.txt "$ST/hup.txt"
rc=0; rk python3 -I -c '
import os, signal, sys
signal.signal(signal.SIGHUP, signal.SIG_IGN)
real = os.replace
def hup_replace(a, b):
    os.kill(os.getpid(), signal.SIGHUP)
    real(a, b)
os.replace = hup_replace
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$ST/hup.txt" 2>"$R/err" || rc=$?
if [ "$rc" != 0 ] || ! grep -qF "rewrapped '$ST/hup.txt'" "$R/err"; then fail "--rewrap with HUP ignored: exit $rc, $(cat "$R/err")"; fi
# An interrupt after the write, before the success line, says the file holds the new blob.
cp blob-age.txt "$ST/late.txt"
rc=0; rk python3 -I -c '
import builtins, sys
def late_print(*a, **k):
    if a and str(a[0]).startswith("consume.py: rewrapped"):
        raise KeyboardInterrupt
    builtins.print(*a, **k)
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__", "print": late_print})
' "$ST/late.txt" 2>"$R/err" || rc=$?
if [ "$rc" != 1 ] || ! grep -qF "interrupted after the rename; '$ST/late.txt' holds the new blob" "$R/err"; then
  fail "an interrupt after the write: exit $rc, $(cat "$R/err")"
fi
cmp -s blob-age.txt "$ST/late.txt" && fail "an interrupt after the write: the file wasn't replaced"
# The blob file is never under the key's directory, however it's spelled:
# beside the key, in a subdirectory, or through a symlink into it.
cp blob-age.txt "$R/beside.txt"; mkdir -p "$R/sub"; cp blob-age.txt "$R/sub/b.txt"
ln -s "$R" "$ST/s"; ln -s "$R/beside.txt" "$ST/to-beside.txt"
for target in "$R/beside.txt" "$R/sub/b.txt" "$ST/s/beside.txt" "$ST/s/sub/../beside.txt" "$ST/to-beside.txt"; do
  expect_refusal "--rewrap of a blob file under the key's directory ($target)" 1 "under the key's directory ('$R" \
    rk python3 ../consume.py --label example --rewrap --blob-file "$target"
  # It names the file as given and where it resolved to.
  grep -qF "' resolves to '" "$S/err" || fail "the key-directory refusal doesn't name $target as given and resolved: $(cat "$S/err")"
done
grep -qF "'$ST/to-beside.txt' resolves to '$RR/beside.txt'" "$S/err" || fail "a symlinked blob file's refusal doesn't say where it points: $(cat "$S/err")"
# The same file by identity, not by path (a bind mount or a case-insensitive
# spelling): with the path comparison disabled, the parent walk still refuses it.
expect_refusal "--rewrap beside the key, by identity only" 1 "under the key's directory" \
  rk python3 -I -c '
import os.path, sys
os.path.commonpath = lambda paths: ""
sys.argv = ["consume.py", "--label", "example", "--rewrap", "--blob-file", sys.argv[1]]
exec(compile(open("../consume.py").read(), "consume.py", "exec"), {"__name__": "__main__"})
' "$R/beside.txt"
cmp -s blob-age.txt "$R/beside.txt" || fail "a refused --rewrap changed a file beside the key"
# A symlinked identity is refused (the key must be a regular file, not a
# link to one), --rewrap included, and nothing is written.
mkdir -p "$S/lk"; ln -s "$KEY" "$S/lk/k.txt"; ln -s "$KEY.previous" "$S/lk/k.txt.previous"; cp blob-age.txt "$S/lk/beside.txt"
cp blob-age.txt "$ST/lkb.txt"
expect_refusal "--rewrap with a symlinked identity" 1 "is a symbolic link" \
  env HANDOFF_PRIVKEY="$S/lk/k.txt" python3 ../consume.py --label example --rewrap --blob-file "$ST/lkb.txt"
cmp -s blob-age.txt "$ST/lkb.txt" || fail "a refused --rewrap changed its blob file (symlinked identity)"
cmp -s blob-age.txt "$S/lk/beside.txt" || fail "a refused --rewrap changed a file beside a symlinked key path"
rm -r "$S/lk"
rm -r "$R/beside.txt" "$R/sub" "$ST/s" "$ST/to-beside.txt"
# The identity files are as they were after all that: the same bytes and the
# same mode, not only the same recipient (a rewrite that kept the key but
# loosened the mode, or dropped the comment lines, would pass a recipient check).
cmp -s "$KEY" "$S/keybefore/current" || fail "a refused --rewrap changed the current identity file"
cmp -s "$KEY.previous" "$S/keybefore/previous" || fail "a refused --rewrap changed the previous identity file"
[ "$(stat_of %a "$KEY")" = 600 ] && [ "$(stat_of %a "$KEY.previous")" = 600 ] || fail "a refused --rewrap changed an identity file's mode"
[ "$("$AGE_KEYGEN" -y "$KEY")" = "$new_rcpt" ] || fail "a refused --rewrap damaged the key"
# --rewrap runs only during a rotation, at the key the wrappers use: with no
# previous key, or pointed at the previous key itself, it refuses.
mv "$KEY.previous" "$R/held.txt"
expect_refusal "--rewrap with no rotation under way" 1 "no rotation under way at '$KEY'" \
  rk python3 ../consume.py --label example --rewrap --blob-file "$ST/new.txt"
mv "$R/held.txt" "$KEY.previous"
expect_refusal "--rewrap pointed at the previous key" 1 "names a rotation's old key (its name ends in .previous); a wrapper sets it to the current key, '$KEY'" \
  env HANDOFF_PRIVKEY="$KEY.previous" python3 ../consume.py --label example --rewrap --blob-file "$ST/new.txt"
# A blob neither key opens: stop and report, never another HANDOFF_PRIVKEY.
enc_other '{"svc":"example","password":"mk-Zq9"}' > "$ST/neither.txt"
expect_refusal "--rewrap of a blob neither key opens" 1 "stop and report it to the user" \
  rk python3 ../consume.py --label example --rewrap --blob-file "$ST/neither.txt"
! grep -q "check that HANDOFF_PRIVKEY" "$S/err" || fail "the decrypt refusal still invites trying another key"
# --rewrap needs --blob-file: a blob given as --blob or $HANDOFF_BLOB has no
# file to rewrite.
expect_refusal "--rewrap with --blob" 1 "needs --blob-file" \
  rk python3 ../consume.py --label example --rewrap --blob "$cur_blob"
expect_refusal "--rewrap with \$HANDOFF_BLOB" 1 "needs --blob-file" \
  rk env HANDOFF_BLOB="$cur_blob" python3 ../consume.py --label example --rewrap
# --out is gone: it's an unknown option now.
rc=0; rk python3 ../consume.py --label example --rewrap --blob-file "$ST/new.txt" --out "$ST/x.txt" >/dev/null 2>&1 || rc=$?
[ "$rc" != 0 ] || fail "--out was accepted"
[ ! -e "$ST/x.txt" ] || fail "--out still wrote a file"
# --rewrap refuses a half-done rotation: both names holding one key (linked,
# copied, or copied with other comment lines), a blob "for the current key"
# would be for the key being retired.
mv "$KEY.previous" "$R/held.txt"
printf '%s\n' "$cur_blob" > "$ST/cur.txt"
for how in ln cp comments; do
  case "$how" in
    ln) ln "$KEY" "$KEY.previous" ;;
    cp) cp -p "$KEY" "$KEY.previous" ;;
    # The same key with other comment lines: compared by its recipient.
    comments) { printf '# another comment\n'; cat "$KEY"; } > "$KEY.previous"; chmod 600 "$KEY.previous" ;;
  esac
  expect_refusal "--rewrap in a half-done rotation ($how)" 1 "holds the same key as '$KEY': the rotation didn't finish" \
    rk python3 ../consume.py --label example --rewrap --blob-file "$ST/cur.txt"
  rm "$KEY.previous"
done
mv "$R/held.txt" "$KEY.previous"
# --retire: agent-setup.sh's guards and its confirmation, with the previous
# key in place; then the retire itself, which deletes it.
# A symlinked key path is refused by --rotate and --retire.
ln -s "$KEY" "$R/link.txt"
expect_refusal "--rotate through a symlink" 1 "is a symlink" \
  env HANDOFF_PRIVKEY="$R/link.txt" bash ../agent-setup.sh --rotate
# The refusals before the confirmation run with --yes: without it a run keeps
# .previous whatever the guard does, so only --yes shows the guard holds.
expect_refusal "--retire --yes through a symlink" 1 "is a symlink" \
  env HANDOFF_PRIVKEY="$R/link.txt" bash ../agent-setup.sh --retire --yes
[ -e "$KEY.previous" ] || fail "a refused --retire deleted the previous key"
rm "$R/link.txt"
# A rotation's old key as KEY (issue #46): --rotate on it would keep the old
# key as .previous.previous and put a new key at .previous; --retire would
# delete the wrong key. Refused as a KEY and from HANDOFF_PRIVKEY, in any
# case, before anything is read; nothing on disk changes.
keys_now() { for f in "$KEY" "$KEY.previous"; do "$AGE_KEYGEN" -y "$f"; done; ls -A "$(dirname -- "$KEY")"; }
before_prev=$(keys_now)
expect_refusal "--rotate KEY.previous" 1 "is a rotation's old key (its name ends in .previous); --rotate takes the current key, $KEY; nothing changed" \
  bash ../agent-setup.sh --rotate "$KEY.previous"
expect_refusal "--rotate with HANDOFF_PRIVKEY at .previous" 1 "HANDOFF_PRIVKEY ($KEY.previous) names a rotation's old key (its name ends in .previous); set it to the current key, $KEY, as the wrappers do" \
  env HANDOFF_PRIVKEY="$KEY.previous" bash ../agent-setup.sh --rotate
expect_refusal "--retire --yes KEY.previous" 1 "is a rotation's old key (its name ends in .previous); --retire takes the current key" \
  bash ../agent-setup.sh --retire --yes "$KEY.previous"
expect_refusal "--retire --yes with HANDOFF_PRIVKEY at .previous" 1 "HANDOFF_PRIVKEY ($KEY.previous) names a rotation's old key" \
  env HANDOFF_PRIVKEY="$KEY.previous" bash ../agent-setup.sh --retire --yes
expect_refusal "--rotate KEY.PREVIOUS" 1 "is a rotation's old key" \
  bash ../agent-setup.sh --rotate "$KEY.PREVIOUS"
# A key file named just ".previous": no empty name suggested as the current key.
(cd "$(dirname -- "$KEY")" && expect_refusal "--rotate .previous" 1 "--rotate takes the current key; nothing changed" \
  bash "$OLDPWD/../agent-setup.sh" --rotate .previous)
expect_refusal "consume.py with HANDOFF_PRIVKEY at .previous" 1 "names a rotation's old key (its name ends in .previous); a wrapper sets it to the current key, '$KEY'" \
  env HANDOFF_PRIVKEY="$KEY.previous" python3 ../consume.py --label example --check --blob-file blob-age.txt
expect_refusal "consume.py --rewrap with HANDOFF_PRIVKEY at .Previous" 1 "names a rotation's old key" \
  env HANDOFF_PRIVKEY="$KEY.Previous" python3 ../consume.py --label example --rewrap --blob-file blob-age.txt
(cd "$(dirname -- "$KEY")" && expect_refusal "consume.py with HANDOFF_PRIVKEY=.previous" 1 "a wrapper sets it to the current key (SETUP.md step 7)" \
  env HANDOFF_PRIVKEY=.previous python3 "$OLDPWD/../consume.py" --label example --check --blob-file "$OLDPWD/blob-age.txt")
# The same name with a directory in front: still no name suggested (a/ isn't one).
expect_refusal "--rotate dir/.previous" 1 "--rotate takes the current key; nothing changed" \
  bash ../agent-setup.sh --rotate "$(dirname -- "$KEY")/.previous"
expect_refusal "consume.py with HANDOFF_PRIVKEY=dir/.previous" 1 "a wrapper sets it to the current key (SETUP.md step 7)" \
  env HANDOFF_PRIVKEY="$(dirname -- "$KEY")/.previous" python3 ../consume.py --label example --check --blob-file blob-age.txt
# --check-setup fails such a HANDOFF_PRIVKEY, as consume.py refuses it.
env HANDOFF_PRIVKEY="$KEY.previous" bash ../agent-setup.sh --check-setup >"$S/out" 2>"$S/err" && fail "--check-setup passed a HANDOFF_PRIVKEY at .previous"
grep -qxF "FAIL identity: HANDOFF_PRIVKEY ($KEY.previous) names a rotation's old key (its name ends in .previous); a wrapper sets it to the current key, $KEY" "$S/out" \
  || fail "--check-setup didn't fail the .previous HANDOFF_PRIVKEY: $(grep identity "$S/out")"
echo "ok (refused: --check-setup with HANDOFF_PRIVKEY at .previous)"
[ "$(keys_now)" = "$before_prev" ] || fail "a refused .previous KEY changed the key directory"
# What a --rotate on KEY.previous left (releases up to 0.2.0): --rotate and
# --retire change nothing, and consume.py's neither-key failure names it.
cp -p "$KEY.previous" "$KEY.previous.previous"
expect_refusal "--retire --yes with a .previous.previous" 1 "previous.previous exists, most likely left by an earlier --rotate given $KEY.previous as its KEY" \
  rk bash ../agent-setup.sh --retire --yes
[ -e "$KEY.previous" ] && [ -e "$KEY.previous.previous" ] || fail "a refused --retire with a .previous.previous deleted a key"
expect_refusal "--rotate with a .previous.previous" 1 "previous.previous exists, most likely left by an earlier --rotate given $KEY.previous as its KEY: the keys aren't where a rotation keeps them, and nothing was rotated" \
  rk bash ../agent-setup.sh --rotate
enc_other '{"svc":"example","password":"mk-Zq9"}' > "$R/neither-pp.txt"
expect_refusal "a blob for neither key, with a .previous.previous" 1 "and with the previous key ('$KEY.previous'), and '$KEY.previous.previous' exists (ROTATION.md: A .previous.previous file)" \
  rk python3 ../consume.py --label example --check --blob-file "$R/neither-pp.txt"
# The same with no .previous (what a --retire after that --rotate left): not
# "no rotation to retire", which would read as done with the old key on disk.
mv "$KEY.previous" "$R/held-pp.txt"
expect_refusal "--retire --yes with a .previous.previous and no .previous" 1 "previous.previous exists, most likely left by an earlier --rotate" \
  rk bash ../agent-setup.sh --retire --yes
expect_refusal "a blob for no key, with a .previous.previous and no .previous" 1 "decryption failed with the key at '$KEY', and '$KEY.previous.previous' exists" \
  rk python3 ../consume.py --label example --check --blob-file "$R/neither-pp.txt"
rk bash ../agent-setup.sh --check-setup >"$S/out" 2>"$S/err" && fail "--check-setup passed with a .previous.previous"
grep -qxF "FAIL identity: $KEY.previous.previous exists: the keys aren't where a rotation keeps them (ROTATION.md: A .previous.previous file)" "$S/out" \
  || fail "--check-setup didn't fail a .previous.previous: $(grep identity "$S/out")"
echo "ok (refused: --check-setup with a .previous.previous)"
mv "$R/held-pp.txt" "$KEY.previous"
rm "$KEY.previous.previous"; ln -s "$R/nowhere" "$KEY.previous.previous"
expect_refusal "--retire --yes with a dangling .previous.previous link" 1 "previous.previous exists" \
  rk bash ../agent-setup.sh --retire --yes
expect_refusal "--rotate with a dangling .previous.previous link" 1 "previous.previous exists" \
  rk bash ../agent-setup.sh --rotate
expect_refusal "a blob for neither key, with a dangling .previous.previous link" 1 "and '$KEY.previous.previous' exists (ROTATION.md: A .previous.previous file)" \
  rk python3 ../consume.py --label example --check --blob-file "$R/neither-pp.txt"
rk bash ../agent-setup.sh --check-setup >"$S/out" 2>"$S/err" && fail "--check-setup passed with a dangling .previous.previous link"
grep -qxF "FAIL identity: $KEY.previous.previous exists: the keys aren't where a rotation keeps them (ROTATION.md: A .previous.previous file)" "$S/out" \
  || fail "--check-setup didn't fail a dangling .previous.previous link: $(grep identity "$S/out")"
echo "ok (refused: --check-setup with a dangling .previous.previous link)"
rm "$KEY.previous.previous" "$R/neither-pp.txt"
[ "$(keys_now)" = "$before_prev" ] || fail "the .previous.previous checks changed the key directory"
# --retire without --yes keeps the old key and names it with its recipient.
expect_refusal "--retire without --yes" 1 "only once ROTATION.md step 5's last pass is recorded" \
  rk bash ../agent-setup.sh --retire
[ -e "$KEY.previous" ] || fail "--retire without --yes deleted the previous key"
grep -qF "deletes the previous key $KEY.previous (recipient $old_rcpt)" "$S/err" \
  || fail "--retire without --yes didn't name the old key and its recipient: $(cat "$S/err")"
expect_refusal "--retire --yes given twice" 2 "--yes given twice" \
  rk bash ../agent-setup.sh --retire --yes --yes
expect_refusal "--yes with another mode" 2 "goes only right after --retire" \
  rk bash ../agent-setup.sh --rotate --yes
expect_refusal "--retire KEY --yes (misordered)" 2 "usage: agent-setup.sh --retire --yes [KEY]" \
  rk bash ../agent-setup.sh --retire "$KEY" --yes
[ -e "$KEY.previous" ] || fail "a refused --retire --yes deleted the previous key"
# A caller's yes= can't confirm: only --yes on the command line does.
expect_refusal "--retire with yes=1 in the environment" 1 "only once ROTATION.md step 5's last pass is recorded" \
  rk env yes=1 bash ../agent-setup.sh --retire
[ -e "$KEY.previous" ] || fail "a caller's yes= confirmed --retire"
# A mistyped confirmation (-y) is a KEY with no key file, not "no rotation".
(cd "$S" && expect_refusal "--retire -y" 1 "no key file at -y (the confirmation is spelled --yes)" \
  env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --retire -y)
expect_refusal "--retire --YES" 2 "the confirmation is spelled --yes" \
  rk bash ../agent-setup.sh --retire --YES
expect_refusal "--retire --yes=1" 2 "the confirmation is spelled --yes" \
  rk bash ../agent-setup.sh --retire --yes=1
[ -e "$KEY.previous" ] || fail "a mistyped confirmation deleted the previous key"
# With --yes given, a stray -y or --YES isn't called a misspelling of it.
(cd "$S" && env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --retire --yes -y >/dev/null 2>"$S/err") || true
if ! grep -qxF "no key file at -y" "$S/err"; then fail "--retire --yes -y gave the confirmation hint: $(cat "$S/err")"; fi
expect_refusal "--retire --yes --YES" 2 "--YES isn't a KEY" \
  rk bash ../agent-setup.sh --retire --yes --YES
expect_refusal "--rotate --YES" 2 "--YES isn't a KEY" \
  rk bash ../agent-setup.sh --rotate --YES
# Each KEY the hint covers, typed on the command line; not one from
# HANDOFF_PRIVKEY, which nobody typed as a confirmation.
for k in yes -yes y ye -ye; do
  (cd "$S" && expect_refusal "--retire $k" 1 "no key file at $k (the confirmation is spelled --yes)" \
    env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --retire "$k")
done
(cd "$S" && env HANDOFF_PRIVKEY=yes bash "$OLDPWD/../agent-setup.sh" --retire >/dev/null 2>"$S/err") || true
if ! grep -qxF "no key file at yes" "$S/err"; then fail "HANDOFF_PRIVKEY=yes got the confirmation hint: $(cat "$S/err")"; fi
for y in --y --ye; do
  expect_refusal "--retire $y" 2 "the confirmation is spelled --yes" \
    rk bash ../agent-setup.sh --retire "$y"
done
expect_refusal "--retire --yes KEY --yes" 2 "(--yes given twice)" \
  rk bash ../agent-setup.sh --retire --yes "$KEY" --yes
expect_refusal "--retire KEY --yes (the reason)" 2 "--yes goes right after --retire, before KEY" \
  rk bash ../agent-setup.sh --retire "$KEY" --yes
# A misspelled or misplaced confirmation in any position gets its reason,
# not a bare usage line (issue #16 item 1); upper case too (item 5).
for args in "-y $KEY" "$KEY -y" "$KEY -Y" "$KEY --YES" "--y $KEY" "$KEY yes" "yes $KEY" "$KEY y" "$KEY YES" "Y $KEY"; do
  # shellcheck disable=SC2086  # the words are separate arguments on purpose
  expect_refusal "--retire $args" 2 "the confirmation is spelled --yes, right after --retire" \
    rk bash ../agent-setup.sh --retire $args
done
# With --yes given, a stray --YES isn't called a misspelling of it, with a
# KEY after it as without one (below).
expect_refusal "--retire --yes --YES KEY" 2 "(--YES isn't a KEY)" \
  rk bash ../agent-setup.sh --retire --yes --YES "$KEY"
expect_refusal "--retire --yes --yes KEY" 2 "(--yes given twice)" \
  rk bash ../agent-setup.sh --retire --yes --yes "$KEY"
# An unknown option after --retire is an option of --retire (item 4); after
# --rotate, it says --rotate takes none; another mode is still "one mode".
expect_refusal "--retire --force" 2 "--force isn't an option of --retire; its one option is the confirmation --yes" \
  rk bash ../agent-setup.sh --retire --force
expect_refusal "--rotate --force" 2 "--force isn't an option of --rotate, which takes none" \
  rk bash ../agent-setup.sh --rotate --force
expect_refusal "--retire --rotate" 2 "one mode at a time; --rotate isn't a KEY" \
  rk bash ../agent-setup.sh --retire --rotate
[ -e "$KEY.previous" ] || fail "a misplaced confirmation deleted the previous key"
# --retire --yes deletes the previous key: an old blob stops opening, a
# rewrapped one doesn't. (The key is put back afterward from the copy taken
# before the --rewrap checks.)
rk bash ../agent-setup.sh --retire --yes >"$R/out" 2>"$R/err" || { cat "$R/err" >&2; fail "--retire --yes failed"; }
[ ! -e "$KEY.previous" ] || fail "--retire left the previous key"
grep -qxF "deleted the previous key $KEY.previous; the current key is $KEY (recipient $new_rcpt)" "$R/out" || fail "--retire didn't say what it deleted: $(cat "$R/out")"
[ "$("$AGE_KEYGEN" -y "$KEY")" = "$new_rcpt" ] || fail "--retire changed the current key"
expect_refusal "an old blob after the previous key is gone" 1 "decryption failed" \
  rk python3 ../consume.py --label example --check --blob-file blob-age.txt
rk python3 ../consume.py --label example --check --blob-file "$ST/new.txt" >/dev/null || fail "the rewrapped blob stopped opening without the previous key"
expect_refusal "--retire --yes with no rotation" 1 "no rotation to retire" \
  rk bash ../agent-setup.sh --retire --yes
cp -p "$S/keybefore/previous" "$KEY.previous"
# Two blobs appended into one file are named as that, not "not base64".
printf '%s\n%s\n' "$cur_blob" "$cur_blob" > "$ST/two.txt"
expect_refusal "two blobs concatenated" 1 "looks like several blobs concatenated" \
  rk python3 ../consume.py --label example --rewrap --blob-file "$ST/two.txt"
# Padding signs that don't belong, with nothing after them, in a single blob
# are just "not valid base64".
printf '%s===\n' "$cur_blob" > "$ST/one.txt"
rc=0; rk python3 ../consume.py --label example --check --blob-file "$ST/one.txt" >/dev/null 2>"$S/err" || rc=$?
if [ "$rc" != 1 ] || ! grep -qF "not valid base64" "$S/err" || grep -qF "concatenated" "$S/err"; then
  fail "one damaged blob was called several concatenated: exit $rc, $(cat "$S/err")"
fi
# With stdout closed, run mode starts the command without a traceback.
now_blob=$(enc_to "$new_rcpt" '{"svc":"example","password":"mk-Zq9-now"}')
rc=0; rk python3 ../consume.py --label example --blob "$now_blob" -- sh -c 'echo ran >&2' >&- 2>"$R/err" || rc=$?
if grep -q Traceback "$R/err" || ! grep -qx ran "$R/err"; then
  fail "run mode with stdout closed: exit $rc, $(cat "$R/err")"
fi
# Under the ./consume.py launcher with stderr closed (fd 2 is then the script,
# read-only): a refusal exits 1, not 120, and run mode runs the command with
# nothing of the helper's on stdout, during a rotation or not.
rc=0; rk ../consume.py --label example 2>&- || rc=$?
[ "$rc" = 1 ] || fail "a refusal with stderr closed under the launcher: exit $rc, expected 1"
for mode in plain rotating; do
  [ "$mode" = plain ] && mv "$KEY.previous" "$R/held.txt"
  [ "$mode" = rotating ] && mv "$R/held.txt" "$KEY.previous"
  rc=0; out=$(rk ../consume.py --label example --blob "$now_blob" -- sh -c 'echo ran' 2>&-) || rc=$?
  if [ "$rc" != 0 ] || [ "$out" != ran ]; then
    fail "run mode with stderr closed ($mode): exit $rc, stdout: $out"
  fi
done
# --help anywhere among the helper's own options prints the usage.
consume --rewrap --help >"$S/out" 2>&1 || fail "--rewrap --help failed"
grep -qF -- "--rewrap --blob-file" "$S/out" || fail "--rewrap --help doesn't show the usage"
# --help as an option's value isn't a request for help.
rc=0; consume --label --help --check >"$S/out" 2>&1 || rc=$?
if [ "$rc" = 0 ] || grep -qF "Usage:" "$S/out"; then fail "--label --help printed the usage"; fi
# The scan walks the options as parse_args does (issue #8 item 5): a value
# can look like an option, and "--" as a value doesn't start the command.
consume --blob --label --help >"$S/out" 2>&1 || fail "--blob --label --help failed: $(cat "$S/out")"
grep -qF -- "--rewrap --blob-file" "$S/out" || fail "--blob --label --help doesn't show the usage"
consume --label -- --help >"$S/out" 2>&1 || fail "--label -- --help failed: $(cat "$S/out")"
grep -qF -- "--rewrap --blob-file" "$S/out" || fail "--label -- --help doesn't show the usage"
# ...and --help after the command's own "--" is the command's.
rc=0; consume --label example --check -- --help >"$S/out" 2>&1 || rc=$?
if grep -qF "Usage:" "$S/out"; then fail "--help after -- printed the helper's usage"; fi
# --help prints the usage and exits 0.
consume --help >"$S/out" 2>&1 || fail "consume.py --help failed"
grep -qF -- "--rewrap" "$S/out" || fail "consume.py --help doesn't show the usage"
# ...also with $HANDOFF_LABEL set, and with docstrings stripped (-OO).
HANDOFF_LABEL=x python3 ../consume.py --help >/dev/null 2>&1 || fail "--help was refused with HANDOFF_LABEL set"
python3 -OO ../consume.py --help >"$S/out" 2>&1 || fail "--help failed under python3 -OO: $(cat "$S/out")"
grep -qF "usage: consume.py" "$S/out" || fail "--help under -OO printed no usage"

# agent-setup.sh on its own: interrupted and repeated rotations, failures of
# the key generation, the lock, and odd key paths. (The --rewrap and
# consume.py checks that go with them are above.)
real_keygen=$(command -v "$AGE_KEYGEN")
# fake_keygen DIR SNIPPET: an age-keygen in DIR that runs SNIPPET (sh; the
# arguments are "$@") and then the real one.
fake_keygen() {
  mkdir -p "$1"
  printf '#!/bin/sh\n%s\nexec %s "$@"\n' "$2" "$real_keygen" >"$1/age-keygen"
  chmod 755 "$1/age-keygen"
}
# An interrupted --rotate (stopped after keeping the old key, before the new
# one replaced it): both names are the old key. --retire refuses, and a
# re-run of --rotate finishes it.
rk bash ../agent-setup.sh --retire --yes >/dev/null 2>&1 || fail "--retire before the interrupted-rotation checks failed"
cur_rcpt=$("$AGE_KEYGEN" -y "$KEY")
ln "$KEY" "$KEY.previous"
expect_refusal "--retire --yes before an interrupted rotation finished" 1 "the rotation didn't finish" \
  rk bash ../agent-setup.sh --retire --yes
[ -e "$KEY.previous" ] || fail "a refused --retire deleted the previous key"
rk bash ../agent-setup.sh --rotate >"$R/out" 2>"$R/err" || { cat "$R/err" >&2; fail "a re-run --rotate failed"; }
grep -qF "resuming an interrupted rotation" "$R/err" || fail "a re-run --rotate didn't say it resumed"
[ ! "$KEY.previous" -ef "$KEY" ] || fail "a re-run --rotate didn't make a new key"
[ "$(rk bash ../agent-setup.sh --fingerprint "$KEY.previous" 2>/dev/null)" = "recipient: $cur_rcpt" ] \
  || fail "a re-run --rotate lost the key it was rotating from"
rk bash ../agent-setup.sh --retire --yes >/dev/null 2>&1 || fail "--retire after the resumed rotation failed"
cur_rcpt=$("$AGE_KEYGEN" -y "$KEY")
# A key generation that fails leaves the old key in place and no temporary
# file, and shows age-keygen's reason: a fake age-keygen that fails -o and
# passes everything else on.
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
fake_keygen "$S/nogen" 'for a; do [ "$a" = -o ] && { echo "age-keygen: simulated failure" >&2; exit 1; }; done'
before=$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)
expect_refusal "--rotate whose key generation fails" 1 "key generation failed; the old key is unchanged" \
  rk env PATH="$S/nogen:/usr/bin:/bin" bash ../agent-setup.sh --rotate
grep -qF "simulated failure" "$S/err" || fail "a failed key generation hid age-keygen's reason"
[ "$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)" = "$before" ] || fail "a failed --rotate changed the current key"
# shellcheck disable=SC2015  # the || branch is the failure message, not an else
! compgen -G "$R/.handoff-new*" >/dev/null && ! compgen -G "$R/.handoff-tmp*" >/dev/null || fail "a failed --rotate left a temporary key file"
# It did keep the old key as the previous one: a re-run resumes from there.
[ "$KEY.previous" -ef "$KEY" ] || fail "a failed --rotate didn't leave the resumable state"
rm "$KEY.previous"
expect_refusal "--rotate with no key" 1 "no key file at" \
  env HANDOFF_PRIVKEY="$R/none.txt" bash ../agent-setup.sh --rotate
expect_refusal "--rotate, two keys" 2 "usage: agent-setup.sh --rotate" \
  bash ../agent-setup.sh --rotate "$KEY" "$KEY"
# A key generation that exits 0 after a short write (a full disk) is caught
# before it replaces anything, in --rotate and at first setup.
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
fake_keygen "$S/shortgen" 'prev=; for a; do [ "$prev" = -o ] && { head -c 1024 /dev/zero > "$a"; exit 0; }; prev=$a; done'
before=$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)
expect_refusal "--rotate whose age-keygen writes a short file" 1 "the new key didn't check out" \
  rk env PATH="$S/shortgen:/usr/bin:/bin" bash ../agent-setup.sh --rotate
[ "$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)" = "$before" ] || fail "a short key write replaced the current key"
# shellcheck disable=SC2015  # the || branch is the failure message, not an else
! compgen -G "$R/.handoff-new*" >/dev/null && ! compgen -G "$R/.handoff-tmp*" >/dev/null || fail "a short key write left a temporary key file"
cur_blob=$(enc_to "$("$AGE_KEYGEN" -y "$KEY")" '{"svc":"example","password":"mk-Zq9-cur"}')
rk python3 ../consume.py --label example --check --blob "$cur_blob" >/dev/null || fail "the current key stopped working after a short key write"
rm "$KEY.previous"
expect_refusal "first setup whose age-keygen writes a short file" 1 "nothing was written" \
  env PATH="$S/shortgen:/usr/bin:/bin" HANDOFF_KEY_DIR="$S/short-setup" bash ../agent-setup.sh
[ ! -e "$S/short-setup/handoff-identity.txt" ] || fail "first setup left a short key file at the key path"
# shellcheck disable=SC2015  # the || branch is the failure message, not an else
! compgen -G "$S/short-setup/.handoff-setup.*" >/dev/null && ! compgen -G "$S/short-setup/.handoff-tmp.*" >/dev/null || fail "first setup left a temporary key file"
# An age-keygen -y that fails is "cannot load", whatever the file holds.
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
fake_keygen "$S/noy" 'for a; do [ "$a" = -y ] && exit 1; done'
expect_refusal "--fingerprint whose age-keygen -y fails" 1 "cannot load the age identity at $KEY" \
  rk env PATH="$S/noy:/usr/bin:/bin" bash ../agent-setup.sh --fingerprint
! grep -q "is not an age identity" "$S/err" || fail "a failing age-keygen -y was reported as another kind of file"
# A copied (not hard-linked) .previous holding the current key resumes and
# rotates, read by recipient; one holding another key is a rotation under way.
cur_rcpt=$("$AGE_KEYGEN" -y "$KEY")
cp -p "$KEY" "$KEY.previous"
rk bash ../agent-setup.sh --rotate >"$R/out" 2>"$R/err" || { cat "$R/err" >&2; fail "--rotate with a copied .previous failed"; }
grep -qF "resuming an interrupted rotation" "$R/err" || fail "a copied .previous holding the current key didn't resume"
[ "$("$AGE_KEYGEN" -y "$KEY")" != "$cur_rcpt" ] || fail "a copied .previous made --rotate rotate nothing"
[ "$(rk bash ../agent-setup.sh --fingerprint "$KEY.previous" 2>/dev/null)" = "recipient: $cur_rcpt" ] || fail "the copied .previous isn't the old key after --rotate"
cp -p "$KEY" "$KEY.previous"
expect_refusal "--retire --yes with a .previous holding the current key" 1 "holds the current key: the rotation didn't finish" \
  rk bash ../agent-setup.sh --retire --yes
# ...and it says to stop and points at ROTATION.md, not at another --rotate,
# which would strand the labels already rewrapped (issue #117).
grep -qF "Nothing was deleted: stop, and do what ROTATION.md says for this refusal where you are (Rotation step 5 or step 1 case 4, or Compromise step 2 or 4)" "$S/err" || fail "the same-key --retire refusal doesn't point at ROTATION.md: $(cat "$S/err")"
! grep -qF "run agent-setup.sh --rotate again" "$S/err" || fail "the same-key --retire refusal still says to run --rotate again"
[ -f "$KEY.previous" ] || fail "a refused --retire --yes deleted a .previous holding the current key"
rm "$KEY.previous"; mkdir "$KEY.previous"
expect_refusal "--rotate with a directory at .previous" 1 "is not a regular file" \
  rk bash ../agent-setup.sh --rotate
expect_refusal "--retire --yes with a directory at .previous" 1 "is not a regular file" \
  rk bash ../agent-setup.sh --retire --yes
[ -d "$KEY.previous" ] || fail "a refused --retire --yes removed a directory at .previous"
rmdir "$KEY.previous"
# One --rotate or --retire at a time: a held lock refuses, and a temporary key
# a killed run left is removed by the next one.
mkdir "$R/.handoff-lock"
expect_refusal "--rotate while another holds the lock" 1 "another setup, --rotate or --retire is running" \
  rk bash ../agent-setup.sh --rotate
grep -qF "Stop and report it to the user" "$S/err" || fail "the lock refusal doesn't say to report it"
# The rmdir it gives is absolute and single-quoted (issue #9 item 9).
grep -qF "they remove it with: rmdir '$(cd "$R" && pwd -P)/.handoff-lock'" "$S/err" || fail "the lock refusal's rmdir isn't absolute and quoted: $(cat "$S/err")"
[ ! -e "$KEY.previous" ] || fail "a refused --rotate made a previous key"
rmdir "$R/.handoff-lock"
printf 'leftover\n' > "$R/.handoff-new.Leftov"
rk bash ../agent-setup.sh --rotate >/dev/null 2>"$R/err" || { cat "$R/err" >&2; fail "--rotate with a leftover temporary key failed"; }
grep -qF "removed a temporary key a killed --rotate left behind: $R/.handoff-new.Leftov" "$R/err" || fail "the leftover temporary key wasn't reported"
[ ! -e "$R/.handoff-new.Leftov" ] || fail "the leftover temporary key wasn't removed"
[ ! -e "$R/.handoff-lock" ] || fail "--rotate left its lock behind"
rk bash ../agent-setup.sh --retire --yes >/dev/null 2>&1 || fail "--retire after the lock checks failed"
# A caller's BASHOPTS can't change the script's globbing (issue #43 item 12):
# with failglob, every unmatched cleanup glob was fatal.
rk env BASHOPTS=failglob:nullglob:nocasematch bash ../agent-setup.sh --rotate >/dev/null 2>"$R/err" || fail "--rotate failed with BASHOPTS=failglob: $(cat "$R/err")"
rk env BASHOPTS=failglob:nullglob:nocasematch bash ../agent-setup.sh --retire --yes >/dev/null 2>"$R/err" || fail "--retire --yes failed with BASHOPTS=failglob: $(cat "$R/err")"
# With noglob (SHELLOPTS), every sweep matched nothing: a killed --rotate's
# temporary key stayed.
printf 'leftover\n' > "$R/.handoff-new.Leftov"
rk env SHELLOPTS=noglob bash ../agent-setup.sh --rotate >/dev/null 2>"$R/err" || fail "--rotate failed with SHELLOPTS=noglob: $(cat "$R/err")"
[ ! -e "$R/.handoff-new.Leftov" ] || fail "--rotate under SHELLOPTS=noglob didn't remove a killed run's temporary key"
rk env SHELLOPTS=noglob bash ../agent-setup.sh --retire --yes >/dev/null 2>"$R/err" || fail "--retire --yes failed with SHELLOPTS=noglob: $(cat "$R/err")"
echo "ok (--rotate and --retire under a caller's BASHOPTS=failglob or SHELLOPTS=noglob)"
[ ! -e "$R/.handoff-lock" ] || fail "--retire left its lock behind"
# --rotate's sweep takes only mktemp's shape, as setup's does: a directory the
# user named .handoff-tmp.mybackup stays.
mkdir "$R/.handoff-tmp.mybackup"
rk bash ../agent-setup.sh --rotate >/dev/null 2>"$R/err" || fail "--rotate beside a .handoff-tmp.mybackup failed: $(cat "$R/err")"
[ -d "$R/.handoff-tmp.mybackup" ] || fail "--rotate removed a directory not of mktemp's shape"
rk bash ../agent-setup.sh --retire --yes >/dev/null 2>&1 || fail "--retire after the sweep-shape check failed"
rmdir "$R/.handoff-tmp.mybackup"
# A key path that starts with "-" is a path, not an option.
mkdir -p "$R/dash"; cp "$TMPKEY" "$R/dash/-k.txt"
(cd "$R/dash" && env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --rotate -k.txt >/dev/null 2>&1 \
  && env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --retire --yes -k.txt >/dev/null 2>&1) \
  || fail "--rotate / --retire on a key path starting with - failed"
[ ! -e "$R/dash/-k.txt.previous" ] || fail "--retire on a key path starting with - left the previous key"
# Two --rotate runs at once: the second, started while the first is
# generating, is refused at the lock, and the first one's key is the key.
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
fake_keygen "$S/slowgen" 'for a; do [ "$a" = -o ] && sleep 2; done'
# The second run's recipient read is slow too (its -y takes 4 s), so a run
# that read the key before taking the lock would see the first run finish,
# then take that run's new key for its own old one.
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
fake_keygen "$S/slowy" 'for a; do [ "$a" = -y ] && sleep 4; done'
rk env PATH="$S/slowgen:/usr/bin:/bin" bash ../agent-setup.sh --rotate >"$R/race-a" 2>&1 &
first=$!
sleep 0.5
rc=0; rk env PATH="$S/slowy:/usr/bin:/bin" bash ../agent-setup.sh --rotate >"$R/race-b" 2>&1 || rc=$?
wait "$first" || fail "the first of two --rotate runs failed: $(cat "$R/race-a")"
if [ "$rc" != 1 ] || ! grep -qF "another setup, --rotate or --retire is running" "$R/race-b"; then
  fail "the second of two --rotate runs wasn't refused at the lock: exit $rc, $(cat "$R/race-b")"
fi
won=$(sed -n 's/^new recipient: //p' "$R/race-a")
[ -n "$won" ] && [ "$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)" = "recipient: $won" ] \
  || fail "the first --rotate's key isn't the current key after a refused second run"
# --retire takes the lock too, and the lock message is only for a lock: an
# unwritable key directory is reported as that.
mkdir "$R/.handoff-lock"
expect_refusal "--retire --yes while another holds the lock" 1 "another setup, --rotate or --retire is running" \
  rk bash ../agent-setup.sh --retire --yes
[ -e "$KEY.previous" ] || fail "a refused --retire deleted the previous key"
rmdir "$R/.handoff-lock"
if [ "$(id -u)" != 0 ]; then
  chmod 500 "$R"
  rc=0; rk bash ../agent-setup.sh --retire --yes >"$S/out" 2>"$S/err" || rc=$?
  chmod 700 "$R"
  if [ "$rc" != 1 ] || ! grep -qF "cannot create the lock in $R" "$S/err" || grep -qF "is running" "$S/err"; then
    fail "an unwritable key directory was reported as a held lock: exit $rc, $(cat "$S/err")"
  fi
  echo "ok (refused: an unwritable key directory, reported as such)"
fi
# A caller's $new or $lock can't make --retire delete something.
printf 'keep\n' > "$R/victim"
rk env new="$R/victim" lock="$R/victim" bash ../agent-setup.sh --retire --yes >/dev/null 2>&1 || fail "--retire with new= and lock= set failed"
[ -f "$R/victim" ] || fail "--retire deleted a file named by the caller's \$new or \$lock"
# A key directory starting with "-" works for --rotate and first setup.
mkdir -p "$R/dash2/-d"; cp "$TMPKEY" "$R/dash2/-d/k.txt"
(cd "$R/dash2" && env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --rotate -d/k.txt >/dev/null 2>&1 \
  && env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --retire --yes -d/k.txt >/dev/null 2>&1 \
  && env -u HANDOFF_PRIVKEY HANDOFF_KEY_DIR=-g bash "$OLDPWD/../agent-setup.sh" >/dev/null 2>&1) \
  || fail "a key directory starting with - failed"
[ -f "$R/dash2/-g/handoff-identity.txt" ] || fail "first setup in a directory starting with - wrote no key"
# First setup never replaces a key that appears while it generates.
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
fake_keygen "$S/racegen" 'prev=; for a; do [ "$prev" = -o ] && printf existing > "$(dirname "$(dirname "$a")")/handoff-identity.txt"; prev=$a; done'
expect_refusal "first setup when a key appears meanwhile" 1 "could not link the new key into place" \
  env PATH="$S/racegen:/usr/bin:/bin" HANDOFF_KEY_DIR="$S/race-setup" bash ../agent-setup.sh
[ "$(cat "$S/race-setup/handoff-identity.txt")" = existing ] || fail "first setup replaced a key that appeared meanwhile"
# A TERM while age-keygen runs leaves no temporary private key behind (bash
# waits for the child, then its EXIT trap removes the file the child wrote).
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
fake_keygen "$S/slowgen3" 'for a; do [ "$a" = -o ] && sleep 3; done'
mkdir -p "$S/term-setup"
env PATH="$S/slowgen3:/usr/bin:/bin" HANDOFF_KEY_DIR="$S/term-setup" bash ../agent-setup.sh >/dev/null 2>&1 &
gen=$!
sleep 1
kill -TERM "$gen"
wait "$gen" 2>/dev/null || true
sleep 3
! compgen -G "$S/term-setup/.handoff-setup.*" >/dev/null || fail "a TERM during key generation left a temporary private key"
[ ! -e "$S/term-setup/handoff-identity.txt" ] || fail "a TERM during key generation still wrote the key"
# A directory named like a temporary key stops --rotate's sweep with a report.
mkdir "$R/.handoff-new.dir"
expect_refusal "--rotate with a directory named like a temporary key" 1 "is not a temporary key file" \
  rk bash ../agent-setup.sh --rotate
rmdir "$R/.handoff-new.dir"
# A TERM during --rotate's key generation leaves no temporary key and the key as it was.
before=$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)
# Started directly (env execs bash), not through rk: a backgrounded function
# is a subshell, and $! would be its PID.
env HANDOFF_PRIVKEY="$KEY" PATH="$S/slowgen3:/usr/bin:/bin" bash ../agent-setup.sh --rotate >/dev/null 2>"$S/term-rot-err" &
rot=$!
sleep 1
kill -TERM "$rot"
wait "$rot" 2>/dev/null || true
sleep 3
! compgen -G "$R/.handoff-*" >/dev/null || fail "a TERM during --rotate left a temporary key or the lock"
grep -qF "interrupted; run --rotate again to finish" "$S/term-rot-err" || fail "an interrupted --rotate didn't say so: $(cat "$S/term-rot-err")"
[ "$(rk bash ../agent-setup.sh --fingerprint 2>/dev/null)" = "$before" ] || fail "a TERM during --rotate changed the key"
rm -f "$KEY.previous"
# A key path that turns into a directory during generation: ln would put the
# key inside it. Refused, with no copy left behind.
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
fake_keygen "$S/dirgen" 'prev=; for a; do [ "$prev" = -o ] && mkdir "$(dirname "$(dirname "$a")")/handoff-identity.txt"; prev=$a; done'
expect_refusal "first setup when the key path becomes a directory" 1 "it is now a directory" \
  env PATH="$S/dirgen:/usr/bin:/bin" HANDOFF_KEY_DIR="$S/dir-setup" bash ../agent-setup.sh
if compgen -G "$S/dir-setup/handoff-identity.txt/*" >/dev/null || compgen -G "$S/dir-setup/handoff-identity.txt/.handoff-*" >/dev/null; then
  fail "a key was left inside the directory at the key path"
fi
# What a killed setup or --rotate left is removed by the next setup, at once
# with one note, by mktemp's six-character shape only (issue #5 item 6).
mkdir -p "$S/stale-setup"; chmod 700 "$S/stale-setup"
printf 'leftover\n' > "$S/stale-setup/.handoff-setup.Leftov"
mkdir "$S/stale-setup/.handoff-tmp.AbCdEf"; printf 'x\n' > "$S/stale-setup/.handoff-tmp.AbCdEf/AbCdEf.key"
# Not mktemp's shape (seven characters), and a symlink with a matching name:
# neither is something setup makes, so both stay.
printf 'keep\n' > "$S/stale-setup/.handoff-setup.Longer7"
ln -s "$TMPKEY" "$S/stale-setup/.handoff-setup.LinkAb"
HANDOFF_KEY_DIR="$S/stale-setup" bash ../agent-setup.sh >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "first setup with leftover temporary files failed"; }
grep -qxF "note: removed 2 temporary key file(s) or directory(ies) a killed setup or --rotate left in $S/stale-setup" "$S/err" \
  || fail "the leftover temporary files weren't reported in one note: $(cat "$S/err")"
[ ! -e "$S/stale-setup/.handoff-setup.Leftov" ] && [ ! -e "$S/stale-setup/.handoff-tmp.AbCdEf" ] || fail "the leftover temporary files weren't removed"
[ -e "$S/stale-setup/.handoff-setup.Longer7" ] || fail "the stale cleanup removed a name mktemp doesn't make"
[ -L "$S/stale-setup/.handoff-setup.LinkAb" ] || fail "the stale cleanup removed a symlink, which no setup makes"
# The setup's own temporary copy (a second hard link to the new key) is gone
# once it's linked, and the directory is 0700, so no note about it either.
[ -z "$(find "$S/stale-setup" -name '.handoff-tmp.*' -print)" ] || fail "first setup left its temporary directory: $(find "$S/stale-setup" -name '.handoff-tmp.*')"
[ -z "$(find "$S/stale-setup/handoff-identity.txt" -links +1 -print)" ] || fail "the new key has another hard link after setup"
! grep -q 'already exists; its permissions were left unchanged' "$S/err" || fail "first setup noted an existing 0700 key directory"
# First setup takes the lock too (issue #43 item 11): with another run's lock
# held, it refuses and makes nothing.
mkdir -p "$S/locked-setup"; chmod 700 "$S/locked-setup"; mkdir "$S/locked-setup/.handoff-lock"
# The lock comes before the sweep: the lock holder's temporary directory stays.
mkdir "$S/locked-setup/.handoff-tmp.AbCdEf"
expect_refusal "first setup while another holds the lock" 1 "another setup, --rotate or --retire is running" \
  env HANDOFF_KEY_DIR="$S/locked-setup" bash ../agent-setup.sh
[ ! -e "$S/locked-setup/handoff-identity.txt" ] || fail "first setup made a key while another run held the lock"
[ -d "$S/locked-setup/.handoff-tmp.AbCdEf" ] || fail "a first setup refused at the lock swept the lock holder's temporary directory"
# A setup killed after the lock leaves it, and perhaps a temporary copy of the
# key: a rerun refuses to overwrite the key, and names both, with the rmdir;
# --check-setup names them too (an INFO line).
cp "$TMPKEY" "$S/locked-setup/handoff-identity.txt"; chmod 600 "$S/locked-setup/handoff-identity.txt"
# (With HANDOFF_PRIVKEY on another key, --rotate would rotate that one, so
# the note leaves the leftovers to the user; with it on this key, --rotate.)
expect_refusal "a rerun after a setup killed at the lock, HANDOFF_PRIVKEY elsewhere" 1 "a killed run left (report them to the user, who removes them)" \
  env HANDOFF_KEY_DIR="$S/locked-setup" bash ../agent-setup.sh
expect_refusal "a rerun after a setup killed at the lock" 1 "exists: a setup, --rotate or --retire is running, or one was killed; also 1 temporary key directory(ies) a killed run left (the next --rotate removes them). If none is running, report it to the user, who removes the lock with: rmdir '$(cd "$S/locked-setup" && pwd -P)/.handoff-lock'" \
  env HANDOFF_KEY_DIR="$S/locked-setup" HANDOFF_PRIVKEY="$S/locked-setup/handoff-identity.txt" bash ../agent-setup.sh
grep -qF "refusing to overwrite existing key" "$S/err" || fail "the rerun didn't refuse to overwrite: $(cat "$S/err")"
env HANDOFF_PRIVKEY="$S/locked-setup/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -q '^INFO leftovers: .*\.handoff-lock exists' "$S/out" || fail "--check-setup didn't name a killed run's lock: $(cat "$S/out")"
# Without the lock, each kind is named with what removes it, and that is
# true: --rotate removes the directory, and leaves the file for the user.
rmdir "$S/locked-setup/.handoff-lock"
printf 'leftover\n' >"$S/locked-setup/.handoff-setup.Leftov"
env HANDOFF_PRIVKEY="$S/locked-setup/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -qxF "INFO leftovers: $S/locked-setup holds 1 temporary key directory(ies) a killed run left (the next --rotate removes them), and 1 temporary key file(s) a killed setup left (report them to the user, who removes them)" "$S/out" \
  || fail "--check-setup's leftovers line is wrong: $(grep leftovers "$S/out")"
env HANDOFF_PRIVKEY="$S/locked-setup/handoff-identity.txt" bash ../agent-setup.sh --rotate >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "--rotate in a directory with leftovers failed"; }
[ ! -e "$S/locked-setup/.handoff-tmp.AbCdEf" ] || fail "--rotate didn't remove the temporary directory the leftovers line says it removes"
[ -f "$S/locked-setup/.handoff-setup.Leftov" ] || fail "--rotate removed a .handoff-setup file (the leftovers line says the user does)"
rm "$S/locked-setup/.handoff-setup.Leftov"
env HANDOFF_PRIVKEY="$S/locked-setup/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
! grep -q '^INFO leftovers' "$S/out" || fail "--check-setup named leftovers where there are none: $(cat "$S/out")"
# With no key yet (where SETUP step 1 runs --check-setup), the next setup
# removes both kinds, and --rotate refuses: the line says setup.
mkdir -p "$S/nokey-left"; chmod 700 "$S/nokey-left"
printf 'leftover\n' >"$S/nokey-left/.handoff-setup.AbCdEf"; mkdir "$S/nokey-left/.handoff-tmp.XyZ123"
env HANDOFF_PRIVKEY="$S/nokey-left/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -qxF "INFO leftovers: $S/nokey-left holds 2 temporary key file(s) or directory(ies) a killed setup left (the next setup removes them)" "$S/out" \
  || fail "--check-setup's leftovers line with no key is wrong: $(grep leftovers "$S/out")"
HANDOFF_KEY_DIR="$S/nokey-left" bash ../agent-setup.sh >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "setup into a directory with leftovers failed"; }
[ -z "$(find "$S/nokey-left" -name '.handoff-*' -print)" ] || fail "setup didn't remove what the leftovers line said it removes"
# Where neither setup nor --rotate would sweep, the user is told about both
# kinds: another key in the way of setup (HANDOFF_PRIVKEY names a file that
# isn't there), and a symlinked key, which --rotate refuses.
mkdir -p "$S/other-left"; chmod 700 "$S/other-left"
cp "$TMPKEY" "$S/other-left/handoff-identity.txt"; chmod 600 "$S/other-left/handoff-identity.txt"
mkdir "$S/other-left/.handoff-tmp.XyZ123"
env HANDOFF_PRIVKEY="$S/other-left/typo.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -qxF "INFO leftovers: $S/other-left holds 1 temporary key file(s) or directory(ies) a killed run left (report them to the user, who removes them)" "$S/out" \
  || fail "--check-setup's leftovers line beside another key is wrong: $(grep leftovers "$S/out")"
ln -s "$S/nowhere" "$S/other-left/link.txt"
env HANDOFF_PRIVKEY="$S/other-left/link.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -q "^INFO leftovers: .*(report them to the user, who removes them)$" "$S/out" \
  || fail "--check-setup's leftovers line for a symlinked key is wrong: $(grep leftovers "$S/out")"
rm -r "$S/other-left"
# The leftovers line's remover follows the identity line beside it: wherever
# that line doesn't advise setup or pass a key --rotate would rotate, the
# user is told. One state per row: a relative path, a key in a group-writable
# directory, a .previous key, a file that isn't an identity, and no key in a
# group-writable directory.
for state in relative gw-key previous not-identity gw-nokey; do
  sd="$S/who-$state"; rm -rf "$sd"; mkdir -p "$sd/.handoff-tmp.AbCdEf"; chmod 700 "$sd"
  kp="$sd/handoff-identity.txt"
  case "$state" in
    relative) kp=handoff-identity.txt ;;
    gw-key) cp "$TMPKEY" "$kp"; chmod 600 "$kp"; chmod 770 "$sd" ;;
    previous) cp "$TMPKEY" "$sd/k.txt.previous"; chmod 600 "$sd/k.txt.previous"; kp="$sd/k.txt.previous" ;;
    not-identity) printf 'not a key\n' >"$kp"; chmod 600 "$kp" ;;
    gw-nokey) chmod 770 "$sd" ;;
  esac
  (cd "$sd" && env HANDOFF_PRIVKEY="$kp" bash "$OLDPWD/../agent-setup.sh" --check-setup >"$S/out" 2>/dev/null) || true
  grep -q '^INFO leftovers: .*(report them to the user, who removes them)$' "$S/out" \
    || fail "--check-setup's leftovers line ($state) doesn't leave them to the user: $(grep -E 'identity|leftovers' "$S/out")"
  chmod 700 "$sd"; rm -rf "$sd"
done
echo "ok (the leftovers line's remover follows the identity line)"
# A carriage return (or a Unicode line separator) in a key path can't
# overprint or start a line of --check-setup's output.
(cd "$S" && env HANDOFF_PRIVKEY=$'x\rPASS identity: forged' bash "$OLDPWD/../agent-setup.sh" --check-setup >"$S/out" 2>/dev/null) || true
! grep -q $'\r' "$S/out" || fail "--check-setup printed a key path's carriage return"
for ch in $'\xe2\x80\xa8' $'\xc2\x85' $'\xe2\x81\xa6' $'\xe2\x80\x8f' $'\xef\xbb\xbf'; do
  env HANDOFF_PRIVKEY="$S/u${ch}PASS identity: forged/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
  ! LC_ALL=C grep -qF "$ch" "$S/out" || fail "--check-setup printed a key path's $(LC_ALL=C printf '%q' "$ch")"
done
# printf %q leaves a bidi override as it is in a UTF-8 locale: qp quotes such
# a path in C, so --fingerprint's key file: line escapes it.
rod="$S/k"$'\xe2\x80\xae'"txt.exe"; mkdir -p "$rod"; chmod 700 "$rod"; cp "$TMPKEY" "$rod/k.txt"; chmod 600 "$rod/k.txt"
env LC_ALL=C.UTF-8 HANDOFF_PRIVKEY="$rod/k.txt" bash ../agent-setup.sh --fingerprint >/dev/null 2>"$S/err" || true
! LC_ALL=C grep -qF $'\xe2\x80\xae' "$S/err" || fail "--fingerprint printed a key path's bidi override raw: $(LC_ALL=C cat -v "$S/err")"
rm -rf "$rod"
# With HANDOFF_KEY_DIR exported to another directory, the default path's
# advice names its directory: plain setup would make the key elsewhere.
env HOME="$S/kdhome" HANDOFF_PRIVKEY="$S/kdhome/.config/handoff/handoff-identity.txt" HANDOFF_KEY_DIR="$S/elsewhere" \
  bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -qF "HANDOFF_KEY_DIR=$S/kdhome/.config/handoff agent-setup.sh makes it" "$S/out" \
  || fail "--check-setup's default-path advice with HANDOFF_KEY_DIR exported elsewhere: $(grep identity "$S/out")"
# Setup refuses a key directory with a Unicode line separator or a bidi
# override, as it does a control character.
for ch in $'\xe2\x80\xa8' $'\xc2\x85' $'\xe2\x80\xae' $'\xe2\x81\xa6' $'\xe2\x80\x8f' $'\xe2\x80\x8b' $'\xd8\x9c' $'\xef\xbb\xbf' $'\xc2\xad' $'\xe2\x81\xa0'; do
  expect_refusal "setup into a key directory with $(LC_ALL=C printf '%q' "$ch")" 1 "has a control character in its path" \
    env HANDOFF_KEY_DIR="$S/sep${ch}recipient: age1fake" bash ../agent-setup.sh
  [ ! -e "$S/sep${ch}recipient: age1fake" ] || fail "setup made a key directory with $(LC_ALL=C printf '%q' "$ch")"
done
# With a killed run's lock and no key, the identity line doesn't tell the
# agent to run setup, which the lock would refuse.
mkdir -p "$S/lock-nokey/.handoff-lock"; chmod 700 "$S/lock-nokey"
env HANDOFF_PRIVKEY="$S/lock-nokey/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -qxF "INFO identity: no key at $S/lock-nokey/handoff-identity.txt yet; setup there is held up by the .handoff-lock the leftovers line below names" "$S/out" \
  || fail "--check-setup's identity line under a lock is wrong: $(grep identity "$S/out")"
grep -q '^INFO leftovers: .*\.handoff-lock exists' "$S/out" || fail "--check-setup didn't name the lock: $(cat "$S/out")"
# A .handoff-lock that isn't a directory (no run makes one) is reported as
# that, not as a run in progress with an rmdir that would fail.
rmdir "$S/lock-nokey/.handoff-lock"; : >"$S/lock-nokey/.handoff-lock"
expect_refusal "setup with a .handoff-lock file" 1 ".handoff-lock exists but isn't a directory (no run makes one); nothing was written" \
  env HANDOFF_KEY_DIR="$S/lock-nokey" bash ../agent-setup.sh
# --check-setup says the same, and its identity line points at it, for a
# file and for a symlinked lock.
for kind in file link; do
  rm -rf "$S/lock-nokey/.handoff-lock"
  if [ "$kind" = file ]; then : >"$S/lock-nokey/.handoff-lock"; else mkdir -p "$S/lock-target"; ln -s "$S/lock-target" "$S/lock-nokey/.handoff-lock"; fi
  env HANDOFF_PRIVKEY="$S/lock-nokey/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
  grep -qF "setup there is held up by the .handoff-lock the leftovers line below names" "$S/out" || fail "--check-setup's identity line with a $kind lock: $(grep identity "$S/out")"
  grep -q "^INFO leftovers: .*\.handoff-lock exists but isn't a directory (no run makes one)" "$S/out" || fail "--check-setup's leftovers line with a $kind lock: $(grep leftovers "$S/out")"
done
rm -rf "$S/lock-nokey" "$S/lock-target"
# A group-writable directory with no key yet is a FAIL (setup would refuse
# it), not setup advice.
mkdir -p "$S/gw-nokey"; chmod 770 "$S/gw-nokey"
env HANDOFF_PRIVKEY="$S/gw-nokey/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -q '^FAIL identity: .*writable by others' "$S/out" || fail "--check-setup gave setup advice for a group-writable key directory: $(grep identity "$S/out")"
rmdir "$S/gw-nokey"
# A key path with a control character gets no setup advice.
env HANDOFF_PRIVKEY="$S/nl"$'\n'"PASS identity: forged/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -qF "setup refuses a key path with a control character" "$S/out" || fail "--check-setup's advice for a key path with a newline: $(grep identity "$S/out")"
! grep -q '^PASS identity: forged' "$S/out" || fail "a key path's newline started a line of --check-setup's output"
# With a .previous.previous, --rotate refuses before its sweep: the
# leftovers line says the user removes them, as in the overwrite refusal.
mkdir -p "$S/pp-left/.handoff-tmp.AbCdEf"; chmod 700 "$S/pp-left"
cp "$TMPKEY" "$S/pp-left/handoff-identity.txt"; chmod 600 "$S/pp-left/handoff-identity.txt"
cp "$S/pp-left/handoff-identity.txt" "$S/pp-left/handoff-identity.txt.previous.previous"
env HANDOFF_PRIVKEY="$S/pp-left/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -q '^INFO leftovers: .*(report them to the user, who removes them)$' "$S/out" || fail "--check-setup's leftovers line beside a .previous.previous: $(grep leftovers "$S/out")"
expect_refusal "setup over a key with a .previous.previous" 1 "(report them to the user, who removes them)" \
  env HANDOFF_KEY_DIR="$S/pp-left" bash ../agent-setup.sh
rm -r "$S/pp-left"
# A caller's SHELLOPTS=physical doesn't get a key directory symlinked to a
# path with a newline past the control-character check (pwd would print
# the target).
mkdir -p "$S/phys" "$S/phys-real"$'\n'"recipient: age1fake"; chmod 700 "$S/phys-real"$'\n'"recipient: age1fake"
ln -s "$S/phys-real"$'\n'"recipient: age1fake" "$S/phys/link"
env SHELLOPTS=physical HANDOFF_KEY_DIR="$S/phys/link" bash ../agent-setup.sh >"$S/out" 2>"$S/err" || true
! grep -q '^recipient: age1fake' "$S/out" "$S/err" || fail "SHELLOPTS=physical let a key directory's newline start a line: $(cat "$S/out")"
rm -rf "$S/phys" "$S/phys-real"$'\n'"recipient: age1fake"
# A caller's BASHOPTS=xpg_echo doesn't make echo read a key path's
# backslashes: a literal \n can't start a forged line.
bsdir="$S/a\\nrecipient: age1fake"
mkdir -p "$bsdir"; chmod 700 "$bsdir"
# (bash -O, not BASHOPTS: bash 3.2, macOS's, doesn't read BASHOPTS.)
env HANDOFF_KEY_DIR="$bsdir" bash -O xpg_echo ../agent-setup.sh >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "setup under xpg_echo failed"; }
! grep -q '^recipient: age1fake' "$S/out" "$S/err" || fail "BASHOPTS=xpg_echo made a key path's \\n start a line"
grep -qxF "this key lives at: $bsdir/handoff-identity.txt" "$S/out" || fail "setup under BASHOPTS=xpg_echo didn't print the key path as written"
rm -r "$bsdir"
# A caller's SHELLOPTS=keyword doesn't break the scripts.
mkdir -p "$S/kw-setup"; chmod 700 "$S/kw-setup"
env SHELLOPTS=keyword HANDOFF_KEY_DIR="$S/kw-setup" bash ../agent-setup.sh >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "setup under SHELLOPTS=keyword failed"; }
env SHELLOPTS=keyword HANDOFF_PRIVKEY="$S/kw-setup/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>"$S/err" \
  || { cat "$S/out" "$S/err" >&2; fail "--check-setup under SHELLOPTS=keyword failed"; }
# A dangling symlink at the key path gets the overwrite refusal, not a lock,
# a sweep and a failed ln.
mkdir -p "$S/dangle"; chmod 700 "$S/dangle"; ln -s "$S/nowhere-key" "$S/dangle/handoff-identity.txt"
expect_refusal "setup over a dangling symlink at the key path" 1 "refusing to overwrite existing key" \
  env HANDOFF_KEY_DIR="$S/dangle" bash ../agent-setup.sh
rm -r "$S/dangle"
# A key directory with a control or hidden character (made by hand: setup
# refuses one) gets no command to paste: bash's $'...' form turns into code
# under dash. The message says to remove it by hand, and no line of its own
# starts in the output.
nld="$S/b"$'\n'"recipient: age1fake"
mkdir -p "$nld/.handoff-lock"; chmod 700 "$nld"; cp "$TMPKEY" "$nld/k.txt"; chmod 600 "$nld/k.txt"
expect_refusal "--rotate of a key in a directory with a newline, under a lock" 1 "they remove the .handoff-lock directory with rmdir (never rm -r) by hand: its path has a hidden or control character, so no command to paste is printed (LC_ALL=C ls -b shows such a name)" \
  env HANDOFF_PRIVKEY="$nld/k.txt" bash ../agent-setup.sh --rotate
! grep -q '^recipient: age1fake' "$S/err" || fail "the lock message for a directory with a newline printed it raw: $(cat "$S/err")"
! grep -qE "rmdir ['\$/]" "$S/err" || fail "the lock message printed a command for a directory with a newline: $(cat "$S/err")"
rm -r "$nld"
# The dash injection QA found: a soft hyphen (U+00AD), a quote and a # in the
# name. --check-setup's leftovers line prints no rmdir to paste.
inj="$S/a"$'\xc2\xad'"';echo PWNED #"
mkdir -p "$inj/.handoff-lock"; chmod 700 "$inj"
env HANDOFF_PRIVKEY="$inj/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
grep -q '^INFO leftovers: .*removes the .handoff-lock directory with rmdir (never rm -r) by hand' "$S/out" || fail "--check-setup's lock line for a hidden-character path: $(grep leftovers "$S/out")"
! grep -qE "rmdir ['\$/]" "$S/out" || fail "--check-setup printed an rmdir for a hidden-character path: $(grep leftovers "$S/out")"
rm -r "$inj"
# The overwrite refusal names --rotate only for HANDOFF_PRIVKEY naming this
# key itself: a symlink to it (--rotate refuses one) or a hard link in
# another directory (--rotate would sweep that one) gets "the user".
mkdir -p "$S/hp-d/.handoff-tmp.AbCdEf" "$S/hp-o"; chmod 700 "$S/hp-d" "$S/hp-o"
cp "$TMPKEY" "$S/hp-d/handoff-identity.txt"; chmod 600 "$S/hp-d/handoff-identity.txt"
ln -s "$S/hp-d/handoff-identity.txt" "$S/hp-o/link.txt"; ln "$S/hp-d/handoff-identity.txt" "$S/hp-o/handoff-identity.txt"
for hp in "$S/hp-o/link.txt" "$S/hp-o/handoff-identity.txt"; do
  expect_refusal "the overwrite refusal with HANDOFF_PRIVKEY=${hp##*/} in another directory" 1 "(report them to the user, who removes them)" \
    env HANDOFF_KEY_DIR="$S/hp-d" HANDOFF_PRIVKEY="$hp" bash ../agent-setup.sh
done
rm -rf "$S/hp-d" "$S/hp-o"
# No command to paste uses printf %q's $'...' form, which dash turns into
# code: under LC_ALL=C, %q gives it for any non-ASCII path. QA's case, a
# directory é';touch PWNED #, in the no-key advice, the chmod hint (0770),
# and setup's overwrite refusal; each command runs under dash where dash is
# installed, and touches nothing.
pd="$S/"$'\xc3\xa9'"';touch PWNED #"; mkdir -p "$pd"; chmod 700 "$pd"
LC_ALL=C env HANDOFF_PRIVKEY="$pd/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
c1=$(sed -n 's/^INFO identity: no key at .* yet; \(HANDOFF_KEY_DIR=.*\) agent-setup.sh makes it$/\1/p' "$S/out")
chmod 770 "$pd"
LC_ALL=C env HANDOFF_PRIVKEY="$pd/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
c2=$(sed -n 's/.*who runs: \(chmod -- go-w .*\)$/\1/p' "$S/out")
chmod 700 "$pd"; cp "$TMPKEY" "$pd/handoff-identity.txt"; chmod 600 "$pd/handoff-identity.txt"
LC_ALL=C env HANDOFF_KEY_DIR="$pd" bash ../agent-setup.sh >/dev/null 2>"$S/err" || true
c3=$(sed -n 's/.*this is its key: \(HANDOFF_PRIVKEY=.*\) agent-setup.sh --public-key shows it.*/\1/p' "$S/err")
for c in "$c1" "$c2" "$c3"; do
  [ -n "$c" ] || fail "a command for QA's path wasn't printed: c1=$c1 c2=$c2 c3=$c3"
  case "$c" in *"\$'"*) fail "a command to paste uses the \$'...' form: $c" ;; esac
done
if command -v dash >/dev/null 2>&1; then
  (cd "$S" && dash -c "$c1 true; $c3 true; $(printf '%s' "$c2" | sed 's/^chmod -- go-w/: /')") || true
  [ ! -e "$S/PWNED" ] && [ ! -e "$pd/PWNED" ] || fail "a printed command ran code under dash"
  echo "ok (commands for a non-ASCII path with a quote run as data under dash)"
fi
rm -rf "$pd" "$S/PWNED"
echo "ok (no command to paste uses printf %q's \$'...' form)"
# Every rmdir printed for a plain path runs under dash as under bash, where
# dash is installed (--check-setup's lock line).
if command -v dash >/dev/null 2>&1; then
  qd="$S/it's \$(echo X) dir"; mkdir -p "$qd/.handoff-lock"; chmod 700 "$qd"
  env HANDOFF_PRIVKEY="$qd/handoff-identity.txt" bash ../agent-setup.sh --check-setup >"$S/out" 2>/dev/null || true
  cmd=$(sed -n 's/.*who removes the lock with: //p' "$S/out")
  [ -n "$cmd" ] || fail "no rmdir printed for a plain path under a lock: $(grep leftovers "$S/out")"
  dash -c "$cmd" || fail "the printed rmdir didn't run under dash: $cmd"
  [ ! -e "$qd/.handoff-lock" ] || fail "the printed rmdir, run under dash, didn't remove the lock: $cmd"
  rm -r "$qd"
  echo "ok (the printed rmdir runs under dash)"
fi
# A relative key directory named "-" is a directory, not cd's $OLDPWD, in
# the commands printed for the user: the overwrite refusal's lock note, and
# --rotate's lock refusal.
mkdir -p "$S/dashdir/-"; chmod 700 "$S/dashdir/-"; mkdir "$S/dashdir/-/.handoff-lock"
cp "$TMPKEY" "$S/dashdir/-/handoff-identity.txt"; chmod 600 "$S/dashdir/-/handoff-identity.txt"
dashlock="rmdir '$(cd "$S/dashdir/-" && pwd -P)/.handoff-lock'"
(cd "$S/dashdir" && expect_refusal "setup into a key directory named -" 1 "$dashlock" \
  env HANDOFF_KEY_DIR=- bash "$OLDPWD/../agent-setup.sh")
(cd "$S/dashdir" && expect_refusal "--rotate of a key in a directory named -" 1 "$dashlock" \
  env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --rotate -/handoff-identity.txt)
rm -r "$S/dashdir"
# A key directory with a control character in its path is refused before
# anything is made: the printed path could pass for other lines of output.
nlkd="$S/a"$'\n'"recipient: age1fake"
expect_refusal "setup into a key directory with a newline" 1 "has a control character in its path (a newline?); nothing was written" \
  env HANDOFF_KEY_DIR="$nlkd" bash ../agent-setup.sh
[ ! -e "$nlkd" ] || fail "setup made a key directory with a newline in its path"
! grep -q '^recipient: age1fake' "$S/err" || fail "the refusal printed the path's newline raw"
# The quoting note is matched in C: a UTF-8 path under a Latin-1 caller locale
# (whose 0x80-0x9f are control characters) gets no note.
mkdir -p "$S/日本€"; chmod 700 "$S/日本€"
env LC_ALL=en_US.ISO-8859-1 HANDOFF_KEY_DIR="$S/日本€" bash ../agent-setup.sh >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "setup into a non-ASCII directory under a Latin-1 locale failed"; }
! grep -qF "quote it in every wrapper" "$S/out" || fail "a UTF-8 path got the quoting note under a Latin-1 caller locale"
# A caller's SHELLOPTS=noclobber doesn't make --check-setup's second write
# to a scratch file fail (a false FAIL identity).
env SHELLOPTS=noclobber HANDOFF_PRIVKEY="$TMPKEY" bash ../agent-setup.sh --check-setup >"$S/out" 2>"$S/err" \
  || { cat "$S/out" "$S/err" >&2; fail "--check-setup failed under SHELLOPTS=noclobber"; }
grep -q '^PASS identity' "$S/out" || fail "--check-setup under SHELLOPTS=noclobber: $(grep identity "$S/out")"
# A caller's SHELLOPTS=noglob doesn't stop the sweep (issue #43 item 12).
mkdir -p "$S/noglob-setup"; chmod 700 "$S/noglob-setup"; mkdir "$S/noglob-setup/.handoff-tmp.QwErTy"
env SHELLOPTS=noglob HANDOFF_KEY_DIR="$S/noglob-setup" bash ../agent-setup.sh >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "first setup under SHELLOPTS=noglob failed"; }
[ ! -e "$S/noglob-setup/.handoff-tmp.QwErTy" ] || fail "first setup under SHELLOPTS=noglob didn't sweep a killed run's leftovers"
# A temporary copy that goes between the link and the check (an ln shim
# removes its source after linking) is reported as that, not trusted.
mkdir -p "$S/lnshim" "$S/gone-setup"; chmod 700 "$S/gone-setup"
# shellcheck disable=SC2016  # $@ and $2 are the shim's own, not this shell's
printf '#!/bin/sh\n%s "$@" || exit\nrm -f -- "$2"\n' "$(command -v ln)" >"$S/lnshim/ln"; chmod 755 "$S/lnshim/ln"
expect_refusal "first setup whose temporary copy goes after the link" 1 "but its temporary copy has gone (another run?): don't trust this run's recipient" \
  env PATH="$S/lnshim:$PATH" HANDOFF_KEY_DIR="$S/gone-setup" bash ../agent-setup.sh
[ -f "$S/gone-setup/handoff-identity.txt" ] || fail "the key linked before its temporary copy went isn't there"
[ -z "$(find "$S/gone-setup" -name '.handoff-*' -print)" ] || fail "setup left files after its temporary copy went: $(find "$S/gone-setup" -name '.handoff-*')"
# An existing key directory that isn't 0700 (but isn't writable by others)
# gets the note.
mkdir -p "$S/note-setup"; chmod 750 "$S/note-setup"
HANDOFF_KEY_DIR="$S/note-setup" bash ../agent-setup.sh >/dev/null 2>"$S/err" || { cat "$S/err" >&2; fail "first setup into a 0750 directory failed"; }
grep -qF "already exists; its permissions were left unchanged (setup makes it 0700)" "$S/err" || fail "first setup didn't note a 0750 key directory"
# A key path a shell reads specially gets a note to quote it, and the path is
# printed in one form, as written (issue #5 item 4).
mkdir -p "$S/q dir"; chmod 700 "$S/q dir"
HANDOFF_KEY_DIR="$S/q dir" bash ../agent-setup.sh >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "first setup into a directory with a space failed"; }
grep -qxF "this key lives at: $S/q dir/handoff-identity.txt" "$S/out" || fail "first setup didn't print the key path as written"
grep -qF "quote it in every wrapper" "$S/out" || fail "first setup didn't say to quote a path with a space"
# The temporary copy (a second hard link to the new key) is gone before setup
# prints anything about the key, not left for the EXIT trap: a sed shim (sq
# runs sed for the quoting note, after the copy's removal) records whether a
# .handoff-tmp.* is still there.
mkdir -p "$S/sedshim" "$S/early rm"; chmod 700 "$S/early rm"
# shellcheck disable=SC2016  # the shim's own variables
printf '#!/bin/sh\nfor f in "$SHIM_DIR"/.handoff-tmp.*; do [ -e "$f" ] && echo seen >>"$SHIM_LOG"; done\nexec %s "$@"\n' "$(command -v sed)" >"$S/sedshim/sed"
chmod 755 "$S/sedshim/sed"; rm -f "$S/sed-seen"
env PATH="$S/sedshim:$PATH" SHIM_DIR="$S/early rm" SHIM_LOG="$S/sed-seen" HANDOFF_KEY_DIR="$S/early rm" bash ../agent-setup.sh >"$S/out" 2>"$S/err" \
  || { cat "$S/err" >&2; fail "first setup with a sed shim failed"; }
grep -qF "quote it in every wrapper" "$S/out" || fail "the sed-shim setup printed no quoting note, so sed never ran there"
[ ! -s "$S/sed-seen" ] || fail "setup's temporary copy of the new key was still there when it printed the key path"
# The quoting it gives works for a path with a ', and a non-ASCII letter or a
# comma, which no shell reads specially, gets no note (even under LC_ALL=C).
mkdir -p "$S/it's dir"; chmod 700 "$S/it's dir"
HANDOFF_KEY_DIR="$S/it's dir" bash ../agent-setup.sh >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "first setup into a directory with a ' failed"; }
q=$(sed -n "s/^note: that path has characters a shell reads specially: quote it in every wrapper, as HANDOFF_PRIVKEY=//p" "$S/out")
[ -n "$q" ] && [ "$(sh -c "printf '%s' $q")" = "$S/it's dir/handoff-identity.txt" ] || fail "the quote note's HANDOFF_PRIVKEY= form doesn't give the path back: $q"
mkdir -p "$S/josé,x"; chmod 700 "$S/josé,x"
HANDOFF_KEY_DIR="$S/josé,x" LC_ALL=C bash ../agent-setup.sh >"$S/out" 2>"$S/err" || { cat "$S/err" >&2; fail "first setup into a non-ASCII directory failed"; }
! grep -qF "quote it in every wrapper" "$S/out" || fail "first setup said to quote a path with only a non-ASCII letter and a comma"
! grep -qF 'q\ dir' "$S/out" || fail "first setup printed the key path in a second, shell-quoted form"
# --rotate under POSIX option parsing (as BSD chmod parses): chmod -- MODE,
# through the chmod shim above (agent-setup.sh unsets POSIXLY_CORRECT).
rk env PATH="$S/posixchmod:$PATH" POSIXLY_CORRECT=1 bash ../agent-setup.sh --rotate >/dev/null 2>"$R/err" \
  || fail "--rotate failed with POSIX option parsing (BSD chmod): $(cat "$R/err")"
[ "$(stat_of %a "$KEY")" = 600 ] && [ -f "$KEY.previous" ] || fail "--rotate under POSIX option parsing left the wrong state"
# --retire also removes a temporary file that is another link to the old key
# (a setup killed between its ln and its cleanup): its data doesn't survive.
ln "$KEY.previous" "$R/.handoff-new.Linked"
# Without --yes too, as the docs say: the leftover link goes, the old key stays.
rc=0; rk bash ../agent-setup.sh --retire >/dev/null 2>"$R/err" || rc=$?
[ "$rc" = 1 ] && [ ! -e "$R/.handoff-new.Linked" ] && [ -f "$KEY.previous" ] \
  || fail "--retire without --yes and a linked leftover: exit $rc, $(cat "$R/err")"
grep -qF "another link to the previous key" "$R/err" || fail "--retire without --yes didn't report the link it removed"
# ...and its exit 1 is the missing confirmation's, not some other refusal's.
grep -qF "only once ROTATION.md step 5's last pass is recorded" "$R/err" || fail "--retire without --yes didn't ask for the confirmation: $(cat "$R/err")"
ln "$KEY.previous" "$R/.handoff-setup.Linked"
rk bash ../agent-setup.sh --retire --yes >/dev/null 2>"$R/err" || fail "--retire with a linked leftover failed: $(cat "$R/err")"
[ ! -e "$R/.handoff-setup.Linked" ] || fail "--retire left another link to the old key"
grep -qF "another link to the previous key" "$R/err" || fail "--retire didn't report the link it removed"
# KEY turning into a directory during --rotate: refused, the new key removed,
# the old key kept as .previous.
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
fake_keygen "$S/dirrot" "T='$S/dr/k.txt'"'
prev=; for a; do [ "$prev" = -o ] && { rm -f "$T" && mkdir "$T"; }; prev=$a; done'
mkdir -p "$S/dr"; cp "$TMPKEY" "$S/dr/k.txt"
expect_refusal "--rotate when the key path becomes a directory" 1 "is now a directory; the new key was removed" \
  env HANDOFF_PRIVKEY="$S/dr/k.txt" PATH="$S/dirrot:/usr/bin:/bin" bash ../agent-setup.sh --rotate
! compgen -G "$S/dr/k.txt/.handoff-*" >/dev/null || fail "a new key was left inside the directory at the key path"
! compgen -G "$S/dr/.handoff-tmp.*" >/dev/null || fail "a refused --rotate left its private temporary directory"
# The same with a relative KEY starting with "-": rm, mv and ln must read it as a path.
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
fake_keygen "$S/dirrot2" 'prev=; for a; do [ "$prev" = -o ] && { rm -f -- -k.txt && mkdir -- -k.txt; }; prev=$a; done'
mkdir -p "$S/dr2"; cp "$TMPKEY" "$S/dr2/-k.txt"
(cd "$S/dr2" && expect_refusal "--rotate when a key path starting with - becomes a directory" 1 "is now a directory; the new key was removed" \
  env -u HANDOFF_PRIVKEY PATH="$S/dirrot2:/usr/bin:/bin" bash "$OLDPWD/../agent-setup.sh" --rotate -k.txt)
# shellcheck disable=SC2015  # the || branch is the failure message, not an else
! compgen -G "$S/dr2/-k.txt/*" >/dev/null && ! compgen -G "$S/dr2/-k.txt/.handoff-*" >/dev/null || fail "a new key was left inside the directory at a key path starting with -"
! compgen -G "$S/dr2/.handoff-tmp.*" >/dev/null || fail "the dash-path run left its private temporary directory"
[ -f "$S/dr/k.txt.previous" ] || fail "the old key wasn't kept as .previous"
# A key file named like a temporary key isn't swept by its own --rotate,
# however its path is spelled (relative, or with a doubled slash).
mkdir -p "$S/spell"; cp "$TMPKEY" "$S/spell/.handoff-new.txt"
(cd "$S/spell" && env HANDOFF_PRIVKEY=.handoff-new.txt bash "$OLDPWD/../agent-setup.sh" --rotate >/dev/null 2>"$S/err") \
  || fail "--rotate of a relative .handoff-new.txt failed: $(cat "$S/err")"
[ -f "$S/spell/.handoff-new.txt" ] && [ -f "$S/spell/.handoff-new.txt.previous" ] || fail "a relative key path was swept"
(cd "$S/spell" && env HANDOFF_PRIVKEY="$S//spell//.handoff-new.txt" bash "$OLDPWD/../agent-setup.sh" --rotate >/dev/null 2>&1) || true
[ -f "$S/spell/.handoff-new.txt" ] && [ -f "$S/spell/.handoff-new.txt.previous" ] || fail "a doubled-slash key path was swept"
(cd "$S/spell" && env HANDOFF_PRIVKEY=.handoff-new.txt bash "$OLDPWD/../agent-setup.sh" --retire --yes >/dev/null 2>&1) || fail "--retire of a relative key failed"
[ -f "$S/spell/.handoff-new.txt" ] && [ ! -e "$S/spell/.handoff-new.txt.previous" ] || fail "--retire of a relative key removed the wrong file"
# The hard-link guard holds for a key path starting with -.
mkdir -p "$S/dashlink"; cp "$TMPKEY" "$S/dashlink/-k.txt"
(cd "$S/dashlink" && env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --rotate -k.txt >/dev/null 2>&1) || fail "--rotate -k.txt failed"
ln -- "$S/dashlink/-k.txt.previous" "$S/dashlink/backup.txt"
rc=0; (cd "$S/dashlink" && env -u HANDOFF_PRIVKEY bash "$OLDPWD/../agent-setup.sh" --retire --yes -k.txt >/dev/null 2>"$S/err") || rc=$?
if [ "$rc" != 1 ] || ! grep -qF "has another hard link" "$S/err"; then
  fail "--retire -k.txt with another link: exit $rc, $(cat "$S/err")"
fi
# A key path with a quote in it: the hint's paths are quoted for a POSIX shell.
mkdir -p "$S/q'; touch PWNED; echo '"; qk="$S/q'; touch PWNED; echo '/k.txt"; cp "$TMPKEY" "$qk"
env HANDOFF_PRIVKEY="$qk" bash ../agent-setup.sh --rotate >/dev/null 2>&1 || fail "--rotate on a key path with a quote failed"
ln "$qk.previous" "$S/qbackup.txt"
rc=0; env HANDOFF_PRIVKEY="$qk" bash ../agent-setup.sh --retire >/dev/null 2>"$S/qerr" || rc=$?
[ "$rc" = 1 ] || fail "--retire with a quoted path and another link: exit $rc"
hint=$(sed -n 's/.*finds the other name with: \(find .* -samefile .*\) (or, where.*/\1/p' "$S/qerr")
got=$(cd "$S" && sh -c "find() { printf '%s\n' \"\$4\"; }; $hint")
[ "$got" = "$(cd "$S" && pwd -P)/q'; touch PWNED; echo '/k.txt.previous" ] && [ ! -e "$S/PWNED" ] || fail "the find hint's path isn't quoted: $hint"
grep -qF -- "-xdev -inum $(stat_of %i "$qk.previous")" "$S/qerr" || fail "the find hint has no -inum form with the key's inode"
rm -rf "$S/q'; touch PWNED; echo '" "$S/qbackup.txt"
# A key path with a newline in it: the -inum form takes one line of digits,
# and nothing after the newline becomes a line of its own.
nl="$S/nl
touch PWNED"; mkdir -p "$nl"; cp "$TMPKEY" "$nl/k.txt"
env HANDOFF_PRIVKEY="$nl/k.txt" bash ../agent-setup.sh --rotate >/dev/null 2>&1 || fail "--rotate on a key path with a newline failed"
ln "$nl/k.txt.previous" "$S/nlbackup.txt"
rc=0; env HANDOFF_PRIVKEY="$nl/k.txt" bash ../agent-setup.sh --retire >/dev/null 2>"$S/qerr" || rc=$?
[ "$rc" = 1 ] || fail "--retire with a newline in the path and another link: exit $rc"
grep -qE -- "-xdev -inum [0-9]+, as root" "$S/qerr" || fail "the -inum hint isn't one number: $(cat "$S/qerr")"
! grep -q '^touch), as root' "$S/qerr" || fail "the -inum hint split on the newline: $(cat "$S/qerr")"
# ...and with no inode to give (an ls -di that prints nothing), it gives no
# -inum command at all, only the words for finding one.
mkdir -p "$S/nolsdi"
# shellcheck disable=SC2016  # the shim's own variables
printf '#!/bin/sh\nif [ "$1" = -di ]; then exit 0; fi\nexec %s "$@"\n' "$(command -v ls)" >"$S/nolsdi/ls"; chmod +x "$S/nolsdi/ls"
rc=0; env PATH="$S/nolsdi:$PATH" HANDOFF_PRIVKEY="$nl/k.txt" bash ../agent-setup.sh --retire >/dev/null 2>"$S/qerr" || rc=$?
[ "$rc" = 1 ] || fail "--retire with a newline in the path and no inode: exit $rc"
! grep -qF -- "-xdev -inum ," "$S/qerr" || fail "the hint gave an -inum command with no inode: $(cat "$S/qerr")"
grep -qF "with find's -inum and the old key's inode (ls -di)" "$S/qerr" || fail "the hint with no inode lost its fallback words: $(cat "$S/qerr")"
rm -rf "$S/nolsdi"
rm -rf "$nl" "$S/nlbackup.txt"
# The -inum form only with an inode that is all digits (issue #9 item 13):
# an ls -di that prints something else, or nothing, drops it, and the
# -samefile form stays.
mkdir -p "$S/badls" "$S/inum"; cp "$TMPKEY" "$S/inum/k.txt"
env HANDOFF_PRIVKEY="$S/inum/k.txt" bash ../agent-setup.sh --rotate >/dev/null 2>&1 || fail "--rotate for the -inum guard tests failed"
ln "$S/inum/k.txt.previous" "$S/inum-backup.txt"
for bad in 'x1y' ''; do
  # A shim for ls -di only: any other ls call is the real one.
  # shellcheck disable=SC2016  # the shim's own variables
  printf '#!/bin/sh\nif [ "$1" = -di ]; then [ -n "%s" ] && printf "%%s %%s\\n" "%s" "$3"; exit 0; fi\nexec %s "$@"\n' "$bad" "$bad" "$(command -v ls)" >"$S/badls/ls"
  chmod +x "$S/badls/ls"
  rc=0; env PATH="$S/badls:$PATH" HANDOFF_PRIVKEY="$S/inum/k.txt" bash ../agent-setup.sh --retire >/dev/null 2>"$S/qerr" || rc=$?
  { [ "$rc" = 1 ] && grep -qF "has another hard link" "$S/qerr"; } || fail "--retire with ls -di printing '$bad': exit $rc, $(cat "$S/qerr")"
  ! grep -q -- "-inum" "$S/qerr" || fail "the hint kept an -inum form for an inode of '$bad': $(cat "$S/qerr")"
  grep -qF -- "-xdev -samefile '$(cd "$S/inum" && pwd -P)/k.txt.previous'" "$S/qerr" || fail "the hint lost its -samefile form for an inode of '$bad': $(cat "$S/qerr")"
done
rm -rf "$S/badls" "$S/inum" "$S/inum-backup.txt"
# A relative key path still gets an absolute path in the find hint.
grep -qF -- "-samefile '$(cd "$S/dashlink" && pwd -P)/-k.txt.previous'" "$S/err" || fail "the find hint for a relative key isn't absolute: $(cat "$S/err")"
# A key file named like a temporary key isn't swept by its own --rotate.
mkdir -p "$S/tmpname"; cp "$TMPKEY" "$S/tmpname/.handoff-new.txt"
env HANDOFF_PRIVKEY="$S/tmpname/.handoff-new.txt" bash ../agent-setup.sh --rotate >/dev/null 2>"$S/err" \
  || fail "--rotate of a key named .handoff-new.txt failed: $(cat "$S/err")"
[ -f "$S/tmpname/.handoff-new.txt" ] && [ -f "$S/tmpname/.handoff-new.txt.previous" ] || fail "--rotate swept its own key"
# --retire refuses while the old key has another hard link (a backup made
# with ln): deleting .previous wouldn't remove the key data.
ln "$S/tmpname/.handoff-new.txt.previous" "$S/tmpname/backup.txt"
expect_refusal "--retire with another link to the old key" 1 "has another hard link" \
  env HANDOFF_PRIVKEY="$S/tmpname/.handoff-new.txt" bash ../agent-setup.sh --retire
[ -f "$S/tmpname/.handoff-new.txt.previous" ] || fail "a refused --retire deleted the previous key"
# The same with --yes: the guard, not the missing confirmation, keeps it.
expect_refusal "--retire --yes with another link to the old key" 1 "has another hard link" \
  env HANDOFF_PRIVKEY="$S/tmpname/.handoff-new.txt" bash ../agent-setup.sh --retire --yes
[ -f "$S/tmpname/.handoff-new.txt.previous" ] || fail "a refused --retire --yes deleted the previous key"
# The refusal says how to find the other name: find from the disk's mount point.
grep -qF -- "-xdev -samefile '$(cd "$S/tmpname" && pwd -P)/.handoff-new.txt.previous'" "$S/err" || fail "the link refusal doesn't give the find command: $(cat "$S/err")"
# It says to remove the other name, not .previous, which find lists too, and
# names .previous by the physical path find prints (issue #21 item 4).
grep -qF "removes that other name first, not '$(cd "$S/tmpname" && pwd -P)/.handoff-new.txt.previous', which the command lists too" "$S/err" \
  || fail "the link refusal doesn't name .previous as find lists it: $(cat "$S/err")"
grep -qF "(ROTATION.md: A hard-link refusal at the retire)" "$S/err" || fail "the link refusal doesn't point at ROTATION.md's rule: $(cat "$S/err")"
grep -qF "**A hard-link refusal at the retire.**" ../ROTATION.md || fail "ROTATION.md has no rule named as the link refusal says"
# Every "(ROTATION.md: <name>)" the scripts print names a bold rule there.
names=$(grep -h -o -E 'ROTATION\.md: [A-Za-z. -]+' ../agent-setup.sh ../consume.py | sed 's/^ROTATION\.md: //' | sort -u)
[ -n "$names" ] || fail "no (ROTATION.md: <name>) pointer found in the scripts"
while IFS= read -r n; do
  grep -qF "**$n.**" ../ROTATION.md || fail "the scripts point to ROTATION.md's \"$n\", which it doesn't have"
done <<EOF_NAMES
$names
EOF_NAMES
# ROTATION.md's Current-key probe counts two fixed strings of consume.py's run-mode
# lines (the checks of its real output above pin them: "decrypted with the
# previous key; rewrap it" and the whole current-key line). ROTATION.md must name the
# same strings, or the count is a false pass.
for s in "opened with the current key (a rotation is under way)" "decrypted with the previous key;"; do
  grep -qF "'$s'" ../ROTATION.md || fail "ROTATION.md's Current-key probe doesn't count: $s"
done
mnt=$(sed -n "s/.*find '\([^']*\)' -xdev.*/\1/p" "$S/err")
# Under the mount point by path, or (macOS: /var/folders is on the Data volume,
# mounted at /System/Volumes/Data and reached through a firmlink) by the same
# directory appearing beneath it.
s_real=$(cd -P "$S" && pwd)
{ case "$S/" in "${mnt%/}/"*) [ -d "$mnt" ] ;; *) false ;; esac ||
  { [ "$(uname -s)" = Darwin ] && [ -d "$mnt" ] && [ "$S" -ef "${mnt%/}$s_real" ]; }; } || fail "the link refusal's mount point ($mnt) doesn't hold the key"
rm "$S/tmpname/backup.txt"
# A find that fails is a refusal, not a pass.
mkdir -p "$S/nofind"; ln -sf "$real_keygen" "$S/nofind/age-keygen"
printf '#!/bin/sh\nexit 1\n' > "$S/nofind/find"; chmod 755 "$S/nofind/find"
expect_refusal "--retire --yes whose link check fails" 1 "couldn't check" \
  env PATH="$S/nofind:/usr/bin:/bin" HANDOFF_PRIVKEY="$S/tmpname/.handoff-new.txt" bash ../agent-setup.sh --retire --yes
[ -f "$S/tmpname/.handoff-new.txt.previous" ] || fail "--retire whose link check failed deleted the previous key"
# A mount point df reports as not absolute (a space in it, cut short) isn't
# used: the hint says where to look in words instead.
mkdir -p "$S/reldf"; ln -sf "$real_keygen" "$S/reldf/age-keygen"
printf '#!/bin/sh\necho "Filesystem 1024-blocks Used Available Capacity Mounted on"\necho "x 1 1 1 1%% ."\n' > "$S/reldf/df"; chmod 755 "$S/reldf/df"
ln "$S/tmpname/.handoff-new.txt.previous" "$S/tmpname/backup2.txt"
rc=0; env PATH="$S/reldf:/usr/bin:/bin" HANDOFF_PRIVKEY="$S/tmpname/.handoff-new.txt" bash ../agent-setup.sh --retire >/dev/null 2>"$S/qerr" || rc=$?
rm "$S/tmpname/backup2.txt"
if [ "$rc" != 1 ] || ! grep -qF "find <the mount point of its disk> -xdev" "$S/qerr"; then fail "a relative mount point from df was used in the hint: $(cat "$S/qerr")"; fi
env HANDOFF_PRIVKEY="$S/tmpname/.handoff-new.txt" bash ../agent-setup.sh --retire --yes >/dev/null 2>&1 || fail "--retire after removing the other link failed"
# A misordered flag isn't taken as KEY; the lock message gives the exact rmdir.
expect_refusal "--rotate --fingerprint" 2 "one mode at a time" \
  bash ../agent-setup.sh --rotate --fingerprint
mkdir "$S/tmpname/.handoff-lock"
expect_refusal "the lock message's rmdir" 1 "rmdir '$(cd "$S/tmpname" && pwd -P)/.handoff-lock'" \
  env HANDOFF_PRIVKEY="$S/tmpname/.handoff-new.txt" bash ../agent-setup.sh --rotate
rmdir "$S/tmpname/.handoff-lock"
echo "ok"
fi

if section 7; then
echo "== 7. nesting: \$HANDOFF_LABEL =="
out=$(consume --label example --blob-file blob-age.txt -- python3 -c '
import os
print(os.environ["HANDOFF_LABEL"])
')
[ "$out" = example ] || fail "the command didn't get HANDOFF_LABEL=example: $out"
expect_refusal "a consume.py started by another one's command" 1 "wrappers never nest" \
  consume --label example --blob-file blob-age.txt -- python3 ../consume.py --label example --check --blob-file blob-age.txt
expect_refusal "HANDOFF_LABEL set by the caller" 1 "\$HANDOFF_LABEL is set" \
  env HANDOFF_LABEL=mk-Zq9-outer python3 ../consume.py --label example --check --blob-file blob-age.txt
expect_refusal "HANDOFF_LABEL set, empty" 1 "\$HANDOFF_LABEL is set" \
  env HANDOFF_LABEL= python3 ../consume.py --label example --check --blob-file blob-age.txt
echo "ok"
fi

if section 8; then
echo "== 8. --check-setup (handoff.sh, agent-setup.sh) =="
REAL_AGE=$(command -v "$AGE")
REAL_KEYGEN=$(command -v "$AGE_KEYGEN")
C8="$S/c8"
mkdir -p "$C8/tmp"
install_handoff handoff-test.age "$C8/hd/handoff.sh"
prep_agent
# The payload the check encrypts, in the forms that must never be printed.
pay_leak() {  # FILE...
  local f
  for f in "$@"; do
    ! grep -qF -e 'pässwörd' -e '日本' -e '"svc":"check"' "$f" || fail "the check's test payload appeared in the output ($(basename "$f"))"
  done
}
# Every stdout line is a check line: PASS, INFO or FAIL, a name, a colon, a detail.
only_check_lines() {  # DESC
  if grep -qvE '^(PASS|INFO|FAIL) [a-z0-9][a-z0-9. -]*: .+' "$C8/out"; then
    cat "$C8/out" >&2; fail "$1: stdout holds something besides check lines"
  fi
  ! grep -q 'skip:' "$C8/out" || fail "$1: a skip: line"
}
# run8 DESC WANT_RC CMD...: stdin is /dev/null; leaves $C8/out and $C8/err.
run8() {
  local desc=$1 want=$2 rc=0
  shift 2
  "$@" </dev/null >"$C8/out" 2>"$C8/err" || rc=$?
  [ "$rc" = "$want" ] || { cat "$C8/out" "$C8/err" >&2; fail "$desc: exit $rc, expected $want"; }
  only_check_lines "$desc"
  pay_leak "$C8/out" "$C8/err"
  [ -z "$(ls -A "$C8/tmp")" ] || fail "$desc: the temporary directory was left behind: $(ls -A "$C8/tmp")"
}
has() {  # DESC LINE-PREFIX-REGEX: a check line matching it is in out
  grep -qE -- "^$2" "$C8/out" || { cat "$C8/out" >&2; fail "$1: no line starting '$2'"; }
}
hasnt() {
  ! grep -qE -- "^$2" "$C8/out" || { cat "$C8/out" >&2; fail "$1: unexpected line '$2'"; }
}
# A directory of symlinks to the named tools (and none other): a PATH that
# lacks one of them. mkpath DIR TOOL...
mkpath() {
  local d=$1 t p; shift
  rm -rf "$d"; mkdir -p "$d"
  for t in "$@"; do
    p=$(command -v "$t") || fail "test setup: $t is not installed here (mkpath $d)"
    ln -s "$p" "$d/$t"
  done
}
# sha256 of a file: GNU's tool, else macOS's.
sha() { sha256sum "$@" 2>/dev/null || shasum -a 256 "$@"; }
BASE_TOOLS="sleep sh tail awk base64 tr cmp sed head cat rm mkdir mktemp chmod env dirname grep uname wc ls id stat sort cut od"
# shellcheck disable=SC2086  # a deliberate word list
mkpath "$C8/p-all" $BASE_TOOLS bash jq
ln -s "$REAL_AGE" "$C8/p-all/age"; ln -s "$REAL_KEYGEN" "$C8/p-all/age-keygen"
ln -s "$PY" "$C8/p-all/python3"
P_ALL="$C8/p-all"

# --- handoff.sh -------------------------------------------------------------
H8="$C8/hd/handoff.sh"
run8 "handoff.sh --check-setup" 0 env TMPDIR="$C8/tmp" PATH="$P_ALL" "$BASH" "$H8" --check-setup
for n in bash age age-keygen jq "jq rawfile" "round trip" header base64 recipient; do
  has "handoff.sh --check-setup" "PASS $n: "
done
hasnt "handoff.sh --check-setup" "(FAIL|INFO) "
[ "$(wc -l <"$C8/out")" -eq 9 ] || { cat "$C8/out" >&2; fail "handoff.sh --check-setup: not nine lines"; }
[ ! -s "$C8/err" ] || { cat "$C8/err" >&2; fail "handoff.sh --check-setup wrote to stderr"; }
echo "ok (handoff.sh --check-setup)"
# A caller's SHELLOPTS=noclobber doesn't break the base64 -d || base64 -D
# fallback (its second write to the same file), as on a base64 with only -D.
rm -rf "$C8/p-b64"; cp -RP "$P_ALL" "$C8/p-b64"; rm "$C8/p-b64/base64"
# shellcheck disable=SC2016  # $1 and $@ are the shim's own, not this shell's
printf '#!/bin/sh\ncase "${1-}" in -d) exit 1 ;; -D) shift; exec %s -d "$@" ;; esac\nexec %s "$@"\n' \
  "$(command -v base64)" "$(command -v base64)" >"$C8/p-b64/base64"; chmod 755 "$C8/p-b64/base64"
run8 "handoff.sh --check-setup under noclobber, base64 with only -D" 0 \
  env SHELLOPTS=noclobber TMPDIR="$C8/tmp" PATH="$C8/p-b64" "$BASH" "$H8" --check-setup
has "handoff.sh --check-setup under noclobber" "PASS base64: "
has "handoff.sh --check-setup under noclobber" "PASS round trip: "
echo "ok (handoff.sh --check-setup under a caller's noclobber)"

# It reads no stdin: a stdin that never ends doesn't hold it up.
mkfifo "$C8/stdin.fifo"
exec 9<>"$C8/stdin.fifo"
rc=0; run_to env TMPDIR="$C8/tmp" PATH="$P_ALL" "$BASH" "$H8" --check-setup <&9 >"$C8/out" 2>"$C8/err" || rc=$?
exec 9<&-
[ "$rc" = 0 ] || fail "handoff.sh --check-setup waited on stdin (exit $rc)"
echo "ok (handoff.sh --check-setup does not read stdin)"

# Usage errors.
expect_refusal "--check-setup with a FILE" 2 "--check-setup takes no FILE" bash "$H8" --check-setup x.json
expect_refusal "--check-setup --fingerprint" 2 "one mode at a time" bash "$H8" --check-setup --fingerprint
expect_refusal "--fingerprint --check-setup" 2 "one mode at a time" bash "$H8" --fingerprint --check-setup
bash "$H8" --help 2>&1 | grep -q -e '--check-setup' || fail "handoff.sh --help doesn't list --check-setup"

# A missing recipient file is INFO, not a failure; another NAME picks its file.
run8 "--to NAME without a file" 0 env TMPDIR="$C8/tmp" PATH="$P_ALL" "$BASH" "$H8" --check-setup --to nosuch
has "--to nosuch" "INFO recipient: "
has "--to nosuch" "PASS round trip: "
# A bad recipient file.
printf 'age1notarecipient\n' >"$C8/hd/handoff-bad.age"
run8 "a bad recipient file" 1 env TMPDIR="$C8/tmp" PATH="$P_ALL" "$BASH" "$H8" --check-setup --to bad
has "bad recipient" "FAIL recipient: "
has "bad recipient" "PASS round trip: "
sed 's/.$/q/' handoff-test.age >"$C8/hd/handoff-bad.age"   # right shape, wrong checksum
run8 "a recipient with a bad checksum" 1 env TMPDIR="$C8/tmp" PATH="$P_ALL" "$BASH" "$H8" --check-setup --to bad
has "bad checksum" "FAIL recipient: "
# No environment variable changes a check: HANDOFF_SHAPE_ONLY (an old internal
# switch) set by the caller still gets the checksum asked.
expect_refusal "--fingerprint with HANDOFF_SHAPE_ONLY=1 and a bad checksum" 1 "not a valid age recipient" \
  env HANDOFF_SHAPE_ONLY=1 bash "$H8" --fingerprint --to bad
run8 "--check-setup with HANDOFF_SHAPE_ONLY=1 and a bad checksum" 1 env TMPDIR="$C8/tmp" PATH="$P_ALL" HANDOFF_SHAPE_ONLY=1 "$BASH" "$H8" --check-setup --to bad
has "SHAPE_ONLY" "FAIL recipient: "
hasnt "SHAPE_ONLY" "PASS recipient"
echo "ok (recipient file)"

# A PATH without age: FAIL age.
# shellcheck disable=SC2086  # a deliberate word list
mkpath "$C8/p-noage" $BASE_TOOLS bash jq age-keygen
run8 "no age" 1 env TMPDIR="$C8/tmp" PATH="$C8/p-noage" "$BASH" "$H8" --check-setup
has "no age" "FAIL age: "
hasnt "no age" "PASS (round trip|header|base64): "
has "no age" "INFO recipient: .*checksum is not checked \\(no age\\)"
hasnt "no age" "FAIL recipient"
printf 'age1notarecipient\n' >"$C8/hd/handoff-bad.age"
run8 "no age, a recipient file of the wrong shape" 1 env TMPDIR="$C8/tmp" PATH="$C8/p-noage" "$BASH" "$H8" --check-setup --to bad
has "no age, bad shape" "FAIL recipient: "
# No age-keygen: INFO, an encrypt-only round trip, header and base64 still checked.
# shellcheck disable=SC2086  # a deliberate word list
mkpath "$C8/p-nokg" $BASE_TOOLS bash jq
ln -s "$REAL_AGE" "$C8/p-nokg/age"
run8 "no age-keygen" 0 env TMPDIR="$C8/tmp" PATH="$C8/p-nokg" "$BASH" "$H8" --check-setup
has "no age-keygen" "INFO age-keygen: "
has "no age-keygen" "INFO round trip: .*decrypt skipped"
has "no age-keygen" "PASS header: "
has "no age-keygen" "PASS base64: "
# ... and with no recipient file either, there is nothing to encrypt to.
run8 "no age-keygen, no recipient file" 0 env TMPDIR="$C8/tmp" PATH="$C8/p-nokg" "$BASH" "$H8" --check-setup --to nosuch
has "no keygen, no file" "INFO round trip: "
echo "ok (age and age-keygen)"

# jq: a stub that says 1.5, one that says 1.6 and works, one whose --rawfile
# fails, and no jq.
mkdir -p "$C8/stubjq"
printf '#!/bin/sh\necho jq-1.5\n' >"$C8/stubjq/jq"; chmod 755 "$C8/stubjq/jq"
run8 "jq 1.5" 1 env TMPDIR="$C8/tmp" PATH="$C8/stubjq:$P_ALL" "$BASH" "$H8" --check-setup
has "jq 1.5" "FAIL jq: .*jq-1.5"
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
printf '#!/bin/sh\nif [ "$1" = --version ]; then echo jq-1.6; else exec %s "$@"; fi\n' "$(command -v jq)" >"$C8/stubjq/jq"
run8 "jq 1.6" 0 env TMPDIR="$C8/tmp" PATH="$C8/stubjq:$P_ALL" "$BASH" "$H8" --check-setup
has "jq 1.6" "PASS jq: jq-1.6"
# shellcheck disable=SC2016  # stub script text: it is meant to expand when the stub runs
printf '#!/bin/sh\nif [ "$1" = --version ]; then echo jq-1.6; else echo wrong; fi\n' >"$C8/stubjq/jq"
run8 "jq whose --rawfile fails" 1 env TMPDIR="$C8/tmp" PATH="$C8/stubjq:$P_ALL" "$BASH" "$H8" --check-setup
has "jq rawfile" "FAIL jq rawfile: "
# shellcheck disable=SC2086  # a deliberate word list
mkpath "$C8/p-nojq" $BASE_TOOLS bash
ln -s "$REAL_AGE" "$C8/p-nojq/age"; ln -s "$REAL_KEYGEN" "$C8/p-nojq/age-keygen"
run8 "no jq" 1 env TMPDIR="$C8/tmp" PATH="$C8/p-nojq" "$BASH" "$H8" --check-setup
has "no jq" "FAIL jq: "
echo "ok (jq)"

# An age that changes a byte of its output: FAIL round trip. One that writes a
# second stanza: FAIL header (the file still decrypts).
mkdir -p "$C8/stub-flip" "$C8/stub-two"
cat >"$C8/stub-flip/age" <<EOF
#!/bin/sh
case "\$1" in --version|-d) exec "$REAL_AGE" "\$@" ;; esac
f=\$(mktemp)
"$REAL_AGE" "\$@" >"\$f"
n=\$(wc -c <"\$f" | tr -d ' ')
last=\$(tail -c 1 "\$f" | od -An -c | tr -d ' ')
head -c \$((n - 1)) "\$f"
if [ "\$last" = X ]; then printf Y; else printf X; fi
rm -f "\$f"
EOF
cat >"$C8/stub-two/age" <<EOF
#!/bin/sh
case "\$1" in --version|-d) exec "$REAL_AGE" "\$@" ;; esac
exec "$REAL_AGE" "\$@" -r "$(cat handoff-test.age)"
EOF
mkdir -p "$C8/stub-differ"
cat >"$C8/stub-differ/age" <<EOF
#!/bin/sh
case "\$1" in -d) cat >/dev/null; printf '%s' '{"svc":"check","password":"other"}'; exit 0 ;; esac
exec "$REAL_AGE" "\$@"
EOF
chmod 755 "$C8/stub-flip/age" "$C8/stub-two/age" "$C8/stub-differ/age"
run8 "an age that flips a byte" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-flip:$P_ALL" "$BASH" "$H8" --check-setup
has "flip" "FAIL round trip: .*could not decrypt"
# A real age's MAC makes "decrypts to other bytes" unreachable, so the
# branch is pinned by an age whose decrypt returns valid but different text.
run8 "an age that decrypts to other bytes" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-differ:$P_ALL" "$BASH" "$H8" --check-setup
has "differ" "FAIL round trip: .*differ"
run8 "an age that writes a second stanza" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-two:$P_ALL" "$BASH" "$H8" --check-setup
has "second stanza" "FAIL header: "
has "second stanza" "PASS round trip: "
echo "ok (round trip, header)"

# The header rule against the vectors, through an age that writes the vector.
# Refused: every one in vectors/. Accepted: the two real blobs (the check then
# fails the decrypt, as the vector isn't for the throwaway key).
mkdir -p "$C8/stub-vec" "$C8/vec"
vec_age() {  # FILE: an age stub that writes FILE as its output
  cat >"$C8/stub-vec/age" <<EOF
#!/bin/sh
case "\$1" in --version|-d) exec "$REAL_AGE" "\$@" ;; esac
cat >/dev/null
cat "$1"
EOF
  chmod 755 "$C8/stub-vec/age"
}
for v in scrypt two-x25519 grease-only plugin-stanza pq-stanza ssh-stanza unknown-stanza armored-b64; do
  base64 -d <"vectors/$v.txt" >"$C8/vec/$v.bin"
  vec_age "$C8/vec/$v.bin"
  run8 "header vector $v" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-vec:$P_ALL" "$BASH" "$H8" --check-setup
  has "vector $v" "FAIL header: "
done
vec_age "$PWD/vectors/armored-raw.txt"
run8 "header vector armored-raw" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-vec:$P_ALL" "$BASH" "$H8" --check-setup
has "vector armored-raw" "FAIL header: "
for v in blob-age blob-age-rage; do
  base64 -d <"$v.txt" >"$C8/vec/$v.bin"
  vec_age "$C8/vec/$v.bin"
  run8 "header vector $v" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-vec:$P_ALL" "$BASH" "$H8" --check-setup
  has "vector $v" "PASS header: "
  has "vector $v" "PASS base64: "
done
# Stanza types are split on a single space, as consume.py does: two spaces,
# a tab, or a leading tab don't make an X25519 stanza.
printf 'age-encryption.org/v1\n->  X25519 abc\nAAAA\n--- abc\n' >"$C8/vec/two-spaces.bin"
printf 'age-encryption.org/v1\n-> X25519\tabc\nAAAA\n--- abc\n' >"$C8/vec/tab-after.bin"
printf 'age-encryption.org/v1\n-> \tX25519 a\nAAAA\n--- abc\n' >"$C8/vec/tab-before.bin"
for v in two-spaces tab-after tab-before; do
  vec_age "$C8/vec/$v.bin"
  run8 "header $v" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-vec:$P_ALL" "$BASH" "$H8" --check-setup
  has "$v" "FAIL header: "
done
# A header with no end line, and an empty output.
printf 'age-encryption.org/v1\n-> X25519 abc\nAAAA\n' >"$C8/vec/noend.bin"
vec_age "$C8/vec/noend.bin"
run8 "header with no end line" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-vec:$P_ALL" "$BASH" "$H8" --check-setup
has "no end line" "FAIL header: "
: >"$C8/vec/empty.bin"
vec_age "$C8/vec/empty.bin"
run8 "empty age output" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-vec:$P_ALL" "$BASH" "$H8" --check-setup
has "empty output" "FAIL (round trip|header|base64): "
echo "ok (header vectors)"

# The temporary directory is gone after a signal in the middle of a run.
interrupt_run() {  # DESC SIG CMD... : stub age sleeps; signal the run once it is in it
  local desc=$1 sig=$2
  shift 2
  mkdir -p "$C8/stub-slow"
  cat >"$C8/stub-slow/age" <<EOF
#!/bin/sh
case "\$1" in --version|-d) exec "$REAL_AGE" "\$@" ;; esac
: >"$C8/age-started"
sleep 3
exec "$REAL_AGE" "\$@"
EOF
  chmod 755 "$C8/stub-slow/age"
  rm -f "$C8/age-started"
  python3 -I - "$C8" "$sig" "$@" <<'PYEOF' || fail "$desc: the run did not end as expected"
import os, signal, subprocess, sys, time
c8, sig = sys.argv[1], sys.argv[2]
cmd = sys.argv[3:]
env = dict(os.environ, TMPDIR=c8 + "/tmp", PATH=c8 + "/stub-slow:" + c8 + "/p-all")
# A child started from a script has SIGINT ignored: restore the default.
p = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                     preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))
for _ in range(100):
    if os.path.exists(c8 + "/age-started"):
        break
    time.sleep(0.1)
else:
    p.kill()
    sys.exit("the run never reached age")
for _ in range(50):
    if os.listdir(c8 + "/tmp"):
        break
    time.sleep(0.1)
else:
    p.kill()
    out, err = p.communicate()
    sys.exit("no temporary directory in %s/tmp while the run was going (TMPDIR there; run's stderr: %r)"
             % (c8, err.decode("utf-8", "replace")[:400]))
p.send_signal(getattr(signal, sig))
out, err = p.communicate(timeout=30)
if p.returncode == 0:
    sys.exit("the interrupted run exited 0")
if os.listdir(c8 + "/tmp"):
    sys.exit("left behind: %r" % os.listdir(c8 + "/tmp"))
for blob in (out, err):
    if "pässwörd".encode() in blob or "日本".encode() in blob:
        sys.exit("payload in output")
PYEOF
}
interrupt_run "handoff.sh INT" SIGINT "$BASH" "$H8" --check-setup
interrupt_run "handoff.sh TERM" SIGTERM "$BASH" "$H8" --check-setup
echo "ok (handoff.sh: no temporary directory left after INT or TERM)"

# --- agent-setup.sh ---------------------------------------------------------
A8="$PWD/../agent-setup.sh"
AKEY="$S/agent/handoff-identity.txt"
sum_before=$(sha "$AKEY")
run8 "agent-setup.sh --check-setup" 0 env TMPDIR="$C8/tmp" PATH="$P_ALL" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
for n in age age-keygen python3 "round trip" header base64 identity; do
  has "agent-setup.sh --check-setup" "PASS $n: "
done
hasnt "agent-setup.sh --check-setup" "(FAIL|INFO) "
[ ! -s "$C8/err" ] || { cat "$C8/err" >&2; fail "agent-setup.sh --check-setup wrote to stderr"; }
[ "$sum_before" = "$(sha "$AKEY")" ] || fail "--check-setup changed the real key"
echo "ok (agent-setup.sh --check-setup)"
# The caller's own HANDOFF_BLOB and HANDOFF_LABEL don't reach the round trip's
# consume.py: a second blob source, or the nesting refusal, would fail it for
# a reason that isn't this machine's tools.
run8 "agent-setup.sh --check-setup, HANDOFF_BLOB and HANDOFF_LABEL exported" 0 \
  env TMPDIR="$C8/tmp" PATH="$P_ALL" HANDOFF_PRIVKEY="$AKEY" HANDOFF_BLOB=x HANDOFF_LABEL=other "$BASH" "$A8" --check-setup
has "HANDOFF_BLOB exported" "PASS round trip: "
hasnt "HANDOFF_BLOB exported" "(FAIL|INFO) "
echo "ok (agent-setup.sh --check-setup ignores the caller's HANDOFF_BLOB and HANDOFF_LABEL)"

exec 9<>"$C8/stdin.fifo"
rc=0; run_to env TMPDIR="$C8/tmp" PATH="$P_ALL" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup <&9 >"$C8/out" 2>"$C8/err" || rc=$?
exec 9<&-
[ "$rc" = 0 ] || fail "agent-setup.sh --check-setup waited on stdin (exit $rc)"
expect_refusal "agent-setup.sh --check-setup with an argument" 2 "usage" bash "$A8" --check-setup "$AKEY"
bash "$A8" --help 2>&1 | grep -q -e '--check-setup' || fail "agent-setup.sh --help doesn't list --check-setup"

# The real key is only read: a missing one is INFO, a loose one FAIL, a
# recipient file in its place FAIL; none is created.
run8 "no key yet" 0 env TMPDIR="$C8/tmp" PATH="$P_ALL" HANDOFF_PRIVKEY="$C8/nokey/handoff-identity.txt" "$BASH" "$A8" --check-setup
has "no key yet" "INFO identity: "
has "no key yet" "PASS round trip: "
[ ! -e "$C8/nokey" ] || fail "--check-setup made the key's directory"
cp "$AKEY" "$C8/loose.txt"; chmod 644 "$C8/loose.txt"
run8 "a loose key" 1 env TMPDIR="$C8/tmp" PATH="$P_ALL" HANDOFF_PRIVKEY="$C8/loose.txt" "$BASH" "$A8" --check-setup
has "loose key" "FAIL identity: "
! grep -q 'AGE-SECRET-KEY' "$C8/out" "$C8/err" || fail "the key was printed"
cp handoff-test.age "$C8/rcpt.txt"; chmod 600 "$C8/rcpt.txt"
run8 "a recipient in place of the key" 1 env TMPDIR="$C8/tmp" PATH="$P_ALL" HANDOFF_PRIVKEY="$C8/rcpt.txt" "$BASH" "$A8" --check-setup
has "recipient as key" "FAIL identity: "
# The default key path, with HOME as the only way to it.
mkdir -p "$C8/home"
run8 "the default key path" 0 env TMPDIR="$C8/tmp" PATH="$P_ALL" HOME="$C8/home" HANDOFF_PRIVKEY= "$BASH" "$A8" --check-setup
has "default key path" "INFO identity: "
[ ! -e "$C8/home/.config" ] || fail "--check-setup made the default key directory"
# HANDOFF_KEY_DIR alone (the documented non-default setup, without the
# wrappers' HANDOFF_PRIVKEY): a FAIL naming HANDOFF_PRIVKEY, as --fingerprint
# refuses it, never "no key yet" for a key that exists.
run8 "HANDOFF_KEY_DIR without HANDOFF_PRIVKEY" 1 env -u HANDOFF_PRIVKEY TMPDIR="$C8/tmp" PATH="$P_ALL" HOME="$C8/home" HANDOFF_KEY_DIR="${AKEY%/*}" "$BASH" "$A8" --check-setup
has "HANDOFF_KEY_DIR alone" "FAIL identity: HANDOFF_KEY_DIR applies only to generating a key; for --check-setup, set HANDOFF_PRIVKEY="
hasnt "HANDOFF_KEY_DIR alone" "INFO identity: "
has "HANDOFF_KEY_DIR alone" "PASS round trip: "
run8 "HANDOFF_KEY_DIR with HANDOFF_PRIVKEY" 0 env TMPDIR="$C8/tmp" PATH="$P_ALL" HOME="$C8/home" HANDOFF_KEY_DIR="${AKEY%/*}" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
has "HANDOFF_KEY_DIR with HANDOFF_PRIVKEY" "PASS identity: "
echo "ok (identity)"

# Missing tools and failing ones.
# shellcheck disable=SC2086  # a deliberate word list
mkpath "$C8/pa-noage" $BASE_TOOLS bash python3 age-keygen
run8 "agent: no age" 1 env TMPDIR="$C8/tmp" PATH="$C8/pa-noage" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
has "agent no age" "FAIL age: "
# shellcheck disable=SC2086  # a deliberate word list
mkpath "$C8/pa-nokg" $BASE_TOOLS bash python3 age
run8 "agent: no age-keygen" 1 env TMPDIR="$C8/tmp" PATH="$C8/pa-nokg" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
has "agent no age-keygen" "FAIL age-keygen: "
has "agent no age-keygen" "INFO identity: skipped"
# HANDOFF_KEY_DIR alone is a setup error with or without age-keygen.
run8 "agent: no age-keygen, HANDOFF_KEY_DIR alone" 1 env -u HANDOFF_PRIVKEY TMPDIR="$C8/tmp" PATH="$C8/pa-nokg" HOME="$C8/home" HANDOFF_KEY_DIR="${AKEY%/*}" "$BASH" "$A8" --check-setup
has "no age-keygen, HANDOFF_KEY_DIR alone" "FAIL identity: HANDOFF_KEY_DIR applies only to generating a key"
hasnt "no age-keygen, HANDOFF_KEY_DIR alone" "INFO identity: "
mkdir -p "$C8/stubpy"
printf '#!/bin/sh\necho 3.6\n' >"$C8/stubpy/python3"; chmod 755 "$C8/stubpy/python3"
run8 "agent: python3 3.6" 1 env TMPDIR="$C8/tmp" PATH="$C8/stubpy:$P_ALL" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
has "python3 3.6" "FAIL python3: .*3.6"
# shellcheck disable=SC2086  # a deliberate word list
mkpath "$C8/pa-nopy" $BASE_TOOLS bash
ln -s "$REAL_AGE" "$C8/pa-nopy/age"; ln -s "$REAL_KEYGEN" "$C8/pa-nopy/age-keygen"
run8 "agent: no python3" 1 env TMPDIR="$C8/tmp" PATH="$C8/pa-nopy" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
has "no python3" "FAIL python3: "
run8 "agent: an age that flips a byte" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-flip:$P_ALL" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
has "agent flip" "FAIL round trip: "
run8 "agent: an age that decrypts to other bytes" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-differ:$P_ALL" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
has "agent differ" "FAIL round trip: "
run8 "agent: an age that writes a second stanza" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-two:$P_ALL" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
has "agent second stanza" "FAIL header: "
# consume.py's header rule, through the vectors.
for v in scrypt two-x25519 grease-only plugin-stanza pq-stanza ssh-stanza unknown-stanza armored-b64; do
  vec_age "$C8/vec/$v.bin"
  run8 "agent: header vector $v" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-vec:$P_ALL" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
  has "agent vector $v" "FAIL header: "
done
for v in two-spaces tab-after tab-before; do
  vec_age "$C8/vec/$v.bin"
  run8 "agent: header $v" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-vec:$P_ALL" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
  has "agent $v" "FAIL header: "
  has "agent $v" "FAIL round trip: "
done
vec_age "$PWD/vectors/armored-raw.txt"
run8 "agent: header vector armored-raw" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-vec:$P_ALL" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
has "agent vector armored-raw" "FAIL header: "
for v in blob-age blob-age-rage; do
  vec_age "$C8/vec/$v.bin"
  run8 "agent: header vector $v" 1 env TMPDIR="$C8/tmp" PATH="$C8/stub-vec:$P_ALL" HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
  hasnt "agent vector $v" "FAIL header: "
done
echo "ok (agent-setup.sh: tools, round trip, header)"
interrupt_run "agent-setup.sh INT" SIGINT env HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
interrupt_run "agent-setup.sh TERM" SIGTERM env HANDOFF_PRIVKEY="$AKEY" "$BASH" "$A8" --check-setup
[ "$sum_before" = "$(sha "$AKEY")" ] || fail "--check-setup changed the real key"
echo "ok (agent-setup.sh: no temporary directory left after INT or TERM)"
echo "ok"
fi

[ -n "$RAN" ] || fail "no section ran"
[ -z "${HANDOFF_TEST_ONLY-}" ] || echo "ran: $RAN"
echo "ALL INTEROP CHECKS PASSED"
