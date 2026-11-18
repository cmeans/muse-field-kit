#!/bin/bash
# handoff.sh — securely pass a secret to your AI agent's machine.
#
# The plaintext never enters the chat: it is encrypted with age (X25519) on
# THIS machine and only the ciphertext is pasted in. The matching private
# key (an age identity) lives in a locked-down file on the agent's machine
# and never enters chat.
#
# The plaintext never touches disk in the interactive path, but it does live
# in this shell's memory while the script runs and could in principle be
# swapped out. That is the residual exposure; "shredding" is not claimed.
#
# SETUP: save the recipient printed by agent-setup.sh on the agent's machine
# (one line, age1...) as handoff-<recipient>.age in the same directory as
# this script (for an agent called muse, the default: handoff-muse.age), and
# confirm the --fingerprint output matches the recipient the agent reports
# for its key. At a rotation, replace that file; this script itself never
# changes. The directory is the one in the path this script was run by, not
# resolved through a symlink: for a symlink ~/bin/handoff.sh, the file goes
# in ~/bin.
#
# Needs age and jq 1.6 or newer on PATH (README.md, "Installing age").
# handoff.sh --check-setup runs them and reports PASS, INFO or FAIL lines.
#
# Usage: handoff.sh --help (the usage() text below is the one copy).
#
# stdout is ONLY the base64 ciphertext; all prompts go to stderr, so
#   handoff.sh secrets.json > blob.txt
# yields a clean blob.
# Under zsh or sh, BASH_SOURCE and compgen don't exist: say so, rather than a
# misleading refusal further down. (First, before options sh may not have.)
[ -n "${BASH_VERSION-}" ] || { echo "handoff.sh: run it with bash (./handoff.sh, or bash handoff.sh)" >&2; exit 1; }
# Leave POSIX mode if bash was started in it (macOS's sh, POSIXLY_CORRECT or
# SHELLOPTS=posix), so the script runs the same either way.
set +o posix
set +x   # SHELLOPTS=xtrace or bash -x would print the secret
set +a   # SHELLOPTS=allexport would export the secret to every command run
set -euo pipefail
# Glob and match behavior a caller's BASHOPTS or SHELLOPTS could change
# (noglob, failglob, nullglob, nocasematch on the payload checks' case
# patterns): this script's own. The rest of a caller's shell (BASH_ENV,
# exported functions) belongs to whoever set it up: run
# `bash -p ./handoff.sh` to ignore them. noclobber (set -C) would make a
# second write to a scratch file fail, keyword (set -k) would take a word
# like a=b anywhere as an assignment, and xpg_echo would make echo read a
# path's backslashes as escapes. (onecmd, set -t, can't be undone here: bash
# exits after the first command.)
set +f
set +C
set +k
shopt -u failglob nullglob dotglob nocaseglob nocasematch extglob xpg_echo 2>/dev/null || true
# A SECRET_JSON exported by the caller would sit in every child's environment:
unset SECRET_JSON blob

# Kept equal to consume.py's MAX_KEY_FILE and agent-setup.sh's MAX_KEY_BYTES
# (a recipient file is 63 bytes; the same bound keeps the three alike):
MAX_KEY_BYTES=16384
# NAME's length cap: keeps handoff-NAME.age far under any file system's 255-byte name limit.
MAX_NAME=64
# The largest payload, in bytes, handed to age. Twin of consume.py's
# MAX_BLOB_FILE (65536 characters); a change to one changes both:
#   a blob is at most MAX_BLOB_FILE / 4 * 3 = 49152 bytes (base64: 3 bytes in 4 characters)
#   Go age's blob = 168 (version line, X25519 stanza, MAC) + 32 (payload nonce 16
#     + tag 16) + payload
#   margin for one rage grease stanza (about 200 bytes at most) = 256
#   MAX_PAYLOAD = 49152 - 168 - 32 - 256 = 48696
# run-test.sh checks this arithmetic against consume.py and a real blob.
MAX_PAYLOAD=48696

# A path in a message, quoted as the shell would (printf %q): a name with a
# newline or other control character can't pass for a line of output.
qp() { printf '%q' "$1"; }

usage() {
  cat >&2 <<'USAGE'
Usage:
  handoff.sh [--to NAME]                 paste or type JSON, then Enter and Ctrl-D
  handoff.sh [--to NAME] FILE            read JSON from FILE
  handoff.sh [--to NAME] --fingerprint   print the agent's recipient and exit
  handoff.sh [--to NAME] --check-setup   check that age and jq work on this machine
  handoff.sh --help                      print this usage and exit
NAME (default muse; up to 64 letters, digits, _ and -, not starting with -)
picks the agent's recipient file, handoff-NAME.age, in this script's
directory.
stdout is ONLY the base64 ciphertext; all prompts go to stderr.
USAGE
}
usage_error() { echo "handoff.sh: $1" >&2; usage; exit 2; }

# --- arguments ----------------------------------------------------------
to=muse
to_given=0
mode=encrypt
file_given=0
file=
# Options may come before or after FILE; after --, the next argument is FILE
# even if it starts with -.
while [ $# -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --fingerprint) [ "$mode" = encrypt ] || [ "$mode" = fingerprint ] || usage_error "one mode at a time"
                   mode=fingerprint ;;
    --check-setup) [ "$mode" = encrypt ] || [ "$mode" = check-setup ] || usage_error "one mode at a time"
                   mode=check-setup ;;
    --to=*) usage_error "write --to NAME, with a space" ;;
    --to)
      # The next word is the NAME; a long option there is a NAME left out.
      [ $# -ge 2 ] || usage_error "--to needs a NAME"
      case "$2" in --*) usage_error "--to needs a NAME" ;; esac
      [ "$to_given" = 0 ] || usage_error "--to given more than once"
      to=$2; to_given=1; shift ;;
    --)
      shift
      [ $# -le 1 ] || usage_error "at most one FILE"
      if [ $# -eq 1 ]; then
        [ "$file_given" = 0 ] || usage_error "at most one FILE"
        file=$1; file_given=1; shift
      fi
      break ;;
    -?*) usage_error "unknown option $(printf '%q' "$1")" ;;
    *)
      [ "$file_given" = 0 ] || usage_error "at most one FILE"
      file=$1; file_given=1 ;;
  esac
  shift
done
[ "$mode" = encrypt ] || [ "$file_given" = 0 ] || usage_error "--$mode takes no FILE"

# The name becomes part of a file name: plain ASCII letters, digits, _ and -
# only (listed, not ranges, which can match more in some locales), so it
# can't name another directory; not starting with -, so it never reads as an
# option.
case "$to" in
  -*) usage_error "--to NAME can't start with - (got $(printf '%q' "$to"))" ;;
  ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-]*)
    usage_error "--to NAME takes only letters, digits, _ and - (got $(printf '%q' "$to"))" ;;
esac
[ "${#to}" -le "$MAX_NAME" ] || usage_error "--to NAME is at most $MAX_NAME characters"

# --- the tools: refused here, before any prompt or file is read -------------
# age encrypts; jq checks the payload's shape (a refusal, not a warning: a
# payload that fails the consume side's checks should fail here, where the
# human can see why). Both come first, ahead of the recipient file.
if [ "$mode" = encrypt ]; then
  command -v jq >/dev/null 2>&1 \
    || { echo "handoff.sh: jq not found. Install jq 1.6 or newer (README.md, Installing age, lists it beside age)" >&2; exit 1; }
  jq_version=$(jq --version 2>/dev/null) || jq_version=
  jq_re='^jq-([0-9]+)\.([0-9]+)'
  if [[ "$jq_version" =~ $jq_re ]] \
     && { [ "${BASH_REMATCH[1]}" -gt 1 ] || { [ "${BASH_REMATCH[1]}" -eq 1 ] && [ "${BASH_REMATCH[2]}" -ge 6 ]; }; }; then
    :
  else
    echo "handoff.sh: jq 1.6 or newer is required; found ${jq_version:-no version output}. Install a newer jq (README.md, Installing age, lists it beside age)" >&2
    exit 1
  fi
fi
age_version="(not run)"
if [ "$mode" != check-setup ]; then   # --check-setup reports a missing age itself
  command -v age >/dev/null 2>&1 \
    || { echo "handoff.sh: age not found. Install it (README.md, Installing age)" >&2; exit 1; }
  # Read once, for the messages when age fails. Every age run gets an
  # environment of only PATH (never AGE_PASSPHRASE, AGEDEBUG and the like).
  age_version=$(env -i PATH="${PATH-}" age --version 2>/dev/null | head -n 1) || age_version=
  [ -n "$age_version" ] || age_version="(version unknown)"
fi

# --- --check-setup: prove the tools work on this machine, by running them -----
# One line per check on stdout (PASS, INFO or FAIL, a name, a detail), nothing
# else there; exit 0 unless a line is FAIL. No version floor is compared for
# age: it is run. The round trip uses a throwaway identity in a private
# temporary directory, removed on every exit. No prompt, no stdin, no real key.
cs_failed=0
cs_tmp=
cs_out() {  # STATUS NAME DETAIL
  local d=${3//$'\n'/ }
  printf '%s %s: %s\n' "$1" "$2" "$d"
  [ "$1" != FAIL ] || cs_failed=1
}
# consume.py's check_age_header, as an awk routine: a binary age file for
# exactly one X25519 recipient (other stanzas only "*-grease"). Prints the
# reason and nothing else when the file is refused; prints nothing when it's fine.
cs_header() {  # FILE
  LC_ALL=C awk '
    function bad(m) { print m; stop = 1; exit }
    NR == 1 {
      if ($0 == "-----BEGIN AGE ENCRYPTED FILE-----") bad("armored (ASCII) age text, not the binary format")
      if ($0 != "age-encryption.org/v1") bad("not a binary age file")
      next
    }
    $0 == "---" || substr($0, 1, 4) == "--- " { done = 1; exit }
    substr($0, 1, 3) == "-> " {
      in_stanza = 1
      kind = substr($0, 4)
      i = index(kind, " ")
      if (i) kind = substr(kind, 1, i - 1)
      if (kind == "X25519") x++
      else if (substr(kind, length(kind) - 6) != "-grease") bad("a recipient kind other than X25519")
      next
    }
    !in_stanza { bad("the header is malformed") }
    END {
      if (stop) exit
      if (!done) print "the header has no end line"
      else if (x != 1) print "expected exactly one X25519 stanza, found " (x + 0)
    }' "$1"
}
check_setup() {
  local p v rc blob rcpt="" rt="" hdr="" b64="" payload re jq_re have_age=0 have_keygen=0 have_jq=0
  local probe_rc=1 probe_info=0 probe_msg="" probe_rcpt=""
  set +e
  cs_out PASS bash "$BASH_VERSION"
  # The traps first, so no signal can fall between the folder and its cleanup.
  trap '[ -z "$cs_tmp" ] || rm -rf "$cs_tmp"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM HUP
  cs_tmp=$(mktemp -d "${TMPDIR:-/tmp}/handoff-check.XXXXXX" 2>/dev/null) && [ -d "$cs_tmp" ] \
    || { cs_tmp=; cs_out FAIL tempdir "cannot make a private temporary directory (check TMPDIR)"; exit 1; }
  chmod 700 "$cs_tmp"

  # age: found, and it runs.
  if p=$(command -v age 2>/dev/null) && [ -n "$p" ]; then
    if v=$(env -i PATH="${PATH-}" age --version </dev/null 2>/dev/null | head -n 1) && [ -n "$v" ]; then
      cs_out PASS age "$v"; have_age=1
    else
      cs_out FAIL age "found at $p, but 'age --version' did not run; reinstall age (README.md, Installing age)"
    fi
  else
    cs_out FAIL age "not found on PATH; install it (README.md, Installing age)"
  fi

  # age-keygen: the user side never needs it, so a missing one is INFO.
  if p=$(command -v age-keygen 2>/dev/null) && [ -n "$p" ]; then
    if env -i PATH="${PATH-}" age-keygen -o "$cs_tmp/id.txt" </dev/null >/dev/null 2>&1 && [ -s "$cs_tmp/id.txt" ]; then
      v=$(env -i PATH="${PATH-}" age-keygen --version </dev/null 2>/dev/null | head -n 1)
      cs_out PASS age-keygen "${v:-made a throwaway identity}"; have_keygen=1
    else
      cs_out FAIL age-keygen "found at $p, but it did not make an identity; reinstall age"
    fi
  else
    cs_out INFO age-keygen "not found; this side never needs it. The round trip below is encrypt-only (decrypt skipped)"
  fi

  # jq 1.6 or newer, and --rawfile.
  payload='{"svc":"check","password":"pässwörd-ü-日本"}'
  if command -v jq >/dev/null 2>&1; then
    v=$(jq --version </dev/null 2>/dev/null) || v=
    jq_re='^jq-([0-9]+)\.([0-9]+)'
    if [[ "$v" =~ $jq_re ]] \
       && { [ "${BASH_REMATCH[1]}" -gt 1 ] || { [ "${BASH_REMATCH[1]}" -eq 1 ] && [ "${BASH_REMATCH[2]}" -ge 6 ]; }; }; then
      cs_out PASS jq "$v"; have_jq=1
    else
      cs_out FAIL jq "jq 1.6 or newer is required; found ${v:-no version output}. Install a newer jq (README.md, Installing age)"
    fi
  else
    cs_out FAIL jq "not found. Install jq 1.6 or newer (README.md, Installing age)"
  fi
  if [ "$have_jq" = 1 ]; then
    printf '%s' "$payload" >"$cs_tmp/payload"
    if jq -j -n --rawfile p "$cs_tmp/payload" '$p' </dev/null >"$cs_tmp/jq-out" 2>/dev/null && cmp -s "$cs_tmp/payload" "$cs_tmp/jq-out"; then
      cs_out PASS "jq rawfile" "--rawfile reads a file's bytes unchanged"
    else
      cs_out FAIL "jq rawfile" "this jq's --rawfile did not return the file's bytes; install a current jq"
    fi
  fi

  # The saved recipient file, probed with this script's own --fingerprint (so
  # the one recipient check is the one the encrypt path runs).
  if [ "$nopath" = 1 ]; then
    probe_msg="no script path to find the recipient file beside; save handoff.sh to a file and run that file"
    probe_info=1
  elif [ ! -e "$keyfile" ] && [ ! -L "$keyfile" ]; then
    probe_msg="no $(qp "$keyfile") yet; save the agent's recipient there (SETUP.md, setup step 3)"
    probe_info=1
  else
    # With age: this script's own --fingerprint, in a clean environment (the
    # whole recipient check). Without: the file and its shape alone, read by
    # the same function in a subshell (the checksum needs age).
    if [ "$have_age" = 1 ]; then
      v=$(env -i PATH="${PATH-}" "$BASH" "$src" --fingerprint --to "$to" </dev/null 2>"$cs_tmp/probe-err")
    else
      v=$( (load_recipient && printf 'recipient: %s\n' "$RECIPIENT") </dev/null 2>"$cs_tmp/probe-err")
    fi
    probe_rc=$?
    probe_rcpt=$(printf '%s\n' "$v" | sed -n 's/^recipient: //p')
    probe_msg=$(head -n 1 "$cs_tmp/probe-err" 2>/dev/null)
    probe_msg=${probe_msg#handoff.sh: }
  fi

  # The round trip. With age-keygen: a throwaway recipient, encrypt as
  # handoff.sh does, decrypt with age -d -i. Without it: encrypt to the saved
  # recipient, and check the blob only.
  if [ "$have_age" = 1 ]; then
    re='^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$'
    if [ "$have_keygen" = 1 ]; then
      rcpt=$(env -i PATH="${PATH-}" age-keygen -y "$cs_tmp/id.txt" </dev/null 2>/dev/null)
      [[ "$rcpt" =~ $re ]] || { rcpt=""; rt="FAIL|age-keygen -y did not print a recipient for the throwaway identity"; }
    elif [ "$probe_rc" = 0 ] && [ -n "$probe_rcpt" ]; then
      rcpt=$probe_rcpt
    else
      rt="INFO|skipped: with no age-keygen there is no throwaway recipient, and no usable recipient file to encrypt to"
    fi
    if [ -n "$rcpt" ]; then
      # The same command handoff.sh runs.
      blob=$(printf '%s' "$payload" | env -i PATH="${PATH-}" age -r "$rcpt" 2>/dev/null | base64 | tr -d '\n')
      rc=$?
      if [ "$rc" -ne 0 ] || [ -z "$blob" ]; then
        rt="FAIL|age failed to encrypt to the recipient"
      else
        # base64: decodes (GNU and BSD spellings) and re-encodes to the same text.
        if printf '%s' "$blob" | base64 -d >"$cs_tmp/blob.bin" 2>/dev/null || printf '%s' "$blob" | base64 -D >"$cs_tmp/blob.bin" 2>/dev/null; then
          if [ "$(base64 <"$cs_tmp/blob.bin" | tr -d '\n')" = "$blob" ]; then
            b64="PASS|the blob decodes and re-encodes to itself ($(wc -c <"$cs_tmp/blob.bin" | tr -d ' ') bytes)"
          else
            b64="FAIL|base64 does not round-trip the blob here"
          fi
        else
          : >"$cs_tmp/blob.bin"
          b64="FAIL|this base64 cannot decode the blob"
        fi
        v=$(cs_header "$cs_tmp/blob.bin")
        if [ -z "$v" ]; then hdr="PASS|exactly one X25519 stanza"; else hdr="FAIL|$v"; fi
        if [ "$have_keygen" = 1 ]; then
          printf '%s' "$payload" >"$cs_tmp/expected"
          if env -i PATH="${PATH-}" age -d -i "$cs_tmp/id.txt" <"$cs_tmp/blob.bin" >"$cs_tmp/decrypted" 2>/dev/null; then
            if cmp -s "$cs_tmp/expected" "$cs_tmp/decrypted"; then
              rt="PASS|encrypted and decrypted $(wc -c <"$cs_tmp/expected" | tr -d ' ') bytes of UTF-8, unchanged"
            else
              rt="FAIL|the decrypted bytes differ from what was encrypted"
            fi
          else
            rt="FAIL|age could not decrypt what it had just encrypted"
          fi
        else
          rt="INFO|encrypt-only: decrypt skipped (no age-keygen here, so no throwaway key); the blob's header and base64 are checked"
        fi
      fi
    fi
    [ -z "$rt" ] || cs_out "${rt%%|*}" "round trip" "${rt#*|}"
    [ -z "$hdr" ] || cs_out "${hdr%%|*}" header "${hdr#*|}"
    [ -z "$b64" ] || cs_out "${b64%%|*}" base64 "${b64#*|}"
  fi

  # The recipient file, if it's saved.
  if [ "$probe_rc" = 0 ] && [ "$have_age" = 0 ]; then
    cs_out INFO recipient "$(qp "$keyfile") has the shape of an age X25519 recipient; its checksum is not checked (no age)"
  elif [ "$probe_rc" = 0 ]; then
    cs_out PASS recipient "$(qp "$keyfile") is a valid age X25519 recipient"
  elif [ "$probe_info" = 1 ]; then
    cs_out INFO recipient "$probe_msg"
  else
    cs_out FAIL recipient "${probe_msg:-the recipient check failed}"
  fi
  exit "$cs_failed"
}

# --- the agent's recipient, from handoff-NAME.age beside this script --------
# The recipient is public: what matters is that it's the agent's (the user
# compares it with what the agent reports) and that it's the only recipient
# this script can use. There's none in the script and no fallback: without a
# usable recipient file, nothing is encrypted.
src=${BASH_SOURCE[0]-}
# Fed on stdin or through bash -c, the script has no path, so no directory to
# find the file in (and the working directory isn't a stand-in for it).
nopath=0
no_path() {
  # --check-setup says so on its recipient line instead of stopping.
  if [ "$mode" = check-setup ]; then nopath=1; return 0; fi
  echo "handoff.sh: save handoff.sh to a file and run that file: its recipient file is found beside it" >&2; exit 1
}
[ -n "$src" ] || no_path
case "$src" in
  */*) dir=${src%/*}; [ -n "$dir" ] || dir=/ ;;
  *) dir=. ;;
esac
case "$dir" in /*|.|./*) ;; *) dir=./$dir ;; esac   # shown as a path, never like an option
# Run as bash <(cat handoff.sh) or bash /dev/stdin, the path is a descriptor's,
# and its directory isn't where the user keeps the file. Compared after
# resolving, so //dev/fd or /dev/./fd is caught too.
cdir=$(cd -P -- "$dir" 2>/dev/null && pwd -P) || cdir=
while case "$cdir" in //*) true ;; *) false ;; esac; do cdir=${cdir#/}; done   # bash keeps a leading //
case "$cdir" in /dev|/dev/fd|/proc/*/fd) no_path ;; esac
keyfile=${dir%/}/handoff-$to.age

no_key() { echo "handoff.sh: $1" >&2; exit 1; }
# The recipient file: found, read, and its shape checked. Sets RECIPIENT;
# a refusal is no_key (exit 1). --check-setup runs it in a subshell when
# there is no age to ask about the checksum.
load_recipient() {
  if [ ! -e "$keyfile" ]; then
    [ ! -L "$keyfile" ] || no_key "$(qp "$keyfile") is a symlink that doesn't resolve to a file"
    # A near miss beside it is named, from a short allow-list only: a _ or . in
    # place of the -, another case (handoff_muse.age, handoff-Muse.age), or an
    # editor's extra extension (handoff-muse.age.txt, handoff-muse.age.age). Anything
    # else, such as a kept old file (handoff-muse.age.old, .2025-06-01), isn't
    # offered, and the hint asks for a check, never a rename on its own.
    near=
    restore=$(shopt -p nullglob nocaseglob || true)
    shopt -s nullglob nocaseglob
    for f in "${dir%/}"/handoff[-_.]"$to".age "${dir%/}"/handoff[-_.]"$to".age.txt "${dir%/}"/handoff[-_.]"$to".age.age; do
      if [ "$f" != "$keyfile" ] && [ -f "$f" ] && [ ! -L "$f" ]; then near=${f##*/}; break; fi
    done
    eval "$restore"
    # Only NAME's case differs (--to Muse, with handoff-muse.age there): the
    # remedy is the other --to, not a rename the default run would then miss.
    nm=${near#handoff-}; nm=${nm%.age}
    lc() { printf '%s' "$1" | LC_ALL=C tr '[:upper:]' '[:lower:]'; }
    if [ -n "$near" ] && [ "$near" = "handoff-$nm.age" ] && [ "$nm" != "$to" ] && [ "$(lc "$nm")" = "$(lc "$to")" ]; then
      no_key "no recipient file for '$to': $(qp "$keyfile") doesn't exist, but $(printf '%q' "$near") does. Names are case-sensitive: did you mean --to $(printf '%q' "$nm")?"
    fi
    [ -z "$near" ] || no_key "no recipient file for '$to': $(qp "$keyfile") doesn't exist, but $(printf '%q' "$near") does. If that file is the agent's current recipient, rename it to handoff-$to.age, then compare --fingerprint with the recipient the agent reports"
    # A 0.1.0 install: the RSA public key is beside it, the age recipient isn't.
    if [ -f "${dir%/}/handoff-$to.pem" ]; then
      no_key "found handoff-$to.pem but no $(qp "$keyfile"). Version 0.2.0 uses age, not RSA keys: ask your agent for its recipient (agent-setup.sh --fingerprint prints it) and save it as handoff-$to.age beside handoff.sh"
    fi
    no_key "no recipient file for '$to': $(qp "$keyfile") doesn't exist. Save the agent's recipient there (SETUP.md, setup step 3), or name another agent with --to NAME"
  fi
  [ -f "$keyfile" ] || no_key "$(qp "$keyfile") is not a regular file"
  # One bounded read, and the size checked on what was read: a file swapped
  # after the check above can't bring back an unbounded read.
  # (The x keeps $(...) from dropping trailing newlines before they're counted,
  # and NULs, which $(...) would drop too, are counted as another byte.)
  raw=$( { LC_ALL=C head -c "$((MAX_KEY_BYTES + 1))" -- "$keyfile" | LC_ALL=C tr '\000' '\001' && printf x; } 2>/dev/null ) || no_key "cannot read $(qp "$keyfile")"
  size=$(( $(printf '%s' "$raw" | LC_ALL=C wc -c) - 1 ))
  [ "$size" -le "$MAX_KEY_BYTES" ] || no_key "$(qp "$keyfile") is over $MAX_KEY_BYTES bytes; not a recipient file"
  RECIPIENT=${raw%x}
  case "$RECIPIENT" in   # matched in place: a pipe to head -c 2 could break the writer's pipe
    $'\xff\xfe'*|$'\xfe\xff'*) no_key "$(qp "$keyfile") is saved as UTF-16: save it as UTF-8 or plain text" ;;
  esac
  RECIPIENT=${RECIPIENT#$'\xef\xbb\xbf'}   # a UTF-8 byte-order mark, as some Windows editors save
  # A copy saved on Windows or by an editor, or copied from an indented block,
  # can carry CRLF line endings, leading or trailing blanks or blank lines: drop
  # them before the checks.
  RECIPIENT=$(printf '%s\n' "$RECIPIENT" | tr -d '\r' | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//' | grep -v '^$' || true)
  # An identity (private key) here means it left the agent's machine.
  if printf '%s\n' "$RECIPIENT" | grep -q -e '^AGE-SECRET-KEY-' -e '^AGE-PLUGIN-'; then
    no_key "$(qp "$keyfile") holds a private key. Only the agent's recipient (age1...) belongs here: delete this file now. If it's the agent's identity, it has left the agent's machine: treat it as leaked (README.md, Rotation, and compromise)"
  fi
  case "$RECIPIENT" in
    ''|*$'\n'*) no_key "$(qp "$keyfile") must hold exactly one age recipient line (age1...), as agent-setup.sh prints it" ;;
  esac
  # An X25519 recipient exactly: HRP age, separator 1, then 58 lowercase
  # characters of the bech32 alphabet, 62 in all. That refuses age1pq1... and
  # age1tag1... and every plugin recipient, which also begin age1.
  recipient_re='^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$'
  [[ "$RECIPIENT" =~ $recipient_re ]] \
    || no_key "$(qp "$keyfile") is not an age X25519 recipient (age1 and 58 more lowercase characters), as agent-setup.sh prints it"
}
[ "$mode" != check-setup ] || check_setup
load_recipient
# The bech32 checksum: age itself rejects a recipient that fails it. Asked
# now, on nothing, so a mistyped file is refused before the secret is typed.
env -i PATH="${PATH-}" age -r "$RECIPIENT" </dev/null >/dev/null 2>&1 \
  || no_key "$(qp "$keyfile") is not a valid age recipient: age $age_version did not accept it. Check the file for a typo and copy it again from the agent, or check that age itself runs (age --version)"

if [ "$mode" = fingerprint ]; then
  echo "key file: $(qp "$keyfile")" >&2
  echo "recipient: $RECIPIENT"
  exit 0
fi

# --- read the secret --------------------------------------------------
# Single-line `read` is unsafe here: pasting multi-line JSON would leave the
# extra lines in the terminal input buffer, where the interactive shell would
# EXECUTE them after the script exits (password in shell + history, invisible
# because echo is off). So: file argument, or read everything up to Ctrl-D.
#
# At a terminal this uses `stty -echo` + `cat`, not `read -d ''`: bash puts
# the terminal in character mode for `read -d ''`, where Ctrl-D is just
# another byte and the script would wait forever.
#
# Every read maps a NUL byte to \001 before the $(...): a substitution drops
# NULs (with only a warning), so a raw NUL, a NUL between tokens or a BOM-less
# UTF-16 file would otherwise be encrypted shortened. \001 is a control byte,
# which no JSON text holds raw: the check after the read refuses it.
if [ "$file_given" = 1 ]; then
  [ -r "$file" ] || { echo "handoff.sh: cannot read $(qp "$file")" >&2; exit 1; }
  SECRET_JSON=$(LC_ALL=C tr '\000' '\001' <"$file")   # note: plaintext is already on disk in this path
elif [ -t 0 ]; then
  {
    echo "Paste or type the JSON, then press Enter and Ctrl-D."
    echo 'Example: {"svc": "example", "username": "u", "password": "p"}  or  {"svc": "example", "api_key_id": "k", "api_key_secret": "s"}'
    echo "(input is hidden and is not written to shell history)"
  } >&2
  tty_saved=$(stty -g)
  trap 'stty "$tty_saved"' EXIT          # always give the terminal its echo back
  trap 'exit 130' INT TERM
  stty -echo
  SECRET_JSON=$(LC_ALL=C tr '\000' '\001')
  stty "$tty_saved"
  trap - EXIT INT TERM
  echo >&2
else
  SECRET_JSON=$(LC_ALL=C tr '\000' '\001')   # piped input: no terminal to manage
fi

# A UTF-8 byte-order mark, as some Windows editors save: dropped, as
# handoff.ps1 does (consume.py would refuse the payload with one).
SECRET_JSON=${SECRET_JSON#$'\xef\xbb\xbf'}
[ -n "${SECRET_JSON//[[:space:]]/}" ] || { echo "handoff.sh: empty, aborting" >&2; exit 1; }

# --- validate ---------------------------------------------------------
bad_json() { echo "handoff.sh: input must be a single JSON object with a string \"svc\" and string values only, aborting" >&2; exit 1; }
# No raw control byte (a NUL arrives as \001, above): JSON allows only tab, LF
# and CR, and only between tokens, which jq checks next. Checked here too, in
# this shell, so it doesn't rest on each jq version's parser. The bytes are
# listed, not a range, which can match more in some locales.
ctl=$(printf '\001\002\003\004\005\006\007\010\013\014\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037')
case "$SECRET_JSON" in *["$ctl"]*) bad_json ;; esac
# UTF-8 text only, as consume.py decodes it: jq -R replaces each invalid
# byte sequence with U+FFFD, so its copy differs from the input exactly when
# the input isn't valid UTF-8. (printf is a builtin: the secret is in no
# command's arguments, and <(...) is a pipe, not a file.)
printf '%s' "$SECRET_JSON" | jq -Rjs . 2>/dev/null | cmp -s - <(printf '%s' "$SECRET_JSON") || bad_json
# Exactly one JSON value, an object, carrying a non-empty string "svc"
# and only string values: `jq -e .` alone also accepts arrays, bare
# strings, and several concatenated values. With the checks below, this
# refuses every payload consume.py would refuse for its shape or fields
# (not UTF-8, a lone surrogate, no "svc", a value that isn't a string, a
# NUL, an empty credential field, no known credential field), here, early,
# where the human can see why; only the label match is left to consume.py.
printf '%s' "$SECRET_JSON" | jq -e -s \
  'length==1 and (.[0]|type)=="object"
   and (.[0].svc|type)=="string" and (.[0].svc|length)>0
   and (.[0]|all(.[]; type=="string"))' >/dev/null 2>&1 \
  || bad_json
# No \uD800-\uDFFF escape that isn't half of a pair (a lone surrogate): jq
# accepts some (1.8 takes a lone low half), and consume.py refuses them as
# not UTF-8 text. jq has parsed the JSON, so once the escaped backslashes are
# gone every \u left starts an escape with four hex digits; the valid pairs
# go next, and any surrogate escape still there is a lone one. Bash
# patterns, so the secret stays in this shell; the hex digits are listed,
# not ranges, which can match more in some locales.
bs=\\   # one backslash
hx='[0123456789abcdefABCDEF]'
sj=${SECRET_JSON//"$bs$bs"/}
sj=${sj//"$bs"u[dD][89abAB]$hx$hx"$bs"u[dD][cdefCDEF]$hx$hx/}
case "$sj" in
  *"$bs"u[dD][89abcdefABCDEF]$hx$hx*) sj=; bad_json ;;
esac
sj=
# The fields consume.py refuses (its check_payload), on the values jq has
# parsed (a repeated key counts the last one, as in consume.py): a NUL in any
# value (\u0000; consume.py refuses one in a credential field, and a NUL
# can't go into an environment variable), an empty credential field, and no
# credential field at all. KNOWN_FIELDS is consume.py's DEFAULT_ENV_MAP's
# keys, and handoff.ps1's $KnownFields; run-test.sh checks all three agree.
# jq prints only one of four fixed words, never anything from the payload.
KNOWN_FIELDS='username password api_key_id api_key_secret token_id token_secret private_key app_id installation_id'
fields=$(printf '%s' "$SECRET_JSON" | jq -r -s --arg known "$KNOWN_FIELDS" \
  '.[0] as $p | ($known | split(" ")) as $k
   | if any($p[]; any(explode[]; . == 0)) then "nul"
     elif any($k[]; . as $f | $p[$f] == "") then "empty"
     elif any($k[]; . as $f | $p | has($f)) then "ok"
     else "none" end' 2>/dev/null) || fields=
case "$fields" in
  ok) ;;
  nul) printf '%s\n' 'handoff.sh: a value contains a NUL character (\u0000), aborting' >&2; exit 1 ;;
  empty) echo "handoff.sh: a credential field is empty, aborting" >&2; exit 1 ;;
  none) echo "handoff.sh: no known credential field (one of: ${KNOWN_FIELDS// /, }), aborting" >&2; exit 1 ;;
  *) bad_json ;;
esac

# The cap (MAX_PAYLOAD, above) keeps the blob within consume.py's limit.
# $(( )) drops the padding BSD wc (macOS) puts before the count.
n=$(( $(printf '%s' "$SECRET_JSON" | wc -c) ))
if [ "$n" -gt "$MAX_PAYLOAD" ]; then
  echo "handoff.sh: payload is ${n} bytes; the most handoff.sh sends is ${MAX_PAYLOAD} bytes." >&2
  echo "Shorten the JSON. (Larger payloads need a larger limit on both sides;" >&2
  echo "see README.md.)" >&2
  exit 1
fi

# --- encrypt (no plaintext ever touches disk) -------------------------
# The recipient is public, so it can be an argument; the secret goes in on
# stdin through a pipe, never on a command line. age writes the binary
# format; base64 makes it one line (tr drops the line breaks that some
# base64 programs add).
blob=$(printf '%s' "$SECRET_JSON" | env -i PATH="${PATH-}" age -r "$RECIPIENT" 2>/dev/null | base64 | tr -d '\n') \
  || { echo "handoff.sh: age failed to encrypt (age $age_version), aborting" >&2; exit 1; }
echo "recipient: $RECIPIENT (from $(qp "$keyfile"))  <- compare with the recipient" >&2
echo "   your agent reports for its key before trusting this output" >&2
echo "--- paste everything below into chat with $to (recipient file $(qp "$keyfile")) ---" >&2
printf '%s\n' "$blob"

echo "--- end ---" >&2
