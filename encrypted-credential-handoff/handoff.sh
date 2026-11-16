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
set -euo pipefail

# Kept equal to consume.py's MAX_KEY_FILE and agent-setup.sh's MAX_KEY_BYTES
# (a recipient file is 63 bytes; the same bound keeps the three alike):
MAX_KEY_BYTES=16384
# NAME's length cap: keeps handoff-NAME.age far under any file system's 255-byte name limit.
MAX_NAME=64
# The largest payload, in bytes, handed to age. Twin of consume.py's
# MAX_BLOB_FILE (65536 characters); Task 9 changes both together:
#   a blob is at most MAX_BLOB_FILE / 4 * 3 = 49152 bytes (base64: 3 bytes in 4 characters)
#   Go age's blob = 168 (version line, X25519 stanza, MAC) + 32 (payload nonce 16
#     + tag 16) + payload
#   margin for one rage grease stanza (about 200 bytes at most) = 256
#   MAX_PAYLOAD = 49152 - 168 - 32 - 256 = 48696
# run-test.sh checks this arithmetic against consume.py and a real blob.
MAX_PAYLOAD=48696

usage() {
  cat >&2 <<'USAGE'
Usage:
  handoff.sh [--to NAME]                 paste or type JSON, then Enter and Ctrl-D
  handoff.sh [--to NAME] FILE            read JSON from FILE
  handoff.sh [--to NAME] --fingerprint   print the agent's recipient and exit
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
    --fingerprint) mode=fingerprint ;;
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
[ "$mode" = encrypt ] || [ "$file_given" = 0 ] || usage_error "--fingerprint takes no FILE"

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
     && { [ "${BASH_REMATCH[1]}" -gt 1 ] || [ "${BASH_REMATCH[2]}" -ge 6 ]; }; then
    :
  else
    echo "handoff.sh: jq 1.6 or newer is required; found ${jq_version:-no version output}. Install a newer jq (README.md, Installing age, lists it beside age)" >&2
    exit 1
  fi
fi
command -v age >/dev/null 2>&1 \
  || { echo "handoff.sh: age not found. Install it (README.md, Installing age)" >&2; exit 1; }

# --- the agent's recipient, from handoff-NAME.age beside this script --------
# The recipient is public: what matters is that it's the agent's (the user
# compares it with what the agent reports) and that it's the only recipient
# this script can use. There's none in the script and no fallback: without a
# usable recipient file, nothing is encrypted.
src=${BASH_SOURCE[0]-}
# Fed on stdin or through bash -c, the script has no path, so no directory to
# find the file in (and the working directory isn't a stand-in for it).
no_path() { echo "handoff.sh: save handoff.sh to a file and run that file: its recipient file is found beside it" >&2; exit 1; }
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
if [ ! -e "$keyfile" ]; then
  [ ! -L "$keyfile" ] || no_key "$keyfile is a symlink that doesn't resolve to a file"
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
    no_key "no recipient file for '$to': $keyfile doesn't exist, but $(printf '%q' "$near") does. Names are case-sensitive: did you mean --to $(printf '%q' "$nm")?"
  fi
  [ -z "$near" ] || no_key "no recipient file for '$to': $keyfile doesn't exist, but $(printf '%q' "$near") does. If that file is the agent's current recipient, rename it to handoff-$to.age, then compare --fingerprint with the recipient the agent reports"
  # A 0.1.0 install: the RSA public key is beside it, the age recipient isn't.
  if [ -f "${dir%/}/handoff-$to.pem" ]; then
    no_key "found handoff-$to.pem but no $keyfile. Version 0.2.0 uses age, not RSA keys: ask your agent for its recipient (agent-setup.sh --fingerprint prints it) and save it as handoff-$to.age beside handoff.sh"
  fi
  no_key "no recipient file for '$to': $keyfile doesn't exist. Save the agent's recipient there (SETUP.md, setup step 3), or name another agent with --to NAME"
fi
[ -f "$keyfile" ] || no_key "$keyfile is not a regular file"
# One bounded read, and the size checked on what was read: a file swapped
# after the check above can't bring back an unbounded read.
# (The x keeps $(...) from dropping trailing newlines before they're counted,
# and NULs, which $(...) would drop too, are counted as another byte.)
raw=$( { LC_ALL=C head -c "$((MAX_KEY_BYTES + 1))" -- "$keyfile" | LC_ALL=C tr '\000' '\001' && printf x; } 2>/dev/null ) || no_key "cannot read $keyfile"
size=$(( $(printf '%s' "$raw" | LC_ALL=C wc -c) - 1 ))
[ "$size" -le "$MAX_KEY_BYTES" ] || no_key "$keyfile is over $MAX_KEY_BYTES bytes; not a recipient file"
RECIPIENT=${raw%x}
case "$RECIPIENT" in   # matched in place: a pipe to head -c 2 could break the writer's pipe
  $'\xff\xfe'*|$'\xfe\xff'*) no_key "$keyfile is saved as UTF-16: save it as UTF-8 or plain text" ;;
esac
RECIPIENT=${RECIPIENT#$'\xef\xbb\xbf'}   # a UTF-8 byte-order mark, as some Windows editors save
# A copy saved on Windows or by an editor, or copied from an indented block,
# can carry CRLF line endings, leading or trailing blanks or blank lines: drop
# them before the checks.
RECIPIENT=$(printf '%s\n' "$RECIPIENT" | tr -d '\r' | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//' | grep -v '^$' || true)
# An identity (private key) here means it left the agent's machine.
if printf '%s\n' "$RECIPIENT" | grep -q -e '^AGE-SECRET-KEY-' -e '^AGE-PLUGIN-'; then
  no_key "$keyfile holds a private key. Only the agent's recipient (age1...) belongs here: delete this file now. If it's the agent's identity, it has left the agent's machine: treat it as leaked (README.md, Rotation, and compromise)"
fi
case "$RECIPIENT" in
  ''|*$'\n'*) no_key "$keyfile must hold exactly one age recipient line (age1...), as agent-setup.sh prints it" ;;
esac
# An X25519 recipient exactly: HRP age, separator 1, then 58 lowercase
# characters of the bech32 alphabet, 62 in all. That refuses age1pq1... and
# age1tag1... and every plugin recipient, which also begin age1.
recipient_re='^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$'
[[ "$RECIPIENT" =~ $recipient_re ]] \
  || no_key "$keyfile is not an age X25519 recipient (age1 and 58 more lowercase characters), as agent-setup.sh prints it"
# The bech32 checksum: age itself rejects a recipient that fails it. Asked
# now, on nothing, so a mistyped file is refused before the secret is typed.
age -r "$RECIPIENT" </dev/null >/dev/null 2>&1 \
  || no_key "$keyfile is not a valid age recipient (age rejects it; check for a typo): copy it again from the agent"

if [ "$mode" = fingerprint ]; then
  echo "key file: $keyfile" >&2
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
if [ "$file_given" = 1 ]; then
  [ -r "$file" ] || { echo "handoff.sh: cannot read $file" >&2; exit 1; }
  SECRET_JSON=$(<"$file")       # note: plaintext is already on disk in this path
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
  SECRET_JSON=$(cat)
  stty "$tty_saved"
  trap - EXIT INT TERM
  echo >&2
else
  SECRET_JSON=$(cat)            # piped input: no terminal to manage
fi

[ -n "${SECRET_JSON//[[:space:]]/}" ] || { echo "handoff.sh: empty, aborting" >&2; exit 1; }

# --- validate ---------------------------------------------------------
# Exactly one JSON value, an object, carrying a non-empty string "svc"
# and only string values: `jq -e .` alone also accepts arrays, bare
# strings, and several concatenated values, and a payload that fails the
# consume side's binding or shape checks should fail here, early, where
# the human can see why.
printf '%s' "$SECRET_JSON" | jq -e -s \
  'length==1 and (.[0]|type)=="object"
   and (.[0].svc|type)=="string" and (.[0].svc|length)>0
   and (.[0]|all(.[]; type=="string"))' >/dev/null 2>&1 \
  || { echo "handoff.sh: input must be a single JSON object with a string \"svc\" and string values only, aborting" >&2; exit 1; }

# The cap (MAX_PAYLOAD, above) keeps the blob within consume.py's limit.
n=$(printf '%s' "$SECRET_JSON" | wc -c)
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
blob=$(printf '%s' "$SECRET_JSON" | age -r "$RECIPIENT" | base64 | tr -d '\n') \
  || { echo "handoff.sh: age failed to encrypt, aborting" >&2; exit 1; }
echo "recipient: $RECIPIENT (from $keyfile)  <- compare with the recipient" >&2
echo "   your agent reports for its key before trusting this output" >&2
echo "--- paste everything below into chat with $to (recipient file $keyfile) ---" >&2
printf '%s\n' "$blob"

echo "--- end ---" >&2
