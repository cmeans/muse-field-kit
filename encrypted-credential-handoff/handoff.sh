#!/bin/bash
# handoff.sh — securely pass a secret to your AI agent's machine.
#
# The plaintext never enters the chat: it is RSA-OAEP-encrypted on THIS
# machine and only the ciphertext is pasted in. The matching private key
# lives in a locked-down file on the agent's machine and never enters chat.
#
# The plaintext never touches disk in the interactive path, but it does live
# in this shell's memory while the script runs and could in principle be
# swapped out. That is the residual exposure; "shredding" is not claimed.
#
# SETUP: save the public key printed by agent-setup.sh on the agent's machine
# as handoff-<recipient>.pem in the same directory as this script (for an
# agent called muse, the default: handoff-muse.pem), and confirm the
# --fingerprint output matches the fingerprint the agent reports for its key.
# At a rotation, replace that file; this script itself never changes. The
# directory is the one in the path this script was run by, not resolved
# through a symlink: for a symlink ~/bin/handoff.sh, the key goes in ~/bin.
#
# Usage:
#   handoff.sh [--to NAME]                 # paste or type JSON, then Enter and Ctrl-D
#   handoff.sh [--to NAME] FILE            # read JSON from FILE
#   handoff.sh [--to NAME] --fingerprint   # print the key's fingerprint and exit
#   handoff.sh --help                      # print this usage and exit
# NAME (default muse) picks the key file handoff-NAME.pem beside this script.
#
# stdout is ONLY the base64 ciphertext; all prompts go to stderr, so
#   handoff.sh secrets.json > blob.txt
# yields a clean blob.
set -euo pipefail

# The caller's OPENSSL_* variables (OPENSSL_CONF, OPENSSL_MODULES, ...) are
# dropped, in any case, as consume.py does: a stray or planted openssl config
# can't load a provider into the openssl processes this script runs. This
# guards against a config, not against a caller who controls the environment
# (LD_PRELOAD would still pass): that control is a clean environment, the
# wrapper's env -i (SETUP.md step 7).
for v in $(compgen -e); do
  case "$v" in [Oo][Pp][Ee][Nn][Ss][Ss][Ll]_*) unset "$v" ;; esac
done

command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }

# Fail closed on the wrong crypto tool, the same gate as agent-setup.sh and
# consume.py: LibreSSL's pkeyutl OAEP behavior differs and is unverified for
# this protocol. (The hint leaves out wrappers: this runs in the user's shell.)
ssl_version=$(openssl version) || { echo "openssl version failed" >&2; exit 1; }
case "$ssl_version" in
  "OpenSSL 3."*|"OpenSSL 4."*) ;;
  *) echo "requires OpenSSL 3 or 4; found: ${ssl_version:-no version output}. Put one first on your PATH$(case "${OSTYPE-}" in (darwin*) printf '%s' "; on macOS, Homebrew's openssl@3" ;; esac)" >&2; exit 1 ;;
esac

usage() {
  cat >&2 <<'USAGE'
Usage:
  handoff.sh [--to NAME]                 paste or type JSON, then Enter and Ctrl-D
  handoff.sh [--to NAME] FILE            read JSON from FILE
  handoff.sh [--to NAME] --fingerprint   print the key's fingerprint and exit
  handoff.sh --help                      print this usage and exit
NAME (default muse; letters, digits, _ and -) picks the agent's public key
file, handoff-NAME.pem, in this script's directory.
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
      # The next word is the NAME; one that looks like an option is a NAME left out.
      [ $# -ge 2 ] || usage_error "--to needs a NAME"
      case "$2" in -*) usage_error "--to needs a NAME" ;; esac
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
# can't name another directory.
case "$to" in
  ''|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-]*)
    usage_error "--to NAME takes only letters, digits, _ and - (got $(printf '%q' "$to"))" ;;
esac
[ "${#to}" -le 64 ] || usage_error "--to NAME is at most 64 characters"

# --- the agent's public key, from handoff-NAME.pem beside this script ------
# The key is public: what matters is that it's the agent's (the fingerprint
# check) and that it's the only key this script can use. There's no key in
# the script and no fallback: without a usable key file, nothing is encrypted.
src=${BASH_SOURCE[0]-}
# Fed on stdin or through bash -c, the script has no path, so no directory to
# find the key in (and the working directory isn't a stand-in for it).
[ -n "$src" ] || { echo "handoff.sh: run handoff.sh by its path: its key file is found beside it" >&2; exit 1; }
case "$src" in
  */*) dir=${src%/*}; [ -n "$dir" ] || dir=/ ;;
  *) dir=. ;;
esac
case "$dir" in /*|.|./*) ;; *) dir=./$dir ;; esac   # shown as a path, never like an option
keyfile=${dir%/}/handoff-$to.pem

no_key() { echo "handoff.sh: $1" >&2; exit 1; }
if [ ! -e "$keyfile" ]; then
  [ ! -L "$keyfile" ] || no_key "$keyfile is a symlink that doesn't resolve to a file"
  no_key "no key file for recipient '$to': $keyfile doesn't exist. Save the agent's public key there (SETUP.md, setup step 3), or name another recipient with --to NAME"
fi
[ -f "$keyfile" ] || no_key "$keyfile is not a regular file"
# A large non-key file makes openssl's decoder very slow: refuse it.
size=$( { wc -c < "$keyfile"; } 2>/dev/null ) || no_key "cannot read $keyfile"
[ "$size" -le 16384 ] || no_key "$keyfile is over 16384 bytes; not a public key file"
PUBKEY=$(<"$keyfile") || no_key "cannot read $keyfile"
# A copy saved on Windows or by an editor can carry CRLF line endings or
# trailing blanks: openssl reads those, so drop them before the line checks.
PUBKEY=$(printf '%s\n' "$PUBKEY" | tr -d '\r' | sed 's/[[:blank:]]*$//')
count() { { grep -cxF -- "$1" <<<"$PUBKEY" || true; } }
if grep -qF -- 'PRIVATE KEY' <<<"$PUBKEY"; then
  no_key "$keyfile holds a private key. Only the agent's public key belongs here: delete this file now. If it's the agent's handoff key, it has left the agent's machine: treat it as leaked (README.md, Rotation, and compromise)"
fi
begins=$( { grep -cF -- '-----BEGIN ' <<<"$PUBKEY" || true; } )
if [ "$begins" != 1 ] || [ "$(count '-----BEGIN PUBLIC KEY-----')" != 1 ] \
   || [ "$(count '-----END PUBLIC KEY-----')" != 1 ]; then
  no_key "$keyfile must hold exactly one public key (one -----BEGIN PUBLIC KEY----- block), as agent-setup.sh prints it"
fi
# RSA-2048 with e = 65537 only, as agent-setup.sh and consume.py check: its
# public key in DER is 294 bytes, a fixed 33-byte header (its modulus field's
# leading 00 means exactly 2048 bits), and the exponent 65537 at the end.
der=$(printf '%s\n' "$PUBKEY" | openssl pkey -pubin -outform DER 2>/dev/null | od -An -tx1 -v | tr -d ' \n') \
  || no_key "$keyfile is not a readable public key"
case "$der" in
  30820122300d06092a864886f70d01010105000382010f003082010a0282010100*0203010001) ;;
  *) der=bad ;;
esac
[ "${#der}" -eq 588 ] || no_key "$keyfile is not an RSA-2048 public key with e = 65537, as agent-setup.sh makes"

fingerprint() {
  printf '%s\n' "$PUBKEY" | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary | openssl base64
}

if [ "$mode" = fingerprint ]; then
  # Assign first, echo second: inside an echo argument a failing pipeline
  # would be masked and the script would print the SHA-256 of empty input
  # and exit 0. As an assignment under `set -e` + pipefail, it exits 1.
  fp=$(fingerprint)
  echo "key file: $keyfile" >&2
  echo "SHA256:$fp"
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
  [ -r "$file" ] || { echo "cannot read $file" >&2; exit 1; }
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

[ -n "${SECRET_JSON//[[:space:]]/}" ] || { echo "empty, aborting" >&2; exit 1; }

# --- validate ---------------------------------------------------------
if command -v jq >/dev/null; then
  # Exactly one JSON value, an object, carrying a non-empty string "svc"
  # and only string values: `jq -e .` alone also accepts arrays, bare
  # strings, and several concatenated values, and a payload that fails the
  # consume side's binding or shape checks should fail here, early, where
  # the human can see why.
  printf '%s' "$SECRET_JSON" | jq -e -s \
    'length==1 and (.[0]|type)=="object"
     and (.[0].svc|type)=="string" and (.[0].svc|length)>0
     and (.[0]|all(.[]; type=="string"))' >/dev/null 2>&1 \
    || { echo "input must be a single JSON object with a string \"svc\" and string values only, aborting" >&2; exit 1; }
else
  echo "warning: jq not found — skipping JSON validation" >&2
fi

# RSA-2048 + OAEP(SHA-256) ceiling: 256 - 2*32 - 2 = 190 bytes.
n=$(printf '%s' "$SECRET_JSON" | wc -c)
if [ "$n" -gt 190 ]; then
  echo "payload is ${n} bytes; RSA-2048/OAEP-SHA256 max is 190 bytes." >&2
  echo "Shorten the JSON. (Larger payloads need a different, reviewed" >&2
  echo "construction — see README.md, Variations.)" >&2
  exit 1
fi

# --- encrypt (no plaintext ever touches disk) -------------------------
# Pubkey via process substitution, secret via stdin pipe.
fp=$(fingerprint)
echo "pubkey SHA256:$fp (from $keyfile)  <- compare with the fingerprint" >&2
echo "   your agent reports for its key before trusting this output" >&2
echo "--- paste everything below into chat with your agent ---" >&2
printf '%s' "$SECRET_JSON" | openssl pkeyutl -encrypt -pubin \
  -inkey <(printf '%s\n' "$PUBKEY") \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256 \
  | openssl base64 -A
echo

echo "--- end ---" >&2
