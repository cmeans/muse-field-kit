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
# SETUP: replace the placeholder public key below with the one printed by
# agent-setup.sh on the agent's machine, and confirm the --fingerprint output
# matches the fingerprint the agent reports for its key.
#
# Usage:
#   handoff.sh                 # paste or type JSON, then Enter and Ctrl-D
#   handoff.sh FILE            # read JSON from FILE
#   handoff.sh --fingerprint   # print pubkey fingerprint and exit
#   handoff.sh --help          # print this usage and exit
#
# stdout is ONLY the base64 ciphertext; all prompts go to stderr, so
#   handoff.sh secrets.json > blob.txt
# yields a clean blob.
set -euo pipefail

# The caller's OPENSSL_* variables (OPENSSL_CONF, OPENSSL_MODULES, ...) are
# dropped, in any case: they could load a provider module into the openssl
# processes this script runs. consume.py does the same.
for v in $(compgen -e); do
  case "$v" in [Oo][Pp][Ee][Nn][Ss][Ss][Ll]_*) unset "$v" ;; esac
done

command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }

# Fail closed on the wrong crypto tool: LibreSSL's pkeyutl OAEP behavior
# differs and is unverified for this protocol.
ssl_version=$(openssl version)
case "$ssl_version" in
  "OpenSSL 3."*|"OpenSSL 4."*) ;;
  *) echo "requires OpenSSL 3 or 4; found: $ssl_version. Put one first on your PATH$( [ "$(uname -s)" = Darwin ] && printf '%s' "; on macOS, Homebrew's openssl@3")" >&2; exit 1 ;;
esac

# The agent's long-lived handoff public key (encryption only — safe to share).
# NOTE: `read -d ''` exits non-zero at EOF by design; `|| true` keeps
# `set -e` from killing the script here.
read -r -d '' PUBKEY <<'EOF' || true
-----BEGIN PUBLIC KEY-----
REPLACE WITH THE PUBLIC KEY PRINTED BY agent-setup.sh
-----END PUBLIC KEY-----
EOF

fingerprint() {
  printf '%s\n' "$PUBKEY" | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary | openssl base64
}

case "${1-}" in
  --help|-h)
    cat >&2 <<'USAGE'
Usage:
  handoff.sh                 paste or type JSON, then Enter and Ctrl-D
  handoff.sh FILE            read JSON from FILE
  handoff.sh --fingerprint   print pubkey fingerprint and exit
  handoff.sh --help          print this usage and exit
stdout is ONLY the base64 ciphertext; all prompts go to stderr.
USAGE
    exit 0
    ;;
esac

if [ "${1-}" = "--fingerprint" ]; then
  # Assign first, echo second: if the embedded key is a placeholder or
  # damaged, `openssl pkey` fails — inside an echo argument that failure
  # would be masked and the script would print the SHA-256 of empty input
  # and exit 0. As an assignment under `set -e` + pipefail, it exits 1.
  fp=$(fingerprint)
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
if [ $# -ge 1 ]; then
  [ -r "$1" ] || { echo "cannot read $1" >&2; exit 1; }
  SECRET_JSON=$(<"$1")          # note: plaintext is already on disk in this path
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
echo "pubkey SHA256:$fp  <- compare with the fingerprint" >&2
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
