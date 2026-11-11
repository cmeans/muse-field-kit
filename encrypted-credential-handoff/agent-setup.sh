#!/bin/bash
# agent-setup.sh — run ONCE on the agent's machine (the computer that will
# decrypt the blobs, e.g. your Muse's VM).
#
# Generates an RSA-2048 keypair for the encrypted credential handoff:
#   private key: ~/.config/handoff/handoff-priv.pem  (mode 0600, NEVER shared)
#   public key:  printed at the end, for embedding in handoff.sh
# Also prints the public key's SHA-256 fingerprint, which the human compares
# before trusting any blob, and the consume-side key path to configure.
#
# Usage:
#   agent-setup.sh                      generate a new keypair
#   agent-setup.sh --fingerprint [KEY]  print an existing key's fingerprint
#
# Environment:
#   HANDOFF_KEY_DIR  where a NEW key is generated (default ~/.config/handoff);
#                    rotation points this at a fresh directory.
#   HANDOFF_PRIVKEY  which EXISTING key --fingerprint reads: the same variable,
#                    with the same default (~/.config/handoff/handoff-priv.pem),
#                    that consume.py decrypts with. HANDOFF_KEY_DIR doesn't
#                    change it. A KEY argument overrides it.
set -euo pipefail
umask 077

[ -n "${HOME-}" ] || { echo "agent-setup.sh: HOME is not set" >&2; exit 1; }

# The one default, the same as consume.py's.
DEFAULT_DIR="$HOME/.config/handoff"
DEFAULT_PRIV="$DEFAULT_DIR/handoff-priv.pem"

# Expand a leading ~/ (an MCP client's JSON env passes it literally) and
# refuse ~user, exactly as consume.py does, so the two never disagree.
expand_home() {  # PATH WHAT
  # shellcheck disable=SC2088  # matching a literal ~ is the point
  case "$1" in
    "~"|"~/"*) printf '%s\n' "$HOME${1#\~}" ;;
    "~"*) echo "agent-setup.sh: $2 '$1': only ~/ is expanded, not ~user; use an absolute path" >&2
          return 1 ;;
    *) printf '%s\n' "$1" ;;
  esac
}

KEY_DIR=$(expand_home "${HANDOFF_KEY_DIR:-$DEFAULT_DIR}" HANDOFF_KEY_DIR) || exit 1
PRIV="$KEY_DIR/handoff-priv.pem"

command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }

# openssl's stderr stays visible: when the key can't be read, the cause
# (permissions, a passphrase, a damaged file) is what the human needs.
fingerprint_of() {
  local pub
  # First stage on its own: if the file isn't a readable private key, its
  # error is the one that matters, without a second one from the next stage.
  pub=$(openssl pkey -in "$1" -pubout) || return 1
  printf '%s\n' "$pub" | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary | openssl base64
}

# Recompute the fingerprint of an EXISTING key, e.g. at comparison time.
# The setup and SETUP.md rules require the fingerprint to come from the
# key file itself, never from notes, and forbid the agent reading the key
# with general-purpose tools: this mode is the sanctioned path. It reads
# the key the consume side uses ($HANDOFF_PRIVKEY), and says which file it
# read, so that during rotation the old key can't be reported by mistake.
case "${1-}" in
  --fingerprint)
    [ $# -le 2 ] || { echo "usage: agent-setup.sh --fingerprint [KEY]" >&2; exit 2; }
    if [ $# -eq 2 ] && [ -z "$2" ]; then
      echo "agent-setup.sh: --fingerprint was given an empty KEY" >&2; exit 2
    fi
    what=HANDOFF_PRIVKEY; [ $# -lt 2 ] || what=KEY
    key=$(expand_home "${2:-${HANDOFF_PRIVKEY:-$DEFAULT_PRIV}}" "$what") || exit 1
    [ -f "$key" ] || { echo "no key file at $key" >&2; exit 1; }
    fp=$(fingerprint_of "$key") || { echo "could not read key at $key" >&2; exit 1; }
    echo "key file: $key" >&2
    echo "SHA256:$fp"
    exit 0
    ;;
  "") ;;
  *)
    # Anything else (--help, a typo of --fingerprint) must not fall through
    # to generating a key.
    echo "usage: agent-setup.sh                      generate a new keypair" >&2
    echo "       agent-setup.sh --fingerprint [KEY]  print an existing key's fingerprint" >&2
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then exit 0; fi
    exit 2
    ;;
esac

if [ -e "$PRIV" ]; then
  echo "refusing to overwrite existing key: $PRIV" >&2
  echo "for rotation, set HANDOFF_KEY_DIR to a fresh directory instead" >&2
  exit 1
fi

# Only chmod a directory this script created: if the user pointed
# HANDOFF_KEY_DIR at an existing directory by mistake, silently tightening
# its permissions would be a nasty surprise. Say so when that happens.
if [ -d "$KEY_DIR" ]; then
  echo "note: key directory $KEY_DIR already exists; its permissions were left unchanged (expected 0700)" >&2
else
  mkdir -p "$KEY_DIR"
  chmod 700 "$KEY_DIR"
fi
# An absolute path from here on: the path printed below is what wrappers
# set HANDOFF_PRIVKEY to, from whatever directory they run in.
KEY_DIR=$(cd "$KEY_DIR" && pwd)
PRIV="$KEY_DIR/handoff-priv.pem"

# No stderr suppression: if key generation fails, the human needs the cause.
# Remove any partial file a failed run leaves behind.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$PRIV" \
  || { rm -f "$PRIV"; echo "key generation failed" >&2; exit 1; }
chmod 600 "$PRIV"

PUB=$(openssl pkey -in "$PRIV" -pubout) \
  || { echo "could not derive the public key" >&2; exit 1; }
FPR=$(printf '%s\n' "$PUB" | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary | openssl base64)

echo "private key written to $PRIV (mode 600) — never copy it off this machine"
echo
echo "public key fingerprint: SHA256:$FPR"
echo "report this fingerprint to the human; they compare it with handoff.sh's output"
echo
echo "embed this public key in handoff.sh:"
echo
printf '%s\n' "$PUB"
echo
echo "consume side: the decrypt helper reads \$HANDOFF_PRIVKEY"
echo "(default ~/.config/handoff/handoff-priv.pem)."
echo "this key lives at: $PRIV"
if [ "$PRIV" != "$DEFAULT_PRIV" ]; then
  echo "non-default location: set HANDOFF_PRIVKEY=$PRIV wherever the helper runs"
fi
