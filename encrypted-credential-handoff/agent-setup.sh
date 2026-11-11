#!/bin/bash
# agent-setup.sh — run ONCE on the agent's machine (the computer that will
# decrypt the blobs, e.g. your Muse's VM).
#
# Generates an RSA-2048 keypair for the encrypted credential handoff:
#   private key: ~/.config/handoff/handoff-priv.pem  (mode 0600, NEVER shared)
#   public key:  printed at the end, for embedding in handoff.sh
# Also prints the public key's SHA-256 fingerprint, which the human compares
# before trusting any blob, and the consume-side key path to configure.
set -euo pipefail
umask 077

KEY_DIR="${HANDOFF_KEY_DIR:-$HOME/.config/handoff}"
PRIV="$KEY_DIR/handoff-priv.pem"

command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }

fingerprint_of() {
  openssl pkey -in "$PRIV" -pubout 2>/dev/null \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary | openssl base64
}

# Recompute the fingerprint of an EXISTING key, e.g. at comparison time.
# The setup and SETUP.md rules require the fingerprint to come from the
# key file itself, never from notes, and forbid the agent reading the key
# with general-purpose tools: this mode is the sanctioned path.
if [ "${1-}" = "--fingerprint" ]; then
  [ -r "$PRIV" ] || { echo "no key at $PRIV" >&2; exit 1; }
  fp=$(fingerprint_of) || { echo "could not read key at $PRIV" >&2; exit 1; }
  echo "SHA256:$fp"
  exit 0
fi

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
if [ "$PRIV" != "$HOME/.config/handoff/handoff-priv.pem" ]; then
  echo "non-default location: set HANDOFF_PRIVKEY=$PRIV wherever the helper runs"
fi
