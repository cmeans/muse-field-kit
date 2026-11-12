#!/bin/bash
# agent-setup.sh — run on the agent's machine (the computer that will
# decrypt the blobs, e.g. your Muse's VM): once to make the keypair, and
# again for fingerprints and rotations.
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
#   agent-setup.sh --public-key [KEY]   print an existing key's public key and
#                                       fingerprint again (to give the user)
#   agent-setup.sh --rotate [KEY]       start a rotation: a new key at KEY,
#                                       the old one kept as KEY.previous;
#                                       during one, shows the new key again
#   agent-setup.sh --retire [KEY]       end a rotation: delete KEY.previous;
#                                       blobs still made for it stop opening
# Exit codes: 0 done (or, for --rotate during a rotation, shown), 1 refused
# or failed (the reason on stderr), 2 a usage error.
#
# Environment:
#   HANDOFF_KEY_DIR  where a NEW key is generated (default ~/.config/handoff).
#   HANDOFF_PRIVKEY  which EXISTING key --fingerprint, --public-key, --rotate
#                    and --retire use: the same variable, with the same default
#                    (~/.config/handoff/handoff-priv.pem), that consume.py
#                    decrypts with. HANDOFF_KEY_DIR doesn't change it. A KEY
#                    argument overrides it.
set -euo pipefail
umask 077
# cd must never search the caller's CDPATH for a relative key directory.
unset CDPATH
# This run's temporary key and lock (cleanup removes them, except after a
# SIGKILL; the next run removes a key left behind): never inherited.
new=""
lock=""

# The caller's OPENSSL_* variables (OPENSSL_CONF, OPENSSL_MODULES, ...) are
# dropped, in any case, as consume.py does: a stray or planted openssl config
# can't load a provider into the openssl processes this script runs. This
# guards against a config, not against a caller who controls the environment
# (LD_PRELOAD would still pass): that control is a clean environment, the
# wrapper's env -i (SETUP.md step 7).
for v in $(compgen -e); do
  case "$v" in [Oo][Pp][Ee][Nn][Ss][Ss][Ll]_*) unset "$v" ;; esac
done

# HOME is needed only for the default paths and for a leading ~: an absolute
# HANDOFF_KEY_DIR, HANDOFF_PRIVKEY or KEY works without it, as in consume.py.
need_home() {  # WHAT
  [ -n "${HOME-}" ] || { echo "agent-setup.sh: HOME is not set, and $1 needs it; set HOME or use an absolute path" >&2; exit 1; }
}

# The one default, the same as consume.py's.
# HOME is normalized as KEY_DIR is below (a trailing slash, a symlink), so
# the default compares equal to itself in the "non-default location" check.
default_dir() {
  need_home "the default key directory"
  local h
  h=$(cd -- "$HOME" 2>/dev/null && pwd) || h=$HOME
  printf '%s\n' "$h/.config/handoff"
}

# Expand a leading ~/ (an MCP client's JSON env passes it literally) and
# refuse ~user, exactly as consume.py does, so the two never disagree.
expand_home() {  # PATH WHAT
  # shellcheck disable=SC2088  # matching a literal ~ is the point
  case "$1" in
    "~"|"~/"*) need_home "a ~ in $2"; printf '%s\n' "$HOME${1#\~}" ;;
    "~"*) echo "agent-setup.sh: $2 '$1': only ~/ is expanded, not ~user; use an absolute path" >&2
          return 1 ;;
    *) printf '%s\n' "$1" ;;
  esac
}

# The same gate as handoff.sh and consume.py, and the same hint as consume.py
# (handoff.sh's leaves out wrappers): LibreSSL is
# unverified here.
need_openssl() {
  command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }
  local v
  v=$(openssl version) || { echo "openssl version failed" >&2; exit 1; }
  case "$v" in
    "OpenSSL 3."*|"OpenSSL 4."*) ;;
    *) echo "requires OpenSSL 3 or 4; found: ${v:-no version output}. Put one first in the PATH this runs with (in a wrapper, its PATH= line)$(case "${OSTYPE-}" in (darwin*) printf '%s' "; on macOS, Homebrew's openssl@3" ;; esac)" >&2; exit 1 ;;
  esac
}

# openssl's stderr stays visible: when the key can't be read, the cause
# (permissions, a passphrase, a damaged file) is what the human needs.
fingerprint_of() {
  local pub
  # First stage on its own: if the file isn't a readable private key, its
  # error is the one that matters, without a second one from the next stage.
  # -passin pass:: an encrypted key fails instead of prompting for a passphrase.
  pub=$(openssl pkey -in "$1" -passin pass: -pubout) || return 1
  # RSA-2048 with e = 65537 only, as consume.py checks: its public key in DER
  # is 294 bytes, a fixed 33-byte header (its modulus field's leading 00 means
  # exactly 2048 bits), and the exponent 65537 at the end. Returns 2 for a key
  # of another type.
  local der
  # A failing openssl here is "could not read", not "another key type".
  der=$(printf '%s\n' "$pub" | openssl pkey -pubin -outform DER | od -An -tx1 -v | tr -d ' \n') || return 1
  case "$der" in
    30820122300d06092a864886f70d01010105000382010f003082010a0282010100*0203010001) ;;
    *) der=bad ;;
  esac
  if [ "${#der}" -ne 588 ]; then
    echo "agent-setup.sh: the key at $1 is not an RSA-2048 key; this protocol uses RSA-2048 keys with e = 65537 (as this script makes)" >&2
    return 2
  fi
  printf '%s\n' "$pub" | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary | openssl base64
}

# The key the consume side uses: KEY if given, else $HANDOFF_PRIVKEY, else
# the default. Sets $key.
resolve_key() {  # [KEY]
  if [ $# -eq 1 ]; then
    key=$(expand_home "$1" KEY) || exit 1
  elif [ -n "${HANDOFF_PRIVKEY-}" ]; then
    key=$(expand_home "$HANDOFF_PRIVKEY" HANDOFF_PRIVKEY) || exit 1
  else
    key="$(default_dir)/handoff-priv.pem" || exit 1
  fi
}

# The fingerprint of an existing key file, refusing what isn't a usable
# RSA-2048 key. Sets $fp.
key_fingerprint() {  # FILE
  [ -f "$1" ] || { echo "no key file at $1" >&2; exit 1; }
  # A large non-key file makes openssl's decoder very slow: refuse it.
  local size rc=0
  size=$( { wc -c < "$1"; } 2>/dev/null ) || { echo "cannot read key file at $1" >&2; exit 1; }
  [ "$size" -le 16384 ] || { echo "key file at $1 is over 16384 bytes; not an RSA-2048 key file" >&2; exit 1; }
  fp=$(fingerprint_of "$1") || rc=$?
  if [ "$rc" -ne 0 ]; then
    # 2: read, but not an RSA-2048 key (already said); else unreadable.
    [ "$rc" -eq 2 ] || echo "could not read key at $1" >&2
    exit 1
  fi
}

# --rotate and --retire act on the names KEY and KEY.previous: through a
# symlink, the hard link and rename would act on the link, not the key file
# (leaving the new key off the volume the link points to, and the old key on
# it after --retire). Refuse, and have the path name the file itself.
no_symlinks() {
  local p
  for p in "$key" "$prev"; do
    if [ -L "$p" ]; then
      echo "agent-setup.sh: $p is a symlink; set HANDOFF_PRIVKEY (or KEY) to the key file itself, not a link to it" >&2
      exit 1
    fi
  done
}

# The fingerprint of FILE, or nothing (and the reason on stderr) if it isn't
# a usable key: key_fingerprint in a subshell, so its exit doesn't end this one.
fingerprint_or_fail() {  # FILE
  ( key_fingerprint "$1" && printf '%s' "$fp" )
}

# One --rotate or --retire at a time per key directory: a portable lock
# (mkdir is atomic everywhere; flock isn't on macOS). An interrupted run
# that couldn't remove it says so on the next run.
lock_dir() {  # DIR
  local l="$1/.handoff-lock" err
  if ! err=$(mkdir -- "$l" 2>&1); then
    if [ -e "$l" ]; then
      echo "agent-setup.sh: another --rotate or --retire is running ($l exists)." >&2
      echo "Stop and report it to the user: if no run is going (one was killed), they remove that directory." >&2
    else
      echo "agent-setup.sh: cannot create the lock in $1: $err" >&2
    fi
    exit 1
  fi
  lock=$l  # only once it's ours, so cleanup never removes another run's
}

# Run on any exit: removes this run's lock and temporary key. Both start
# empty at the top of the script, so a caller's environment can't name them.
cleanup() {
  [ -z "${new-}" ] || rm -f -- "$new"
  [ -z "${lock-}" ] || rmdir -- "$lock" 2>/dev/null || true
}

usage() {
  echo "usage: agent-setup.sh                      generate a new keypair (once, at setup)" >&2
  echo "       agent-setup.sh --fingerprint [KEY]  print an existing key's fingerprint" >&2
  echo "       agent-setup.sh --public-key [KEY]   print an existing key's public key and fingerprint" >&2
  echo "       agent-setup.sh --rotate [KEY]       start a rotation: a new key at KEY, the old one kept as KEY.previous;" >&2
  echo "                                           during one, shows the new key again (exit 0)" >&2
  echo "       agent-setup.sh --retire [KEY]       end a rotation: delete KEY.previous (blobs still made for it stop opening)" >&2
}

# Recompute the fingerprint of an EXISTING key, e.g. at comparison time.
# The setup and SETUP.md rules require the fingerprint to come from the
# key file itself, never from notes, and forbid the agent reading the key
# with general-purpose tools: this mode is the sanctioned path. It reads
# the key the consume side uses ($HANDOFF_PRIVKEY), and says which file it
# read, so that during rotation the old key can't be reported by mistake.
case "${1-}" in
  --fingerprint|--public-key|--rotate|--retire)
    mode=$1
    [ $# -le 2 ] || { echo "usage: agent-setup.sh $mode [KEY]" >&2; exit 2; }
    if [ $# -eq 2 ] && [ -z "$2" ]; then
      echo "agent-setup.sh: $mode was given an empty KEY" >&2; exit 2
    fi
    need_openssl
    shift
    resolve_key "$@"
    ;;
  "") mode=generate ;;
  *)
    # Anything else (--help, a typo of --fingerprint) must not fall through
    # to generating a key.
    usage
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then exit 0; fi
    exit 2
    ;;
esac

case "$mode" in
  --fingerprint)
    key_fingerprint "$key"
    echo "key file: $key" >&2
    echo "SHA256:$fp"
    exit 0
    ;;
  --rotate)
    # The current key becomes KEY.previous (consume.py tries it when the
    # current key can't open a blob) and a new key takes KEY's place, so
    # wrappers keep their HANDOFF_PRIVKEY. Each step is atomic, and a
    # re-run after an interruption finishes the job:
    #   1. KEY.previous is a hard link to KEY (ln refuses to replace one);
    #   2. the new key, written and checked beside KEY, is renamed over KEY.
    # Between the two, both names hold the old key, and everything decrypts.
    # Which state a rotation is in is read from the keys' fingerprints, not
    # their inodes, so a copied .previous (a backup restore) reads the same.
    prev="$key.previous"
    no_symlinks
    [ -f "$key" ] || { echo "no key file at $key" >&2; exit 1; }
    dir=$(dirname -- "$key")
    # The lock first, then the state: a run that read the key before another
    # finished would otherwise take that run's new key for its own old one.
    trap cleanup EXIT
    # A TERM, HUP or INT ends the run through cleanup, after the running
    # openssl exits (see first-time generation below).
    trap 'exit 1' INT TERM HUP
    lock_dir "$dir"
    key_fingerprint "$key"
    for f in "$dir"/.handoff-new.*; do
      # A temporary key a killed --rotate left (the lock says none is running).
      [ -e "$f" ] || [ -L "$f" ] || continue
      if [ ! -f "$f" ] || [ -L "$f" ]; then
        echo "agent-setup.sh: $f is not a temporary key file; report it to the user" >&2; exit 1
      fi
      rm -f -- "$f"
      echo "note: removed a temporary key a killed --rotate left behind: $f" >&2
    done
    if [ -e "$prev" ]; then
      [ -f "$prev" ] || { echo "agent-setup.sh: $prev is not a regular file; report it to the user" >&2; exit 1; }
      prev_fp=$(fingerprint_or_fail "$prev") || exit 1
      if [ "$prev_fp" != "$fp" ]; then
        # The new key is in place: show its public half again, since an
        # interruption may have come before the user got it (SETUP step 3).
        PUB=$(openssl pkey -in "$key" -passin pass: -pubout) \
          || { echo "could not derive the public key" >&2; exit 1; }
        echo "agent-setup.sh: a rotation is under way ($prev is the old key), and the new key is in place: nothing rotated." >&2
        echo "If the user hasn't embedded this key in handoff.sh and confirmed its fingerprint, continue at SETUP.md Rotation step 3; else step 4." >&2
        echo "current (new) public key fingerprint: SHA256:$fp"
        echo
        printf '%s\n' "$PUB"
        exit 0
      fi
      echo "note: resuming an interrupted rotation ($prev holds the current key)" >&2
    else
      ln -- "$key" "$prev" || { echo "agent-setup.sh: could not keep the old key as $prev" >&2; exit 1; }
    fi
    new=$(mktemp -- "$dir/.handoff-new.XXXXXX") || { echo "agent-setup.sh: cannot write a new key in $dir" >&2; exit 1; }
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$new" \
      || { echo "key generation failed; the old key is unchanged" >&2; exit 1; }
    chmod -- 600 "$new"
    # Checked before it replaces anything: genpkey can exit 0 after a short
    # write (a full disk).
    new_fp=$(fingerprint_or_fail "$new") \
      || { echo "the new key didn't check out (a full disk?); the old key is unchanged" >&2; exit 1; }
    mv -f -- "$new" "$key"
    new=""
    fp=$new_fp
    PUB=$(openssl pkey -in "$key" -pubout) \
      || { echo "could not derive the public key" >&2; exit 1; }
    echo "new key written to $key (mode 600); the old key is now $prev"
    echo
    echo "new public key fingerprint: SHA256:$fp"
    echo "report this fingerprint to the human; they compare it with handoff.sh's output"
    echo
    echo "embed this public key in handoff.sh, in place of the old one:"
    echo
    printf '%s\n' "$PUB"
    echo
    echo "next: SETUP.md Rotation step 3 (the user embeds this key in handoff.sh and confirms its fingerprint), then the rest of Rotation (or Compromise)"
    exit 0
    ;;
  --retire)
    # Deletes KEY.previous: blobs still made for it no longer open. SETUP.md
    # says when (every label's rewrap reported the previous key's blob
    # replaced); this checks only that a rotation finished.
    prev="$key.previous"
    no_symlinks
    if [ ! -e "$prev" ]; then
      echo "agent-setup.sh: no $prev: no rotation to retire" >&2; exit 1
    fi
    [ -f "$prev" ] || { echo "agent-setup.sh: $prev is not a regular file; report it to the user" >&2; exit 1; }
    [ -f "$key" ] || { echo "no key file at $key" >&2; exit 1; }
    trap cleanup EXIT
    lock_dir "$(dirname -- "$key")"
    key_fingerprint "$key"
    prev_fp=$(fingerprint_or_fail "$prev") || exit 1
    if [ "$prev_fp" = "$fp" ]; then
      echo "agent-setup.sh: $prev holds the current key: the rotation didn't finish; run agent-setup.sh --rotate again" >&2
      exit 1
    fi
    rm -f -- "$prev"
    echo "deleted the previous key $prev; the current key is $key (SHA256:$fp)"
    exit 0
    ;;
  --public-key)
    # The sanctioned way to show a key's public half again (a resumed setup
    # or rotation needs it for the user; the public key isn't a secret),
    # from a key that passes the same checks as --fingerprint.
    key_fingerprint "$key"
    PUB=$(openssl pkey -in "$key" -passin pass: -pubout) \
      || { echo "could not derive the public key from $key" >&2; exit 1; }
    echo "key file: $key" >&2
    echo "public key fingerprint: SHA256:$fp"
    echo
    printf '%s\n' "$PUB"
    exit 0
    ;;
esac

need_openssl
if [ -n "${HANDOFF_KEY_DIR-}" ]; then
  KEY_DIR=$(expand_home "$HANDOFF_KEY_DIR" HANDOFF_KEY_DIR) || exit 1
else
  KEY_DIR=$(default_dir) || exit 1
fi
PRIV="$KEY_DIR/handoff-priv.pem"

if [ -e "$PRIV" ]; then
  echo "refusing to overwrite existing key: $PRIV" >&2
  printf 'to rotate it, run HANDOFF_PRIVKEY=%q agent-setup.sh --rotate (SETUP.md, Rotation)\n' "$PRIV" >&2
  exit 1
fi

# Only chmod a directory this script created: if the user pointed
# HANDOFF_KEY_DIR at an existing directory by mistake, silently tightening
# its permissions would be a nasty surprise. Say so when that happens.
if [ -d "$KEY_DIR" ]; then
  echo "note: key directory $KEY_DIR already exists; its permissions were left unchanged (expected 0700)" >&2
else
  mkdir -p -- "$KEY_DIR"
  # `--` before the mode: BSD chmod stops reading options at the mode, so a
  # `--` after it would be taken as a file.
  chmod -- 700 "$KEY_DIR"
fi
# An absolute path from here on: the path printed below is what wrappers
# set HANDOFF_PRIVKEY to, from whatever directory they run in.
case "$KEY_DIR" in /*) ;; *) KEY_DIR="./$KEY_DIR" ;; esac  # not cd's "-" or a search
KEY_DIR=$(cd -- "$KEY_DIR" && pwd)
PRIV="$KEY_DIR/handoff-priv.pem"

# No stderr suppression: if key generation fails, the human needs the cause.
# Written to a temporary file and checked first (genpkey can exit 0 after a
# short write), then linked into place: ln never replaces a key that
# appeared meanwhile, and a failed run leaves no file at $PRIV.
trap 'rm -f -- "$new"' EXIT
# A TERM, HUP or INT ends the run through the EXIT trap, after the running
# openssl exits: without these, bash would die at once and the EXIT trap
# would run before genpkey wrote its file, leaving a private key behind.
trap 'exit 1' INT TERM HUP
for f in "$KEY_DIR"/.handoff-setup.*; do
  # A temporary key a killed (SIGKILL) setup left behind: never a live key.
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  rm -f -- "$f"
  echo "note: removed a temporary key a killed (or concurrent) setup left behind: $f" >&2
done
new=$(mktemp -- "$KEY_DIR/.handoff-setup.XXXXXX") || { echo "cannot write a key in $KEY_DIR" >&2; exit 1; }
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$new" \
  || { echo "key generation failed" >&2; exit 1; }
chmod -- 600 "$new"
FPR=$(fingerprint_or_fail "$new") \
  || { echo "the new key didn't check out (a full disk?); nothing was written" >&2; exit 1; }
ln -- "$new" "$PRIV" || {
  echo "could not link the new key into place at $PRIV; nothing was written (the key directory needs hard links, SETUP.md step 1, or a key appeared meanwhile)" >&2
  exit 1
}
if [ ! "$PRIV" -ef "$new" ]; then
  # $PRIV became a directory meanwhile, and ln put the key inside it.
  rm -f -- "$PRIV/${new##*/}"
  echo "could not link the new key into place at $PRIV (it is now a directory); nothing was written" >&2
  exit 1
fi

PUB=$(openssl pkey -in "$PRIV" -pubout) \
  || { printf "the key was written to %s, but its public key couldn't be derived; show it with: agent-setup.sh --public-key %q\n" "$PRIV" "$PRIV" >&2; exit 1; }

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
if [ -z "${HOME-}" ] || [ "$PRIV" != "$(default_dir)/handoff-priv.pem" ]; then
  printf 'non-default location: set HANDOFF_PRIVKEY=%q wherever the helper runs\n' "$PRIV"
fi
