#!/bin/bash
# agent-setup.sh — run on the agent's machine (the computer that will
# decrypt the blobs, e.g. your Muse's VM): once to make the identity, and
# again for recipients and rotations.
#
# Makes an age identity (X25519) for the encrypted credential handoff:
#   identity:  ~/.config/handoff/handoff-identity.txt  (mode 0600, NEVER shared)
#   recipient: printed at the end, for the user to save as handoff-<name>.age beside handoff.sh
# The recipient is the identity's public key, one line (age1…). The human
# compares the whole line with the one handoff.sh shows before trusting any
# blob. The consume-side key path to configure is printed too.
#
# Usage:
#   agent-setup.sh                      make a new identity
#   agent-setup.sh --fingerprint [KEY]  print an existing identity's recipient
#                                       (the key file it read goes to stderr)
#   agent-setup.sh --public-key [KEY]   print an existing identity's recipient
#                                       again (to give the user), and where
#                                       they save it
#   agent-setup.sh --rotate [KEY]       start a rotation: a new identity at KEY,
#                                       the old one kept as KEY.previous;
#                                       during one, shows the new recipient again
#   agent-setup.sh --retire --yes [KEY] end a rotation: delete KEY.previous;
#                                       blobs still made for it stop opening
#                                       (without --yes, it says what it would
#                                       delete, keeps the old key, removing
#                                       only a leftover temporary link to it,
#                                       and exits 1)
#   agent-setup.sh --check-setup        run age, age-keygen and consume.py --check
#                                       on a throwaway identity; prints PASS,
#                                       INFO or FAIL lines, exits 1 on a FAIL
# Exit codes: 0 done (or, for --rotate during a rotation, shown), 1 refused
# or failed (the reason on stderr), 2 a usage error.
#
# Environment:
#   HANDOFF_KEY_DIR  where a NEW identity is made (default ~/.config/handoff).
#   HANDOFF_PRIVKEY  which EXISTING identity --fingerprint, --public-key,
#                    --rotate and --retire use: the same variable, with the same
#                    default (~/.config/handoff/handoff-identity.txt), that
#                    consume.py decrypts with. A KEY argument overrides it.
#                    These modes refuse HANDOFF_KEY_DIR without HANDOFF_PRIVKEY
#                    (exit 2); --check-setup reads the same identity and gives
#                    that case a FAIL identity line.
# Needs age-keygen (the age package) on the PATH. It runs with an environment
# of PATH only, as consume.py's age does, and is given an identity on its
# stdin, never as a path.
# The identity file's text sits in a shell variable while it's checked, so
# the caller's shell options must not reach it: xtrace (bash -x,
# SHELLOPTS=xtrace) would print it on stderr, and allexport
# (SHELLOPTS=allexport) would export it to every command run after it is
# read. First, before anything is read.
# Under zsh or sh, say so, rather than fail on an option they don't have (as
# handoff.sh does).
[ -n "${BASH_VERSION-}" ] || { echo "agent-setup.sh: run it with bash (./agent-setup.sh, or bash agent-setup.sh)" >&2; exit 1; }
set +x
set +a
# Leave POSIX mode if bash was started in it (POSIXLY_CORRECT, SHELLOPTS=posix
# or sh), as handoff.sh does: bash before 5.1 refuses process substitution
# there, which recipient_of uses. Before any function is parsed. (This also
# unsets POSIXLY_CORRECT, so the commands run here parse options their usual
# way; chmod is called as BSD's needs either way.)
set +o posix
set -euo pipefail
umask 077

MAX_KEY_BYTES=16384   # equal to consume.py's MAX_KEY_FILE
# cd must never search the caller's CDPATH for a relative key directory.
unset CDPATH
# This run's temporary key and lock (cleanup removes them, except after a
# SIGKILL; the next run removes a key left behind): never inherited.
new=""
newd=""
lock=""
# --retire's confirmation: set only by --yes on the command line.
yes=""
key_given=0

# The shapes of the lines of an age identity file, as consume.py's
# AGE_SECRET_RE and AGE_RECIPIENT_RE spell them (bech32: 58 characters of the
# alphabet, lowercase for a recipient; no range, so no locale changes them).
SECRET_RE='^AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}$'
RECIPIENT_RE='^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$'

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

# A path in a message, quoted as the shell would (printf %q): a name with a
# newline or other control character can't pass for a line of output.
qp() { printf '%q' "$1"; }

# The PATH age-keygen is looked for on, in the words of consume.py's
# age_missing (long ones cut at 300 characters).
path_was() {
  local p=${PATH-}
  [ "${#p}" -le 300 ] || p="${p:0:300}..."
  printf "(PATH was '%s')" "$p"
}

# age-keygen is the one tool this script runs. The same refusal as
# consume.py's age_missing.
need_age() {
  command -v age-keygen >/dev/null 2>&1 || {
    echo "agent-setup.sh: age-keygen not found on this PATH (in a wrapper, its PATH= line); install age: README.md, Installing age $(path_was)" >&2
    exit 1
  }
}

# age-keygen with an environment of PATH only: none of the variables age reads
# (AGE_PASSPHRASE and the rest, AGEDEBUG) may reach it. stdin passes through.
age_keygen() {
  env -i PATH="${PATH-}" age-keygen "$@"
}

# env's exit status for a command it found but couldn't run (126) or couldn't
# find after all (127): the same refusal as consume.py's age_cannot_run.
keygen_cannot_run() {  # RC
  case "$1" in
    126|127) echo "agent-setup.sh: cannot run age-keygen $(path_was)" >&2; return 0 ;;
  esac
  return 1
}

# The recipient of an identity file, printed on stdout; the reason for a
# refusal on stderr, in consume.py's check_key words, never with a line of the
# file in it. Returns 1 if the file can't be used at all (missing, a symlink,
# loose, someone else's, unreadable, too big, or age-keygen won't run or load
# it), 2 if it was read and isn't one plain age identity (an RSA key from
# 0.1.0, another text, a plugin or post-quantum identity, a recipient, two
# secret keys). The recipient is age-keygen -y's, never a comment's.
recipient_of() {  # FILE
  local f=$1 mode size data line secrets=0 recipient=0 out rc=0
  if [ -L "$f" ]; then
    echo "key file at $(qp "$f") is a symbolic link; give the identity file itself. Refusing." >&2
    return 1
  fi
  [ -f "$f" ] || { echo "no key file at $(qp "$f")" >&2; return 1; }
  # Only group and other bits matter, as in consume.py: a setgid bit alone
  # doesn't. GNU stat first, BSD's if that isn't understood.
  mode=$(stat -c %a -- "$f" 2>/dev/null) || mode=$(stat -f %Lp -- "$f" 2>/dev/null) || mode=""
  [ -n "$mode" ] || { echo "cannot read key file at $(qp "$f")" >&2; return 1; }
  if [ $(( 8#$mode & 8#077 )) -ne 0 ]; then
    echo "key file at $(qp "$f") is mode $mode; it must be owner-only (0600). Refusing." >&2
    return 1
  fi
  [ -O "$f" ] || { echo "key file at $(qp "$f") is not owned by this user. Refusing." >&2; return 1; }
  # One bounded read, as handoff.sh reads a recipient file, and every check
  # below is on what was read: a file swapped after the checks above can't
  # bring back an unbounded read, and the size is that of the bytes read.
  # (The x keeps $(...) from dropping trailing newlines; a NUL, which $(...)
  # would drop, is read as \001 and counted, and then refused.) A FIFO or
  # device at the path is refused by [ -f ] above; only a swap in the moment
  # between, by someone who can write the key's directory, could still make
  # the read wait.
  data=$( { LC_ALL=C head -c "$((MAX_KEY_BYTES + 1))" -- "$f" | LC_ALL=C tr '\000' '\001' && printf x; } 2>/dev/null ) \
    || { echo "cannot read key file at $(qp "$f")" >&2; return 1; }
  data=${data%x}
  size=$(( $(printf '%s' "$data" | LC_ALL=C wc -c) ))
  if [ "$size" -gt "$MAX_KEY_BYTES" ]; then
    echo "key file at $(qp "$f") is over $MAX_KEY_BYTES bytes; not an age identity file" >&2
    return 1
  fi
  # A NUL byte is never in an identity: not one.
  case "$data" in
    *$'\001'*) echo "the file at $(qp "$f") is not an age identity file" >&2; return 2 ;;
  esac
  case "$data" in
    *"-----BEGIN RSA PRIVATE KEY-----"*|*"-----BEGIN PRIVATE KEY-----"*|*"-----BEGIN ENCRYPTED PRIVATE KEY-----"*)
      echo "the key at $(qp "$f") is an RSA key from 0.1.0; 0.2.0 uses age: a 0.1.0 install sets up again (README.md)" >&2
      return 2 ;;
  esac
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in "#"*) continue ;; esac
    [ -n "${line//[[:space:]]/}" ] || continue
    case "$line" in
      AGE-PLUGIN-*)
        echo "the identity at $(qp "$f") holds a plugin identity; only a plain age identity is supported" >&2
        return 2 ;;
      AGE-SECRET-KEY-PQ-1*)
        echo "the identity at $(qp "$f") is a post-quantum identity; only a plain age identity is supported" >&2
        return 2 ;;
    esac
    if [[ $line =~ $SECRET_RE ]]; then
      secrets=$((secrets + 1))
    elif [[ $line =~ $RECIPIENT_RE ]]; then
      recipient=1
    else
      echo "the file at $(qp "$f") is not an age identity file" >&2
      return 2
    fi
  # A pipe, not a here-string: bash before 5.1 (macOS's /bin/bash is 3.2)
  # backs <<< with a temporary file, which would put the secret line on disk.
  done < <(printf '%s\n' "$data")
  if [ "$secrets" -eq 0 ]; then
    if [ "$recipient" -eq 1 ]; then
      echo "the file at $(qp "$f") is not an age identity file; that is a recipient (public), not an identity" >&2
    else
      echo "the file at $(qp "$f") is not an age identity file" >&2
    fi
    return 2
  fi
  if [ "$secrets" -gt 1 ]; then
    echo "the identity at $(qp "$f") holds $secrets secret keys; it must hold exactly one" >&2
    return 2
  fi
  if [ "$recipient" -eq 1 ]; then
    echo "the file at $(qp "$f") is not an age identity file" >&2
    return 2
  fi
  # The text just checked goes to age-keygen on its stdin, so what it reads is
  # what was checked. Its own text is not shown.
  out=$(printf '%s\n' "$data" | age_keygen -y 2>/dev/null) || rc=$?
  if [ "$rc" -ne 0 ]; then
    keygen_cannot_run "$rc" && return 1
    echo "cannot load the age identity at $(qp "$f")" >&2
    return 1
  fi
  if ! [[ $out =~ $RECIPIENT_RE ]]; then
    echo "cannot load the age identity at $(qp "$f")" >&2
    return 1
  fi
  printf '%s\n' "$out"
}

# The key the consume side uses: KEY if given, else $HANDOFF_PRIVKEY, else
# the default. Sets $key.
resolve_key() {  # [KEY]
  if [ $# -eq 1 ]; then
    key=$(expand_home "$1" KEY) || exit 1
  elif [ -n "${HANDOFF_PRIVKEY-}" ]; then
    key=$(expand_home "$HANDOFF_PRIVKEY" HANDOFF_PRIVKEY) || exit 1
  else
    key="$(default_dir)/handoff-identity.txt" || exit 1
  fi
}

# The recipient of an existing identity file, refusing what isn't a usable
# one (recipient_of says why). Sets $rcpt.
key_recipient() {  # FILE
  rcpt=$(recipient_of "$1") || exit 1
}

# --rotate and --retire act on the names KEY and KEY.previous: through a
# symlink, the hard link and rename would act on the link, not the key file
# (leaving the new key off the volume the link points to, and the old key on
# it after --retire). Refuse, and have the path name the file itself.
# The key's directory (through a symlink, as the key is read) must be owned
# by this user or root and writable by no group or other: anyone else who can
# write there can rename another file over the key, or add one beside it.
# No sticky exception (it stops renames, not new files). consume.py refuses
# the same directories. Prints the refusal (exit 0) when the directory fails;
# returns 1 when it's fine. find's -perm -MODE and -user are POSIX, so this
# reads the same on BSD and BusyBox; "$q/." makes find look at the directory
# a symlink points to, not the link itself.
key_dir_unsafe_msg() {  # DIR
  local d=$1 q me other writable mine
  case "$d" in /*) q=$d ;; *) q=./$d ;; esac
  me=$(id -u)
  other=$(find "$q/." -prune ! -user 0 ! -user "$me" -print 2>/dev/null) || other=
  if [ -n "$other" ]; then
    printf "the key's directory %s is owned by another account; stop and report it to the user: the key belongs in a directory of this account's own (SETUP.md step 1)" "$(qp "$d")"
    return 0
  fi
  writable=$(find "$q/." -prune \( -perm -0020 -o -perm -0002 \) -print 2>/dev/null) || writable=
  [ -n "$writable" ] || return 1
  # chmod is the fix only for this account's own directory: on a shared one
  # (/tmp, owned by root) it would break the directory for everyone.
  mine=$(find "$q/." -prune -user "$me" -print 2>/dev/null) || mine=
  if [ -n "$mine" ]; then
    printf "the key's directory %s is writable by others; stop and report it to the user, who runs: chmod -- go-w %s" "$(qp "$d")" "$(qp "$d")"
  else
    printf "the key's directory %s is writable by others; stop and report it to the user: the key belongs in a directory of this account's own (SETUP.md step 1)" "$(qp "$d")"
  fi
}
key_dir_safe() {  # DIR
  local m
  if m=$(key_dir_unsafe_msg "$1"); then
    echo "agent-setup.sh: $m" >&2
    exit 1
  fi
}

no_symlinks() {
  local p
  for p in "$key" "$prev"; do
    if [ -L "$p" ]; then
      echo "agent-setup.sh: $p is a symlink; set HANDOFF_PRIVKEY (or KEY) to the key file itself, not a link to it" >&2
      exit 1
    fi
  done
}

# --rotate and --retire take the current key, never a rotation's old one: on
# KEY.previous, --rotate would keep the old key as KEY.previous.previous,
# where consume.py never looks, and put a new key at KEY.previous; --retire
# would delete the wrong key (issue #46). Matched without case, as macOS's
# default volume names the same file either way.
is_previous_name() {  # PATH
  case "$1" in *.[Pp][Rr][Ee][Vv][Ii][Oo][Uu][Ss]) return 0 ;; esac
  return 1
}
# ", <the name without .previous>" when that is a file name, else nothing
# (a key file named just ".previous" has no current key to suggest).
suggest_current() {  # PATH
  local c=${1%.*}
  case "$c" in ''|*/) ;; *) printf ', %s' "$(qp "$c")" ;; esac
}
not_previous() {
  is_previous_name "$key" || return 0
  if [ "$key_given" = 1 ]; then
    echo "agent-setup.sh: $(qp "$key") is a rotation's old key (its name ends in .previous); $mode takes the current key$(suggest_current "$key"); nothing changed" >&2
  else
    echo "agent-setup.sh: HANDOFF_PRIVKEY ($(qp "$key")) names a rotation's old key (its name ends in .previous); set it to the current key$(suggest_current "$key"), as the wrappers do; nothing changed" >&2
  fi
  exit 1
}

# Make a new identity at FILE, which must not exist (age-keygen makes it
# itself and refuses to replace anything, a planted link included). Its own
# text, "Public key: …" on success, is not shown; on failure it is, since the
# human needs the cause. Returns age-keygen's status.
make_identity() {  # FILE
  local err rc=0
  err=$(age_keygen -o "$1" 2>&1 >/dev/null) || rc=$?
  if [ "$rc" -ne 0 ]; then
    keygen_cannot_run "$rc" || printf '%s\n' "$err" >&2
    return 1
  fi
}

# What the user needs to save the recipient. The bare line is the thing to
# save, the whole of it; nothing here is derived from the secret.
show_recipient() {  # RECIPIENT
  echo "save it as handoff-<name>.age beside handoff.sh"
  echo "(handoff-muse.age for the default name; SETUP.md step 3). The file holds this one line:"
  echo
  printf '%s\n' "$1"
}

# One --rotate or --retire at a time per key directory: a portable lock
# (mkdir is atomic everywhere; flock isn't on macOS). An interrupted run
# that couldn't remove it says so on the next run.
lock_dir() {  # DIR
  local l="$1/.handoff-lock" err
  if ! err=$(mkdir -- "$l" 2>&1); then
    if [ -e "$l" ]; then
      echo "agent-setup.sh: another --rotate or --retire is running ($l exists)." >&2
      echo "Stop and report it to the user: if no run is going (one was killed), they remove it with: rmdir $l" >&2
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
  [ -z "${newd-}" ] || rm -rf -- "$newd"
  [ -z "${lock-}" ] || rmdir -- "$lock" 2>/dev/null || true
}

usage() {
  echo "usage: agent-setup.sh                      make a new identity (once, at setup)" >&2
  echo "       agent-setup.sh --fingerprint [KEY]  print an existing identity's recipient" >&2
  echo "       agent-setup.sh --public-key [KEY]   print an existing identity's recipient and where to save it" >&2
  echo "       agent-setup.sh --rotate [KEY]       start a rotation: a new identity at KEY, the old one kept as KEY.previous;" >&2
  echo "                                           during one, shows the new recipient again (exit 0)" >&2
  echo "       agent-setup.sh --retire --yes [KEY] end a rotation: delete KEY.previous (blobs still made for it stop opening);" >&2
  echo "                                           without --yes, says what it would delete and keeps the old key, removing only" >&2
  echo "                                           a leftover temporary link to it (exit 1)" >&2
  echo "       agent-setup.sh --check-setup        check that age, age-keygen and python3 work here (PASS, INFO or FAIL lines)" >&2
}

# --- --check-setup: prove the tools work on this machine, by running them -----
# One line per check on stdout (PASS, INFO or FAIL, a name, a detail), nothing
# else there; exit 0 unless a line is FAIL. The round trip goes through
# consume.py --check itself, with HANDOFF_PRIVKEY pointed at a throwaway
# identity in a private temporary directory (removed on every exit), so the
# helper's own header check and decrypt are what's tested. The real key is
# only read, by recipient_of's checks, and never printed. No prompt, no stdin.
cs_failed=0
cs_out() {  # STATUS NAME DETAIL
  local d=${3//$'\n'/ }
  printf '%s %s: %s\n' "$1" "$2" "$d"
  [ "$1" != FAIL ] || cs_failed=1
}
check_setup() {
  local p v rc blob rcpt re have_age=0 have_keygen=0 have_py=0 here consume
  local payload rt="" hdr="" b64="" want k kmsg kc
  set +e
  # The traps first, so no signal can fall between the folder and its cleanup
  # (newd starts empty, and cleanup removes it only if set).
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM HUP
  newd=$(mktemp -d "${TMPDIR:-/tmp}/handoff-check.XXXXXX" 2>/dev/null) && [ -d "$newd" ] \
    || { newd=""; cs_out FAIL tempdir "cannot make a private temporary directory (check TMPDIR)"; exit 1; }
  chmod 700 "$newd"

  if p=$(command -v age 2>/dev/null) && [ -n "$p" ]; then
    if v=$(env -i PATH="${PATH-}" age --version </dev/null 2>/dev/null | head -n 1) && [ -n "$v" ]; then
      cs_out PASS age "$v"; have_age=1
    else
      cs_out FAIL age "found at $p, but 'age --version' did not run; reinstall age (README.md, Installing age)"
    fi
  else
    cs_out FAIL age "not found on PATH; install it (README.md, Installing age) $(path_was)"
  fi
  if p=$(command -v age-keygen 2>/dev/null) && [ -n "$p" ]; then
    if env -i PATH="${PATH-}" age-keygen -o "$newd/id.txt" </dev/null >/dev/null 2>&1 && [ -s "$newd/id.txt" ]; then
      v=$(env -i PATH="${PATH-}" age-keygen --version </dev/null 2>/dev/null | head -n 1)
      cs_out PASS age-keygen "${v:-made a throwaway identity}"; have_keygen=1
    else
      cs_out FAIL age-keygen "found at $p, but it did not make an identity; reinstall age"
    fi
  else
    cs_out FAIL age-keygen "not found on PATH; install age (README.md, Installing age) $(path_was)"
  fi
  # python3 3.7 or newer: consume.py needs it.
  if command -v python3 >/dev/null 2>&1; then
    v=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' </dev/null 2>/dev/null) || v=
    if [[ "$v" =~ ^([0-9]+)\.([0-9]+) ]] \
       && { [ "${BASH_REMATCH[1]}" -gt 3 ] || { [ "${BASH_REMATCH[1]}" -eq 3 ] && [ "${BASH_REMATCH[2]}" -ge 7 ]; }; }; then
      cs_out PASS python3 "$v"; have_py=1
    else
      cs_out FAIL python3 "Python 3.7 or newer is required; found ${v:-no version output}"
    fi
  else
    cs_out FAIL python3 "not found on PATH; consume.py needs Python 3.7 or newer"
  fi

  if [ "$have_age" = 1 ] && [ "$have_keygen" = 1 ] && [ "$have_py" = 1 ]; then
    here=${BASH_SOURCE[0]-}
    case "$here" in */*) here=${here%/*} ;; *) here=. ;; esac
    consume=$here/consume.py
    re='^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$'
    payload='{"svc":"check","password":"pässwörd-ü-日本"}'
    rcpt=$(env -i PATH="${PATH-}" age-keygen -y "$newd/id.txt" </dev/null 2>/dev/null)
    if [[ ! "$rcpt" =~ $re ]]; then
      rt="FAIL|age-keygen -y did not print a recipient for the throwaway identity"
    elif [ ! -f "$consume" ]; then
      rt="FAIL|consume.py is not beside agent-setup.sh ($here)"
    else
      blob=$(printf '%s' "$payload" | env -i PATH="${PATH-}" age -r "$rcpt" 2>/dev/null | base64 | tr -d '\n')
      rc=$?
      if [ "$rc" -ne 0 ] || [ -z "$blob" ]; then
        rt="FAIL|age failed to encrypt to the throwaway recipient"
      else
        printf '%s\n' "$blob" >"$newd/blob.txt"
        if printf '%s' "$blob" | base64 -d >"$newd/blob.bin" 2>/dev/null || printf '%s' "$blob" | base64 -D >"$newd/blob.bin" 2>/dev/null; then
          if [ "$(base64 <"$newd/blob.bin" | tr -d '\n')" = "$blob" ]; then
            b64="PASS|the blob decodes and re-encodes to itself ($(wc -c <"$newd/blob.bin" | tr -d ' ') bytes)"
          else
            b64="FAIL|base64 does not round-trip the blob here"
          fi
        else
          b64="FAIL|this base64 cannot decode the blob"
        fi
        # None of the caller's HANDOFF_* variables (an exported $HANDOFF_BLOB
        # is a second blob source, a $HANDOFF_LABEL the nesting refusal), and
        # no PYTHON* ones (-I): the check is of this machine's tools, not of
        # the calling shell. Unset in the $(...)'s subshell, so it stays there.
        v=$(unset HANDOFF_BLOB HANDOFF_LABEL HANDOFF_PRIVKEY
            HANDOFF_PRIVKEY="$newd/id.txt" python3 -I "$consume" --label check --check --blob-file "$newd/blob.txt" </dev/null 2>"$newd/cerr")
        rc=$?
        want="svc: matches label 'check'
password: 20 bytes"
        if [ "$rc" -eq 0 ] && [ "$v" = "$want" ]; then
          hdr="PASS|consume.py accepted the header: exactly one X25519 stanza"
          rt="PASS|encrypted, then decrypted by consume.py --check: the 20-byte UTF-8 password came back unchanged"
        elif [ "$rc" -eq 0 ]; then
          hdr="PASS|consume.py accepted the header: exactly one X25519 stanza"
          rt="FAIL|consume.py --check decrypted something other than what was encrypted"
        else
          kmsg=$(head -n 1 "$newd/cerr" 2>/dev/null)
          kmsg=${kmsg#consume.py: }
          case "$kmsg" in
            *"age blob"*|*"armored"*|*"header"*)
              hdr="FAIL|$kmsg"
              rt="FAIL|not reached: consume.py refused the blob's header, so it never decrypted" ;;
            *) rt="FAIL|consume.py --check failed: ${kmsg:-no message}" ;;
          esac
        fi
      fi
    fi
    [ -z "$rt" ] || cs_out "${rt%%|*}" "round trip" "${rt#*|}"
    [ -z "$hdr" ] || cs_out "${hdr%%|*}" header "${hdr#*|}"
    [ -z "$b64" ] || cs_out "${b64%%|*}" base64 "${b64#*|}"
  fi

  # The real key, if there is one: read with the same checks as --fingerprint.
  # HANDOFF_KEY_DIR alone: the same refusal as --fingerprint's, since the
  # default path would be the wrong key, and "no key yet" the wrong advice.
  # Before the age-keygen gate: it's a setup error with or without the tools.
  if [ -n "${HANDOFF_KEY_DIR-}" ] && [ -z "${HANDOFF_PRIVKEY-}" ]; then
    cs_out FAIL identity "HANDOFF_KEY_DIR applies only to generating a key; for --check-setup, set HANDOFF_PRIVKEY=<dir>/handoff-identity.txt as the wrappers do"
  elif [ "$have_keygen" = 1 ]; then
    k=$( { resolve_key; printf '%s' "$key"; } 2>"$newd/kerr" )
    if [ -z "$k" ]; then
      kmsg=$(head -n 1 "$newd/kerr" 2>/dev/null); kmsg=${kmsg#agent-setup.sh: }
      cs_out FAIL identity "${kmsg:-cannot work out where the key is}"
    elif is_previous_name "$k"; then
      # consume.py refuses it (issue #46): every wrapper with it would fail.
      kc=${k%.*}
      case "$kc" in ''|*/) kc= ;; *) kc=", $kc" ;; esac
      cs_out FAIL identity "HANDOFF_PRIVKEY ($k) names a rotation's old key (its name ends in .previous); a wrapper sets it to the current key$kc"
    elif [ ! -e "$k" ] && [ ! -L "$k" ]; then
      cs_out INFO identity "no key at $k yet; agent-setup.sh with no argument makes it"
    elif kmsg=$(key_dir_unsafe_msg "$(dirname -- "$k")"); then
      # consume.py refuses such a directory: every wrapper would fail.
      cs_out FAIL identity "$kmsg"
    elif [ -e "$k.previous.previous" ] || [ -L "$k.previous.previous" ]; then
      cs_out FAIL identity "$k.previous.previous exists: the keys aren't where a rotation keeps them (SETUP.md, Rotation: A .previous.previous file)"
    elif recipient_of "$k" >/dev/null 2>"$newd/kerr"; then
      cs_out PASS identity "the key at $k passes the identity checks (owner-only, one plain age identity)"
    else
      kmsg=$(head -n 1 "$newd/kerr" 2>/dev/null)
      cs_out FAIL identity "${kmsg:-the key at $k did not pass the identity checks}"
    fi
  else
    cs_out INFO identity "skipped (needs age-keygen)"
  fi
  exit "$cs_failed"
}

# Recompute the recipient of an EXISTING identity, e.g. at comparison time.
# The setup and SETUP.md rules require the recipient to come from the key
# file itself, never from notes, and forbid the agent reading the key
# with general-purpose tools: this mode is the sanctioned path. It reads
# the key the consume side uses ($HANDOFF_PRIVKEY), and says which file it
# read, so that during rotation the old key can't be reported by mistake.
case "${1-}" in
  --fingerprint|--public-key|--rotate|--retire)
    mode=$1
    shift
    syntax="$mode [KEY]"
    if [ "$mode" = --retire ]; then
      syntax="--retire --yes [KEY]"
      # Only right after --retire: a KEY of "--yes" is refused below as any
      # --* KEY is, and -k.pem stays a KEY.
      if [ "${1-}" = --yes ]; then yes=1; shift; fi
    fi
    if [ $# -gt 1 ]; then
      if [ "$mode" = --retire ] && [ "$2" = --yes ] && [ $# -eq 2 ] && [ -n "$yes" ]; then
        echo "usage: agent-setup.sh $syntax (--yes given twice)" >&2
      elif [ "$mode" = --retire ] && [ "$2" = --yes ] && [ $# -eq 2 ]; then
        echo "usage: agent-setup.sh $syntax (--yes goes right after --retire, before KEY)" >&2
      else
        echo "usage: agent-setup.sh $syntax" >&2
      fi
      exit 2
    fi
    # The KEY came from the command line (for --retire's misspelling hint).
    key_given=$#
    if [ $# -eq 1 ] && [ -z "$1" ]; then
      echo "agent-setup.sh: $mode was given an empty KEY" >&2; exit 2
    fi
    case "${1-}" in
      (--yes)
        if [ -n "$yes" ]; then
          echo "usage: agent-setup.sh $syntax (--yes given twice)" >&2
        else
          echo "usage: agent-setup.sh $syntax (--yes goes only right after --retire)" >&2
        fi
        exit 2 ;;
      (--yes=*|--[Yy][Ee][Ss]|--[Yy]|--[Yy][Ee])
        if [ "$mode" = --retire ] && [ -z "$yes" ]; then
          echo "usage: agent-setup.sh $syntax (the confirmation is spelled --yes, right after --retire)" >&2
        else
          echo "usage: agent-setup.sh $syntax (one mode at a time; $1 isn't a KEY)" >&2
        fi
        exit 2 ;;
      (--*) echo "usage: agent-setup.sh $syntax (one mode at a time; $1 isn't a KEY)" >&2; exit 2 ;;
    esac
    if [ $# -eq 0 ] && [ -n "${HANDOFF_KEY_DIR-}" ] && [ -z "${HANDOFF_PRIVKEY-}" ]; then
      echo "agent-setup.sh: HANDOFF_KEY_DIR applies only to generating a key; for $mode, set HANDOFF_PRIVKEY=<dir>/handoff-identity.txt as the wrappers do" >&2
      exit 2
    fi
    need_age
    resolve_key "$@"
    ;;
  "") mode=generate ;;
  --check-setup)
    [ $# -eq 1 ] || { echo "usage: agent-setup.sh --check-setup (takes no argument)" >&2; exit 2; }
    mode=--check-setup
    ;;
  *)
    # Anything else (--help, a typo of --fingerprint) must not fall through
    # to generating a key.
    usage
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then exit 0; fi
    exit 2
    ;;
esac

case "$mode" in
  --check-setup) check_setup ;;
  --fingerprint)
    key_recipient "$key"
    echo "key file: $(qp "$key")" >&2
    echo "recipient: $rcpt"
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
    # Which state a rotation is in is read from the keys' recipients, not
    # their inodes, so a copied .previous (a backup restore) reads the same.
    prev="$key.previous"
    not_previous
    no_symlinks
    [ -f "$key" ] || { echo "no key file at $(qp "$key")" >&2; exit 1; }
    dir=$(dirname -- "$key")
    key_dir_safe "$dir"
    # The lock first, then the state: a run that read the key before another
    # finished would otherwise take that run's new key for its own old one.
    trap cleanup EXIT
    # A TERM, HUP or INT ends the run through cleanup, after the running
    # age-keygen exits (see first-time generation below).
    trap 'echo "agent-setup.sh: interrupted; run --rotate again to finish (SETUP.md, Rotation step 1)" >&2; exit 1' INT TERM HUP
    lock_dir "$dir"
    key_recipient "$key"
    if [ -e "$prev.previous" ] || [ -L "$prev.previous" ]; then
      # See --retire: the keys aren't where a rotation keeps them, and
      # rotating again would only move them further (issue #46).
      echo "agent-setup.sh: $(qp "$prev.previous") exists, most likely left by an earlier --rotate given $(qp "$prev") as its KEY: the keys aren't where a rotation keeps them, and nothing was rotated. Stop and report it to the user (SETUP.md, Rotation: A .previous.previous file)" >&2
      exit 1
    fi
    for f in "$dir"/.handoff-new.*; do
      # A temporary key a killed --rotate left (the lock says none is running).
      [ -e "$f" ] || [ -L "$f" ] || continue
      # Never the key itself, whatever it's named (by its two names only: a
      # temporary key hard-linked to the old key is still a temporary file).
      # Compared as the glob spells them ($dir/name): a relative or doubled-
      # slash KEY must still match.
      if [ "$f" = "$dir/${key##*/}" ] || [ "$f" = "$dir/${prev##*/}" ]; then continue; fi
      if [ ! -f "$f" ] || [ -L "$f" ]; then
        echo "agent-setup.sh: $(qp "$f") is not a temporary key file; report it to the user" >&2; exit 1
      fi
      rm -f -- "$f"
      echo "note: removed a temporary key a killed --rotate left behind: $(qp "$f")" >&2
    done
    for f in "$dir"/.handoff-tmp.*; do
      # The private directory of a killed --rotate or setup (the lock says
      # none is running).
      [ -d "$f" ] && [ ! -L "$f" ] || continue
      rm -rf -- "$f"
      echo "note: removed a temporary key directory a killed run left behind: $(qp "$f")" >&2
    done
    if [ -e "$prev" ]; then
      [ -f "$prev" ] || { echo "agent-setup.sh: $(qp "$prev") is not a regular file; report it to the user" >&2; exit 1; }
      prev_rcpt=$(recipient_of "$prev") || exit 1
      if [ "$prev_rcpt" != "$rcpt" ]; then
        # The new key is in place: show its recipient again, since an
        # interruption may have come before the user got it (SETUP step 3).
        echo "agent-setup.sh: a rotation is under way ($(qp "$prev") is the old key), and the new key is in place: nothing rotated." >&2
        echo "If the user hasn't saved this recipient as their handoff-<name>.age and confirmed it, continue at SETUP.md Rotation step 3; else step 4 (with staging held in your notes, Rotation step 1 says where)." >&2
        echo "current (new) recipient: $rcpt"
        echo
        show_recipient "$rcpt"
        exit 0
      fi
      echo "note: resuming an interrupted rotation ($(qp "$prev") holds the current key)" >&2
    else
      ln -- "$key" "$prev" || { echo "agent-setup.sh: could not keep the old key as $(qp "$prev") (the key directory needs hard links, SETUP.md step 1); nothing changed" >&2; exit 1; }
    fi
    # A private directory (mode 0700, beside KEY so the rename stays on one
    # filesystem) holds the new key until it is checked: age-keygen makes the
    # file in it, and no name is ever freed for someone else to plant a link on.
    newd=$(mktemp -d -- "$dir/.handoff-tmp.XXXXXX") || { echo "agent-setup.sh: cannot write a new key in $(qp "$dir")" >&2; exit 1; }
    new="$newd/${newd##*/}.key"
    make_identity "$new" \
      || { echo "key generation failed; the old key is unchanged, and $(qp "$prev") holds it too: run --rotate again to finish (SETUP.md, Rotation step 1)" >&2; exit 1; }
    chmod -- 600 "$new"
    # Checked before it replaces anything: age-keygen can exit 0 after a short
    # write (a full disk).
    new_rcpt=$(recipient_of "$new" 2>/dev/null) \
      || { echo "the new key didn't check out (a full disk?); the old key is unchanged, and $(qp "$prev") holds it too: run --rotate again to finish (SETUP.md, Rotation step 1)" >&2; exit 1; }
    mv -f -- "$new" "$key"
    if [ -d "$key" ]; then
      # KEY became a directory meanwhile, and mv put the new key inside it.
      rm -f -- "$key/${new##*/}"
      new=""
      echo "agent-setup.sh: $(qp "$key") is now a directory; the new key was removed, and the old key is $(qp "$prev"). Report it to the user." >&2
      exit 1
    fi
    new=""
    echo "new key written to $(qp "$key") (mode 600); the old key is now $(qp "$prev")"
    echo
    echo "new recipient: $new_rcpt"
    echo "report this recipient to the human; they compare it with handoff.sh's output"
    echo
    echo "the user replaces their old recipient file with this one:"
    show_recipient "$new_rcpt"
    echo
    echo "next: SETUP.md Rotation step 3 (the user replaces their handoff-<name>.age with this recipient and confirms it), then the rest of Rotation (or Compromise)"
    exit 0
    ;;
  --retire)
    # Deletes KEY.previous: blobs still made for it no longer open. SETUP.md
    # says when (Rotation step 5: every label in the setup record probed ok
    # with the current key, or written off); this checks only that a rotation
    # finished, and asks for --yes, since nothing here can tell whether a
    # label's stored blob still needs the old key (issue #4).
    prev="$key.previous"
    not_previous
    no_symlinks
    # The key first, as the other modes check it: a mistyped KEY (-y for
    # --yes) is "no key file", not "no rotation to retire", which would read
    # as the old key being gone.
    if [ ! -f "$key" ]; then
      # A hint only for a KEY typed on the command line (not HANDOFF_PRIVKEY)
      # when --yes wasn't given: then the KEY may be a typo of it.
      case "$yes:$key_given:$key" in
        :1:-[Yy]|:1:-[Yy][Ee]|:1:-[Yy][Ee][Ss]|:1:[Yy]|:1:[Yy][Ee]|:1:[Yy][Ee][Ss]) echo "no key file at $(qp "$key") (the confirmation is spelled --yes)" >&2 ;;
        *) echo "no key file at $(qp "$key")" >&2 ;;
      esac
      exit 1
    fi
    # Most likely left by a --rotate given KEY.previous, which releases up to
    # 0.2.0 allowed (issue #46): it may hold the rotation's real old key, and
    # this run would delete another. Checked before anything else about the
    # rotation, since a retire after that --rotate leaves it with no
    # KEY.previous, and "no rotation to retire" would read as done with the
    # old key still on disk. Nothing here can tell which key the user needs.
    if [ -e "$prev.previous" ] || [ -L "$prev.previous" ]; then
      echo "agent-setup.sh: $(qp "$prev.previous") exists, most likely left by an earlier --rotate given $(qp "$prev") as its KEY: the keys aren't where a rotation keeps them, and nothing was deleted. Stop and report it to the user (SETUP.md, Rotation: A .previous.previous file)" >&2
      exit 1
    fi
    if [ ! -e "$prev" ]; then
      echo "agent-setup.sh: no $(qp "$prev"): no rotation to retire" >&2; exit 1
    fi
    [ -f "$prev" ] || { echo "agent-setup.sh: $(qp "$prev") is not a regular file; report it to the user" >&2; exit 1; }
    trap cleanup EXIT
    key_dir_safe "$(dirname -- "$key")"
    lock_dir "$(dirname -- "$key")"
    key_recipient "$key"
    prev_rcpt=$(recipient_of "$prev") || exit 1
    if [ "$prev_rcpt" = "$rcpt" ]; then
      echo "agent-setup.sh: $(qp "$prev") holds the current key: the rotation didn't finish; run agent-setup.sh --rotate again" >&2
      exit 1
    fi
    # A killed setup or --rotate can leave a temporary file that is a hard
    # link to the old key: removing only $prev would leave its data on disk.
    kdir=$(dirname -- "$key")
    for f in "$kdir"/.handoff-setup.* "$kdir"/.handoff-new.*; do
      # As the glob spells them, so a relative or doubled-slash KEY matches.
      if [ "$f" = "$kdir/${prev##*/}" ] || [ "$f" = "$kdir/${key##*/}" ]; then continue; fi
      if [ -f "$f" ] && [ ! -L "$f" ] && [ "$f" -ef "$prev" ]; then
        rm -f -- "$f"
        echo "note: removed $(qp "$f"), another link to the previous key" >&2
      fi
    done
    # Another name for the old key (a backup copy made with ln) would keep it
    # on disk after this: refuse, so the user can find and remove it first.
    # find reads a path starting with - as a predicate: ./ in front. And a
    # find that fails is a refusal, not a pass.
    case "$prev" in /*) q=$prev ;; *) q=./$prev ;; esac
    links=$(find "$q" -links +1) || { echo "agent-setup.sh: couldn't check $(qp "$prev")'s links; report it to the user" >&2; exit 1; }
    if [ -n "$links" ]; then
      # Where to look: the mount point of the old key's disk (df's last
      # field; a mount point with a space in it reads short, hence the
      # fallback wording).
      mnt=$(df -P -- "$q" 2>/dev/null | awk 'NR == 2 { print $NF }')
      case $mnt in /*) [ -d "$mnt" ] || mnt= ;; *) mnt= ;; esac
      # Absolute, so the command works from any directory (sudo -i changes it).
      abs=$(cd -- "$(dirname -- "$prev")" && pwd -P)/${prev##*/} || abs=$prev
      # shellcheck disable=SC2012  # ls -di is the portable inode read (find -printf is GNU's)
      ino=$(ls -di -- "$q" 2>/dev/null | awk 'NR == 1 { print $1; exit }')
      case $ino in ''|*[!0-9]*) ino= ;; esac
      # Each path single-quoted for a POSIX shell: the user may run this as root.
      sq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
      if [ -n "$mnt" ]; then where=$(sq "$mnt"); else where="<the mount point of its disk>"; fi
      if [ -n "$ino" ]; then alt=" (or, where find has no -samefile, as in some BusyBox builds: find $where -xdev -inum $ino)"; else alt=; fi
      echo "agent-setup.sh: $(qp "$prev") has another hard link, so deleting it wouldn't remove the old key from disk; the previous key was not deleted. Report it to the user, who finds the other name with: find $where -xdev -samefile $(sq "$abs")$alt, as root to see every directory, and removes that other name first, not $(qp "$prev"), which the command lists too (SETUP.md, Rotation: A hard-link refusal at the retire)" >&2
      exit 1
    fi
    # Last, so every other refusal comes first: a hard link to resolve shows
    # up before the confirmation, not after it.
    if [ -z "$yes" ]; then
      echo "agent-setup.sh: --retire deletes the previous key $(qp "$prev") (recipient $prev_rcpt), and a blob still made for it never opens again; it was not deleted." >&2
      echo "Run agent-setup.sh --retire --yes (with the same KEY or HANDOFF_PRIVKEY) only once SETUP.md Rotation step 5's last pass is recorded: every label in your setup record probed ok with the current key, or written off by the user in a direct conversational turn, and no blob stored since that pass began (SETUP.md Rotation step 5). In a compromise response your notes record (the user's go-ahead, given directly), run it at Compromise step 2 or 4." >&2
      exit 1
    fi
    # Not atomic with the hard-link check above: an ln made in between (the lock is
    # advisory) keeps the old key on disk. That takes a deliberate actor with
    # the key directory's write access, which can copy the key anyway.
    rm -f -- "$prev"
    echo "deleted the previous key $(qp "$prev"); the current key is $(qp "$key") (recipient $rcpt)"
    exit 0
    ;;
  --public-key)
    # The sanctioned way to show a key's public half again (a resumed setup
    # or rotation needs it for the user; the recipient isn't a secret),
    # from a key that passes the same checks as --fingerprint.
    key_recipient "$key"
    echo "key file: $(qp "$key")" >&2
    echo "recipient: $rcpt"
    echo
    show_recipient "$rcpt"
    exit 0
    ;;
esac

need_age
if [ -n "${HANDOFF_KEY_DIR-}" ]; then
  KEY_DIR=$(expand_home "$HANDOFF_KEY_DIR" HANDOFF_KEY_DIR) || exit 1
else
  KEY_DIR=$(default_dir) || exit 1
fi
PRIV="$KEY_DIR/handoff-identity.txt"

if [ -e "$PRIV" ]; then
  echo "refusing to overwrite existing key: $PRIV" >&2
  printf 'if a setup was cut short, this is its key: agent-setup.sh --public-key %q shows it; to replace it, see SETUP.md Rotation\n' "$PRIV" >&2
  exit 1
fi

# Only chmod a directory this script created: if the user pointed
# HANDOFF_KEY_DIR at an existing directory by mistake, silently tightening
# its permissions would be a nasty surprise. Say so when that happens.
if [ -d "$KEY_DIR" ]; then
  key_dir_safe "$KEY_DIR"
  echo "note: key directory $(qp "$KEY_DIR") already exists; its permissions were left unchanged (expected 0700)" >&2
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
PRIV="$KEY_DIR/handoff-identity.txt"

# No stderr suppression of a failure: if key generation fails, the human needs
# the cause. Written to a temporary file and checked first (age-keygen can
# exit 0 after a short write), then linked into place: ln never replaces a key
# that appeared meanwhile, and a failed run leaves no file at $PRIV.
trap cleanup EXIT
# A TERM, HUP or INT ends the run through the EXIT trap, after the running
# age-keygen exits: without these, bash would die at once and the EXIT trap
# would run before age-keygen wrote its file, leaving a private key behind.
trap 'echo "agent-setup.sh: interrupted; run it again (if it then refuses, the key was written: --public-key shows it)" >&2; exit 1' INT TERM HUP
for f in "$KEY_DIR"/.handoff-setup.*; do
  # A temporary key a killed (SIGKILL) setup left behind: never a live key.
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  rm -f -- "$f"
  echo "note: removed a temporary key a killed (or concurrent) setup left behind: $(qp "$f")" >&2
done
for f in "$KEY_DIR"/.handoff-tmp.*; do
  [ -d "$f" ] && [ ! -L "$f" ] || continue
  rm -rf -- "$f"
  echo "note: removed a temporary key directory a killed (or concurrent) setup left behind: $(qp "$f")" >&2
done
# A private directory holds the new key until it is checked (see --rotate).
newd=$(mktemp -d -- "$KEY_DIR/.handoff-tmp.XXXXXX") || { echo "cannot write a key in $(qp "$KEY_DIR")" >&2; exit 1; }
new="$newd/${newd##*/}.key"
make_identity "$new" || { echo "key generation failed" >&2; exit 1; }
chmod -- 600 "$new"
RCPT=$(recipient_of "$new" 2>/dev/null) \
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

echo "identity written to $PRIV (mode 600) — never copy it off this machine"
echo
echo "recipient: $RCPT"
echo "report this recipient to the human; they compare it with handoff.sh's output"
echo
show_recipient "$RCPT"
echo
echo "consume side: the decrypt helper reads \$HANDOFF_PRIVKEY"
echo "(default ~/.config/handoff/handoff-identity.txt)."
echo "this key lives at: $PRIV"
if [ -z "${HOME-}" ] || [ "$PRIV" != "$(default_dir)/handoff-identity.txt" ]; then
  printf 'non-default location: set HANDOFF_PRIVKEY=%q wherever the helper runs\n' "$PRIV"
fi
