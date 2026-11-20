#!/bin/sh
"""":
exec python3 -I "$0" "$@" || exit 127
(Lines 1-3 are for sh: run as ./consume.py or sh consume.py, this file
re-runs itself as python3 -I, with no env -S, which BusyBox and older
coreutils lack. To Python they are the start of this docstring. Keep line
2 exactly as it is: a formatter that puts a space after its opening quotes
makes sh print an error on every run. run-test.sh checks the launcher is
silent.)

Consume-side template for the encrypted credential handoff.

Fetches nothing itself: the caller (a per-service wrapper) fetches the
base64 blob from wherever ciphertexts are stored and supplies it by
argument, file, or environment variable — never on stdin, which belongs
to the command (a stdio MCP server's stdin is its transport).
This helper decrypts IN MEMORY with `age` and the agent's age identity
(default ~/.config/handoff/handoff-identity.txt, override with
$HANDOFF_PRIVKEY; $HANDOFF_KEY_DIR without it is refused, since that one is
agent-setup.sh's, for making a key), verifies the payload's purpose binding, and either:

  run mode    replaces itself (exec) with a command, the credential values
              injected into its environment; the command's stdin, stdout
              and stderr are the helper's own, untouched, or
  --check     prints the svc match, then field names and value lengths
              ONLY. For the SETUP DUMMY round-trip only: lengths are output
              too, so never run --check on a real credential, or
  --rewrap    rewrites its --blob-file in place: the same payload, byte for
              byte, encrypted to the current key, written atomically and
              checked (ROTATION.md). Only during a rotation (refused
              with no <key path>.previous), only with --blob-file, never a
              file under the key's directory, and nothing is written for a
              blob that's already for the current key. Its stderr line names
              the key file the old blob was for.

During a rotation the old identity stays beside the current one as
<key path>.previous (agent-setup.sh --rotate makes it, --retire deletes
it). A blob the current key can't open is tried with the previous key;
in run mode, that prints a note to rewrap the label.

This helper never writes the plaintext to disk and never prints it, in
any mode, on success or on error. Nothing derived from the payload — not a
value, not a field name — is echoed in any message (--check's field names
and lengths excepted): payloads are unauthenticated input, and error text
lands in the agent's tool output. What the launched command prints is the
command's own business: a command that prints its environment (printenv)
reveals the credential to whoever ran the helper. So execute access to this
helper is read access to every staged credential, and each label runs only
what SETUP.md's hard rules record for it.

    username / password          -> SERVICE_USERNAME / SERVICE_PASSWORD
    api_key_id / api_key_secret  -> SERVICE_API_KEY_ID / SERVICE_API_KEY_SECRET
    token_id / token_secret      -> SERVICE_TOKEN_ID / SERVICE_TOKEN_SECRET
    private_key                  -> SERVICE_PRIVATE_KEY (a PEM, kept byte for byte)
    app_id / installation_id     -> SERVICE_APP_ID / SERVICE_INSTALLATION_ID
    svc                          -> purpose binding; never injected

Every field stands alone: none needs another, and a payload may carry any
of them (private_key, app_id and installation_id together are a GitHub
App's). Which fields a label's command needs is that label's record in
SETUP.md, not this helper's check.

Per-service variable names differ; map them per invocation instead of
editing this file:  --env username=APP_USER --env password=APP_PASS
Only the fields above can be mapped, each at most once. The default names
(SERVICE_*) and this call's mapped names are removed from the inherited
environment before the payload's values go in, along with $HANDOFF_BLOB
and $HANDOFF_PRIVKEY. Other variables pass through as inherited. The
command also gets $HANDOFF_LABEL (the label), and this helper refuses to
start when $HANDOFF_LABEL is already set, so a command started by one
consume.py that runs another one directly is refused, and no credential an
outer call injected under another name reaches a second service by
accident. It's an accident guard, not a boundary: a command that unsets the
marker gets past it. A wrapper's env -i removes the marker, along with the
outer credentials, so a command that starts a wrapper isn't refused here:
SETUP.md's no-nesting rule covers that.

A blob file must be a regular file. A pipe, a FIFO, a tty or a device
(so /dev/stdin on a pipe) and a process substitution (--blob-file
<(fetch)) are refused: give the blob with --blob "$(fetch </dev/null)"
or $HANDOFF_BLOB instead (the fetch must not read stdin, which belongs
to the command).

Exactly one blob source (--blob, --blob-file or $HANDOFF_BLOB), and
--label, --blob, --blob-file, --check and --rewrap at most once each. That is a
backstop for a wrongly written wrapper, not a license for one: a wrapper
passes no caller arguments at all (SETUP.md step 7), since a caller's
own --env or -- would otherwise pick where the credential goes. An empty
credential value is refused.
A target must be a plain variable name that reads as a credential's (it
ends in USER, PASSWORD, TOKEN, KEY, SECRET, ID and the like, after a _ or
as the whole name, and some of them with no _ too, as in PGPASSWORD:
CREDENTIAL_WORDS below), never the shell's own USER, USERNAME or PWD, never
one that changes what the command runs or where it connects
(PATH, LD_*, PYTHON*, GIT_*, BASH_ENV, the proxy and CA-bundle variables, ...;
a partial list, in any case),
and two fields can't share one target, the default mappings included.
Mapped variables come from the payload only: one the payload leaves out is
removed from the command's environment, not inherited from the caller's.

Every payload must carry "svc", and it must equal the --label the blob
was fetched under; otherwise this helper refuses. A payload with unknown
fields is noted by COUNT only; a payload with no known credential field
at all is refused, so a typo'd payload can't silently launch a tool with
no credentials.

`age` runs with an environment built from scratch (PATH only) and reads
its identity only from the bytes this helper checked, on a pipe of its
own (`-i /dev/fd/N`), never from the key's path: never `-p`, never `-j`,
never a passphrase or a plugin. A blob is opened only if its header names exactly one
X25519 recipient.

The injected values live in the command's environment for the life of
the command and are inherited by its children — and the target command
must not log its own environment or resolved config, and must never be
handed a credential on its command line (argv is world-readable).

Usage:
    HANDOFF_BLOB=$(cat blob.txt) consume.py --label example -- my-tool --serve
    consume.py --label example --blob-file blob.txt -- my-tool --serve
    consume.py --label test --check --blob-file blob.txt
    consume.py --label example --rewrap --blob-file store/example
    (during a rotation only: ROTATION.md step 4)
"""
# Run as ./consume.py, the helper is isolated (python3 -I, see the top of
# the docstring): the caller's PYTHON* variables and user site-packages don't
# reach it. A wrapper that calls Python itself should run python3 -I too.
import base64
import errno
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading

DEFAULT_PRIVKEY = "~/.config/handoff/handoff-identity.txt"
PRIVKEY_ENV = "HANDOFF_PRIVKEY"
BLOB_ENV = "HANDOFF_BLOB"
LABEL_ENV = "HANDOFF_LABEL"  # set in the command's environment: the nesting marker
KEY_DIR_ENV = "HANDOFF_KEY_DIR"  # agent-setup.sh's, for making a key; refused here alone
RSA_BLOB_BYTES_010 = 256  # a 0.1.0 (RSA-2048) blob decodes to exactly this: only for the hint
MAX_KEY_FILE = 16384    # bytes; an age identity file is about 190
# An age secret key: bech32, upper case, "AGE-SECRET-KEY-" + "1" + 52 data
# characters + a 6-character checksum.
AGE_SECRET_RE = re.compile(r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}")
AGE_RECIPIENT_RE = re.compile(r"age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}")
AGE_MAGIC = b"age-encryption.org/v1\n"
AGE_ARMOR_BEGIN = b"-----BEGIN AGE ENCRYPTED FILE-----"
# Characters of base64, whitespace dropped. Measured 2026-11-17: every store
# tested, and the chat path, carried a 64,000-character blob (a reference blob
# is about 370).
MAX_BLOB_FILE = 65536
MAX_BLOB_BYTES = MAX_BLOB_FILE // 4 * 3  # the most that many characters decode to
# What a blob file may hold as it is read, line breaks and blanks included: a
# blob at the cap saved wrapped (76 columns, as base64 tools wrap) is about
# 860 characters longer. Still a bound; decode_blob checks the cap itself.
MAX_BLOB_FILE_RAW = 2 * MAX_BLOB_FILE

DEFAULT_ENV_MAP = {
    "username": "SERVICE_USERNAME",
    "password": "SERVICE_PASSWORD",
    "api_key_id": "SERVICE_API_KEY_ID",
    "api_key_secret": "SERVICE_API_KEY_SECRET",
    "token_id": "SERVICE_TOKEN_ID",
    "token_secret": "SERVICE_TOKEN_SECRET",
    "private_key": "SERVICE_PRIVATE_KEY",
    "app_id": "SERVICE_APP_ID",
    "installation_id": "SERVICE_INSTALLATION_ID",
}

# --env target names: a plain identifier that reads as a credential, and
# never one of the well-known variables that change which program runs or how
# it starts. Mapping a payload field onto PATH or GIT_SSH_COMMAND, for
# example, would let whoever wrote the payload choose what runs. Both checks
# are backstops, not the control: what SETUP.md's hard rules record for each
# label is the control.
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# The allowlist (issue #43 item 13): the name ends in a credential word, as a
# whole word (after "_", or the whole name). The words in
# CREDENTIAL_WORDS_UNSEPARATED may also end a name without the "_"
# (PGPASSWORD, PGUSER); the others need the "_", so OLDPWD, SSH_AGENT_PID and
# PROXY_BYPASS stay refused. So no list of every runtime's
# variables is needed: NODE_TLS_REJECT_UNAUTHORIZED, AWS_CA_BUNDLE, SHELL,
# TMPDIR, GODEBUG and LUA_CPATH aren't credential names, so they're refused,
# and so is a name for a file (GOOGLE_APPLICATION_CREDENTIALS, *_KEY_FILE),
# whose value would choose what the command trusts. Compared upper-cased.
# It checks a name's shape, not what a program does with it: an ACCOUNT or ID
# name can still choose an endpoint or a stored identity (SNOWFLAKE_ACCOUNT,
# CLOUDSDK_CORE_ACCOUNT), so the mapping recorded for the label stays the
# control.
CREDENTIAL_WORDS = (
    "USER", "USERNAME", "LOGIN", "EMAIL", "ACCOUNT", "ID",
    "PASS", "PASSWORD", "PASSWD", "PASSPHRASE", "PWD",
    "TOKEN", "PAT", "KEY", "SECRET", "AUTH",
    "APIKEY", "ACCESSKEY", "SECRETKEY", "AUTHKEY", "PRIVATEKEY",
)
AUTH_SWITCH_WORDS = {"NO", "DISABLE", "DISABLED", "SKIP", "INSECURE", "BYPASS"}
CREDENTIAL_WORDS_UNSEPARATED = (
    "USER", "USERNAME", "PASSWORD", "PASSWD", "PASSPHRASE", "TOKEN", "SECRET",
)
CREDENTIAL_NAME_RE = re.compile(
    r"(?:[A-Z0-9_]*_)?(?:" + "|".join(CREDENTIAL_WORDS) + r")"
    r"|[A-Z0-9_]*(?:" + "|".join(CREDENTIAL_WORDS_UNSEPARATED) + r")")
# The refused list, checked first, and the only check that catches a
# credential-shaped name a tool reads for something else (GIT_*_TOKEN,
# PIP_PASSWORD, NPM_CONFIG_*_TOKEN, by prefix). Compared case-insensitively
# (curl and others read http_proxy as well as HTTP_PROXY). Two kinds:
# variables that change what code runs, and ones that change where the
# command connects or whom it trusts, which would let the payload's writer
# choose where the credential goes.
# USER, USERNAME and PWD end in credential words but are the shell's own: who
# runs (getpass.getuser() reads USERNAME too, and Windows names the user with
# it), and where. Refused before the list, with a message of their own.
SHELL_OWN_NAMES = {"USER", "USERNAME", "PWD"}
REFUSED_ENV_NAMES = {n.upper() for n in (
    # what runs, and how it starts
    "PATH", "HOME", "IFS", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "PS4",
    "PROMPT_COMMAND", "NODE_OPTIONS", "NODE_PATH", "PERL5OPT", "PERL5LIB",
    "PERLLIB", "PERL5DB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "GCONV_PATH",
    "GLIBC_TUNABLES", "LUA_INIT", "PAGER", "EDITOR", "VISUAL", "ZDOTDIR",
    "SSH_ASKPASS", "SSH_AUTH_SOCK", BLOB_ENV, PRIVKEY_ENV, LABEL_ENV,
    # where it connects, and whom it trusts
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS", "SSLKEYLOGFILE", "HOSTALIASES", "CURL_HOME",
    "WGETRC", "DOCKER_HOST", "KUBECONFIG", "XDG_CONFIG_HOME",
)}
REFUSED_ENV_PREFIXES = (
    "LD_", "DYLD_", "PYTHON", "BASH_FUNC_", "GIT_", "LUA_INIT_", "OPENSSL_",
    "NPM_CONFIG_", "PIP_",
)


def fail(msg: str) -> "SystemExit":
    return SystemExit(f"consume.py: {msg}")


def expand_home(path: str, what: str) -> str:
    """Expand a leading ~/ (an MCP client's JSON env passes it literally).

    Only ~/ itself: ~user is refused rather than guessed at, and
    agent-setup.sh follows the same rule, so the two never disagree.
    """
    if path == "~" or path.startswith("~/"):
        home = os.environ.get("HOME")
        if not home:
            raise fail(f"HOME is not set, and {what} needs it; set HOME or use an absolute path")
        return home + path[1:]
    if path.startswith("~"):
        raise fail(f"{what} {path!r}: only ~/ is expanded, not ~user; use an absolute path")
    return path


def privkey_path() -> str:
    # Unset or empty means the default, as in agent-setup.sh --fingerprint.
    # An error names what the path came from, not a variable nobody set.
    value = os.environ.get(PRIVKEY_ENV)
    if value:
        return expand_home(value, PRIVKEY_ENV)
    # HANDOFF_KEY_DIR is agent-setup.sh's, for making a key: here the default
    # key would be the wrong one (or missing, with no hint). Refused as
    # agent-setup.sh refuses it (issue #44 item 2); its value isn't shown.
    if os.environ.get(KEY_DIR_ENV):
        raise fail("HANDOFF_KEY_DIR is set but HANDOFF_PRIVKEY isn't: HANDOFF_KEY_DIR applies "
                   "only to agent-setup.sh making a key. Set HANDOFF_PRIVKEY="
                   "<dir>/handoff-identity.txt as the wrappers do (SETUP.md step 7)")
    return expand_home(DEFAULT_PRIVKEY, "the default key path")


def age_env() -> dict:
    """The environment for this helper's own age and age-keygen calls.

    Built from scratch, PATH only: age reads AGE_PASSPHRASE,
    AGE_PASSPHRASE_FD, AGE_PASSPHRASE_WORK_FACTOR,
    AGE_PASSPHRASE_MAX_WORK_FACTOR and AGEDEBUG (age 1.3.2), and none of them
    may reach it. Which age runs is still the PATH's choice, which is the
    wrapper's job, with its env -i and PATH= line (SETUP.md step 7).
    """
    return {"PATH": os.environ.get("PATH", os.defpath)}


def age_missing(tool: str) -> "SystemExit":
    path = age_env()["PATH"]
    if len(path) > 300:
        path = path[:300] + "..."
    return fail(f"{tool} not found on this PATH (in a wrapper, its PATH= line); "
                f"install age: README.md, Installing age (PATH was {path!r})")


def age_cannot_run(tool: str, e: OSError) -> "SystemExit":
    path = age_env()["PATH"]
    if len(path) > 300:
        path = path[:300] + "..."
    return fail(f"cannot run {tool}: {e.strerror} (PATH was {path!r})")


def check_age() -> str:
    """Return `age --version`'s first line, or refuse if age can't run."""
    try:
        out = subprocess.run(
            ["age", "--version"], capture_output=True, env=age_env(),
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        raise age_missing("age") from None
    except OSError as e:
        raise age_cannot_run("age", e) from None
    lines = out.stdout.decode("utf-8", "replace").strip().splitlines()
    if out.returncode != 0 or not lines:
        raise fail("age --version failed; install a working age: README.md, Installing age")
    return "".join(ch for ch in lines[0] if ch.isprintable())[:40]


def check_age_header(raw: bytes) -> None:
    """Refuse anything but a binary age file for exactly one X25519 recipient.

    Parses the text header up to its "---" MAC line before any decryption,
    so a header that asks `age` for a passphrase, a plugin or an SSH key
    never reaches it. A stanza is accepted only if its type is X25519 or
    ends in "-grease". Messages never include stanza contents.
    """
    if raw.startswith(AGE_ARMOR_BEGIN):
        raise fail(armored_message())
    if not raw.startswith(AGE_MAGIC):
        hint = ""
        if len(raw) == RSA_BLOB_BYTES_010:
            hint = " (0.2.0 uses age: a 0.1.0 install sets up again)"
        raise fail("not an age blob" + hint)
    x25519 = 0
    in_stanza = False
    done = False
    for line in raw[len(AGE_MAGIC):MAX_BLOB_BYTES].split(b"\n"):
        if line == b"---" or line.startswith(b"--- "):
            done = True
            break
        if line.startswith(b"-> "):
            in_stanza = True
            kind = line[3:].split(b" ", 1)[0]
            if kind == b"X25519":
                x25519 += 1
            elif not kind.endswith(b"-grease"):
                raise fail("age blob of a kind this helper doesn't open: "
                           "only X25519 recipients are supported")
        elif not in_stanza:
            raise fail("not an age blob: the header is malformed")
    if not done:
        raise fail("not an age blob: the header has no end line")
    if x25519 != 1:
        raise fail("age blob needs exactly one X25519 recipient")


def armored_message() -> str:
    return ("the blob is armored (ASCII-armored age text); "
            "give the binary age format, base64 on one line")


def decode_blob(blob_b64: str) -> bytes:
    # An armored file pasted as it is, before the base64 decode sees it: its
    # BEGIN line anywhere, so lines a shell joined (echo $A) are caught too
    # (#66 F15). Its spaces can't be part of base64.
    if AGE_ARMOR_BEGIN.decode("ascii").strip("-") in blob_b64:
        raise fail(armored_message())
    # handoff.sh's and handoff.ps1's framing lines, kept with the blob (#43
    # item 16): only the line between them is the blob.
    if "--- paste everything below" in blob_b64 or "--- end ---" in blob_b64:
        raise fail("input is not valid base64: it still has the '--- paste everything below "
                   "... ---' or '--- end ---' line the handoff script prints; give only the "
                   "line between them")
    # Tolerate line wrapping from a paste: strip ALL whitespace.
    compact = "".join(blob_b64.split())
    if not compact:
        raise fail("the blob is empty")
    if len(compact) > MAX_BLOB_FILE:
        raise fail(f"the blob is over {MAX_BLOB_FILE} characters; not a blob")
    try:
        raw = base64.b64decode(compact, validate=True)
    except Exception:
        # Padding inside the text: one blob's "==" followed by another's.
        if re.search(r"={1,2}[A-Za-z0-9+/]", compact):
            raise fail("input is not valid base64: it looks like several blobs "
                       "concatenated (an appending redirect?); give one")
        raise fail("input is not valid base64")
    check_age_header(raw)
    return raw


def read_identity(path: str) -> bytes:
    """The identity file's bytes, after the file checks.

    A regular file (a symbolic link is refused, and the open doesn't follow
    one), owner-only, owned by this user, and small. The checks run before
    the open, so a file this user can't read is refused for what it is, and
    again on the open file, so they describe what is read.
    """
    try:
        lst = os.lstat(path)
    except OSError:
        raise fail(f"cannot read private key at {path!r}") from None
    if stat.S_ISLNK(lst.st_mode):
        raise fail(f"private key at {path!r} is a symbolic link; "
                   "give the identity file itself. Refusing.")
    check_identity_stat(path, lst)
    check_key_dir(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0))
    except OSError:
        raise fail(f"cannot read private key at {path!r}") from None
    with os.fdopen(fd, "rb") as f:
        check_identity_stat(path, os.fstat(f.fileno()))
        return f.read(MAX_KEY_FILE + 1)


def check_key_dir(path: str) -> None:
    """The key's directory (followed through a symlink, as the key is read
    through it) must be owned by this user or root and writable by no group
    or other: anyone else who can write there can rename another file over
    the key, or add one beside it (agent-setup.sh makes it 0700). No sticky
    exception, unlike a blob's directory: the sticky bit stops renames, not
    new files beside the key, and a key directory has no reason to be shared.
    (The sticky bit changes only the advice: move the key, not chmod.)"""
    if os.name == "nt":
        return
    # Absolute but not normalized: abspath would fold a ".." by its text,
    # while the kernel follows it through the real directories (a symlink
    # then ..), so the directory checked must be the one the open walks.
    directory = os.path.dirname(os.path.join(os.getcwd(), path))
    try:
        dst = os.stat(directory)
    except OSError as e:
        raise fail(f"cannot read the key's directory {directory!r}: {e.strerror}") from None
    move = ("stop and report it to the user: the key belongs in a directory only this "
            "account can write (SETUP.md step 1)")
    if dst.st_uid not in (os.geteuid(), 0):
        raise fail(f"the key's directory {directory!r} is owned by another account; {move}")
    if dst.st_mode & 0o022:
        # chmod is the fix only for this account's own directory: on a shared
        # one (/tmp, owned by root) it would break the directory for everyone.
        # A sticky, world-writable directory is a shared one whoever owns it
        # (root owns /tmp, so an agent running as root would own it).
        shared = dst.st_mode & stat.S_ISVTX and dst.st_mode & 0o002
        if dst.st_uid == os.geteuid() and not shared:
            fix = f"stop and report it to the user, who runs: chmod -- go-w {shell_quote(directory)}"
        else:
            fix = move
        raise fail(f"the key's directory {directory!r} is writable by others (mode "
                   f"{stat.S_IMODE(dst.st_mode):04o}); {fix}")


def check_identity_stat(path: str, st: os.stat_result) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise fail(f"cannot read private key at {path!r}")
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise fail(
            f"private key at {path!r} is mode {mode:03o}; "
            "it must be owner-only (0600). Refusing."
        )
    if st.st_uid != os.geteuid():
        raise fail(f"private key at {path!r} is not owned by this user. Refusing.")
    if st.st_size > MAX_KEY_FILE:
        raise fail(
            f"private key at {path!r} is {st.st_size} bytes, over {MAX_KEY_FILE}; "
            "not an age identity file"
        )


def check_key(privkey: str) -> str:
    """The identity's recipient, after load_key's checks."""
    return load_key(privkey)[0]


def load_key(privkey: str) -> "tuple[str, bytes]":
    """Refuse a key file that isn't an owner-only age identity.

    Exactly one AGE-SECRET-KEY-1 line (comment and blank lines aside), no
    plugin or post-quantum identity, and nothing else. Returns the identity's
    recipient (`age-keygen -y`), which names the key whatever the file's
    comments say, and the bytes checked, which are what age is given
    (age_decrypt): age never opens the key's path itself. Nothing in a
    message comes from the file's contents.
    """
    data = read_identity(privkey)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None and any(
            f"-----BEGIN {kind}-----" in text
            for kind in ("RSA PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY")):
        raise fail(f"the key at {privkey!r} is an RSA key from 0.1.0; 0.2.0 uses age: "
                   "a 0.1.0 install sets up again (README.md)")
    not_identity = f"the file at {privkey!r} is not an age identity file"
    if text is None:
        raise fail(not_identity)
    secrets = 0
    recipient = False
    # Lines split on \n alone, as age and agent-setup.sh split them:
    # splitlines() would also break on \f, \v and U+2028 (issue #43 item 18).
    for line in text.split("\n"):
        line = line.rstrip("\r")
        if not line.strip() or line.startswith("#"):
            continue
        if line.startswith("AGE-PLUGIN-"):
            raise fail(f"the identity at {privkey!r} holds a plugin identity; "
                       "only a plain age identity is supported")
        if line.startswith("AGE-SECRET-KEY-PQ-1"):
            raise fail(f"the identity at {privkey!r} is a post-quantum identity; "
                       "only a plain age identity is supported")
        if AGE_SECRET_RE.fullmatch(line):
            secrets += 1
        elif AGE_RECIPIENT_RE.fullmatch(line):
            recipient = True
        else:
            raise fail(not_identity)
    if secrets == 0:
        raise fail(not_identity + (
            "; that is a recipient (public), not an identity" if recipient else ""))
    if secrets > 1:
        raise fail(f"the identity at {privkey!r} holds {secrets} secret keys; "
                   "it must hold exactly one")
    if recipient:
        raise fail(not_identity)
    # The bytes just checked go to age-keygen on its stdin, so what it reads
    # is what was checked.
    try:
        proc = subprocess.run(
            ["age-keygen", "-y"], input=data, capture_output=True, env=age_env(),
        )
    except FileNotFoundError:
        raise age_missing("age-keygen") from None
    except OSError as e:
        raise age_cannot_run("age-keygen", e) from None
    out = proc.stdout.decode("utf-8", "replace").strip()
    if proc.returncode != 0 or not AGE_RECIPIENT_RE.fullmatch(out):
        # age-keygen's own text is not shown.
        raise fail(f"cannot load the age identity at {privkey!r}")
    return out, data


def age_decrypt(raw: bytes, identity: bytes) -> "bytes | None":
    """age -d on raw with the identity bytes load_key checked: the
    plaintext, or None if age said no.

    The identity goes to age on a pipe of its own (`-i /dev/fd/N`), never by
    the key's path, so what age reads is what was checked, whatever happens
    to the file meanwhile. A thread writes it, so an identity bigger than a
    pipe's buffer can't block. The blob goes in through another pipe of
    age's own (never the caller's stdin), and age's stderr is not shown:
    what it says depends on the blob.
    """
    r, w = os.pipe()
    writer = threading.Thread(target=write_all_close, args=(w, identity), daemon=True)
    try:
        # The name age opens for the inherited fd: /dev/fd/N, or Linux's
        # /proc/self/fd/N where /dev/fd is missing (a chroot, a minimal
        # container). Neither: a clear refusal, not a "wrong key" one.
        fd_path = next((p % r for p in ("/dev/fd/%d", "/proc/self/fd/%d")
                        if os.path.exists(p % r)), None)
        if fd_path is None:
            os.close(w)
            raise fail("neither /dev/fd nor /proc/self/fd is available, so the identity "
                       "can't be handed to age on a pipe; stop and report it to the user")
        try:
            writer.start()
        except RuntimeError:
            os.close(w)
            raise fail("cannot start a thread to hand the identity to age") from None
        try:
            proc = subprocess.run(
                ["age", "-d", "-i", fd_path],
                input=raw, capture_output=True, env=age_env(), pass_fds=(r,),
            )
        except FileNotFoundError:
            raise age_missing("age") from None
        except OSError as e:
            raise age_cannot_run("age", e) from None
    finally:
        os.close(r)
        if writer.ident is not None:
            writer.join()
    if proc.returncode != 0:
        return None
    return proc.stdout


def write_all_close(fd: int, data: bytes) -> None:
    """Write data to fd and close it; a reader that has gone (EPIPE) ends it."""
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    except OSError:
        pass
    finally:
        os.close(fd)


def decrypt(blob_b64: str, current: str, previous: str) -> "tuple[bytes, str]":
    """Decrypt with the current key, else the previous one.

    Returns the plaintext bytes and which key opened it ("current" or
    "previous"). The previous key is <current key path>.previous, which
    exists only during a rotation (agent-setup.sh --rotate makes it,
    --retire deletes it); it is checked like the current key, and tried
    only when the current key can't decrypt the blob. The keys are tried one
    at a time, so the caller can say which one opened it.
    """
    raw = decode_blob(blob_b64)
    version = check_age()
    plain = age_decrypt(raw, load_key(current)[1])
    if plain is not None:
        return plain, "current"
    tried = f"decryption failed with the key at {current!r}"
    if os.path.lexists(previous):
        plain = age_decrypt(raw, load_key(previous)[1])
        if plain is not None:
            return plain, "previous"
        tried = (f"decryption failed with the current key ({current!r}) "
                 f"and with the previous key ({previous!r})")
    if os.path.lexists(previous + ".previous"):
        # Most likely a --rotate given the .previous key, which releases up
        # to 0.2.0 allowed: the old key may be there, with or without a
        # .previous beside the current key (issue #46).
        tried += (f", and {previous + '.previous'!r} exists "
                  "(ROTATION.md: A .previous.previous file)")
    # One fixed message, whichever key failed and however, without age's
    # own text, which depends on the blob. It names the key files it tried
    # (paths, never payload data) and the age that ran. It's a stop condition:
    # retrying with another HANDOFF_PRIVKEY is the "variation" SETUP.md forbids.
    raise fail(
        tried + f" (a blob made for another key, or a damaged one; age {version}): "
        "stop and report it to the user (SETUP.md, stop conditions)"
    )


BLOB_FILE_READ = None  # the blob file's identity when it was read (--rewrap rechecks it)
WRITTEN = None         # set once --rewrap's rename is done: what an interrupt then reports


def shell_quote(s: str) -> str:
    """POSIX single-quoting, for a command shown to the user to run."""
    return "'" + s.replace("'", "'\\''") + "'"


def file_identity(st: os.stat_result) -> tuple:
    # ctime too: every blob is the same size, and an mtime can be set back
    # (touch -r, cp -p), but the ctime can't be from user space. Best-effort on
    # NFS and CIFS, whose attributes can be cached.
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def under_dir(target: str, directory: str) -> bool:
    """Whether target is at or under directory: by path, and by identity
    (st_dev, st_ino) of each of target's parents, so a bind mount or a
    case-insensitive spelling of the directory is caught too."""
    try:
        if os.path.commonpath([directory, target]) == directory:
            return True
    except ValueError:  # Windows: another drive
        pass
    try:
        d = os.stat(directory)
    except OSError as e:
        raise fail(f"cannot check the key's directory {directory!r}: {e.strerror}") from None
    want = (d.st_dev, d.st_ino)
    p = target
    while True:
        try:
            st = os.stat(p)
            if (st.st_dev, st.st_ino) == want:
                return True
        except OSError:
            pass  # the target itself may not exist; its parents are what count
        parent = os.path.dirname(p)
        if parent == p:
            return False
        p = parent


# The --rewrap blob file as the user gave it (made absolute, symlinks not
# followed), keyed by its resolved path. Messages name the blob the way they
# name the key paths: on macOS /var is a symlink to /private/var, and a blob
# in resolved form beside a key in given form reads as two places. The
# resolved path is still what is checked and written.
SHOWN_AS: "dict[str, str]" = {}


def shown(path: str) -> str:
    return SHOWN_AS.get(path, path)


def both(given: str, resolved: str) -> str:
    """A path as the user gave it, and, when that is another spelling of the
    place that was checked (a symlink, macOS /var), the place too."""
    if given == resolved:
        return repr(resolved)
    return f"{given!r} (that is {resolved!r})"


def check_blob_file(path: str) -> os.stat_result:
    """--rewrap's checks on its blob file, run before anything else is
    decided about it (an already-current blob included)."""
    directory = os.path.dirname(path)
    try:
        st = os.stat(path)
    except OSError as e:
        raise fail(f"cannot read the blob file {shown(path)!r}: {e.strerror}") from None
    # Windows reports any writable file as 0o666: no group or world bits to read.
    if os.name != "nt":
        # Group- or world-writable: anyone who can write it can plant a blob,
        # and anyone who can write its own directory (without the sticky bit)
        # can rename another file over it. Only the immediate directory is
        # checked: a writable ancestor is the store's setup to get right
        # (SETUP.md, step 6). The file and its directory must also be owned by
        # this account or root: another account that owns either can change
        # it whatever its mode. The chmod in the advice is given only for what
        # this account owns, since no other chmod would work.
        try:
            dst = os.stat(directory)
        except OSError as e:
            raise fail(f"cannot read the blob file's directory {both(os.path.dirname(shown(path)), directory)}: {e.strerror}") from None
        shown_dir = both(os.path.dirname(shown(path)), directory)
        move = ("stop and report it to the user: a blob file belongs in a store only this "
                "account can write (SETUP.md step 6)")
        mine = (os.geteuid(), 0)
        if st.st_uid not in mine:
            raise fail(f"the blob file {both(shown(path), path)} is owned by another account; {move}")
        if dst.st_uid not in mine:
            raise fail(f"the blob file's directory {shown_dir} is owned by another account; {move}")
        if st.st_mode & 0o022:
            fix = (f"stop and report it to the user, who runs: chmod go-w {shell_quote(path)}"
                   if st.st_uid == os.geteuid() else move)
            raise fail(f"the blob file {both(shown(path), path)} is writable by others (mode "
                       f"{stat.S_IMODE(st.st_mode):04o}); {fix}")
        if dst.st_mode & 0o022 and not dst.st_mode & stat.S_ISVTX:
            fix = (f"stop and report it to the user, who runs: chmod go-w {shell_quote(directory)}"
                   if dst.st_uid == os.geteuid() else move)
            raise fail(f"the blob file's directory {shown_dir} is writable by others "
                       f"(mode {stat.S_IMODE(dst.st_mode):04o}); {fix}")
    if BLOB_FILE_READ is not None and file_identity(st) != BLOB_FILE_READ:
        raise fail(f"the blob file {shown(path)!r} changed since it was read (a blob staged "
                   "meanwhile?); it is left as it is now: probe the label (ROTATION.md "
                   "step 4)")
    return st


def write_atomically(path: str, data: bytes) -> None:
    """Replace path with data: a temporary file beside it, synced, read back
    and checked, then renamed over it. Any failure leaves path as it was."""
    directory = os.path.dirname(path)
    st = check_blob_file(path)
    mode = stat.S_IMODE(st.st_mode)
    global WRITTEN
    tmp = None
    renamed = False
    try:
        # The basename cut to at most 100 bytes on a character boundary, so
        # the temporary name stays under NAME_MAX and is still valid text.
        short = os.path.basename(path)
        while len(os.fsencode(short)) > 100:
            short = short[:-1]
        try:
            fd, tmp = tempfile.mkstemp(prefix="." + short + ".", suffix=".rewrap",
                                       dir=directory)
        except OSError as e:
            why = (" (the temporary file goes in the same directory, so that directory "
                   "must be writable)" if e.errno in (errno.EACCES, errno.EROFS) else "")
            raise fail(f"could not write the new blob beside {shown(path)!r}: {e.strerror}{why}; "
                       "it is unchanged") from None
        with os.fdopen(fd, "wb") as fh:
            if hasattr(os, "fchmod"):
                os.fchmod(fh.fileno(), mode)
            if hasattr(os, "fchown"):
                try:
                    os.fchown(fh.fileno(), -1, st.st_gid)  # keep its group, where allowed
                except OSError:
                    pass
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        with open(tmp, "rb") as fh:
            if fh.read(len(data) + 1) != data:
                raise fail(f"the new blob didn't read back whole from the temporary file beside it; {shown(path)!r} is unchanged")
        # The file must still be the one read: a blob staged while this ran
        # isn't replaced with the old payload.
        if BLOB_FILE_READ is not None and file_identity(os.stat(path)) != BLOB_FILE_READ:
            raise fail(f"the blob file {shown(path)!r} changed while it was being rewrapped (a "
                       "blob staged meanwhile?); it is left as it is now: probe the label "
                       "(ROTATION.md step 4)")
        # TERM, HUP and INT blocked around the rename and the two flags, where
        # the platform can (not Windows): a signal then lands after them, so
        # what an interrupt reports always matches the file.
        sigs = {getattr(signal, n) for n in ("SIGINT", "SIGTERM", "SIGHUP")
                if hasattr(signal, n)}
        # The mask as it is, read with nothing changed: a signal pending now
        # runs its handler here, before anything is blocked. The block itself
        # is inside the try (#9 item 10), so a handler run as it returns still
        # gets the mask restored.
        mask = (signal.pthread_sigmask(signal.SIG_BLOCK, ())
                if hasattr(signal, "pthread_sigmask") else None)
        try:
            if mask is not None:
                signal.pthread_sigmask(signal.SIG_BLOCK, sigs)
            os.replace(tmp, path)
            renamed = True
            WRITTEN = path
        finally:
            if mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        tmp = None
        try:
            dfd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass  # some platforms can't sync a directory; the rename is done
    except OSError as e:
        raise fail(f"could not write the new blob to {shown(path)!r}: {e.strerror}; it is unchanged") from None
    except KeyboardInterrupt:
        # After the rename, the file already holds the new blob.
        if renamed or (tmp is not None and not os.path.lexists(tmp)):
            tmp = None
            WRITTEN = path
            raise fail(f"interrupted after the rename; {shown(path)!r} holds the new blob "
                       "(probe the label: ROTATION.md step 4)") from None
        raise fail(f"interrupted; {shown(path)!r} is unchanged") from None
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def parse_payload(plaintext: bytes) -> dict:
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception:
        raise fail("decrypted payload is not valid JSON")
    if not isinstance(payload, dict):
        raise fail("decrypted payload is not a JSON object")
    return payload


def age_encrypt(plaintext: bytes, recipient: str) -> bytes:
    """age -r RECIPIENT on plaintext: the binary age file.

    The plaintext goes in through a pipe of age's own, the environment is
    age_env()'s, and age's stderr is not shown. Refuses, with one fixed
    message, when age fails or its output isn't a binary age file.
    """
    try:
        proc = subprocess.run(
            ["age", "-r", recipient], input=plaintext, capture_output=True,
            env=age_env(),
        )
    except FileNotFoundError:
        raise age_missing("age") from None
    except OSError as e:
        raise age_cannot_run("age", e) from None
    if proc.returncode != 0 or not proc.stdout.startswith(AGE_MAGIC):
        raise fail("re-encrypting to the current key failed")
    return proc.stdout


def rewrap(plaintext: bytes, current: str) -> str:
    """The same payload, byte for byte, encrypted to the current key.

    Checked before it's returned: the new blob must open with the current
    key to exactly this payload, since it replaces the old blob in the store
    with no copy kept (ROTATION.md).
    """
    recipient, identity = load_key(current)
    blob = age_encrypt(plaintext, recipient)
    back = age_decrypt(blob, identity)
    if back is None or back != plaintext:
        raise fail("the new blob doesn't open with the current key to the same "
                   "payload; keep the old blob, and report this")
    return base64.b64encode(blob).decode("ascii")


def check_payload(payload: dict, label: str, env_map: dict) -> dict:
    """Validate binding and field shapes; return the credential fields."""
    svc = payload.get("svc")
    if svc is None:
        raise fail("payload has no 'svc' field; purpose binding is required")
    if svc != label:
        # Never print the payload's svc: payloads are unauthenticated, and
        # this text lands in the agent's tool output.
        raise fail(f"purpose mismatch: payload does not belong to label {label!r}. Refusing.")
    creds = {}
    unknown = 0
    for name, value in payload.items():
        if name == "svc":
            continue
        if name not in env_map:
            unknown += 1
            continue
        if not isinstance(value, str):
            raise fail("a credential field is not a string; refusing")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate from a \ud800-style escape. Say nothing about
            # it: the exception's own text would quote the character.
            raise fail("a credential field is not valid UTF-8 text; refusing") from None
        if "\0" in value:
            raise fail("a credential field contains a NUL byte; refusing")
        if not value:
            # An empty value would start the command with the variable set
            # but no credential in it.
            raise fail("a credential field is empty; refusing")
        creds[name] = value
    if unknown:
        print(f"consume.py: ignoring {unknown} unknown field(s)", file=sys.stderr)
    if not creds:
        raise fail("payload contains no known credential field; refusing to run")
    return creds


def check_env_name(name: str) -> None:
    if not ENV_NAME_RE.fullmatch(name):
        raise fail(f"--env target {name!r} is not a valid variable name")
    upper = name.upper()
    # The shell's own names and the refused list first: their messages say
    # what such a name does.
    if upper in SHELL_OWN_NAMES:
        raise fail(
            f"--env target {name!r} is the shell's own (who runs, or where): it isn't "
            "a credential's variable; refusing (a tool's credential goes in a name of "
            "its own, such as APP_USER or APP_PWD)"
        )
    if upper in REFUSED_ENV_NAMES or upper.startswith(REFUSED_ENV_PREFIXES):
        raise fail(
            f"--env target {name!r} is on the refused list: it changes what the "
            "command runs or where it connects; refusing"
        )
    if not CREDENTIAL_NAME_RE.fullmatch(upper):
        raise fail(
            f"--env target {name!r} isn't a credential variable's name: it must end in "
            "one of " + ", ".join(CREDENTIAL_WORDS) + " (after a _, or the whole name; "
            + ", ".join(CREDENTIAL_WORDS_UNSEPARATED) + " without one too). "
            "Refusing: a name a program reads for anything else could change what it "
            "runs or whom it trusts (SETUP.md step 7)"
        )
    # An AUTH name that is a switch, not a credential (NO_AUTH, DISABLE_AUTH,
    # INSECURE_SKIP_AUTH): its value would turn a check off.
    parts = upper.split("_")
    if parts[-1] == "AUTH" and AUTH_SWITCH_WORDS & set(parts[:-1]):
        raise fail(
            f"--env target {name!r} reads as a switch that turns authentication off, "
            "not a credential's variable; refusing (SETUP.md step 7)"
        )


# The options that take a value: parse_args reads them, and help_asked walks
# argv the same way, so both use this one tuple.
VALUE_OPTIONS = ("--label", "--blob", "--blob-file", "--env")


def parse_args(argv):
    label = None
    check = False
    do_rewrap = False
    blob = None
    blob_file = None
    env_map = dict(DEFAULT_ENV_MAP)
    remapped = set()
    seen = set()
    cmd = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            cmd = argv[i + 1:]
            break
        if a in ("--label", "--blob", "--blob-file", "--check", "--rewrap"):
            # Each at most once: a backstop if a wrapper wrongly passes its
            # caller's arguments (SETUP.md says it never does), so at least
            # the label can't be overridden.
            if a in seen:
                raise fail(f"{a} given twice")
            seen.add(a)
        if a in VALUE_OPTIONS:
            i += 1
            if i >= len(argv):
                raise fail(f"{a} needs a value")
            v = argv[i]
            if a == "--label":
                label = v
            elif a == "--blob":
                blob = v
            elif a == "--blob-file":
                blob_file = v
            else:
                if "=" not in v:
                    raise fail("--env takes field=NAME")
                field, name = v.split("=", 1)
                if not field or not name:
                    raise fail("--env takes field=NAME")
                # Only the known credential fields can be remapped: a typo
                # (pasword=APP_PASS) would otherwise add a field no payload
                # has, and the command would start without APP_PASS. New
                # fields are a payload-schema change (SETUP.md).
                if field not in DEFAULT_ENV_MAP:
                    raise fail(f"--env field {field!r} is not a known credential field")
                if field in remapped:
                    raise fail(f"--env maps {field!r} twice")
                remapped.add(field)
                check_env_name(name)
                env_map[field] = name
        elif a == "--check":
            check = True
        elif a == "--rewrap":
            do_rewrap = True
        else:
            raise fail(f"unrecognized argument: {a!r}")
        i += 1
    # Counted over the whole map, the default mappings included: a payload
    # may carry any known field, so no two may ever share a target.
    targets = list(env_map.values())
    if len(set(targets)) != len(targets):
        raise fail("two fields map to the same environment variable; refusing")
    if not label:
        raise fail("--label is required (the service label the blob was fetched under)")
    if check and do_rewrap:
        raise fail("--check and --rewrap can't be combined")
    if check and cmd:
        raise fail("--check takes no command; it only inspects the payload")
    if do_rewrap and cmd:
        raise fail("--rewrap takes no command; it rewrites its --blob-file in place")
    if do_rewrap and remapped:
        raise fail("--rewrap takes no --env; it re-encrypts the payload as it is")
    if do_rewrap and blob_file is None:
        raise fail("--rewrap rewrites its --blob-file in place, so it needs --blob-file "
                   "(the label's own stored blob, or a fetched copy of it: ROTATION.md "
                   "step 4)")
    if not (check or do_rewrap) and (not cmd or not cmd[0]):
        raise fail("no command given after -- (or use --check or --rewrap)")
    sources = [s for s, given in (
        ("--blob", blob is not None),
        ("--blob-file", blob_file is not None),
        (f"${BLOB_ENV}", BLOB_ENV in os.environ),
    ) if given]
    if len(sources) > 1:
        raise fail(f"more than one blob source ({', '.join(sources)}); give exactly one")
    if blob_file is not None:
        if not blob_file:
            raise fail("--blob-file is empty")
        path = expand_home(blob_file, "--blob-file")
        not_regular = (
            f"blob file at {blob_file!r} is not a regular file (a "
            "directory, pipe, FIFO or device); give the blob with "
            "--blob or $HANDOFF_BLOB"
        )
        try:
            # A regular file only: /dev/stdin, a pipe or a tty would take
            # the command's stdin. Checked before opening, since opening a
            # device can act on it (a tty can become the controlling
            # terminal), and again on the open descriptor, in case the path
            # changed in between. Opened non-blocking and without taking a
            # controlling terminal, so even that race can't hang or attach.
            # (A redirect from a file, < blob.txt, is a regular file and
            # isn't caught here.)
            if not stat.S_ISREG(os.stat(path).st_mode):
                raise fail(not_regular)
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOCTTY", 0))
            read_st = os.fstat(fd)
            if not stat.S_ISREG(read_st.st_mode):
                os.close(fd)
                raise fail(not_regular)
            global BLOB_FILE_READ
            BLOB_FILE_READ = file_identity(read_st)
            # utf-8-sig: some editors save a byte-order mark first.
            with os.fdopen(fd, "r", encoding="utf-8-sig") as fh:
                blob = fh.read(MAX_BLOB_FILE_RAW + 1)
        except OSError as e:
            # strerror comes from the OS, never from the file's contents.
            raise fail(f"cannot read blob file at {blob_file!r}: {e.strerror}") from None
        except UnicodeError:
            raise fail(f"cannot read blob file at {blob_file!r} as text") from None
        if len(blob) > MAX_BLOB_FILE_RAW:
            raise fail(f"blob file at {blob_file!r} is over {MAX_BLOB_FILE_RAW} characters "
                       "(line breaks and blanks included); not a blob")
    if blob is None:
        blob = os.environ.get(BLOB_ENV)
    if blob is None:
        raise fail(f"no blob supplied: use --blob, --blob-file, or ${BLOB_ENV}")
    target = os.path.realpath(expand_home(blob_file, "--blob-file")) if do_rewrap else None
    if do_rewrap:
        SHOWN_AS[target] = os.path.abspath(expand_home(blob_file, "--blob-file"))
    return label, check, do_rewrap, target, blob, env_map, cmd


def fix_std_fds() -> None:
    """Put /dev/null on a closed stdin, stdout or stderr, and on a stdout or
    stderr open read-only: the ./consume.py launcher, started with stderr
    closed, has its own script on fd 2. Without this, a note would fail at
    flush (exit 120, after a --rewrap's write), or go to stdout, which for a
    stdio MCP server is its transport. What is open and usable is left as
    it is: it's the command's."""
    try:
        import fcntl
    except ImportError:  # Windows: only a closed descriptor can be seen
        fcntl = None
    for fd, mode in ((0, os.O_RDONLY), (1, os.O_WRONLY), (2, os.O_WRONLY)):
        name = ("stdin", "stdout", "stderr")[fd]
        try:
            os.fstat(fd)
            # None: the descriptor was closed when Python started, and
            # whatever holds that number now isn't the caller's.
            usable = getattr(sys, name) is not None and (
                fcntl is None or fd == 0 or
                fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY)
        except OSError:
            usable = False
        if usable:
            continue
        null = os.open(os.devnull, mode)
        if null != fd:
            os.dup2(null, fd)
            os.close(null)
        stream = open(fd, "w" if fd else "r", closefd=False)
        setattr(sys, name, stream)


def help_asked(argv) -> bool:
    """Whether -h or --help is one of the helper's own options. Walks argv
    as parse_args does: an option that takes a value consumes the next
    argument, whatever it is (--label --help is a label, and --label -- sets
    the label to "--"), and the first "--" that isn't a value starts the
    command. Unlike parse_args, it skips over an argument it doesn't
    recognize, so --help after a typo still prints the usage."""
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            return False
        if a in ("-h", "--help"):
            return True
        i += 2 if a in VALUE_OPTIONS else 1
    return False


def main() -> int:
    fix_std_fds()
    if sys.version_info < (3, 7):
        # capture_output and text= need 3.7; say so instead of a traceback.
        print("consume.py: requires Python 3.7 or later", file=sys.stderr)
        return 1
    if help_asked(sys.argv[1:]):
        # __doc__ is None under python3 -OO; the usage then is the one line.
        doc = __doc__ or ""
        print(doc[doc.index("Usage:"):].rstrip() if "Usage:" in doc else
              "usage: consume.py --label LABEL [--env field=NAME ...] "
              "[--blob B | --blob-file F] (--check | --rewrap | -- command ...)")
        return 0
    if LABEL_ENV in os.environ:
        # Set by a consume.py that is running the command this call came
        # from: wrappers never nest. The value is the outer label, which the
        # caller controls: not echoed.
        raise fail(
            f"${LABEL_ENV} is set (normally by an outer consume.py, for the "
            "command it started), and wrappers never nest (SETUP.md step 7). Refusing. "
            "Don't unset it to get past this: report it to the user."
        )
    label, check, do_rewrap, target, blob, env_map, cmd = parse_args(sys.argv[1:])
    # Run mode builds the command's environment from bytes. Every platform
    # this side runs on (Linux, macOS: SETUP.md step 1) has one; refused
    # before anything is decrypted where there isn't.
    if not (check or do_rewrap) and not os.supports_bytes_environ:
        raise fail("run mode needs Linux or macOS (SETUP.md step 1): this "
                   "platform has no bytes environment")
    current = privkey_path()
    if current.lower().endswith(".previous"):
        # A rotation's old key as the current one: the previous key would be
        # looked up at .previous.previous, and where one exists --rewrap would
        # encrypt to the old key (issue #46). Without case, as on macOS's
        # default volume.
        stem = current[:-len(".previous")]
        # A key file named just ".previous" has no current key to suggest.
        named = f", {stem!r}" if stem and not stem.endswith(os.sep) else ""
        raise fail(
            f"${PRIVKEY_ENV} ({current!r}) names a rotation's old key (its name ends in "
            f".previous); a wrapper sets it to the current key{named} "
            "(SETUP.md step 7). Refusing: report it to the user."
        )
    previous = current + ".previous"
    if do_rewrap and not os.path.lexists(previous):
        # "For the current key" means the label is done only during a
        # rotation, and only for the key the wrappers use: with no previous
        # key beside this one, HANDOFF_PRIVKEY names the wrong key, or there's
        # no rotation to rewrap for.
        raise fail(
            f"--rewrap: no rotation under way at {current!r} (no {previous!r}). "
            "Run it with HANDOFF_PRIVKEY as the label's wrappers set it, during "
            "a rotation (ROTATION.md); anything else, stop and report it."
        )
    if do_rewrap:
        check_age()
    # The same key, compared by its recipient (the identity's public half):
    # a copy with other comment lines is still it.
    if do_rewrap and check_key(current) == check_key(previous):
        # Between agent-setup.sh --rotate's two steps both names hold the old
        # key: a blob "for the current key" then is for the key being retired.
        raise fail(
            f"--rewrap: {previous!r} holds the same key as {current!r}: the rotation "
            "didn't finish, or a key file was replaced since. Nothing was written: "
            "stop, and do what ROTATION.md step 4 says."
        )
    if do_rewrap:
        # TERM and HUP end a --rewrap as INT does: a clean line, the file as it
        # was (write_atomically says which, before or after its rename).
        # Only where the signal has its default action: one inherited as
        # ignored (nohup, a background job) stays ignored.
        for name in ("SIGTERM", "SIGHUP"):
            sig = getattr(signal, name, None)
            if sig is not None and signal.getsignal(sig) == signal.SIG_DFL:
                signal.signal(sig, signal.default_int_handler)
        # Never anywhere under the key's directory: resolved for real (symlinks
        # and .. followed, as the kernel will), so no spelling of a path can
        # put the rewrite on a key, and a blob doesn't land beside it.
        # Both the directory the key file is in and the one the wrappers name
        # (a symlinked HANDOFF_PRIVKEY, where .previous is looked up).
        asked = os.path.dirname(os.path.abspath(current))
        # The directory is named as given when the key's own is that one (not
        # a symlinked key file, whose real directory is somewhere else).
        key_real = os.path.dirname(os.path.realpath(current))
        for key_dir, given_dir in ((key_real,
                                    asked if key_real == os.path.realpath(asked) else key_real),
                                   (os.path.realpath(asked), asked)):
            if under_dir(target, key_dir):
                raise fail(f"--rewrap's --blob-file {shown(target)!r} resolves to {target!r}, "
                           f"under the key's directory ({given_dir!r}"
                           + ("" if given_dir == key_dir else f", that is {key_dir!r}") + "); "
                           "the blob belongs in the store")
    plaintext, slot = decrypt(blob, current, previous)
    creds = check_payload(parse_payload(plaintext), label, env_map)
    if check:
        print(f"svc: matches label {label!r}")
        for name in sorted(creds):
            print(f"{name}: {len(creds[name].encode('utf-8'))} bytes")
        return 0
    if do_rewrap:
        check_blob_file(target)
        if slot == "current":
            # Already for the current key: rewriting it would only change the
            # bytes (age output is randomized) and confuse a comparison with the store.
            print(f"consume.py: the blob in {shown(target)!r} is already for the current key "
                  f"{current!r}; nothing written", file=sys.stderr)
            return 0
        # The new blob is ciphertext, written over the blob file only once it's
        # whole and checked.
        write_atomically(target, (rewrap(plaintext, current) + "\n").encode("ascii"))
        print(f"consume.py: rewrapped {shown(target)!r} to the current key {current!r}; the blob "
              f"was for the previous key ({previous!r})", file=sys.stderr)
        return 0
    # The two rotation lines start with a newline: the wrapper's fetch writes
    # to the same stderr first, and store-controlled text left without one
    # (a NUL, say: BSD grep then doesn't see the rest of that line) would
    # join onto them and hide them from the probe's count (issue #21 item 1).
    if slot == "current" and os.path.lexists(previous):
        # During a rotation, a positive line too: a probe's check is then for
        # a line that is there, not one that isn't.
        print(f"\nconsume.py: label {label!r} opened with the current key "
              "(a rotation is under way)", file=sys.stderr)
    if slot == "previous":
        # Nothing from the payload: which key file opened it.
        print(f"\nconsume.py: label {label!r} decrypted with the previous key; "
              "rewrap it once ROTATION.md step 3 is done", file=sys.stderr)
    # Built from bytes: each value goes to the command as its UTF-8 bytes, the
    # bytes the user encrypted, whatever this process's locale. With str
    # values, os.execvpe encodes them in the locale's encoding, so a non-UTF-8
    # locale gave a traceback or another password's bytes (issue #75).
    # Inherited variables pass through as the bytes they were (checked for a
    # bytes environment before the decrypt, in main). An entry with an empty
    # name, which a raw execve can pass, is dropped: os.execvpe refuses one
    # with a ValueError.
    env = {k: v for k, v in os.environb.items() if k}
    key = os.fsencode  # a variable's name, as the OS encodes names
    # The command needs the credentials, not the blob or the key's path.
    env.pop(key(BLOB_ENV), None)
    env.pop(key(PRIVKEY_ENV), None)
    # The default names and this call's targets come from this payload or
    # not at all: a value already in the caller's environment would otherwise
    # reach the command beside the payload's values (a planted blob with only
    # a username would run with the real password, and a nested wrapper would
    # hand service A's SERVICE_PASSWORD to service B). Other names pass
    # through (see the docstring on nesting).
    for target in set(env_map.values()) | set(DEFAULT_ENV_MAP.values()):
        env.pop(key(target), None)
    for field, value in creds.items():
        # check_payload checked each value encodes as UTF-8.
        env[key(env_map[field])] = value.encode("utf-8")
    # The nesting marker: a consume.py the command starts refuses to run.
    # The label's value as it came in argv: os.fsencode undoes Python's
    # decoding of argv, giving those bytes back.
    env[key(LABEL_ENV)] = os.fsencode(label)
    # Deliberately no logging of env or creds here — that is the whole point.
    # exec, not a subprocess: the command takes over this process, so a
    # signal meant for the helper (an MCP client stopping its server sends
    # TERM) reaches the command itself, and no parent is left that could
    # exit and leave a credentialed child running. It also means this
    # process holds no copy of the plaintext after the hand-over. stdin,
    # stdout and stderr are inherited as they are (a closed or read-only
    # one is /dev/null since fix_std_fds): they are the command's.
    # Python ignores SIGPIPE and SIGXFSZ at startup, and an ignored signal
    # stays ignored across exec: give the command the defaults it would have
    # had if launched directly.
    for name in ("SIGPIPE", "SIGXFSZ"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), signal.SIG_DFL)
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        os.execvpe(cmd[0], cmd, env)
    except OSError as e:
        # Only the caller's own command name appears here, never payload data.
        code = 127 if isinstance(e, FileNotFoundError) else 126
        print(f"consume.py: cannot run {cmd[0]!r}: {e.strerror}", file=sys.stderr)
        return code
    return 0  # not reached: execvpe only returns by raising


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        if WRITTEN is not None:
            print(f"consume.py: interrupted after the rename; {shown(WRITTEN)!r} holds the new "
                  "blob (probe the label: ROTATION.md step 4)", file=sys.stderr)
        else:
            print("consume.py: interrupted; nothing written", file=sys.stderr)
        sys.exit(1)
