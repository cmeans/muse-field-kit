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
This helper decrypts IN MEMORY with the private key (default
~/.config/handoff/handoff-priv.pem, override with $HANDOFF_PRIVKEY),
verifies the payload's purpose binding, and either:

  run mode    replaces itself (exec) with a command, the credential values
              injected into its environment; the command's stdin, stdout
              and stderr are the helper's own, untouched, or
  --check     prints the svc match, then field names and value lengths
              ONLY. For the SETUP DUMMY round-trip only: lengths are output
              too, so never run --check on a real credential.

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
    svc                          -> purpose binding; never injected

Per-service variable names differ; map them per invocation instead of
editing this file:  --env username=APP_USER --env password=APP_PASS
Only the fields above can be mapped, each at most once. The default names
(SERVICE_*) and this call's mapped names are removed from the inherited
environment before the payload's values go in, along with $HANDOFF_BLOB
and $HANDOFF_PRIVKEY. Other variables pass through as inherited, including
a credential an outer wrapper mapped under a name this call doesn't use:
never nest wrappers (SETUP.md step 7).

A blob file must be a regular file. A pipe, a FIFO, a tty or a device
(so /dev/stdin on a pipe) and a process substitution (--blob-file
<(fetch)) are refused: give the blob with --blob "$(fetch </dev/null)"
or $HANDOFF_BLOB instead (the fetch must not read stdin, which belongs
to the command).

Exactly one blob source (--blob, --blob-file or $HANDOFF_BLOB), and
--label, --blob, --blob-file and --check at most once each. That is a
backstop for a wrongly written wrapper, not a license for one: a wrapper
passes no caller arguments at all (SETUP.md step 7), since a caller's
own --env or -- would otherwise pick where the credential goes. An empty
credential value is refused.
A target must be a plain variable name, never one that changes what the
command runs or where it connects (PATH, LD_*, PYTHON*, GIT_*, BASH_ENV,
the proxy and CA-bundle variables, ...; a partial list, in any case),
and two fields can't share one target, the default mappings included.
Mapped variables come from the payload only: one the payload leaves out is
removed from the command's environment, not inherited from the caller's.

Every payload must carry "svc", and it must equal the --label the blob
was fetched under; otherwise this helper refuses. A payload with unknown
fields is noted by COUNT only; a payload with no known credential field
at all is refused, so a typo'd payload can't silently launch a tool with
no credentials.

The injected values live in the command's environment for the life of
the command and are inherited by its children — and the target command
must not log its own environment or resolved config, and must never be
handed a credential on its command line (argv is world-readable).

Usage:
    HANDOFF_BLOB=$(cat blob.txt) consume.py --label example -- my-tool --serve
    consume.py --label example --blob-file blob.txt -- my-tool --serve
    consume.py --label test --check --blob-file blob.txt
"""
# Run as ./consume.py, the helper is isolated (python3 -I, see the top of
# the docstring): the caller's PYTHON* variables and user site-packages don't
# reach it. A wrapper that calls Python itself should run python3 -I too.
import base64
import json
import os
import re
import signal
import stat
import subprocess
import sys

DEFAULT_PRIVKEY = "~/.config/handoff/handoff-priv.pem"
PRIVKEY_ENV = "HANDOFF_PRIVKEY"
BLOB_ENV = "HANDOFF_BLOB"
CIPHERTEXT_BYTES = 256  # RSA-2048: every reference blob decodes to exactly this
MAX_KEY_FILE = 16384    # bytes; an RSA-2048 PEM key is about 1.7 KB
# An RSA-2048 public key in DER SubjectPublicKeyInfo form: always 294 bytes,
# starting with the rsaEncryption algorithm identifier.
RSA2048_SPKI_LEN = 294
RSA2048_SPKI_PREFIX = bytes.fromhex("30820122300d06092a864886f70d0101010500")
MAX_REASON = 300        # characters of openssl's error text shown
MAX_BLOB_FILE = 8192    # characters; a reference blob is 344

DEFAULT_ENV_MAP = {
    "username": "SERVICE_USERNAME",
    "password": "SERVICE_PASSWORD",
    "api_key_id": "SERVICE_API_KEY_ID",
    "api_key_secret": "SERVICE_API_KEY_SECRET",
    "token_id": "SERVICE_TOKEN_ID",
    "token_secret": "SERVICE_TOKEN_SECRET",
}

# --env target names: a plain identifier, and never one of the well-known
# variables that change which program runs or how it starts. Mapping a
# payload field onto PATH or GIT_SSH_COMMAND, for example, would let whoever
# wrote the payload choose what runs. This list is a partial backstop, not
# the control: no list can name every variable every program reads.
# What SETUP.md's hard rules record for each label is the control.
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Compared case-insensitively (curl and others read http_proxy as well as
# HTTP_PROXY). Two kinds: variables that change what code runs, and ones that
# change where the command connects or whom it trusts, which would let the
# payload's writer choose where the credential goes.
REFUSED_ENV_NAMES = {n.upper() for n in (
    # what runs, and how it starts
    "PATH", "HOME", "IFS", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "PS4",
    "PROMPT_COMMAND", "NODE_OPTIONS", "NODE_PATH", "PERL5OPT", "PERL5LIB",
    "PERLLIB", "PERL5DB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "GCONV_PATH",
    "GLIBC_TUNABLES", "LUA_INIT", "PAGER", "EDITOR", "VISUAL", "ZDOTDIR",
    "SSH_ASKPASS", "SSH_AUTH_SOCK", BLOB_ENV, PRIVKEY_ENV,
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
    return expand_home(DEFAULT_PRIVKEY, "the default key path")


def openssl_env() -> dict:
    """The environment for this helper's own openssl calls.

    Without OPENSSL_* variables, in any case: a stray or planted
    OPENSSL_CONF or OPENSSL_MODULES can't load a provider into the process
    that reads the private key. This guards against a config, not a caller
    who controls the environment (LD_PRELOAD would still pass), and which
    openssl runs is still the PATH's choice: both are the wrapper's job, with
    its env -i and PATH= line (SETUP.md step 7).
    """
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("OPENSSL_")}


def openssl_reason(stderr: str) -> str:
    """': <reason>' from openssl's stderr, or '' if it said nothing.

    The first line that isn't one of openssl's hex-prefixed internal error
    lines ("00B1...:error:...:store_result.c:157:") is usually the readable
    one; otherwise the last line.
    """
    lines = [ln for ln in stderr.strip().splitlines() if ln.strip()]
    if not lines:
        return ""
    readable = [ln for ln in lines if not re.match(r"^[0-9A-Fa-f]+:error:", ln)]
    reason = readable[0] if readable else lines[-1]
    if len(reason) > MAX_REASON:
        reason = reason[:MAX_REASON] + "..."
    return ": " + reason


def check_openssl() -> None:
    # The same gate as handoff.sh and agent-setup.sh, and the same hint as
    # agent-setup.sh (handoff.sh's leaves out wrappers):
    # LibreSSL's pkeyutl OAEP behavior is
    # unverified for this protocol.
    try:
        out = subprocess.run(
            ["openssl", "version"], capture_output=True, text=True, errors="replace",
            env=openssl_env(),
        )
    except FileNotFoundError:
        raise fail("openssl not found") from None
    version = out.stdout.strip()
    if out.returncode != 0:
        # openssl's own reason (a broken OPENSSL_CONF, a missing provider):
        # its stderr names configuration problems, never secrets.
        raise fail("openssl version failed" + openssl_reason(out.stderr))
    if not (version.startswith("OpenSSL 3.") or version.startswith("OpenSSL 4.")):
        raise fail(
            f"requires OpenSSL 3 or 4; found: {version or 'no version output'}. "
            "Put one first in the PATH this runs with (in a wrapper, its PATH= line)"
            + ("; on macOS, Homebrew's openssl@3" if sys.platform == "darwin" else "")
        )


def decrypt(blob_b64: str) -> dict:
    privkey = privkey_path()
    if not os.path.isfile(privkey):
        raise fail(f"cannot read private key at {privkey}")
    st = os.stat(privkey)
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise fail(
            f"private key at {privkey} is mode {mode:03o}; "
            "it must be owner-only (0600). Refusing."
        )
    if st.st_uid != os.geteuid():
        raise fail(f"private key at {privkey} is not owned by this user. Refusing.")
    if st.st_size > MAX_KEY_FILE:
        # openssl's decoder slows down badly on large non-key input: a wrong
        # HANDOFF_PRIVKEY pointing at a big file would hang the start.
        raise fail(
            f"private key at {privkey} is {st.st_size} bytes, over {MAX_KEY_FILE}; "
            "not an RSA-2048 key file"
        )
    # Tolerate line wrapping from a paste: strip ALL whitespace.
    compact = "".join(blob_b64.split())
    if not compact:
        raise fail("the blob is empty")
    try:
        cipher = base64.b64decode(compact, validate=True)
    except Exception:
        raise fail("input is not valid base64")
    if len(cipher) != CIPHERTEXT_BYTES:
        raise fail(
            f"the blob decodes to {len(cipher)} bytes, not {CIPHERTEXT_BYTES}: "
            "truncated, padded, or not a blob for an RSA-2048 key"
        )
    check_openssl()
    # Load the key on its own first, so a key that can't be read (a public
    # key, a damaged or passphrase-protected file) isn't reported as a bad
    # blob. openssl's stderr names key problems, never secrets.
    try:
        loaded = subprocess.run(
            # -passin pass:, as in the decrypt below: an encrypted key fails
            # here instead of prompting, and never reads a passphrase from
            # stdin (the command's transport) or a terminal. The public half
            # comes back as DER, to check the key type below.
            ["openssl", "pkey", "-in", privkey, "-passin", "pass:",
             "-pubout", "-outform", "DER"],
            capture_output=True, env=openssl_env(), stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        raise fail("openssl not found") from None
    if loaded.returncode != 0:
        raise fail(
            f"cannot load the private key at {privkey}"
            + openssl_reason(loaded.stderr.decode("utf-8", "replace"))
            + " (it must be an unencrypted RSA-2048 private key)"
        )
    spki = loaded.stdout
    if len(spki) != RSA2048_SPKI_LEN or not spki.startswith(RSA2048_SPKI_PREFIX):
        raise fail(
            f"the private key at {privkey} is not an RSA-2048 key; "
            "this protocol uses RSA-2048 only"
        )
    try:
        proc = subprocess.run(
            [
                "openssl", "pkeyutl", "-decrypt",
                "-inkey", privkey, "-passin", "pass:",
                "-pkeyopt", "rsa_padding_mode:oaep",
                "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256",
            ],
            input=cipher,
            capture_output=True,
            env=openssl_env(),
        )
    except FileNotFoundError:
        raise fail("openssl not found") from None
    if proc.returncode != 0:
        # openssl's stderr names algorithms and key problems, never secrets.
        raise fail(
            "decryption failed"
            + openssl_reason(proc.stderr.decode("utf-8", "replace"))
            + " (a blob made for another key, a damaged one, or a key that"
            " isn't RSA-2048: check that HANDOFF_PRIVKEY names the key this"
            " blob was made for)"
        )
    try:
        payload = json.loads(proc.stdout.decode("utf-8"))
    except Exception:
        raise fail("decrypted payload is not valid JSON")
    if not isinstance(payload, dict):
        raise fail("decrypted payload is not a JSON object")
    return payload


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
    if upper in REFUSED_ENV_NAMES or upper.startswith(REFUSED_ENV_PREFIXES):
        raise fail(
            f"--env target {name!r} is on the refused list: it changes what the "
            "command runs or where it connects; refusing"
        )


def parse_args(argv):
    label = None
    check = False
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
        if a in ("--label", "--blob", "--blob-file", "--check"):
            # Each at most once: a backstop if a wrapper wrongly passes its
            # caller's arguments (SETUP.md says it never does), so at least
            # the label can't be overridden.
            if a in seen:
                raise fail(f"{a} given twice")
            seen.add(a)
        if a in ("--label", "--blob", "--blob-file", "--env"):
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
        else:
            raise fail(f"unrecognized argument: {a}")
        i += 1
    # Counted over the whole map, the default mappings included: a payload
    # may carry any known field, so no two may ever share a target.
    targets = list(env_map.values())
    if len(set(targets)) != len(targets):
        raise fail("two fields map to the same environment variable; refusing")
    if not label:
        raise fail("--label is required (the service label the blob was fetched under)")
    if check and cmd:
        raise fail("--check takes no command; it only inspects the payload")
    if not check and (not cmd or not cmd[0]):
        raise fail("no command given after -- (or use --check)")
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
            f"blob file at {blob_file} is not a regular file (a "
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
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise fail(not_regular)
            # utf-8-sig: some editors save a byte-order mark first.
            with os.fdopen(fd, "r", encoding="utf-8-sig") as fh:
                blob = fh.read(MAX_BLOB_FILE + 1)
        except OSError as e:
            # strerror comes from the OS, never from the file's contents.
            raise fail(f"cannot read blob file at {blob_file}: {e.strerror}") from None
        except UnicodeError:
            raise fail(f"cannot read blob file at {blob_file} as text") from None
        if len(blob) > MAX_BLOB_FILE:
            raise fail(f"blob file at {blob_file} is over {MAX_BLOB_FILE} characters; not a blob")
    if blob is None:
        blob = os.environ.get(BLOB_ENV)
    if blob is None:
        raise fail(f"no blob supplied: use --blob, --blob-file, or ${BLOB_ENV}")
    return label, check, blob, env_map, cmd


def main() -> int:
    if sys.version_info < (3, 7):
        # capture_output and text= need 3.7; say so instead of a traceback.
        print("consume.py: requires Python 3.7 or later", file=sys.stderr)
        return 1
    label, check, blob, env_map, cmd = parse_args(sys.argv[1:])
    payload = decrypt(blob)
    creds = check_payload(payload, label, env_map)
    if check:
        print(f"svc: matches label {label!r}")
        for name in sorted(creds):
            print(f"{name}: {len(creds[name].encode('utf-8'))} bytes")
        return 0
    env = dict(os.environ)
    # The command needs the credentials, not the blob or the key's path.
    env.pop(BLOB_ENV, None)
    env.pop(PRIVKEY_ENV, None)
    # The default names and this call's targets come from this payload or
    # not at all: a value already in the caller's environment would otherwise
    # reach the command beside the payload's values (a planted blob with only
    # a username would run with the real password, and a nested wrapper would
    # hand service A's SERVICE_PASSWORD to service B). Other names pass
    # through (see the docstring on nesting).
    for target in set(env_map.values()) | set(DEFAULT_ENV_MAP.values()):
        env.pop(target, None)
    for field, value in creds.items():
        env[env_map[field]] = value
    # Deliberately no logging of env or creds here — that is the whole point.
    # exec, not a subprocess: the command takes over this process, so a
    # signal meant for the helper (an MCP client stopping its server sends
    # TERM) reaches the command itself, and no parent is left that could
    # exit and leave a credentialed child running. It also means this
    # process holds no copy of the plaintext after the hand-over. stdin,
    # stdout and stderr are inherited untouched: they are the command's.
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
    sys.exit(main())
