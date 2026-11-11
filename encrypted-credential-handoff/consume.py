#!/usr/bin/env python3
"""Consume-side template for the encrypted credential handoff.

Fetches nothing itself: the caller (a per-service wrapper) fetches the
base64 blob from wherever ciphertexts are stored and supplies it by
argument, file, or environment variable — never on stdin, which belongs
to the child process (a stdio MCP server's stdin is its transport).
This helper decrypts IN MEMORY with the private key (default
~/.config/handoff/handoff-priv.pem, override with $HANDOFF_PRIVKEY),
verifies the payload's purpose binding, and either:

  run mode    replaces itself (exec) with a command, the credential values
              injected into its environment; the command's stdin, stdout
              and stderr are the helper's own, untouched, or
  --check     prints field names and value lengths ONLY. For the SETUP
              DUMMY round-trip only: lengths are output too, so never
              run --check on a real credential.

This helper never writes the plaintext to disk and never prints it, in
any mode, on success or on error. Nothing derived from the payload — not a
value, not a field name — is echoed in any message (--check's field names
and lengths excepted): payloads are unauthenticated input, and error text
lands in the agent's tool output. What the launched command prints is the
command's own business: a command that prints its environment (printenv)
reveals the credential to whoever ran the helper. So execute access to this
helper is read access to every staged credential, and each label runs only
the command it was set up with (SETUP.md, hard rules).

    username / password          -> SERVICE_USERNAME / SERVICE_PASSWORD
    api_key_id / api_key_secret  -> SERVICE_API_KEY_ID / SERVICE_API_KEY_SECRET
    token_id / token_secret      -> SERVICE_TOKEN_ID / SERVICE_TOKEN_SECRET
    svc                          -> purpose binding; never injected

Per-service variable names differ; map them per invocation instead of
editing this file:  --env username=APP_USER --env password=APP_PASS
A target must be a plain variable name, never one that changes how the
command starts (PATH, LD_*, PYTHON*, BASH_ENV, ...), and two fields can't
share one target.

Every payload must carry "svc", and it must equal the --label the blob
was fetched under; otherwise this helper refuses. A payload with unknown
fields is noted by COUNT only; a payload with no known credential field
at all is refused, so a typo'd payload can't silently launch a tool with
no credentials.

The injected values live in the child's environment for the life of the
child process and are inherited by its children — and the target command
must not log its own environment or resolved config, and must never be
handed a credential on its command line (argv is world-readable).

Usage:
    HANDOFF_BLOB=$(cat blob.txt) consume.py --label example -- my-tool --serve
    consume.py --label example --blob-file blob.txt -- my-tool --serve
    consume.py --label test --check --blob-file blob.txt
"""
import base64
import json
import os
import re
import stat
import subprocess
import sys

PRIVKEY = os.environ.get(
    "HANDOFF_PRIVKEY", os.path.expanduser("~/.config/handoff/handoff-priv.pem")
)
BLOB_ENV = "HANDOFF_BLOB"

DEFAULT_ENV_MAP = {
    "username": "SERVICE_USERNAME",
    "password": "SERVICE_PASSWORD",
    "api_key_id": "SERVICE_API_KEY_ID",
    "api_key_secret": "SERVICE_API_KEY_SECRET",
    "token_id": "SERVICE_TOKEN_ID",
    "token_secret": "SERVICE_TOKEN_SECRET",
}

# --env target names: a plain identifier, and never one that changes which
# program runs or how it starts. Mapping a payload field onto PATH, for
# example, would let whoever wrote the payload choose the binary. This list
# is a backstop, not the control: SETUP.md's hard rule pins each label to its
# recorded command and mappings.
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
REFUSED_ENV_NAMES = {
    "PATH", "HOME", "IFS", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "PS4",
    "NODE_OPTIONS", "NODE_PATH", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB",
    "JAVA_TOOL_OPTIONS", BLOB_ENV, "HANDOFF_PRIVKEY",
}
REFUSED_ENV_PREFIXES = ("LD_", "DYLD_", "PYTHON", "BASH_FUNC_")


def fail(msg: str) -> "SystemExit":
    return SystemExit(f"consume.py: {msg}")


def decrypt(blob_b64: str) -> dict:
    if not os.path.isfile(PRIVKEY):
        raise fail(f"cannot read private key at {PRIVKEY}")
    st = os.stat(PRIVKEY)
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise fail(
            f"private key at {PRIVKEY} is mode {mode:03o}; "
            "it must be owner-only (0600). Refusing."
        )
    if st.st_uid != os.geteuid():
        raise fail(f"private key at {PRIVKEY} is not owned by this user. Refusing.")
    # Tolerate line wrapping from a paste: strip ALL whitespace.
    compact = "".join(blob_b64.split())
    try:
        cipher = base64.b64decode(compact, validate=True)
    except Exception:
        raise fail("input is not valid base64")
    proc = subprocess.run(
        [
            "openssl", "pkeyutl", "-decrypt",
            "-inkey", PRIVKEY,
            "-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ],
        input=cipher,
        capture_output=True,
    )
    if proc.returncode != 0:
        # openssl's stderr names algorithms and key problems, never secrets.
        detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise fail("decryption failed" + (f": {detail[-1]}" if detail else ""))
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
        creds[name] = value
    if unknown:
        print(f"consume.py: ignoring {unknown} unknown field(s)", file=sys.stderr)
    if not creds:
        raise fail("payload contains no known credential field; refusing to run")
    return creds


def check_env_name(name: str) -> None:
    if not ENV_NAME_RE.fullmatch(name):
        raise fail(f"--env target {name!r} is not a valid variable name")
    if name in REFUSED_ENV_NAMES or name.startswith(REFUSED_ENV_PREFIXES):
        raise fail(
            f"--env target {name!r} would change how the command starts; refusing"
        )


def parse_args(argv):
    label = None
    check = False
    blob = None
    blob_file = None
    env_map = dict(DEFAULT_ENV_MAP)
    cmd = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            cmd = argv[i + 1:]
            break
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
                check_env_name(name)
                env_map[field] = name
        elif a == "--check":
            check = True
        else:
            raise fail(f"unrecognized argument: {a}")
        i += 1
    targets = list(env_map.values())
    if len(set(targets)) != len(targets):
        raise fail("two fields map to the same environment variable; refusing")
    if not label:
        raise fail("--label is required (the service label the blob was fetched under)")
    if check and cmd:
        raise fail("--check takes no command; it only inspects the payload")
    if not check and not cmd:
        raise fail("no command given after -- (or use --check)")
    if blob is None and blob_file is not None:
        try:
            with open(blob_file, "r", encoding="utf-8") as fh:
                blob = fh.read()
        except OSError:
            raise fail(f"cannot read blob file at {blob_file}")
    if blob is None:
        blob = os.environ.get(BLOB_ENV)
    if blob is None:
        raise fail(f"no blob supplied: use --blob, --blob-file, or ${BLOB_ENV}")
    return label, check, blob, env_map, cmd


def main() -> int:
    label, check, blob, env_map, cmd = parse_args(sys.argv[1:])
    payload = decrypt(blob)
    creds = check_payload(payload, label, env_map)
    if check:
        print(f"svc: matches label {label!r}")
        for name in sorted(creds):
            print(f"{name}: {len(creds[name].encode('utf-8'))} bytes")
        return 0
    env = dict(os.environ)
    env.pop(BLOB_ENV, None)  # the child needs the credentials, not the blob
    for field, value in creds.items():
        env[env_map[field]] = value
    # Deliberately no logging of env or creds here — that is the whole point.
    # exec, not a subprocess: the command takes over this process, so a
    # signal meant for the helper (an MCP client stopping its server sends
    # TERM) reaches the command itself, and no parent is left that could
    # exit and leave a credentialed child running. It also means this
    # process holds no copy of the plaintext after the hand-over. stdin,
    # stdout and stderr are inherited untouched: they are the command's.
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        os.execvpe(cmd[0], cmd, env)
    except OSError as e:
        # Only the caller's own command name appears here, never payload data.
        code = 127 if isinstance(e, FileNotFoundError) else 126
        print(f"consume.py: cannot run {cmd[0]!r}: {e.strerror}", file=sys.stderr)
        return code
    except ValueError:
        # An embedded NUL, in the command or in a credential value. Say
        # neither which nor where: the value may be the payload's.
        print("consume.py: the command or a credential contains a NUL byte; refusing",
              file=sys.stderr)
        return 126
    return 0  # not reached: execvpe only returns by raising


if __name__ == "__main__":
    sys.exit(main())
