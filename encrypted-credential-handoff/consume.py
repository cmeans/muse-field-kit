#!/usr/bin/env python3
"""Consume-side template for the encrypted credential handoff.

Fetches nothing itself: the caller (a per-service wrapper) fetches the
base64 blob from wherever ciphertexts are stored and supplies it by
argument, file, or environment variable — never on stdin, which belongs
to the child process (a stdio MCP server's stdin is its transport).
This helper decrypts IN MEMORY with the private key (default
~/.config/handoff/handoff-priv.pem, override with $HANDOFF_PRIVKEY),
verifies the payload's purpose binding, and either:

  run mode    runs a command with the credential values injected into
              its environment (the child's stdin/stdout/stderr pass
              through untouched), or
  --check     prints field names and value lengths ONLY. For the SETUP
              DUMMY round-trip only: lengths are output too, so never
              run --check on a real credential.

The plaintext is never written to disk and never printed, in any mode,
on success or on error. Nothing derived from the payload — not a value,
not a field name — is echoed in any message: payloads are unauthenticated
input, and error text lands in the agent's tool output.

    username / password          -> SERVICE_USERNAME / SERVICE_PASSWORD
    api_key_id / api_key_secret  -> SERVICE_API_KEY_ID / SERVICE_API_KEY_SECRET
    token_id / token_secret      -> SERVICE_TOKEN_ID / SERVICE_TOKEN_SECRET
    svc                          -> purpose binding; never injected

Per-service variable names differ; map them per invocation instead of
editing this file:  --env username=APP_USER --env password=APP_PASS

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
                env_map[field] = name
        elif a == "--check":
            check = True
        else:
            raise fail(f"unrecognized argument: {a}")
        i += 1
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
    # stdin is inherited untouched: it is the child's channel, not ours.
    rc = subprocess.run(cmd, env=env).returncode
    # A child killed by signal N reports -N; map to the shell convention.
    return 128 + (-rc) if rc < 0 else rc


if __name__ == "__main__":
    sys.exit(main())
