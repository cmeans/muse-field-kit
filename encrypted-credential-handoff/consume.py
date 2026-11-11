#!/usr/bin/env python3
"""Consume-side template for the encrypted credential handoff.

Fetches nothing itself: the caller (a per-service wrapper) supplies the
base64 blob on stdin, having fetched it from wherever ciphertexts are
stored. This helper decrypts IN MEMORY with the private key (default
~/.config/handoff/handoff-priv.pem, override with $HANDOFF_PRIVKEY),
verifies the payload's purpose binding, and either:

  run mode    runs a command with the credential values injected into its
              environment, or
  --check     prints field names and value lengths ONLY (for the setup
              dummy round-trip and for verifying a staged blob's shape).

The plaintext is never written to disk and never printed, in any mode,
on success or on error. Error messages name fields, never values.

    username / password          -> SERVICE_USERNAME / SERVICE_PASSWORD
    api_key_id / api_key_secret  -> SERVICE_API_KEY_ID / SERVICE_API_KEY_SECRET
    token_id / token_secret      -> SERVICE_TOKEN_ID / SERVICE_TOKEN_SECRET
    svc                          -> purpose binding; never injected

Every payload must carry "svc", and it must equal the --label the blob was
fetched under; otherwise this helper refuses. Unknown payload fields are
reported by NAME on stderr and ignored; a payload with no known credential
field at all is refused, so a typo'd payload can't silently launch a tool
with no credentials.

The injected values live in the child's environment for the life of the
child process and are inherited by its children — and the target command
must not log its own environment or resolved config.

Usage:
    consume.py --label nas-admin -- my-tool --serve < blob.txt
    consume.py --label test --check < blob.txt
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

ENV_MAP = {
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
    mode = stat.S_IMODE(os.stat(PRIVKEY).st_mode)
    if mode & 0o077:
        raise fail(
            f"private key at {PRIVKEY} is mode {mode:03o}; "
            "it must be owner-only (0600). Refusing."
        )
    try:
        cipher = base64.b64decode(blob_b64.strip(), validate=True)
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


def check_payload(payload: dict, label: str) -> dict:
    """Validate binding and field shapes; return the credential fields."""
    svc = payload.get("svc")
    if svc is None:
        raise fail("payload has no 'svc' field; purpose binding is required")
    if svc != label:
        raise fail(
            f"purpose mismatch: payload is for svc={svc!r}, "
            f"but it was fetched under label {label!r}. Refusing."
        )
    creds = {}
    unknown = []
    for name, value in payload.items():
        if name == "svc":
            continue
        if name not in ENV_MAP:
            unknown.append(name)
            continue
        if not isinstance(value, str):
            raise fail(f"field {name!r} is not a string; refusing")
        creds[name] = value
    if unknown:
        print(
            "consume.py: ignoring unknown field(s): " + ", ".join(sorted(unknown)),
            file=sys.stderr,
        )
    if not creds:
        raise fail("payload contains no known credential field; refusing to run")
    return creds


def parse_args(argv):
    label = None
    check = False
    cmd = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            cmd = argv[i + 1:]
            break
        if a == "--label":
            i += 1
            if i >= len(argv):
                raise fail("--label needs a value")
            label = argv[i]
        elif a == "--check":
            check = True
        else:
            raise fail(f"unrecognized argument: {a}")
        i += 1
    if not label:
        raise fail("--label is required (the service label the blob was fetched under)")
    if not check and not cmd:
        raise fail("no command given after -- (or use --check)")
    return label, check, cmd


def main() -> int:
    label, check, cmd = parse_args(sys.argv[1:])
    payload = decrypt(sys.stdin.read())
    creds = check_payload(payload, label)
    if check:
        print(f"svc: matches label {label!r}")
        for name in sorted(creds):
            print(f"{name}: {len(creds[name].encode('utf-8'))} bytes")
        return 0
    env = dict(os.environ)
    for field, value in creds.items():
        env[ENV_MAP[field]] = value
    # Deliberately no logging of env or creds here — that is the whole point.
    rc = subprocess.run(cmd, env=env).returncode
    # A child killed by signal N reports -N; map to the shell convention.
    return 128 + (-rc) if rc < 0 else rc


if __name__ == "__main__":
    sys.exit(main())
