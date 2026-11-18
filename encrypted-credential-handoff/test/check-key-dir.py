#!/usr/bin/env python3
"""Checks of consume.py that need a faked system call, run by run-test.sh.

    python3 -I check-key-dir.py IDENTITY BLOB_FILE

IDENTITY is an owner-only copy of test-dummy-identity.txt in an owner-only
directory, and BLOB_FILE a blob for it. Each check prints "ok: ..." or exits
non-zero with "FAIL: ...":

  other-owner   a key directory owned by another (non-root) account is
                refused (no such directory can be made without root, so the
                directory's stat result is faked)
  proc-fd       with /dev/fd missing, age gets the identity as
                /proc/self/fd/N and decrypts (Linux only; skipped elsewhere)
  no-fd         with neither /dev/fd nor /proc/self/fd, the refusal names
                them, not a wrong key
"""
import base64
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import consume  # noqa: E402


def fail(msg):
    print("FAIL: " + msg, file=sys.stderr)
    sys.exit(1)


def refusal(fn, *args):
    try:
        fn(*args)
    except SystemExit as e:
        return str(e)
    return None


def main(identity, blob_file):
    key_dir = os.path.dirname(os.path.abspath(identity))
    real_stat = os.stat

    def other_owner_stat(path, *a, **k):
        st = real_stat(path, *a, **k)
        if isinstance(path, str) and os.path.abspath(path) == key_dir:
            fields = list(st)
            fields[4] = os.geteuid() + 4242  # st_uid
            return os.stat_result(fields)
        return st

    os.stat = other_owner_stat
    try:
        msg = refusal(consume.check_key_dir, identity)
    finally:
        os.stat = real_stat
    if not msg or "is owned by another account" not in msg:
        fail("other-owner: a key directory owned by another account wasn't refused: %r" % msg)
    print("ok: other-owner")

    _, data = consume.load_key(identity)
    raw = base64.b64decode(Path(blob_file).read_text().strip())
    real_exists = os.path.exists

    def exists_without(*prefixes):
        def fake(p):
            if isinstance(p, str) and p.startswith(prefixes):
                return False
            return real_exists(p)
        return fake

    if real_exists("/proc/self/fd"):
        os.path.exists = exists_without("/dev/fd/")
        try:
            plain = consume.age_decrypt(raw, data)
        finally:
            os.path.exists = real_exists
        if plain is None:
            fail("proc-fd: with /dev/fd missing, age didn't decrypt through /proc/self/fd")
        print("ok: proc-fd")
    else:
        print("skipped: proc-fd (no /proc/self/fd here)")

    os.path.exists = exists_without("/dev/fd/", "/proc/self/fd/")
    try:
        msg = refusal(consume.age_decrypt, raw, data)
    finally:
        os.path.exists = real_exists
    if not msg or "neither /dev/fd nor /proc/self/fd is available" not in msg:
        fail("no-fd: without /dev/fd or /proc/self/fd, the refusal didn't say so: %r" % msg)
    print("ok: no-fd")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        fail("usage: check-key-dir.py IDENTITY BLOB_FILE")
    main(sys.argv[1], sys.argv[2])
