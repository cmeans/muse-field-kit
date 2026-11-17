#!/usr/bin/env python3
"""Open the blobs run-test.ps1 wrote on Windows with the reference consume.py.

    python3 -I check-interop.py DIR [DIR...]

Each DIR holds the *.blob, *.expect.json and (where present) *.payload files
that run-test.ps1 leaves under $RUNNER_TEMP/handoff-ps-interop/ps<major>.
For every blob: age (the dummy identity) decrypts it to the exact payload
bytes (when a .payload file exists) or to JSON equal to the expected JSON.
Three named blobs also go through consume.py:

  expected      --check output equals expected-check.txt
  nonascii      the injected SERVICE_USERNAME and SERVICE_PASSWORD equal the
                UTF-8 bytes of the test's values
  private-key   the injected SERVICE_PRIVATE_KEY equals the CRLF PEM byte
                for byte

and every payload-* blob (payload-cases.json's accepted cases) must open
with consume.py --check under its own svc.

Exits non-zero, with a message, on the first mismatch, or when a directory
lacks one of the three named blobs.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONSUME = HERE.parent / "consume.py"
REQUIRED = ("expected", "nonascii", "private-key")
ENV_NAMES = {
    "username": b"SERVICE_USERNAME",
    "password": b"SERVICE_PASSWORD",
    "private_key": b"SERVICE_PRIVATE_KEY",
    "app_id": b"SERVICE_APP_ID",
    "installation_id": b"SERVICE_INSTALLATION_ID",
}


def differ(got, want):
    """How two byte strings differ, with none of their content: a payload
    may be a credential, and a log keeps what is printed."""
    if got is None:
        return "missing (wanted %d bytes)" % len(want)
    n = 0
    while n < len(got) and n < len(want) and got[n] == want[n]:
        n += 1
    return "%d bytes, wanted %d; first difference at byte %d" % (len(got), len(want), n)


def fail(msg):
    print("FAIL: " + msg, file=sys.stderr)
    sys.exit(1)


def run(argv, env=None, data=None):
    p = subprocess.run(argv, input=data, capture_output=True, env=env)
    return p.returncode, p.stdout, p.stderr


def main(dirs):
    tmp = Path(tempfile.mkdtemp(prefix="handoff-interop-"))
    try:
        key = tmp / "identity.txt"
        shutil.copyfile(HERE / "test-dummy-identity.txt", key)
        key.chmod(0o600)
        env = dict(os.environ, HANDOFF_PRIVKEY=str(key))
        total = 0
        for d in map(Path, dirs):
            blobs = sorted(d.glob("*.blob"))
            names = {b.name[: -len(".blob")] for b in blobs}
            for need in REQUIRED:
                if need not in names:
                    fail("%s: no %s.blob (found: %s)" % (d, need, " ".join(sorted(names))))
            for blob in blobs:
                name = blob.name[: -len(".blob")]
                expect_text = (d / (name + ".expect.json")).read_text(encoding="utf-8")
                expect = json.loads(expect_text)
                raw = base64.b64decode(blob.read_text(encoding="ascii").strip(), validate=True)
                rc, plain, err = run(["age", "--decrypt", "-i", str(key)], data=raw)
                if rc != 0:
                    fail("%s/%s: age: %s" % (d, name, err.decode("utf-8", "replace")))
                payload = d / (name + ".payload")
                if payload.exists():
                    if plain != payload.read_bytes():
                        fail("%s/%s: decrypted bytes differ from %s.payload" % (d, name, name))
                elif json.loads(plain.decode("utf-8")) != expect:
                    fail("%s/%s: decrypted JSON differs from %s.expect.json" % (d, name, name))
                total += 1
                label = expect.get("svc")
                if name.startswith("payload-"):
                    rc, out, err = run([sys.executable, "-I", str(CONSUME), "--label", label, "--check",
                                        "--blob-file", str(blob)], env=env)
                    if rc != 0:
                        fail("%s/%s: consume.py --check refused it: %s"
                             % (d, name, err.decode("utf-8", "replace")))
                if name == "expected":
                    rc, out, err = run([sys.executable, "-I", str(CONSUME), "--label", label, "--check",
                                        "--blob-file", str(blob)], env=env)
                    want = (HERE / "expected-check.txt").read_bytes()
                    if rc != 0 or out != want:
                        fail("%s/expected: consume.py --check: rc %d, output %s (%s)"
                             % (d, rc, differ(out, want), err.decode("utf-8", "replace")))
                elif name in ("nonascii", "private-key"):
                    rc, out, err = run([sys.executable, "-I", str(CONSUME), "--label", label,
                                        "--blob-file", str(blob), "--", "env", "-0"], env=env)
                    if rc != 0:
                        fail("%s/%s: consume.py: rc %d: %s" % (d, name, rc, err.decode("utf-8", "replace")))
                    got = {}
                    for item in out.split(b"\0"):
                        k, sep, v = item.partition(b"=")
                        if sep:
                            got[k] = v
                    for field, var in ENV_NAMES.items():
                        if field in expect:
                            want = expect[field].encode("utf-8")
                            if got.get(var) != want:
                                fail("%s/%s: %s: %s" % (d, name, var.decode(), differ(got.get(var), want)))
                    if name == "private-key" and b"\r\n" not in got.get(b"SERVICE_PRIVATE_KEY", b""):
                        fail("%s/private-key: the PEM lost its CRLF line ends" % d)
                print("ok: %s/%s" % (d.name, name))
        if total == 0:
            fail("no blobs checked")
        print("checked %d blobs" % total)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        fail("usage: check-interop.py DIR [DIR...]")
    main(sys.argv[1:])
