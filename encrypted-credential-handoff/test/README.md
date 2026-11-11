# Interop test vectors

Known-answer vectors for the encrypted credential handoff reference protocol (RSA-2048, OAEP-SHA256, MGF1-SHA256, single-line base64).

**The keypair here is a published throwaway.** `test-dummy-priv.pem` protects nothing and must never be used for a real credential. Its presence in the repo is the point: anyone can check an implementation against these vectors.

## Files

- `test-dummy-priv.pem` / `test-dummy-pub.pem` — the dummy keypair.
- `expected.json` — the plaintext payload: `{"svc":"example","username":"dummy-user-Qx7","password":"dummy-pass-K3z9w"}`. The two values differ on purpose, so a swapped mapping fails the test.
- `blob.txt` — `expected.json` encrypted to the dummy public key, base64, one line.
- `expected-check.txt` — the exact expected output of the reference `consume.py --label example --check` on `blob.txt`.
- `run-test.sh` — runs the full check against the reference implementation in this folder.

## Using these vectors for a port or variant

An implementation is interoperable with the reference when:

1. It decrypts `blob.txt` with `test-dummy-priv.pem` to exactly `expected.json` (the `svc` binding check against the label `example` must pass).
2. It encrypts `expected.json` to `test-dummy-pub.pem`, and the reference `consume.py` decrypts the result to the same values (run it with `HANDOFF_PRIVKEY` pointing at a `0600` copy of the dummy key — the reference helper refuses group/other-readable key files, including this published one at its repo permissions).

`run-test.sh` also covers the reference scripts themselves: that `consume.py` passes the child's stdin through, execs the command (so a TERM sent to it leaves no credentialed process behind), drops `$HANDOFF_BLOB` from the command's environment and never prints a dummy value itself; that `agent-setup.sh --fingerprint` reads `$HANDOFF_PRIVKEY` and agrees with `handoff.sh --fingerprint`, for the dummy key and a freshly generated one; that a 190-byte payload works; and each documented refusal by its exit code and message (purpose mismatch, a payload with no known credential field — `unknown.json` / `blob-unknown.txt` — a loose or missing key, damaged input, refused `--env` targets, a command that can't be run, an existing key, an unknown argument, a 191-byte or misshapen payload, and the placeholder public key).

Passing both directions is the minimum bar before a port touches a real credential (see `../SETUP.md`).
