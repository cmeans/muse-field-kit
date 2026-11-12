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

`run-test.sh` also covers the reference scripts themselves: that `consume.py` passes stdin through to the command, execs the command, directly and through its sh launcher (so a TERM sent to it leaves no credentialed process behind), drops `$HANDOFF_BLOB`, `$HANDOFF_PRIVKEY` and every inherited credential variable (mapped or default name) from the command's environment, hands the command SIGPIPE and SIGXFSZ at their defaults, runs isolated through its sh launcher (a planted `sitecustomize` doesn't run), accepts a blob file with a byte-order mark, and never prints a dummy value itself (the crafted payloads' values carry a marker, `mk-Zq9`, that the leak check looks for too); that `agent-setup.sh --fingerprint` reads `$HANDOFF_PRIVKEY`, accepts OpenSSL 4 and refuses LibreSSL as `consume.py` and `handoff.sh` do, needs `HOME` only for its defaults and `~`, falls back to the same default key as `consume.py` (unset or empty, with a literal `~/` expanded and `~user` refused by both), and agrees with `handoff.sh --fingerprint`, for the dummy key and a freshly generated one; that a 190-byte payload works; and each documented refusal by its exit code and message (purpose mismatch, a payload with no known credential field — `unknown.json` / `blob-unknown.txt` — a payload without `svc`, not JSON or not an object, a non-string or empty credential, a loose or missing key, a key that won't load (a public key), an encrypted key (its passphrase on stdin, and under a terminal), an Ed25519 or P-256 key, an oversized key file, damaged, empty, short or oversized input, no blob or two blob sources, a repeated option, a NUL byte or invalid UTF-8 in a credential, refused `--env` targets and fields (every listed name, in both cases, and every prefix), a blob file that's a FIFO (refused without opening it) or pipe, a device, a missing file or an empty `--blob-file`, a blob path swapped to a FIFO or a terminal between the `stat` and the open (the terminal without becoming the helper's controlling terminal), a private key owned by another user (CI supplies a root-owned copy of the dummy key in `$HANDOFF_TEST_OTHER_OWNER_KEY`; elsewhere the test uses a root-owned owner-only system file such as Fedora's `/etc/shadow`, whose contents are never read, and skips where there is none), no `OPENSSL_*` variable reaching the openssl of any of the three scripts, a blob file that isn't text, openssl missing or not OpenSSL 3/4, `~user` paths, an empty command or one that can't be run, an existing key, an unknown argument, a 191-byte or misshapen payload, and the placeholder public key). It also checks first-time key generation's edges (a short `genpkey` write leaves nothing at the key path, a key that appears meanwhile is never replaced, a key directory starting with `-`), a failing DER export reported as unreadable, `consume.py --help`, and the `HANDOFF_LABEL` nesting refusal. It runs on Linux; macOS portability of the test itself is issue #3.

Passing both directions is the minimum bar before a port touches a real credential (see `../SETUP.md`).
