# Interop test vectors

Known-answer vectors for the encrypted credential handoff reference protocol (`age` X25519, one recipient, the binary age format, single-line base64).

**The identity here is a published throwaway.** `test-dummy-identity.txt` protects nothing and must never be used for a real credential. Its presence in the repo is the point: anyone can check an implementation against these vectors.

## Files

- `test-dummy-identity.txt` / `handoff-test.age` — the `age` dummy identity and its recipient (one line).
- `expected.json` — the plaintext payload: `{"svc":"example","username":"dummy-user-Qx7","password":"dummy-pass-K3z9w"}`. The two values differ on purpose, so a swapped mapping fails the test.
- `expected-check.txt` — the exact expected output of the reference `consume.py --label example --check` on `blob-age.txt`.
- `blob-age.txt` — `expected.json` encrypted to that recipient by Go `age` 1.3.2: the binary age format (not `-a` armor), base64, one line.
- `blob-age-rage.txt` — the same payload made by rage; its header carries a `-grease` stanza, which the header check must accept.
- `unknown.json` / `blob-unknown.txt` — a payload with no known credential field (`{"svc":"example","note":"mk-Zq9-note"}`) and its age blob for the same recipient; the reference helper refuses it.
- `vectors/` — blobs the reader must refuse, base64 on one line unless noted: `scrypt.txt`, `two-x25519.txt`, `grease-only.txt`, `plugin-stanza.txt`, `pq-stanza.txt`, `ssh-stanza.txt`, `unknown-stanza.txt`, `armored-b64.txt`, and `armored-raw.txt` (the raw multi-line `age -a` text, not base64). The hand-built ones have no valid MAC; the header check refuses them before `age` runs.
- `make-vectors.sh` — how each age vector was made, with the tool versions and the SHA-256 of each. The suite never runs it (age's output is random, so a re-run changes every blob). It refuses a full run while `test-dummy-identity.txt` exists (a new identity would orphan every blob) unless given `--regenerate`; `--only unknown` makes `blob-unknown.txt` alone for the existing identity. `age-plugin-batchpass` must be on `PATH` for the scrypt vector.
- `user-side-cases.json`, `payload-cases.json` — tables shared by `run-test.sh` and `run-test.ps1` for the user-side scripts (`handoff.sh`, `handoff.ps1`) and the payload checks.
- `run-test.sh` — runs the full check against the reference implementation in this folder. `HANDOFF_TEST_AGE` and `HANDOFF_TEST_AGE_KEYGEN` name the `age` binaries to test against; `HANDOFF_TEST_ONLY="3b 5a"` runs only the named sections (`1a 1b 1c 1d 2a 2b 3a 3b 4a 4b 5 5a 5b 6 7 8`) and prints `ran: <ids>` (an unknown id, or an empty list, fails instead of running nothing). It needs `age`, `age-keygen`, `bash`, `python3` and `jq`; nothing else crypto-related.
- `check-key-dir.py` — run by `run-test.sh`: the `consume.py` checks that need a faked system call (a key directory owned by another account; a root-owned world-writable one, refused with advice to move the key, not `chmod`; the `/proc/self/fd` fallback; and the refusal when neither fd directory exists). `--rewrap`'s owner checks on the blob file and its directory fake `os.stat` too, inline in `run-test.sh` section 6 (`rk_stat`), since they need that section's rotation state.
- `check-interop.py` — CI only: opens the blobs `run-test.ps1` wrote on Windows (5.1 and 7) with the reference `consume.py` and checks the values byte for byte.
- `run-test.ps1` — the same checks for the Windows side (`handoff.ps1`), on Windows PowerShell 5.1 and PowerShell 7, including the forms [`README.md`](../README.md#payloads)'s “Payloads” shows: the `private_key` payload built with `[IO.File]::ReadAllText` and `ConvertTo-Json -Compress` (with a CRLF PEM, opened byte for byte on Linux by `check-interop.py`), and, on Windows, [`INSTALL-windows.md`](../INSTALL-windows.md)'s Mark of the Web and execution-policy routes.

0.1.0 detection is tested with made-up PEM-shaped text written inline by the tests (a `-----BEGIN RSA PRIVATE KEY-----` or `-----BEGIN PUBLIC KEY-----` block with a nonsense body): the scripts look only at the header line, so no real RSA key exists in the repo.

## Using these vectors for a port or variant

An implementation is interoperable with the reference when:

1. It decrypts `blob-age.txt` (and `blob-age-rage.txt`) with `test-dummy-identity.txt` to exactly `expected.json` (the `svc` binding check against the label `example` must pass).
2. It encrypts `expected.json` to the recipient in `handoff-test.age`, and the reference `consume.py` decrypts the result to the same values (run it with `HANDOFF_PRIVKEY` pointing at a `0600` copy of the dummy identity: the reference helper refuses group/other-readable identity files, including this published one at its repo permissions).
3. It refuses every blob in `vectors/` and `blob-unknown.txt` as the reference does.

`run-test.sh` also covers the reference scripts themselves, section by section (the ids are the `== ID.` headings):

- **1a-1d, 2a-2b:** `consume.py` decrypts the vectors, prints exactly `expected-check.txt` under `--check`, injects the credential environment (default `SERVICE_*` names, per-invocation `--env` mappings, a PEM `private_key` byte for byte), never prints a dummy value itself, passes the command's stdin through untouched and execs the command (a TERM sent to the helper reaches it and leaves nothing running).
- **3a-3b:** `handoff.sh` writes a blob, which `consume.py` opens, and the maximum payload's blob holds its bytes.
- **4a-4b:** `agent-setup.sh --fingerprint` and `--public-key` print the recipient of `$HANDOFF_PRIVKEY`; for a freshly generated identity the setup output, `--fingerprint` and `handoff.sh --fingerprint` agree.
- **5, 5a:** each documented refusal by its exit code and message, with nothing on stdout, no traceback and no dummy value: purpose mismatch, a payload with no known credential field, damaged, empty, oversized or non-text input, a blob for another key, the age header allowlist (`vectors/`), identity-file checks (mode, owner, symlink, size, a recipient or a PEM key where an identity belongs, plugin and post-quantum identity lines), the environment `age` and `age-keygen` get, and `~user` paths.
- **5b:** `handoff.sh`'s recipient file `handoff-NAME.age` beside the script and nothing else (near-miss names, symlinks, size and encoding limits, the shells it refuses, running from `/dev/shm`), and the 0.1.0 `handoff-NAME.pem` hint; and the payload rules `handoff.sh` enforces (`payload-cases.json`), where each accepted payload's blob, from stdin and from FILE, decrypts to the input's bytes.
- **6:** a whole rotation on a copy of the dummy identity: `agent-setup.sh --rotate`, old blobs opening through the previous key, `consume.py --rewrap --blob-file`, [`ROTATION.md`](../ROTATION.md) step 4's fetched-store rewrap wrapper (taken from the doc and run against a fake store), `--retire` and its guards, locks, interruptions and cleanup.
- **7, 8:** the `HANDOFF_LABEL` nesting refusal, and `--check-setup` in `handoff.sh` and `agent-setup.sh`.

Passing both directions is the minimum bar before a port touches a real credential (see [`../SETUP.md`](../SETUP.md)).
