# Changelog — encrypted-credential-handoff

## Unreleased — first publication

The folder's first public version. Nothing here has been released before, so this entry describes what ships, not a sequence of changes. (Renamed before publication from "blind-RSA credential handoff": "blind RSA" names a different, standardized technique.)

Before its first commit, the folder had a structural review and a line-level script review, with findings reproduced. PR #1 then went through a cold read and several QA review rounds, each with Dev's own pre-QA reviews. The PR body records each round's findings and what was fixed or declined. The reviewers were AI agent sessions in the author's setup, plus the author: peer review inside one shop, not a third-party audit.

### Added

**The pattern** (README.md)

- **Threat model**, including what the pattern does not defend against: host trust, the agent account, no sender authentication, no forward secrecy under key compromise, the helper as a decryption oracle (execute access to the helper is read access to every staged credential), writers to the store (a store writer can plant a blob for a label; signed blobs would close it), and the unattended-fetch credential.
- **Ten invariants**: one-way delivery, careful ciphertext storage, plaintext never in a model's context, never on the agent's disk, mandatory key/ciphertext separation, identity verification, provenance (stage only blobs the user pastes), purpose binding (`svc`), controlled egress and key confinement.
- **Rotation** split into routine rotation and compromise response (on a suspected leak, credentials change at their services first). **Platform** status stated plainly: Linux reviewed; macOS expected but unreviewed; Windows has no reference.

**Setting it up** (SETUP.md)

- **Hard rules**, including one list of what is recorded per label (both wrappers, the sha256 sums of each label's wrappers and own programs, a shared section of sums for the programs every label runs, each whole command line and its `--env` mappings, each wrapper's environment and working directory, the fetch and its environment, the endpoint, and anything the user accepted knowingly). A change to anything on it is a mechanism change; the one exception is the key-path edit during rotation.
- **Wrappers**: a probe wrapper and a use wrapper per label, identical apart from the comment line and the command after `--` (checked with `diff`; the sha256 of each wrapper and its own programs recorded per label, and of the shared programs, `consume.py`, the fetch script, `openssl` and `python3`, once, all compared before a run and at each session's start), with a complete example. A wrapper takes no caller arguments and no caller environment: it refuses arguments, `cd`s to a fixed directory, starts the helper with `env -i`, and runs the fetch with `</dev/null` under its own clean environment (for a stdio MCP server, the wrapper's stdin is the client's transport). Wrappers are never nested.
- **Steps** with exact commands: `HANDOFF_KEY_DIR` and `HANDOFF_PRIVKEY`, the fingerprint check, the dummy round-trip, giving the user the exact `svc`, rotation one service at a time, recorded step by step in a rotation entry, with a resume point for every state, so an interrupted rotation resumes where it stopped (the old blob copied to `<label>.old`, which is never overwritten, the new one stored, both wrappers switched by `cp -p`, edit and `mv`, the probe run, then `<label>.old` deleted, or restored in a rollback if the probe fails), and macOS `PATH` lines for Homebrew's `openssl@3`. Prerequisites: OpenSSL 3 or 4, Python 3.7 or later.

**`handoff.sh`** (the user's side)

- Encrypts with RSA-2048, OAEP-SHA256, MGF1-SHA256; prints only the base64 ciphertext on stdout. Reads the payload with echo off, or from a file or pipe; checks it's a single JSON object with a string `svc` and string values (with `jq`), and at most 190 bytes.
- The fingerprint fails closed on a placeholder or damaged key. Requires OpenSSL 3 or 4 (refuses LibreSSL, with a `PATH` hint), and drops the caller's `OPENSSL_*` variables.

**`agent-setup.sh`** (the agent's side)

- Generates the keypair (mode 600, a 700 directory it creates; it refuses to overwrite a key or to treat an unknown argument as "generate"). `--fingerprint [KEY]` reads `KEY`, else `$HANDOFF_PRIVKEY`, else the same default key `consume.py` uses, and names the file it read; it refuses an encrypted key, a key that isn't RSA-2048, and a file over 16384 bytes.
- One `~/` rule shared with `consume.py` (`~user` refused), `HOME` needed only for the defaults and `~`, the same OpenSSL 3/4 gate, and `OPENSSL_*` dropped.

**`consume.py`** (the consume helper)

- Loads the key on its own first, never prompting for a passphrase, and checks it's an RSA-2048 key with e = 65537 (a key that won't load, an encrypted one, another key type or size, or a file over 16384 bytes is reported as such, with openssl's readable reason, cut to 300 characters), then decrypts in memory (a failed decrypt names the likely cause: a blob made for another key, or a damaged one), checks `svc` against `--label`, and **execs** the command with the credentials in its environment (a TERM to the helper reaches the command; no credentialed child is left behind). Run as `./consume.py`, it re-runs itself as `python3 -I` through a two-line sh launcher (no `env -S`, which BusyBox lacks).
- Prints nothing derived from the payload. `--check` shows field names and lengths, for the dummy round-trip only.
- **Environment:** the default `SERVICE_*` names and its own mappings are removed from what it inherits before the payload's values go in, along with `$HANDOFF_BLOB` and `$HANDOFF_PRIVKEY`. `--env` maps only the known fields, each once, and refuses targets that aren't plain names or that change what the command runs or where it connects (a partial list, compared case-insensitively). `OPENSSL_*` is stripped from its own openssl calls.
- **Input:** exactly one blob source; `--label`, `--blob`, `--blob-file` and `--check` at most once each; a blob file must be a regular file (checked before opening, opened non-blocking, rechecked); empty, wrong-length or oversized blobs, empty, NUL or non-UTF-8 values, and non-OpenSSL-3/4 openssl are clean refusals, never tracebacks.

**Tests and CI**

- `test/run-test.sh`: a known-answer decrypt vector and an encrypt round trip through `consume.py` (OAEP is randomized), the exec and TERM behavior through both entry points, leak checks on the helper's own output (every crafted value carries a marker), fingerprint agreement across the scripts, the 190/191-byte boundary, and every documented refusal by exit code and message, including a key owned by another user (from a root-owned owner-only file; skipped where there is none) and a blob file swapped to a terminal after its check (refused without taking a controlling terminal). It needs only bash, python3, openssl and jq, and runs without execute bits. The PR #1 rounds checked the suite with mutation runs kept outside the repo, and issue #2 brings mutation testing in; the survivors those runs found were fixed by new tests.
- CI runs the execute-bit and line-ending checks, shellcheck, `ruff check` and the suite, gives the suite a root-owned key file for the key-owner refusal, and fails if the suite skips any check. `.gitattributes` keeps scripts and vectors LF.
