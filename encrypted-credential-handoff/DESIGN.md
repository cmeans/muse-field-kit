# Design notes

Background on the choices behind this folder: why it isn't a vault, what is fixed and what is a choice, how the encryption suite was chosen, and what CI tests. None of it is needed to set up or use the handoff ([`README.md`](README.md), [`SETUP.md`](SETUP.md), [`ROTATION.md`](ROTATION.md) and [`STORES.md`](STORES.md) are).

## Why not a built-in vault?

Saved-login and vault features are built for browser sign-in: the browser fills a form, and neither you nor the agent can read the value back out. That is the right design for websites. It does not solve this problem:

- A local tool often needs the credential as an **environment variable or config value at process start** (this pattern covers the environment case; see below). There is no supported path that turns a stored browser login into a value a subprocess can consume.
- API-credential flows accept API keys and OAuth, **not username/password pairs** for arbitrary local services — including services that are plain HTTP on a private network address and have no public login page to point a vault flow at.

Named precisely, and dated: as of November 2026, Muse's own credential machinery — the Secure Credentials Store for API-style credentials, and Sentinel credential surrogation for browser sign-in — declines username/password credentials (it supports `api_key` and OAuth-style flows), and saved website logins are consumed only by the browser's fill flow; no supported mechanism reads a stored value back for injection into a local process. That was verified against the platform's behavior in the author's setup in October 2026. If Meta ships a readback-for-local-tools path, this section should be revised and this pattern's reason to exist shrinks accordingly.

This pattern fills that gap for programs that read the credential from their environment, and only that gap: it writes no config file and feeds no program's stdin. Use the platform's own flows wherever they fit. If you already run a secrets manager whose CLI starts a command with secrets in its environment (such as 1Password's `op run` or Bitwarden's `bws run`), prefer it, and use this pattern at most to hand over that tool's own access token.

## Variations: what is fixed, and what is a choice

[`age`](https://github.com/FiloSottile/age) with one X25519 recipient, in its binary format and base64 on one line, is this folder's **reference implementation**. “Choosing the suite,” below, says what it was compared with and why it was chosen.

The suite may be changed, deliberately, by the human, before setup — subject to two constraints:

- **Only as an existing, reviewed tool used as-is**: for example libsodium's `crypto_box_seal` through a maintained binding. It must preserve the invariants in [`README.md`](README.md) (with the same absence of sender authentication, which stays behavioral with any suite swap; only the signed-blob variant below removes it).
- **“Hybrid encryption, hand-rolled” is not a user-selectable variant.** A home-grown AES-GCM-plus-RSA construction, or a payload split across several blocks of a smaller cipher, is a mechanism change: it belongs upstream, as an issue against this repo ([`CONTRIBUTING.md`](../CONTRIBUTING.md) at the repo's root), where it can be reviewed once for every adopter.

Two stronger variants worth knowing about: **signed blobs** (the human signs each payload with a key the agent can verify, removing the behavioral provenance invariant), and a **separate-account key holder** (a helper the agent can ask to decrypt-and-launch, but whose key file the agent's own account cannot read). Both are real designs; neither is in the reference implementation.

Whatever suite is in force, all ten invariants apply, and the known-answer test under `test/` is how an implementation proves it speaks the same protocol as the reference.

### Choosing the suite

Version 0.1.0 used RSA-2048 with OAEP-SHA256 through `openssl pkeyutl`, which caps a payload at 190 bytes. Real credentials are larger: a GitHub App's private key is a PEM of about 1,700 bytes. Version 0.2.0 replaced it, for every payload size, after comparing these (November 2026):

| Candidate | What was checked | Outcome |
| --- | --- | --- |
| **OpenSSL CMS** (AuthEnvelopedData: RSA-OAEP-SHA256 key transport, AES-256-GCM) | Probed with OpenSSL 3.5.0: the strong form works and round-trips. But `openssl cms -decrypt` also opens the weak forms (AES-CBC, PKCS#1 v1.5 key transport) without a warning, so every consumer would have to pin the form itself. The sender needs an X.509 certificate, not a bare public key (an expired one still encrypts, so it carries nothing but the key). Two 2026 OpenSSL advisories are in exactly this code ([CVE-2026-34182](https://www.cve.org/CVERecord?id=CVE-2026-34182), forged AuthEnvelopedData messages; [CVE-2026-63072](https://www.cve.org/CVERecord?id=CVE-2026-63072), a heap overflow in CMS key unwrapping), and distributions patch them into old version numbers ([Ubuntu's tracker](https://ubuntu.com/security/cves)), so no version check can tell a fixed machine from an unfixed one. Stock macOS ships LibreSSL, and no source showed its CMS supports AuthEnvelopedData. | Rejected |
| **`age` above 190 bytes, RSA below** | Two mechanisms, two key formats, two sets of interop tests, and the 190-byte limit still in the docs. | Rejected |
| **`age` for everything, RSA kept for reading for one release** | Keeps OpenSSL, a second decrypt path, a migration flag and a cleanup release, all to convert a handful of labels that can simply be staged again. | Rejected |
| **`age` for everything** ([format](https://age-encryption.org/v1)) | One format with no algorithm options, so nothing to pin but which recipient types are accepted. A recipient is one short line, with no certificate. Native binaries for Linux, macOS and Windows, and packages in the main distributions ([Repology](https://repology.org/project/age/versions)). Its one published advisory ([GHSA-32gq-x56h-299c](https://github.com/FiloSottile/age/security/advisories/GHSA-32gq-x56h-299c)) is in plugin handling, which this folder never uses. | **Chosen** |
| HPKE, `openssl enc` with GCM, JWE, GPG, libsodium sealed boxes | Not probed in depth: HPKE is a library API in OpenSSL 3.2+ with no command line; `openssl enc` refuses AEAD ciphers; JWE and sealed boxes need a library or binding beyond Python's standard library; GPG is far heavier and has its own downgrade history. | Rejected |

What the probes of `age` showed (versions 1.0.0, 1.1.1 and 1.3.2, throwaway keys): small and large payloads (a 1.7 KB JSON with a PEM-sized field) round-trip byte for byte; blobs and keys made by each version work with the others; a wrong key, a flipped byte and a truncated blob are each refused with no plaintext output. Two findings shaped `consume.py`. A passphrase-encrypted blob given an identity is refused by 1.1.1 and 1.3.2, but **1.0.0 tries to read a passphrase from the terminal**. And a blob's length doesn't tell its format. So `consume.py` reads the blob's header itself before `age` runs: the first line must be `age-encryption.org/v1`, the header must name exactly one X25519 recipient, and every other stanza type (passphrase, plugin, post-quantum, SSH, anything unknown) is refused, except the random `-grease` stanzas that rage adds and that can't carry a key. With that check, there is no minimum `age` version: a floor would refuse distribution packages of 1.0.0 and 1.1.1 for no gain.

The costs accepted: a new dependency on both sides; no independent audit of `age` found; and one main maintainer, hedged by a public specification and independent implementations ([rage](https://github.com/str4d/rage) in Rust, whose blobs `consume.py` accepts and the tests cover; [typage](https://github.com/FiloSottile/typage) in TypeScript, not yet checked). Post-quantum recipients (`age1pq1…`, in `age` 1.3) are not supported yet; RSA-2048 wasn't post-quantum either.

**Which senders work:** Go `age` (what the handoff scripts run) and rage, each writing the binary format for one X25519 recipient. A blob for several recipients, an armored (`-a`) blob, and a passphrase blob are refused.

## What CI tests

What CI runs on every change, on GitHub's hosted runners:

- **Linux:** the whole suite (`test/run-test.sh`) against the distribution's packaged `age` and against the `age` 1.3.2 release binary (pinned by SHA-256, checked once against its Sigsum proof), and `test/run-test.ps1` under PowerShell 7; the agent's side again against `age` 1.0.0 and 1.1.1, built from source with `go install` (the Go checksum database checks that source), the oldest packaged versions, which having no minimum version means supporting.
- **macOS:** the whole suite with Homebrew's `age` and `jq`, and [`INSTALL-linux-macos.md`](INSTALL-linux-macos.md)'s macOS checksum command on the release files.
- **Windows:** `test/run-test.ps1` under Windows PowerShell 5.1 and PowerShell 7 with the `age.exe` release (pinned by SHA-256), including [`INSTALL-windows.md`](INSTALL-windows.md)'s execution-policy routes and its Windows checksum command. The blobs it makes are then opened on Linux by `consume.py`, which checks the values byte for byte.

A check that is skipped fails the run, as one that fails does. Run anywhere else, `test/run-test.sh` may skip the checks whose files only CI makes: those that need files owned by another account (`the key-owner refusal wasn't tested`, `the key-directory owner checks weren't run`), and, run as root (as Muse's agent is), `the read-only blob file check didn't run`. Those `skip:` lines are expected there, as are `n/a on this OS:` lines on macOS. Any other `skip:` line names what that machine lacks, and a `FAIL` is a failure.

On pull request #42 every job passed: Linux (the distribution's `age` package, the pinned `age` 1.3.2 release, and PowerShell 7 on Linux), the agent's side against `age` 1.0.0 and 1.1.1, macOS, Windows PowerShell 5.1 and PowerShell 7, and the Linux job that opens the Windows-made blobs. That is test coverage, not field time; [`README.md`](README.md#status), “Status”, says what has run live.
