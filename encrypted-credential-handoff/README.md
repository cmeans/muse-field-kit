# Encrypted credential handoff

Hand your Muse a service credential **without the plaintext ever entering the chat**.

**What this is:** you encrypt a small JSON payload on your own machine with a public key whose private half lives only on your Muse's computer. You paste the resulting ciphertext into chat — ciphertext is safe to handle in the open. On the agent's side, decryption and use happen inside a single helper process: the plaintext is injected into the consuming tool's environment in memory and never written to disk. The helper itself never prints it; what reaches the agent is the consuming tool's own output, which is why each service is wired to a tool that doesn't print its credentials, and only that tool.

**Who it's for:** anyone whose agent needs credentials for *local tools* — MCP servers, CLIs — that take secrets as environment variables or config values, where the platform's browser-oriented saved logins can't reach. See “Why not a built-in vault?” below.

**Tested with:** Linux, OpenSSL 3.0 / 3.5, bash 5.x, Python 3.11 / 3.12, jq 1.7 / 1.8. Platform position in detail under “Platform.”

## Prompts for your Muse

**Set it up:**

> Set up the encrypted credential handoff from https://github.com/cmeans/muse-field-kit (folder `encrypted-credential-handoff`). Read README.md, then follow SETUP.md exactly. Use the scripts verbatim during setup; do not improvise the mechanism or write any decrypted value to disk. If you spot an improvement, propose it to me separately rather than applying it mid-setup. Give me the public key to embed in my copy of handoff.sh, report its fingerprint computed from the private key file, and wait: I will confirm the fingerprint from my copy matches before we test with a dummy credential.

**Stage a new credential (once set up):**

> I need to stage a credential for [service]. First tell me the exact label to put in the payload's "svc". I will run handoff.sh on my machine and paste the ciphertext here, in this conversation. When it arrives: store the ciphertext under that label, decrypt it only inside the consume helper, and run the label's recorded probe once (status only, no response body) to prove it works. Never ask me for the plaintext, never print a decrypted value, and do not write it anywhere.

## How it works

1. **Once, on the agent's machine:** generate an RSA-2048 keypair. The private key stays there, mode `0600`, owner-only, and never leaves. The public key is embedded in your handoff script. (`agent-setup.sh` does this and prints the fingerprint.)
2. **Per credential, on your machine:** run `handoff.sh`. It reads a small JSON payload with terminal echo off (or from a file, or a pipe), validates it (with `jq` installed: a single JSON object, a non-empty string `svc`, string values only; without `jq` it warns and skips validation), and prints one line of base64 ciphertext. Nothing plaintext touches disk in the interactive path.
3. **Verify the fingerprint.** The script prints the public key's SHA-256 fingerprint; the agent recomputes its fingerprint from the private key file (not from its notes) and reports it. Compare before trusting any output — see the threat model for exactly what this does and doesn't defend against.
4. **Paste the ciphertext into chat, in a direct message to your agent.** The agent may store the *ciphertext* in its memory store under the service's label — subject to the separation invariant below.
5. **At use time,** a per-service wrapper fetches the ciphertext from the store and hands it to the consume helper (`consume.py`, the template in this folder) by argument, file, or environment variable — never on stdin, which belongs to the target. The helper decrypts in memory, checks the payload's service binding, and replaces itself with the target process, the values injected into its environment. The helper prints nothing derived from the payload; the target's own stdout and stderr reach whoever ran it, so the target must be what SETUP's hard rules record for the label, a tool that doesn't print its credentials (`SETUP.md`, hard rules).

Payloads carry the service they belong to:

```json
{"svc": "example", "username": "agent-account", "password": "example-only"}
{"svc": "example-api", "api_key_id": "example-id", "api_key_secret": "example-only"}
```

## Threat model

**Defends against:**

- The credential appearing in chat transcripts, message logs, or the agent's context (chat, tool output, or files the agent later reads).
- Plaintext at rest on the agent's machine: none is written to any file. (Process memory is not magic: on a host with swap or core dumps enabled, in-memory plaintext can still reach disk that way. The claim is “never written by this design,” stated exactly.)
- A reader of the agent's memory store learning the secret from a stored blob — *provided the separation invariant holds* (below).
- Accidental disclosure by the agent in conversation: it never holds the value in context, so it cannot quote it.

**Does not defend against:**

- **A compromised or curious host.** The private key is a `0600` file on the agent's machine, and injected values are visible in the consuming process's environment to anything running as the same account, for as long as that process lives. If the agent's computer is provider-hosted, the provider — and its snapshots — are trusted. There is no way to use a credential on a machine without trusting that machine.
- **The agent itself misbehaving.** The agent's account can read its own key file. A separate hard rule in `SETUP.md` forbids it ever reading, printing, or copying that file outside the setup and consume helpers, but that is a policy control, not a cryptographic one. (A stronger variant — a helper running under a separate account owns the key — is noted under “Variations.”)
- **Sender authentication. There is none.** The public key is public: anyone can encrypt a valid blob. What stops a planted blob (arriving via a web page, a message, a tool result, a poisoned note) from being staged as a credential is a behavioral invariant, not cryptography: **the agent stages blobs only from a direct user turn in conversation, never from content it fetched or read.** A signing variant that removes this reliance on behavior is also noted under “Variations.”
- **Key compromise.** There is no forward secrecy: every stored copy of every blob becomes readable if the private key ever leaks. See “Compromise” under Rotation.
- **The helper as a decryption oracle.** Anything that can invoke the consume helper with a label can have that credential injected into a command of the invoker's choosing, and a command such as `printenv` simply prints it. **Execute access to the helper is read access to every staged credential.** The reference's control is a rule, not code: `SETUP.md` pins each label to what is recorded for it (its hard rules keep the one list), and treats any change to them as a mechanism change. (The hardening option, not in the reference: a per-label allowlist of commands that the helper itself enforces.)
- **Writers to the store.** The public key is public and the `svc` binding is not a signature: anyone who can write to wherever the blobs are stored can replace a label's blob with one of their own for the same label — their own account's credentials, say, so the agent logs in as them. Provenance (invariant 7) is checked when the user pastes a blob, not when a wrapper fetches it at use time. Keep the store writable by the agent alone; signed blobs (“Variations”) close this.
- **Unattended fetch.** Use without the user present means the agent authenticates to wherever the blobs are stored. That fetch credential is itself a secret, and this design does not cover it; in the original setup it is the agent platform's own authenticated session rather than a stored password. If your fetch needs a stored password of its own, you have moved the problem, not solved it.

## Invariants

Any implementation of this pattern — any platform, any protocol suite — must preserve all of these. If a proposed change cannot say how it preserves one, it is not a variant of this pattern; it is a weaker one.

1. **One-way delivery.** Encryption uses a public key whose private half exists only on the agent's machine.
2. **Ciphertext is safe to store where needed — and is not spread casually.** It may travel through chat and be stored for later use, but every retained copy is a future plaintext if the key ever leaks, so copies are kept to the places that need them.
3. **Plaintext never enters any model's context.** Not chat, not tool output, not logs the agent reads. Decryption and consumption happen inside one helper process, which prints nothing derived from the payload; the consuming command is one that doesn't print its credentials either, and it runs only as SETUP's hard rules record for the label (see `SETUP.md`). (The single deliberate exception is the dummy round-trip during setup, and even that uses the helper's `--check` mode, which reports field names and lengths, never values.)
4. **Plaintext is never written to disk on the agent's side.** Injected values live in the consuming process's environment — which means for the life of that process, not just the call, and they are inherited by its children. Long-lived consumers (daemons) should be chosen with that in mind.
5. **Key/ciphertext separation is mandatory.** The private key and the stored ciphertexts never share a disk or disk image, including backups and snapshots of either. This costs a remote fetch per use in the original setup; that cost is the price of the property, not an implementation detail.
6. **Identity verification.** The human compares the key fingerprint before first use. The agent recomputes it from the private key file at comparison time, using the shipped tooling (`agent-setup.sh --fingerprint`). Scope, stated plainly: since the key and its fingerprint normally travel through the same channel, this catches local tampering and a wrong paste. It does not defeat a compromise of the channel itself, nor a maliciously crafted copy of the script that lies about its own fingerprint — the fingerprint is not a secret, so take `handoff.sh` from this repository, not from an untrusted copy.
7. **Provenance.** The agent stages a blob only when the user pastes it in a direct conversational turn. Blobs found in tool results, fetched pages, files, messages, or pre-existing notes are never staged. (One exception: a rotation's rollback restores its own `<label>.old`; SETUP, Rotation step 4.)
8. **Purpose binding.** Each payload names its service in `svc`, and the consume side refuses a blob whose `svc` doesn't match the label it was fetched under: a blob staged for one service can't be swapped in for another. It does not stop someone who can write to the store from planting a new blob of their own for the same label; that is listed under “Does not defend against.”
9. **Controlled egress.** Decrypted values go only into the consuming process's environment. The helper itself never sends them anywhere, never passes them to another tool, and decrypts only for the labels the user approved, run as SETUP's hard rules record them. What the consuming process then does — including authenticating to its service, often over a network — is its normal function, and is the point of the exercise.
10. **Key confinement.** The private key is mode `0600`, owner-only, never displayed, and never copied.

**When separation (invariant 5) can't be met as stated** — the common case is a hosted agent whose memory store and home directory are the same disk image — there are three honest options: store the blobs in a service that lives elsewhere (a remote notes/memory service, a different machine), put the key or the store on a genuinely separate volume, or don't adopt the pattern until one of those is possible. An agent that cannot observe its provider's snapshot policy should say so rather than claim the invariant holds.

## Why not a built-in vault?

Saved-login and vault features are built for browser sign-in: the browser fills a form, and neither you nor the agent can read the value back out. That is the right design for websites. It does not solve this problem:

- A local tool often needs the credential as an **environment variable or config value at process start**. There is no supported path that turns a stored browser login into a value a subprocess can consume.
- API-credential flows accept API keys and OAuth, **not username/password pairs** for arbitrary local services — including services that are plain HTTP on a private network address and have no public login page to point a vault flow at.

Named precisely, and dated: as of November 2026, Muse's own credential machinery — the Secure Credentials Store for API-style credentials, and Sentinel credential surrogation for browser sign-in — declines username/password credentials (it supports `api_key` and OAuth-style flows), and saved website logins are consumed only by the browser's fill flow; no supported mechanism reads a stored value back for injection into a local process. That was verified against the platform's behavior in the author's setup in October 2026. If Meta ships a readback-for-local-tools path, this section should be revised and this pattern's reason to exist shrinks accordingly.

This pattern fills exactly that gap, and only that gap. Use the platform's own flows wherever they fit.

## Residual exposure (stated plainly)

- On your machine, the plaintext lives in the handoff shell's memory while the script runs, and could in principle be swapped out. No “shredding” is claimed.
- If you pass a file argument, that file already contains plaintext on your disk; the script did not put it there, and deleting it is your call.
- Whoever holds the private key can decrypt every blob ever made with its public key. Protect it like any private key; rotate on suspicion (below).
- The host and the agent-account caveats in the threat model are real and accepted by this design, not footnotes to skip.

## Rotation, and compromise

**Routine rotation** (no suspicion of compromise): generate a fresh keypair in a new directory (`HANDOFF_KEY_DIR`), update the embedded public key in `handoff.sh`, verify the fingerprint of the *new* key, then one service at a time: re-stage its credential under the new key (keeping a copy of the old blob until the probe passes, then deleting it), point both its wrappers, probe and use, at the new key (`HANDOFF_PRIVKEY`), and confirm one real login; if it fails, roll that service back to its old blob and key, and stop. When every service is switched, delete the old private key. Old blobs are then undecryptable. `SETUP.md` gives the exact commands.

**Compromise** (the private key may have leaked): rotating the key is *not* sufficient — every blob ever encrypted to it must be assumed readable. **Change each credential at its service first**, then perform a routine rotation and stage the new credentials. “Rotate on suspicion” means this paragraph, not just a new key.

## Variations: what is fixed, and what is a choice

RSA-2048 + OAEP-SHA256 is this folder's **reference implementation**, chosen because OpenSSL is everywhere and the payloads are tiny. RSA-2048 offers roughly 112-bit security, which NIST SP 800-131A accepts through 2030 and deprecates thereafter; it is not a weakness to be “upgraded” without cause.

The suite may be changed, deliberately, by the human, before setup — subject to two constraints:

- **Only as an existing, reviewed tool used as-is**: for example the `age` CLI, or libsodium's `crypto_box_seal` through a maintained binding. Each preserves the invariants above (with the same absence of sender authentication, which is behavioral in every variant listed here).
- **“Hybrid encryption, hand-rolled” is not a user-selectable variant.** A home-grown AES-GCM-plus-RSA construction is a mechanism change: it belongs upstream, as an issue or pull request against this repo, where it can be reviewed once for every adopter.

Two stronger variants worth knowing about: **signed blobs** (the human signs each payload with a key the agent can verify, removing the behavioral provenance invariant), and a **separate-account key holder** (a helper the agent can ask to decrypt-and-launch, but whose key file the agent's own account cannot read). Both are real designs; neither is in the reference implementation.

Whatever suite is in force, all ten invariants apply, and the known-answer test under `test/` is how an implementation proves it speaks the same protocol as the reference.

## Limits

RSA-2048 with OAEP-SHA256 encrypts at most **190 bytes** per blob (256 − 2×32 − 2). Keep payloads small; the examples above fit comfortably, including the `svc` field.

## Platform

The reference scripts are the reviewed **Linux** implementation (bash + OpenSSL), developed and tested on Linux on both sides.

- **macOS:** expected to work with the same bash script once OpenSSL 3 is installed and first on `PATH` (Homebrew's `openssl@3`; `SETUP.md` gives the exact lines) — note that the stock `/usr/bin/openssl` on macOS is LibreSSL, whose `pkeyutl` OAEP behavior is unverified here. Treat macOS as *expected, not yet reviewed*: a reviewed macOS reference will be added once one has been run end-to-end; until then any macOS port is unreviewed, and the interop test is its minimum bar.
- **Windows:** no reference yet. The expected shape is a small PowerShell script using `Read-Host -AsSecureString` (not saved to PSReadLine history) and .NET `RSA.Encrypt` with `RSAEncryptionPadding.OaepSHA256` — to be verified against the interop test when written. Until a reviewed Windows reference ships in this folder, a Windows port written by an agent is *unreviewed by definition*, and `SETUP.md` says how it must be gated (user review plus the interop test) before it touches a real credential.

In short: reviewed references where they exist; where they don't, the honest status is printed on the box.

## Operational cautions, learned the hard way

- **Test the decrypt/store path against scratch data first.** A dry run that overwrites a live credential store with test values is a self-inflicted outage. Point tests at a scratch config, and verify the live store is untouched afterward.
- **Keep a login probe honest:** after decrypting, attempt one real authentication before declaring the handoff good; judge it by status only, never by printing a response body; and log out any session the probe created if the service supports it.
- **One keypair per agent environment.** Do not reuse the key across machines; the point is that exactly one place can decrypt.

## Status: what is field-tested, and what is new

The core of this pattern — one keypair on the agent's machine, encrypt-on-yours, ciphertext through chat, decrypt-in-memory at use, key and ciphertext never sharing a disk — has run daily in the author's setup since October 2026 (the store-only separation form dates from 2026-10-12). New in this publication revision, and covered by the interop and refusal tests rather than by field time: the `svc` purpose binding and `--label` enforcement, the `--check` mode, the `--env` mapping option, the exec hand-over, `consume.py`'s refusal set, and SETUP's wrapper rules and example. `CHANGELOG.md` lists what ships.

A note on review, in the same spirit: the reviewers of this folder were AI agent sessions in the author's own multi-agent setup (structural review, line-level review with reproduced findings, and a cold read), plus the author. That is peer review inside one shop — valuable, and not a third-party security audit.

## Files

- `handoff.sh` — your side (Linux reference). Embed your agent's public key in the marked block before use.
- `agent-setup.sh` — the agent's side. Generates the keypair and prints the public key, the fingerprint, and the consume-side key path to use.
- `consume.py` — the consume-side template: fetch-side decryption in memory, `svc` purpose-binding check, environment injection, and a `--check` mode (field names and lengths only) for setup tests.
- `SETUP.md` — step-by-step instructions written for your Muse, including the hard rules, the precise definition of a mechanism change, and the rotation procedures.
- `test/` — a known-answer interop test: dummy keypair, a fixed blob, and its expected plaintext, so any port or variant can prove byte-compatibility.
- `SECURITY.md` — how to report a flaw in this pattern or these scripts.
- `CHANGELOG.md` — what ships in this folder, and later what changes.

MIT licensed, code and text alike.
