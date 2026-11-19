# Encrypted credential handoff

Hand your Muse a service credential **without the plaintext ever entering the chat**.

1. **You encrypt** a small JSON payload, such as `{"svc": "example", "username": "…", "password": "…"}`, on your own machine with `handoff.sh` (`handoff.ps1` on Windows), to your Muse's public key, its `age` recipient.
2. **You paste the ciphertext** into chat. It's safe to handle in the open: the private key that opens it lives only on your Muse's computer.
3. **At use time, a helper on Muse's side decrypts it in memory** and replaces itself with the one tool that needs it, the values in that tool's environment: decryption and use happen in that single process. The plaintext is never written to disk, and the helper prints nothing derived from it. What reaches Muse is the tool's own output, which is why each credential is wired to a tool that doesn't print it, and only that tool.

**Who it's for:** anyone whose agent needs credentials for programs it runs on its own machine that read them from their environment — MCP servers, CLIs, scripts that call an API — where the platform's browser-oriented saved logins can't reach. A PEM private key (a GitHub App's, say) travels too, in the payload's `private_key` field, and arrives the same way, as an environment variable. Not for website sign-in, or a program that needs the credential in a file, a config file or on stdin: this version delivers through the environment only. See `DESIGN.md`, “Why not a built-in vault?”.

**What it needs:** on your side, [`age`](https://github.com/FiloSottile/age) and, for `handoff.sh`, bash and `jq` 1.6 or newer (Linux, macOS); on Windows, `age` and the PowerShell that ships with Windows, nothing else. On the agent's side (Linux or macOS), bash, `age` and Python 3.7 or newer. No OpenSSL anywhere. “Installing age” and “Getting the scripts” say how; “Platform” says what runs where, and `DESIGN.md`, “What CI tests”, what is tested.

**Coming from 0.1.0?** Version 0.2.0 replaces 0.1.0's RSA keys with `age` and can't read 0.1.0's keys or blobs: a 0.1.0 install sets up again from scratch (a new identity, and each credential staged again).

**For your Muse:** `SKILL.md` routes each request (set up, stage a credential, rotate the key) to its step in `SETUP.md`, the instructions it follows. Muse finds a skill only once its folder is installed among its skills, not from a link to this repo, so the setup prompt below asks it to install this folder as one. The installed copy only points Muse back here: it reads the instructions and runs the scripts from a clone of this repository.

## Prompts for your Muse

**Set it up:**

> Set up the encrypted credential handoff from https://github.com/cmeans/muse-field-kit (folder `encrypted-credential-handoff`): clone it and work from the clone. Also install that folder as one of your skills, so its SKILL.md brings you back to the clone for later requests; run nothing from the installed copy. Read README.md, then follow SETUP.md exactly. Use the scripts verbatim during setup; do not improvise the mechanism or write any decrypted value to disk. If you spot an improvement, propose it to me separately rather than applying it mid-setup. Tell me which release to download my script from and the commands for my platform, then give me your recipient to save as handoff-muse.age beside my copy of the script, computed from your identity file, and wait: I will run my script's setup check, tell you its result, and confirm the recipient my copy prints matches yours before we test with a dummy credential.

**Stage a new credential (once set up):**

> I need to stage a credential for [service]. First tell me the exact label to put in the payload's "svc", and which fields the payload carries. I will run my handoff script on my machine and paste the ciphertext here, in this conversation. When it arrives: store the ciphertext under that label, decrypt it only inside the consume helper, and run the label's recorded probe once (status only, no response body) to prove it works. Never ask me for the plaintext, never print a decrypted value, and do not write it anywhere.

## How it works

1. **Once, on the agent's machine:** generate an `age` identity (an X25519 key pair). The identity, the private half, stays there, mode `0600`, owner-only, and never leaves. Its public half, the **recipient**, is one line of text (`age1` and 58 more characters) that goes in a file beside your handoff script, `handoff-<name>.age` (`handoff-muse.age` for the default name, `muse`). (`agent-setup.sh` makes the identity and prints the recipient.)
2. **Per credential, on your machine:** run `handoff.sh` (Linux, macOS) or `handoff.ps1` (Windows), from a release you downloaded and checked (“Getting the scripts”). It reads a small JSON payload with echo off (or from a file, or a pipe), checks it is a single JSON object with a non-empty string `svc` and string values only, with at least one known credential field, none of them empty, and no NUL (`\u0000`) in any value (what `consume.py` would refuse is refused here), encrypts it with `age` to the recipient, and prints one line of base64 ciphertext. Nothing plaintext touches disk in the interactive path.
3. **Compare the recipient.** Your script prints the recipient it encrypted to; the agent prints its recipient from the identity file (not from its notes) and reports it. They must be the same line, character for character, before you trust any output — see the threat model for exactly what this does and doesn't defend against.
4. **Paste the ciphertext into chat, in your own turn in the conversation with your agent.** The agent stores the *ciphertext* under the service's label in a store off its own disk — subject to the separation invariant below. On a stock Muse that is never its memory files, which share the key's disk: see “Choosing a store”.
5. **At use time,** a per-service wrapper fetches the ciphertext from the store and hands it to the consume helper (`consume.py`, the template in this folder) by argument, file, or environment variable — never on stdin, which belongs to the target. The helper checks the blob's `age` header (exactly one X25519 recipient, nothing that would ask for a passphrase or a plugin), decrypts in memory, checks the payload's service binding, and replaces itself with the target process, the values injected into its environment. The helper prints nothing derived from the payload; the target's own stdout and stderr reach whoever ran it, so the target must be what SETUP's hard rules record for the label, a tool that doesn't print its credentials (`SETUP.md`, hard rules).

### Payloads

Payloads carry the service they belong to, in `svc`, and string values only:

```json
{"svc": "example", "username": "agent-account", "password": "example-only"}
{"svc": "example-api", "api_key_id": "example-id", "api_key_secret": "example-only"}
{"svc": "example-app", "private_key": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----\n", "app_id": "12345", "installation_id": "67890"}
```

The fields `consume.py` knows, and the environment variable each goes into unless the label's wrapper maps it elsewhere (`--env field=NAME`):

| Field | Default variable |
| --- | --- |
| `username`, `password` | `SERVICE_USERNAME`, `SERVICE_PASSWORD` |
| `api_key_id`, `api_key_secret` | `SERVICE_API_KEY_ID`, `SERVICE_API_KEY_SECRET` |
| `token_id`, `token_secret` | `SERVICE_TOKEN_ID`, `SERVICE_TOKEN_SECRET` |
| `private_key` | `SERVICE_PRIVATE_KEY` (a PEM or similar multi-line secret, byte for byte) |
| `app_id`, `installation_id` | `SERVICE_APP_ID`, `SERVICE_INSTALLATION_ID` (a GitHub App's, beside its `private_key`) |

Every field stands alone; a payload carries the ones its tool needs. A field `consume.py` doesn't know is counted on stderr and injected nowhere, and `handoff.sh` and `handoff.ps1` count them before encrypting, and name the known field a likely misspelling is close to (`note: consume.py ignores 1 field(s) it doesn't know, 1 of them close to "username" (misspelled?)`), so a misspelling shows before the blob is sent. Neither prints the payload's own names: a value typed in a name's place could be a secret. A payload with no known field is refused, by `handoff.sh` and `handoff.ps1` before it is encrypted and by `consume.py`.

**Typing or pasting it.** `handoff.sh` reads a payload file as UTF-8 (a UTF-16 file, as Windows PowerShell 5.1's `>` writes, is refused with that reason; `handoff.ps1` reads one with a byte-order mark). At `handoff.sh`'s hidden prompt, one line can hold about 4 KB on Linux and 1 KB on macOS. Linux cuts a longer line (the script then says it may have been cut); macOS beeps and ignores the rest of the line, Enter and Ctrl-D included, so press Ctrl-C. A long payload on one line, such as a `private_key` JSON-escaped by hand, goes in through a pipe instead, as below (or as a file, which leaves it on disk); the prompt says so before you paste. Typographic quotes (“ ” ‘ ’), which some editors and chat apps put in place of `"`, aren't JSON quotes around a name or a value (inside a value, they're part of it): both scripts say so when they refuse a payload holding them.

**Building a `private_key` payload.** A PEM's line breaks have to be JSON-escaped, which is no job for a hidden paste. Let `jq` build the payload from the key file you already hold and pipe it straight in (Linux, macOS):

```sh
jq -n --arg svc example-app --rawfile private_key ./key.pem \
  --arg app_id 12345 --arg installation_id 67890 \
  '{svc: $svc, private_key: $private_key, app_id: $app_id, installation_id: $installation_id}' \
  | ./handoff.sh
```

On Windows, the same with PowerShell's own tools (this form works on Windows PowerShell 5.1 and PowerShell 7; `Get-Content -Raw` in its place can make 5.1's `ConvertTo-Json` add properties that `handoff.ps1` refuses):

```powershell
@{ svc = 'example-app'; private_key = [IO.File]::ReadAllText((Resolve-Path .\key.pem)); app_id = '12345'; installation_id = '67890' } | ConvertTo-Json -Compress | .\handoff.ps1
```

What each step writes: `jq` (or `ConvertTo-Json`) reads the key file and writes the payload only into the pipe; the handoff script reads the pipe and writes only the blob, on stdout. Nothing new reaches the disk or the terminal. The key file itself was on your disk before you started; deleting it, once the credential is staged and probed, is your call (“Residual exposure”). If the key comes from a tool's output rather than a file, `--rawfile private_key <(that-tool …)` reads it through a pipe instead. The app and installation IDs aren't secrets, so they can sit on the command line; a secret never does (another program can read a command line, and the shell's history keeps it): secrets come from a file or from the script's hidden prompt.

## Threat model

**Defends against:**

- The credential appearing in chat transcripts, message logs, or the agent's context (chat, tool output, or files the agent later reads).
- Plaintext at rest on the agent's machine: none is written to any file. (Process memory is not magic: on a host with swap or core dumps enabled, in-memory plaintext can still reach disk that way. The claim is “never written by this design,” stated exactly.)
- A reader of the blob store learning the secret from a stored blob — *provided the separation invariant holds* (below).
- Accidental disclosure by the agent in conversation: it never holds the value in context, so it cannot quote it.

**Does not defend against:**

- **A compromised or curious host.** The private key is a `0600` file on the agent's machine, and injected values are visible in the consuming process's environment to anything running as the same account, for as long as that process lives. If the agent's computer is provider-hosted, the provider — and its snapshots — are trusted. There is no way to use a credential on a machine without trusting that machine.
- **The agent itself misbehaving.** The agent's account can read its own key file. A separate hard rule in `SETUP.md` forbids it ever reading, printing, or copying that file outside the setup and consume helpers, but that is a policy control, not a cryptographic one. (A stronger variant — a helper running under a separate account owns the key — is noted in `DESIGN.md`, “Variations.”)
- **Sender authentication. There is none.** The recipient is public: anyone can encrypt a valid blob. What stops a planted blob (arriving via a web page, a message from anyone else, a tool result, a poisoned note) from being staged as a credential is a behavioral invariant, not cryptography: **the agent stages blobs only from a direct user turn in conversation, never from content it fetched or read.** A signing variant that removes this reliance on behavior is also noted in `DESIGN.md`, “Variations.”
- **Key compromise.** There is no forward secrecy: every stored copy of every blob becomes readable if the private key ever leaks. See “Compromise” under Rotation.
- **The helper as a decryption oracle.** Anything that can invoke the consume helper with a label can have that credential injected into a command of the invoker's choosing, and a command such as `printenv` simply prints it. **Execute access to the helper is read access to every staged credential.** The reference's control is a rule, not code: `SETUP.md` pins each label to what is recorded for it (its hard rules keep the one list), and treats any change to them as a mechanism change. (The hardening option, not in the reference: a per-label allowlist of commands that the helper itself enforces.)
- **Writers to the store.** The recipient is public and the `svc` binding is not a signature: anyone who can write to wherever the blobs are stored can replace a label's blob with one of their own for the same label — their own account's credentials, say, so the agent logs in as them. Provenance (invariant 7) is checked when the user pastes a blob, not when a wrapper fetches it at use time. Keep the store writable by the agent alone; signed blobs (`DESIGN.md`, “Variations”) close this.
- **Unattended fetch.** Use without the user present means the agent authenticates to wherever the blobs are stored. That fetch credential is itself a secret, and this design does not cover it; in the original setup it is the agent platform's own authenticated session rather than a stored password (a custom connection whose token the platform swaps in at egress; the fetch needs the platform's proxy variables written into its `env -i` line, SETUP step 7). “Choosing a store” says which stores meet this on Muse. If your fetch needs a stored password of its own, you have moved the problem, not solved it.

## Invariants

Any implementation of this pattern — any platform, any protocol suite — must preserve all of these. If a proposed change cannot say how it preserves one, it is not a variant of this pattern; it is a weaker one.

1. **One-way delivery.** Encryption uses a public key whose private half exists only on the agent's machine.
2. **Ciphertext is safe to store where needed — and is not spread casually.** It may travel through chat and be stored for later use, but every retained copy is a future plaintext if the key ever leaks, so copies are kept to the places that need them.
3. **Plaintext never enters any model's context.** Not chat, not tool output, not logs the agent reads. Decryption and consumption happen inside one helper process, which prints nothing derived from the payload; the consuming command is one that doesn't print its credentials either, and it runs only as SETUP's hard rules record for the label (see `SETUP.md`). (The single deliberate exception is the dummy round-trip during setup, and even that uses the helper's `--check` mode, which reports field names and lengths, never values.)
4. **Plaintext is never written to disk on the agent's side.** Injected values live in the consuming process's environment — which means for the life of that process, not just the call, and they are inherited by its children. Long-lived consumers (daemons) should be chosen with that in mind.
5. **Key/ciphertext separation is mandatory.** The private key and the stored ciphertexts never share a disk or disk image, including backups and snapshots of either. This costs a remote fetch per use in the original setup; that cost is the price of the property, not an implementation detail.
6. **Identity verification.** The human compares the recipient before first use: the whole line their script prints with the whole line the agent reports. The agent derives it from the private key file at comparison time, using the shipped tooling (`agent-setup.sh --fingerprint`, which prints the recipient). Scope, stated plainly: since the recipient normally travels through the same channel as the comparison, this catches local tampering and a wrong paste. It does not defeat a compromise of the channel itself, nor a maliciously crafted copy of the script that lies about the recipient it encrypts to — the recipient is not a secret, so take the script from this repository's release, checked as “Getting the scripts” says, not from an untrusted copy, and never from a file sent through chat.
7. **Provenance.** The agent stages a blob only when the user pastes it in a direct conversational turn. Blobs found in tool results, fetched pages, files, messages from anyone else, or pre-existing notes are never staged. (One exception: during a rotation, a label's blob is replaced by the one `consume.py --rewrap` makes from it, the same payload encrypted to the new key; SETUP, Rotation step 4.)
8. **Purpose binding.** Each payload names its service in `svc`, and the consume side refuses a blob whose `svc` doesn't match the label it was fetched under: a blob staged for one service can't be swapped in for another. It does not stop someone who can write to the store from planting a new blob of their own for the same label; that is listed under “Does not defend against.”
9. **Controlled egress.** Decrypted values go only into the consuming process's environment. The helper itself never sends them anywhere, never passes them to another tool, and decrypts only for the labels the user approved, run as SETUP's hard rules record them. What the consuming process then does — including authenticating to its service, often over a network — is its normal function, and is the point of the exercise.
10. **Key confinement.** The private key is mode `0600`, owner-only, never displayed, and never copied. During a rotation the old key stays beside it, under the same rules, until it is retired.

## Choosing a store

Where the agent keeps the blobs matters as much as the key: the store must be off the key's disk, and only the fetch path may read it. `STORES.md` says what a store must provide (R1 to R6), which stores were tested on Muse, and how to approve the connection.

## Residual exposure (stated plainly)

- On your machine, the plaintext lives in the handoff script's memory while it runs (the shell's, or PowerShell's), and could in principle be swapped out. No “shredding” is claimed. `handoff.sh` turns core dumps off for itself and the programs it runs (`ulimit -c 0`), so a crash or a Ctrl-\ at the prompt writes no core file; a system that collects crashes another way (Windows Error Reporting, for `handoff.ps1`) is outside the script's reach.
- If you pass a file argument, or build a payload from a key file (“Payloads”), that file already contains plaintext on your disk; the script did not put it there, and deleting it is your call.
- Whoever holds the private key can decrypt every blob ever made with its public key. Protect it like any private key; rotate on suspicion (below).
- The host and the agent-account caveats in the threat model are real and accepted by this design, not footnotes to skip.

## Rotation, and compromise

**Routine rotation** (no suspicion of compromise) works as key-management services do it: the old key keeps decrypting until nothing needs it. `agent-setup.sh --rotate` moves the old key aside as `<key path>.previous` and puts a new one at the same path, so no wrapper changes, and `consume.py` tries the previous key whenever the current one can't open a blob. You replace the line in `handoff-<name>.age` beside your handoff script with the new recipient and compare it again; the script itself never changes. The agent then runs each label's recorded rewrap wrapper (`consume.py --rewrap --blob-file`, started as the other wrappers start it), which re-encrypts the same payload to the new key and replaces the stored blob atomically, and confirms one real login on the new blob. Once every label is on the new key, checked against the agent's setup record and by a last probe of each, `agent-setup.sh --retire --yes` deletes the old one, and blobs still made for it no longer open. (Without `--yes` it keeps the old key, removing only a leftover temporary link to it, and says what would stop opening: the script can't tell whether some label's blob still needs the old key, so the agent's check is what guards it.) An interruption at any point leaves every label working, given a file store or a store with an atomic write (for one without, SETUP says what's at risk). `SETUP.md` gives the exact steps.

An install whose wrappers run a consumer other than this folder's `consume.py` must update that consumer to try the previous key before its first rotation; otherwise its labels stop working when the key rotates.

**Compromise** (the private key may have leaked): rotating the key is *not* sufficient — every blob ever encrypted to it must be assumed readable. **Change each credential at its service first**, then rotate the key (retiring first any rotation already under way, whose keys leaked too), retire the old key right away, and stage the new credentials; don't rewrap the old blobs, which hold the exposed ones. “Rotate on suspicion” means this paragraph, not just a new key.

## Limits

`consume.py` accepts a blob of at most **65,536** base64 characters (`MAX_BLOB_FILE`), and `handoff.sh` and `handoff.ps1` send a payload of at most **48,696** bytes (`MAX_PAYLOAD`), which keeps the blob within that with room for a rage grease stanza. Line breaks and blanks in a blob don't count toward the cap; a `--blob-file` may hold up to 131,072 characters as read (`MAX_BLOB_FILE_RAW`), line breaks included. A blob made by Go `age` is 200 bytes larger than its payload before base64, which adds a third: a password-sized payload makes a blob of about 370 characters, and a GitHub App's `private_key` payload one of about 2,700. Every store tested carried a 64,000-character blob (Muse, 2026-11-17; `STORES.md`), so no store sets a limit below the cap. The chat path carries one too: an 8,000-character blob and a 64,000-character blob, which the author pasted into a chat with Muse on 2026-11-17, each arrived at exactly that length, and `consume.py --check` passed on both. So the cap stays at 65,536 characters (a payload of up to 48,696 bytes).

## Installing age

Your side needs `age` (and, for `handoff.sh`, `jq` 1.6 or newer); the agent's side needs `age` (with `age-keygen`, which comes with it) and Python 3.7 or newer. There's no minimum `age` version (`DESIGN.md`, “Choosing the suite”), but install the current release where you can choose.

- **Linux and macOS:** your package manager (`sudo apt install age jq`, `sudo dnf install age jq`, or `brew install age jq` with [Homebrew](https://brew.sh)); `INSTALL-linux-macos.md` has the details.
- **Windows:** `winget install --id FiloSottile.age`; `INSTALL-windows.md` has the details.
- **Phones, release binaries, and other ways:** `INSTALL-options.md`.

## Getting the scripts

Your agent tells you which release to use (the one its own scripts come from) and gives you only its recipient through chat: **it never sends you the script**, and a script that arrives as a file in chat isn't one to run (invariant 6). `INSTALL-linux-macos.md` and `INSTALL-windows.md` say how to download the script for your platform, check it against the release's `SHA256SUMS`, save the agent's recipient beside it, and run the setup check.

## Platform

- **Your side, Linux and macOS:** `handoff.sh`, with bash (written for macOS's own `/bin/bash` too), `age` and `jq`.
- **Your side, Windows:** `handoff.ps1`, with Windows PowerShell 5.1 or PowerShell 7 and `age.exe`. It is `handoff.sh`'s twin: the same recipient file, rules and messages.
- **The agent's side, Linux and macOS:** `agent-setup.sh` and `consume.py`. They rely on Unix file ownership and modes and on `exec`, so there is no Windows version of the agent's side. On macOS, a fetched store's rotation needs a RAM disk (`SETUP.md`, Rotation step 4).
- **Phones:** untested (`INSTALL-options.md`).

A port to another platform written by an agent is *unreviewed by definition*, and `SETUP.md` says how it must be gated (the user's review plus the interop test under `test/`) before it touches a real credential.

What CI tests on each platform is in `DESIGN.md`, “What CI tests”.

## Operational cautions, learned the hard way

- **Test the decrypt/store path against scratch data first.** A dry run that overwrites a live credential store with test values is a self-inflicted outage. Point tests at a scratch config, and verify the live store is untouched afterward.
- **Keep a login probe honest:** after decrypting, attempt one real authentication before declaring the handoff good; judge it by status only, never by printing a response body; and log out any session the probe created if the service supports it.
- **One identity per agent environment.** Do not reuse the key across machines; the point is that exactly one place can decrypt.

## Status: what is field-tested, and what is new

The core of this pattern — one key pair on the agent's machine, encrypt-on-yours, ciphertext through chat, decrypt-in-memory at use, key and ciphertext never sharing a disk — has run daily in the author's setup since October 2026 (the store-only separation form dates from 2026-10-12). Before 0.1.0 was published, Muse also ran its `consume.py` and wrappers live on two production labels, one complete routine rotation (rotate, rewrap, last pass and retire, 2026-11-14), and each of the five stores in `STORES.md`'s table end to end with a dummy blob (2026-11-14). All of that ran on 0.1.0's RSA keys and blobs.

Version 0.2.0 keeps that flow and changes what's under it: `age` in place of RSA and OpenSSL, the header check, the `private_key`, `app_id` and `installation_id` fields, `handoff.ps1` for Windows, the setup checks, and the release files. These are covered by the interop and refusal tests on Linux, macOS and Windows (`DESIGN.md`, “What CI tests”), not yet by field time: 0.2.0's store tests on Muse at the blob sizes up to 64,000 characters passed (2026-11-17), and its live runs moving its own labels to `age` one at a time are pending: they come after the release. Not yet field-tested at all: a compromise response, which no live run has needed, a read-only store token, approvals on a fetch (`STORES.md`, “Approving a connection”), typing a payload into `handoff.ps1` at a real Windows console (CI runs it with no console), and phones. `CHANGELOG.md` lists what ships.

A note on review, in the same spirit: the reviewers of this folder were AI agent sessions in the author's own multi-agent setup (structural review, line-level review with reproduced findings, a cold read, and QA rounds on every pull request), plus Muse, which reviewed every pull request as the agent this folder is written for, and the author. That is peer review inside one shop — valuable, and not a third-party security audit.

## Files

- `handoff.sh` — your side, on Linux and macOS. It reads your agent's recipient from `handoff-<name>.age` in its own directory (`--to NAME`; the default name is `muse`), and refuses to encrypt without one: the script holds no key of its own. `--fingerprint` prints the recipient it would encrypt to; `--check-setup` checks the tools.
- `handoff.ps1` — the same for Windows (`-To NAME`, `-File FILE`, `-Fingerprint`, `-CheckSetup`, `-Help`).
- `agent-setup.sh` — the agent's side. Makes the identity and prints the recipient and the consume-side key path to use; `--fingerprint` prints an existing identity's recipient, `--public-key` prints the wrappers' identity's recipient (from `HANDOFF_PRIVKEY`, or the default; it takes no KEY) with where to save it, `--rotate` and `--retire` start and end a rotation, and `--check-setup` checks the tools.
- `consume.py` — the consume-side template: the header check, decryption in memory (with the previous key too, during a rotation), `svc` purpose-binding check, environment injection, a `--check` mode (field names and lengths only) for setup tests, and `--rewrap` for rotation.
- `SETUP.md` — step-by-step instructions written for your Muse, including the hard rules, the precise definition of a mechanism change, and the rotation procedures.
- `SKILL.md` — the skill file for your Muse: when to use the handoff, which `SETUP.md` step each request goes to, and the rules that hold from the start. It routes only; `SETUP.md` is the authority.
- `test/` — the interop and refusal tests, with known-answer vectors (a dummy identity, fixed blobs from Go `age` and rage, and the expected plaintext), so any port or variant can prove byte-compatibility.
- `INSTALL-linux-macos.md`, `INSTALL-windows.md` — your side on one platform: install the tools, get and check the script, save the recipient, check the setup. `INSTALL-options.md` — other ways to install (phones, release binaries).
- `STORES.md` — choosing and checking a store for the blobs.
- `DESIGN.md` — background: why not a vault, the choices behind the design, and what CI tests.
- `STORE-TEST.md` — a prompt for your agent to test a store not yet listed in `STORES.md`.
- `SECURITY.md` — how to report a flaw in this pattern or these scripts.
- `CHANGELOG.md` — what ships in this folder, and what changes.

MIT licensed, code and text alike.
