# Encrypted credential handoff

Hand your Muse a service credential **without the plaintext ever entering the chat**.

1. **You encrypt** a small JSON payload, such as `{"svc": "example", "username": "…", "password": "…"}`, on your own machine with `handoff.sh` (`handoff.ps1` on Windows), to your Muse's public key, its `age` recipient.
2. **You paste the ciphertext** into chat. It's safe to handle in the open: the private key that opens it lives only on your Muse's computer.
3. **At use time, a helper on Muse's side decrypts it in memory** and replaces itself with the one tool that needs it, the values in that tool's environment: decryption and use happen in that single process. The plaintext is never written to disk, and the helper prints nothing derived from it. What reaches Muse is the tool's own output, which is why each credential is wired to a tool that doesn't print it, and only that tool.

**Who it's for:** anyone whose agent needs credentials for programs it runs on its own machine that read them from their environment — MCP servers, CLIs, scripts that call an API — where the platform's browser-oriented saved logins can't reach. A PEM private key (a GitHub App's, say) travels too, in the payload's `private_key` field, and arrives the same way, as an environment variable. Not for website sign-in, or a program that needs the credential in a file, a config file or on stdin: this version delivers through the environment only. See “Why not a built-in vault?” below.

**What it needs:** on your side, [`age`](https://github.com/FiloSottile/age) and, for `handoff.sh`, bash and `jq` 1.6 or newer (Linux, macOS); on Windows, `age` and the PowerShell that ships with Windows, nothing else. On the agent's side (Linux or macOS), bash, `age` and Python 3.7 or newer. No OpenSSL anywhere. “Installing age” and “Getting the scripts” say how; “Platform” says what is tested where.

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
- **The agent itself misbehaving.** The agent's account can read its own key file. A separate hard rule in `SETUP.md` forbids it ever reading, printing, or copying that file outside the setup and consume helpers, but that is a policy control, not a cryptographic one. (A stronger variant — a helper running under a separate account owns the key — is noted under “Variations.”)
- **Sender authentication. There is none.** The recipient is public: anyone can encrypt a valid blob. What stops a planted blob (arriving via a web page, a message from anyone else, a tool result, a poisoned note) from being staged as a credential is a behavioral invariant, not cryptography: **the agent stages blobs only from a direct user turn in conversation, never from content it fetched or read.** A signing variant that removes this reliance on behavior is also noted under “Variations.”
- **Key compromise.** There is no forward secrecy: every stored copy of every blob becomes readable if the private key ever leaks. See “Compromise” under Rotation.
- **The helper as a decryption oracle.** Anything that can invoke the consume helper with a label can have that credential injected into a command of the invoker's choosing, and a command such as `printenv` simply prints it. **Execute access to the helper is read access to every staged credential.** The reference's control is a rule, not code: `SETUP.md` pins each label to what is recorded for it (its hard rules keep the one list), and treats any change to them as a mechanism change. (The hardening option, not in the reference: a per-label allowlist of commands that the helper itself enforces.)
- **Writers to the store.** The recipient is public and the `svc` binding is not a signature: anyone who can write to wherever the blobs are stored can replace a label's blob with one of their own for the same label — their own account's credentials, say, so the agent logs in as them. Provenance (invariant 7) is checked when the user pastes a blob, not when a wrapper fetches it at use time. Keep the store writable by the agent alone; signed blobs (“Variations”) close this.
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

Step 4's store is a function, not a product: any place that holds an opaque text blob under a service label and hands that exact blob back later. Only ciphertext is ever written to it or read from it. The obvious choice is a trap: **most agents' built-in memory is files on the agent's own machine, on the same disk as the private key**, and a blob stored there sits beside the key (invariant 5 fails). The author's setup works because its store is a remote service, fetched over the network at use time. Whatever you use has to meet the same requirements.

### What a store must provide

All six. A candidate that fails one isn't a store for this pattern, whatever it calls itself. Two things to check along the way: the largest blob the store holds as *one* item, which is a different limit from its total quota (splitting a blob across items is a partial pass at best); and what a fetch of a missing label returns, and whether "missing" can be told from "damaged" from that result.

1. **R1, separation from the key.** The blobs don't live on the key's disk or disk image, including backups and snapshots of either. A synced or cached local copy (a desktop sync client's mirror, a client-side cache) is a local copy and fails R1 like a plain file. A file a wrapper keeps on a tmpfs while it works (SETUP, Rotation step 4) is off the disk (unless the host swaps it out to a swap area on the key's disk, as the threat model's plaintext caveat says), and is removed when the wrapper is done.
2. **R2, addressable by label.** A blob can be stored, fetched and *replaced* under its label: re-staging and rotation replace a label's blob in place. It can also be *deleted*, which retires a label. Check how fetch addresses an item: by a stable id or path, not by name or search alone. Check whether two items can share a name, whether a new item takes time to appear in search, and whether labels that differ only in letter case share a slot.
3. **R3, private.** Only the user and the agent can read it. Every reader holds a copy that becomes plaintext if the key ever leaks (invariant 2), so a store shared with other people or agents widens that set.
4. **R4, a fetch that doesn't recreate the problem.** Fetching a blob needs no password, token or key file stored on the agent's machine: otherwise a copy of the agent's disk yields both the key and the means to fetch every blob, and separation has bought nothing. Access through the agent platform's own authenticated session meets R4: a connected service the platform reaches for the agent, or a custom connection whose token the platform swaps in at egress, so the real token never reaches the machine. If a store's fetch credential has to live on the agent's machine, it is the **weaker form**: say so plainly, scope that credential to the blob store alone, and record the store as the weaker form. It still defends against a reader of the store alone, not against a copy of the agent's disk. A platform session isn't free either: what the agent reaches through it, any process on its machine can reach too, so the connected account's whole reach counts (below).
5. **R5, a ciphertext-only path to the helper.** The fetch returns the blob straight to the label's wrapper, which hands it to the consume helper. It never passes through the agent's context, a tool output the agent reads, or a log. (Ciphertext in context wouldn't leak the secret, but a fetch path the agent reads is one a planted blob can be injected into, against invariant 7.) Also note where the fetched blob lands on the agent's side, in memory or in a file, and on which disk.
6. **R6, checkable.** The agent can say where the blobs live and why R1 holds there, and records both (SETUP step 8). An agent that can't observe its provider's snapshot or backup policy says so, rather than claiming R1 holds.

Three properties don't disqualify a store, but change what a rotation leaves behind and who could act on a leak, so know them before you choose:

- **History.** A store that keeps old versions (revisions, a changelog, a trash folder, a soft delete) keeps every replaced blob, each still readable with the key it was made for. After a rotation, or a compromise, purge them where the store allows it, and where it doesn't, know that they remain (invariant 2).
- **Idle expiry.** Whether the store expires, evicts or archives an idle item or database. A missing blob looks like a vanished credential, so check the plan's idle rules before you rely on it.
- **Reach.** What else the store's access opens. A connection to a whole account (a whole Drive, a whole workspace) gives standing access to everything in that account, not only the blobs. An account or database used for the blobs and nothing else keeps that reach to the blobs.

### On Muse (as of November 2026)

A stock Muse has no off-disk store until the user connects one: its memory files and workspace are on its VM's disk, beside the key. With nothing connected, the honest answer is the one at the end of this section: don't adopt the pattern yet. These stores were each tested end to end on Muse on 2026-11-14 with a dummy blob (stage, unattended fetch into `consume.py --check`, replace, delete, history, nothing left on disk); in every one the blob reached `consume.py` without passing through Muse's context. Those tests used a 0.1.0 blob of about 350 characters. **Tested on Muse (2026-11-17):** the same stores again with 0.2.0 dummy blobs of 400, 2,700, 8,000 and 64,000 characters (a password-sized payload, a GitHub App's private key, and two larger sizes), each staged unattended, fetched unattended, replaced, and checked byte for byte with `consume.py --check`. Every store passed every size, so no store limited the blob: each carried 64,000 characters, close to the 65,536 that `consume.py` accepts (“Limits”). The history and delete columns below come from that run where it re-checked them, and from 2026-11-14 where it didn't.

| Store | How Muse reaches it | Largest blob tested | Unattended fetch | Old blob after a replace | Delete | Reach |
|---|---|---|---|---|---|---|
| A dedicated Redis database (Upstash) | a custom connection, token swapped in at egress | 64,000 characters | yes, with the platform's proxy variables in the fetch's `env -i` line | none reachable through its API (provider backups not observable) | permanent through its API (backups, including an idle free database's archive, not observable) | that one database |
| Google Drive | the platform's Drive connector | 64,000 characters | yes (it downloads to a file: put that on a tmpfs) | kept as a revision; the superseded revision can be deleted through the API, the live one can't | permanent (the file is gone, 404 after) | the whole Drive |
| Dropbox | the platform's Dropbox connector | 64,000 characters | yes (it downloads to a file: put that on a tmpfs) | no revision or restore through the connector (the provider's own version retention can't be seen from it) | soft only: the file goes to Deleted files, restorable in Dropbox's own interface; the connector has no permanent delete | the whole account |
| Notion | the platform's Notion connector | 64,000 characters (one block, several blocks or a file attachment) | yes | **reachable through the connector:** the page's version changes show the superseded blob (this reverses 2026-11-14's finding) | soft only: the page moves to Trash, a trashed page still returns its content when fetched by id, and the connector can't delete permanently or empty the Trash | the whole workspace |
| A remote memory service shared with other agents (the author's) | a custom connection | 64,000 characters | yes, with the proxy variables | kept in the entry's change history, readable with its history | soft, recoverable for 30 days (the entry stays in the deleted listing; no hard purge through the connection) | every agent sharing it |

In order of preference:

1. **A store dedicated to the blobs, through a custom connection.** It meets R1 to R6 with the smallest reach. What the user sets up at the provider, whatever its console looks like this month: a database (or bucket) used for these blobs and nothing else; nothing that evicts or expires keys, since a missing blob looks exactly like a staged credential that vanished, and a plan that doesn't archive or remove an idle database (Upstash's free tier archives one after at least 30 days with no activity, keeping a backup of it: every fetch fails from then on, and the data comes back only in a new database, with a new host, so the connection is registered again and its host recorded again); an HTTPS API that takes a bearer token. The provider's own documentation says how to create one (for the tested example, [Upstash's Redis docs](https://upstash.com/docs/redis)). The user gives Muse only the endpoint's host name. The token goes nowhere but the platform's own credential page when Muse registers the connection: never into chat, a note or a file. Don't paste anything copied from the provider's console (sample commands, connection snippets, a ready-made prompt for an agent): those carry the token with them. Tested limit: Upstash's read-only token wouldn't register as a connection on 2026-11-14 (the platform's connect check refused it while the full token passed), so the tested setup is one connection with the full token, and the fetch path can also write to the store. That is the "Writers to the store" exposure in the threat model, kept to that one database.

   Muse's side, which doesn't depend on the provider's console: it registers the connection through the platform's own credential flow, naming the database's host as the only host the connection may reach, with the token sent as a bearer header; the platform doesn't let those be edited afterward, so a mistake means registering again. The platform's connect check tries the token when it's registered (that check is what refused Upstash's read-only token), but only the first real fetch proves it works for the label. The fetch program (SETUP step 7's fetch rules) asks the store's REST API for the label's slot (for Redis, a `GET` of `/get/<key>`), with a bounded timeout (curl's `--max-time`, say) so a stalled call fails instead of holding up the MCP client, prints only the blob, and exits non-zero on an HTTP error, an error in the reply, a missing key or a value that isn't a string: Redis answers a missing key with a null result, and a fetch that prints it hands `consume.py` the text `null`, which it refuses as "not an age blob", not as a missing one. The write program sends the blob as the request body (for Redis, a `POST` to `/set/<key>`) and exits non-zero unless the store answers that it was written. Both run under their own `env -i` with the platform's proxy variables written in (a bare `env -i` fails), and the token appears in neither, in no wrapper and on no command line. The slot name goes into the URL path, where a `/` adds an argument and a `#` or `?` cuts the name short (a label `svc#2` would overwrite label `svc`'s blob): if a label holds anything but ASCII letters, digits, `_`, `.`, `:` and `-`, or doesn't start with a letter or digit (curl collapses a name of `.` or `..` as a path segment), give it a slot name that does (`key=`, SETUP Rotation step 4), and don't rely on percent-encoding. On a store that ignores case (Dropbox paths, suspected; a file store on a case-insensitive volume), labels that differ only in case share one slot: give them different slot names.
2. **Google Drive, Dropbox or Notion, on an account used for the blobs alone.** The connectors reach the whole account (or workspace), so a dedicated account keeps their reach to the blobs. On Drive, a replaced blob stays as a revision until it's deleted. On Dropbox and Notion, a delete is soft: the file or page stays restorable (Dropbox's Deleted files, Notion's Trash) and the connector can't purge it. On Notion the connector also reads back a replaced blob (page version changes), and a trashed page can still be fetched by id; on Dropbox the provider's own old versions are out of the connector's reach and unchecked. Notion's reachable history doesn't move it out of this tier, but within it, a rotation leaves replaced blobs there that Muse can't purge, which Drive's deletable revision doesn't. Points the tests found:
   - **Drive** uploads only from a file under the home directory (a tmpfs path is refused), so staging, and a rewrap's write, puts a copy of the ciphertext on the key's disk: remove it right after the upload, but on a copy-on-write or snapshotted filesystem its blocks may outlive the removal, so Drive meets R1 only with that exception, recorded (R6). Replace a blob with an update that keeps its file id, and fetch it by id: Drive allows several files with one name, and a fetch by name can find a stale one. Its download writes to a file: put it in a directory of your own on a tmpfs, made by the fetch program if it's missing (a restart empties the tmpfs; the same rules as Rotation step 4's file, SETUP), and remove the file once the blob is handed over.
   - **Dropbox**'s connection starts read-only, and staging needs a one-time grant of write access. Its download also writes to a file (a tmpfs path, removed after, as for Drive), and takes the path as a list of entries (`{"entries": [path]}`); a single `path` argument fails in every environment with a misleading message about file permissions.
   - **Notion**: a staged page turned up in search only after about a minute, so a fetch should find the page by its id, not by searching for it, or the probe right after staging can fail. A 64,000-character blob as one paragraph was accepted and came back byte for byte (2026-11-17): the 2,000-character rich-text limit didn't apply through the connector, so there's no need to split. Splitting across blocks, joined in order, also passed. A `.txt` attachment, uploaded and downloaded by id, passed too; it is an alternative, but it adds an upload step, and one upload failed once with no message (an immediate retry worked), so the plain page is simpler.
   - **Upstash**: its documented limits (2026-11-17) are far above the cap: 10 MB per request, 100 MB per value. The free tier's 500,000 commands and 10 GB of bandwidth a month are far more than a handful of credentials need.
3. **A remote memory or notes service you already run for agents**, as in the author's setup. It meets R4 and R5, but every agent sharing it can read the blobs (R3), and its history keeps replaced blobs.

Limited forms, for staging or tests rather than everyday use:

- **A third-party store reached with its own credential on Muse's VM** (a cloud API token, an SSH key to a machine you control): the weaker form of R4.
- **`/dev/shm`** (a tmpfs): off the disk, and needs no secret, but it is emptied at every VM restart, which Muse reported as frequent (2026-11-14), and possibly at your account's last logout too (SETUP, Rotation step 4), and every credential has to be staged again after one. That a tmpfs is outside the provider's snapshots is an inference: Muse can't observe the provider's policy.
- **Muse's built-in file links**: off the VM and fetchable without a secret, but they last at most 48 hours (as Muse reported, 2026-11-14), and anyone holding a link can read it (R3).

Not stores: Muse's own memory files and workspace (the key's disk); any file on its VM; a sync client's local mirror; a public repository, gist or pastebin (ciphertext is safe to handle in the open, not to publish, and a public copy can't be deleted); the platform's credential stores (the Secure Credentials Store, saved website logins: no tool can read a value back out; a custom connection's token is held there and swapped in at egress, never read).

If nothing qualifies, don't adopt the pattern yet, or put the key or the store on a genuinely separate volume. A store that fails these requirements doesn't make the pattern slightly weaker; it removes the property the pattern is for.

### Other stores (untested)

These weren't tested for this release, and free tiers and limits change, so check each one against the requirements above before you use it.

- **Cloudflare Workers KV:** a dedicated key-value store, like Upstash, reached through a custom connection. Check the free tier's limits and that no history is kept.
- **Redis Cloud (free database):** plain Redis, the same model as Upstash, reached through a custom connection.
- **Supabase or Firebase (free tier):** a private table or record, with more setup. Check row-level access, so nothing is readable by anyone else.
- **OneDrive or Box:** file storage, like Drive and Dropbox. Use a dedicated account, and check version history and the recycle bin.
- **Evernote:** a notes app. Check whether your agent can reach it unattended at all, then the note history, the trash and the free plan's limits.
- **GitHub Gist:** a "secret" gist is only unlisted, not private, and it keeps every revision. It doesn't fit.
- **Airtable:** check the long-text field limits and the revision history.

To test a store yourself, with dummy data only, give your agent the prompt in [STORE-TEST.md](STORE-TEST.md); it ends with a scorecard you can paste into an issue.

### Approving a connection: Allow or Allow Always

A connected service's call can bring up an approval for the user, with **Allow** (this time) or **Allow Always**. Approvals are per tool of each connection: until a tool has a standing approval, every call to it waits for the user, so a fetch at use time isn't unattended until each tool it uses is approved for good (for example the read/download tool, and for setup the write and delete tools). In Muse's tests on 2026-11-14 none appeared when the blob was staged in Upstash, the remote memory service, Drive or Notion; for Dropbox none was recorded then, but its staging needed the user's one-time grant of write access during the run (ranking item 2). As an example of the difference approvals make, on 2026-11-17 a Dropbox connection with no standing approvals asked on every operation, while connections approved in earlier runs asked nothing; Dropbox's prompts did offer Allow Always, it simply hadn't been set. The 2026-11-14 tests didn't ask about approvals on the fetches, though each fetch, run as a wrapper runs it (`env -i`, from a fresh shell), succeeded. So whether an approval can hold up a wrapper's fetch, and when one appears, is not verified. Where one does, which to choose is the user's call, and sometimes there's no practical choice. What each is expected to mean:

- **Allow:** approves this one call. A later call would ask again, so an unattended fetch, with no one there to approve it, would wait and fail: if a wrapper's fetch hangs or times out with no error from the store, look for a pending approval.
- **Allow Always, on a store used only for the blobs:** what makes unattended fetch work. It is standing access to ciphertext only, with the key elsewhere.
- **Allow Always, on a whole-account connection** (Drive, Dropbox, Notion): standing access to the whole account, not only the blob file.
- **Allow Always over writes, replaces and deletes:** those then proceed without anyone approving them too. Staging and rotation run with the user present, so they can use Allow.

Not yet verified on Muse: exactly what Allow Always covers (the service, the tool, or the kind of call), how long it lasts, and where to review or revoke it. Treat it as standing until you've checked.

## Why not a built-in vault?

Saved-login and vault features are built for browser sign-in: the browser fills a form, and neither you nor the agent can read the value back out. That is the right design for websites. It does not solve this problem:

- A local tool often needs the credential as an **environment variable or config value at process start**. There is no supported path that turns a stored browser login into a value a subprocess can consume.
- API-credential flows accept API keys and OAuth, **not username/password pairs** for arbitrary local services — including services that are plain HTTP on a private network address and have no public login page to point a vault flow at.

Named precisely, and dated: as of November 2026, Muse's own credential machinery — the Secure Credentials Store for API-style credentials, and Sentinel credential surrogation for browser sign-in — declines username/password credentials (it supports `api_key` and OAuth-style flows), and saved website logins are consumed only by the browser's fill flow; no supported mechanism reads a stored value back for injection into a local process. That was verified against the platform's behavior in the author's setup in October 2026. If Meta ships a readback-for-local-tools path, this section should be revised and this pattern's reason to exist shrinks accordingly.

This pattern fills that gap for programs that read the credential from their environment, and only that gap: it writes no config file and feeds no program's stdin. Use the platform's own flows wherever they fit. If you already run a secrets manager whose CLI starts a command with secrets in its environment (such as 1Password's `op run` or Bitwarden's `bws run`), prefer it, and use this pattern at most to hand over that tool's own access token.

## Residual exposure (stated plainly)

- On your machine, the plaintext lives in the handoff script's memory while it runs (the shell's, or PowerShell's), and could in principle be swapped out. No “shredding” is claimed. `handoff.sh` turns core dumps off for itself and the programs it runs (`ulimit -c 0`), so a crash or a Ctrl-\ at the prompt writes no core file; a system that collects crashes another way (Windows Error Reporting, for `handoff.ps1`) is outside the script's reach.
- If you pass a file argument, or build a payload from a key file (“Payloads”), that file already contains plaintext on your disk; the script did not put it there, and deleting it is your call.
- Whoever holds the private key can decrypt every blob ever made with its public key. Protect it like any private key; rotate on suspicion (below).
- The host and the agent-account caveats in the threat model are real and accepted by this design, not footnotes to skip.

## Rotation, and compromise

**Routine rotation** (no suspicion of compromise) works as key-management services do it: the old key keeps decrypting until nothing needs it. `agent-setup.sh --rotate` moves the old key aside as `<key path>.previous` and puts a new one at the same path, so no wrapper changes, and `consume.py` tries the previous key whenever the current one can't open a blob. You replace the line in `handoff-<name>.age` beside your handoff script with the new recipient and compare it again; the script itself never changes. The agent then runs each label's recorded rewrap wrapper (`consume.py --rewrap --blob-file`, started as the other wrappers start it), which re-encrypts the same payload to the new key and replaces the stored blob atomically, and confirms one real login on the new blob. Once every label is on the new key, checked against the agent's setup record and by a last probe of each, `agent-setup.sh --retire --yes` deletes the old one, and blobs still made for it no longer open. (Without `--yes` it keeps the old key, removing only a leftover temporary link to it, and says what would stop opening: the script can't tell whether some label's blob still needs the old key, so the agent's check is what guards it.) An interruption at any point leaves every label working, given a file store or a store with an atomic write (for one without, SETUP says what's at risk). `SETUP.md` gives the exact steps.

An install whose wrappers run a consumer other than this folder's `consume.py` must update that consumer to try the previous key before its first rotation; otherwise its labels stop working when the key rotates.

**Compromise** (the private key may have leaked): rotating the key is *not* sufficient — every blob ever encrypted to it must be assumed readable. **Change each credential at its service first**, then rotate the key (retiring first any rotation already under way, whose keys leaked too), retire the old key right away, and stage the new credentials; don't rewrap the old blobs, which hold the exposed ones. “Rotate on suspicion” means this paragraph, not just a new key.


## Variations: what is fixed, and what is a choice

[`age`](https://github.com/FiloSottile/age) with one X25519 recipient, in its binary format and base64 on one line, is this folder's **reference implementation**. “Choosing the suite,” below, says what it was compared with and why it was chosen.

The suite may be changed, deliberately, by the human, before setup — subject to two constraints:

- **Only as an existing, reviewed tool used as-is**: for example libsodium's `crypto_box_seal` through a maintained binding. It must preserve the invariants above (with the same absence of sender authentication, which is behavioral in every variant listed here).
- **“Hybrid encryption, hand-rolled” is not a user-selectable variant.** A home-grown AES-GCM-plus-RSA construction, or a payload split across several blocks of a smaller cipher, is a mechanism change: it belongs upstream, as an issue against this repo (`CONTRIBUTING.md` at the repo's root), where it can be reviewed once for every adopter.

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

## Limits

`consume.py` accepts a blob of at most **65,536** base64 characters (`MAX_BLOB_FILE`), and `handoff.sh` and `handoff.ps1` send a payload of at most **48,696** bytes (`MAX_PAYLOAD`), which keeps the blob within that with room for a rage grease stanza. Line breaks and blanks in a blob don't count toward the cap; a `--blob-file` may hold up to 131,072 characters as read (`MAX_BLOB_FILE_RAW`), line breaks included. A blob made by Go `age` is 200 bytes larger than its payload before base64, which adds a third: a password-sized payload makes a blob of about 370 characters, and a GitHub App's `private_key` payload one of about 2,700. Every store tested carried a 64,000-character blob (Muse, 2026-11-17; “Choosing a store”), so no store sets a limit below the cap. The chat path carries one too: an 8,000-character blob and a 64,000-character blob, which the author pasted into a chat with Muse on 2026-11-17, each arrived at exactly that length, and `consume.py --check` passed on both. So the cap stays at 65,536 characters (a payload of up to 48,696 bytes).

## Installing age

Your side needs `age` (and, for `handoff.sh`, `jq` 1.6 or newer); the agent's side needs `age` (with `age-keygen`, which comes with it) and Python 3.7 or newer. There's no minimum `age` version (“Choosing the suite”), but install the current release where you can choose.

- **Linux:** your distribution's package, for example `sudo apt install age jq` (Debian, Ubuntu) or `sudo dnf install age jq` (Fedora). Packaged versions differ (as of November 2026: Ubuntu 22.04 has 1.0.0, Debian 12 and Ubuntu 24.04 1.1.1, Debian 13 1.2.1, Alpine and Arch 1.3.2), and none is too old for this folder, which has no minimum version. For a newer one, take the release binary from [age's releases](https://github.com/FiloSottile/age/releases) and check it (below).
- **macOS:** `brew install age jq` ([Homebrew](https://brew.sh)).
- **Windows:** `winget install --id FiloSottile.age`, then open a new PowerShell window so it finds `age.exe`. That is all `handoff.ps1` needs: it runs in the PowerShell that ships with Windows (Windows PowerShell 5.1, or PowerShell 7), with no bash, Git or `jq`. (If you already use Git Bash or WSL, you can run `handoff.sh` there instead, with `age` and `jq` installed for it.)
- **Phones (untested):** nothing here has been run on a phone. What should work: on Android, [Termux](https://termux.dev) with `pkg install age jq`, then `handoff.sh` as on Linux; on iOS, [iSH](https://ish.app) (an Alpine Linux shell, slow) with `apk add age bash jq`. A third-party `age` app (AgePony on iOS is one) is another way, and it is the app's code, not this folder's: it skips `handoff.sh`'s checks, so you build the payload yourself (one JSON object, a string `svc`, string values) and compare the recipient yourself, and its output must be the binary format, base64 on one line, not armored text.

### Running handoff.ps1 on Windows

Client Windows starts with the execution policy `Restricted`, which runs no script at all. The supported way to run `handoff.ps1`, which works under any policy set on the machine itself (a policy set by Group Policy wins: ask its administrator) and with a payload piped in, is to allow scripts in this PowerShell window only, then run it as usual:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\handoff.ps1
```

(It asks you to confirm; the setting ends when the window closes.)

- **`Unblock-File .\handoff.ps1`** removes the Mark of the Web, the note Windows adds to a downloaded file, which the `RemoteSigned` policy checks. Run it only after the file has passed its checksum (“Getting the scripts”); on its own it doesn't let a script run under `Restricted`. A `git clone` adds no Mark of the Web.
- **`powershell -NoProfile -ExecutionPolicy Bypass -File .\handoff.ps1`** starts a new PowerShell for one run. Use it only for the interactive paste (or with `-File FILE` after it). Don't pipe a payload into it: the pipe into a new PowerShell process goes through your session's output encoding, which can change non-ASCII characters on the way.
- **PowerShell 7.7 unpacked from its zip** (7.7 ships no MSI): under `Restricted`, PowerShell loads its own module files only from Program Files or `C:\Windows\System32`, so a zip copy kept anywhere else can't run `Set-ExecutionPolicy` at all (`…was found in the module 'Microsoft.PowerShell.Security', but the module could not be loaded…`). Install 7.7 from its MSIX package instead (`winget install Microsoft.PowerShell`, or the Store), which puts it under Program Files and runs the route above as usual; or keep the zip's folder under Program Files; or start that copy with `-ExecutionPolicy Bypass -File .\handoff.ps1`, as in the bullet above. (Tested 2026-11-18 on Windows 11 with 7.7.0's zip, MSIX and 7.6.9's MSI.)
- **A `private_key` payload** is built with `ConvertTo-Json -Compress` and piped in, as “Payloads” shows.
- **A payload in a file** goes in with `-File FILE` (`.\handoff.ps1 -File secrets.json`), which reads the file's bytes as UTF-8, or as UTF-16 with a byte-order mark. Piping the file in with `Get-Content` is the other way, and then it needs `-Encoding UTF8` (`Get-Content secrets.json -Encoding UTF8 | .\handoff.ps1`): without it, Windows PowerShell 5.1 reads a UTF-8 file that has no byte-order mark in the ANSI code page, and changes every non-ASCII character in the values without a word.

### Checking a downloaded age binary

Your package manager (apt, dnf, Homebrew, winget) checks what it downloads. For a release binary taken by hand: from version 1.2.0, each of age's release binaries has a [Sigsum](https://www.sigsum.org) proof beside it (a `.proof` file), and age's [`SIGSUM.md`](https://github.com/FiloSottile/age/blob/v1.3.2/SIGSUM.md) gives the public key, the policy and the `sigsum-verify` command to check one. Releases before 1.2.0 have no proof and no checksum file: use a package for those.

Then get the handoff script (next section) and run its setup check: `./handoff.sh --check-setup` (Windows: `.\handoff.ps1 -CheckSetup`). “Check your setup,” below, says what its lines mean.

## Getting the scripts

Each tagged release of this repository carries `handoff.sh`, `handoff.ps1` and `SHA256SUMS`, byte for byte the files in this folder at that tag, with a build-provenance attestation for each script. Your agent tells you which release to use (the one its own scripts come from) and gives you only its recipient through chat: **it never sends you the script**, and a script that arrives as a file in chat isn't one to run (invariant 6). Below, replace `vX.Y.Z` with that release's tag.

**Linux and macOS.** Download `handoff.sh` and `SHA256SUMS` for the tag into the directory you'll run the script from:

```sh
curl -fL --remote-name-all "https://github.com/cmeans/muse-field-kit/releases/download/vX.Y.Z/handoff.sh" "https://github.com/cmeans/muse-field-kit/releases/download/vX.Y.Z/SHA256SUMS"
```

`curl` is needed only to download (macOS and most Linux desktops have it). Without it, `wget` with the same two URLs works, or the release page in a browser, saving both files to one directory. Then check the script against `SHA256SUMS` (the line it prints must say `handoff.sh: OK`) and make it executable:

<!-- verify-macos-linux:start -->
```sh
# Linux:
sha256sum -c --ignore-missing SHA256SUMS
# macOS:
shasum -a 256 -c --ignore-missing SHA256SUMS
```
<!-- verify-macos-linux:end -->

```sh
chmod +x handoff.sh
```

**Windows (PowerShell).** Download `handoff.ps1` and `SHA256SUMS` into the folder you'll run it from (on an older Windows PowerShell 5.1 that can't connect, run `[Net.ServicePointManager]::SecurityProtocol = 'Tls12'` first):

```powershell
$base = 'https://github.com/cmeans/muse-field-kit/releases/download/vX.Y.Z'
Invoke-WebRequest -UseBasicParsing -Uri "$base/handoff.ps1" -OutFile handoff.ps1
Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile SHA256SUMS
```

Check it against `SHA256SUMS` (this stops with an error if it doesn't match, and prints nothing if it does):

<!-- verify-windows:start -->
```powershell
$expected = ((Get-Content .\SHA256SUMS | Where-Object { $_ -match '\s\*?handoff\.ps1$' }) -split '\s+')[0]
if ((Get-FileHash .\handoff.ps1 -Algorithm SHA256).Hash -ne $expected) { throw 'handoff.ps1 does not match SHA256SUMS' }
```
<!-- verify-windows:end -->

Only then remove the Mark of the Web with `Unblock-File .\handoff.ps1`, and run it as “Running handoff.ps1 on Windows” says.

**With `gh`,** you can also check where the file was built: `gh attestation verify handoff.sh --repo cmeans/muse-field-kit --signer-workflow cmeans/muse-field-kit/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z` (or `.\handoff.ps1` in place of `handoff.sh`) proves it came from this repository's release workflow, run for that release's tag.

**With Git,** `git clone --branch vX.Y.Z https://github.com/cmeans/muse-field-kit` gets the same files, in `muse-field-kit/encrypted-credential-handoff/`; run the script from there. Git isn't required.

**What the checksum proves, plainly:** `SHA256SUMS` comes from the same release page as the script, so it catches a damaged download and a copy swapped on the way (a chat attachment, a mirror), not a compromise of the GitHub account or repository. The attestation ties the file to the release workflow's run. Neither replaces the recipient comparison (invariant 6).

Save the agent's recipient as `handoff-<name>.age` in the same directory as the script (`handoff-muse.age` for the default name): one line, `age1…`, as the agent gives it, without the `recipient: ` that `--fingerprint` prints before it, or any quotes. The script reads it from there and nowhere else, and it must be a plain file: a symlink there is refused, since whoever can repoint a link changes the recipient without touching the file you checked. To replace one, remove the link itself first (`rm`; `Remove-Item` on Windows): saving over it writes through to its target and leaves the link. (Only the file itself is checked: the directory it's in is the one in the path you run the script by, which may itself be a link, as SETUP step 3 says.)

### Check your setup

Run the script's setup check once the tools and the script are in place, and again after any change to them:

```sh
./handoff.sh --check-setup
```

On Windows: `.\handoff.ps1 -CheckSetup`. It runs the tools rather than comparing version numbers: `age` (and `jq` for `handoff.sh`) starts, a test payload (never a credential) is encrypted to a throwaway key (never yours) and decrypted with its non-ASCII text unchanged (without `age-keygen`, which only the agent's side needs, it is encrypted to the saved recipient instead and not decrypted, and an `INFO` line says so), the blob's header passes the rule `consume.py` applies, and the saved recipient file is checked if it's there. It prints one line per check, `PASS`, `INFO` or `FAIL`, and nothing else. `INFO` is fine (a recipient file not saved yet, say). A **`FAIL`** line means that part of your setup won't work with the agent's side; the line says what and what to do (install `jq` 1.6 or newer, reinstall `age`, fix the recipient file). Fix it and run the check again before you encrypt anything. If it still fails, tell your agent the output (it never contains a secret) and stop there, or report it as an issue (`CONTRIBUTING.md` at the repo's root). The agent asks for this result before the recipient comparison (`SETUP.md`, step 3), and runs its own check, `./agent-setup.sh --check-setup`, before it makes its key.

## Platform

- **Your side, Linux and macOS:** `handoff.sh`, with bash (written for macOS's own `/bin/bash` too), `age` and `jq`.
- **Your side, Windows:** `handoff.ps1`, with Windows PowerShell 5.1 or PowerShell 7 and `age.exe`. It is `handoff.sh`'s twin: the same recipient file, rules and messages.
- **The agent's side, Linux and macOS:** `agent-setup.sh` and `consume.py`. They rely on Unix file ownership and modes and on `exec`, so there is no Windows version of the agent's side. On macOS, a fetched store's rotation needs a RAM disk (`SETUP.md`, Rotation step 4).
- **Phones:** untested (“Installing age”).

What CI runs on every change, on GitHub's hosted runners:

- **Linux:** the whole suite (`test/run-test.sh`) against the distribution's packaged `age` and against the `age` 1.3.2 release binary (pinned by SHA-256, checked once against its Sigsum proof), and `test/run-test.ps1` under PowerShell 7; the agent's side again against `age` 1.0.0 and 1.1.1, built from source with `go install` (the Go checksum database checks that source), the oldest packaged versions, which having no minimum version means supporting.
- **macOS:** the whole suite with Homebrew's `age` and `jq`, and this README's macOS checksum command on the release files.
- **Windows:** `test/run-test.ps1` under Windows PowerShell 5.1 and PowerShell 7 with the `age.exe` release (pinned by SHA-256), including the execution-policy routes above and this README's Windows checksum command. The blobs it makes are then opened on Linux by `consume.py`, which checks the values byte for byte.

A check that is skipped fails the run, as one that fails does. Run anywhere else, `test/run-test.sh` may skip the checks whose files only CI makes: those that need files owned by another account (`the key-owner refusal wasn't tested`, `the key-directory owner checks weren't run`), and, run as root (as Muse's agent is), `the read-only blob file check didn't run`. Those `skip:` lines are expected there, as are `n/a on this OS:` lines on macOS. Any other `skip:` line names what that machine lacks, and a `FAIL` is a failure.

On pull request #42 every job passed: Linux (the distribution's `age` package, the pinned `age` 1.3.2 release, and PowerShell 7 on Linux), the agent's side against `age` 1.0.0 and 1.1.1, macOS, Windows PowerShell 5.1 and PowerShell 7, and the Linux job that opens the Windows-made blobs. That is test coverage, not field time; “Status” says what has run live.

A port to another platform written by an agent is *unreviewed by definition*, and `SETUP.md` says how it must be gated (the user's review plus the interop test under `test/`) before it touches a real credential.

## Operational cautions, learned the hard way

- **Test the decrypt/store path against scratch data first.** A dry run that overwrites a live credential store with test values is a self-inflicted outage. Point tests at a scratch config, and verify the live store is untouched afterward.
- **Keep a login probe honest:** after decrypting, attempt one real authentication before declaring the handoff good; judge it by status only, never by printing a response body; and log out any session the probe created if the service supports it.
- **One identity per agent environment.** Do not reuse the key across machines; the point is that exactly one place can decrypt.

## Status: what is field-tested, and what is new

The core of this pattern — one key pair on the agent's machine, encrypt-on-yours, ciphertext through chat, decrypt-in-memory at use, key and ciphertext never sharing a disk — has run daily in the author's setup since October 2026 (the store-only separation form dates from 2026-10-12). Before 0.1.0 was published, Muse also ran its `consume.py` and wrappers live on two production labels, one complete routine rotation (rotate, rewrap, last pass and retire, 2026-11-14), and each of the five stores in the table under “Choosing a store” end to end with a dummy blob (2026-11-14). All of that ran on 0.1.0's RSA keys and blobs.

Version 0.2.0 keeps that flow and changes what's under it: `age` in place of RSA and OpenSSL, the header check, the `private_key`, `app_id` and `installation_id` fields, `handoff.ps1` for Windows, the setup checks, and the release files. These are covered by the interop and refusal tests on Linux, macOS and Windows (“Platform”), not yet by field time: 0.2.0's store tests on Muse at the blob sizes up to 64,000 characters passed (2026-11-17), and its live runs moving its own labels to `age` one at a time are pending: they come after the release. Not yet field-tested at all: a compromise response, which no live run has needed, a read-only store token, approvals on a fetch (“Choosing a store”), typing a payload into `handoff.ps1` at a real Windows console (CI runs it with no console), and phones. `CHANGELOG.md` lists what ships.

A note on review, in the same spirit: the reviewers of this folder were AI agent sessions in the author's own multi-agent setup (structural review, line-level review with reproduced findings, a cold read, and QA rounds on every pull request), plus Muse, which reviewed every pull request as the agent this folder is written for, and the author. That is peer review inside one shop — valuable, and not a third-party security audit.

## Files

- `handoff.sh` — your side, on Linux and macOS. It reads your agent's recipient from `handoff-<name>.age` in its own directory (`--to NAME`; the default name is `muse`), and refuses to encrypt without one: the script holds no key of its own. `--fingerprint` prints the recipient it would encrypt to; `--check-setup` checks the tools.
- `handoff.ps1` — the same for Windows (`-To NAME`, `-File FILE`, `-Fingerprint`, `-CheckSetup`, `-Help`).
- `agent-setup.sh` — the agent's side. Makes the identity and prints the recipient and the consume-side key path to use; `--fingerprint` prints an existing identity's recipient, `--public-key` prints the wrappers' identity's recipient (from `HANDOFF_PRIVKEY`, or the default; it takes no KEY) with where to save it, `--rotate` and `--retire` start and end a rotation, and `--check-setup` checks the tools.
- `consume.py` — the consume-side template: the header check, decryption in memory (with the previous key too, during a rotation), `svc` purpose-binding check, environment injection, a `--check` mode (field names and lengths only) for setup tests, and `--rewrap` for rotation.
- `SETUP.md` — step-by-step instructions written for your Muse, including the hard rules, the precise definition of a mechanism change, and the rotation procedures.
- `SKILL.md` — the skill file for your Muse: when to use the handoff, which `SETUP.md` step each request goes to, and the rules that hold from the start. It routes only; `SETUP.md` is the authority.
- `test/` — the interop and refusal tests, with known-answer vectors (a dummy identity, fixed blobs from Go `age` and rage, and the expected plaintext), so any port or variant can prove byte-compatibility.
- `SECURITY.md` — how to report a flaw in this pattern or these scripts.
- `CHANGELOG.md` — what ships in this folder, and what changes.

MIT licensed, code and text alike.
