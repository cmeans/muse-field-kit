# Your side on Linux and macOS

How to install what `handoff.sh` needs, get and check the script, save your agent's recipient, and check your setup. (Windows: [`INSTALL-windows.md`](INSTALL-windows.md). Phones and other ways to install: [`INSTALL-options.md`](INSTALL-options.md).)

## Install age and jq

`handoff.sh` needs [bash](https://www.gnu.org/software/bash/) (most Linux distributions have it, Alpine with `apk add bash`, and macOS's own `/bin/bash` is fine), [`age`](https://github.com/FiloSottile/age#installation) and [`jq`](https://jqlang.org/download/) 1.6 or newer. The recommended way to install them:

- **Linux:** your distribution's package, for example `sudo apt install age jq` (Debian, Ubuntu) or `sudo dnf install age jq` (Fedora). Packaged versions differ (as of November 2026: Ubuntu 22.04 has 1.0.0, Debian 12 and Ubuntu 24.04 1.1.1, Debian 13 1.2.1, Alpine and Arch 1.3.2), and none is too old for this folder, which has no minimum version. For a newer one, take the release binary from [age's releases](https://github.com/FiloSottile/age/releases) and check it ([`INSTALL-options.md`](INSTALL-options.md)).
- **macOS:** `brew install age jq` ([Homebrew](https://brew.sh)).

## Get the script

Each of this kit's releases carries `handoff.sh`, `handoff.ps1` and `SHA256SUMS`, byte for byte the files in this folder at that tag, with a build-provenance attestation for each script. Releases after 0.2.1 also carry your agent's scripts (`agent-setup.sh`, `consume.py`), which you don't need. Your agent tells you which release to use (the one its own scripts come from) and gives you only its recipient through chat: **it never sends you the script**, and a script that arrives as a file in chat isn't one to run (invariant 6 in [`README.md`](README.md)). Below, replace `X.Y.Z` with that release's version: its tag is `encrypted-credential-handoff-vX.Y.Z` (releases before 0.2.1 were tagged `vX.Y.Z`, so for 0.2.0 the commands below have `v0.2.0` in place of `encrypted-credential-handoff-vX.Y.Z`). This kit's releases are listed at <https://github.com/cmeans/muse-field-kit/releases?q=encrypted-credential-handoff&expanded=true>.

Download `handoff.sh` and `SHA256SUMS` for the tag into the directory you'll run the script from:

```sh
curl -fL --remote-name-all "https://github.com/cmeans/muse-field-kit/releases/download/encrypted-credential-handoff-vX.Y.Z/handoff.sh" "https://github.com/cmeans/muse-field-kit/releases/download/encrypted-credential-handoff-vX.Y.Z/SHA256SUMS"
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

**With `gh`,** you can also check where the file was built: `gh attestation verify handoff.sh --repo cmeans/muse-field-kit --signer-workflow cmeans/muse-field-kit/.github/workflows/release.yml --source-ref refs/tags/encrypted-credential-handoff-vX.Y.Z` proves it came from this repository's release workflow, run for that release's tag.

**With Git,** `git clone --branch encrypted-credential-handoff-vX.Y.Z https://github.com/cmeans/muse-field-kit` gets the same files, in `muse-field-kit/encrypted-credential-handoff/`; run the script from there. Git isn't required.

**What the checksum proves, plainly:** `SHA256SUMS` comes from the same release page as the script, so it catches a damaged download and a copy swapped on the way (a chat attachment, a mirror), not a compromise of the GitHub account or repository. The attestation ties the file to the release workflow's run. Neither replaces the recipient comparison (invariant 6).

Save the agent's recipient as `handoff-<name>.age` in the same directory as the script (`handoff-muse.age` for the default name), with a text editor, or with `cat > handoff-muse.age`, then paste the line, press Enter and Ctrl-D (`cat` saves the text you paste; no command runs). A recipient is `age1` followed by lowercase letters and digits only, exactly 62 characters (`age1` and 58 more): if what you got has anything else (a quote, a space, a `;`), don't save it, and tell your agent. The file holds one line, `age1…`, as the agent gives it, without the `recipient: ` that `--fingerprint` prints before it, or any quotes. The script reads it from there and nowhere else, and it must be a plain file: a symlink there is refused, since whoever can repoint a link changes the recipient without touching the file you checked. To replace one, remove the link itself first (`rm`): saving over it writes through to its target and leaves the link. (Only the file itself is checked: the directory it's in is the one in the path you run the script by, which may itself be a link, as [SETUP](SETUP.md) step 3 says.)

## Check your setup

Run the script's setup check once the tools and the script are in place, and again after any change to them:

```sh
./handoff.sh --check-setup
```

It runs the tools rather than comparing version numbers: `age` and `jq` start, a test payload (never a credential) is encrypted to a throwaway key (never yours) and decrypted with its non-ASCII text unchanged (without `age-keygen`, which only the agent's side needs, it is encrypted to the saved recipient instead and not decrypted, and an `INFO` line says so), the blob's header passes the rule `consume.py` applies, and the saved recipient file is checked if it's there. It prints one line per check, `PASS`, `INFO` or `FAIL`, and nothing else. `INFO` is fine (a recipient file not saved yet, say). A **`FAIL`** line means that part of your setup won't work with the agent's side; the line says what and what to do (install `jq` 1.6 or newer, reinstall `age`, fix the recipient file). Fix it and run the check again before you encrypt anything. If it still fails, tell your agent the output (it never contains a secret) and stop there, or report it as an issue ([`CONTRIBUTING.md`](../CONTRIBUTING.md) at the repo's root). The agent asks for this result before the recipient comparison ([`SETUP.md`](SETUP.md), step 3), and runs its own check, `./agent-setup.sh --check-setup`, before it makes its key.
