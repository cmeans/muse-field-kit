# Your side on Windows

How to install what `handoff.ps1` needs, get and check the script, run it, save your agent's recipient, and check your setup. (Linux and macOS: [`INSTALL-linux-macos.md`](INSTALL-linux-macos.md). Other ways to install: [`INSTALL-options.md`](INSTALL-options.md).)

## Install age

`handoff.ps1` needs [`age`](https://github.com/FiloSottile/age#installation) and the PowerShell that ships with Windows (Windows PowerShell 5.1), or [PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows); no bash, Git or `jq`. The recommended way to install `age` is [winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/):

```powershell
winget install --id FiloSottile.age
```

Then open a new PowerShell window, so it finds `age.exe`. `handoff.ps1` looks for `age.exe` only on `PATH`, which winget sets: a copy of `age.exe` saved beside the script, or anywhere else off `PATH`, isn't found (“age not found”).

Tested on Windows 11 with Windows PowerShell 5.1 and PowerShell 7.6 (and 7.7, for the execution-policy routes below), and in CI on GitHub's Windows runners under both editions. Git Bash or WSL instead: [`INSTALL-options.md`](INSTALL-options.md).

## Get the script

Each of this kit's releases carries `handoff.sh`, `handoff.ps1` and `SHA256SUMS`, byte for byte the files in this folder at that tag, with a build-provenance attestation for each script. Releases after 0.2.1 also carry your agent's scripts (`agent-setup.sh`, `consume.py`), which you don't need. Your agent tells you which release to use (the one its own scripts come from) and gives you only its recipient through chat: **it never sends you the script**, and a script that arrives as a file in chat isn't one to run (invariant 6 in [`README.md`](README.md)). Below, replace `X.Y.Z` with that release's version: its tag is `encrypted-credential-handoff-vX.Y.Z` (releases before 0.2.1 were tagged `vX.Y.Z`, so for 0.2.0 the commands below have `v0.2.0` in place of `encrypted-credential-handoff-vX.Y.Z`). This kit's releases are listed at <https://github.com/cmeans/muse-field-kit/releases?q=encrypted-credential-handoff&expanded=true>.

Download `handoff.ps1` and `SHA256SUMS` into the folder you'll run it from (on an older Windows PowerShell 5.1 that can't connect, run `[Net.ServicePointManager]::SecurityProtocol = 'Tls12'` first):

```powershell
$base = 'https://github.com/cmeans/muse-field-kit/releases/download/encrypted-credential-handoff-vX.Y.Z'
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

**With `gh`,** you can also check where the file was built: `gh attestation verify .\handoff.ps1 --repo cmeans/muse-field-kit --signer-workflow cmeans/muse-field-kit/.github/workflows/release.yml --source-ref refs/tags/encrypted-credential-handoff-vX.Y.Z` proves it came from this repository's release workflow, run for that release's tag.

**With Git,** `git clone --branch encrypted-credential-handoff-vX.Y.Z https://github.com/cmeans/muse-field-kit` gets the same files, in `muse-field-kit/encrypted-credential-handoff/`; run the script from there. Git isn't required.

**What the checksum proves, plainly:** `SHA256SUMS` comes from the same release page as the script, so it catches a damaged download and a copy swapped on the way (a chat attachment, a mirror), not a compromise of the GitHub account or repository. The attestation ties the file to the release workflow's run. Neither replaces the recipient comparison (invariant 6).

Save the agent's recipient as `handoff-<name>.age` in the same directory as the script (`handoff-muse.age` for the default name), with a text editor, or by copying the line and running `Get-Clipboard | Set-Content -Encoding ascii handoff-muse.age` (this saves the text you copied; no command runs; don't use `>`, which in Windows PowerShell 5.1 writes UTF-16, which the script refuses). A recipient is `age1` followed by lowercase letters and digits only, exactly 62 characters (`age1` and 58 more): if what you got has anything else (a quote, a space, a `;`), don't save it, and tell your agent. The file holds one line, `age1…`, as the agent gives it, without the `recipient: ` that `--fingerprint` prints before it, or any quotes. The script reads it from there and nowhere else, and it must be a plain file: a symlink there is refused, since whoever can repoint a link changes the recipient without touching the file you checked. To replace one, remove the link itself first (`Remove-Item`; for a junction or a link to a folder, `(Get-Item -LiteralPath .\handoff-muse.age -Force).Delete()`, since `Remove-Item` on one in Windows PowerShell 5.1 can delete the folder's contents): saving over it writes through to its target and leaves the link. (Only the file itself is checked: the directory it's in is the one in the path you run the script by, which may itself be a link, as [SETUP](SETUP.md) step 3 says.)

## Running handoff.ps1 on Windows

Client Windows starts with the execution policy `Restricted`, which runs no script at all. The supported way to run `handoff.ps1`, which works under any policy set on the machine itself (a policy set by Group Policy wins: ask its administrator) and with a payload piped in, is to allow scripts in this PowerShell window only, then run it as usual:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\handoff.ps1
```

(It asks you to confirm; the setting ends when the window closes.)

- **`Unblock-File .\handoff.ps1`** removes the Mark of the Web, the note Windows adds to a downloaded file, which the `RemoteSigned` policy checks. Run it only after the file has passed its checksum (“Get the script”, above); on its own it doesn't let a script run under `Restricted`. A `git clone` adds no Mark of the Web.
- **`powershell -NoProfile -ExecutionPolicy Bypass -File .\handoff.ps1`** starts a new PowerShell for one run. Use it only for the interactive paste (or with `-File FILE` after it). Don't pipe a payload into it: the pipe into a new PowerShell process goes through your session's output encoding, which can change non-ASCII characters on the way.
- **PowerShell 7.7 unpacked from its zip** (7.7 ships no MSI): under `Restricted`, PowerShell loads its own module files only from Program Files or `C:\Windows\System32`, so a zip copy kept anywhere else can't run `Set-ExecutionPolicy` at all (`…was found in the module 'Microsoft.PowerShell.Security', but the module could not be loaded…`). Install 7.7 from its MSIX package instead (`winget install Microsoft.PowerShell`, or the Store), which puts it under Program Files and runs the route above as usual; or keep the zip's folder under Program Files; or start that copy with `-ExecutionPolicy Bypass -File .\handoff.ps1`, as in the bullet above. (Tested 2026-11-18 on Windows 11 with 7.7.0's zip, MSIX and 7.6.9's MSI.)
- **A `private_key` payload** is built with `ConvertTo-Json -Compress` and piped in, as [`README.md`](README.md#payloads), “Payloads”, shows.
- **A payload in a file** goes in with `-File FILE` (`.\handoff.ps1 -File secrets.json`), which reads the file's bytes as UTF-8, or as UTF-16 with a byte-order mark. Piping the file in with `Get-Content` is the other way, and then it needs `-Encoding UTF8` (`Get-Content secrets.json -Encoding UTF8 | .\handoff.ps1`): without it, Windows PowerShell 5.1 reads a UTF-8 file that has no byte-order mark in the ANSI code page, and changes every non-ASCII character in the values without a word.

## Check your setup

Run the script's setup check once the tools and the script are in place, and again after any change to them:

```powershell
.\handoff.ps1 -CheckSetup
```

It runs the tools rather than comparing version numbers: `age` starts, a test payload (never a credential) is encrypted to a throwaway key (never yours) and decrypted with its non-ASCII text unchanged (without `age-keygen`, which only the agent's side needs, it is encrypted to the saved recipient instead and not decrypted, and an `INFO` line says so), the blob's header passes the rule `consume.py` applies, and the saved recipient file is checked if it's there. It prints one line per check, `PASS`, `INFO` or `FAIL`, and nothing else. `INFO` is fine (a recipient file not saved yet, say). A **`FAIL`** line means that part of your setup won't work with the agent's side; the line says what and what to do (reinstall `age`, fix the recipient file). Fix it and run the check again before you encrypt anything. If it still fails, tell your agent the output (it never contains a secret) and stop there, or report it as an issue ([`CONTRIBUTING.md`](../CONTRIBUTING.md) at the repo's root). The agent asks for this result before the recipient comparison ([`SETUP.md`](SETUP.md), step 3), and runs its own check, `./agent-setup.sh --check-setup`, before it makes its key.
