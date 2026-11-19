# Other ways to install

The recommended way for each platform is in `INSTALL-linux-macos.md` and `INSTALL-windows.md`. These are the alternatives.

## Phones (untested)

Nothing here has been run on a phone. What should work: on Android, [Termux](https://termux.dev) with `pkg install age jq`, then `handoff.sh` as on Linux; on iOS, [iSH](https://ish.app) (an Alpine Linux shell, slow) with `apk add age bash jq`. A third-party `age` app (AgePony on iOS is one) is another way, and it is the app's code, not this folder's: it skips `handoff.sh`'s checks, so you build the payload yourself (one JSON object, a string `svc`, string values) and compare the recipient yourself, and its output must be the binary format, base64 on one line, not armored text.

Cautions specific to a phone, whichever way you run it:

- **The keyboard can learn the secret:** predictive text, autocorrect and keyboard cloud sync (Gboard, SwiftKey) may store what's typed. Use the keyboard's incognito mode, or paste from a password manager instead of typing.
- **Clipboard history and sync** (Gboard's clipboard, cross-device clipboards) can copy a password to other places. Copying the *blob* is safe; copying the plaintext isn't. Clear the clipboard after pasting a password.
- **The payload file** lives in the app's storage: delete it after the blob is made, as on a computer.

## WSL, or Git Bash (untested), on Windows

In [WSL](https://learn.microsoft.com/en-us/windows/wsl/install), you can run `handoff.sh` instead of `handoff.ps1`: follow `INSTALL-linux-macos.md` inside the WSL distribution. In [Git Bash](https://gitforwindows.org/), which nothing here has been tested on, `handoff.sh` would need `age.exe` and `jq.exe` on `PATH` (`winget install --id FiloSottile.age` and `winget install --id jqlang.jq`), since the package managers in `INSTALL-linux-macos.md` don't exist there.

## A release binary of age, and checking it

Your package manager (apt, dnf, Homebrew, winget) checks what it downloads. For a release binary taken by hand: from version 1.2.0, each of age's release binaries has a [Sigsum](https://www.sigsum.org) proof beside it (a `.proof` file), and age's [`SIGSUM.md`](https://github.com/FiloSottile/age/blob/v1.3.2/SIGSUM.md) gives the public key, the policy and the `sigsum-verify` command to check one. Releases before 1.2.0 have no proof and no checksum file: use a package for those.
