# Other ways to install

The recommended way for each platform is in `INSTALL-linux-macos.md` and `INSTALL-windows.md`. These are the alternatives.

## Phones (untested)

Nothing here has been run on a phone. What should work: on Android, [Termux](https://termux.dev) with `pkg install age jq`, then `handoff.sh` as on Linux; on iOS, [iSH](https://ish.app) (an Alpine Linux shell, slow) with `apk add age bash jq`. A third-party `age` app (AgePony on iOS is one) is another way, and it is the app's code, not this folder's: it skips `handoff.sh`'s checks, so you build the payload yourself (one JSON object, a string `svc`, string values) and compare the recipient yourself, and its output must be the binary format, base64 on one line, not armored text.

## A release binary of age, and checking it

Your package manager (apt, dnf, Homebrew, winget) checks what it downloads. For a release binary taken by hand: from version 1.2.0, each of age's release binaries has a [Sigsum](https://www.sigsum.org) proof beside it (a `.proof` file), and age's [`SIGSUM.md`](https://github.com/FiloSottile/age/blob/v1.3.2/SIGSUM.md) gives the public key, the policy and the `sigsum-verify` command to check one. Releases before 1.2.0 have no proof and no checksum file: use a package for those.
