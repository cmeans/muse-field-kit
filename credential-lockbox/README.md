# Credential Lockbox has moved

Credential Lockbox now lives in its own repository: **[credential-lockbox/credential-lockbox](https://github.com/credential-lockbox/credential-lockbox)**.

It lets you pass service credentials to Muse as public-key ciphertext. Muse decrypts them in memory on its own machine, so the plaintext stays out of the chat. Its README, setup guide, threat model and releases are there now.

- **New setups:** start from the new repository's README. Its releases are tagged `vX.Y.Z`. The first, [`v0.3.1`](https://github.com/credential-lockbox/credential-lockbox/releases/tag/v0.3.1), was the move release, with the scripts byte-identical to `credential-lockbox-v0.3.0`'s.
- **Existing setups keep working.** This repository's releases and tags stay: [`credential-lockbox-v0.3.0`](https://github.com/cmeans/muse-field-kit/releases/tag/credential-lockbox-v0.3.0), `encrypted-credential-handoff-v0.2.1`, `v0.2.0` and `v0.1.0`. A clone checked out at one of those tags has every file it had before. Only this folder on `main` is now a pointer. Don't update a working setup's clone to `main`: moving a setup to the new repository is a change to its recorded paths, which that repository's `SETUP.md` describes.
- **History:** the folder's history moved with it, and its commits there link back to this repository's pull requests and issues. Those, with their discussions, stay here.
- **Reporting a problem:** open issues and security reports for Credential Lockbox in the new repository ([its `SECURITY.md`](https://github.com/credential-lockbox/credential-lockbox/blob/main/SECURITY.md)).
