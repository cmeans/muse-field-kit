# Contributing to muse-field-kit

Thanks for your interest. This is a small, one-person project, and parts of it are security patterns, so changes come in a particular way. Please read this short document first.

## How to contribute: issues, not pull requests

**Pull requests are open to the project's collaborators only** (the repository's "Collaborators only" pull request setting). Everyone can read them, and everyone can open an issue.

So the way to contribute is an issue:

- **[Bug report](../../issues/new?template=bug_report.yml):** something doesn't work as a folder's docs say.
- **[Feature request](../../issues/new?template=feature_request.yml):** a new capability, or a change to how something works.
- **[Platform test report](../../issues/new?template=platform_test_report.yml):** what happened when you ran a folder on a platform or tool version we don't test (macOS, Windows, a phone, an older `bash`).
- **Security problems:** an exploitable flaw never goes in a public issue; report it privately as [`SECURITY.md`](SECURITY.md) says (or, if you can't use a private advisory, ask for a private channel with the [Security contact request](../../issues/new?template=security_contact.yml) form, which takes no details). (Hardening work that isn't embargoed is tracked as issues with the `security` label.)

A good issue is specific: the folder, its version, your platform, what you ran, what you expected and what happened, and output with any secret removed. A proposed fix in the issue (a diff, or the exact wording) is welcome; the maintainer's side turns an agreed fix into a pull request and credits you in it.

Why not outside pull requests: the scripts here handle credentials, and every change to them is reviewed in several rounds before it merges (below). Taking changes as issues keeps outside code from running in this repository's CI and keeps every mechanism change on the review path described below.

## License of contributions

**By contributing (an issue's proposed fix, a diff, or text), you agree that it may be used under the [MIT License](LICENSE)**, the license of the rest of the project. You keep your copyright; you grant everyone the MIT License's permissions for what you contributed. Please don't attach extra terms (payment, bounty claims, restrictions on use): they have no effect, and the contribution will be asked to drop them.

There are no bug bounties or paid contributions. Sponsoring the maintainer through the repository's **Sponsor** button is separate: it supports the project as a whole and buys no change, priority or review.

## What changes need agreement first

Some changes are decided before anyone writes them:

- **Mechanism changes.** Each folder's `SETUP.md` lists what counts as one (for `credential-lockbox`, its section "What counts as a mechanism change": for example the crypto, the payload schema, how input is read, key generation and permissions). These need the maintainer's agreement and the review of Muse, the agent the folder is written for, before a pull request.
- **Designs and plans** for larger work are written and reviewed first, then implemented.
- **New dependencies** for the people who use a folder: each costs every adopter an install, and is the maintainer's call. Test-only and CI-only tools are fine.

## How a change is made and reviewed (collaborators)

1. **Branch from `main`.** One concern per pull request.
2. **Run the checks locally** (below) and the folder's tests.
3. **Open the PR** with a body that has a `## Summary` (what changed and why), a `## QA` checklist the reviewer can run (each item names the exact command or file and the expected result), and `Closes #N` for any issue it fixes. The pull request template has these sections.
4. **Labels track the review.** CI runs on every push (`Awaiting CI`), then the PR is `Ready for QA`. QA reviews it and applies `QA Failed` with findings, or `Ready for QA Signoff`. Muse reviews it as the folder's user (`Muse Approved` or `Muse Failed`). A PR merges only after the maintainer applies `QA Approved` and approves the PR's latest push in a review, and Dev's merge also waits for `Muse Approved` on that push. `main` requires an approval of the latest push from an account with write access that neither opened the PR nor made that push. Today that means the maintainer's account: Dev's app opens every PR, and workflows can't approve. So the maintainer doesn't push to, or update, a PR's branch (Dev merges `main` in), and the gate holds only as long as no other installed app has Pull requests: write, since one that did could approve. A push after the approval needs a new one. The `QA Gate` status (`qa-gate.yml`, run from `main`'s copy on `pull_request_target`) turns green only when the maintainer applied the label; it's a signal, not the gate, since any workflow can post a status. A push, or reopening the PR, removes the review labels, `QA Approved`, `Muse Approved` and `Muse Failed` included, and starts the round again: each verdict counts only until the next push or reopen. `main` requires a branch to be up to date before it merges.
5. **The exit bar:** a PR merges with no open High or Medium finding; Lows block only when marked blocking; the rest are filed as issues before signoff.
6. **Squash merge.** The squashed commit's message is built from the PR's own commit messages (and a single-commit PR's subject is that commit's), so write each commit message for someone reading `git log` a year from now.

## Local checks

For `credential-lockbox` (run from the repository root):

```bash
./credential-lockbox/test/run-test.sh        # interop and refusal tests; ends ALL INTEROP CHECKS PASSED
shellcheck credential-lockbox/*.sh credential-lockbox/test/*.sh
pipx run ruff==0.17.6 check credential-lockbox/ .github/scripts/md-links.py
# every script executable in git, as CI checks first (prints nothing when right):
git ls-files -s credential-lockbox | awk '$1 != "100755" && $4 ~ /(\.sh|\.py)$/ { print $4 }'
```

The suite runs each script through `bash` or `python3`, so a new script committed without its execute bit passes it and fails only in CI: `chmod 755` it and `git add` it again.

The suite needs only what the folder needs: `bash`, `python3` 3.7 or later, the folder's crypto tool (`age`, with `age-keygen`), and `jq`. `test/run-test.ps1` checks the Windows script, `handoff.ps1`, under PowerShell 7 (on any OS) or Windows PowerShell 5.1. CI also parses the scripts under bash 3.2 (macOS's `/bin/bash`) and fails on any skipped check.

## Style

- Scripts: `bash` that parses under bash 3.2; Python from the standard library only, no third-party packages on the user's or the agent's side.
- Messages never print a secret or anything derived from one, and errors say what to do next.
- Docs and messages use American English spelling (behavior, color, license).
- Each folder's `CHANGELOG.md` gets an entry for every change to that folder, one line per change: `- **Short title** (#PR): what changed, for the user.` The reasons and edge cases go in the PR and the docs. A release adds two or three sentences on how it was reviewed and what wasn't run.

## Releases

Each kit is released on its own, with a tag `KIT-vX.Y.Z` (for example `credential-lockbox-vX.Y.Z`; that kit's releases through 0.2.1, before its rename, were `encrypted-credential-handoff-v0.2.1`, `v0.2.0` and `v0.1.0`). Only the maintainer can create, move or delete a release tag (the repository's "release tags" ruleset). To release:

1. Merge a PR that turns the kit's `## Unreleased` section into `## X.Y.Z — YYYY-MM-DD — <title>`, with the review sentences.
2. Wait for `ci-ok` to pass on that merge commit on `main`.
3. Tag it and push the tag: `git tag credential-lockbox-vX.Y.Z <commit>`, then `git push origin credential-lockbox-vX.Y.Z`.

`release.yml` then checks that the commit is on `main`, that its `ci-ok` passed and that the CHANGELOG has the heading, builds and attests the assets, and publishes the release. If it refuses because of `ci-ok` (`missing` or `pending` while CI on that commit is still running, since `ci-ok` starts only after the other jobs), open the commit's CI run in Actions and wait for it to finish. Then:

- **CI passed** (or a job failed on a flake, and re-running the failed jobs made it pass): run Release again on the tag (Actions, Release, "Run workflow" on the tag, `dry_run` false).
- **CI failed for real, or never ran on that commit:** delete the tag (`git push --delete origin credential-lockbox-vX.Y.Z`), so no setup picks a version that has no release; fix `main`; and release the fix under a new version.

If it refuses over the tag itself (it checks the tag before attesting and again right before creating the release):

- **The tag was moved on purpose** during the run: nothing to do for this run. Pushing the moved tag started a new Release run for its commit.
- **The tag was moved by mistake** during the run: moving it was a tag push too, so it started a Release run for the wrong commit. First cancel that run (Actions, Release), or, if it already published, delete its release (`gh release delete credential-lockbox-vX.Y.Z --yes`, which keeps the tag). Then put the tag back on the built commit the message names, locally and on GitHub (`git tag -f credential-lockbox-vX.Y.Z <commit>`, then `git push --force origin credential-lockbox-vX.Y.Z`), so a later push of your local tag can't move it again. The force push starts a new Release run; run Release again on the tag only if none starts. If the scripts were already attested, the new run attests the same files again, which is harmless.
- **The tag couldn't be read** (the API call failed): run Release again on the tag. If the tag was deleted, release a new version instead.

## Contact

Open an issue. This is a one-person project, so response times vary.
