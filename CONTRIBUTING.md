# Contributing to muse-field-kit

Thanks for your interest. This is a small, one-person project, and parts of it are security patterns, so changes come in a particular way. Please read this short document first.

## How to contribute: issues, not pull requests

**Pull requests are open to the project's collaborators only** (the repository's "Collaborators only" pull request setting). Everyone can read them, and everyone can open an issue.

So the way to contribute is an issue:

- **[Bug report](../../issues/new?template=bug_report.yml):** something doesn't work as a folder's docs say.
- **[Feature request](../../issues/new?template=feature_request.yml):** a new capability, or a change to how something works.
- **[Platform test report](../../issues/new?template=platform_test_report.yml):** what happened when you ran a folder on a platform or tool version we don't test (macOS, Windows, a phone, an older `bash`).
- **Security problems:** an exploitable flaw never goes in a public issue; report it privately as [`SECURITY.md`](SECURITY.md) says. (Hardening work that isn't embargoed is tracked as issues with the `security` label.)

A good issue is specific: the folder, its version, your platform, what you ran, what you expected and what happened, and output with any secret removed. A proposed fix in the issue (a diff, or the exact wording) is welcome; the maintainer's side turns an agreed fix into a pull request and credits you in it.

Why not outside pull requests: the scripts here handle credentials, and every change to them is reviewed in several rounds before it merges (below). Taking changes as issues keeps outside code from running in this repository's CI and keeps every mechanism change on the review path described below.

## License of contributions

**By contributing (an issue's proposed fix, a diff, or text), you agree that it may be used under the [MIT License](LICENSE)**, the license of the rest of the project. You keep your copyright; you grant everyone the MIT License's permissions for what you contributed. Please don't attach extra terms (payment, bounty claims, restrictions on use): they have no effect, and the contribution will be asked to drop them.

There are no bug bounties or paid contributions. Sponsoring the maintainer through the repository's **Sponsor** button is separate: it supports the project as a whole and buys no change, priority or review.

## What changes need agreement first

Some changes are decided before anyone writes them:

- **Mechanism changes.** Each folder's `SETUP.md` lists what counts as one (for `encrypted-credential-handoff`, its section "What counts as a mechanism change": for example the crypto, the payload schema, how input is read, key generation and permissions). These need the maintainer's agreement and the review of Muse, the agent the folder is written for, before a pull request.
- **Designs and plans** for larger work are written and reviewed first, then implemented.
- **New dependencies** for the people who use a folder: each costs every adopter an install, and is the maintainer's call. Test-only and CI-only tools are fine.

## How a change is made and reviewed (collaborators)

1. **Branch from `main`.** One concern per pull request.
2. **Run the checks locally** (below) and the folder's tests.
3. **Open the PR** with a body that has a `## Summary` (what changed and why), a `## QA` checklist the reviewer can run (each item names the exact command or file and the expected result), and `Closes #N` for any issue it fixes. The pull request template has these sections.
4. **Labels track the review.** CI runs on every push (`Awaiting CI`), then the PR is `Ready for QA`. QA reviews it and applies `QA Failed` with findings, or `Ready for QA Signoff`. Muse reviews it as the folder's user (`Muse Approved` or `Muse Failed`). A PR merges only after the maintainer applies `QA Approved`. A push removes the review labels, `QA Approved` included, and starts the round again; Muse's label is renewed by hand. `main` requires a branch to be up to date before it merges.
5. **The exit bar:** a PR merges with no open High or Medium finding; Lows block only when marked blocking; the rest are filed as issues before signoff.
6. **Squash merge.** The squashed commit's message is built from the PR's own commit messages (and a single-commit PR's subject is that commit's), so write each commit message for someone reading `git log` a year from now.

## Local checks

For `encrypted-credential-handoff` (run from the repository root):

```bash
./encrypted-credential-handoff/test/run-test.sh        # interop and refusal tests; ends ALL INTEROP CHECKS PASSED
shellcheck encrypted-credential-handoff/*.sh encrypted-credential-handoff/test/*.sh
pipx run ruff==0.15.7 check encrypted-credential-handoff/
```

The suite needs only what the folder needs: `bash`, `python3` 3.7 or later, the folder's crypto tool (OpenSSL 3 or 4 in 0.1.x), and `jq`. CI also parses the scripts under bash 3.2 (macOS's `/bin/bash`) and fails on any skipped check.

## Style

- Scripts: `bash` that parses under bash 3.2; Python from the standard library only, no third-party packages on the user's or the agent's side.
- Messages never print a secret or anything derived from one, and errors say what to do next.
- Docs and messages use American English spelling (behavior, color, license).
- Each folder's `CHANGELOG.md` gets an entry for every change to that folder.

## Contact

Open an issue. This is a one-person project, so response times vary.
