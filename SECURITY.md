# Security policy

## Supported versions

Each folder is versioned on its own, in its `CHANGELOG.md`. Security fixes go into the latest release of a folder only; older releases get no backports, so upgrade to the latest.

| Folder | Supported | Not supported |
| --- | --- | --- |
| `encrypted-credential-handoff` | 0.2.x (the latest release) | 0.1.x: 0.2.0 replaced its cryptography (RSA through OpenSSL) with `age`, and a 0.1.x install sets up again (the folder's `CHANGELOG.md`) |

## Reporting an issue

**Please do not open a public issue for a security problem in a folder's scripts or pattern.**

The supported channel is a **GitHub private security advisory**:

1. Go to <https://github.com/cmeans/muse-field-kit/security/advisories/new> (or the repository's **Security and quality** tab, which may be under the "…" menu on a narrow window, then **Report a vulnerability**). You need to be signed in to GitHub.
2. Describe the problem, how to reproduce it, and the version affected.
3. Submit it. Only you and the repository's maintainers see the report, and the report, any proof of concept, the fix and the disclosure timing are discussed there.

If you can't use a private advisory, open a **public** issue with the [Security contact request](https://github.com/cmeans/muse-field-kit/issues/new?template=security_contact.yml) form, which asks for no details, and the maintainer will arrange a private channel.

Guides and patterns without scripts (documentation problems) can be reported as normal issues; there's no embargo expectation for those.

## Please include

- What the problem is and what it lets an attacker do.
- Steps to reproduce, or a proof of concept. Use the published test keys under a folder's `test/` directory, never a real key or credential.
- The folder and its version (the release tag, or the commit you used).
- Your platform and tool versions. For `encrypted-credential-handoff`, the operating system, the `bash`, `python3` and `jq` versions (on Windows, the PowerShell version, `$PSVersionTable.PSVersion`), and `age --version`. The output of `handoff.sh --check-setup` (or `handoff.ps1 -CheckSetup`) or `agent-setup.sh --check-setup` gives these; it holds no secret.
- Whether it reproduces with the folder's scripts used exactly as its instructions say (`SETUP.md`, and for `encrypted-credential-handoff` also `ROTATION.md`), or only with a changed setup.

## What to expect

- **An acknowledgment** once the maintainer sees the report. This is a one-person project, so response times vary.
- **A coordinated fix and disclosure timeline**, agreed in the advisory.
- **Credit in the release notes** if you want it; anonymous reports are fine too.
- **No monetary reward.** There's no bug bounty.

## Scope

Each security-relevant folder's own `SECURITY.md` says what its pattern claims to defend against, and so what counts as a vulnerability:

- [`encrypted-credential-handoff/SECURITY.md`](encrypted-credential-handoff/SECURITY.md): the threat model and the ten invariants in that folder's [`README.md`](encrypted-credential-handoff/README.md#threat-model).

**In scope**

- A way a folder's documented guarantees fail when its scripts are used as its instructions say (`SETUP.md`, and `ROTATION.md` where there is one) (for example, a credential reaching the chat, the agent's context or disk), or wording that overstates what is defended.
- A request the instructions should treat as an injection attempt but don't: content the agent reads (a web page, a tool result, a message) that gets a credential disclosed while the agent follows its instructions as written. That's a gap in the rules, not the agent misbehaving.
- The scripts themselves: input that gets past a documented check, a credential in output or logs, a race by another account that defeats a check.
- This repository's GitHub Actions workflows: injection through `${{ github.event.* }}` expressions in `run:` blocks, token permissions, and anything that lets a pull request's content run with more than read access.
- The integrity of what a release publishes.

**Out of scope**

- Anything a folder's threat model lists under "does not defend against" (for `encrypted-credential-handoff`: a compromised host, the agent misbehaving, sender authentication, key compromise and the others listed there). A report that one of those isn't defended is a documentation discussion, not a vulnerability.
- Vulnerabilities in the tools a folder uses (`age`, Python, `jq`, `bash`, PowerShell): report them upstream.
- Vulnerabilities in Muse, its platform or its connectors: report them to Meta.
- Attacks that need shell access as the agent's account, or the private key, already.

## Historical issues

Security-relevant findings that aren't embargoed are tracked as issues with the `security` label. See also `LICENSE` for the warranty disclaimer.
