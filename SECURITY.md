# Security policy

## Supported versions

Each folder is versioned on its own, in its `CHANGELOG.md`. Security fixes go into the latest release of a folder only; older releases get no backports, so upgrade to the latest.

No folder in this repository has a supported release today.

**Credential Lockbox**, the only folder released from here so far, moved to [`credential-lockbox/credential-lockbox`](https://github.com/credential-lockbox/credential-lockbox), where its supported versions are listed in [its `SECURITY.md`](https://github.com/credential-lockbox/credential-lockbox/blob/main/SECURITY.md). Report Credential Lockbox problems there. The releases it left here (`credential-lockbox-v0.3.0` and older) get no fixes; its 0.3.1 (the same scripts as 0.3.0) and later releases are in the new repository.

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
- Steps to reproduce, or a proof of concept. Use a folder's published test keys, where it has them, never a real key or credential.
- The folder and its version (the release tag, or the commit you used).
- Your platform and tool versions.
- Whether it reproduces with the folder's scripts used exactly as its instructions say (`SETUP.md`, and `ROTATION.md` where there is one), or only with a changed setup.

## What to expect

- **An acknowledgment** once the maintainer sees the report. This is a one-person project, so response times vary.
- **A coordinated fix and disclosure timeline**, agreed in the advisory.
- **Credit in the release notes** if you want it; anonymous reports are fine too.
- **No monetary reward.** There's no bug bounty.

## Scope

Each security-relevant folder's own `SECURITY.md` says what its pattern claims to defend against, and so what counts as a vulnerability:

- None in this repository today. Credential Lockbox's threat model and invariants are in [its repository](https://github.com/credential-lockbox/credential-lockbox#threat-model).

**In scope**

- A way a folder's documented guarantees fail when its scripts are used as its instructions say (`SETUP.md`, and `ROTATION.md` where there is one) (for example, a credential reaching the chat, the agent's context or disk), or wording that overstates what is defended.
- A request the instructions should treat as an injection attempt but don't: content the agent reads (a web page, a tool result, a message) that gets a credential or the key disclosed, or a label run other than as recorded, while the agent follows its instructions as written. That's a gap in the rules. The threat model's "Prompt injection at use time" and "the agent misbehaving" cover an agent that departs from its rules, which is out of scope.
- The scripts themselves: input that gets past a documented check, a credential in output or logs, a race by another account that defeats a check.
- This repository's GitHub Actions workflows: injection through `${{ github.event.* }}` expressions in `run:` blocks, token permissions, and anything that lets a pull request's content run with more than read access.
- The integrity of what a release publishes.

**Out of scope**

- Anything a folder's threat model lists under "does not defend against". A report that one of those isn't defended is a documentation discussion, not a vulnerability.
- Vulnerabilities in the tools a folder uses (`age`, Python, `jq`, `bash`, PowerShell): report them upstream.
- Vulnerabilities in Muse, its platform or its connectors: report them to Meta.
- Attacks that need shell access as the agent's account, or the private key, already.

## Historical issues

Security-relevant findings that aren't embargoed are tracked as issues with the `security` label. See also `LICENSE` for the warranty disclaimer.
