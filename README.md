# muse-field-kit

[![CI](https://github.com/cmeans/muse-field-kit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cmeans/muse-field-kit/actions/workflows/ci.yml?query=branch%3Amain) [![License](https://img.shields.io/github/license/cmeans/muse-field-kit)](LICENSE)

Field-tested patterns, guides, and small tools for extending [Muse](https://ai.meta.com/muse), Meta's personal AI agent. The patterns here are in daily use in one person's setup. The scripts are their generalized, publication form — written to be adopted, not copied from a live machine — and nothing here is a demo built for this repo.

I'm a developer. I develop MCP servers and related tooling, and I run Muse as a design partner, a builder, and one of a group of AI agents that test and cross-check each other's work. This repo collects the transferable pieces of that setup: the patterns, not the configs. No credentials, addresses, hostnames, or inventories are included, and the examples use placeholders throughout. Each folder also states plainly which of its parts are field-tested and which are new from the publication process itself — “generalized from daily use” should never quietly mean “rewritten last week.”

**Platform:** my setup is Linux throughout, and everything here is developed and tested on Linux first. The *patterns* are platform-independent. The *scripts* say which platforms they cover, and each folder says what its CI runs on which systems and what has been field-tested, which is Linux so far: for example, Credential Lockbox's user side runs on Linux and macOS (`handoff.sh`) and on Windows (`handoff.ps1`), and its CI runs on all three. Each folder states its platform position plainly: where a reviewed reference exists for another platform it is included, and where a port would currently be unreviewed, the folder says so rather than pretending otherwise.

## What's in the kit

| Folder | What it is |
| --- | --- |
| [Credential Lockbox](https://github.com/credential-lockbox/credential-lockbox) | Pass service credentials to Muse as public-key ciphertext that it decrypts in memory on its own machine, keeping the plaintext out of the chat. **Moved to its own repository**, [`credential-lockbox/credential-lockbox`](https://github.com/credential-lockbox/credential-lockbox), from 0.3.1 on. Its releases through `credential-lockbox-v0.3.0` stay here ([`credential-lockbox/`](credential-lockbox/) says more). |

More folders are added as each piece is generalized from daily use into publishable form:

- **stdio MCP daemon pattern** — run frequently called stdio MCP servers as long-lived session daemons (one login, warm calls) instead of spawning a process per call, with a one-shot caller kept for diagnostics.
- **Home Assistant wake-and-acknowledge** — an MQTT pattern so home-automation events can wake the agent, and actionable alerts carry a "Got it" acknowledgement back over the same path, so acknowledged alerts are never repeated.
- **Shadow-mode alerting** — a design pattern for new alerts: run in shadow (log what *would* fire, notify nobody), compare predicted against actual on a schedule, and go live only at a set review date.

## Folder layout

Every folder follows the same two-track layout: a `README.md` for humans, the source itself (scripts, skills, templates), a `SETUP.md` written for your Muse to follow, a `SKILL.md` that routes your Muse's requests to it, and copy-paste prompts in the README. Security-relevant folders also carry a `SECURITY.md`, a `CHANGELOG.md`, and tests. The mechanism ships as reviewed source, never as something the agent improvises; the prompts and SETUP.md carry the decisions, the sequence, and the guardrails around it. Improvements to a mechanism are welcome — as reviewed changes to this repo, not as silent local edits (each folder's SETUP.md defines exactly what counts as a mechanism change).

## Assumptions the patterns are built on

These patterns were developed under a set of operating rules. They are listed here because the designs assume them, not as steps to copy:

- No proactive messages, except one user-controlled priority channel reserved for urgent, immediately actionable items — the designs assume the agent is not a broadcast surface.
- One alert, on one surface, never repeated once acknowledged — the wake-and-acknowledge pattern exists to make that enforceable.
- Verify against the live source before stating a fact — the testing patterns assume evidence over assertion.
- The user's verbatim approval before anything is sent, bought, or published — the guardrails in each SETUP.md assume a human gate on outward actions.

## Disclosure

I direct this work and submit it myself. The patterns come from my own setup, and the builds are a collaboration with the agents named under [Acknowledgments](#acknowledgments). The shared-memory store and NAS MCP server referenced in some guides live in their own repositories and are not part of this one.

## Contributing, security and conduct

Contributions come in as issues (bug reports, feature requests, platform test reports); pull requests are opened by collaborators. See [`CONTRIBUTING.md`](CONTRIBUTING.md). An exploitable security flaw goes through a private advisory, never a public issue: [`SECURITY.md`](SECURITY.md). Everyone taking part follows the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Acknowledgments

This kit is one maintainer's work, built with AI agents that each have a fixed role. Muse, Meta's personal AI agent and the agent these guides are written for, built the first working version for its own setup, tested it on itself, and reviews changes as the end user the patterns serve. Claude Code (Anthropic's Claude) generalized that version and wrote most of what's here now, and a separate Claude Code session reviewed each change as QA before the maintainer's sign-off. Claude on claude.ai reviewed the whole repository once. Nothing merged without the maintainer's sign-off.

The reviews found real bugs, which is why they're there, but they all ran inside one setup. That's peer review, not a third-party audit: each release's CHANGELOG says what was reviewed and what wasn't run ([Credential Lockbox's](https://github.com/credential-lockbox/credential-lockbox/blob/main/CHANGELOG.md)).

## License

MIT, for code and text alike. See `LICENSE`.
