# muse-field-kit

Field-tested patterns, guides, and small tools for extending [Muse](https://ai.meta.com/muse), Meta's personal AI agent. The patterns here are in daily use in one person's setup. The scripts are their generalized, publication form — written to be adopted, not copied from a live machine — and nothing here is a demo built for this repo.

I'm a developer. I develop MCP servers and related tooling, and I run Muse as a design partner, a builder, and one of a group of AI agents that test and cross-check each other's work. This repo collects the transferable pieces of that setup: the patterns, not the configs. No credentials, addresses, hostnames, or inventories are included, and the examples use placeholders throughout.

**Platform:** my setup is Linux throughout, and everything here is developed and tested on Linux first. The *patterns* are platform-independent; the *scripts* are reviewed Linux implementations of them. Each folder states its platform position plainly: where a reviewed reference exists for another platform it is included, and where a port would currently be unreviewed, the folder says so rather than pretending otherwise.

## What's in the kit

| Folder | What it is |
| --- | --- |
| [encrypted-credential-handoff](encrypted-credential-handoff/) | Pass service credentials to Muse as public-key ciphertext that it decrypts in memory on its own machine, keeping the plaintext out of the chat. |

More folders are added as each piece is generalized from daily use into publishable form:

- **stdio MCP daemon pattern** — run frequently called stdio MCP servers as long-lived session daemons (one login, warm calls) instead of spawning a process per call, with a one-shot caller kept for diagnostics.
- **Home Assistant wake-and-acknowledge** — an MQTT pattern so home-automation events can wake the agent, and actionable alerts carry a "Got it" acknowledgement back over the same path, so acknowledged alerts are never repeated.
- **Shadow-mode alerting** — a design pattern for new alerts: run in shadow (log what *would* fire, notify nobody), compare predicted against actual on a schedule, and go live only at a set review date.

## Folder layout

Every folder follows the same two-track layout: a `README.md` for humans, the source itself (scripts, skills, templates), a `SETUP.md` written for your Muse to follow, and copy-paste prompts in the README. Security-relevant folders also carry a `SECURITY.md`, a `CHANGELOG.md`, and tests. The mechanism ships as reviewed source, never as something the agent improvises; the prompts and SETUP.md carry the decisions, the sequence, and the guardrails around it. Improvements to a mechanism are welcome — as reviewed changes to this repo, not as silent local edits (each folder's SETUP.md defines exactly what counts as a mechanism change).

## Assumptions the patterns are built on

These patterns were developed under a set of operating rules. They are listed here because the designs assume them, not as steps to copy:

- No proactive messages, except one user-controlled priority channel reserved for urgent, immediately actionable items — the designs assume the agent is not a broadcast surface.
- One alert, on one surface, never repeated once acknowledged — the wake-and-acknowledge pattern exists to make that enforceable.
- Verify against the live source before stating a fact — the testing patterns assume evidence over assertion.
- The user's verbatim approval before anything is sent, bought, or published — the guardrails in each SETUP.md assume a human gate on outward actions.

## Disclosure

These are my own builds and guides, written up and submitted by me. The shared-memory store and NAS MCP server referenced in some guides live in their own repositories and are not part of this one.

## License

MIT, for code and text alike. See `LICENSE`.
