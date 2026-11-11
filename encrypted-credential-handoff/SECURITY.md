# Security policy — encrypted-credential-handoff

This folder is a security pattern; flaws in it matter more than most bugs.

## Reporting

- Preferred: report it privately. On this repository's **Security** tab, choose **Report a vulnerability** (https://github.com/cmeans/muse-field-kit/security/advisories/new). Only you and the repository's maintainers see the report, and it and any fix can be discussed there before disclosure.
- Please do **not** open a public issue containing exploit detail for an unpatched flaw.
- Reports about the *pattern* (a way the invariants fail even when the scripts are used as documented) are as welcome as reports about the scripts.

## Scope notes

- The threat model and the ten invariants in `README.md` define what this pattern claims to defend against. A report that something in the “does not defend against” list is indeed not defended is a documentation discussion, not a vulnerability — but if the README's wording anywhere overstates the defended side, that overstatement is itself worth reporting.
- The keypair under `test/` is a published, throwaway test vector. It protects nothing; never use it for a real credential.
