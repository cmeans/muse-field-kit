# Changelog — encrypted-credential-handoff

## Unreleased — pre-publication revision (2026-11-11)

Produced by a two-round independent review (structural review of the documents, then a line-level review of the scripts, with findings reproduced on a separate machine) before this folder's first public commit.

- **Renamed** from “blind-RSA credential handoff” to **encrypted credential handoff**: “blind RSA” already names a different, standardized technique (blind signatures), and the old name mis-signalled the mechanism.
- **Threat model added** to the README, including what the pattern does not defend against: host trust, the agent-account caveat, the absence of sender authentication, and no forward secrecy under key compromise.
- **Invariants expanded from six to ten**: provenance (stage only user-pasted blobs), purpose binding (`svc`), controlled egress, key confinement, and mandatory (not default) key/ciphertext separation. The setup dummy check now uses `--check` output (field names and lengths) instead of reporting a decrypted value.
- **Rotation split** into routine rotation and compromise response; key rotation alone is no longer presented as a remedy for compromise.
- **consume.py replaces decrypt-example.py**: adds `--label` purpose-binding enforcement, a `--check` mode, unknown-field handling (a payload with no known credential field is refused), non-string field rejection, a missing-key error that names the path, refusal of group/other-readable private keys, clean errors for non-object payloads, and shell-convention exit codes for signal-killed children.
- **handoff.sh fixes**: fingerprint printing now fails closed (a placeholder or damaged embedded key exits 1 instead of printing the SHA-256 of empty input); JSON validation requires exactly one JSON object; neutral `api_key_*` payload examples replace a vendor-shaped token example; `--help` added; stale “blind” wording removed.
- **agent-setup.sh fixes**: openssl stderr no longer suppressed (failures show their cause); `umask 077` set explicitly; a pre-existing key directory's permissions are no longer silently changed; the consume-side `HANDOFF_PRIVKEY` configuration is printed at the end.
- **Platform doctrine corrected**: reviewed reference implementations are the default; agent-written ports are explicitly labelled unreviewed and gated on user review plus the interop test. macOS status stated as expected-but-unreviewed; Windows as no-reference-yet.
- **Interop test added** under `test/` (known-answer vectors) and this changelog and `SECURITY.md` added.
- **Licensing clarified**: MIT for code and text alike.
