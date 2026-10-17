# ADR 0005: Ephemeral verifier nonces and conservative crash handling

Status: implemented prerequisite for review, 2026-10-17. Runtime integration and
accepted-result transactions remain subsequent work. This does not expand the
synthetic application threat model or authorize execution.

Use one fresh 256-bit nonce per verifier request, held in memory by the trusted
controller and delivered only through a private trusted launcher channel to the
separate verifier. Bind a versioned public challenge to every independently
selected execution identity plus the nonce commitment before launch. Authenticate
the challenge and complete supplied report under a domain-separated HMAC-SHA256.

Do not persist raw nonces in SQLite, object storage, job files, logs or backups.
The project does not yet have a reviewed controller-only persistent secret store.
Persisting a secret beside public candidate-visible evidence would undermine the
existing verifier boundary. A public challenge and nonce commitment are not
proof that a verifier ran.

If the controller dies before an authenticated observation and exact evidence
are admitted in one fenced result transaction, leave verification incomplete and
retain the cost hold. Do not reconstruct a nonce, accept an old saved report or
resubmit generation/verification merely to obtain a new acknowledgement. A
committed result can later be read only through the future validated admission
ledger, not by reclassifying a public observation as authenticated.

This deliberately sacrifices automatic verification recovery at that crash
window. It keeps uncertainty explicit and prevents acceptance from candidate
reports or guessed provenance. A future persistent secret store or asymmetric
worker signing identity requires separate review and backup/key-lifecycle tests.

The contract is independent of Harbor and model providers. It preserves the
existing public verifier protocol, scores, offline evidence and historical rows.
