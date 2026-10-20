# Trusted verifier request authentication

Issue #56 implements a standard-library challenge/report contract. It is a
prerequisite to trusted runtime admission, not a dispatcher, accepted-result
transaction or replacement for Harbor's existing control acceptance.

The trusted controller independently resolves and revalidates the expected
campaign, trial, attempt, runner request, worker, verifier request, current
controller generation, expected revision, task revision, artifact binding digest,
artifact payload hash, raw object hash, verifier hash and protocol. It constructs
`VerificationContext` before reading an incoming report. Context syntax checks do
not establish the origin of these values; the controller must obtain them from
validated state and authenticated worker observations.

`VerifierSession(expected)` creates a fresh 256-bit nonce. `public_challenge()`
exports only the public context, nonce SHA-256 commitment and challenge digest.
The future runtime must commit this exact challenge before launching a verifier.
`verifier_nonce()` is for a private trusted launcher channel only. It must never
enter a candidate environment, public job configuration, logs, exported records
or backups. The session prevents ordinary copying and pickling; Python reflection
by a trusted controller owner remains outside this protection.

The independent verifier calls `sign_report(challenge, nonce, report)` after
checking the selected artifact. This validates the existing report contract and
returns canonical JSON under a domain-separated HMAC-SHA256. Every public context
field and the entire report are authenticated. Report protocol and scoring stay
`synthetic-reference-v3`; the authentication envelope has its own schema version 1.

`session.authenticate(raw_bytes)` requires an exact match with the independently
selected challenge and a valid MAC. It rejects malformed, oversized, duplicate-key,
noncanonical or altered records. It returns an `AuthenticatedObservation` with
detached report values, public context and envelope/challenge hashes. Complete
failed reports remain failures; missing or not-evaluated checks remain incomplete.
The `complete` property describes check accounting and does not mean success.

An exact same-envelope authentication retry is idempotent. Two different valid
reports for one session permanently stop it. Cross-request or cross-restart
replay is rejected, including a restart with identical public execution identities.
Nonce transport and authentication also reject a session inherited by a forked
controller process. Store admission still requires its own generation/revision
fencing; process binding here is not durable ownership or memory isolation.

## Nonce lifetime and crash policy

See [ADR 0005](decisions/0005-runtime-verifier-nonces.md). The initial nonce exists
only in the current controller's memory and the trusted verifier's private
transport/process. No reconstruct-from-public-challenge API exists. If the
controller dies before an authenticated result is durably admitted, the saved
report remains incomplete for acceptance and the attempt/cost hold is retained.
No automatic verifier or generation resubmission follows. A later controller
cannot infer trusted execution from the report's hashes or a public observation.

## Integration boundary still to implement

The launcher must authenticate its worker/stop observations, validate and pin the
verifier source/image, commit challenge intent before dispatch, supply the nonce
only to the separate verifier and use this contract to authenticate its result.
The store must admit that observation and the exact evidence references together
with its event/revision/result in one fenced transaction. A deserialized public
record or a directly constructed Python dataclass is not admission authority.
Store v7 (#62) implements that admission: `PlanStore.admit_result` rebuilds the
context from validated state, requires the session holding the committed
challenge and commits the authenticated result atomically (see
[PERSISTENCE.md](PERSISTENCE.md)). The launcher, worker observation
authentication and verifier pinning remain unimplemented.

Existing offline evidence and Harbor control envelopes retain their formats and
limits. A future adapter must explicitly bridge the reviewed verifier into this
contract; the presence of this module does not retrofit authentication onto
historical or candidate-authored reports. No model call or spending is enabled.

## Validation

`tests/test_runtime_auth.py` exercises signing in a separate trusted subprocess
using a private stdin pipe, successful authentication, complete failures,
incomplete coverage, replay after restart, valid-MAC substitution of every context
field, wrong/guessed nonces, modified reports, duplicate/unknown fields, byte
bounds, exact retries and conflicting reports. The subprocess is a reviewed
protocol fixture; it is not a claim of an independently executed HTTP evaluation
or worker isolation.
