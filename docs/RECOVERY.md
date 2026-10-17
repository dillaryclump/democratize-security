# Offline recovery decisions

Issue #48 implements slice 4a of [PERSISTENCE.md](PERSISTENCE.md):
`recovery.recovery_decision(state, observation)` produces deterministic inspection
advice from frozen, validated Python records. It performs no I/O and changes no
ledger, phase, reservation, file or external worker. Its output always has
`execution_enabled=False` and `dispatch_blocked=True`.

This is a standalone policy model with synthetic inputs. It is not wired to
PlanStore or Harbor. Store v5 still supports only preparing/interrupted accounting;
the additional runtime phases here model the proposed contract. These dataclasses
are not a new persisted schema or a JSON import API. No result acceptance exists.

## Input boundary

`RecoveryState` describes one trial, its optional attempt, current revision,
current inspecting controller generation, request/worker identities, artifact
publication stage and already committed accounting. `actual_cost_cents=None`
means unknown. A known cost, including zero, is permitted only on a terminal
attempt and means settlement already committed. Recovery never creates settlement.
Amounts are nonnegative integer cents; booleans and floats are rejected.

`RecoveryObservation` describes a fresh inspection of those same identities.
Trial, attempt, controller generation, revision and both request IDs must match
exactly, including absence. An observed worker cannot conflict with a recorded
worker. Before acknowledgement, a fresh inspection may identify the worker for
the recorded request, but this function does not persist that acknowledgement.
On mismatch, `RecoveryError` rejects the observation; callers must keep dispatch
blocked. Optional worker absence does not establish worker termination.

The generation belongs to the current inspecting controller. After a restart,
observations must be obtained again in that controller's context. This equality
check does not allocate generations, acquire ownership or fence database writes.
Durable controller fencing is the next separate slice.

The caller must independently validate the store/event chain and expected object
hashes, and ultimately authenticate worker/verifier observations. `integrity_ok`,
`workspace_verified`, `valid` bytes and `complete` coverage are synthetic assertions
for testing policy, not authentication mechanisms. Never fill these fields from
candidate-provided claims. The reducer deliberately cannot return accepted results
even when all supplied assertions look favorable.

## Crash-window coverage

All actions below are inspection advice, not commands to execute. Integrity
failure, missing referenced bytes, a partial/missing completed result, an active
worker conflicting with terminal state or a recorded cost overrun takes precedence
and produces `integrity_stop`. Every decision preserves accounting exactly.

| Durable crash boundary | Advice and limits |
| --- | --- |
| Plan import / before preparation commit | `inspect_plan`; no attempt is invented. Existing store transaction tests prove import is all-or-none. |
| Reservation before dispatch intent | `review_preparation`; preserve full hold, including unknown zero-cost reservations. |
| Dispatch intent before/after send, lost acknowledgement | `reconcile_runner` by the same request. Unknown or not-found outcomes never emit resubmission. |
| Acknowledged worker active | `observe_worker`, or `inspect_stop` after deadline expiry; expiration never proves termination. |
| Worker missing, request/bill unresolved | `reconcile_runner`; keep the full hold. |
| Worker stopped before sealing | `review_collection` only with verified original workspace; otherwise `review_interruption`. Neither action collects or interrupts automatically. |
| Object linked before directory sync | `reconcile_publication`; valid bytes do not prove durability. |
| Object durable before reference commit | `review_orphan`; no automatic attachment, deletion or acceptance. |
| Reference committed | `revalidate_artifact`; after valid bytes, inspect existing verifier request or `review_verification_intent`. No verifier launch is emitted. |
| Verification / lost acknowledgement | `reconcile_verifier` for the same request, even for complete coverage; authentication remains unresolved. |
| Result committed before acknowledgement | `review_committed_result`; preserve the terminal record and hold while checking provenance. No duplicate attempt/result is created. |
| Settlement transaction | Return old full hold or already committed charge. Interrupted unknown cost produces `reconcile_billing`; overrun stops while preserving actual cost. Existing store tests prove transaction atomicity. |

Runner uncertainty is resolved before artifact/verification advice on a nonterminal
attempt. A `reconciling` record must retain its previous active phase and yields
the same advice as that phase. Replaying identical inputs yields equal decisions
without mutation; durable application of advice and event-idempotency remain future
work. This module does not prove recovery of a live provider or power-loss safety.

## Validation and next integration

`tests/test_recovery.py` exercises the crash windows, malformed states, identity
mismatches, contradictory terminal observations and replay. A cross-product test
varies worker status, deadline expiry, artifact validity and evidence coverage,
checking that no combination releases an unknown-cost hold or enables dispatch.

Next: persist monotonically increasing controller generations under the existing
exclusive lock, test crash/reopen and stale writes, and define how validated store
projections feed this policy. Trusted runtime authentication and accepted-result
transactions are separate prerequisites before advice can become transitions.
M0/M2 owner acceptance, dedicated worker bounds and finite model budget still gate
live execution.
