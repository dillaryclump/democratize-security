# Offline recovery decisions

Issue #48 implements slice 4a of [PERSISTENCE.md](PERSISTENCE.md):
`recovery.recovery_decision(state, observation)` produces deterministic inspection
advice from frozen, validated Python records. It performs no I/O and changes no
ledger, phase, reservation, file or external worker. Its output always has
`execution_enabled=False` and `dispatch_blocked=True`.

The policy itself is pure. Store v7 (#62) adds `PlanStore.recovery_state`, which
projects a fully validated runtime attempt onto `RecoveryState` under the current
controller generation; integrity failures raise rather than producing
`integrity_ok=False`. It is not wired to Harbor or any runner. These dataclasses
are not a persisted schema or a JSON import API, and advice never transitions,
dispatches or resubmits.

## Input boundary

`RecoveryState` describes one trial, its optional attempt, current revision,
current inspecting controller generation, request/worker identities, artifact
publication stage and already committed accounting. `actual_cost_cents=None`
means unknown. A known cost, including zero, is permitted only on a terminal
attempt and means settlement already committed. Recovery never creates settlement.
Amounts are nonnegative integer cents; booleans and floats are rejected.
Records must be consistent with the contract's phase prerequisites:
- `running`, `sealed`, `verifying` and `completed` need the acknowledged worker's
  identity, since that acknowledgement binds the worker before `running`;
- a committed artifact reference needs `sealed` or later, and a verification
  intent needs `verifying` or later;
- `preparing` and `interrupted` may still hold the offline bindings store v5
  allows.

A `reconciling` record is checked against the phase it came from.

`RecoveryObservation` describes a fresh inspection of those same identities.
Trial, attempt, controller generation, revision and both request IDs must match
exactly, including absence. An observed worker cannot conflict with a recorded
worker. Before acknowledgement, a fresh inspection may identify the worker for
the recorded request, but this function does not persist that acknowledgement.
An observed active or stopped worker must always be named.
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
worker conflicting with sealed, verifying or terminal state (each of which
records the worker's observed stop) or a recorded cost overrun takes precedence
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
mismatches, contradictory sealed and terminal observations and replay. Each
validation rule and contradiction has a case that fails when that rule is
removed. A cross-product test
varies worker status, deadline expiry, artifact validity and evidence coverage,
checking that no combination releases an unknown-cost hold or enables dispatch.

Controller generations (#53) and the v7 projection (#62) are implemented;
`tests/test_runtime_store.py` feeds `recovery_state` through each runtime phase
and a lost acknowledgement. Observations are still caller-supplied: a runner
integration must authenticate them before advice can become transitions.
M0/M2 owner acceptance, dedicated worker bounds and finite model budget still gate
live execution.
