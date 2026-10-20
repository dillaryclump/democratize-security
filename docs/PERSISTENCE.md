# Persistence and crash recovery contract

Status: proposed design for M3, issue #21; **offline plan import and synthetic
attempt/budget accounting are merged via #33**, as described below.
The external recovery engine remains unimplemented. Issue #48 adds a standalone
pure policy for synthetic recovery observations; see [RECOVERY.md](RECOVERY.md).
It returns inspection advice without changing store state or enabling execution.
Store v6 adds durable controller generations and write fencing (issue #53),
described below. Store v7 (issue #62) adds the runtime attempt lifecycle,
authenticated result admission and restore fences in the same ledger; no
dispatcher or runner is connected to it.
Integration #33 merged at
`d6c2657`; implementation originates in #26/#28/#30. ADR [0004](decisions/0004-persistence-recovery.md) records the choice.
This contract does not approve model execution or change campaign schema v1,
artifact schema v1, verifier protocol v3, or existing scores. M0/M2 owner
acceptance, dedicated worker isolation and a finite approved budget remain gates.

## Implemented offline plan ledger (slice 1a)

`democratize_security.store.PlanStore` imports a campaign through the existing
planner and commits its full plan, all ordered trial records and one immutable
`planned` event per trial in a single transaction. A matching re-import is a
validated no-op. Reopening validates schema, database integrity, foreign keys,
canonical plan identities, complete trial coverage and import-event coverage.
Snapshots retain `execution_enabled: false` and return independent Python values.

Use as a Python context manager with an existing trusted local directory:

```python
from pathlib import Path
from democratize_security.contracts import load_campaign
from democratize_security.store import PlanStore

campaign = load_campaign(Path("campaigns/development.example.json"))
# ledger_directory must already exist durably under controller ownership.
with PlanStore(ledger_directory) as store:
    saved_plan = store.import_campaign(campaign)
    same_plan = store.snapshot(saved_plan["campaign_id"])
```

The API fixes filenames to `ledger.sqlite3` and `ledger.lock`, uses a nonblocking
POSIX flock for the context lifetime, creates files with private permissions,
rejects symlink/hardlinked database or lock files, requires SQLite FULL sync,
DELETE journaling and foreign keys, and syncs the parent before returning from
open. Do not rename, unlink or replace the live directory/lock/database. Never
share one open instance across forked processes or use network filesystems.
Close the context to release ownership. Unknown versions or schema differences
refuse to open. Version 1 stores require explicit `migrate=True` to upgrade to
version 7; versions 2, 3, 4, 5 and 6 also require explicit migration. No other upgrade is supported. Plans are limited to 16 MiB canonical JSON.

Version 1 had only campaigns, immutable planned trials and import events at
sequence zero. Version 2 adds the bounded accounting API below. It still has no
controller generation, general runtime transitions, verifier-result references,
result acceptance, recovery dispatcher, backup tool or CLI. Version 3 adds the
artifact binding described below. Version 4 adds immutable offline evidence
linkage, still without accepted results or runtime authentication. These additions
require an explicit store-version migration; the wider runtime
contracts below remain proposals. A complete plan snapshot is not a
successful experiment or an execution authorization. The lock/SQL triggers protect
cooperating code, not an owner editing files. No sensitive final cases belong here.

Tests kill a subprocess with `os._exit` immediately before or after import commit,
reopen the store and require none/all of the scheduled records. Other tests inject
a mid-import SQL failure, hold the lock from another process, corrupt stored
rows/schema, reject writes to immutable records, reopen and re-import plans, and
check byte limits. These prove local process-crash behavior, not power-loss
durability or live provider recovery.

## Implemented offline accounting (version 2, issue #29)

This API records synthetic accounting inputs only; it does not authenticate
provider receipts, resolve candidate/task files, prove worker termination or
approve spending. Plan snapshots remain unchanged with execution disabled.
`record_accounting(event_id, request)` supports exactly three actions:

| Action | Required request fields besides `action`, `attempt_id`, `expected_revision` | Result |
| --- | --- | --- |
| `prepare` | `campaign_id`, `trial_id`, `max_cost_cents`, `basis_sha256` | At revision 0, create preparing attempt, full cost hold and immutable event together; output revision 1 |
| `interrupt` | `reason` | Only preparing -> interrupted, recording reason and incrementing revision; unknown cost retains the entire hold |
| `settle` | `actual_cost_cents`, `receipt_id` | Only an interrupted, unsettled attempt; replace hold with recorded cost and increment revision without changing terminal phase |

Amounts are nonnegative integers in USD cents, not booleans or floats. IDs are
bounded portable strings. The reservation basis is a lowercase 64-character
SHA-256 reference to the caller's synthetic cost/limit assumptions; syntax alone
is not proof that a real dispatch is bounded. Example after importing a campaign:

```python
trial = saved_plan["trials"][0]
state = store.record_accounting("reserve-example", {
    "action": "prepare",
    "attempt_id": "example-attempt",
    "expected_revision": 0,
    "campaign_id": saved_plan["campaign_id"],
    "trial_id": trial["trial_id"],
    "max_cost_cents": 0,  # Offline example; not a free model call.
    "basis_sha256": "a" * 64,  # Synthetic placeholder, never dispatch evidence.
})
budget = store.budget_snapshot(saved_plan["campaign_id"])
assert budget["execution_enabled"] is False
```

`attempts()` replays immutable accounting events and compares the derived state
with each saved attempt. Missing/mismatched events, invalid transitions or
changed projections reject reads and reopening. Import events and scheduled
trial rows stay immutable; accounting does not remove failures from the denominator.
There is only one attempt per logical trial in this version. No retries, repairs,
dispatch, running, verifying or successful completion transitions are accepted.

All accounting mutations use one SQLite transaction. A stale expected revision
rolls back without changing state, events or funds. Exact repeats of an event ID
or receipt ID with the original request return its original result without adding
another event, even after later transitions. A changed request reusing either ID
records an immutable store-wide integrity stop and raises an error; existing
charges remain unchanged. That stop survives reopen and has no automatic reset.
New preparations are blocked, while existing attempts may still be interrupted
or settled. Reviewed reconciliation/reset procedures remain future work.

Budget snapshots derive held and settled amounts from validated attempt states.
Any active or unknown-cost attempt blocks another preparation across the store,
including a zero-value hold. A settlement above its reservation is retained at
its actual amount and permanently blocks further preparation in that campaign;
negative available balance is reported honestly. A settled receipt is terminal:
corrections, credits and receipt authentication are not implemented.

Upgrade an existing version 1 store with `PlanStore(directory, migrate=True)`.
The exact old schema and all plans/import events are validated before migration.
New tables/triggers and the version bump commit atomically; old rows are never
rewritten. Normal opening refuses version 1 rather than implicitly modifying it.
New stores now start at version 6. All old versions require explicit migration;
old accounting and, for v3, artifact bindings are validated before schema changes. Unknown versions or altered schemas are rejected.
Take a verified backup before migrating valuable data. The current offline
[backup tool](BACKUP.md) supports only store v6; existing v5 archives need their
matching implementation before explicit source migration.

Tests abruptly exit subprocesses before/after prepare, interruption, settlement
and migration commits. Faults between projection and event writes must roll back
both. Tests also cover unknown-cost holds, stale revisions, exact/conflicting
receipts, overrun stops, schema preservation, corruption and append-only events.
These are offline process-crash tests, not provider recovery or power-loss proof.

## Artifact object publication (slice 3a, issue #34)

The `objects` module now publishes and revalidates sealed artifact objects using
both raw-file and payload identities. Exact existing objects require explicit
file/directory sync reconciliation. See [ARTIFACTS.md](ARTIFACTS.md). This is only
the publication prerequisite: no SQLite evidence table, attempt binding, accepted
result, schema migration or recovery transition was added in slice 3a. Slice 3b below adds artifact reference/event linkage. Verifier-result evidence
and acceptance remain future work.

## Immutable artifact bindings (version 3, slice 3b, issue #36)

Open `PlanStore(ledger_directory, objects_directory=object_directory)` to use
bindings. `record_artifact(event_id, request)` accepts exactly these request fields:

| Field | Check |
| --- | --- |
| `attempt_id`, `expected_revision` | Existing preparing attempt at its current accounting revision; no stale first insertion |
| `campaign_id`, `trial_id`, `task_revision` | Exact immutable planned trial and preparing-event identities |
| `artifact_ref` | Slice 3a object reference; reread and validate both raw-file and artifact-payload hashes |
| `verifier_sha256`, `protocol` | Concrete verifier hash and bounded protocol identifier, pinned as synthetic intent |

The artifact must already exist. Before inserting a binding the store validates
it and reconciles file/directory durability through the object publisher. One
immutable `artifact_bindings` row is both reference and event, with a foreign key
to the exact accounting attempt/revision. Its canonical envelope contains schema
version 1, event ID, request and `binding_sha256`. The returned record is detached.
There is at most one binding per attempt. No accounting revision, phase, cost,
reservation or scientific result changes.

Exact same-event/request retries return the original validated binding, including
after interruption or settlement. Reusing an event or attempt for a different
binding records a persistent integrity stop, preserves the original, and rejects.
New preparations/bindings are blocked; interruption/settlement may still resolve
existing accounting. Event IDs in this API are scoped to artifact bindings.
Verifier hashes and protocols cannot be rewritten after the first binding.

`artifact_bindings()` checks accounting history, canonical envelope, planned
identities and every referenced object. Opening a store with bindings requires
its object directory and performs the same checks. Budget snapshots and new
preparation also check references; missing or tampered bytes raise an error rather
than returning an apparently usable budget. Ordinary offline plan snapshots stay
available with execution disabled. Integrity checks are not protection against
the controller owner editing both database and files, and no automatic repair or
cleanup is implemented.

Version 3 migration validates the exact old v1/v2 schema and old records first,
then adds only the binding table/triggers and version bump in one transaction.
Existing plans, attempts, events and accounting stops are not rewritten. Tests
cover abrupt subprocess death before/after binding and v2 migration commits,
SQL/sync failure, missing/changed objects, stale/conflicting identities, immutable
rows and byte-for-byte preservation of old records. These are process-crash tests,
not power-loss proof.

The caller supplies trusted **synthetic intent**. Pinning a verifier hash is not
proof it executed or authenticated a result; no verifier result is stored here.
The [offline evidence contract](EVIDENCE.md) now validates report/check coverage
and binds expected identities before serialization; it adds no database writes.
Version 4 below adds durable offline evidence linkage. Completed states,
authenticated result acceptance, runtime request provenance, controller
generations and recovery remain subsequent work. A binding cannot
promote a candidate, release its reservation or authorize execution.

## Immutable offline evidence bindings (version 4, issue #42)

Open `PlanStore(ledger_directory, objects_directory=artifact_directory,
evidence_directory=evidence_directory)` for evidence linkage. Use existing durable
controller-owned directories; no candidate may modify them. Artifacts and evidence
may share a directory, but use distinct reference kinds and validation contracts.

Version 4 introduced the fields below. In version 5, new calls also require
`verification_intent_sha256` from a previously committed verification intent.
Historical records remain unchanged; see the v5 section below.

| Field | Check |
| --- | --- |
| `attempt_id`, `expected_revision` | Current preparing attempt, at the same revision pinned by its artifact binding |
| `artifact_binding_sha256` | Exact digest of that attempt's independently loaded immutable artifact binding |
| `verification_request_id` | Bounded identifier, unique across all evidence bindings in this store |
| `evidence_ref` | Existing bounded canonical offline evidence object, with raw object and envelope hashes |

The store resolves expected campaign/trial/task/artifact/verifier context from
its artifact binding, revalidating the artifact bytes, then validates the evidence
against that context and the caller's expected request identity. It reconciles
evidence file/directory durability before committing one immutable reference/event
row. The envelope has schema version 1, kind `offline_evidence_binding`, event ID,
request and binding digest. SQL foreign keys bind it to the artifact event and
accounting attempt/revision. There is at most one observation per attempt. Later
partial-report completion/replacement is not supported by this offline API.

This stores a **synthetic offline observation**, not a trusted runtime result.
The caller supplies the request identity; this is not a recorded pre-dispatch
intent and cannot authenticate a verifier or prove it ran. No phase, revision,
cost, reservation or acceptance changes, even for a complete passing report.
Failed/incomplete reports retain every recorded outcome. Candidate promotion and
completed-result reporting must not use these records as authenticated results.

Exact same-event/request retries return the revalidated original, even after
interruption or settlement. Reusing an event ID, attempt or verification request
for a different record persists an integrity stop without replacing the original.
The stop blocks new preparation/artifact/evidence binding; existing accounting can
still be interrupted/settled. Event IDs are scoped to this evidence table.

`evidence_bindings()` checks accounting history, artifact bindings/bytes, canonical
row/projection identities and evidence files on every call. Reopening a ledger,
budget snapshots and new preparation perform the same validation. Missing or
changed objects raise errors; an orphan file never becomes a ledger record by
being present. Plan snapshots remain offline and do not report result acceptance.

Explicit migration validates existing v1/v2/v3 schemas and applicable records,
then adds missing tables/triggers and bumps to v4 in one transaction. Old records
are not rewritten. V3 artifact corruption rejects migration before its schema
changes. Tests cover v1/v2/v3 migration, SQL/sync faults, process death around v4
migration and evidence commits, stale/foreign/conflicting identities, tampering,
immutable rows and preservation of accounting and reports. These tests do not
prove power-loss durability, worker provenance or live recovery.

Version 5 adds immutable verification intent below. Next: trusted runtime
provenance, accepted-result lifecycle rules, recovery decisions and controller fencing.

## Durable verification intent (version 5, issue #44)

`record_verification_intent(event_id, request)` commits a stable expected request
identity before new evidence can enter the ledger. Its exact request fields are
`attempt_id`, `expected_revision`, `artifact_binding_sha256` and
`verification_request_id`. The attempt must still be preparing at the revision
pinned by its immutable artifact binding. Artifact bytes are revalidated.

The immutable envelope has schema version 1, kind `offline_verification_intent`,
event ID, request and `intent_sha256`. SQL foreign keys bind each intent to its
artifact event and accounting attempt/revision. Attempt, artifact event and
verification request identities are unique. Exact retries return the same
validated record, including after evidence admission or accounting settlement.
Conflicting event/attempt/request identities persist a stop and preserve the
original record. Existing integrity stops block new intents.

New `record_evidence` calls require the additional `verification_intent_sha256`
field. Their bindings use schema version 2, while report and evidence-file schemas
remain unchanged. Before admitting evidence, the store loads the independently
persisted intent and compares its digest and all four request fields. Read/reopen,
budget and new-preparation checks validate intents as well as artifacts/evidence.
No timestamps are used to infer ordering: the intent must already exist when the
separate evidence transaction runs. The SQLite process lock serializes callers.

Migration from v1-v4 is explicit and preserves old rows byte-for-byte. V4 evidence
is validated before migration; missing/corrupt evidence blocks it. Historical
schema-v1 evidence stays readable and exact retries remain no-ops, but no intent
is fabricated. A new intent cannot reuse an already evidenced attempt or request,
and readers reject a legacy evidence/intent collision. Fresh schema-v1 evidence
cannot be inserted through the v5 API. Old v4 clients must add the intent call and
hash field before writing new evidence.

These are **offline expectations, not authenticated execution provenance**. A
caller could already possess a report before committing intent; the store only
proves ordering of its own admitted records. It does not launch a verifier, store
credentials, acquire execution approval, prove worker termination, complete an
attempt or release a reservation. Restarts retain intent but do not resend any
request. Live provenance, controller generations, recovery decisions and accepted
results remain separate work.

Tests cover missing/mismatched/stale/retrospective intent, immutable rows,
conflicting IDs, missing artifacts, projection tampering, v4 legacy preservation,
SQL insert/commit and migration failures, and process death immediately before or
after intent/migration commit. Existing v1-v3 migration and evidence durability
regressions remain required. These tests prove process-crash behavior, not
power-loss durability or real verifier authentication.


## Durable controller generations and write fencing (version 6, issue #53)

Every successful `PlanStore` open allocates a store-local positive integer
`controller_generation`, including opens used only for reads. The process first
acquires the existing nonblocking exclusive flock, checks the exact schema,
validates all old records and object references, and requires SQLite FULL sync.
An independent `BEGIN IMMEDIATE` transaction then appends the next
`(generation, process_id)` to immutable `controller_generations`. The accessor
publishes that value only after its commit returns. PID identifies process
ownership of this handle; generation distinguishes successive controllers even
when the operating system reuses a PID.

The complete generation history must start at 1 and remain contiguous, with
integer positive PIDs. Corrupt history rejects reopening and writes; it is never
repaired automatically. SQLite INTEGER exhaustion rejects allocation rather
than wrapping. SQL triggers reject update/delete of this history. As with the
rest of the ledger, these checks protect cooperating controller code, not a
privileged owner editing both records and schema.

A crash before allocation commit leaves no allocated value and publishes no
handle. A crash after commit consumes that generation even if the process never
receives the acknowledgement or returns from open. Reopening allocates the next
value; a committed generation is never reused in that ledger. Creating/migrating
the schema and allocating ownership are separate transactions. A schema-only v6
store left by a crash has no allocated generations and safely starts at 1 when
next opened. These are local process-crash guarantees, not power-loss proof or
protection against restoring an older backup, cloning a ledger, replacing its
files, or bypassing the API. An offline copy is not external execution authority.

`store.controller_generation` is a read-only property for trusted runtime
integration. It validates the history and matches the tip against the open
handle's generation and process. It rejects a closed, fork-inherited or
superseded handle. Never carry an open `PlanStore` across `fork`; the child must
create its own controller after acquiring ownership. Do not manually release,
replace or share the flock or ledger while the handle is open.

Every write API (`import_campaign`, `record_accounting`, `record_artifact`,
`record_verification_intent`, `record_evidence`) enters the same fenced
`BEGIN IMMEDIATE` transaction. The process and generation check runs before any
SQL mutation, persistent integrity-stop insertion, exact-retry return, artifact
publication or evidence durability reconciliation. Holding the SQLite write
lock through commit/rollback prevents a successor from allocating between the
check and effects. A superseded handle fails with no new records or file effects,
even if its original flock was accidentally released. A valid old read snapshot
is not a write capability.

Exact canonical event/request retries remain deliberate no-ops within the current
generation and after a new controller reopens the ledger. The new owner validates
the original records and referenced files before returning the original result;
it does not rewrite them or fabricate their provenance. Conflicting identity
reuse by the current owner still durably records the existing integrity stop.
Both exact and conflicting retries through a stale or fork-inherited handle fail
at the fence; stale callbacks cannot insert stops in a successor's ledger.
Generations do not replace expected attempt revisions or authorize resubmission.

The reviewed offline [backup tool](BACKUP.md) explicitly supports v6. Creating a
backup takes ownership and appends one source generation, then snapshots that
complete history coherently. Package verification and restoration validate only
private scratch database copies; frozen/restored bytes and history remain exact
until the restored store is deliberately opened. Rehashed generation corruption
still rejects the package. Store v7 replaces this with v7-only backups whose
restores carry a durable restore fence; see the version 7 section below.

Upgrade existing v5 stores only with `PlanStore(directory, migrate=True, ...)`,
providing their artifact/evidence directories. Before adding the generation table
and triggers or changing the version, migration validates plans, accounting,
artifacts, verification intents and evidence under the original v5 schema. The
schema addition and version bump commit atomically; all historical rows and
canonical JSON bytes remain unchanged. Existing v1-v4 migrations retain the same
explicit gate and validate their corresponding historical contracts. Migration
never fabricates controller ownership for historical events.

`tests/test_controller_generations.py` covers reopen, immutable history,
corruption, lock contention, real forked handles, every writer's insertion,
retry/conflict paths after simulated lock loss, cross-generation idempotency,
SQL rollback and abrupt process death before/after allocation and migration
commit. Existing v1-v4 migration and import/accounting/artifact/evidence/intent
crash tests remain required; their record-transaction fault injection starts
after ownership allocation. Runtime recovery, authenticated result acceptance
and external execution remain separate work and gates.

## Runtime attempt lifecycle, admission and restore fences (version 7, issue #62)

Store v7 records runtime attempts in the same `attempts`/`attempt_events` ledger
as offline accounting, marked `"mode": "runtime"`. A single attempt history may
not mix modes; replay rejects it. Offline writers (`record_accounting`,
`record_artifact`, `record_verification_intent`, `record_evidence`) reject runtime
attempts, and `record_runtime` rejects offline ones. Every runtime write uses the
v6 fenced `BEGIN IMMEDIATE` transaction, revalidates every attempt and re-reads
every sealed artifact before any effect. Exact event retries return the original
state; conflicting reuse persists the existing integrity stop.

`record_runtime(event_id, request)` applies the pure reducer
`runtime_events.reduce_runtime`:

| Action | From | To | Extra checks |
| --- | --- | --- | --- |
| `prepare` | none | `preparing` | Planned trial and task revision; budget not blocked; full cost hold |
| `dispatch_intent` | `preparing` | `dispatch_pending` | No unreconciled restore fence or integrity stop. Commit **before** any external submission; never submit twice |
| `acknowledge` | `dispatch_pending` | `running` | Same runner request; binds the worker |
| `seal` | `running` | `sealed` | Stop observation hash; artifact bytes re-read and durability reconciled before the reference commits |
| `verify_intent` | `sealed` | `verifying` | Challenge built from `runtime_context`: current controller generation, next revision and artifact binding digest |
| `reconcile` | any active | `reconciling` | Keeps `previous_phase`; `resolve` with an observation hash returns to it |
| `interrupt` | nonterminal | `interrupted` | Bounded reason; hold retained until `settle` |
| `settle` | terminal, unsettled | same | Actual cost and receipt identity |

`record_runtime` cannot complete an attempt. Only `admit_result(event_id,
attempt_id, expected_revision, session, raw)` can: it rebuilds the expected
`VerificationContext` from validated state, requires the live `VerifierSession`
to hold the exact committed challenge, authenticates the raw envelope and commits
the immutable `runtime_results` row, admit event and new attempt state together.
Complete coverage completes the attempt with its pass or fail outcome; partial
coverage interrupts it as `incomplete_verification` and keeps the hold. The
signed envelope is stored inline (base64) with its public observation; the nonce
never is. Admission after a controller restart is impossible because the session
and nonce do not survive it, so the attempt stays `verifying` for reconciliation.

`backup.restore_backup` now inserts one `restore_fences` row into the restored
ledger before writing `restore.json`. While any fence lacks a
`restore_reconciliations` row, `budget_snapshot` reports `restore_fenced` and
`blocked`, preparation is refused and `dispatch_intent` is refused.
`reconcile_restore(event_id, fence_id, statement)` clears a fence only after every
restored nonterminal runtime attempt has been moved to `reconciling`; the bounded
statement records how the operator established that no unrecorded external work
remains. Clearing a fence does not resume an attempt. The three new tables are
append-only under SQL triggers and validated on open.

`recovery_state(attempt_id)` projects one fully validated runtime attempt onto
`recovery.RecoveryState` for `recovery_decision`. Its generation is the current
inspecting controller. Integrity failures raise instead of returning
`integrity_ok=False`. Advice remains advice: no transition, dispatch or
resubmission follows from it.

Upgrade v6 stores only with `migrate=True`; migration validates the complete v6
records and generation history first, then adds the tables atomically without
changing historical bytes. `tests/test_runtime_events.py`,
`tests/test_runtime_store.py` and `tests/test_runtime_admission.py` cover every
transition, exact retry and conflict across reopen, superseded handles, fences,
stale challenges, tampered artifacts and envelopes, incomplete coverage, mixed
histories, migration and the recovery projection, including a lost acknowledgement
that never yields resubmission. These are local process-level guarantees; no live
runner, provider receipt or power-loss behavior is proven.

## Scope and invariants

One local controller process, one active attempt, one controller-owned SQLite
file and a separate content-addressed object directory. The first implementation
is an offline ledger tested with synthetic inputs. No provider calls, execution
CLI, automatic retry, scheduler service or new Harbor integration in that slice.

1. Import the entire deterministic plan atomically. Every scheduled logical trial
   remains in the denominator, including trials never started or never verified.
2. Persist intent and reserve the maximum cost **before** an external side effect.
   A database transaction cannot make a provider request atomic.
3. A lost connection, expired lease or missing worker is not proof that a request
   was never accepted, completed or billed. Unknown dispatch means reconciliation,
   not another submission.
4. No completed record without durable, validated evidence and exact input
   identities. Hashes establish byte identity, not trustworthy execution.
5. Trials, attempts, events, reservations and evidence have separate identities.
   A retry never deletes a failed attempt or creates an extra logical trial.
6. Fail closed on corrupt evidence, unknown database versions, unresolved workers,
   uncertain costs or broken storage. Preserve observations and stop dispatch.

## Records and transaction boundaries

Store schema version 5 is separate from the existing campaign version. The wider
record set below is the target contract, not the complete implemented schema.
All write APIs reject unknown fields and incompatible versions. JSON is bounded,
finite, canonical and rejects duplicate keys, using existing contract conventions.
The frozen campaign and plan identities remain those produced by `contracts.plan`.

| Record | Required content and constraints |
| --- | --- |
| Campaign | Campaign ID, canonical campaign and plan, schema/scoring versions, scheduled count; immutable after import |
| Controller ownership | Store-local monotonically increasing generation, incremented under the process lock at startup; callbacks must match current generation and expected attempt revision |
| Logical trial | Existing trial ID and immutable task/family/split/condition/repetition; current attempt and optimistic revision; unique in campaign |
| Attempt | Trial ID, monotonically increasing attempt number, unique attempt ID, candidate/task/verifier/configuration hashes, phase, explicit reason, deadlines, controller generation, runner request ID and observed worker ID (nullable until acknowledged) |
| Event | Immutable event ID, attempt/trial IDs, per-trial sequence, UTC timestamp, old/new phase, reason code, bounded sanitized payload and provenance; unique event ID and sequence |
| Reservation | Unique attempt-linked reservation, upper bound in integer USD cents, pricing/limit provenance, settlement status, nullable actual cost; one reservation per attempt |
| Evidence reference | Object kind, content digest, byte length, schema/protocol, artifact and verifier identities, attempt ID and acceptance provenance; immutable |
| Result | Attempt ID, completion reason, independent functionality/security/coverage outcomes, required check IDs and outcomes, evidence references, nullable usage/cost; no candidate-supplied authoritative pass |

Use foreign keys and uniqueness constraints, not caller discipline alone. Event
insertion, materialized phase/revision update and any associated reservation
change commit in **one** transaction. A stale expected revision fails without
partial effects. Repeated event IDs with identical canonical payloads are a
no-op; reuse with different content is an integrity error. Timestamps are
observations, not ordering authority; sequence numbers order events.

The ledger prevents UPDATE/DELETE of event rows through its API and database
triggers. This is auditability against application mistakes, not protection
against a controller owner editing the database. Materialized state must agree
with the event chain on recovery. A mismatch blocks dispatch; never silently
repair it by accepting whichever representation looks newer.

Initial storage uses local POSIX files, SQLite rollback journaling with
`synchronous=FULL` and foreign keys enabled/checked on each connection. No
network filesystem, distributed writers or weakened sync configuration. Maintain
a process-lifetime exclusive OS lock on the store before startup reconciliation;
a second controller refuses to run. Database revisions additionally fence stale
callbacks. An expiring database lease alone is insufficient fencing. Future
remote workers must acknowledge stable request identities; process death does
not terminate them by assumption.

## Attempt transitions

The existing architecture's lifecycle is refined with durable dispatch intent
and an explicit unresolved phase. These are proposed runtime states, not new
values in the existing offline planner. Initial attempt creation, reservation
and `planned -> preparing` commit together. Preflight failure may leave a trial
planned with a reason event; it cannot remove that trial from accounting.

| From | To | Required evidence / atomic action |
| --- | --- | --- |
| planned | preparing | Frozen identities resolved, finite resource/cost bounds, available budget and no unresolved active attempt; reserve maximum and assign attempt identity |
| preparing | dispatch_pending | Record exact runner request identity, configuration hash and deadline before external submission |
| dispatch_pending | running | Trusted acknowledgement binds the same request and observed worker; no second submission to obtain an acknowledgement |
| running | sealed | Observed worker stopped; trusted collection accepted; exact artifact durably published and validated; save reference atomically |
| sealed | verifying | Revalidate bundle; persist verification intent and stable verification request ID before fresh verifier launch |
| verifying | completed | Trusted independent evidence accepted with complete required-check accounting and exact attempt/input bindings; result and event commit together |
| preparing, dispatch_pending, running, sealed, verifying | reconciling | Restart, lost acknowledgement or ambiguous external/storage outcome; retain reservation and phase being reconciled |
| reconciling | previous phase, running, sealed, verifying, completed | Trusted reconciliation establishes the same attempt's state and all destination-state prerequisites; never resubmit generation; record observation and reason |
| preparing, dispatch_pending, running, sealed, verifying, reconciling | interrupted | Definite abandonment/termination, required cleanup observed, explicit failure category; retain partial evidence and cost uncertainty |

`completed` and `interrupted` are terminal for an attempt. A late trusted billing
receipt adds a settlement event; it does not rewrite the scientific result. A
later integrity discovery adds an invalidation event and blocks promotion and
new dispatch without erasing the original record. An unresolved attempt may stay
`reconciling` indefinitely rather than fabricate a terminal success or retry.

`completed` means evaluated with complete coverage, not necessarily passed.
Security or functionality failure is a completed non-success. Verifier crash,
timeout, missing checks, rejected artifact, missing grade and post-agent verifier
setup exceptions are non-success with incomplete evaluation. Retain each known
check outcome; mark absent checks `not_evaluated`, never `pass`. An unsafe
candidate or candidate-induced failure cannot trigger an infrastructure retry.

Retry eligibility is a separate recorded decision under the frozen protocol,
allowed only for proven transient infrastructure failure, with the previous
worker definitively stopped and its bill reconciled, and at most the campaign's
one allowed retry. It creates a new attempt and new reservation for the same
logical trial. The original outcome remains visible. The initial offline ledger
has no retry dispatcher. Repairs also consume declared budget and must be
recorded, not silently masquerade as infrastructure retries.

## Publishing artifacts and evidence

SQLite and the filesystem are not a shared transaction. Use publication before
reference, in this order:

1. Validate a controller-selected allowlist and sealed artifact using the existing
   artifact module. Do not execute candidate bytes in the controller.
2. Publish canonical bytes under a digest-derived, controller-selected relative
   object name with no overwrite. Sync contents and the containing directory
   before acknowledging durability; parent directories must already be durable.
   PR #25 adds this directory-sync boundary to `artifacts.write_new`.
3. Reopen and validate the published object against its expected digest, schema
   and byte count. An existing name is acceptable only after exact validation and
   an explicit durability reconciliation; `FileExistsError` is not success.
4. Commit the object reference and phase/event update together. Only then may a
   caller observe a persisted `sealed` or `completed` record.

The artifact payload hash and raw object-file hash are different identities.
Store both, label them explicitly, and never substitute one for the other.
Evidence uses its own versioned canonical envelope; acceptance must validate
artifact/verifier hashes plus trial/attempt, task revision, protocol and request
provenance. Existing `bind_evidence` alone does not authenticate those extra
runtime identities. The future adapter must establish them before store writes.
Do not accept candidate-written verdicts or recomputed hashes as verifier proof.

A nonce or credential needed for live acceptance never belongs in public Git,
logs, candidate mounts or exported evidence. If crash recovery requires private
verification secrets, an independently reviewed controller-only secret store is
required. Without that capability, interrupted verification stays incomplete;
it cannot be authenticated merely from a saved candidate-visible report.

Readers revalidate referenced objects before verification, reporting a pass or
promotion review. Missing, truncated, mismatched or unexpected-kind objects
produce an integrity fault, invalidate effective acceptance and stop dispatch.
Do not silently reseal new bytes under an old result. Unreferenced objects and
`.artifact-*` names are orphans, not accepted results; no automatic deletion in
the first slice. Future GC requires exclusive ownership and a verified snapshot
of all live references and retained attempts.

## Crash windows and recovery decisions

Startup acquires exclusive ownership, checks store version/integrity and event
consistency, verifies object references, then reconciles every nonterminal
attempt and unsettled reservation before any new work. A clock expiry can trigger
inspection or a stop request; it cannot prove worker death or cost settlement.

| Crash point | What is durable | Recovery action |
| --- | --- | --- |
| During plan import | Entire plan or nothing | Re-import exact plan idempotently; reject conflicting identity/content |
| Before preparation transaction commits | No new attempt/reservation | No external request may have been issued; preparation may be retried |
| After reservation, before dispatch intent | Preparing attempt and held maximum | Verify no dispatch intent, record preparation recovery; no paid request was permitted yet |
| After dispatch intent, before or after send | Request identity, no reliable acknowledgement | Enter reconciling; query trusted runner/provider by that identity; never send again blindly |
| Acknowledged worker still active | Same attempt and worker identity | Observe/reconnect or stop that worker under existing deadline; no new generation |
| Worker absent but request/bill unresolved | Intent and held reservation | Remain reconciling and block dispatch; absence alone cannot release funds |
| After worker stops, before durable sealing | Stop evidence; candidate files may remain | Collect only if trusted stop and original workspace identity can be established; otherwise interrupted, no re-generation |
| After object link, before directory sync | File may or may not survive | Validate expected bytes and complete sync reconciliation, or record unavailable evidence; never overwrite |
| After durable object, before DB reference | Orphan object | Validate against recorded intent; attach only with proven same-attempt provenance, otherwise retain orphan |
| After DB reference | Phase and exact object identities | Revalidate; resume only the same attempt's next permitted phase |
| During verification / lost acknowledgement | Verification intent; partial result possible | Reconcile same verifier request; absent authenticated complete evidence stays incomplete, no automatic re-verification |
| After result transaction, before acknowledgement | Completed result and event | Idempotent lookup returns the same result; no second attempt or duplicate charge |
| During settlement transaction | Old hold or fully reconciled amount | Reconcile idempotently against trusted usage; retain hold until known |

Provider idempotency is an additional defense only when its scope and retention
are proven. A response saying “not found” after an idempotency window has expired
is insufficient evidence of non-execution. If an adapter cannot establish the
outcome, require manual reconciliation and retain the hold. No exactly-once
execution guarantee is claimed across external systems.

## Budget and reporting semantics

Use integer USD cents for conservative reservations to match campaign limits;
round each maximum upward, never down. Store original provider usage and exact
billing units separately so rounding does not masquerade as measurement.
A missing price, unbounded tool/model loop or unenforceable maximum blocks
submission even if a campaign has a positive budget. A zero-budget offline
campaign grants no external execution permission.

`available = approved_limit - settled_charges - unresolved_reservations`.
These sets must not overlap: settlement atomically replaces a reservation with
the trusted charge. Unknown actual cost is null, not zero; its full maximum stays
held even after an attempt is terminal. Initial policy blocks new dispatch while
any cost or external attempt is unresolved. Partial usage reports do not release
a hold. Duplicate settlement with the same receipt is idempotent; conflicting
receipts stop dispatch and require an appended correction with provenance.

A measured charge above its reservation is recorded truthfully and triggers a
campaign stop; never clip the amount to manufacture compliance. Credits and
corrections are explicit ledger events. The initial version may conservatively
retain a charge until a correction is reviewed. External provider hard limits
remain necessary; a local reservation alone cannot enforce a vendor bill.

Reports retain scheduled, started, completed, interrupted and unresolved counts,
coverage, failures, each attempt and retry, known costs, unknown-cost count and
held exposure. Joint success uses all scheduled logical trials as denominator.
Any retry selection rule must be frozen before execution and report both initial
and retry-inclusive outcomes; do not choose the best attempt after seeing results.
No missing evidence, unresolved attempt or integrity-invalidated result qualifies
for promotion. Human promotion review remains required even for valid passes.

## Implementation slices and fault-injection acceptance

Each slice is a separate bounded PR. No empty adapter hierarchy or execution
command is needed to prove these behaviors.

| Slice | Concrete behavior | Required tests / completion evidence |
| --- | --- | --- |
| 1. Offline plan ledger | Versioned SQLite schema, whole-plan import, read-only snapshot, append-only events and expected revisions | Duplicate import preserves count/IDs; conflicting payload rejected; kill before/after commit yields none/all; two processes cannot own the store; SQL event mutation rejected; stale revision rolls back event and state |
| 2. Reservations | Atomic attempt creation, conservative cost hold and idempotent settlement | Competing reservations cannot overspend; fault between event/state/hold rolls back all; unknown cost stays null/held; duplicate receipt does not charge twice; overrun recorded and stops dispatch |
| 3. Object references | Durable publication and validated references | Inject write/link/file-sync/directory-sync/DB-commit failures; never acknowledge partial objects; missing/tampered objects block effective pass; orphan does not imply completion; changed verifier/input hash rejected |
| 4. Recovery reducer | Pure recovery decisions from persisted state and synthetic trusted observations | Every crash-window row above; lost acknowledgement never emits resubmit; expired lease/missing worker retain hold; old controller callback rejected; partial verifier result never completed; replaying recovery is idempotent |
| 5. Runner integration | Stable request identity and trusted query/stop adapter under accepted M2 gates | Model-free reviewed controls first; kill controller around dispatch/ack, verify one worker only; restart never starts a second generation; candidate-caused verifier failure cannot retry |

Slices 1–4 can use synthetic inputs without execution approval. Slice 5 first
requires the contract reviewed, collector integrated, explicit M2 acceptance,
dedicated-worker checks and (for model calls) a finite approved budget. Existing
Harbor acceptance logic is not replaced until these guarantees are demonstrated.

Backup/restore is an additional gate before real campaigns: pause writes and
external work, produce a consistent database snapshot with all referenced
objects, sync the snapshot/manifest and verify a restore in a new directory.
Never copy a live SQLite file alone. A restored store must reconcile external
requests before dispatch because external work may postdate the backup. Files
under ignored `.research/` are not durable backups by themselves.

## Offline evidence objects (issue #40, stacked on #39)

`evidence_objects.publish_evidence(directory, record, binding, request_id)`
returns a version-1 reference with kind `offline_verifier_evidence`, schema
version, raw object SHA-256, encoded byte length and envelope SHA-256. The raw
file and envelope hashes are different identities. Names are digest-derived;
callers cannot select arbitrary file paths.

`read_evidence(directory, reference, binding, request_id)` revalidates bounded
bytes, canonical envelope, hashes and expected context on every read. Supply
the binding from independently revalidated controller state and the expected
request identity, never from the file being checked. A valid envelope does not
prove a verifier ran. These APIs neither check the artifact file themselves nor
update PlanStore, attempt phase, acceptance or budget.

Use an existing durable controller-owned local directory with stable ancestors,
no candidate access and filesystem support for file/directory fsync and hardlinks.
Publication uses a private temporary file, file fsync, atomic no-replace link,
temporary unlink, directory fsync and readback validation. Exact-existing retry
revalidates then syncs both file and directory; corrupt destinations are never
replaced. No reference is returned after a failed barrier.

Process death before linking can leave a temporary orphan; death between linking
and temporary unlink leaves two names for the same inode. The latter is rejected
as multiply linked, including on retry, until explicit operator reconciliation.
Nothing automatically deletes orphan files. Death after unlink can leave a
singly-linked object that exact-byte retry can reconcile. Tests prove these
process-interruption behaviors, not power-loss durability. Errors may leave
objects behind; an object alone is never a committed or accepted result.
