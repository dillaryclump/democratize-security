# Persistence and crash recovery contract

Status: proposed design for M3, issue #21; **only offline plan import is implemented
on this branch**, as described below. The recovery engine remains unimplemented. Based on main
`1124a0c`. ADR [0004](decisions/0004-persistence-recovery.md) records the choice.
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
refuse to open; there is no migration. Plans are limited to 16 MiB canonical JSON.

This first schema intentionally has only campaigns, immutable planned trials
and import events at sequence zero. It has no controller generation, attempt
state transitions, general event append API, reservations, evidence references,
result acceptance, recovery dispatcher, backup tool or CLI. Those additions
require an explicit store-version migration and further tests; the wider tables
and transitions below remain proposals. A complete plan snapshot is not a
successful experiment or an execution authorization. The lock/SQL triggers protect
cooperating code, not an owner editing files. No sensitive final cases belong here.

Tests kill a subprocess with `os._exit` immediately before or after import commit,
reopen the store and require none/all of the scheduled records. Other tests inject
a mid-import SQL failure, hold the lock from another process, corrupt stored
rows/schema, reject writes to immutable records, reopen and re-import plans, and
check byte limits. These prove local process-crash behavior, not power-loss
durability or live provider recovery.

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

Proposed store schema version 1 is separate from the existing campaign version.
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
