# ADR 0006: Durable local controller generations and fenced writes

Status: implemented for review in issue #53, 2026-10-17. This does not enable
execution. See [persistence contract](../PERSISTENCE.md).

## Problem

The lifetime flock prevents ordinary concurrent controllers, but accidental lock
loss can leave an old callback holding a still-open SQLite connection. Attempt
revisions alone cannot fence plan import, exact retries, artifact publication or
persistent conflict stops. A process inherited through `fork` also shares handles
without becoming a new controller owner.

## Decision

Store v6 appends positive contiguous `(generation, process_id)` rows under the
exclusive flock in a separate SQLite `BEGIN IMMEDIATE` / FULL-sync transaction
at every successful open. No generation is published until commit succeeds.
Once committed, allocation survives process death and failed acknowledgement;
the next controller consumes a strictly larger value. Uncommitted speculative
values are not allocated or exposed. Schema-only v6 stores from a crash can
allocate their first generation safely. Migration requires `migrate=True`,
validates old v5 records and object references first, and preserves their bytes.

Every writer acquires the SQLite write lock and checks its PID and durable
current generation before any effect, including retry returns, conflict stops
and object durability sync. The write lock remains held until commit or rollback.
An accessor exposes validated current ownership to later trusted integration.
An inherited handle cannot read or write through the normal connection API.
An older handle cannot write even after a newer controller has closed.

The current owner may retry an exact historical canonical request across
controller generations. Revalidating and returning its unchanged record does not
claim its execution provenance. Changed identity reuse retains the existing
integrity-stop behavior. A stale owner cannot even insert a conflict stop.

## Consequences and limits

Ownership allocation is append-only audit history and a versioned schema change.
Opening a store for validation also allocates a generation; offline backup tools
must account for that and never imply copied generations authorize resumption.
Generation identifiers are local to an unchanged ledger lineage. Copying,
restoring older backups, editing files as owner or using another filesystem can
break that lineage; no distributed fencing or rollback resistance is claimed.
The PID guard supplements generation matching and is not an external identity.

Keep the flock for the full handle lifetime. Do not manually unlock, unlink,
replace or share the live files, or reuse a handle after `fork`. Process-crash
and SQL-fault tests establish all-or-none local records and durable allocation;
they cannot prove storage-device power-loss behavior. Runtime callbacks still
need their own expected generation/revision checks and authenticated request
context. Recovery integration, accepted results, external cleanup and billing
remain separately reviewed work. No model or worker execution is authorized.
