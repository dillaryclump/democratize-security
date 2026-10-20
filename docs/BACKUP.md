# Verified offline backup and restore

`democratize_security.backup` implements the offline backup prerequisite from
[PERSISTENCE.md](PERSISTENCE.md). It supports store **version 7** only. It preserves
the entire SQLite ledger and every referenced sealed artifact and offline evidence
object. It performs no migration, model call, external job, result acceptance or
cost settlement. It does not modify the offline campaign or verifier protocol.

Pause controller writes and external work before taking a backup. Supply existing,
durable, controller-owned local source directories and a **new destination** under
an existing trusted parent. Keep these paths and their ancestors stable. Local
POSIX file locks, exclusive creation and file/directory `fsync` must work; network
filesystems are unsupported. Backups of valuable data belong on separately managed
durable storage. An ignored `.research/` directory alone is not that policy.

```python
from pathlib import Path
from democratize_security.backup import create_backup, restore_backup, verify_backup

manifest = create_backup(
    Path("/trusted/controller/ledger"),
    Path("/trusted/backups/snapshot-001"),  # Must not exist, even if empty.
    objects_directory=Path("/trusted/controller/artifacts"),
    evidence_directory=Path("/trusted/controller/evidence"),
)
assert verify_backup(Path("/trusted/backups/snapshot-001")) == manifest

provenance = restore_backup(
    Path("/trusted/backups/snapshot-001"),
    Path("/trusted/restores/restore-001"),  # Must not exist.
)
assert provenance["execution_enabled"] is False
assert provenance["reconciliation_required"] is True
```

The returned restore contains `ledger/ledger.sqlite3`, `artifacts/`, `evidence/`
and `restore.json`. Open its ledger with `PlanStore`, supplying the restored object
directories. Unknown-cost holds, interruptions, planned trials, immutable events,
verification intent and incomplete/failed reports retain their original meaning.
A saved passing offline report remains an offline observation. The restored
ledger initially retains the snapshot's exact ownership history and database
bytes plus one restore fence; its first successful `PlanStore` open appends the
next local generation. The fence blocks preparation and dispatch until
`PlanStore.reconcile_restore` records an explicit reconciliation.

Version 5 and 6 source ledgers require an explicit `PlanStore(..., migrate=True,
...)` upgrade before a new backup can be created. This version does not silently
migrate or relabel v5/v6 archives and refuses them with these instructions: use
the matching backup implementation to restore the old package, explicitly
migrate that restored ledger, then create and verify a new v7 backup. Keep the
old archive unchanged. Future schemas require separately reviewed semantics.

## Snapshot and validation behavior

`create_backup` acquires the same exclusive `PlanStore` process lock as a controller.
An existing owner causes immediate refusal. Opening validates the exact schema,
SQLite integrity/foreign keys, whole plans, immutable event history, attempt
projections, artifact bindings, intent, evidence bindings and referenced bytes.
It also validates the complete generation history and durably appends a new
controller generation to the source ledger before creating the snapshot. That
allocation remains consumed if the later backup fails. The snapshot contains
the source's complete history through that allocation; no historical row changes.
The SQLite backup API then takes a coherent snapshot of that connection while
ownership remains held. It never copies a live database file in place of that API.

The destination has private `0700` directories and `0600` files. It contains only
the database and ledger-referenced artifact/evidence files. Source lock files,
orphans, temporary files and unrelated files are excluded. It does not inspect
referenced payloads for secrets; those remain subject to the repository's
synthetic-data and no-secrets rules. Artifact
and evidence source directories may coincide. Every file has an inventory entry
with its exact relative path, byte length and SHA-256 digest. Object payload and
raw-file identities are still independently checked by their existing validators.

Before acknowledgement, the implementation validates a copy of the snapshot
database in a fresh scratch directory against the copied objects, syncs every
copied file and directory, and writes/syncs a canonical manifest last. It then
verifies the complete package again. The manifest binds the complete inventory,
campaign IDs, store version and offline/reconciliation status. Verification
rejects unknown fields, duplicate/noncanonical JSON, wrong types, traversal,
unexpected files, missing files, symlinks, hardlinks, special files and corrupt
bytes. Recomputing a manifest's hashes cannot bypass schema, event-chain, binding
or reference validation. These checks detect inconsistency; a controller owner
able to rewrite both ledger and objects is outside this integrity boundary.

`verify_backup` does not open the frozen snapshot's database as a writable store.
It validates a private database copy, and rechecks the package files afterward.
This leaves the snapshot byte-identical while the store allocates a temporary controller
generation in the disposable scratch database. Repeated validation never appends
to the frozen snapshot or restored database. `restore_backup` validates the package
before creating its destination, copies its exact inventoried bytes, revalidates
the restored ledger/references, and syncs the new files and directories before
returning provenance bound to the manifest digest.

## Failures, limits and runtime boundary

Every destination must be absent. Existing files, directories, symlinks and
partially completed operations are refused without replacement. A failure or
process death can leave an incomplete new directory; nothing automatically
deletes it or treats it as a successful operation. A backup missing its manifest
cannot verify. A process killed after manifest publication may leave a package
whose bytes verify, although the interrupted caller never received an
acknowledgement. This is not power-loss durability evidence.

The implementation bounds each database at 512 MiB, each manifest at 16 MiB and
the inventory at 100,001 files. Existing artifact/evidence limits remain 12 MiB
and 64 KiB per file. Validation scratch space needs one database copy. Storage
capacity, retention, encryption and off-device replication remain operator policy;
the tool does not provision or upload storage.

Restoration never proves external work stopped or that provider bills are known.
Generation monotonicity applies to one unchanged ledger lineage. Copying an older
snapshot preserves that history, but its subsequent local allocations cannot fence
a separate live source or jobs started after the snapshot. Therefore every
restore inserts a durable fence (`restore-<manifest digest>`, also recorded as
`restore_fence_id` in `restore.json`) before acknowledging. Runtime preparation
and dispatch stay blocked until the operator moves each restored nonterminal
runtime attempt to `reconciling` and calls `reconcile_restore` with a statement
of how external requests and bills were checked. The fence is not proof that
work stopped. Admitted runtime results and their signed envelopes are database
rows and are carried by the snapshot; verifier nonces are never stored. New
store versions are refused until they have explicit backup coverage.

## Evidence

`tests/test_backup.py` covers verified round trips, exact ledger/object retention,
unknown-cost accounting, concurrent process ownership, special files, corrupted
source objects, rehashed database corruption, incomplete inventories, bounded
canonical manifests, no-overwrite behavior, write/sync faults and abrupt process
death around publication. V6 regressions assert source/snapshot/restore ownership
rows exactly, unchanged frozen database bytes after repeated scratch validation,
source and rehashed snapshot generation-history corruption, explicit v5 rejection
and successful backup after deliberate source migration. V7 regressions assert
the restored fence, that it blocks the budget and dispatch until reconciled,
that it survives reopen, and that v5/v6 packages are refused with instructions. Run the full required
repository checks as well; PostgreSQL and Docker integration require their
configured disposable services.
