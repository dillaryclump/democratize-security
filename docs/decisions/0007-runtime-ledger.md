# ADR 0007: Runtime attempts in the shared ledger with fenced restores

Status: implemented for review in issue #62, 2026-10-20. This does not enable
execution. See [persistence contract](../PERSISTENCE.md).

## Problem

Offline accounting (store v2-v6) cannot express dispatch, acknowledgement,
sealing, verification or admission of an authenticated result. A separate
runtime database would split budget holds and integrity stops across two
ledgers, and a restored backup could silently resume work that postdates it.

## Decision

Store v7 keeps one attempt/event ledger and marks runtime attempts with
`"mode": "runtime"`. A pure reducer (`runtime_events.reduce_runtime`) defines the
transitions; `PlanStore.record_runtime` applies them under the v6 generation fence
after full revalidation. Budget snapshots count runtime and offline holds
together, so a nonterminal or unsettled runtime attempt blocks new preparation.

Completion enters only through `PlanStore.admit_result`, which authenticates the
verifier envelope with the live session and commits the result row, admit event
and attempt state in one transaction. The canonical signed envelope is stored
inline in `runtime_results` rather than as an object file, so a backup carries it
inside the database. Results are append-only and one per attempt.

`restore_backup` writes a durable `restore_fences` row into every restored ledger.
Dispatch and preparation stay blocked until `reconcile_restore` records an explicit
statement, and only after each restored nonterminal runtime attempt is
`reconciling`. Backups support exactly store v7; v5/v6 packages are refused with
instructions to restore with their matching tool and migrate.

## Consequences and limits

The verifier nonce is memory-only, so a controller restart between verify intent
and admission leaves the attempt `verifying`; recovery advice is
`reconcile_verifier`, never automatic resubmission. Fences are local to a ledger
lineage and protect cooperating code; an owner editing files can bypass them.
No runner, worker, provider or billing integration exists; settlement amounts are
still caller-supplied. Model execution remains gated on an approved finite budget.
