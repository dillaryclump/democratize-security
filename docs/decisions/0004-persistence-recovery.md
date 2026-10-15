# ADR 0004: Durable intent and conservative crash recovery

Status: proposed for review, 2026-10-15, issue #21. No runtime implementation or
owner acceptance is implied. See [persistence contract](../PERSISTENCE.md).

## Problem

A controller can die after a provider accepts a request but before it records
acknowledgement. Retrying automatically can duplicate paid work. Separately,
artifact bytes and SQLite references cannot commit atomically; a saved result
must not pass if its underlying evidence is absent or corrupt.

## Decision

Use one local controller with exclusive process ownership, SQLite transactions
and append-only events, plus separately published content-addressed objects.
Persist bounded budget reservation and stable dispatch intent before side
effects. Distinguish logical trials from attempts and completed evaluations from
successful evaluations. Introduce `dispatch_pending` and `reconciling` runtime
phases. Unknown outcomes retain their cost hold and block dispatch.

Publish and sync objects before committing references; revalidate referenced
bytes at recovery and before effective acceptance. Retain orphans and failed
attempts. Recovery queries the same external request and never infers that a
lost connection, missing worker or expired lease authorizes another submission.
No exactly-once provider guarantee is claimed.

Implement offline import/events, reservations, object references and recovery
rules as separate tested slices before a runner adapter. Keep existing campaign
and scoring schemas unchanged. A fresh protocol decision is needed if retry
selection or scoring semantics change.

## Alternatives and consequences

A mutable JSON status file cannot atomically update trial state, event and budget.
A queue or distributed service adds failure boundaries without a current need.
SQLite alone cannot commit a remote request or guarantee artifact durability.
An automatic retry on timeout risks duplicate charges and biased measurements.

The chosen design favors retained ambiguity over silent duplication. This may
require manual reconciliation and halt a campaign even when budget remains.
Local controller ownership and trustworthy filesystem sync are explicit
assumptions; multi-host writers need a later design. Hashes do not authenticate
candidate reports. Protected evaluation, secret storage, backup/restore and
provider integration remain separate gates.

## Review and implementation gates

Review the transition table, crash windows, terminal/coverage semantics and budget
rules in PERSISTENCE.md. Slice 1 is an offline, synthetic-input SQLite ledger;
no provider or runner calls. Live integration follows M2 acceptance, a dedicated
worker and any required finite execution budget.
