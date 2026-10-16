# Current status and next handoff

Snapshot: 2026-10-16 UTC. Integration #33 is merged on main at `d6c2657`,
including collector #17, container-storage #31 and the offline persistence stack.
Artifact object publication #35 is merged at `dd7fe70`. Branch
`milestone/artifact-bindings` adds immutable artifact references (#36), not yet
merged into main.
Check live [issues](https://github.com/dillaryclump/democratize-security/issues)
and [PRs](https://github.com/dillaryclump/democratize-security/pulls) before editing.
See [COORDINATION.md](COORDINATION.md) for claims and handoffs.

## Runner and verifier already on main

- Offline campaign validation/planning; execution remains disabled.
- Synthetic FastAPI invoice reads, list/search/pagination and CSV with restricted
  PostgreSQL RLS and server-owned fixture identities.
- Independent public HTTP/database verifier, protocol `synthetic-reference-v3`;
  complete accounting of eight required checks and deliberate unsafe controls.
- Harbor 0.24.0 policy controls and three application tasks with separate candidate
  containers, nonce-bound evidence, trusted submission collection and fresh replay.
- Host acceptance rejects forced unfiltered `/logs/artifacts` fallback copies.
- Audit v5 checks bounded container storage, including submission volumes, tmpfs,
  shared memory and logs. Each application task has twelve reviewed control/replay
  trials. See [APPLICATION_TASKS.md](APPLICATION_TASKS.md) and
  [HARBOR_AUDIT.md](HARBOR_AUDIT.md) for exact boundaries and remaining gaps.

## Additions merged through #33

| Source | Capability | Limits |
| --- | --- | --- |
| #22 | Agent ownership/coordination guidance and current-vs-historical status | Claims are advisory; check live remote heads |
| #23 | ID-derived tenant and deny-all read regression controls | Reviewed synthetic mutations, not arbitrary submissions |
| #25 | Directory fsync before acknowledging artifact publication | Requires trusted durable parent and a filesystem honoring fsync |
| #26 | Proposed persistence/recovery contract and ADR 0004 | Proposed live semantics are not owner-approved |
| #28 | SQLite plan import, immutable import events and validated snapshots | Offline; preserves every scheduled trial |
| #30, including `4097c252` | Store v2 synthetic attempt/reservation/settlement accounting, explicit migration and crash tests | No execution, successful evaluation, receipt authentication or live recovery |

The source commits remain ancestors of this branch. Runner implementation and
its tests from main are preserved without edits. Source PRs are merged or closed with their integration disposition; their branches
are preserved. #28/#30 were closed after their commits reached main via #33.

## Evidence and validation

| Revision / scope | Evidence |
| --- | --- |
| Collector final code `e546181` | [CI 38795922164](https://github.com/dillaryclump/democratize-security/actions/runs/38795922164), all jobs passed; merged via #17 |
| Storage final code `5c49232` | [CI 38843803069](https://github.com/dillaryclump/democratize-security/actions/runs/38843803069), all jobs passed; merged via #31 |
| Regression #23 `04a63d4` | [CI 38755674294](https://github.com/dillaryclump/democratize-security/actions/runs/38755674294), all jobs passed |
| Artifact #25 `1794158` | [CI 38768016554](https://github.com/dillaryclump/democratize-security/actions/runs/38768016554), all jobs passed |
| Plan ledger #28 `59fb55f` | [CI 38769458396](https://github.com/dillaryclump/democratize-security/actions/runs/38769458396), all jobs passed |
| Accounting #30 `4097c252` | [CI 38844962355](https://github.com/dillaryclump/democratize-security/actions/runs/38844962355), all jobs passed, including the three later regression tests |

All eight combined CI jobs passed in [run 38847000439](https://github.com/dillaryclump/democratize-security/actions/runs/38847000439)
at #33 head `4197e0d`, including PostgreSQL and all Harbor tasks.
Combined integration local validation on Python 3.12:
391 passed, 32 skipped (PostgreSQL and Docker prerequisites unavailable); Ruff
check/format and package build passed. The skips are not passing integration
evidence. Combined CI results are recorded in the integration PR/issue #32. Historical
failures, fixes and source-branch handoffs remain in
[STATUS_HISTORY.md](STATUS_HISTORY.md). Green CI does not imply owner acceptance.

Artifact-object slice #34 local validation: 25 focused tests passed; complete
suite 416 passed, 32 infrastructure skips. Ruff check/format and package build
passed. All eight jobs passed in [CI 38913561509](https://github.com/dillaryclump/democratize-security/actions/runs/38913561509)
at #35 head `3bbfb82`; #35 is merged.

Artifact-binding slice #36 local validation: 25 new focused tests passed,
including binding/migration process crashes and SQL/sync failures. Full suite:
441 passed, 32 infrastructure skips; Ruff check/format and package build passed.
Its separate PR records CI for this new revision.

## Next bounded work and gates

1. Review immutable artifact binding (#36): explicit store v3 migration, exact
   attempt/task identity, pinned synthetic verifier intent and object revalidation
   at reopen/read/new preparation. This adds no accepted result or execution.
   Keep M2 owner acceptance in #19 separate.
2. Implement verifier-result evidence with complete check accounting and trusted
   runtime provenance. Then implement the
   recovery reducer and controller-generation fencing using synthetic observations.
3. Before runner integration, review the persistence contract and prove the above
   crash windows. Before model execution, obtain M0/M2 owner acceptance, a
   dedicated bounded worker environment and an explicitly approved finite budget.

Remaining observed runner gaps are `agent_can_write_verifier_log_directory`,
`verifier_storage_unbounded` and `trial_storage_unbounded`. Container limits do
not bound the host job directory; a dedicated host must provide a separate bounded
filesystem per trial. No privileged mounting is performed by repository scripts.
The public fixtures are not a protected holdout; all containers share a host kernel.

M3 is partial: offline plans, synthetic accounting and artifact bindings persist
on this branch. No durable
accepted-result/evidence registry, full recovery engine, production dispatcher,
protected final evaluator, paid pilot, demonstrated benchmark gain or GEPA search
exists. Production identity, license, branch protection and vulnerability-reporting
setup remain owner decisions.

## Handoff maintenance

Keep this file a current summary. Preserve superseded evidence in the history
file, with its revision. Use [HANDOFF_TEMPLATE.md](HANDOFF_TEMPLATE.md), record
claims in issues and verify current main before each new implementation slice.
