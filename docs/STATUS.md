# Current status and next handoff

Snapshot: 2026-10-16 UTC. Integration #33 is merged on main at `d6c2657`,
including collector #17, container-storage #31 and the offline persistence stack.
Artifact object publication #35 is merged at `dd7fe70`.
Immutable artifact references #37 are merged at `0791d47`.
Branch `milestone/verifier-evidence-contract` adds report validation and canonical
evidence envelopes (#38, PR #39); this new contract is not yet merged.
Stacked branch `milestone/evidence-objects` adds durable offline evidence object
publication/read/reconciliation (#40), also not yet merged. No ledger linkage or
trusted runtime provenance is added by #40.
Stacked branch `milestone/evidence-ledger` adds explicit store v4 migration and
immutable offline evidence linkage (#42), not yet merged. Runtime provenance
and accepted/completed-result semantics remain unimplemented.
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
All eight jobs passed in [CI 38915505866](https://github.com/dillaryclump/democratize-security/actions/runs/38915505866)
at #37 head `5b31696`; #37 is merged.

Evidence contract #38 local validation: 39 focused tests, including parity for
all 6,561 check-outcome combinations; full suite 480 passed, 32 infrastructure
skips. Ruff check/format and build passed; core imports also passed without site
packages. All CI passed in [run 38916744794](https://github.com/dillaryclump/democratize-security/actions/runs/38916744794)
at #39 head `bc58fd2`; #39 remains in review.

## Next bounded work and gates

1. Keep M2 owner acceptance in #19 separate from the merged implementation.
2. Review the offline [evidence contract](EVIDENCE.md) (#38): strict report/check
   accounting, unchanged v3 scoring, and binding/request identity checks. No result
   authentication is added. Review stacked offline object storage (#41) and
   ledger linkage (#42), then implement trusted runtime provenance/verification
   intent, accepted-result lifecycle rules and the recovery reducer with
   controller-generation fencing using synthetic observations.
3. Before runner integration, review the persistence contract and prove the above
   crash windows. Before model execution, obtain M0/M2 owner acceptance, a
   dedicated bounded worker environment and an explicitly approved finite budget.

Remaining observed runner gaps are `agent_can_write_verifier_log_directory`,
`verifier_storage_unbounded` and `trial_storage_unbounded`. Container limits do
not bound the host job directory; a dedicated host must provide a separate bounded
filesystem per trial. No privileged mounting is performed by repository scripts.
The public fixtures are not a protected holdout; all containers share a host kernel.

M3 is partial: offline plans, synthetic accounting, artifact bindings and offline
evidence linkage persist on this branch. No authenticated accepted-result
registry, full recovery engine, production dispatcher,
protected final evaluator, paid pilot, demonstrated benchmark gain or GEPA search
exists. Production identity, license, branch protection and vulnerability-reporting
setup remain owner decisions.

## Handoff maintenance

Keep this file a current summary. Preserve superseded evidence in the history
file, with its revision. Use [HANDOFF_TEMPLATE.md](HANDOFF_TEMPLATE.md), record
claims in issues and verify current main before each new implementation slice.

## Evidence object handoff (#40)

`evidence_objects.publish_evidence` durably publishes canonical bounded envelopes
without replacement; `read_evidence` revalidates raw and envelope identities plus
independently supplied binding/request context. Existing exact objects require
file and directory sync reconciliation. Missing, corrupt, noncanonical, symlink,
hardlink and special-file objects fail closed. This is offline storage, not
authenticated verifier execution, accepted results or promotion.

Tests include process death after file sync, link and before/after directory
sync. Death after linking but before removing the temporary name leaves a
multiply-linked orphan which deliberately blocks reuse pending explicit operator
reconciliation. No automatic cleanup, ledger migration or runner changes.

Local validation: 30 focused tests passed; full suite 482 passed and 54 skipped
(optional dependencies, PostgreSQL and Docker prerequisites unavailable). Locked
sync, Ruff check/format, package build and diff whitespace checks passed. Skips
are not integration evidence. All eight jobs passed in
[CI 38954132208](https://github.com/dillaryclump/democratize-security/actions/runs/38954132208)
at #41 head `cb42757`; #41 remains in review.

Next: review #39, #41 and offline ledger linkage (#42), then implement a trusted
runtime provenance boundary and recovery/controller fencing. Owner acceptance remains separate in #19.

## Offline evidence ledger handoff (#42)

Store v4 adds immutable reference/events, unique per attempt and verification
request. Reopen/read/budget/new-preparation checks revalidate both artifact and
evidence bytes against ledger-selected identities. Exact retry is a no-op;
conflicting event/attempt/request identities persist a stop. Neither complete
passes nor partial/failed reports change accounting, phase or acceptance.
V1-v3 require explicit migration; existing records are preserved. A synthetic
request ID recorded alongside evidence is not pre-dispatch intent or proof that
any trusted verifier ran.

Focused tests cover reference integrity, immutable/projection checks, conflicting
identities, failure/incomplete preservation, SQL/sync errors and process crashes
around evidence and migration commits. Next: review this offline prerequisite,
then establish trusted runtime provenance, verification intent, accepted-result
semantics and recovery/controller fencing. #19 remains an owner gate.

Local validation for #42: 39 focused tests passed; full locked suite 521 passed,
54 skipped (optional dependencies/PostgreSQL/Docker unavailable). Locked sync,
Ruff check/format, package build and whitespace checks passed. CI must verify
this new revision; the prerequisite CI above is not evidence for #42.
