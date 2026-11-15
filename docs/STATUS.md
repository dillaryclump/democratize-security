# Current status and next handoff

Updated: 2026-11-15 UTC. This page describes main at `c05e58d` plus the release-readiness change in [#80](https://github.com/dillaryclump/democratize-security/issues/80), which adds documentation, the license and package metadata and changes no code. The previous page is archived verbatim in [STATUS_HISTORY.md](STATUS_HISTORY.md).

Check live [issues](https://github.com/dillaryclump/democratize-security/issues) and [PRs](https://github.com/dillaryclump/democratize-security/pulls) before claiming work. [COORDINATION.md](COORDINATION.md) defines the ownership convention.

## Where the project stands

| Gate ([ROADMAP.md](ROADMAP.md)) | State | Evidence |
| --- | --- | --- |
| Foundation | Done | Offline contracts, planner and CLI |
| M0 Contract | Accepted for the synthetic scope | Owner review 2026-10-17, recorded in #19. Production identity is unresolved |
| M1 Verifier | Done | [REFERENCE.md](REFERENCE.md), CI job `postgres-reference` |
| M2 Runner | Done, owner-accepted 2026-10-20 | #19, [APPLICATION_TASKS.md](APPLICATION_TASKS.md), [WORKER_HOST.md](WORKER_HOST.md) |
| M3 Persistence | Partial | Store v8 is built and used by the live runs. Recovery after a crash is still manual |
| M4 Pilot | Built and started, **incomplete** | 20 of 48 trials graded, 1 interrupted, 27 not run. [RESULTS.md](RESULTS.md) |
| M5 Search, M6 Confirmation, M7 Product pilot | Not started | |

**No benefit of the security integration has been demonstrated.** Every graded pilot trial passed every check in all four conditions, so the data shows no difference between them.

## Open items that need the owner

1. **The pilot is interrupted.** The worker's virtual machine stopped on 2026-10-23 at about 19:47 UTC, during trial 21. In the pilot ledger, attempt `pilot-invoice-create-instructions-r1` is still in phase `running` with one open model request and a held 101¢ reservation. Decide whether to close the pilot as reported or run the remaining 27 trials as a declared deviation. Either way the open attempt must be reconciled first. See [RESULTS.md](RESULTS.md).
2. **Costs are unreconciled.** Settled costs (27¢ calibration, 107¢ pilot) are upper bounds and have not been compared with the provider bill.
3. **Worker cleanup.** As observed on 2026-11-15, `ds-worker` still holds three exited containers from the interrupted trial and the unarchived job directories under `.research/pilot`. Nothing was changed there.
4. **The task set does not separate the conditions** for the model tested. Decide whether to design harder scenarios before another comparison.
5. **Production identity** remains undecided. The fixture's fixed bearer tokens are not authentication.
6. **Seven Dependabot PRs** are open and unreviewed (#3, #73, #74, #76 to #79).

## Implemented capabilities

- **Campaign contracts and planner.** Offline validation and deterministic planning (`research validate`, `plan`, `seal`, `inspect-artifact`). See [CONTRACTS.md](CONTRACTS.md).
- **Reference apps.** A synthetic FastAPI invoice API with reads, list/search, CSV export, update, create and summary. One variant is protected by forced PostgreSQL RLS and a restricted role, and one isolates tenants in application code against a plain database. See [REFERENCE.md](REFERENCE.md).
- **Independent verifier.** HTTP and database checks with complete accounting. Protocol `synthetic-reference-v3` has 8 required checks; `synthetic-reference-v4` has 10 and adds writes and aggregates. Reviewed unsafe controls must fail for their intended reason.
- **Harbor tasks.** One policy task and three application tasks under `tasks/harbor/`, and 24 generated pilot variants under `tasks/pilot/` (6 families × 4 conditions). Pinned to Harbor 0.24.0. See [APPLICATION_TASKS.md](APPLICATION_TASKS.md).
- **Evaluation boundary.** Separate candidate containers with no network, a trusted collector that runs after the agent stops, sealed artifacts, sealed replay in a fresh verifier, nonce-bound evidence and a host-observed boundary audit (policy v5) with bounded container storage. Host acceptance rejects a trial where the agent forced Harbor's unfiltered artifact fallback. See [HARBOR_AUDIT.md](HARBOR_AUDIT.md) and [SEALED_REPLAY.md](SEALED_REPLAY.md).
- **Dedicated worker.** A root helper gives each Harbor job its own 64 MiB filesystem when `DS_WORKER_HOST_REQUIRED=1`. See [WORKER_HOST.md](WORKER_HOST.md).
- **Ledger (store v8).** SQLite with immutable events: plans, attempts, budget reservations and settlement, artifact and evidence bindings, verification intent, controller generations with write fencing, the runtime attempt lifecycle, authenticated result admission, restore fences and per-request model metering. Unknown costs keep their holds. See [PERSISTENCE.md](PERSISTENCE.md), [EVIDENCE.md](EVIDENCE.md), [RUNTIME_AUTH.md](RUNTIME_AUTH.md) and ADRs 0004 to 0007.
- **Backup and restore.** Verified offline backup of the ledger and its objects, version 8 only. See [BACKUP.md](BACKUP.md).
- **Recovery decisions.** A pure function that turns a crash observation into inspection advice. It changes no state. See [RECOVERY.md](RECOVERY.md).
- **Model access.** A controller-side broker serves Harbor's Terminus2 agent over a private socket, meters every request and keeps the provider key out of the Harbor environment. A model-free transport conformance test covers the same path. See [CALIBRATION.md](CALIBRATION.md), [MODEL_BATCH.md](MODEL_BATCH.md) and [TERMINUS_CONFORMANCE.md](TERMINUS_CONFORMANCE.md).
- **Pilot.** Four conditions, six families, the `check-isolation` self-check for `full_tool`, model-free controls for every variant, the runner `scripts/pilot.py` and the report `scripts/pilot_report.py`. The protocol is pre-registered in [PILOT_PROTOCOL.md](PILOT_PROTOCOL.md).

## Evidence

| What | Revision | Result |
| --- | --- | --- |
| CI on main | `c05e58d`, run [40001476306](https://github.com/dillaryclump/democratize-security/actions/runs/40001476306) | All 16 jobs passed |
| Full suite on the dedicated worker | `c05e58d`, 2026-10-23 | 1,429 passed, none skipped, with real PostgreSQL, Docker and Harbor |
| Pilot controls on the dedicated worker | `c05e58d`, 2026-10-23 | 84 of 84 control trials accepted and audited |
| Calibration, live | `1f83ca6`, 2026-10-23 | 6 of 6 pass and complete, 27¢ upper bound |
| Pilot, live, incomplete | `c05e58d`, 2026-10-23 | 20 graded and passed, 1 interrupted, 27 not run, 107¢ upper bound |

Each row applies only to its named revision. A green job, merged code and owner acceptance are separate facts. Earlier observations, failures and evidence are preserved in [STATUS_HISTORY.md](STATUS_HISTORY.md).

## Owner decisions on record

| Date | Decision | Where |
| --- | --- | --- |
| 2026-10-17 | Synthetic scope and contract defaults approved | #19 |
| 2026-10-20 | Bounded dedicated-worker evidence accepted, with two documented verifier gaps as residual limitations for the synthetic public scope | #19 |
| 2026-10-20 | $10 model-only cap for the six-trial calibration. Used: 27¢ settled | #57 |
| 2026-10-23 | $15 hard model-only cap for the 48-trial pilot on `gpt-6.1-sol`. Used so far: 107¢ settled, 101¢ held | #57 |
| 2026-11-15 | Apache-2.0 license | [ADR 0002](decisions/0002-licensing.md) |
| 2026-11-15 | Publish the interim pilot record | #80 |
| 2026-11-15 | Enable private vulnerability reporting, Dependabot security updates and a main-branch ruleset | #80, [DEVELOPMENT.md](DEVELOPMENT.md) |

No spending beyond the $15 pilot cap is approved.

## Next bounded work

1. Reconcile the interrupted pilot attempt and record the owner's decision to close or resume (open item 1).
2. Reconcile settled costs against the provider bill (open item 2).
3. Clean up the worker after the ledger is reconciled (open item 3).
4. Only then consider the next experiment. Do not start M5 search on a task set that shows no difference between conditions.

Do not manufacture accepted results from the offline evidence APIs, and do not treat a saved plan, binding or cost reservation as authorization to run a trial.

## Remaining gates and limitations

- **No automated recovery.** No recovery engine, general dispatcher, protected final evaluator, demonstrated improvement or GEPA search exists. The calibration and pilot drivers are single-purpose scripts. The ledger's admission, restore fence and request reservations are local process-level guarantees.
- **Residual isolation gaps.** On ordinary hosts the audit reports `agent_can_write_verifier_log_directory`, `verifier_storage_unbounded` and `trial_storage_unbounded`. The dedicated worker removes the third. The two verifier gaps remain and were accepted for the synthetic public scope only. Containers share the worker's kernel.
- **Public fixtures.** The tasks and the verifier are public. They are not a protected holdout.
- **The signer is a bridge.** Reports are signed by a short-lived controller-side process after the Harbor nonce authenticates the replay evidence, not inside the verifier's container.
- **No release.** No package is published and no version is tagged.

Green CI and merged code are not owner acceptance or evidence of product efficacy.

## Handoff maintenance

Use [HANDOFF_TEMPLATE.md](HANDOFF_TEMPLATE.md), claim bounded work in a live issue and recheck main and open PRs before editing. Archive superseded observations with their exact revision, and keep this page focused on current capabilities and next work.
