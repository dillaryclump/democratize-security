# Current status and next handoff

Snapshot: 2026-10-15, main `1124a0c1919c27998bef941fd9435853276d5abd`.
Check live [issues](https://github.com/dillaryclump/democratize-security/issues)
and [PRs](https://github.com/dillaryclump/democratize-security/pulls) before claiming work.
This is a capability snapshot, not an ownership lock. See [COORDINATION.md](COORDINATION.md).

## Implemented on main

- Versioned offline campaign validation and deterministic planning; execution remains disabled.
- Synthetic FastAPI invoice reads, list/search/pagination and CSV, with server-owned identities and restricted PostgreSQL RLS.
- Independent public HTTP/database verifier, protocol `synthetic-reference-v3`; eight required checks, with incomplete evidence blocking success.
- Bounded allowlisted artifact sealing and integrity checking, evidence/hash binding, and an offline Docker worker probe.
- Harbor 0.24.0 policy controls, sealed replay, nonce-authenticated grades and host-observed boundary auditing.
- Three application tasks in `tasks/harbor/invoice-{read,search,export}`, merged in #16. Candidate application code runs in a separate restricted container. Each task has oracle/nop/unsafe controls and fresh sealed oracle/unsafe replay. See [APPLICATION_TASKS.md](APPLICATION_TASKS.md).
- Audit v3 enforces the reviewed app/container topology. These model-free fixtures establish scoped engineering evidence, not a benchmark improvement or approval to run arbitrary generated code.

## Verified evidence

| Revision / scope | Observed evidence |
| --- | --- |
| Main `1124a0c` | [CI 38750135994](https://github.com/dillaryclump/democratize-security/actions/runs/38750135994) completed successfully |
| #16 final code `82f0603` | [CI 38748449846](https://github.com/dillaryclump/democratize-security/actions/runs/38748449846); detailed control outcomes and review fixes recorded in APPLICATION_TASKS.md and STATUS_HISTORY.md |
| Collector #17 head `1d7258f` (not merged at this snapshot) | [CI 38752494128](https://github.com/dillaryclump/democratize-security/actions/runs/38752494128) completed successfully; implementation/review tracked in #19 |
| Superseded #15 `dc995a2` | [CI 38667818808](https://github.com/dillaryclump/democratize-security/actions/runs/38667818808), all six jobs passed; applies only to that alternate implementation |

Historical results, failures and fixes are preserved in [STATUS_HISTORY.md](STATUS_HISTORY.md).
A CI result applies to its recorded revision; it does not approve a later head or close an owner acceptance gate.

## Work allocation and next steps

| Work | Tracking | State at snapshot / next action |
| --- | --- | --- |
| Agent coordination and status reconciliation | #18 | Codex; documentation PR, separate from runner code |
| Trusted pre-transfer artifact collector | #17 / #19 | Existing Claude Code work; review current head and tests, then merge/reconcile docs |
| ID-derived tenant and deny-all regression controls | #20 | Available bounded follow-up; claim before editing |
| Persistence and recovery contract | #21 | Planned offline design; runtime integration follows M2 acceptance |
| Dependency maintenance | #2–#6 | Separate Dependabot PRs; review current compatibility and CI individually |

PRs #14 and #15 were closed without merging after #16 established the canonical implementation.
Their branches remain historical evidence. Port complementary tests through #20; do not merge the alternate task/runtime layout.

## Open gates and limitations

- **M0:** Dillon's review of synthetic access defaults, production identity and final-study semantics remains pending.
- **M2:** Three application tasks and replays exist. Main still lacks checked artifact extraction *before* Harbor transfers an agent path through the host. #17 addresses this; green CI is not merged code or owner acceptance.
- Harbor's shared log/artifact mounts, host-bounded disk storage, shared kernel/daemon and public fixtures remain limitations. Consult the current audit and collector PR for exact boundaries.
- Dedicated-worker approval and an explicitly approved finite model budget are required before model execution. No model calls, spend or hostile workload approval is implied.
- **M3 onward:** no durable run store, budget enforcement/recovery, production research dispatcher, protected final evaluator, pilot result or GEPA search.
- License, repository protection requirements and private vulnerability reporting remain owner setup decisions.

## Handoff maintenance

Keep this file a current summary. Move superseded observations to the history file with their revision instead of appending contradictory "next" sections. Record live ownership, scope, dependencies, PR, evidence and next action in the relevant issue. Follow [HANDOFF_TEMPLATE.md](HANDOFF_TEMPLATE.md).
