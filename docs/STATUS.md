# Current status and next handoff

Updated: 2026-10-17 UTC. Report contracts #39, durable evidence objects #41,
offline evidence ledger #43 and verification intent #45 are merged into main
through `c5a177c`, with successful CI on all four reviewed source heads.
Check live [issues](https://github.com/dillaryclump/democratize-security/issues)
and [PRs](https://github.com/dillaryclump/democratize-security/pulls) before claiming
work. [COORDINATION.md](COORDINATION.md) defines the ownership convention.

## Implemented capabilities

- Offline campaign validation/planning, with execution disabled.
- Synthetic FastAPI invoice reads, list/search/pagination and CSV; server-owned
  fixture identities and restricted PostgreSQL RLS.
- Public independent HTTP/database verifier, protocol `synthetic-reference-v3`,
  with complete accounting of eight checks and deliberate unsafe controls.
- Harbor 0.24.0 model-free policy and three application tasks, separate candidate
  containers, nonce-bound evidence, trusted submission collection and sealed replay.
- Host rejection of forced unfiltered `/logs/artifacts` fallback copies. Audit v5
  bounds container storage: submissions, tmpfs, shared memory and logs. Each app
  has twelve reviewed control/replay trials. See [APPLICATION_TASKS.md](APPLICATION_TASKS.md).
- SQLite offline plans, immutable events and synthetic attempt/reservation/settlement
  accounting. Unknown costs retain their holds; conflicts persist integrity stops.
- Durable artifact and evidence objects, immutable attempt/artifact/evidence
  bindings, corruption checks and explicit schema migration. Failed/incomplete
  reports retain their outcomes; passing offline reports do not complete trials.
- Store v5 commits verification intent before admitting new schema-v2
  evidence bindings. Historical evidence remains unchanged and cannot acquire
  retrospective intent. This records expectations, not verifier authentication.

## Integration and evidence

| PR | Capability | Reviewed head | CI run | Merge |
| --- | --- | --- | --- | --- |
| #39 | Strict reports and canonical envelopes | `bc58fd2` | [38916744794](https://github.com/dillaryclump/democratize-security/actions/runs/38916744794), passed | `50cfc6b` |
| #41 | Durable evidence objects | `cb42757` | [38954132208](https://github.com/dillaryclump/democratize-security/actions/runs/38954132208), passed | `c9b3fcc` |
| #43 | Store v4 offline evidence ledger | `8cda0d3` | [38955296644](https://github.com/dillaryclump/democratize-security/actions/runs/38955296644), passed | `8d79142` |
| #45 | Store v5 verification intent | `c933a95` | [39039241931](https://github.com/dillaryclump/democratize-security/actions/runs/39039241931), passed | `c5a177c` |

The merged prerequisites retain their source commits and branches. Integration
checks compare merge trees to the reviewed source trees; no runtime files were
modified to reconcile the stack. Local #45 verification: 550 passed, 54 skipped
for unavailable optional dependencies/PostgreSQL/Docker; locked sync, Ruff and
build passed. Skipped checks are not integration evidence. Each CI row applies
only to its named revision. Earlier observations, failures and evidence are
preserved in [STATUS_HISTORY.md](STATUS_HISTORY.md).

## Next bounded work

1. Implement a pure recovery reducer and controller-generation fencing using
   synthetic observations. Cover the crash-window table in [PERSISTENCE.md](PERSISTENCE.md):
   ambiguous request outcomes must retain reservations and never emit resubmission.
2. Define and implement the trusted runtime authentication boundary and
   accepted-result lifecycle. Persisted intent, hashes and report consistency
   alone cannot prove a trusted verifier executed. Do not manufacture accepted
   results from the current offline evidence APIs.
3. Only after persistence/recovery review and M0/M2 acceptance, connect the runner
   on a dedicated bounded worker. Model execution additionally needs an explicitly
   approved finite budget. No paid pilot or optimizer is authorized by this ledger.

## Remaining gates and limitations

M3 remains partial: no live recovery engine, production dispatcher, authenticated
accepted-result registry, backup/restore tool, protected final evaluator, paid
pilot, demonstrated benchmark improvement or GEPA search exists.

M2 owner acceptance remains open in #19. Remaining observed runner gaps are
`agent_can_write_verifier_log_directory`, `verifier_storage_unbounded` and
`trial_storage_unbounded`. A dedicated host must bound each trial job directory;
repository scripts do not mount filesystems with privilege. Public fixtures are
not a protected holdout and containers share the host kernel. See
[HARBOR_AUDIT.md](HARBOR_AUDIT.md) for the measured boundary.

M0 contract defaults, production identity, license, branch protection and
vulnerability-reporting setup remain owner decisions. Green CI and merged code
are not owner acceptance or evidence of product efficacy.

## Handoff maintenance

Use [HANDOFF_TEMPLATE.md](HANDOFF_TEMPLATE.md), claim bounded work in a live issue
and recheck main/open PRs before editing. Archive superseded observations with
their exact revision; keep this page focused on current capabilities and next work.
