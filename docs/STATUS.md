# Current status and next handoff

Updated: 2026-10-17 America/Denver. Report contracts #39, durable evidence objects #41,
offline evidence ledger #43 and verification intent #45 are merged into main
through `c5a177c`, with successful CI on all four reviewed source heads.
Handoff #47 merged at `99a62f7` with CI run 39039851019 passing. Pure recovery
decisions (#48/#49), including review fixes, merged through #52 at `061cd1a`;
main CI run [39054062485](https://github.com/dillaryclump/democratize-security/actions/runs/39054062485)
passed. Authentication #58 and offline backup #59 are merged through `1fd5468`.
Controller fencing and explicit v6 backup support are in review in #64 for #53.
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
- On #53: store v6 adds durable append-only controller generations, validated
  current-generation access and process/generation fencing before every write,
  including exact retries and conflict-stop inserts. Explicit migration validates
  complete v5 history first and preserves historical bytes. This branch implements
  local controller ownership only; no runtime recovery or dispatch is enabled.
  Original fencing head `84592b2`: local locked checks passed 827 tests with no
  skips, on Python 3.12.13 with PostgreSQL and all seven Docker worker cases.
  That evidence predates the merged auth/backup compatibility update.
- Issue #56 adds the standard-library per-request verifier authentication
  contract: exact trusted context, a fresh in-memory nonce, canonical signed
  reports, replay rejection and detached authenticated observations. It is not
  wired to the isolated verifiers, result admission or store transitions. A
  controller crash before admission leaves verification incomplete and retains
  its hold. See [RUNTIME_AUTH.md](RUNTIME_AUTH.md) and ADR 0005. Local verification
  on this change: 807 passed with real PostgreSQL and Docker probes; locked sync,
  Ruff lint/format and offline package build passed. No Harbor live trials were
  rerun locally for this isolated contract change.
- Verified offline backup/restore (#55/#59), with explicit v6 support in #64,
  preserves historical records and the complete controller-generation history.
  Only private scratch copies allocate during validation; frozen/restored bytes
  stay exact until deliberate store open. Corrupt/rehashed generation histories
  reject; v5 sources/archives require explicit migration using matching tooling.
  Restore provenance remains advisory, with no persistent runtime reconciliation
  gate. See [BACKUP.md](BACKUP.md). Combined v6/auth/backup local verification:
  961 passed, no skips, on Python 3.12.13 with real PostgreSQL and all seven
  Docker worker cases; locked sync, Ruff lint/format and package build passed.
- On #48: a pure recovery decision function covers synthetic crash observations,
  rejects stale/foreign context and preserves uncertain cost holds. It emits
  inspection advice only. See [RECOVERY.md](RECOVERY.md); no live recovery or
  durable controller fencing is implemented by the #48 slice. Review fixes:
  - acknowledged phases require the bound worker, so a foreign worker's
    observation is rejected;
  - a worker active after sealing is an integrity stop;
  - a reference or intent cannot precede its phase;
  - the previously untested rules now have tests that fail without them.

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

1. Review/integrate #53 controller-generation ownership and fencing. Connect
   validated store projections to recovery decisions in a separate slice.
   Ambiguous request outcomes must retain holds and never emit resubmission.
2. Integrate the merged per-request authentication contract with a trusted runtime
   boundary and accepted-result lifecycle. Persisted intent, hashes and report
   consistency alone cannot prove a trusted verifier executed. Do not manufacture accepted
   results from the current offline evidence APIs.
3. Only after persistence/recovery review and M0/M2 acceptance, connect the runner
   on a dedicated bounded worker. Model execution additionally needs an explicitly
   approved finite budget. No paid pilot or optimizer is authorized by this ledger.

## Remaining gates and limitations

M3 remains partial: no live recovery engine, production dispatcher, authenticated
accepted-result registry, runtime restore fence, protected final evaluator, paid
pilot, demonstrated benchmark improvement or GEPA search exists.

Issue #50: PR #49's CI run 39043199834 failed one `harbor-apps` audit. In the
`sparse` control, a collector exec carried an earlier timestamp than the agent's
`die` event, which Docker emits after the exit that releases `docker stop`.
Collector ordering now uses the agent's recorded exit time, with the `die` as
fallback. A real stop failure still fails, now with the measured lead. Locally
(Docker 29.8.2, cgroup v1, root; proxy-CA patched images), `invoice-read` passed
all 12 trials and 12/12 audits. In every trial `die` trailed the recorded exit by
48–87 ms, and the first collector exec came 108–840 ms after `die`.

M2 owner acceptance remains open in #19. On ordinary hosts the observed runner
gaps are `agent_can_write_verifier_log_directory`, `verifier_storage_unbounded`
and `trial_storage_unbounded`. Issue #54 (PR #61) adds the dedicated-worker
helper: with `DS_WORKER_HOST_REQUIRED=1`, each Harbor job gets its own 64 MiB
ext4 loop filesystem before launch. On the dedicated WSL2 worker Dillon selected
(source `2a6ed57`, Docker Engine 29.9.1, cgroup v2), the privileged storage
control reached ENOSPC at 57,307,136 bytes, the full suite passed (1000, no
skips, real PostgreSQL and Docker), and replay, audit and all three application
tasks passed. All 37 audited trials observed `own_filesystem: true` at
58,675,200 bytes, so `trial_storage_unbounded` no longer appears there; the two
verifier gaps remain for owner review. All 41 jobs were archived and released in
the same session. Public fixtures are not a protected holdout, and containers
share the WSL2 kernel. See [WORKER_HOST.md](WORKER_HOST.md) and
[HARBOR_AUDIT.md](HARBOR_AUDIT.md).

Production identity, license, branch protection and vulnerability-reporting
setup remain owner decisions. Green CI and merged code
are not owner acceptance or evidence of product efficacy.

Owner review update, 2026-10-17: Dillon approved the existing synthetic scope,
contract defaults and review of M2 evidence/residual limitations; recorded in
[#19](https://github.com/dillaryclump/democratize-security/issues/19#issuecomment-6238276266).
Issue #19 remains open for owner acceptance of the bounded worker-host evidence
above (2026-10-20: Dillon chose a dedicated local WSL2 distro instead of waiting
for another machine). Production identity and the other owner
decisions above remain unresolved. Infrastructure/model spending has no approved
finite budget, and this approval does not enable execution.

## Handoff maintenance

Use [HANDOFF_TEMPLATE.md](HANDOFF_TEMPLATE.md), claim bounded work in a live issue
and recheck main/open PRs before editing. Archive superseded observations with
their exact revision; keep this page focused on current capabilities and next work.
