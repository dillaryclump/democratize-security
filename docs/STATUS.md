# Current status and next handoff

Updated: 2026-10-15. Current work: M2 runner gate. The three application tasks run model-free under the hardened Harbor layout; see APPLICATION_TASKS.md and the latest evidence below. Owner acceptance of M2 is pending.

## Implemented

- Offline versioned campaign validation and deterministic planning from the merged foundation.
- Optional FastAPI invoice reference with synthetic server-owned identities, direct reads, literal search, pagination and CSV.
- PostgreSQL RLS fixtures with separate setup/runtime roles and transaction-local tenant context; no application tenant filter.
- Public verifier that uses HTTP and direct database-role inspection without importing the app. Required-check accounting fails closed on incomplete evidence.
- Five unsafe database variants, authorized/forbidden behavior checks, pool rollback/reuse, broken-transport and empty-output checks.
- Separate real-PostgreSQL CI gate plus existing core Python matrix. Read REFERENCE.md for reproduction and limits.

## Verification

Local Python 3.12: 36 tests pass, 9 PostgreSQL integration tests explicitly skip because no local database server is available. Ruff checks pass and package builds succeed. GitHub PostgreSQL 17 CI run 38466115426 executed all 45 tests with no skips: 45 passed in 4.60 seconds. This includes the protected reference and all five unsafe database variants. A local skip is not security evidence.

## Not implemented / limitations

No production identity provider, sealed-only verification replay, protected holdout verifier, hostile-workload isolation, production Harbor/GEPA adapter, durable run store, paid execution or benchmark result. The public verifier is fixed to the synthetic dataset and trusts the harness to supply the app's actual runtime DSN. Core commands remain dependency-free; reference dependencies are optional.

## Decisions and next work

Review the concrete reference access contract in REFERENCE.md and ADR 0003. Production identity and final-study semantics remain pending founder acceptance. Implemented next slice: sanitized HTTP database errors, real permission-failure/recovery on the same backend, malformed/duplicate auth checks, input bounds and concurrent tenant requests. Local suite: 36 pass, 12 database tests skip. v2 PostgreSQL 17 CI run 38477380739: all 48 tests passed, no skips, in 8.82 seconds. Both core Python matrix jobs also passed. Next: review M0 contract and prove M2 worker isolation and artifact sealing with three real tasks. A dedicated worker host and finite model budget are still required before agent execution.

License choice, main-branch protections (including postgres-reference), and private vulnerability reporting remain repository-owner setup decisions. No open-source license or paid infrastructure was provisioned.

## Handoff discipline

Update this file with actually observed commands/results, limitations and the next bounded task. Preserve negative outcomes. Do not call the entire security MVP complete because a synthetic reference passes.

## M2 artifact prerequisite (current follow-up)

Implemented explicit-allowlist sealing, bounded canonical bundles, integrity inspection, no-overwrite publication and artifact/verifier/result hash binding. See ARTIFACTS.md. This does not establish execution provenance or worker isolation; those remain the next integration task.

Artifact PR #8 validation: 62 local tests passed, 12 PostgreSQL tests skipped; Ruff and builds passed. GitHub CI run 38481516104 ran all 74 tests against PostgreSQL 17 with no skips.

## M2 offline worker capability probe

Implemented a fixed-command Docker probe for reviewed synthetic sealed artifacts, restricted local execution, bounded output/time and execution records. Harbor remains the intended agent runner. See WORKER_PROBE.md. Local validation: 67 tests pass, 18 PostgreSQL/Docker tests explicitly skip; Ruff passes. Live Docker CI is the acceptance gate. No paid execution or full M2 completion is claimed.

## Worker probe acceptance evidence (2026-10-14)

CI run [38573021390](https://github.com/dillaryclump/democratize-security/actions/runs/38573021390), code revision `626074628cef551810216096839958a52464aa4a`: all four jobs passed. PostgreSQL job: 81 passed, 7 Docker cases intentionally skipped. Dedicated Docker job: all 7 container cases passed (one unrelated optional verifier module skipped during collection). Python 3.12 and 3.13 core checks passed. Local verification: 69 passed, 19 infrastructure cases skipped; Ruff formatting/lint and package build passed.

The initial live run exposed a stdout backpressure shutdown timeout. The fix disconnects the attach stream before signalling the workload. Stop-race handling now requires an observed stopped state; live nested-file tests cover a restrictive controller umask. This evidence applies to the reviewed offline probe, not full M2 or a general hostile-code sandbox. Next: pinned Harbor separate-verifier integration with actual tenant-isolation development tasks and a dedicated-host gate.

## Harbor policy spike (2026-10-14)

Pinned Harbor 0.24.0 in a separate dependency group. Added a public declarative
RLS policy task, separate PostgreSQL verifier image, oracle/nop controls, strict
result/coverage checks and post-run artifact hash matching/sealing. See HARBOR.md
for exact boundaries and reproduction. Local: 81 passed, 19 infrastructure tests
skipped; pinned task schema loads. CI run
[38577845657](https://github.com/dillaryclump/democratize-security/actions/runs/38577845657)
at `df8eefcb4f1f6b0f157ca44553f41db0c49a6621` passed all five jobs. PostgreSQL:
93 passed, 7 Docker cases skipped; worker job: all 7 container cases passed.
Harbor: oracle 1 / nop 0, one trial each, zero exceptions, all four checks
respectively true / false, separate mode and input hashes accepted. This one policy fixture is
not one of the three M2 application development tasks. Next: sealed-only replay,
image provenance and actual application tasks; no model execution authorized.

## Sealed policy replay (2026-10-14)

Added pre-verification bundle validation and fresh Harbor nop tasks constructed
from sealed policy bytes, with input/output equality required before publishing
bound replay evidence. See SEALED_REPLAY.md. Initial grades are diagnostic only.
Local: 82 passed, 20 skipped; Ruff and generated-task schema load pass. Live CI
pending. Next: runtime image provenance/worker audit and three application tasks.
This advances M2 prerequisites without completing M2 or authorizing model calls.

## Harbor boundary audit (2026-10-14)

Pinned task base images by multi-arch index digest and added a host-observed
audit of the containers Harbor 0.24.0 actually creates, with one reviewed
grade-forgery and network tamper control. See HARBOR_AUDIT.md. Gating inputs are
`docker events`/`inspect` and a host TCP listener, never candidate output.

Local evidence (disposable cloud container, Docker 29.8.2, cgroup v1): full
suite 137 passed with no skips against real PostgreSQL 16 and Docker; core-only
111 passed, 20 skipped; Ruff and build pass. With pinned images, controls and
sealed replays reproduced the CI bundle hashes `6fb653ff…` (oracle 1) and
`34da710d…` (nop 0). Tamper control: forged `reward.json`, `reward.txt` and
all-pass evidence were observed at agent stop and then discarded; the genuine
reward was 0; all seven audit checks passed; the network positive control
reached the host once and the trial reached it zero times.

Recorded gaps, which block model-generated or hostile candidates: the agent has
the trial's verifier log directory mounted read-write (Harbor reads
`reward.json` first; protection relies on agent stop and directory emptying);
Harbor `no-network` permits external DNS and ICMP; agent and verifier run as
root with default capabilities, writable root filesystem, no PID limit, swap
twice the memory limit and no storage limit. Apt packages remain mutable.

Negative local observation: against a SQL_ASCII-encoded local cluster the
protected reference failed `exports` because psycopg returned bytes; the CSV
contained `b'…'` values and the verifier correctly failed it. A UTF-8 cluster
passed. The test fixture does not pin database encoding; CI's PostgreSQL image
defaults to UTF-8. Pinning `ENCODING 'UTF8'` in the fixture is a small follow-up.

Live CI for this change is pending: the workflow runs on pull requests and named
branches only. Next: reviewed task compose overrides (no network, non-root,
dropped capabilities, PID/swap/read-only limits) proven by rerunning the audit,
and a verifier-only evidence nonce; then three application tasks. No model
calls, spending or hostile-candidate execution are authorized by this audit.

## Harbor container hardening and nonce-bound evidence (2026-10-14)

Closed most of the gaps the boundary audit recorded. Reviewed compose files in
the task harden both containers: `network_mode: none`, non-root users (agent
`10001:10001`, verifier `postgres`), all capabilities dropped (the verifier keeps
`CHOWN`, `DAC_OVERRIDE` and `FOWNER` for Harbor's root housekeeping),
`no-new-privileges`, `init`, PID limits, swap equal to memory and read-only
roots with image volumes for the paths Harbor copies. Each run's verifier
receives a fresh nonce through `harbor run --ve`, and evidence carries an HMAC
the host verifies. The host also rejects any `reward.json`. Replay tasks carry
the same compose files. Audit policy v2 makes the closed gaps required checks and
verifies the nonce is in no container configuration. See HARBOR_AUDIT.md.

The design came from a source map of pinned Harbor 0.24.0 plus live
experiments:
- Under `cap_drop: ALL`, root cannot empty a uid-1001-owned bind mount, so
  planted files survive.
- `docker cp` writes only into volumes on a read-only root.
- Harbor ignores the exit codes of its root housekeeping.
- A same-uid agent could lock the shared log directory, so the agent's uid
  must differ from the controller's.

Local evidence (Docker 29.8.2, cgroup v1, PostgreSQL 16):
- Full suite: 176 passed, no skips. Ruff
  passes.
- Hardened controls and sealed replays: oracle 1 / nop 0. Bundle hashes are
  unchanged (`6fb653ff…`, `34da710d…`).
- Audit: 10/10 v2 checks. The forgery was observed, then discarded; the genuine
  reward was 0.
- The agent probe reports no default route. Gaps fell from 14 to 3: Harbor's
  shared log mount (now non-grading) and storage limits.

An adversarial review then found two CI-only failures that a root-owned local
checkout hides. `docker cp` keeps the runner's uid on uploaded scripts, so
Harbor's capability-less root `chmod` failed and both the oracle and the tamper
`solve.sh` hit `Permission denied`, with a silent reward of 0. Both scripts are
now executable before upload; the failure and the fix were reproduced with
uid-1001-owned copies. The review also found that a task.toml exec user would
override the audited container user; the audit now fails if one is set.

CI [run 38640538700](https://github.com/dillaryclump/democratize-security/actions/runs/38640538700)
at `cd5c433` passed all five jobs on a GitHub runner (uid 1001, cgroup v2).
- Hardened oracle 1 / nop 0 and both sealed replays were accepted with
  nonce-bound evidence.
- The audit passed 10/10 v2 checks with the same 3 gaps.
- The forgery was observed and discarded, the genuine reward was 0, and the
  agent probe reported no default route.

Next: the three application tasks under this layout. No model calls, spending or hostile-candidate execution are authorized.

## Harbor application tasks (2026-10-15)

Implemented the three M2 application tasks: invoice read, list/search and CSV
export (`tasks/harbor/invoice-*`). Each starts from the reference app with one
endpoint removed. Candidate code runs only in a separate `app` service of the
separate verifier: uid `20001:20001`, no capabilities, read-only root, 256 MiB
without swap, joined to the verifier's loopback-only namespace and mounting only
the project's candidate volume read-only. A trusted orchestrator provisions a
fresh database and hands the app a restricted DSN. It grades the app with
protocol `synthetic-reference-v3`, which adds spoofing checks across read, list
and export, and writes nonce-bound evidence (schema 3). `scripts/harbor_apps.py`
runs oracle, nop and a reviewed unsafe control per task, replays the sealed
oracle and unsafe artifacts, and audits every trial. Audit policy v3 admits and
constrains the app container. See APPLICATION_TASKS.md.

Local evidence at `720fb80` (Docker 29.8.2, cgroup v1, root host):
- Full suite with PostgreSQL 16 and the Docker worker tests: 235 passed, no
  skips. Ruff passes.
- `harbor_apps.py` for all three tasks: 15 trials, every outcome exactly as
  reviewed. Oracles 1. Nops 0. Unsafe controls 0, failing only spoofing (read,
  export) or list_search, spoofing and tenant_switching (search). Both replays
  per task reproduced their sealed hashes and outcomes.
- 15/15 v3 audits passed with 4 gaps: the three v2 gaps plus
  `app_storage_unbounded`. The positive control was observed and no trial
  connection reached the host listener.
- Policy-task regressions under v3: the tamper audit passed 10/10 with the same
  3 gaps, and the forgery was observed and discarded (genuine reward 0). The
  replays kept bundle hashes `6fb653ff…` and `34da710d…`.
- Image builds here needed an uncommitted patch so pip trusts this sandbox's
  TLS-intercepting proxy. Committed Dockerfiles are unchanged; CI builds them
  as committed.

CI on the GitHub runner (uid 1001, cgroup v2) passed every job, including one
`harbor-apps` job per task: [run 38673823006](https://github.com/dillaryclump/democratize-security/actions/runs/38673823006)
at `720fb80`, [38674490600](https://github.com/dillaryclump/democratize-security/actions/runs/38674490600)
at `5d9246c` and [38674863679](https://github.com/dillaryclump/democratize-security/actions/runs/38674863679)
at `8a244ad`.

Review fixes after the first evidence:
- Copilot found that the launcher ran the candidate unregistered in
  `sys.modules`, so a correct app using postponed annotations crashed. Fixed,
  with a regression test.
- An adversarial review found:
  - the app had no writable `/tmp`, unlike the agent;
  - audit v3 did not reject PID or IPC namespace sharing with the verifier, or
    a shared uid;
  - application replays were labelled `sealed_policy_replay`;
  - the evidence text was not pinned to revisions.

  All are fixed. The verifier now runs as numeric `999:999`. A local
  `invoice-read` run with these fixes passed 5/5 trials with exact outcomes
  and 5/5 audits: app uid 20001, private PID and IPC namespaces.
- The final review round found more, all fixed:
  - a valid `app.py` saved as 0600 was graded `invalid_submission`, so it
    is now its own bound zero, `unreadable_submission`, and the instructions
    ask for a readable file;
  - no test exercised exact-check acceptance, and the starter and unsafe AST
    tests skipped module functions, async handlers and plain statements;
  - the app-image test missed multi-file `COPY` and `ADD`;
  - v3 admitted the named candidate volume without an app;
  - several docs overstated or were stale.

  Mutation checks confirm the new tests fail on the defects they target. CI
  [run 38748449846](https://github.com/dillaryclump/democratize-security/actions/runs/38748449846)
  at `82f0603` passed every job with the final code and rules.
- The review also confirmed a pre-existing gap: Harbor moves the artifact
  through the host unchecked, so a symlink is resolved there and nothing bounds
  the size. This holds for both task families and is recorded as a limit in
  APPLICATION_TASKS.md; ARCHITECTURE.md step 5 is not yet met.

No model calls, spending or hostile-candidate execution are authorized. Next:
- a trusted artifact collector that stops the worker, rejects links and special
  files and bounds size before Harbor's transfer (ARCHITECTURE.md step 5);
- owner review of the M2 evidence;
- a dedicated worker host and an approved budget before any agent runs.

## Trusted artifact collector (2026-10-15)

Closed the gap the application-task review confirmed: Harbor 0.24.0 copied the
agent's artifact path to the host and into the verifier unchecked, resolving
symlinks on the host and streaming sparse files in full. Every Harbor task
(policy and application) now collects only through a trusted `collector`
service in the agent's compose project (ARCHITECTURE.md runtime step 5):
- The agent's `/candidate` is a named volume, which the collector mounts
  read-only.
- After Harbor stops the agent's container, a `[[verifier.collect]]` hook runs
  `collect.py`. It requires a regular, singly linked file within the size bound
  (checked before reading) and writes a fresh `0444` copy.
- The only artifact entry names `service = "collector"`, so only that copy
  moves through the host. A rejection leaves no file and is graded as a missing
  submission.

Audit policy v4 constrains the collector like a main container. From
`exec_start` events, it requires that every exec into the collector came after
the agent's container died. See HARBOR_AUDIT.md.

Local evidence (Docker 29.8.2, cgroup v1, root host):
- Full suite with PostgreSQL 16 and the Docker worker tests: 278 passed and 1
  skipped (the mode-000 case cannot apply as root; CI runs it). Ruff passes.
- Policy task under v4:
  - oracle 1 / nop 0;
  - replays kept bundle hashes `6fb653ff…` and `34da710d…`, so collection
    preserves the bytes;
  - the tamper audit passed 10/10, the forgery was discarded and the genuine
    reward was 0.
- `invoice-read`: 9 trials, every outcome exactly as reviewed, and 9/9 v4
  audits with the collector observed and zero egress.
  - The symlink to a host canary directory, the 1 GiB sparse file and the FIFO
    each ended in nonce-bound `invalid_submission`, with no collected file and
    the canary secret in no trial output. The output tree stayed at 4.1 MB.
  - A valid `0600` app passed every check.
- A first local run failed in host acceptance on Harbor's list-shaped manifest.
  This was fixed, and `accept_rejected` gained offline tests.

CI evidence for this change is pending. Remaining limits:
- Harbor still uploads the agent's bind-mounted `/logs/artifacts` directory
  itself.
- Storage is bounded only by the host.

No model calls, spending or hostile-candidate execution are authorized. Next:
owner review of the M2 evidence, then a dedicated worker host and an approved
budget before any agent runs.
