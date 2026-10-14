# Current status and next handoff

Updated: 2026-10-14. Current work: M2 Harbor integration prerequisite. M2 is not complete; see HARBOR.md and the latest evidence below.

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
