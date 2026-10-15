# Current status and next handoff

Updated: 2026-10-14. Stage: M2 runner integration, not complete.
Earlier evidence and failures: [STATUS_HISTORY.md](STATUS_HISTORY.md).

## Implemented

- Offline versioned campaign validation and deterministic planning.
- Synthetic FastAPI invoice reads, list/search and CSV, PostgreSQL RLS, restricted
  runtime identity and independent public HTTP/database checks. See REFERENCE.md.
- Bounded artifact sealing and evidence identity. See ARTIFACTS.md.
- Reviewed offline container capability probe. See WORKER_PROBE.md.
- Harbor 0.24.0 separate verification and fresh sealed policy replay. See
  HARBOR.md and SEALED_REPLAY.md.
- Pinned base images, reviewed container hardening, nonce-authenticated evidence
  and host-observed boundary audit v2. See HARBOR_AUDIT.md.
- Invoice-read task contract and three reviewed application controls, each
  replayed twice from sealed app.py in fresh subprocesses. All eight independent
  checks remain required. See INVOICE_READ_TASK.md.
- Disposable test databases explicitly use template0 and UTF8.

## Verification

Merged baseline main bfff0e23 passed all five CI jobs in
[38641811392](https://github.com/dillaryclump/democratize-security/actions/runs/38641811392).
The hardened audit passed 10/10 checks, policy controls/replays matched and the
grade-forgery control was rejected.

Invoice-read slice: local Python 3.12 with reference dependencies has 161 passing
tests and 23 infrastructure skips; core-only has 154 passing tests and 24 skips.
Ruff and package build pass. CI [38665693361](https://github.com/dillaryclump/democratize-security/actions/runs/38665693361)
at d7f285904456943c84bcef99400661b5f241857d passed all five jobs. PostgreSQL:
177 passed, 7 Docker-only skipped. All three application controls replayed twice
with exactly the intended outcomes; UTF8 assertion passed. The dedicated Docker
probe and existing hardened Harbor controls/replay/audit also passed.

## Immediate next task

Connect invoice-read to Harbor using a separate restricted application runtime.
Application code must not execute in the trusted verifier or receive its nonce.
Keep sealed replay, independent HTTP/database checks and the boundary audit.
Then add list/search and export task families. Neither the policy fixture nor
the process-only application regressions satisfy the three-task M2 gate.

## Remaining limitations and later gates

- Reviewed controls only; generated/hostile candidates are not authorized.
- Shared verifier-log mount remains, mitigated by nonce/HMAC acceptance checks.
  Writable-volume storage limits remain unenforced; apt build packages are mutable.
- No durable run store, budget accounting or crash recovery (M3), comparative
  pilot (M4), GEPA search (M5), protected final assessment (M6), or production
  identity integration. No benchmark improvement is claimed.
- Dedicated-worker policy, finite model budget and M0 acceptance remain required
  before model execution. License and repository protections are owner decisions.

## Handoff discipline

Keep this a current snapshot. Preserve superseded observations in the history,
not contradictory pending statements here. Record revisions, actual checks,
skips and limitations. Never relabel historical results.

## In-progress container integration

The invoice-read controls now have a dedicated Harbor nop replay runner with a
separate app container. All IP networking is disabled; database and HTTP traffic
use narrowly shared Unix sockets. The app receives no verifier code, nonce or
log mounts. Locked image/dependency inputs, complete HTTP/database checks and
host-observed app-boundary checks are implemented. See INVOICE_CONTAINER.md.
Local: 173 passed, 23 skips; Ruff and generated-task schema checks pass. Live CI
pending. This is reviewed application replay, not general agent task generation
or completion of the three-task M2 gate.
