# Changelog

What was built, grouped by milestone gate, newest first. Numbers refer to pull requests unless marked as an issue. Dates are UTC merge dates.

No version has been tagged or published. Everything below is unreleased development at version `0.1.0.dev0`. For what is implemented right now see [docs/STATUS.md](docs/STATUS.md), and for what the model runs produced see [docs/RESULTS.md](docs/RESULTS.md).

## Public release readiness (2026-11-15)

- Licensed the project under Apache-2.0 and added `NOTICE`, package metadata and `CITATION.cff` (issue #80, [ADR 0002](docs/decisions/0002-licensing.md)).
- Rewrote the README, added a documentation index and a results record, and reconciled the status page with what was actually run.
- Recorded the interrupted pilot, which until then appeared nowhere in the repository.
- Found and filed, but did not fix: the pilot's `full_tool` agent image no longer builds, because Debian replaced the PostgreSQL package version it pins (issue #84). The pilot CI jobs are red until it is fixed.
- No code, test, task or protocol changed.

## M4 Pilot (2026-10-23)

- Four experimental conditions, six scenario families and 24 generated task variants; verifier protocol `synthetic-reference-v4` with write and aggregate checks; the `check-isolation` self-check; model-free controls for every variant; the pilot runner and the ledger-only report; the pre-registered protocol (#72).
- **Run, 2026-10-23:** the 48-trial pilot started and was interrupted when the worker's virtual machine stopped. 20 trials graded and passed, 1 interrupted, 27 not run. No difference between conditions was observed. The pilot is incomplete.

## Model access and calibration (2026-10-20 to 2026-10-23)

- Finite model-batch proposals and an exact offline cost estimator (#60).
- Store v8: every model request is reserved, sent once and settled; a controller-side broker keeps the provider key out of the agent's environment; the calibration driver (#70).
- Calibration job names made to fit the worker helper's rule (#71).
- **Run, 2026-10-23:** six calibration trials, six passes, 27¢ upper-bound cost.

## M3 Persistence (2026-10-16 to 2026-10-20)

- The persistence, budget and crash-recovery contract (#26, [ADR 0004](docs/decisions/0004-persistence-recovery.md)).
- Offline plan import with immutable events and reservation accounting, integrated with the runner (#33).
- Sealed artifact publication made durable before success is reported (#25); a validated artifact object store (#35); immutable attempt-bound artifact references, store v3 (#37).
- Verifier report validation and canonical evidence envelopes (#39); durable evidence objects (#41); the evidence ledger, store v4 (#43); verification intent required before new evidence, store v5 (#45).
- A pure, conservative recovery decision function (#49, #52).
- Verifier reports authenticated against a per-request challenge (#58, [ADR 0005](docs/decisions/0005-runtime-verifier-nonces.md)).
- Verified offline backup and restore (#59).
- Durable controller generations and stale-write fencing, store v6 (#64, [ADR 0006](docs/decisions/0006-controller-generations.md)).
- The runtime attempt lifecycle, authenticated result admission and restore fences, store v7 (#68, [ADR 0007](docs/decisions/0007-runtime-ledger.md)).

Recovery after a crash is still a manual procedure. This gate is partial.

## M2 Runner (2026-10-14 to 2026-10-20)

- A bounded candidate artifact format with a SHA-256 identity (#8).
- An offline restricted-container probe of host controls (#9).
- A pinned Harbor integration with a separate verifier, on one RLS policy task (#10).
- Fresh verification of sealed inputs (#11).
- A host-observed audit of Harbor's container boundary, with a grade-forgery control (#12).
- Hardened task containers and verifier evidence bound to a run nonce (#13).
- Three application tasks with an isolated candidate runtime and reviewed unsafe controls (#16).
- A trusted collector that extracts the submission after the agent stops (#17).
- Complementary tenant-context regression controls (#23).
- Bounded storage for every trial container, audit policy v5 (#31).
- Collector ordering made race-free against the agent's recorded exit (#51, issue #50).
- A dedicated-worker helper that gives each trial its own bounded filesystem (#61).
- Model-free conformance of Harbor's Terminus2 agent loop through the audited boundary (#67).
- **Owner acceptance, 2026-10-20** (issue #19), with two verifier-side gaps recorded as residual limitations.

## M1 Verifier (2026-10-14)

- The synthetic FastAPI invoice reference protected by PostgreSQL row-level security, and the independent public HTTP and database verifier with deliberately unsafe variants (#7, [ADR 0003](docs/decisions/0003-synthetic-reference-contract.md)).

## Foundation (2026-10-13)

- Repository layout, offline campaign contracts and planner, the `research` CLI, CI, and the agent operating handbook (#1, [ADR 0001](docs/decisions/0001-modular-python-foundation.md)).

## Process

- A convention for concurrent agent sessions to claim work, and a reconciled status page (#22, #47).
