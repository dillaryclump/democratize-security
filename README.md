# Democratize Security

[![CI](https://github.com/dillaryclump/democratize-security/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dillaryclump/democratize-security/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.12 and 3.13](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue.svg)
![Status: research prototype](https://img.shields.io/badge/status-research%20prototype-orange.svg)

An open research harness for one question: **when an AI coding agent writes a feature, is the result both working and secure, and does giving the agent a small security integration change that?**

The first security property is tenant isolation in a multi-tenant web API, built on FastAPI and PostgreSQL row-level security (RLS). An agent adds one endpoint to a synthetic invoice service. An independent verifier then checks that each organization can still use its own invoices and can never read or change another organization's. Cross-tenant leaks of this kind are a form of broken access control, also known as IDOR or BOLA.

> **Status: research prototype.** The measurement pipeline is built, tested and has run real model trials. It has **not** shown that the security integration improves anything. In the trials run so far, every condition passed every check, including the plain baseline, which gets only the feature and ownership requirements. Nothing here is a production security control. See [Results so far](#results-so-far) and [What this does not claim](#what-this-does-not-claim).

## Why this exists

AI coding tools can produce software that works and still leaks data between customers. The project's hypothesis is that a small, inspectable integration (a database-enforced starter, clear instructions and a self-check the agent can run) raises the rate of code that is both functional and secure, and that this can be measured honestly on a small budget. The name is the goal: strong, checkable protection for builders who cannot afford a security team.

Most of the work so far went into the measurement, because a security claim is only as good as the evaluation behind it. A null or negative result is an accepted outcome of this project.

## What is in this repository

| Piece | What it does | Where |
| --- | --- | --- |
| Reference invoice API | A FastAPI service whose tenant isolation is enforced by PostgreSQL RLS and a restricted database role, with no tenant filter in application code. A second variant isolates tenants in application code against a plain database. | `src/democratize_security/reference/`, `src/democratize_security/pilot/` |
| Independent verifier | A black-box grader. It imports no application code, calls the API over HTTP, audits the database role and policies, and inspects response bodies and CSV contents. A check that did not run makes the result incomplete, never a pass. Protocol v3 has 8 required checks and v4 has 10. | `src/democratize_security/verification/`, `src/democratize_security/pilot/verify.py` |
| Deliberately unsafe controls | Reviewed vulnerable implementations, such as trusting an `X-Tenant-ID` header or caching results without the tenant in the key. Each must fail the verifier for its intended reason. | `scripts/app_controls/`, `src/democratize_security/pilot/controls/` |
| Agent tasks | Four development tasks (one RLS policy task and three that add a missing endpoint) and 24 pilot variants (6 scenario families × 4 conditions) for the [Harbor](https://docs.harborframework.com/) agent runner. Each pilot variant asks an agent to add one missing endpoint. | `tasks/harbor/`, `tasks/pilot/` |
| Evaluation boundary | The agent works in a container with no network. After it stops, a trusted collector extracts one allowlisted file, which is sealed under a SHA-256 identity and replayed in a fresh, separate verifier. A host-side audit records how Docker actually configured every container. | `scripts/harbor_*.py`, `src/democratize_security/adapters/runners/` |
| Durable ledger | A SQLite store with immutable events for every trial: budget reservations, each model request, sealed artifacts, authenticated verifier results, crash-recovery state, backup and restore. | `src/democratize_security/store.py` and neighbours |
| Metered model access | A controller-side broker that reserves a cost ceiling before each model request, sends it exactly once and settles from reported usage. The provider key never enters the agent's environment. An unknown outcome stops the batch. | `src/democratize_security/model_*.py` |
| Experiment tooling | Campaign validation and planning (`research` CLI), a calibration driver, the pilot runner and a report generator that reads only the ledger. | `src/democratize_security/cli.py`, `scripts/` |
| Worker host tooling | Scripts that give each trial its own size-bounded filesystem on a dedicated Linux worker, plus a host capability check. | `infra/worker/`, `scripts/worker_host.py` |

## How one trial is graded

```mermaid
flowchart LR
  T[Task: add one endpoint] --> A[Agent container, no network]
  A -->|agent stops| C[Trusted collector]
  C --> S[Sealed app.py, SHA-256]
  S --> V[Fresh verifier and fresh database]
  V --> R[Authenticated report]
  R --> L[(Ledger)]
  A -->|metered model requests| B[Model broker, holds the API key]
  B --> L
```

1. The controller records the trial's cost ceiling and its intent to dispatch before anything starts.
2. The agent edits `/candidate/app.py` inside a container that has no network. Its model requests go through the broker, which meters each one.
3. After the agent's container stops, a trusted collector copies out that single file. Nothing the agent wrote about its own grade is trusted.
4. The file is sealed and replayed in a new verifier container against a fresh synthetic database the agent never saw.
5. The controller checks the verifier's evidence against a nonce issued for that run, signs the report and admits it to the ledger through an authenticated path. Then it settles the cost.

The design and its limits are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Results so far

Full tables, provenance and deviations are in [docs/RESULTS.md](docs/RESULTS.md).

| Run | Date | Trials | Outcome | Model cost (upper bound) |
| --- | --- | --- | --- | --- |
| Model-free controls | in CI; last full pass 2026-11-03 | 84 control trials across the 24 pilot variants | Reference solutions pass; unchanged starters and unsafe controls fail the reviewed checks | none |
| Calibration | 2026-10-23 | 6 of 6 (3 tasks × 2 models) | 6 passed all 8 checks | $0.27 |
| Pilot | 2026-10-23 | 20 of 48 graded, 1 interrupted, 27 not run | 20 passed all 10 checks: 5 of 5 in each of the four conditions | $1.07 |

The pilot is **incomplete**. The worker's virtual machine stopped partway through, and the run has not been resumed. Under the pre-registered rule that unrun trials count as non-success, the joint success rate is 20 of 48, and 5 of 12 in every condition.

What the graded trials show is that the pipeline works end to end for about five cents a trial, and that **no difference between conditions was observed**. The baseline, with no security guidance, no database protection and no self-check, passed everything it attempted, so these tasks do not yet separate the conditions for the model tested. That is a finding about the task set, not evidence that the integration helps or that AI-written code is safe.

**Known breakage, 2026-11-15.** The agent image for the six `full_tool` pilot variants no longer builds, because Debian replaced the exact PostgreSQL package version it pins. The CI jobs `pilot-controls` and `metered-dry-run` fail for that reason on every branch, so the CI badge above is red. Those jobs last passed on 2026-11-03. The other three conditions, the application tasks and grading are unaffected. See [#84](https://github.com/dillaryclump/democratize-security/issues/84).

## Quick start

You need Python 3.12 or 3.13 and [uv](https://docs.astral.sh/uv/getting-started/installation/). The code is POSIX-only and CI runs on Ubuntu. Use Linux or WSL2; it does not import on native Windows. macOS is not covered by CI.

**1. Offline checks.** No Docker, database, model access or money:

```bash
git clone https://github.com/dillaryclump/democratize-security.git
cd democratize-security
uv sync --locked
uv run --locked pytest
uv run --locked research validate campaigns/pilot.v1.json
uv run --locked research plan campaigns/pilot.v1.json
```

Without PostgreSQL and Docker, the integration tests skip and say so. A skipped test is not evidence.

**2. The verifier against real PostgreSQL.** This runs the reference app and every deliberately unsafe variant against a disposable PostgreSQL 17:

```bash
docker run --rm --name ds-reference-pg -e POSTGRES_PASSWORD=synthetic-local-only \
  -p 127.0.0.1:55432:5432 -d postgres:17
uv sync --locked --extra reference
export TEST_POSTGRES_ADMIN_DSN='postgresql://postgres:synthetic-local-only@127.0.0.1:55432/postgres'
export REQUIRE_POSTGRES_TESTS=1
uv run --locked --extra reference pytest -ra
docker stop ds-reference-pg
```

See [docs/REFERENCE.md](docs/REFERENCE.md) for the access contract and the table of faults the verifier must catch.

**3. Model-free agent-runner controls.** These need a disposable Linux Docker host. No model or API key is involved:

```bash
uv sync --locked --group harbor
uv run --locked --group harbor python scripts/harbor_apps.py invoice-read
uv run --locked --group harbor python scripts/calibration.py --dry-run
```

The first command runs the reference, unchanged-starter and unsafe controls for one application task, with sealed replays and boundary audits. The second runs one scripted agent trial through the full metered lifecycle. See [docs/APPLICATION_TASKS.md](docs/APPLICATION_TASKS.md) and [docs/HARBOR_AUDIT.md](docs/HARBOR_AUDIT.md).

The pilot's equivalents are `scripts/pilot_controls.py FAMILY` and `scripts/pilot.py --dry-run`. Until [#84](https://github.com/dillaryclump/democratize-security/issues/84) is fixed they fail when they reach a `full_tool` variant.

Live model runs spend money and are refused unless they run on a prepared dedicated worker with a clean checkout and an approved budget. See [docs/CALIBRATION.md](docs/CALIBRATION.md) and [docs/PILOT_PROTOCOL.md](docs/PILOT_PROTOCOL.md).

## Who might find this useful

- **People evaluating AI coding agents for security.** The verifier, the unsafe controls and the sealed-replay boundary are a worked example of grading agent output without trusting the agent.
- **People building multi-tenant APIs on PostgreSQL.** The reference app shows RLS with a restricted role and transaction-scoped tenant context, and the verifier checks the cases that are easy to miss: pooled connection reuse, failed transactions, spoofed tenant headers and CSV exports.
- **People building evaluation harnesses.** The ledger, the per-request cost metering and the crash-recovery rules are independent of this security property.
- **People running small experiments with a fixed budget.** The pilot protocol was frozen before the first trial and counts every scheduled trial, including the ones that never ran.

## What this does not claim

- **No demonstrated security benefit.** No completed experiment compares the conditions. The trials graded so far show no difference between them.
- **Not a production control.** The reference app is a synthetic fixture. Its fixed bearer tokens (`fixture-alice`, `fixture-bob`) are public test values, not authentication.
- **Not a protected benchmark.** Every task and the verifier are public, and the same author wrote the tasks, the instructions and the verifier. There is no hidden holdout set.
- **Not a hardened sandbox.** Containers share the host kernel, and two documented verifier-side isolation gaps remain. The boundary was built for reviewed and model-generated development tasks, not hostile code.
- **Narrow scope.** One property, one framework, one database, one model family and small single-endpoint tasks.
- **Not a released package.** Nothing is published to PyPI and there is no tagged release.

## Repository map

| Path | Contents |
| --- | --- |
| `src/democratize_security/` | Contracts, CLI, ledger, artifact and evidence storage, model metering, the reference apps and verifiers |
| `scripts/` | Runners for the Harbor controls, boundary audit, calibration, pilot and report |
| `tasks/harbor/` | Four hand-written Harbor development tasks |
| `tasks/pilot/` | 24 generated pilot variants. Regenerate them with `scripts/build_pilot_tasks.py`; do not edit them by hand |
| `campaigns/` | Frozen campaign definitions and cost proposals |
| `tests/` | Unit tests, plus integration tests that need PostgreSQL, Docker or Harbor |
| `infra/worker/` | Dedicated worker bootstrap and host checks |
| `docs/` | Architecture, threat model, protocols, results, decisions and status |
| `candidates/` | Reserved for a shippable product integration. Empty today |

## Documentation

Start with the [documentation index](docs/README.md). The most useful entry points:

- [Project brief](docs/PROJECT.md): purpose, scope and non-goals.
- [Results](docs/RESULTS.md): every model run, with counts, costs and deviations.
- [Status](docs/STATUS.md): what is implemented, what is blocked and what comes next.
- [Roadmap](docs/ROADMAP.md): milestone gates M0 to M7. The project is partway through M4.
- [Changelog](CHANGELOG.md): what was built, by milestone.

## How this project is built

The owner sets the architecture, security assumptions, budget and acceptance. AI coding agents write and test the scoped changes under those rules, and every change lands through a reviewed pull request with recorded evidence. The operating rules are public in [AGENTS.md](AGENTS.md) and [docs/COORDINATION.md](docs/COORDINATION.md). The planning and handoff documents are kept in the repository so that the process can be inspected along with the code.

## Contributing, security and license

- Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). The `*-unsafe.py` files are intentional negative controls, not bugs.
- Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
- To cite the project, use [CITATION.cff](CITATION.cff).
