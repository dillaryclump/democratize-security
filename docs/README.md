# Documentation index

Most pages here were written as their milestone landed, and many open with a status line that describes that moment. For the current state, trust [STATUS.md](STATUS.md) and [RESULTS.md](RESULTS.md) first. Where an older page disagrees with them, the older page is out of date.

## Start here

| Page | What it answers |
| --- | --- |
| [PROJECT.md](PROJECT.md) | Why the project exists, its first deliverable and its explicit non-goals |
| [RESULTS.md](RESULTS.md) | Every model run so far: counts, costs, deviations and what can be concluded |
| [STATUS.md](STATUS.md) | What is implemented, what is blocked, which decisions are open and what comes next |
| [ROADMAP.md](ROADMAP.md) | The milestone gates, Foundation and M0 to M7, and the evidence each one requires |
| [../CHANGELOG.md](../CHANGELOG.md) | What was built, by milestone, with pull request numbers |

## Design and trust boundaries

| Page | What it answers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The three authority domains (controller, candidate worker, verifier), components and runtime flow |
| [THREAT_MODEL.md](THREAT_MODEL.md) | The tenant-isolation property, the access matrix, exclusions and the research-infrastructure threat model |
| [CONTRACTS.md](CONTRACTS.md) | The campaign file format and compatibility rules |
| [decisions/](decisions/) | Architecture decision records, listed [below](#decision-records) |

## The reference app and the verifier

| Page | What it answers |
| --- | --- |
| [REFERENCE.md](REFERENCE.md) | The synthetic invoice API's access contract, what the verifier proves and does not prove, and how to reproduce it with PostgreSQL |
| [EVIDENCE.md](EVIDENCE.md) | How verifier reports are validated and serialized into canonical evidence |
| [ARTIFACTS.md](ARTIFACTS.md) | The sealed-artifact format: allowlisted files, size limits and SHA-256 identity |

## Running agent tasks under isolation

| Page | What it answers |
| --- | --- |
| [HARBOR.md](HARBOR.md) | The first Harbor integration: one RLS policy task with a separate verifier |
| [SEALED_REPLAY.md](SEALED_REPLAY.md) | Grading pre-existing sealed bytes in a fresh verifier |
| [HARBOR_AUDIT.md](HARBOR_AUDIT.md) | The host-observed audit of Harbor's containers, the trusted collector, bounded storage and the remaining gaps |
| [APPLICATION_TASKS.md](APPLICATION_TASKS.md) | The three application tasks, their unsafe controls and their container layout |
| [TERMINUS_CONFORMANCE.md](TERMINUS_CONFORMANCE.md) | A model-free test that Harbor's Terminus2 agent loop works through the audited boundary |
| [WORKER_PROBE.md](WORKER_PROBE.md) | A small Docker probe of host controls, independent of Harbor |
| [WORKER_HOST.md](WORKER_HOST.md) | Preparing a dedicated Linux worker with one bounded filesystem per trial |

## The ledger

| Page | What it answers |
| --- | --- |
| [PERSISTENCE.md](PERSISTENCE.md) | The SQLite ledger contract, store versions 1 to 8, budgets and the attempt lifecycle |
| [RUNTIME_AUTH.md](RUNTIME_AUTH.md) | How a verifier report is bound to a per-request challenge before it is admitted |
| [RECOVERY.md](RECOVERY.md) | The pure function that turns a crash observation into inspection advice |
| [BACKUP.md](BACKUP.md) | Verified offline backup and restore of the ledger and its objects |

## Experiments

| Page | What it answers |
| --- | --- |
| [RESEARCH_PROTOCOL.md](RESEARCH_PROTOCOL.md) | The research question, the four conditions, measurements and integrity rules |
| [MODEL_BATCH.md](MODEL_BATCH.md) | The model choice, prices and the exact offline cost estimator |
| [CALIBRATION.md](CALIBRATION.md) | The metered transport and the six-trial calibration |
| [PILOT_PROTOCOL.md](PILOT_PROTOCOL.md) | The pre-registered 48-trial pilot protocol. Frozen: do not edit |
| [RESULTS.md](RESULTS.md) | What the calibration and the pilot actually produced |

## Working on the project

| Page | What it answers |
| --- | --- |
| [../AGENTS.md](../AGENTS.md) | The operating rules for AI agents and humans changing this repository |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute and what a pull request must contain |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Local setup, the routine workflow and the repository settings |
| [COORDINATION.md](COORDINATION.md) | How concurrent agent sessions claim work and avoid overwriting each other |
| [HANDOFF_TEMPLATE.md](HANDOFF_TEMPLATE.md) | The template for a substantial handoff |
| [SOURCES.md](SOURCES.md) | Where the plans came from and the primary references |
| [STATUS_HISTORY.md](STATUS_HISTORY.md) | Superseded status pages, archived verbatim with their revisions |
| [superpowers/](superpowers/) | Implementation plans and one design spec written by agents before larger changes. Historical: they describe intent at the time, not current behavior |

## Decision records

| ADR | Decision |
| --- | --- |
| [0001](decisions/0001-modular-python-foundation.md) | One modular Python repository |
| [0002](decisions/0002-licensing.md) | Apache License 2.0 |
| [0003](decisions/0003-synthetic-reference-contract.md) | Concrete defaults for the synthetic reference |
| [0004](decisions/0004-persistence-recovery.md) | Durable intent and conservative crash recovery |
| [0005](decisions/0005-runtime-verifier-nonces.md) | Ephemeral verifier nonces and conservative crash handling |
| [0006](decisions/0006-controller-generations.md) | Durable controller generations and fenced writes |
| [0007](decisions/0007-runtime-ledger.md) | Runtime attempts in the shared ledger with fenced restores |
