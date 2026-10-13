# Current status and next handoff

Updated: 2026-10-13. Stage: repository foundation; M0 draft.

## Implemented

- Python 3.12/3.13-compatible, dependency-free runtime package.
- Strict v1 campaign parsing, finite-value checks, split-family consistency and trial limits.
- Deterministic offline `research validate` and `research plan` commands.
- Zero-budget synthetic campaign with three placeholder development tasks and four conditions.
- Unit/CLI tests, dependency lock, lint/format CI, dev container, contribution templates.
- Canonical shared agent guide and architecture/research/security handbooks.

## Not implemented

No FastAPI invoice app, RLS enforcement, PostgreSQL verifier, model integration, Harbor/GEPA adapter, worker isolation, durable run store, spending enforcement, benchmark runs or security score. CI tests foundation behavior only. A valid plan is not an executable or approved experiment.

## Foundation verification

Locally verified with Python 3.12.14: 29 tests passed; Ruff lint and formatting passed; the example validated as 12 offline trials; source distribution and wheel built successfully. Remote CI and an actual Codespaces launch require separate verification. No PostgreSQL or security integration tests exist yet.

## Decisions still needed

1. Approve M0 access contract, including 403/404 and protected metadata semantics.
2. Choose first trusted identity integration and define membership lookup failure behavior.
3. Choose dedicated worker host and prove isolation on that environment.
4. Select model access method and approve a finite API/compute budget for an integration spike.
5. Choose project license before external distribution; no license has been applied.
6. Enable repository rules and private vulnerability reporting through repository settings where supported.

## Next task

M0 review followed by M1 reference/vulnerable invoice fixtures and independent verifier against actual PostgreSQL. See `ROADMAP.md`. Do not infer that planned paths or example hashes refer to existing implementations.

## Handoff discipline

When a capability ships, update this file with exact commands and observed verification, remaining limitations and the next gate. Preserve negative outcomes in research records. Describe work in the PR rather than declaring the entire project complete.
