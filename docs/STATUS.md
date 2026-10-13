# Current status and next handoff

Updated: 2026-10-13. Stage: M0 concrete reference defaults; M1 identity and HTTP recovery slice.

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

No production identity provider, sealed-artifact provenance, protected holdout verifier, hostile-workload isolation, Harbor/GEPA adapter, durable run store, paid execution or benchmark result. The public verifier is fixed to the synthetic dataset and trusts the harness to supply the app's actual runtime DSN. Core commands remain dependency-free; reference dependencies are optional.

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
