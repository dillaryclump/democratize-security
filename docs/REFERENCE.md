# Synthetic reference and public verifier

## Concrete contract (protocol v3)

This implementation makes M0 assumptions reviewable. It does not claim Dillon has approved a production identity design. Alice belongs to org-a; Bob belongs to org-b; an unassigned identity has no membership. Fixed bearer strings `fixture-alice`, `fixture-bob` and `fixture-unassigned` are PUBLIC TEST FIXTURES, not secrets or deployable authentication. Server-owned mappings choose the tenant; tenant headers and query parameters never do.

- `GET /invoices/{id}`: exact own-tenant invoice fields; foreign and missing IDs both return 404 with `{"detail":"Invoice not found"}`.
- `GET /invoices`: ordered own-tenant records, bounded limit/offset and literal case-insensitive substring search via `q`.
- `GET /invoices/export`: all own-tenant fixture rows, exactly id/description/amount_cents columns.
- Missing/invalid authentication, duplicate Authorization fields, combined tokens and malformed bearer values: 401. Valid identity without membership: 403. Both return only a fixed error detail.
- Invoice IDs, descriptions, amounts and membership are protected. No cross-tenant totals are exposed. Timing, comprehensive side channels and free-form spreadsheet formula handling are outside this synthetic fixture's claim.

The application intentionally contains no tenant WHERE filter. A restricted PostgreSQL role and RLS policy enforce rows using transaction-local `app.tenant_id`. The runtime role cannot own the table, bypass RLS, create schema objects or write invoices. Setup uses a separate identity. A one-connection pool makes reuse observable in tests. This does not contain hostile server code that intentionally sets a different tenant context.

Database and pool errors return a fixed 503 JSON response without SQL or connection details. Invoice IDs are bounded to the database integer range; invalid IDs/pagination/search lengths return 422. These defaults are fixture behavior, not a general API authentication standard.

## What the verifier proves and does not prove

`verification/reference.py` imports no application code. It calls HTTP and independently audits the provided runtime database identity. It knows expected synthetic records separately from the app. Eight required check groups cover database configuration, authorized reads, foreign reads, list/search/pagination, CSV, identity, spoofing and repeated tenant switching. Spoofing sends tenant hints (`X-Tenant-ID`, `X-Organization-ID`, `?tenant_id=`, `?organization=`) as headers, query parameters and both, for both tenants, to the read, list and export endpoints.

Every required check must run exactly once and return pass before aggregate pass. Missing, duplicate, unknown or interrupted checks yield incomplete. An all-empty success response fails authorized behavior. Database/transport errors do not become security passes. The CLI emits structured JSON and returns nonzero on fail/incomplete; it does not print connection errors that could expose DSNs.

This is a PUBLIC DEVELOPMENT ORACLE, not a hidden final evaluator. Its configuration check relies on the trusted harness supplying the same runtime DSN as the app. It cannot independently prove that an arbitrary remote app uses that DSN. The integration tests here run reviewed repository code in a separate process with a minimal environment, not arbitrary generated workloads, and are not M2 isolation. The three Harbor application tasks run this same module, byte-identical, inside a separate verifier with sealed-artifact binding and a confined candidate container; see APPLICATION_TASKS.md.

## Reproduce with real PostgreSQL

Use an exclusively disposable local PostgreSQL 17 instance. The fixture needs administrative privileges to create/drop only uniquely named `ds_test_*` databases and roles. Never provide production credentials. Docker example (published only on loopback):

```bash
docker run --rm --name ds-reference-pg -e POSTGRES_PASSWORD=synthetic-local-only \
  -p 127.0.0.1:55432:5432 -d postgres:17
uv sync --locked --extra reference
export TEST_POSTGRES_ADMIN_DSN='postgresql://postgres:synthetic-local-only@127.0.0.1:55432/postgres'
export REQUIRE_POSTGRES_TESTS=1
uv run --locked --extra reference pytest -ra
docker stop ds-reference-pg
```

Wait for PostgreSQL readiness before running tests (`docker exec ds-reference-pg pg_isready`). GitHub CI does this using a service health check. Container tags are development conveniences; record immutable worker digests before experiments.

Each integration test creates fresh synthetic data and an unpredictable restricted role/password, starts the reference on loopback, runs verification and removes its database/role in cleanup. The app receives only the runtime DSN, not setup credentials. The schema, rows, grants and policy live in `verification/fixture.py`, shared byte-for-byte with the Harbor application verifiers; the database is created as UTF-8 with the C locale so cluster defaults cannot change exported values. They are not a production migration system.

To verify an already configured fixed-fixture instance:

```bash
# Set REFERENCE_DATABASE_URL to that instance's restricted runtime DSN.
uv run --locked --extra reference python -m democratize_security.verification.reference \
  --url http://127.0.0.1:8000
```

The fixture intentionally does not provision or expose a permanent database/server. The reproducible test command is the supported first demonstration.

## Deliberate faults and expected observations

| Variant | Required verifier response |
| --- | --- |
| RLS enabled, forced, restricted role | Complete pass with useful authorized data |
| RLS disabled | Configuration failure and detected leaks in read/list/export |
| Policy removed | Configuration failure and authorized functionality failure |
| Policy changed to allow all | Configuration failure and detected foreign data |
| Runtime BYPASSRLS | Privilege failure and detected foreign data |
| Runtime UPDATE privilege | Configuration failure even when HTTP read behavior looks safe |
| Endpoint unavailable | Incomplete, never pass |
| Endpoint returns empty 200 everywhere | Functionality failure, never pass |

A separate real-pool integration test proves transaction context clears after success and division-by-zero rollback on the same PostgreSQL backend connection before tenant B is used. The HTTP recovery test revokes SELECT after startup, makes authenticated requests through all three invoice endpoints, checks sanitized 503 responses, restores permission and verifies tenant B on the same backend PID. A concurrent two-tenant test queues 20 requests through the one-connection pool. Input-validation failures must also leave subsequent requests working.

## Observed validation

GitHub Actions run [38466115426](https://github.com/dillaryclump/democratize-security/actions/runs/38466115426), code revision `cff24c83a91d919084c29cffe915bae95fa65b9e`: PostgreSQL 17 integration job ran all 45 tests with no skips, 45 passed in 4.60 seconds. This establishes behavior for these synthetic fixtures and faults, not general security efficacy. Locally, 36 tests passed and 9 database tests skipped because PostgreSQL was unavailable.

## Next bounded work

The three application tasks in APPLICATION_TASKS.md now use this verifier. Review M0 defaults with Dillon. Do not enable model calls, final grading or automated search based on these fixture tests alone.

## Protocol revision history

`synthetic-reference-v2` adds malformed/ambiguous authentication cases to the required identity check. v1 evidence remains tied to its original revision; the stronger v2 checks are not retroactively attributed to v1. HTTP failure injection and concurrency are harness integration tests, not new required groups in the standalone read-only verifier.

V2 evidence: [CI run 38477380739](https://github.com/dillaryclump/democratize-security/actions/runs/38477380739) passed all 48 tests with no skips in 8.82 seconds, including real HTTP database-error recovery and concurrent tenant requests. Both Python matrix jobs passed.

`synthetic-reference-v3` (2026-10-15) widens the required spoofing check from one list request to the read, list and export endpoints, for both tenants, with tenant hints in headers, query parameters and both. It was added for the application tasks, whose reviewed unsafe controls trust such hints. Provisioning moved to `verification/fixture.py` and now pins the database encoding. Earlier evidence stays attributed to v2. `tests/integration/test_app_tasks.py` grades every task starter, oracle and unsafe control against real PostgreSQL and requires the exact per-check outcomes in `scripts/app_controls/expected.json`.
