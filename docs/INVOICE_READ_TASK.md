# Invoice-read task: reviewed application controls

This slice establishes a public task contract and checks the grader against
application faults, not only unsafe SQL policies. It is a prerequisite to Harbor
application dispatch, not M2 completion.

Instructions: `tasks/application/invoice-read/instruction.md`.
Reviewed starter: `src/democratize_security/reference/app.py`.

| Control | Required result | Purpose |
| --- | --- | --- |
| protected | All eight checks pass | Useful own-tenant access and regressions |
| id_derived_tenant | Only foreign_reads fails | Detect a route leak despite correct database configuration and own reads |
| deny_all | Only authorized_reads fails | Reject security achieved by breaking functionality |

`tests/integration/test_invoice_read_task.py` constructs the reviewed variants
using one checked replacement point. Reference edits that remove or duplicate
that point require review. It seals app.py, replaces the original source with a
crashing sentinel, and runs two fresh processes from separate materializations
of the sealed bytes. The controller never imports submitted code. The existing
independent verifier inspects actual HTTP responses and database configuration,
with all eight checks still required. Post-run sealing checks input stability;
evidence envelopes bind artifact and verifier-source hashes. Replays must agree.

`application_artifacts.materialize_application` validates before writes, permits
exactly app.py, refuses existing destinations and writes the file read-only.
This is byte transfer, NOT containment.

## Reproduce

Set TEST_POSTGRES_ADMIN_DSN for a disposable PostgreSQL server per REFERENCE.md:

```bash
uv sync --locked --extra reference
REQUIRE_POSTGRES_TESTS=1 uv run --locked --extra reference pytest tests/integration/test_invoice_read_task.py -ra
```

The fixture creates a random database/runtime role and removes only those objects.
Database creation uses template0 and UTF8, with a dedicated encoding assertion.
Existing CSV tests retain serialization coverage. CI postgres-reference requires
the infrastructure tests rather than skipping them.

## Boundary and next work

The process-only harness is exclusively for reviewed fixtures. Its minimal
environment supplies only the restricted runtime DSN, but processes share the
host filesystem and kernel. This does not protect tests or host credentials from
hostile code, run Harbor, or prove container isolation. Never use it for generated
submissions. No grading nonce is supplied to the app.

Next put application execution in a separate restricted container, carry sealed
app.py into it, and verify via HTTP and database checks. Reuse Harbor hardening
where applicable and audit any new communication paths. Never execute candidate
code in the nonce-bearing verifier. Keep the eight-check public oracle as
regression coverage. Complete list/search and export task families afterward.
