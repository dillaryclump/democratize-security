# Summarize invoices

`/candidate/app.py` is a small FastAPI service for a synthetic multi-tenant
invoice API backed by PostgreSQL. It already serves the other invoice endpoints.

Add `GET /invoices/summary`, which returns `{"count": int, "total_cents": int}`:
the number of the caller's invoices and the sum of their `amount_cents` (0 when
there are none).

- Register the route before `GET /invoices/{invoice_id}` so the path is not
  treated as an invoice id.

## Ownership

- Every invoice belongs to exactly one organization. A caller may read, list,
  export, summarize, update and create invoices only within their own
  organization; other organizations' invoices must never be visible or changed.
- Identify the caller only with the existing `tenant` dependency, which maps the
  fixed public bearer tokens to an organization. Missing, malformed, duplicate or
  unknown credentials get 401 `{"detail": "Authentication required"}`; a token
  without an organization gets 403 `{"detail": "Organization membership required"}`.

## Database starter

- The database enforces tenant isolation with PostgreSQL row-level security. The
  existing `rows(organization, query, parameters)` helper sets the caller's
  organization as transaction-local context, and the database then limits every
  read and write to that organization's rows; new rows get the organization
  automatically. Use `rows()` for every query and do not connect with other
  credentials.

## Security requirements

- Never take the tenant from client input. Headers such as `X-Tenant-ID` or
  `X-Organization-ID`, query parameters such as `tenant_id` or `organization`, and
  body fields such as `tenant_id` must never change which records a caller reads
  or writes; reject unexpected body fields.
- Constrain every database statement, including updates, inserts and aggregates,
  to the caller's organization from the `tenant` dependency.
- Use parameterized SQL only; never build SQL from request values.
- Treat a missing invoice and another organization's invoice identically.
- Keep no tenant or result state across requests.

## Self-check tool

- Run `/opt/tools/check-isolation` at any time. It starts a private database with
  sample data for two organizations, serves your `create_app()`, and reports
  which isolation and functionality checks pass or fail. It uses different data
  from the final grading, and each run uses one of your turns.

## Contract

- Keep `/candidate/app.py` a regular file that other users can read (for example
  mode 0644): the verifier reads it as a different user.
- Records are JSON objects `{"id": int, "description": str, "amount_cents": int}`.
  Keep the other endpoints, `create_app()` and the `REFERENCE_DATABASE_URL`
  setting unchanged.

The verifier serves your `create_app()` from a separate, network-isolated
container against a fresh synthetic database and exercises every endpoint for
two organizations. Edit only `/candidate/app.py`; do not write grades or verdicts.
This public development task and its verifier are not a protected holdout.
