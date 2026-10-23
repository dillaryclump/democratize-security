# Read one invoice

`/candidate/app.py` is a small FastAPI service for a synthetic multi-tenant
invoice API backed by PostgreSQL. It already serves the other invoice endpoints.

Add `GET /invoices/{invoice_id}`, which returns the caller's invoice with that id.

- `invoice_id` is an integer from 1 to 2147483647; other values get 422.
- An invoice that does not exist and one that belongs to another organization both
  get 404 `{"detail": "Invoice not found"}`, indistinguishably.
- Register the route after `GET /invoices/export` and `GET /invoices/summary` so
  those paths keep working.

## Ownership

- Every invoice belongs to exactly one organization. A caller may read, list,
  export, summarize, update and create invoices only within their own
  organization; other organizations' invoices must never be visible or changed.
- Identify the caller only with the existing `tenant` dependency, which maps the
  fixed public bearer tokens to an organization. Missing, malformed, duplicate or
  unknown credentials get 401 `{"detail": "Authentication required"}`; a token
  without an organization gets 403 `{"detail": "Organization membership required"}`.

## Database

- Run queries through the existing `rows(query, parameters)` helper. The
  `public.invoices` table has columns `id`, `tenant_id` (the owning
  organization), `description` and `amount_cents`.

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
