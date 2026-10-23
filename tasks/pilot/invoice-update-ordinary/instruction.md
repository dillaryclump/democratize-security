# Update an invoice

`/candidate/app.py` is a small FastAPI service for a synthetic multi-tenant
invoice API backed by PostgreSQL. It already serves the other invoice endpoints.

Add `PATCH /invoices/{invoice_id}`, which changes the caller's invoice and
returns the updated record with status 200.

- The JSON body may contain only `description` (a string of 1 to 200
  characters) and/or `amount_cents` (an integer from 0 to 1000000000), and at
  least one of them. Any other key or invalid value gets 422. The existing
  `InvoiceUpdate` model implements these rules.
- An invoice that does not exist and one that belongs to another organization both
  get 404 `{"detail": "Invoice not found"}`, indistinguishably, and nothing changes.

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
