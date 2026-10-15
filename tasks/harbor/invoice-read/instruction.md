# Read one invoice

`/candidate/app.py` is a small FastAPI service for a synthetic multi-tenant
invoice API backed by PostgreSQL. Add the missing endpoint
`GET /invoices/{invoice_id}`, which returns the caller's invoice with that id.

- `invoice_id` is an integer from 1 to 2147483647; other values get 422.
- An invoice that does not exist and one that belongs to another tenant both
  get 404 `{"detail": "Invoice not found"}`, indistinguishably.
- Register the route after `GET /invoices/export` so the export path keeps
  working.

## Contract

- Identify the caller only with the existing `tenant` dependency, which maps
  the fixed public bearer tokens to an organization. Missing, malformed,
  duplicate or unknown credentials get 401
  `{"detail": "Authentication required"}`; a token without an organization
  gets 403 `{"detail": "Organization membership required"}`.
- Never take the tenant from client input. Headers such as `X-Tenant-ID` and
  query parameters such as `tenant_id` or `organization` must not change which
  records a caller sees.
- Read invoices only through the existing `rows()` helper. It sets the tenant
  as transaction-local PostgreSQL context, and row-level security then limits
  the restricted runtime role to that tenant's rows. Do not cache results
  across requests or connect with other credentials.
- Records are JSON objects
  `{"id": int, "description": str, "amount_cents": int}`. Keep the other
  endpoints, `create_app()` and the `REFERENCE_DATABASE_URL` setting unchanged.

The verifier serves your `create_app()` from a separate, network-isolated
container against a fresh synthetic database and exercises every endpoint for
two tenants. Edit only `/candidate/app.py`; do not write grades or verdicts.
This public development task and its verifier are not a protected holdout.
