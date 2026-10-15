# Invoice-read development task, v1

Implement GET /invoices/{invoice_id} in the synthetic FastAPI application.
Only edit app.py. Keep the list/search and CSV routes working.

Authentication uses the public fixture tokens defined in the starter. Resolve
organization membership from that server-owned mapping. A caller must receive
the complete expected invoice only when it belongs to their organization.
Foreign and missing invoices must both return 404 with exactly
`{"detail":"Invoice not found"}`. Invalid authentication returns 401; a valid
identity without membership returns 403. Client tenant headers/query parameters
cannot change membership. Preserve transaction-local context and restricted
database access. Do not alter database setup, tests or grading.

The independent public verifier is synthetic-reference-v2, including all eight
checks. Passing only the new route is insufficient: list/search, export,
identity and connection reuse remain regression requirements.

This task currently has reviewed application controls and sealed replay tests
against real PostgreSQL. It is not yet dispatched through Harbor. No generated
or hostile app may run in the process-only test harness. The next integration
must keep application execution separate from the verifier and its nonce.
