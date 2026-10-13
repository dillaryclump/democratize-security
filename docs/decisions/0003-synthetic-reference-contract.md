# ADR 0003: Concrete synthetic reference defaults

Status: implemented for review, 2026-10-13; production identity and final study approval pending.

Choose a server-owned synthetic bearer-token membership map for the first test fixture. Use identical 404 responses for foreign and absent invoices. Return only invoice id, description and integer amount_cents; require exact own-tenant values for functionality. Use literal substring search, deterministic pagination and CSV contents, with real PostgreSQL RLS enforcement and transaction-local context.

This resolves engineering ambiguity without silently choosing an external identity vendor. Public test tokens are unsuitable for production. The reference omits the app tenant filter deliberately to demonstrate the database boundary. Independent HTTP checks and direct runtime-role inspection constitute a public development oracle, not a protected final evaluator.

Consequences: a reproducible, falsifiable starting point with explicit vulnerable variants. No assertion of general secure-code generation, a complete M1 acceptance gate, or hostile-workload isolation. Broader integration requires separately reviewed authentication and artifact/worker boundaries.
