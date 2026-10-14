Repair `/candidate/policy.json` so a restricted runtime role can read all and only
its current tenant's invoices through PostgreSQL row-level security. The trusted
harness supplies the tenant context. Keep useful reads for both tenants.

The declarative format has exactly two fields: `enabled` (boolean) and
`predicate` (one of `tenant`, `all`, `none`). The verifier translates these fixed
choices into SQL; arbitrary SQL and application code are not accepted.

This public infrastructure fixture is not one of the three application tasks
required by the M2 gate. Do not write verdicts or change other files.
