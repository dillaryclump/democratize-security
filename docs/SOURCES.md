# Planning provenance

This repository handbook is a public technical synthesis of these project-owned planning documents, read on 2026-10-13:

- **Tenant Isolation MVP Delivery Timeline** (`Security_Startup_MVP_Timeline.docx`, October 10, 2026): tenant isolation scope, four conditions, 48-run feasibility pilot, model-assisted implementation and acceptance gates.
- **Automated Security Research Architecture**, version 1.0 (`Automated_Security_Research_Architecture.docx`, October 12, 2026): bounded research controller, verifier independence, immutable evidence, Harbor integration gate, GEPA sequencing and revised milestone order.

The October 12 build sequence takes precedence over the earlier estimated calendar. These plans are proposals, not implementation evidence. Earlier XSS-first exploration is historical and is not the current MVP. Private business, family and personal documents are intentionally not required to understand this repository.

## Primary implementation references

These references came from the architecture and should be reread for the exact selected version during each integration. Listing them does not assert that the integrations have been verified.

- [PostgreSQL row security](https://www.postgresql.org/docs/17/ddl-rowsecurity.html)
- [Psycopg pooling](https://www.psycopg.org/psycopg3/docs/advanced/pool.html)
- [Harbor documentation](https://docs.harborframework.com/)
- [Harbor separate verifier](https://docs.harborframework.com/tasks/separate-verifier)
- [Inspect AI tasks](https://inspect.aisi.org.uk/tasks.html)
- [GEPA guides](https://gepa-ai.github.io/gepa/guides/)
- [Hypothesis stateful tests](https://hypothesis.readthedocs.io/en/latest/stateful.html)
- [Schemathesis](https://schemathesis.readthedocs.io/en/stable/explanations/stateful/)
- [Testcontainers Python](https://testcontainers.com/guides/getting-started-with-testcontainers-for-python/)
- [BaxBench](https://github.com/logic-star-ai/baxbench)
- [Last Secure Code Benchmark](https://github.com/alibaba/last-secure-code-benchmark)

For new research claims, inspect current primary sources, pin versions, and record what was actually tested. Never describe an adapted subset as a full official benchmark result.
