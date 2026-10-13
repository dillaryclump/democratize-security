# Project brief

## Why this exists

AI coding tools can produce working software with insecure authorization and architecture. The hypothesis is that a relatively small independent integration and verification layer can materially improve joint functional/security success. The product should make strong, inspectable protection accessible to builders who cannot afford specialist teams.

The long-term model is an open-source core plus optional paid convenience, hosting, integrations or support. The current engineering goal is to demonstrate added value beyond good instructions and correctly configured existing protection. Customer demand and willingness to pay remain unproven.

## First deliverable

A local, reproducible demonstration with two organizations and synthetic invoices:

1. Show legitimate own-organization invoice reads, search/list and CSV export.
2. Demonstrate a cross-tenant leak in an explicitly vulnerable implementation.
3. Show the protected implementation retains useful behavior after an application tenant filter is removed.
4. Deliberately misconfigure enforcement and show the verifier refuses a green result.
5. Compare ordinary agents, security instructions, an RLS starter and the full tool under matched budgets.

No paid model subscription or API should be necessary to run core verification once implemented. Model-generated feature changes are an optional research input, not the authority that decides security.

## Current strategic choices

- Product property: tenant isolation, not general secure coding.
- Stack: Python/FastAPI and PostgreSQL with row-level security (RLS).
- Operations: read one invoice, list/search, export CSV.
- Identity: one server-controlled membership integration; actual provider unresolved.
- Research: bounded controller with immutable evidence and protected verification.
- Candidate execution: Harbor preferred, subject to an integration gate; Inspect AI is a fallback, not a second simultaneous implementation.
- Search: GEPA only after manually specified interventions can be evaluated reliably.
- Benchmarks: assess compatible BaxBench tasks first; LSCBench later. A subset or transformed task is not a full official benchmark result.

## Explicit non-goals for the first release

Writes, uploads, background jobs, admin exceptions, multiple frameworks, model training, multi-agent research swarms, distributed scheduling, a hosted dashboard and billing. Do not add these merely to make the repository appear future-ready.

## Ownership and constraints

Dillon is the founder and architecture/review owner. Agents implement, test and explain scoped changes. The October delivery plan supersedes the earlier hand-coding preference. Optimize for a small founder team, limited review time, modest compute and portable workflows. API costs are separate from coding-tool subscriptions; no paid-provider configuration has been approved in this foundation.

Success means measured security or maintenance benefit with honest limitations. A benchmark score cannot guarantee real-world security or market demand.
