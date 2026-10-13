# Threat model and draft access contract

**M0 review required.** This document translates the approved direction into explicit proposed behavior. Dillon must resolve identity and response semantics before the verifier freezes expectations.

## Property and assumptions

An authenticated user belonging to organization A may read A's invoices and must never receive protected invoice data belonging to B through direct reads, list/search or CSV. Data, users and memberships are synthetic in research.

Trusted: verified authentication, server-side membership lookup, initial schema/policy setup, independent verifier and controller. Runtime database role has least privilege, does not own protected tables and cannot bypass row restrictions. Context is scoped to the transaction, reset across pooling/error paths, and never copied from an untrusted tenant header or query parameter.

## Access matrix

| Request | Proposed required behavior |
| --- | --- |
| Authenticated A reads A invoice | Return expected A invoice fields |
| Authenticated A reads B invoice ID | No B fields; choose and freeze consistent 403/404 semantics |
| A lists/searches with pagination | Only matching A rows; expected A rows remain discoverable |
| A exports CSV | Only authorized A rows and allowed fields; parse and inspect contents |
| A supplies B tenant header/query field | Cannot switch effective tenant or expand access |
| Missing/invalid authentication | Deny without invoice data |
| Valid user lacking trusted membership | Deny without invoice data |
| A request followed by B on reused connection | Each request sees only its own tenant |
| Failed A transaction followed by B | No A context or rows carried into B request |
| Privileged role, disabled/missing policy | Verifier rejects configuration; cannot report protected pass |
| No rows match legitimate filter | Valid empty result; not a server error |

Do not test only HTTP status. Inspect JSON fields, row identities, CSV, counts and supported response metadata for foreign-tenant exposure. Freeze which metadata is protected and whether existence/timing leakage is excluded.

## Exclusions

This design does not contain arbitrary hostile server code that can select another tenant context or obtain more privileged credentials. PostgreSQL RLS alone does not establish trustworthy identity. Writes, admin exceptions, uploads, background jobs and other frameworks remain out of scope. Network attackers, full host compromise and comprehensive side-channel protection are not claimed.

## Research infrastructure threat model

Generated programs, dependency/build hooks and candidate-written reports are untrusted. They may try to read verifier tests, change grades, steal tokens, exhaust resources or persist across runs. Required controls: separate worker identity, no host/home/Docker socket mounts, scoped secrets, denied unnecessary egress, CPU/memory/process/disk/time/output limits, fresh verification environment and allowlisted artifact extraction. Do not trust a candidate's JSON verdict.

Known protected references must pass; deliberately vulnerable variants must fail for the intended reason. Interrupted verification, absent checks, corrupt artifacts and verifier errors yield incomplete evidence and block promotion.
