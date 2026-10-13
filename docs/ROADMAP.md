# Milestone roadmap

Gates control delivery. The October 10 calendar was an estimate; the October 12 automated-research design changes build order. Re-estimate after the integration spike instead of promising the old dates.

| Gate | Deliverable | Completion evidence |
| --- | --- | --- |
| Foundation | Portable repo, agent handbook, offline contracts/planning | Unit/CLI checks and install verification; this is not M1 |
| M0 Contract | Frozen access matrix, identity assumptions, task families, scoring | Dillon reviews scope and open decisions; real task revisions resolve |
| M1 Verifier | Reference app, vulnerable mutations, pytest + real PostgreSQL | Protected reference passes; seeded leaks/unsafe roles fail; missing checks cannot pass |
| M2 Runner | Three development tasks through Harbor adapter | Fresh replay, sealed artifact, verifier inaccessible to candidate, bounded worker resources |
| M3 Persistence | SQLite events, artifacts, budgets and recovery | Crash recovery avoids duplicate paid dispatch; tampered/missing evidence blocks promotion |
| M4 Pilot | Six families × two repetitions × four conditions | 48 logical trials fully accounted for; matched budgets and interpretable outcomes |
| M5 Search | GEPA and bounded five-candidate development batch | Allowlisted edits, resource/budget stops and manual-search comparison |
| M6 Confirmation | Frozen candidate/protocol and fresh final assessment | Reproduction, uncertainty, no contaminated final-feedback loop, scoped human-reviewed claims |
| M7 Product pilot | Installable local tool and external users | Core verification works without paid model access; setup and feature change work beyond original demo |

## First implementation slice

Resolve response behavior and identity membership contract. Create two tenants with controlled identities and invoices. Build own-tenant reads, list/search and CSV plus vulnerable variants. Add verifier tests that inspect actual returned data and restricted database configuration. Include connection reuse/error tests. Keep seed/setup and runtime identities separate.

## Longer-term expansion triggers

Expand security properties/frameworks after M6 shows a meaningful benefit. Add remote execution after local isolation works and capacity is measured. Add a dashboard or paid service after external usage establishes demand. Broader benchmark coverage is contingent on task compatibility and reproducibility, not repository folder count.

If a correctly configured RLS starter matches the full tool, investigate simpler packaging, diagnostics or maintenance value before broadening scope. A neutral or negative experiment is a valid result.
