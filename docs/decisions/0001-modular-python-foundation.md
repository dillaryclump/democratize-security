# ADR 0001: One modular Python repository

Status: adopted for the foundation, 2026-10-13.

Use one Python package and CLI, project-owned versioned data contracts, and a shared agent handbook. Runtime dependencies start empty. uv pins build/development tools. Python 3.12 is the common development baseline; 3.13 is checked in CI.

The application/control plane can evolve independently of runners, model vendors and benchmarks. Start with offline validation/planning, then implement the verifier, runner and persistence in gate order. Future runtime starts with one controller, one active trial and SQLite; no orchestration cluster is justified yet.

Consequences: low initial operational burden, but no claim that this is a complete agent framework. Adapters and typed interfaces are added when their first actual integration warrants them. A separate trusted evaluation environment remains necessary even in a monorepo.

Revisit on measured concurrent-writer needs, incompatible runtime requirements or an external deployment constraint. Do not split into services solely for anticipated scale.
