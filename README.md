# Democratize Security

Build affordable, inspectable security integration for AI-assisted software development, with reproducible evidence of what it protects.

**Status: development reference and offline research foundation.** Implemented: campaign planning, a synthetic FastAPI invoice app, PostgreSQL RLS integration tests and a public HTTP/database verifier. These are development fixtures, not production authentication or a protected research worker. No benchmark improvement or universal security guarantee is claimed.

## Start here

- New contributor or AI agent: [AGENTS.md](AGENTS.md), then [project brief](docs/PROJECT.md).
- System design: [architecture](docs/ARCHITECTURE.md) and [trust model](docs/THREAT_MODEL.md).
- What to build next: [status](docs/STATUS.md) and [milestone roadmap](docs/ROADMAP.md).
- Worker infrastructure spike: [offline container probe](docs/WORKER_PROBE.md).
- Candidate handoff: [artifact boundary](docs/ARTIFACTS.md).
- Research integrity: [experiment protocol](docs/RESEARCH_PROTOCOL.md) and [contracts](docs/CONTRACTS.md).
- Work from different computers and AI tools: [development guide](docs/DEVELOPMENT.md).

## Quick start

Use Python 3.12 and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```bash
uv sync --locked
uv run --locked research validate campaigns/development.example.json
uv run --locked research plan campaigns/development.example.json
uv run --locked pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
```

The example contains illustrative task hashes and a model placeholder. It plans 12 development trials without executing any of them, accessing a model, or spending money. Validation checks structure and consistency; it does not prove those tasks or revisions exist. A real campaign must resolve and verify them before execution. The budget is deliberately zero.

For browser-based development, open this repository in GitHub Codespaces. Its dev container installs the locked development environment. Codespaces may incur compute/storage charges under your account; no Codespace or paid model job is created by this repository setup.

## Run the reference verification

See [reference guide](docs/REFERENCE.md) for the concrete access contract and reproducible PostgreSQL test command. Install optional dependencies with `uv sync --locked --extra reference`. The CI `postgres-reference` job runs the full suite against real PostgreSQL 17, including deliberately unsafe variants. Without a configured disposable database, local integration tests explicitly skip.

## Initial product and long-term direction

The first property is tenant isolation: authenticated users may read their own organization's invoices, including lists/search and CSV exports, without receiving another organization's data. The planned stack is FastAPI and PostgreSQL row-level security with a restricted application role. Useful authorized behavior must continue to work.

The broader ambition is a reusable security layer across coding agents, frameworks and security properties. Project-owned contracts separate enforcement, verification, experiment orchestration and external adapters. We expand only when the first property has credible evidence. See [architecture](docs/ARCHITECTURE.md) for extension points and boundaries.

## Repository map

| Path | Purpose |
| --- | --- |
| `src/democratize_security/` | Implemented, dependency-free campaign contracts and CLI |
| `tests/` | Foundation unit and CLI tests, not tenant-isolation proof |
| `campaigns/` | Public, synthetic offline examples |
| `candidates/` | Planned product integration boundary |
| `tasks/` | Public development scenario guidance |
| `docs/` | Architecture, protocol, decisions and agent handoffs |
| `.devcontainer/` | Portable development configuration, not an execution sandbox |
| `.github/` | CI, dependency updates and contribution templates |

Private final assessment cases must never enter this checkout or Git history. Experimental outputs default to ignored local storage; durable evidence needs a separate backup policy before real campaigns.

## Licensing

The intention is an open-source core with optional paid services. A license has not yet been selected or granted. Public visibility alone is not an open-source license; see [licensing decision](docs/decisions/0002-licensing.md). Do not publish a package until that decision is resolved.
