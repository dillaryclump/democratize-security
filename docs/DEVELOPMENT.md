# Development from anywhere

## One repository, interchangeable coding tools

GitHub is the source of truth. Use a local clone in VS Code/Cursor or open a GitHub Codespace in a browser. The same `pyproject.toml`, `uv.lock`, commands and `AGENTS.md` apply. Tool-specific instructions point to the canonical guide instead of maintaining divergent plans.

In GitHub, select the branch containing the foundation, then Code → Codespaces → Create codespace. After creation, run the README quick-start commands. The configuration follows GitHub's [Python dev-container workflow](https://docs.github.com/en/codespaces/setting-up-your-project-for-codespaces/adding-a-dev-container-configuration/setting-up-your-python-project-for-codespaces).

The dev-container image has a Python 3.12 version tag; it is development convenience, not an immutable research worker image. Before real experiments, pin and record worker image digests. Dev-container creation requires network access and may use billed compute. This setup does not create a Codespace automatically.

## Local setup

```bash
git clone https://github.com/dillaryclump/democratize-security.git
cd democratize-security
uv sync --locked
uv run --locked research validate campaigns/development.example.json
```

The code is POSIX-only: the ledger and artifact stores use `fcntl` locks and directory file descriptors. Use Linux or WSL2. On native Windows the test suite fails at import, so keep the checkout you test in on a Linux filesystem.

Python 3.12 is the default; CI also checks 3.13. `uv sync --locked` verifies the committed lock rather than silently changing dependency resolution; see [uv locking](https://docs.astral.sh/uv/concepts/projects/sync/). To deliberately update dependencies, edit pyproject, run `uv lock`, then inspect and commit both files.

## Routine workflow

Start from current main. Follow [COORDINATION.md](COORDINATION.md): inspect open PRs/issues, claim a bounded task, and record its owner/session, dependencies and branch. Give the agent that issue plus `AGENTS.md`, and require a PR with observed tests. For simultaneous coding sessions, use separate branches/worktrees so tools cannot overwrite one another. Avoid sharing a mutable working directory between agents.

```bash
uv run --locked pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
uv build
```

The offline planner writes JSON to stdout. Save a local plan if needed:

```bash
mkdir -p .research
uv run --locked research plan campaigns/development.example.json > .research/plan.json
```

This produces a local planning artifact, not persisted scientific results or paid execution. `.research/` is ignored; Git is not its backup.

## Repository settings

Repository configuration files cannot enable these settings by themselves. This is the state the owner approved and that was applied on 2026-11-15 (#80). Settings can drift, so check the live repository before relying on this list.

| Setting | State |
| --- | --- |
| Main-branch ruleset | Pull request required; `test (3.12)`, `test (3.13)` and `postgres-reference` must pass; force pushes and deletion blocked. No second reviewer is required, because the project has one owner |
| Secret scanning and push protection | Enabled |
| Private vulnerability reporting | Enabled. See [SECURITY.md](../SECURITY.md) |
| Dependabot version updates | Weekly, for GitHub Actions and uv |
| Dependabot security updates | Enabled |

Still manual:

- Keep Actions token permissions read-only by default. Do not run untrusted PR code using `pull_request_target`, repository secrets or a personal self-hosted runner.
- Configure Codespaces idle shutdown/spend limits and provider budgets before paid work.
- Review Dependabot PRs; automatic updates are not automatic merges.

## Next agent assignment

Read AGENTS.md, [STATUS.md](STATUS.md) and COORDINATION.md, then inspect live issues and open PRs. Select an unclaimed bounded task and record ownership before editing. The open items in STATUS.md need owner decisions first; do not start them on your own.

## Reference integration gate

Follow [REFERENCE.md](REFERENCE.md) for optional dependencies and PostgreSQL. The plain core suite may skip optional checks; only the dedicated `postgres-reference` job proves PostgreSQL tests ran, which is why the ruleset requires it.
