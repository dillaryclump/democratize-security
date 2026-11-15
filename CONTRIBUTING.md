# Contributing

Contributions are welcome from people and from AI coding agents working on a person's behalf. The same rules apply to both, and they are written down in [AGENTS.md](AGENTS.md).

## What helps most

- **Verifier gaps.** A vulnerable implementation that passes every check is the most valuable bug report this project can get. If it is exploitable beyond the test fixtures, report it privately first. See [SECURITY.md](SECURITY.md).
- **Harder scenarios.** The current tasks do not separate the experimental conditions ([docs/RESULTS.md](docs/RESULTS.md)). Well-specified scenario families where tenant isolation is easy to get wrong are useful.
- **Reproduction reports.** Run the quick start on your platform and say what happened, including failures.
- **Documentation fixes.** If code and documentation disagree, that is a defect. Say which one is right, with evidence.

Not wanted for now: new frameworks, new security properties, dashboards, billing or anything listed under non-goals in [docs/PROJECT.md](docs/PROJECT.md).

## Before you start

1. Read [AGENTS.md](AGENTS.md), [docs/STATUS.md](docs/STATUS.md) and [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
2. Open or pick one bounded issue and say what you plan to change. [docs/COORDINATION.md](docs/COORDINATION.md) explains how work is claimed.
3. Work on a branch. One bounded change per pull request.

## Checks

The code is POSIX-only. Use Linux or WSL2.

```bash
uv sync --locked
uv run --locked pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
```

Changes to enforcement or verification must also pass against real PostgreSQL, with the commands in [docs/REFERENCE.md](docs/REFERENCE.md). A skipped integration test is not a passing one, so say which checks you could not run.

## What a pull request must state

- The problem and the requirement it covers.
- The change and the resulting behavior.
- The tests you actually ran and their outcome.
- Assumptions and remaining limitations.

Update [docs/STATUS.md](docs/STATUS.md) when capability changes. An architectural decision needs a record in `docs/decisions/`. A change to scoring or to an experiment needs a new protocol version.

## Rules that are not negotiable

- **Never weaken a check to improve a score.** Do not remove required functionality or silently exclude failures. A missing evaluation is incomplete, never a pass.
- **New enforcement needs both sides.** Show that authorized behavior still works and that the negative security cases fail, against real PostgreSQL.
- **No secrets, customer data or private test material**, in files, ignored files, container layers or Git history. Examples use synthetic data only.
- **No model calls or spending** in a contribution's tests. Model-free checks only.
- **Do not edit a frozen protocol** such as [docs/PILOT_PROTOCOL.md](docs/PILOT_PROTOCOL.md), and do not edit the generated files under `tasks/pilot/` by hand.
- **No efficacy claims** that the recorded results do not support.

## License

The project is licensed under the [Apache License 2.0](LICENSE). By submitting a contribution you agree that it is licensed under the same terms, as section 5 of the license provides. There is no separate contributor agreement. Only contribute work you have the right to license.

## Conduct

Be direct about technical problems and decent to the people involved. Harassment and personal attacks are not accepted in issues, pull requests or reviews. Report a problem through GitHub's own reporting tools.
