# Public development tasks

Every task here is public, and so is its verifier. None is a protected holdout. Final task definitions, answers and test material must be held outside this repository, its Git history and every candidate-visible environment.

## `harbor/`: hand-written development tasks

Four tasks for the [Harbor](https://docs.harborframework.com/) agent runner, pinned to version 0.24.0.

| Task | The agent's job | Graded by |
| --- | --- | --- |
| `rls-policy` | Replace an unsafe declarative PostgreSQL row-level security policy | A policy check in a separate verifier. See [docs/HARBOR.md](../docs/HARBOR.md) |
| `invoice-read` | Add `GET /invoices/{invoice_id}` | Verifier protocol `synthetic-reference-v3` |
| `invoice-search` | Add `GET /invoices` with search and pagination | The same |
| `invoice-export` | Add `GET /invoices/export` as CSV | The same |

The three invoice tasks start from the reference API with one endpoint removed, against a database protected by forced row-level security. See [docs/APPLICATION_TASKS.md](../docs/APPLICATION_TASKS.md).

## `pilot/`: generated pilot variants

Twenty-four variants: six scenario families (`invoice-read`, `invoice-search`, `invoice-export`, `invoice-update`, `invoice-create`, `invoice-summary`) in each of four conditions (`ordinary`, `instructions`, `rls-starter`, `full-tool`). They are graded with protocol `synthetic-reference-v4`. The conditions are defined in [docs/PILOT_PROTOCOL.md](../docs/PILOT_PROTOCOL.md).

**Do not edit these directories by hand.** They are generated from the sources in `src/democratize_security/pilot/`, and the pilot campaign pins a digest of each tree:

```bash
uv run --locked python scripts/build_pilot_tasks.py          # regenerate
uv run --locked python scripts/build_pilot_tasks.py --check  # verify they match their sources
```

Changing a variant changes its digest, which makes it a different task from the one the pilot ran. See [docs/RESULTS.md](../docs/RESULTS.md).

## Layout of one task

| Path | Purpose |
| --- | --- |
| `instruction.md` | What the agent is told |
| `environment/` | The agent's container: the starter `app.py`, its dependencies and the trusted collector |
| `tests/` | The separate verifier: the fixture, the checks and the container that serves the collected app |
| `solution/` | The reviewed reference solution, used by the `oracle` control |
| `task.toml` | Harbor's task definition and resource limits |

Keep the variants of one scenario family in the same split. The task hashes in `campaigns/development.example.json` are illustrative placeholders, not these tasks.
