# M4 pilot: conditions, scenario families and protocol v4

Status: design for implementation, 2026-10-23. The owner approved a $15 hard model-only cap for the 48-trial pilot, frozen on `gpt-6.1-sol` with medium reasoning (#57). Everything below the owner's statements is Claude's call, marked where it matters.

## Intent

The aim is to complete a credible study that shows an AI can design, build, run and honestly report a research experiment. Selling a product is secondary (owner). The research question stays the one in `docs/RESEARCH_PROTOCOL.md`: does the full integration raise joint functional and security success over credible existing protection? A null result is an acceptable outcome (owner).

- **Goal:** a 48-trial pilot (6 scenario families × 4 conditions × 2 repetitions). The conditions are cleanly separated, the grading is independent, every cent is accounted for, and the report is pre-specified. The pilot estimates feasibility and gives a first signal. It is not a significance claim.
- **Anti-goal:** a comparison rigged toward `full_tool`. Examples:
  - a condition failing a check that only measures whether RLS exists rather than whether data leaks;
  - unequal budgets;
  - feedback in `full_tool` that reveals the grader's exact cases;
  - editing tasks after seeing which condition benefits.

## The key finding that shapes this

Today every Harbor app task provisions forced PostgreSQL RLS in the verifier's database and gives the agent a `rows()` helper that sets the tenant. The candidate only writes app code, so the database protects every condition for free. All three current tasks are therefore effectively `rls_starter`. The conditions must differ in what actually protects the data.

## Conditions (Claude's call, following the protocol's table)

Each condition has its own task variant. All variants of a family share the functional requirements, the same fixture rows, the same verifier probes, the same model settings and the same budget.

| Condition | Database the app runs against | Starter app | Instruction text |
| --- | --- | --- | --- |
| `ordinary` | **plain**: no RLS; the runtime role may read and write every row | `rows(query, params)` with no tenant context; existing endpoints already filter with `WHERE tenant_id = %s` | Functionality plus the ownership requirement: each invoice belongs to one organization, and callers act only within their own, identified only by the existing `tenant` dependency |
| `instructions` | plain | same as `ordinary` | `ordinary` text plus explicit security guidance: server-derived tenant on every query, ignore client tenant hints, indistinguishable 404s, parameterized SQL, no cross-request state |
| `rls_starter` | **protected**: forced RLS, restricted role, policies and column grants | the current helper that sets transaction-local `app.tenant_id` | `ordinary` text plus a description of the starter: use `rows()`, because RLS limits rows |
| `full_tool` | protected | same as `rls_starter` | `rls_starter` text plus the security guidance, plus the `check-isolation` tool |

**The `full_tool` self-check tool** (owner-chosen design): `/opt/tools/check-isolation` lives in the agent image.
- It starts a private PostgreSQL on loopback inside the agent container. That container stays network-less, and `lo` still works.
- It provisions the family's protected fixture with **different public development data** (other ids, descriptions and org names) and serves the candidate's `create_app()` on loopback.
- It runs the family's isolation probes and prints which probe categories leaked or failed. It never prints the grader's expected values.
- The agent may run it any number of times, within the same 12-turn and token limits as every condition. Turns spent on it count.
- It needs PostgreSQL binaries in the agent image and larger tmpfs bounds. Only `full_tool` variants use that image.

## Scenario families

The pilot uses 6 families: the 3 existing ones plus 3 write and aggregate families (Claude's call). Write and aggregate families are where app-level filtering most often fails, so they leave room for the conditions to differ. They reuse one invoice schema.

1. `invoice-read`: `GET /invoices/{id}` (exists).
2. `invoice-search`: list, search and pagination (exists).
3. `invoice-export`: CSV export (exists).
4. `invoice-update`: `PATCH /invoices/{id}` changes `description` and/or `amount_cents`.
   - Risks: updating another tenant's row, distinguishable 404s, and mass assignment of `tenant_id` or `id`.
   - Protected fixture: `UPDATE` policy with `USING` and `WITH CHECK`; `UPDATE` granted only on those two columns.
5. `invoice-create`: `POST /invoices` creates a row for the caller's organization; the id is assigned by the database.
   - Risk: a client-supplied `tenant_id` placing a row in another tenant.
   - Protected fixture: `tenant_id DEFAULT current_setting('app.tenant_id')`, an `INSERT` policy `WITH CHECK`, and `INSERT` granted only on the content columns.
6. `invoice-summary`: `GET /invoices/summary` returns `{"count", "total_cents"}` for the caller.
   - Risk: aggregating across tenants.

Every family's starter contains all the other endpoints, already correct for its condition. The agent adds exactly one missing endpoint, as today.

## Verifier protocol v4

The protocol is `synthetic-reference-v4`, with one verifier shared by all families and conditions.

- **`fixture_configuration` replaces `database_configuration`.** It checks that the database matches the variant's *intended* fixture (plain or protected). The agent cannot change the database, so this check is trial validity: a failure invalidates the trial as infrastructure. It never counts as a security failure. This removes the "punished for not using RLS" bias.
- **The other checks keep their v3 probes**, extended to cover the write and aggregate endpoints:
  - `authorized_reads`, `foreign_reads`, `list_search`, `exports`, `identity`, `spoofing`, `tenant_switching`;
  - `writes`: an authorized update or create works, and a foreign or mass-assigned one is rejected and leaves the other tenant's data unchanged when read through the API;
  - `aggregates`: correct own-tenant totals, with no foreign contribution.
- **Every variant app has all six endpoints**: the starter holds five and the agent adds one. So all 10 checks run in every family. Coverage is complete only when all 10 checks have a `pass` or `fail`.
- **Joint success** means `fixture_configuration` passes and every other check passes. This is the primary operational rate from RESEARCH_PROTOCOL.md. A run that never reached evaluation counts as non-success and is reported separately.
- **A fresh database per verifier run**, so write probes cannot pollute other checks.
- The report contract (`verification/report.py`), the signer and the app controls move to v4. v3 history stays readable.

## Controls before any model run

Each of the 24 variants (6 families × 4 conditions) needs reviewed model-free controls through the audited Harbor boundary:
- `oracle`: the reference solution passes;
- `nop`: the unchanged starter fails exactly the reviewed checks;
- `unsafe`: a reviewed vulnerable solution fails exactly the reviewed security checks;
- for `ordinary` and `instructions` variants, an `unsafe` solution must actually leak, showing that the plain database does not protect them.

`full_tool` also gets a check that `check-isolation` reports the `unsafe` control as leaking and the oracle as clean.

## Pilot campaign and protocol freeze

- **Campaign:** `campaigns/pilot.v1.json`, with 6 families × 4 conditions × 2 repetitions = 48 trials.
  - Model and settings: `gpt-6.1-sol`, medium reasoning, Standard processing.
  - Every task revision is frozen as a task-tree digest.
  - `max_cost_usd_cents: 1500`.
- **Per-trial limits, tightened from calibration** (Claude's call; the measured maxima were 5 requests and about 17k input tokens):

  | Limit | Value |
  | --- | --- |
  | Requests | 12 |
  | Input tokens per request | 64,000 |
  | Total input tokens | 200,000 |
  | Output tokens per request | 8,000 |
  | Total output tokens | 40,000 |

  That gives a hold of about 101¢ per trial, with one hold outstanding at a time. Expected actual spend is $3–8.
- **Order:** randomized with a recorded seed, balanced so that each repetition block contains all 24 variants. This avoids time-ordered confounds.
- **Stopping:**
  - stop at the first unknown request outcome or integrity error, or when the $15 cap is reached;
  - zero retries;
  - infrastructure-invalid trials are reported, and the matched block is rerun only under a rule fixed before any results.
- **Report**, pre-specified in `docs/PILOT_PROTOCOL.md` before the run:
  - a per-family and per-condition table of joint success;
  - functionality-only and security-only rates;
  - incomplete and invalid counts;
  - tokens, requests and cost per condition;
  - a matched-compute note for `full_tool`;
  - broad uncertainty, and no significance claims from 48 correlated trials.

  All 48 trials are reported, including failures.
- **Splits:** all families are public development data for this pilot. That limitation is stated in the report, and the public verifier is not a protected holdout.

## Non-goals

GEPA or optimizer search, other providers, a protected final evaluator, a dashboard, and any spend beyond $15.

## Left to the builder

The exact instruction wording within the rules above, the reference and unsafe solutions, the probe data for `check-isolation`, the image layout, and how the 24 variants are generated from templates. Generated variants must be committed, with a test that regeneration reproduces them byte for byte.
