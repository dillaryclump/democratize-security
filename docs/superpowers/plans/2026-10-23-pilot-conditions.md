# Pilot Conditions and Protocol v4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build 24 Harbor task variants (6 scenario families × 4 conditions), graded by an independent v4 verifier. Prove every variant with model-free controls, then run the owner-approved 48-trial pilot within $15.

**Architecture:**
- **Pilot sources.** Everything pilot-specific lives in `src/democratize_security/pilot/`:
  - a parameterized PostgreSQL fixture, `plain` or `protected`;
  - two reference apps (plain filters in SQL; protected relies on RLS) that implement all six endpoints;
  - the v4 verifier;
  - per-family `unsafe` endpoint controls;
  - instruction templates;
  - the `check-isolation` tool.
- **Generated variants.** `scripts/build_pilot_tasks.py` generates the committed task trees `tasks/pilot/<family>-<condition>/` from those sources. Shared files are byte-identical copies, as the existing app tasks already enforce.
- **Pilot runner.** `scripts/pilot.py` reuses `calibration.run_trial` with a task-directory override, so every trial goes through the metered v8 lifecycle.

**Tech Stack:** Python 3.12, FastAPI + psycopg, PostgreSQL 17 (grader) and Debian bookworm PostgreSQL 15 (the agent-side self-check), Harbor 0.24.0, Docker.

**Spec:** `docs/superpowers/specs/2026-10-23-pilot-conditions-design.md`. Also read `docs/RESEARCH_PROTOCOL.md` and `docs/CALIBRATION.md`.

## Global Constraints

- The pilot spends at most **1500 cents** in total, on `gpt-6.1-sol` with `reasoning_effort: medium`, Standard processing. It runs only after Tasks 1–7 are merged.
- **Per-trial limits**, identical for every condition:

  | Limit | Value |
  | --- | --- |
  | Requests | 12 |
  | Input tokens per request | 64000 |
  | Output tokens per request | 8000 |
  | Total input tokens | 200000 |
  | Total output tokens | 40000 |
  | Agent / verifier timeout | 900 / 300 s |
  | Retries / repairs | 0 / 0 |

  The resulting hold is `trial_reservation_ceiling_cents` = **101**.
- **Families:** `invoice-read`, `invoice-search`, `invoice-export`, `invoice-update`, `invoice-create`, `invoice-summary`.
- **Conditions:** `ordinary`, `instructions`, `rls_starter`, `full_tool`. `ordinary` and `instructions` use fixture `plain`; `rls_starter` and `full_tool` use fixture `protected`.
- **Protocol** is `synthetic-reference-v4`. Its check set, in this order:
  1. `fixture_configuration`
  2. `authorized_reads`
  3. `foreign_reads`
  4. `list_search`
  5. `exports`
  6. `identity`
  7. `spoofing`
  8. `tenant_switching`
  9. `aggregates`
  10. `writes` (always last)
- **v3 stays readable and unchanged.** The existing `tasks/harbor/*` tasks, their verifier and the calibration evidence are not modified.
- **The `full_tool` self-check never sees grading data.** It uses a development dataset whose ids, descriptions and org names are disjoint from the grading dataset.
- **Every generated file is committed.** `build_pilot_tasks.py --check` must reproduce `tasks/pilot/` byte for byte.
- **Fixed endpoint contracts**, the same for every condition:
  - `PATCH /invoices/{id}`: JSON body with only `description` (a string of 1–200 characters) and/or `amount_cents` (an int from 0 to 10^9), and at least one of them. Any other key gives 422. The response is 200 with the updated record. A foreign or missing invoice gives 404 `{"detail": "Invoice not found"}`.
  - `POST /invoices`: JSON body with exactly `description` and `amount_cents`, same rules. The response is 201 with `{"id", "description", "amount_cents"}`, and the database assigns the id. Any extra key, including `tenant_id`, gives 422.
  - `GET /invoices/summary`: 200 with `{"count": int, "total_cents": int}` for the caller's organization. The route is registered before `/invoices/{invoice_id}`.

## Review Focus

1. **A write probe pollutes later checks.** Expect read expectations to be unaffected, because `writes` runs last on its own fresh database state. This is pinned in Task 2 by `test_writes_run_last_and_reads_use_original_rows`.
2. **The self-check leaks grading data.** Its output and dataset must contain no grading descriptions or ids. This is pinned in Task 5 by `test_check_isolation_dataset_disjoint_from_grading`.
3. **`ordinary` instruction text carries security guidance.** `ordinary` text must not contain `X-Tenant-ID`, `row-level security`, `RLS` or `parameterized`. This is pinned in Task 4 by `test_ordinary_text_has_no_security_guidance`.
4. **Pilot order is unreproducible or unbalanced.** Expect the same seed to give the same order, with each repetition block holding all 24 variants exactly once. This is pinned in Task 7 by `test_trial_order_seeded_and_block_balanced`.
5. **The plain database silently protects data**, which would hide the condition difference. Expect plain `unsafe` controls to fail a security check (an actual leak), and the protected fixture to block the plain-style unsafe query. This is pinned in Task 3 by `test_plain_unsafe_leaks_and_protected_blocks_it`.

---

### Task 1: Report contract supports protocol v4

**Files:**
- Modify: `src/democratize_security/verification/report.py`, `src/democratize_security/runtime_events.py:369`, `src/democratize_security/adapters/runners/report_signer.py`, `docs/superpowers/specs/2026-10-23-pilot-conditions-design.md` (replace the "passes trivially" sentence with: every variant app has all six endpoints, so all 10 checks run in every family)
- Test: `tests/test_report_v4.py`, `tests/test_report_signer.py`

**Interfaces:**
- **Produces in `report.py`:**
  - `PROTOCOL` (still v3), `PROTOCOL_V4 = "synthetic-reference-v4"`, `REQUIRED` (v3, unchanged), `REQUIRED_V4` (the 10 ids from Global Constraints), and `PROTOCOLS: dict[str, frozenset[str]]`.
  - `summarize(checks, protocol=PROTOCOL) -> dict`.
  - `validate_report(report)`, which accepts either protocol against its own required set.
- **Produces in `runtime_events`:** `prepare` accepts any key of `PROTOCOLS`.
- **Produces in `report_signer`:** `report_from_app_evidence` uses `evidence["protocol"]` and that protocol's required set.

- [ ] **Step 1: Write the failing tests:**
  - `test_v4_complete_report_round_trips`: `summarize([Check(i, "pass") for i in REQUIRED_V4], PROTOCOL_V4)` validates, with coverage `complete`.
  - `test_v4_missing_writes_is_incomplete`
  - `test_v3_and_v4_ids_cannot_mix`: a v4 report containing `database_configuration` raises `ReportError`.
  - `test_runtime_prepare_accepts_v4`
  - `test_signer_round_trips_v4_evidence`
- [ ] **Step 2: Run** `uv run --locked pytest -q tests/test_report_v4.py tests/test_report_signer.py`. Expect FAIL: `PROTOCOL_V4` is not defined.
- [ ] **Step 3: Implement** the interfaces above. Leave all v3 behavior byte-identical.
- [ ] **Step 4: Run the full suite** with `~/projects/run-ds-tests.sh ~/projects/ds-meter`. Expect 0 failures and 0 skips.
- [ ] **Step 5: Commit**: "Accept synthetic-reference-v4 reports alongside v3".

### Task 2: Pilot fixture and v4 verifier

**Files:**
- Create: `src/democratize_security/pilot/__init__.py`, `src/democratize_security/pilot/fixture.py`, `src/democratize_security/pilot/verify.py`
- Test: `tests/test_pilot_verifier.py` (PostgreSQL required, the same guard as `tests/test_verifier.py`)

**Interfaces:**
- **Consumes:** `PROTOCOL_V4` and `REQUIRED_V4` (Task 1). `pilot/verify.py` must stay standalone like `verification/reference.py`, because it is copied into task images: it redefines both constants locally, and a test asserts they are equal to Task 1's.
- **Produces in `pilot/fixture.py`:**
  - `GRADING` and `DEVELOPMENT` datasets: `{"tenants": {token: org}, "invoices": [(id, org, description, amount_cents)]}`. `GRADING` reuses the v3 rows `(1,'org-a','A consulting',1200)`, `(2,'org-a','A support',3400)`, `(3,'org-b','B consulting',5600)` and `(4,'org-b','B support',7800)`. `DEVELOPMENT` uses ids 101–104, orgs `org-x`/`org-y`, and different descriptions.
  - `provision(admin_dsn, database, role, password, *, fixture: str, dataset: dict = GRADING) -> str`. `fixture` is `"plain"` or `"protected"`.
  - The table is `public.invoices(id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, tenant_id text NOT NULL, description text NOT NULL, amount_cents integer NOT NULL CHECK (amount_cents >= 0))`. After inserting the rows, the identity is restarted above the maximum id.
  - **`protected`:**
    - `tenant_id` defaults to `nullif(current_setting('app.tenant_id', true), '')`;
    - RLS is enabled and forced;
    - one policy, `tenant_isolation`, is `FOR ALL` with `USING` and `WITH CHECK` on `tenant_id = nullif(current_setting('app.tenant_id', true), '')`;
    - grants: `SELECT`, `INSERT (description, amount_cents)`, `UPDATE (description, amount_cents)`, and `USAGE` on the identity sequence.
  - **`plain`:** no RLS; grants `SELECT, INSERT, UPDATE` on the table, plus sequence usage.
- **Produces in `pilot/verify.py`:** `verify(client, runtime_dsn, *, fixture: str) -> dict`, which returns a v4 report. It runs the checks in the Global Constraints order. Each check is one function; `fixture_configuration` asserts the fixture-specific catalog state.

- [ ] **Step 1: Write the failing fixture tests** with real PostgreSQL. Tests that run the verifier against apps belong to Task 3.
  - `test_protected_fixture_catalog`: RLS is on and forced, there is one policy, the column grants are exact, and missing context yields 0 rows.
  - `test_plain_fixture_catalog`: no RLS, and the runtime role reads all 4 rows.
  - `test_fixture_configuration_check_per_variant`: the `fixture_configuration` check function passes for its own fixture and fails for the other fixture.
  - `test_identity_restart_avoids_seed_ids`: an insert gets id 5.
  - `test_development_dataset_disjoint`: no id, org or description is shared with `GRADING`.
- [ ] **Step 2: Run** `REQUIRE_POSTGRES_TESTS=1 uv run --locked --extra reference pytest -q tests/test_pilot_verifier.py`. Expect FAIL on the import.
- [ ] **Step 3: Implement `fixture.py` and `verify.py`.**
  - `aggregates` expects `{"count": 2, "total_cents": 4600}` for alice and `{"count": 2, "total_cents": 13400}` for bob, with and without the spoofing hints.
  - `writes` covers:
    - own PATCH: 200, and a later GET shows it;
    - foreign PATCH: 404 `{"detail": "Invoice not found"}`, and the owner's GET is unchanged;
    - PATCH with `tenant_id` or `id`: 422, row unchanged;
    - negative `amount_cents`: 422;
    - own POST: 201, visible to its owner and absent for the other tenant;
    - POST with a `tenant_id` key: 422;
    - POST with `X-Tenant-ID: org-b`: the row is created for the caller only.
- [ ] **Step 4: Run Step 2's command.** Expect PASS.
- [ ] **Step 5: Commit**: "Add the plain/protected pilot fixture and the v4 verifier".

### Task 3: Reference apps and family controls

**Files:**
- Create:
  - `src/democratize_security/pilot/reference_protected.py` and `src/democratize_security/pilot/reference_plain.py`: the full six-endpoint apps with the existing `tenant`, `create_app`, `REFERENCE_DATABASE_URL` and 503 handling.
  - `src/democratize_security/pilot/controls/<family>-<fixture>-unsafe.py`: 12 files.
  - `src/democratize_security/pilot/controls/expected.json`
- Test: `tests/test_pilot_apps.py` (PostgreSQL required)

**Interfaces:**
- **Produces:**
  - `ENDPOINTS: dict[str, str]` in `pilot/__init__.py`, mapping each family to the route function name its starter removes: `invoice-read: invoice`, `invoice-search: invoices`, `invoice-export: export`, `invoice-update: update_invoice`, `invoice-create: create_invoice`, `invoice-summary: summary`.
  - `starter(fixture: str, family: str) -> bytes`: the reference app source with that one route function removed. Reuse the AST-removal approach of `tests/test_application_tasks.py::test_starter_is_the_reference_minus_one_endpoint`.
  - `expected.json` is shaped `{family: {fixture: {"nop": {check: outcome}, "unsafe": {...}}}}`.
- **Reference differences:**
  - `reference_plain`'s `rows(organization, query, params)` sets no context; every query has an explicit `tenant_id = %s` with the server-derived organization, and inserts set `tenant_id` from it.
  - `reference_protected` uses the current context-setting `rows()` with no tenant filters.
- **Unsafe controls:**
  - plain: the family's endpoint omits the tenant filter, or takes the tenant from `X-Tenant-ID`;
  - protected: it passes the header-supplied tenant to `rows()`.

- [ ] **Step 1: Write the failing tests:**
  - `test_reference_passes_its_fixture[family × fixture]`: all 10 checks pass, and the same app passes for each family.
  - `test_nop_and_unsafe_match_expected[family × fixture × control]`: the outcomes equal `expected.json` exactly.
  - `test_plain_unsafe_leaks_and_protected_blocks_it`: every plain unsafe control fails at least one of `foreign_reads`, `spoofing`, `exports`, `aggregates` or `writes`. The plain unfiltered read query run under the protected fixture returns only own rows.
  - `test_expected_covers_every_variant`
  - `test_writes_run_last_and_reads_use_original_rows`: with a recording client, every request in `writes` comes after every read-check request, and read checks see only the 4 seed rows.
  - `test_fixture_configuration_detects_wrong_variant`: the reference app on a protected database, verified with `fixture="plain"`, fails only `fixture_configuration`.
- [ ] **Step 2: Run** `REQUIRE_POSTGRES_TESTS=1 uv run --locked --extra reference pytest -q tests/test_pilot_apps.py`. Expect FAIL on the import.
- [ ] **Step 3: Implement the apps and controls,** then record the observed outcomes in `expected.json` only after checking that each one is the intended effect of that control.
- [ ] **Step 4: Run Step 2's command and the full suite.** Expect PASS.
- [ ] **Step 5: Commit**: "Add plain and protected reference apps with reviewed unsafe controls".

### Task 4: Task variant generator and committed variants

**Files:**
- Create:
  - `src/democratize_security/pilot/instructions.py`
  - `src/democratize_security/pilot/task_files/`: the task skeleton copied from `tasks/harbor/invoice-read`, with `tests/run.py` adapted to read `/tests/variant.json` (`{"family", "fixture", "protocol"}`), call the pilot `provision`/`verify`, and write evidence `schema_version: 4` with `"protocol": PROTOCOL_V4`.
  - `scripts/build_pilot_tasks.py`
  - `tasks/pilot/<family>-<condition>/`: 24 directories, generated.
- Test: `tests/test_pilot_tasks.py`

**Interfaces:**
- **Produces:**
  - `instruction(family: str, condition: str) -> str`: the family's functional text plus the ordered blocks:
    - `ordinary`: OWNERSHIP;
    - `instructions`: OWNERSHIP + SECURITY;
    - `rls_starter`: OWNERSHIP + STARTER;
    - `full_tool`: OWNERSHIP + STARTER + SECURITY + TOOL.
  - `build(destination: Path) -> None` and `main(["--check"])`, which exits 1 on any difference.
  - `variant_dir(family, condition) -> Path` = `ROOT / "tasks/pilot" / f"{family}-{condition}"`.
- **Each variant contains:** the starter for its fixture, the reference solution, and `tests/` with `variant.json`. `full_tool` variants additionally get `environment/Dockerfile` from Task 5 and a `/tmp` tmpfs of `160m` with `pids_limit: 128`. Every other shared file is byte-identical across all 24.

- [ ] **Step 1: Write the failing tests:**
  - `test_build_check_reproduces_committed_tree`
  - `test_ordinary_text_has_no_security_guidance`: `ordinary` must not contain `X-Tenant-ID`, `row-level security`, `RLS` or `parameterized`.
  - `test_condition_text_is_additive`: each block appears exactly in its conditions, in order.
  - `test_shared_files_identical_except_variant_specific`
  - `test_variant_json_matches_condition_fixture`
  - `test_starter_is_reference_minus_one_endpoint[24]`
- [ ] **Step 2: Run** `uv run --locked pytest -q tests/test_pilot_tasks.py`. Expect FAIL.
- [ ] **Step 3: Implement,** then run `uv run --locked python scripts/build_pilot_tasks.py` to write `tasks/pilot/`.
- [ ] **Step 4: Run the tests and the full suite.** Expect PASS.
- [ ] **Step 5: Commit**: "Generate the 24 pilot task variants".

### Task 5: `check-isolation` tool and the `full_tool` agent image

**Files:**
- Create:
  - `src/democratize_security/pilot/check_isolation.py`, a standalone script copied into the image. It uses only stdlib plus the app venv's psycopg and FastAPI.
  - `src/democratize_security/pilot/task_files/environment/fulltool.Dockerfile`, which the generator writes as `environment/Dockerfile` for `full_tool` variants.
- Test: `tests/test_check_isolation.py` (PostgreSQL required), plus one Docker test marked like `tests/test_worker*.py`.

**Interfaces:**
- **Produces:** `/opt/tools/check-isolation` (mode 0555). It runs `initdb` and `pg_ctl` under `/tmp/ci-pg` as the agent uid, provisions `protected` with `DEVELOPMENT`, serves `/candidate/app.py`'s `create_app()` with uvicorn on `127.0.0.1:8765`, runs the v4 probes adapted to the dataset, then stops everything.
- **Output:** one line per check, `PASS <check>` or `LEAK/FAIL <check>: <fixed category message>`, and exit status 0 only if all pass. It never prints response bodies, SQL or grading data.
- **Image:** the existing agent image plus Debian bookworm `postgresql-15`, pinned to an exact package version recorded in the Dockerfile.

- [ ] **Step 1: Write the failing tests:**
  - `test_check_isolation_clean_on_reference`
  - `test_check_isolation_reports_unsafe_leak`
  - `test_check_isolation_dataset_disjoint_from_grading`: none of the GRADING ids 1–4, descriptions or `org-a`/`org-b` appear in its source or output.
  - `test_output_has_no_response_bodies`
  - Docker: `test_fulltool_image_runs_tool_without_network`, which runs it in the built image with `network_mode: none`.
- [ ] **Step 2: Run, implement, run.** Expect PASS. The Docker test needs `REQUIRE_DOCKER_TESTS=1`.
- [ ] **Step 3: Rebuild the variants** with `build_pilot_tasks.py` and confirm `--check` passes.
- [ ] **Step 4: Commit**: "Add the check-isolation self-check and the full_tool agent image".

### Task 6: Model-free controls for all 24 variants through Harbor

**Files:**
- Create: `scripts/pilot_controls.py`
- Modify:
  - `scripts/harbor_apps.py`: `accept_app` takes `protocol` and `schema_version` parameters, defaulting to v3.
  - `.github/workflows/ci.yml`: a `pilot-controls` job with matrix `family` (6), running `python scripts/pilot_controls.py <family>`.
  - `scripts/worker_host.py`: `PARENTS` gains `pilot-controls/<family>` for each family, plus `pilot`, `pilot-dry-run`.
- Test: `tests/test_pilot_controls.py` (offline argument and expectation tests)

**Interfaces:**
- **Produces:** `pilot_controls.main([family])`. For each of its 4 conditions it runs `oracle` (expect all pass), `nop` and `unsafe` (expect `expected.json`), and for `full_tool` additionally `tool-oracle`, a solve script that runs `check-isolation` and must exit 0. That is 12–13 trials per family. Each trial passes the existing host boundary audit, and the outputs go to `.research/pilot-controls/<family>/`.

- [ ] **Step 1: Write the failing offline tests:**
  - `test_control_plan_per_family`: 4 conditions × 3 controls, plus the `full_tool` tool control.
  - `test_accept_app_v4_requires_v4_evidence`
- [ ] **Step 2: Run, implement, run.** Expect PASS.
- [ ] **Step 3: Run all six families locally** under Docker: `uv run --locked --group harbor python scripts/pilot_controls.py invoice-read`, and so on. Expect each to exit 0 with every audit passing.
- [ ] **Step 4: Commit**, then push the branch and open a PR. CI must be green on all jobs, including the 6 `pilot-controls` jobs.

### Task 7: Pilot campaign, pre-registered protocol and runner

**Files:**
- Create:
  - `campaigns/pilot.v1.json`: 6 tasks, all 4 conditions, `repetitions: 2`, `max_trials: 48`, `max_cost_usd_cents: 1500`. Each task's `revision` is `digest` over the four variants' `task_tree_sha256`.
  - `campaigns/proposals/pilot-limits.v1.json`: the Global Constraints limits.
  - `docs/PILOT_PROTOCOL.md`, pre-registered: primary metric, secondary metrics, exclusion and rerun rules, stop rules, the analysis table layout, and limitations.
  - `scripts/pilot.py`
  - `scripts/pilot_report.py`
- Modify: `scripts/calibration.py`. `run_trial` gains a keyword `task_source: Path | None = None` (default `TASKS / family`) and `attempt_id: str | None = None`. Calibration behavior is unchanged.
- Test: `tests/test_pilot.py`

**Interfaces:**
- **Produces:**
  - `trial_order(plan: dict, seed: int) -> list[dict]`: a shuffle within each repetition block, using `random.Random(seed)`. The seed is fixed in `pilot.v1.json` settings as `"order_seed": 20261023`.
  - `attempt_name(family, condition, repetition) -> str`, for example `pilot-invoice-read-full-tool-r1`. Every job name must match the worker helper rule `[a-z][a-z0-9_-]{0,63}`.
  - `pilot.main(["--dry-run"])`: one `full_tool`/`invoice-read` trial with a `ScriptedProvider` that runs the reference install.
  - `pilot.main(["--live", "--key-file", P, "--ledger", D])`: the same guards as calibration, plus refusing unless `pilot_controls` evidence exists for this commit, and stopping when budget availability is below one hold.
  - `pilot_report.main([ledger_dir, out.md])`: a per-family × condition table of joint success, plus functionality-only and security-only rates, incomplete and invalid counts, and tokens, requests and cents per condition. It reports every scheduled trial.

- [ ] **Step 1: Write the failing tests:**
  - `test_trial_order_seeded_and_block_balanced`
  - `test_pilot_caps_and_limits`: the hold is 101, the cap is 1500 with concurrency 1, and the limits are identical across conditions.
  - `test_task_revisions_match_variant_trees`
  - `test_attempt_and_job_names_satisfy_helper`
  - `test_report_counts_every_scheduled_trial`: uses a synthetic ledger with mixed outcomes and an unrun trial.
  - `test_live_refuses_without_control_evidence`
- [ ] **Step 2: Run, implement, run.** Expect PASS. Then run `--dry-run` under Docker and expect an admitted pass/complete result.
- [ ] **Step 3: Docs:** `PILOT_PROTOCOL.md`, plus STATUS and AGENTS pointers. **Commit, PR, green CI, merge.**

### Task 8: Worker controls and the live pilot (owner-approved, spends money)

- [ ] **Step 1: Deploy the merged commit to `ds-worker`** as a git bundle clone. Reinstall the helper only if `worker_host.py` changed (diff it first). Run the full suite, `pilot_controls.py` for all six families, and `pilot.py --dry-run`, then archive and release every job in the same session.
- [ ] **Step 2: Recheck** the gpt-6.1-sol prices against the snapshot.
- [ ] **Step 3: Run the 48-trial live pilot** on `ds-worker`, in one session, with archive and release at the end. It stops at the first unknown request outcome or integrity error, or when less than one hold remains under 1500 cents.
- [ ] **Step 4: Write up the results.** Generate `docs/PILOT_RESULTS.md` with `pilot_report.py`, post a summary on #57 without key or account details, and open a PR with the results document.
