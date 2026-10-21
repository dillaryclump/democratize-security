# Metered Transport and Calibration Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the owner-approved $10 six-trial calibration (issue #69). Every model request is durably reserved in the ledger before it is sent, sent exactly once, and settled or held as unknown. Every trial goes through the store lifecycle and admits only authenticated verifier results.

**Architecture:**
- **Request accounting.** Store v8 adds three per-request actions to the runtime reducer, so the shared attempt ledger records request intent, settlement and unknown outcomes.
- **Controller-side broker.** A single-threaded broker in the controller process owns the `PlanStore`, the provider key and the provider client. Harbor's Terminus2 runs in a `harbor run` subprocess and reaches the model only through a thin `BaseLLM` client that talks to the broker over a private Unix socket.
- **Authoritative verification.** Verification happens in a separate sealed replay job after `verify_intent`. A trusted signer subprocess converts the replay's Harbor-nonce-bound evidence into a `runtime_auth` envelope for `admit_result`.

**Tech Stack:** Python 3.12, SQLite store (v7 → v8), Harbor 0.24.0 Terminus2, httpx (already locked), OpenAI Responses REST API, Docker.

**Spec:**
- `docs/MODEL_BATCH.md`, in particular "Concrete transport integration contract" and "Pinned Harbor findings".
- `campaigns/proposals/calibration.v1.json`.
- Issue #69.
- Owner approval on #57 (2026-10-20): a **$10 model-only cap for the six calibration trials only**.

## Global Constraints

- The total of all calibration reservations must never exceed **1000 cents**. The 48-trial pilot is **not** approved.
- Models: `gpt-6.1-sol` and `gpt-6-luna`, `reasoning: {"effort": "medium"}`, Standard processing, rates from `campaigns/proposals/pricing.2026-10-17.v1.json`.
- Per-trial limits, verbatim from `calibration.v1.json`:

  | Limit | Value |
  | --- | --- |
  | Model requests | 12 |
  | Input tokens per request | 64000 |
  | Output tokens per request | 25000 |
  | Total input tokens | 500000 |
  | Total output tokens | 100000 |
  | Agent / verifier timeout | 900 / 300 s |
  | Retries / repairs | 0 / 0 |

- Per-trial hold: `trial_reservation_ceiling_cents` = **236** (Sol) and **23** (Luna), **777** cents in total.
- Retries:
  - Every HTTP client retry is disabled.
  - Terminus2's `_query_llm` tenacity retry must never cause a second send. The transport latches shut after any refusal or failure and raises `TransportHalted`, a subclass of `ContextLengthExceededError`, which tenacity does not retry.
- Terminus2 runs with `enable_summarize=False`, `max_turns=12`, `record_terminal_session=False`, and tmux baked into the image (`PresenceCheckedTmuxSession`).
- Credentials:
  - The provider key is read only from a `--key-file` owned by the controller with mode `0600`.
  - It is never placed in any subprocess environment, log, ledger row, exception message or artifact.
  - The `harbor run` env is `os.environ` minus every name matching `*_API_KEY`, `*_TOKEN`, `OPENAI_*` and `ANTHROPIC_*`.
- The candidate container is unchanged: `network_mode: none`, non-root, no socket mounts.
- Missing or invalid usage or prices are **unknown**, never zero. An unknown request keeps its full reservation, blocks further requests, blocks `settle`, and stops the batch.
- The core package (`src/democratize_security/*.py`) imports only the stdlib and the project itself. httpx stays under `adapters/providers/`, and Harbor stays under `adapters/runners/`.
- No real provider request happens in any test or CI job. Live mode runs only on `ds-worker`, after Task 6 is merged and the owner has placed a key file.

## Review Focus

1. **Lost provider response after send** (timeout, connection reset, 5xx body). The request must be recorded `request_unknown`, never resent, and the batch must halt. This is pinned in Task 2 by `test_send_failure_after_intent_records_unknown_and_latches`.
2. **Controller crash between `request_intent` commit and send/settle.** On reopen, the open request must be treated as unknown and the attempt must not resume requesting. This is pinned in Task 1 by `test_open_request_blocks_seal_and_new_requests_after_reopen`.
3. **Harbor's retry decorator re-invoking `call` after a refusal.** There must be no second broker round-trip. This is pinned in Task 4 by `test_latched_client_never_contacts_broker_again`.
4. **Oversized or hostile prompt history** (the model echoes huge terminal output). The preflight count above 64000 must refuse before any reservation or send. This is pinned in Task 2 by `test_preflight_over_cap_refuses_without_intent`.
5. **Key leakage into the Harbor subprocess or logs.** Pinned in Task 6 by `test_harbor_env_scrubs_credentials` and in Task 3 by `test_errors_never_contain_key`.

---

### Task 1: Per-request reservations in the runtime reducer (store v8)

**Files:**
- Modify: `src/democratize_security/runtime_events.py`, `src/democratize_security/store.py`, `src/democratize_security/backup.py`
- Test: `tests/test_runtime_events.py`, `tests/test_runtime_store.py`, `tests/test_backup.py`; update version constants in the existing store tests

**Interfaces:**
- **Produces:** reducer actions, allowed only while the phase is `running`:
  - `request_intent`, with fields `{request_id, preflight_input_tokens, max_output_tokens, reserve_cents, payload_sha256}`.
  - `request_settle`, with fields `{request_id, input_tokens, cached_input_tokens, output_tokens, cost_cents, response_sha256}`.
  - `request_unknown`, with fields `{request_id, reason}`.
- **Produces:** new state keys:
  - `request_count`, `input_tokens`, `output_tokens` and `committed_cents` (all ints, starting at 0);
  - `open_request`: `None`, or `{request_id, preflight_input_tokens, max_output_tokens, reserve_cents}`;
  - `unknown_requests` (int).
- **Rules:**
  - `request_intent` requires `open_request is None`, `unknown_requests == 0`, and `committed_cents + reserve_cents <= max_cost_cents`. It increments `request_count`, adds the preflight and max-output tokens and the reserve to the counters, and sets `open_request`.
  - `request_settle` requires a matching `open_request`, `cost_cents <= reserve_cents`, `input_tokens <= preflight_input_tokens` and `output_tokens <= max_output_tokens`. It replaces the reserved amounts in the counters with the actual amounts and clears `open_request`.
  - `request_unknown` requires a matching `open_request`. It keeps the reserved maxima, clears `open_request` and increments `unknown_requests`.
  - `seal` requires `open_request is None`.
  - A runtime `settle` requires `unknown_requests == 0`, `open_request is None` and `actual_cost_cents == committed_cents`.
- **Produces:** `store.VERSION == 8`.
  - v7 → v8 migration (`migrate=True`) is allowed only when the v7 ledger has **no runtime attempts**. Otherwise it fails with `"v7 runtime attempts cannot be migrated"`. Offline history bytes are unchanged.
  - `backup.SUPPORTED_STORE_VERSIONS == {8}`, and store_version 5, 6 or 7 packages are refused with the existing matching-tool instructions.

- [ ] **Step 1: Write the failing tests**
  - `test_runtime_events.py`:
    - `test_request_intent_settle_updates_counters`: intent with reserve 40, preflight 1000, max output 500, then settle with cost 3, input 900, output 200. Expect `(request_count, input_tokens, output_tokens, committed_cents) == (1, 900, 200, 3)` and `open_request is None`.
    - `test_request_requires_running_and_single_open`
    - `test_request_reserve_cannot_exceed_hold`: `max_cost_cents=236`, `committed_cents` 200, reserve 40 → `RuntimeLedgerError`.
    - `test_settle_exceeding_reservation_rejected`
    - `test_unknown_request_keeps_maxima_and_blocks`: after unknown, a new intent raises, `settle` raises, and the counters keep the reserved values.
    - `test_seal_requires_no_open_request`
    - `test_runtime_settle_must_equal_committed_cents`
  - `test_runtime_store.py`:
    - `test_open_request_blocks_seal_and_new_requests_after_reopen`
    - `test_v7_runtime_ledger_refuses_migration`
    - `test_v7_offline_ledger_migrates_bytes_unchanged`
  - `test_backup.py`: parametrize the old-package refusal over `[5, 6, 7]`.
- [ ] **Step 2: Run and confirm the failures**: `uv run --locked pytest -q tests/test_runtime_events.py tests/test_runtime_store.py tests/test_backup.py`.
- [ ] **Step 3: Implement.**
  - Add the actions to `_FIELDS`, the state keys to `_STATE_KEYS`, and the transitions to `reduce_runtime`. Validate every int with `_amount` and every hash with `_hash`.
  - In `store.py`, bump `VERSION`, add `V7_SCHEMA = SCHEMA` (no table change) plus the migration guard, and update `budget_snapshot` so a nonzero `unknown_requests` keeps the attempt counted at its full hold. That already holds while it stays unsettled, but assert it in a test.
- [ ] **Step 4: Run the full suite with PostgreSQL and Docker**: `~/projects/run-ds-tests.sh ~/projects/ds-meter`. Expect 0 failures and 0 skips.
- [ ] **Step 5: Commit**: "Reserve and settle each model request in the runtime ledger (store v8)".

### Task 2: Pure metering core

**Files:**
- Create: `src/democratize_security/model_meter.py`
- Test: `tests/test_model_meter.py`

**Interfaces:**
- **Consumes:**
  - Task 1 actions.
  - `model_budget.RateCard`, `TrialLimits`, `Usage`, `quote_next_request`, `actual_cost` and `ceiling_cents`.
- **Produces:**
  - `ProviderResult` (frozen dataclass), with fields `content: str`, `status: str` (`"completed"` | `"incomplete"`), `model: str`, `usage: Usage | None`, `response_sha256: str`.
  - `class Provider(Protocol)`, with methods `count_input_tokens(payload: dict) -> int` and `create(payload: dict) -> ProviderResult`.
  - `class ProviderError(Exception)`, which means the outcome is unknown.
  - `class MeterRefused(Exception)`, which means nothing was sent.
  - `class Meter`, with constructor `Meter(store: PlanStore, attempt_id: str, rate: RateCard, limits: TrialLimits, provider: Provider, *, reasoning_effort: str)`.
  - `Meter.generate(messages: list[dict]) -> str`, where each message is `{"role": "system"|"user"|"assistant", "content": str}` and at most 512 messages are accepted.
  - `Meter.latched: bool`.
  - `ScriptedProvider(responses: tuple[str, ...], *, input_tokens: int = 1000, output_tokens: int = 200)`, a model-free provider that returns fixed `Usage` values.
- **`generate` sequence.** No step may be reordered.
  1. If `latched`, raise `MeterRefused`.
  2. Build the payload: `{"model": rate.model, "input": messages, "reasoning": {"effort": ...}, "max_output_tokens": limits.max_output_tokens_per_request, "store": False}`.
  3. Preflight: `count_input_tokens(payload)`.
  4. Quote with `quote_next_request`, using the counters from `store.attempts()` (state key names from Task 1) and `remaining_usd = Fraction(max_cost_cents - committed_cents, 100)`, read from the same state.
  5. `record_runtime(request_intent)` with `reserve_cents=ceiling_cents(quote)` and `payload_sha256=digest(payload)`.
  6. `create(payload)`, exactly once.
  7. Validate the result:
     - `status == "completed"`;
     - `model` starts with `rate.model`;
     - `usage` is not None;
     - `usage.output_tokens <= max_output_tokens`;
     - `usage.input_tokens <= preflight`.
  8. Settle. The cost is an upper bound: OpenAI reports no cache-write count, so all uncached input is priced at `max(input, cache_write)`. Use `Usage(input, cached, input - cached, output)` and `cost_cents=ceiling_cents(actual_cost(...))`, then record `request_settle` and return the content.
  9. Failure handling:
     - Any failure in steps 1–4 raises `MeterRefused` without recording an intent.
     - Any exception, or any invalid result, in steps 6–8 records `request_unknown` with a bounded reason, then latches and re-raises it as `ProviderError`.
     - The meter latches after any `MeterRefused` as well.

- [ ] **Step 1: Write the failing tests:**
  - `test_generate_reserves_before_send`: a fake provider asserts inside `create` that the store already shows `open_request`.
  - `test_settlement_is_upper_bound_cost`: Sol, input 1000 (cached 0), output 200 → `cost_cents == ceiling_cents(Fraction(1000*2500000 + 200*10000000, 10**12))` = 1.
  - `test_preflight_over_cap_refuses_without_intent`: preflight 64001 → `MeterRefused`, no new events, `create` never called.
  - `test_send_failure_after_intent_records_unknown_and_latches`: `create` raises `TimeoutError` → `ProviderError`, the state has `unknown_requests == 1`, and the next `generate` raises `MeterRefused` with `create` call count 1.
  - `test_incomplete_or_missing_usage_is_unknown`: parametrize over `status="incomplete"`, `usage=None` and a wrong model.
  - `test_twelfth_request_allowed_thirteenth_refused`
  - `test_remaining_budget_refuses_quote`: an attempt with `max_cost_cents=1` → refused without an intent.
- [ ] **Step 2: Run and confirm the failures.** `uv run --locked pytest -q tests/test_model_meter.py` should fail on the import.
- [ ] **Step 3: Implement** in `model_meter.py`. Use event IDs `f"{attempt_id}-req-{n:02d}-intent"` and `f"...-settle"` / `f"...-unknown"`, so that exact retries are idempotent.
- [ ] **Step 4: Run the tests and Ruff**, and confirm they pass.
- [ ] **Step 5: Commit**: "Meter each model request through a durable reservation".

### Task 3: OpenAI Responses provider adapter

**Files:**
- Create: `src/democratize_security/adapters/providers/__init__.py`, `src/democratize_security/adapters/providers/openai_responses.py`
- Test: `tests/test_openai_responses.py`, using `httpx.MockTransport` only. No network.

**Interfaces:**
- **Produces:** `OpenAIResponsesProvider(api_key: str, *, transport: httpx.BaseTransport | None = None, timeout_seconds: float = 300.0)`, which implements `model_meter.Provider`.
- **Details:**
  - It uses `httpx.Client(base_url="https://api.openai.com/v1", transport=..., timeout=...)` with no retries. httpx does not retry by default, so do not wrap it.
  - `count_input_tokens` sends `POST /responses/input_tokens` with the payload minus `max_output_tokens`, `store` and `reasoning`, and returns `int(body["input_tokens"])`. Any non-200 response raises `MeterRefused`.
  - `create` sends `POST /responses` with the payload plus `"service_tier": "default"`. It maps `body["status"]`, `body["model"]` and the `output_text` concatenation of `output[*].content[*]` items of `type == "output_text"`. Usage comes from `usage.input_tokens`, `usage.input_tokens_details.cached_tokens` and `usage.output_tokens`; any missing field gives `usage=None`. `response_sha256` is the sha256 of the raw body bytes.
  - Any transport error, any non-200 response, or invalid JSON raises `ProviderError`.
  - `__repr__` and every exception message must exclude the key.
  - `load_key(path: Path) -> str` requires a regular file owned by the current uid with mode `0o600`, at most 512 bytes, and strips surrounding whitespace.

- [ ] **Step 1: Write the failing tests:**
  - `test_count_and_create_map_usage`
  - `test_missing_usage_fields_give_none`
  - `test_http_500_and_timeout_raise_provider_error`
  - `test_errors_never_contain_key`: set the key to `"sk-test-SECRET"`, trigger every error path, and assert the key appears in no `str(exc)` or `repr`.
  - `test_request_body_has_no_previous_response_id_and_store_false`
  - `test_load_key_rejects_group_readable_and_symlink`
- [ ] **Step 2: Run, implement, and run again until green.**
- [ ] **Step 3: Commit**: "Add a retry-free OpenAI Responses provider for the meter".

### Task 4: Broker socket and Harbor client agent

**Files:**
- Create: `src/democratize_security/model_broker.py` (core, stdlib only), `src/democratize_security/adapters/runners/metered_terminus.py`
- Test: `tests/test_model_broker.py`, `tests/test_metered_terminus.py`

**Interfaces:**
- **Produces (`model_broker`):**
  - `Broker(meter: Meter, socket_path: Path)`. This creates the socket inside a fresh `0700` directory, with socket mode `0600`.
  - `Broker.serve(process: subprocess.Popen, *, deadline: float) -> str`. It returns `"exited"`, `"deadline"` or `"halted"`. It is single-threaded: `select` with a 1 s timeout, then `process.poll()` checks.
  - Protocol: one JSON object per connection, newline-terminated, at most 8 MiB, `{"messages": [...]}`. The reply is `{"content": str}` or `{"error": "refused"|"unknown"}`.
  - On `"deadline"` the process is killed, after `process.terminate()` and a 10 s wait.
- **Produces (`metered_terminus`):**
  - `BrokeredLLM(BaseLLM)`. It reads the socket path from env `DS_MODEL_BROKER_SOCKET`. Its `call(prompt, message_history=..., **_)` sends `history + [{"role":"user","content":prompt}]` and ignores `previous_response_id`, so every payload is complete.
    - An error reply, or any socket failure, sets `self._latched` and raises `TransportHalted(ContextLengthExceededError)`.
    - Once latched, every call raises immediately without connecting.
    - It returns `LLMResponse(content=..., model_name="metered", usage=None)`. Harbor's cost fields are never authoritative.
  - `MeteredTerminus(Terminus2)`, with the same `setup` override as `terminus_conformance._ScriptedTerminus` and reusing `PresenceCheckedTmuxSession`. It forces `max_turns=12`, `enable_summarize=False`, `record_terminal_session=False` and `llm_backend="metered"`, and its `_init_llm` returns `BrokeredLLM()`. `name()` returns `"metered-terminus"`.

- [ ] **Step 1: Write the failing tests:**
  - `test_broker_round_trip_with_scripted_meter`: a real Unix socket, a child `python -c` client and `ScriptedProvider`.
  - `test_broker_rejects_oversized_and_malformed_requests_without_meter_call`
  - `test_broker_deadline_kills_process`
  - `test_latched_client_never_contacts_broker_again`: the first call gets `{"error":"unknown"}` and raises `TransportHalted`. A second call raises without a connection; count the accepts on a test server.
  - `test_transport_halted_is_not_retried_by_query_llm`: wrap `Terminus2._query_llm` retry semantics by calling it with a Chat over `BrokeredLLM` pointed at a server that answers an error, and assert exactly 1 accept.
  - `test_socket_dir_private`
- [ ] **Step 2: Run, implement, and run again until green.** The Harbor tests need `--group harbor`, so mark them the same way `tests/test_terminus_conformance.py` does.
- [ ] **Step 3: Commit**: "Broker Terminus2 model calls through the controller-owned meter".

### Task 5: Authenticated verification bridge

**Files:**
- Modify: `scripts/harbor_spike.py` (`accept_trial` accepts `reward=None`, which means either 0 or 1 is allowed while every MAC and artifact binding check is kept; `run_trial` gains keyword arguments `timeout: int = 600` and `env: dict | None = None`)
- Create: `src/democratize_security/adapters/runners/report_signer.py`
- Test: `tests/test_report_signer.py`, plus updated `tests/test_harbor_*` callers if signatures change

**Interfaces:**
- **Produces:**
  - `report_from_app_evidence(evidence: dict) -> dict`. It builds `verification.report.summarize([Check(id, evidence["checks"][id], evidence["details"].get(id, "")[:2048]) for id in sorted(evidence["checks"])])`. A check missing from `REQUIRED` gives an incomplete report, and an unknown id raises `ValueError`.
  - `python -m democratize_security.adapters.runners.report_signer`. It reads one JSON object from stdin, `{"challenge":..., "nonce_hex":..., "evidence":...}`, and writes the `sign_report` bytes to stdout. It writes nothing else, and exits 2 on any error with no nonce in stderr.
  - `sign_via_subprocess(challenge: dict, nonce: bytes, evidence: dict) -> bytes`. This is the controller side and passes the nonce only through the stdin pipe.
- [ ] **Step 1: Write the failing tests:**
  - `test_complete_pass_and_fail_reports_round_trip_through_admission`: a v8 store at `verifying`, the subprocess signer, then `admit_result`. Expect the phase to be completed with the outcome preserved.
  - `test_partial_evidence_interrupts_as_incomplete`
  - `test_signer_rejects_unknown_check_and_never_echoes_nonce`
  - `test_accept_trial_reward_none_still_requires_mac`
- [ ] **Step 2: Run, implement, and run again until green.**
- [ ] **Step 3: Commit**: "Bridge sealed-replay evidence into authenticated runtime admission".

### Task 6: Calibration driver, model-free dry run, CI and docs

**Files:**
- Create:
  - `scripts/calibration.py`
  - `campaigns/calibration-sol.v1.json`, `campaigns/calibration-luna.v1.json`. These are campaign schema v1 with the conditions `["rls_starter"]` (the public tasks ship the RLS helper and the instructions; this is recorded as a calibration label, not a comparison), 3 tasks, `repetitions: 1`, and `limits.max_cost_usd_cents` 708 and 69, `infrastructure_retries: 0`, `concurrency: 1`.
  - `docs/CALIBRATION.md`
  - `tests/test_calibration.py`
- Modify:
  - `.github/workflows/*.yml`: add a job `metered-dry-run` next to `terminus-conformance` that runs `python scripts/calibration.py --dry-run`.
  - `docs/MODEL_BATCH.md` (status: approved $10 calibration, transport implemented), `docs/STATUS.md`, `AGENTS.md` next-work pointer.
  - `scripts/worker_host.py`: add `"calibration"` to `PARENTS`.

**Interfaces:**
- **Consumes:** Tasks 1–5, `terminus_conformance.prepare_terminus_task`, `policy_replay.prepare_replay`, and `harbor_apps` `MAX_APP_BYTES`/`EVIDENCE_KEYS`.
- **Produces:**
  - `task_tree_sha256(path: Path) -> str`, which is `digest` over sorted `(relative_path, sha256(bytes), executable_bit)` tuples. It is used as each task's `revision` in the campaign files and is checked at run time.
  - `harbor_env() -> dict`, the scrubbed environment from Global Constraints plus `DS_MODEL_BROKER_SOCKET`.
  - `run_trial(store, campaign, trial, provider, rate, limits, workdir) -> dict`. Per trial it follows this exact order, with deterministic event IDs `f"{attempt_id}-{step}"`:
    1. **prepare:** `max_cost_cents` is the trial hold, and `config_sha256` is `digest({limits, model, reasoning_effort, pricing_snapshot_sha256})`.
    2. **dispatch_intent:** use `runner_request_id = job_name` and a deadline 30 minutes out.
    3. **Launch Harbor:** start `harbor run -a democratize_security.adapters.runners.metered_terminus:MeteredTerminus` through `Popen`, with the task copy whose `task.toml` agent timeout is 900.
    4. **acknowledge:** use `worker_id = f"harbor:{job_name}"`, then call `Broker.serve`.
    5. **Collect** with `accept_trial(..., reward=None)`. On any collection failure, stop here: interrupt with a bounded reason and settle with `committed_cents` (unless a request is unknown), then return the record.
    6. **Publish and seal:** publish the bundle to `objects/`, then seal with `stop_observation_sha256 = digest({"returncode": rc, "result_sha256": sha256(result.json)})`.
    7. **verify_intent:** create a `VerifierSession` from `store.runtime_context`.
    8. **Replay:** run the replay job with `nop` and a fresh Harbor nonce, call `accept_trial(reward=None, expected_bundle=bundle)`, sign with `sign_via_subprocess`, and admit with `admit_result`.
    9. **settle:** use `actual_cost_cents = committed_cents` and `receipt_id = f"{attempt_id}-ledger"`.
  - `main()`:
    - `--dry-run` uses one Sol-shaped trial on `invoice-read` with `ScriptedProvider((reference_response(), COMPLETE, COMPLETE))`, in a temp ledger. It requires admitted outcome `pass`, coverage `complete` and `committed_cents > 0`.
    - `--live --key-file PATH --ledger DIR` refuses unless all of these hold:
      - `DS_WORKER_HOST_REQUIRED=1`;
      - the summed campaign caps are ≤ 1000;
      - the ledger's `budget_snapshot` is unblocked for both campaigns.

      It runs the six trials in order (Sol read, search, export, then Luna), stops at the first unknown request or integrity error, and writes `.research/calibration/summary.json` with the per-trial outcome, the requests, the tokens and `committed_cents`.

- [ ] **Step 1: Write the failing tests:**
  - `test_campaign_caps_within_approved_budget`: 708 + 69 ≤ 1000, and each equals 3 × `trial_reservation_ceiling_cents`.
  - `test_task_revisions_match_trees`
  - `test_harbor_env_scrubs_credentials`: set `OPENAI_API_KEY`, `FOO_API_KEY` and `GH_TOKEN` and assert none of them is present.
  - `test_live_refuses_without_worker_host_flag`
  - `test_collection_failure_interrupts_and_settles_committed`: use a fake job directory.
- [ ] **Step 2: Run, implement, and run again until green.** Then run `python scripts/calibration.py --dry-run` locally under Docker and record its summary.
- [ ] **Step 3: Run the full suite plus the dry run on `ds-worker`** with `DS_WORKER_HOST_REQUIRED=1`, the same way #67 did. Archive and release the jobs.
- [ ] **Step 4: Write the docs.** `docs/CALIBRATION.md` covers:
  - the run commands;
  - the trust boundary: the signer bridges Harbor-nonce-bound evidence, so it is not a verifier signing independently in its own container;
  - the cost basis: an upper bound, reconciled against the provider bill separately;
  - the stop conditions.
- [ ] **Step 5: Commit, push, open a PR closing #69, wait for green CI, and merge.**

### Task 7: Live calibration (owner-gated, spends money)

Run this task only after Task 6 is merged.

- [ ] **Step 1: Gate check.** Confirm all of the following:
  - #19 has owner acceptance of the worker evidence (it is listed as unresolved in `calibration.v1.json`);
  - the owner has placed the key at `/home/controller/.secrets/openai-api-key` on `ds-worker` (directory `0700`, file `0600`, owned by `controller`) and set a provider hard limit of ≤ $10. #19 was accepted on 2026-10-20;
  - the prices on the cited pages still match the snapshot (if not, stop and re-propose).
- [ ] **Step 2: Run** `python scripts/calibration.py --live --key-file ... --ledger ...` on `ds-worker`.
- [ ] **Step 3: Report the results.** Record the outcomes, requests, tokens, `committed_cents` and stop reason on #57/#69 without any key or account details. Re-estimate the pilot from the measured usage, and ask the owner before anything beyond the $10.
