# Terminus2 Transport Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove, without any model or provider, that pinned Harbor 0.24.0 Terminus2's real parser, tmux command loop and completion confirmation can drive the audited invoice-read candidate container end to end, under the existing collector, separate verifier, sealing and boundary audit.

**Architecture:** A trusted `Terminus2` subclass overrides `_init_llm` to return a fixed in-process `ScriptedLLM` (no LiteLLM/client/key) and replaces Terminus2's root tool-install step with an unprivileged, fail-closed `tmux -V` presence check. Each reviewed script is a fixed class loaded by `harbor run -a module:Class`, so `harbor_spike.run_trial` is reused unchanged. A conformance script copies the invoice-read task with a derived Dockerfile that bakes tmux at build time, runs three finite controls, and reuses the existing acceptance, replay and audit helpers.

**Tech Stack:** Python 3.12, Harbor 0.24.0 (`harbor` dependency group only), Docker Engine, pytest.

**Spec:** GitHub issue #63 (scope, acceptance and exclusions), plus `docs/APPLICATION_TASKS.md`, `docs/HARBOR_AUDIT.md`.

## Global Constraints

- Harbor version is exactly `0.24.0`; refuse to run otherwise (same check as `scripts/harbor_audit.py`).
- No LiteLLM/client/provider construction, no API keys, no network calls from the agent side; `model_calls` reported as 0.
- Fixed finite limits: scripted responses are a fixed tuple; `max_turns = 6`; `enable_summarize = False`; `record_terminal_session = False`; exhaustion raises.
- The adapter module imports Harbor; nothing in `src/democratize_security` outside it may import it. Core stays Harbor-independent.
- Canonical task files (`tasks/harbor/invoice-read/**`), collector, compose hardening, verifier and scoring stay byte-identical; only a *copied* task under `.research/` gets the derived Dockerfile.
- Candidate stays rootless, read-only rootfs, `network_mode = "no-network"`, no capabilities; no controller/home/socket/credential mounts. All existing extraction/storage/replay controls remain regressions.
- Fake transport output is never evidence of model capability or research success: results carry `"scope": "model_free_transport_conformance"` and `"security_verdict": "not_evaluated"`.
- Do not edit `src/democratize_security/store.py`, `cli.py`, shared `docs/STATUS.md` beyond a factual capability line, or `scripts/harbor_spike.py`.

## Review Focus

1. Image without tmux (or tmux not runnable as the unprivileged default user) → setup must fail closed with a clear error, never fall back to Harbor's root apt install.
2. Script exhausted before completion (e.g. the confirmation turn missing) → `ScriptedLLM.call` raises; the trial must not be accepted as an oracle-equivalent pass.
3. A caller passing model/provider options (`-m`, `llm_backend="litellm"`, `api_base`) → still no LiteLLM construction; the scripted backend ignores no instruction silently but rejects non-scripted backends.
4. Malformed JSON from the script → Terminus2's real parser path is exercised; the candidate app stays the starter and the verifier grades exactly the reviewed `nop` outcomes.
5. Base64 payload larger than tmux's message limit → the reference payload size is asserted below 12 KiB at test time, so a growing reference app fails a unit test instead of truncating in the pane.

---

### Task 1: Scripted backend and presence-checked tmux session

**Files:**
- Create: `src/democratize_security/adapters/runners/terminus_conformance.py`
- Test: `tests/test_terminus_conformance.py`

**Interfaces:**
- Produces:
  - `class ScriptedLLM(harbor.llms.base.BaseLLM)`: `__init__(self, responses: tuple[str, ...])`; `async call(self, prompt: str, **kwargs) -> LLMResponse` returns the next response with `usage=None`, raises `ScriptExhausted` after the last; `calls: int` property; `get_model_context_limit() -> 32768`; `get_model_output_limit() -> 4096`.
  - `class ScriptExhausted(RuntimeError)`.
  - `class PresenceCheckedTmuxSession(TmuxSession)`: overrides `_attempt_tmux_installation()` to exec `tmux -V` as `self._user` (the environment default user) and raise `RuntimeError("tmux missing for unprivileged agent user")` on nonzero; never execs as root.
  - `reference_response() -> str`: the JSON response whose single command is `printf '%s' '<base64 of tasks/harbor/invoice-read/solution/app.py>' | base64 -d > /candidate/app.py\n` with `task_complete: false`.
  - `COMPLETE = '{"analysis": "done", "plan": "confirm", "commands": [], "task_complete": true}'`.

- [ ] **Step 1: Write failing tests** — `pytest.importorskip("harbor")` at module top, plus a CI job in Task 3 that sets `REQUIRE_HARBOR_TESTS=1` and fails on skip (mirror `tests/integration/conftest.py`'s REQUIRE pattern). Tests:
  - `test_scripted_llm_returns_fixed_responses_then_exhausts`: two calls return the tuple in order, third raises `ScriptExhausted`, `calls == 2`.
  - `test_reference_response_parses_with_real_terminus_parser`: `TerminusJSONPlainParser().parse_response(reference_response())` has no error, one command, `is_task_complete is False`; decoding the base64 equals the reference app bytes exactly.
  - `test_reference_payload_fits_tmux_message_limit`: `len(reference_response().encode()) < 12 * 1024`.
  - `test_presence_check_never_runs_as_root_and_fails_closed`: fake environment records `(command, user)`; returncode 1 → `RuntimeError`; every recorded user is the unprivileged default user, never `"root"`.
- [ ] **Step 2: Run** `uv run --locked --group harbor pytest tests/test_terminus_conformance.py -v` — expect ImportError/FAIL.
- [ ] **Step 3: Implement** the module (module docstring states: trusted conformance fixture, not a model or research agent).
- [ ] **Step 4: Run** the same command — PASS.
- [ ] **Step 5: Commit** `Add scripted Terminus2 backend and fail-closed tmux presence check`.

### Task 2: Conformance agents

**Files:**
- Modify: `src/democratize_security/adapters/runners/terminus_conformance.py`
- Test: `tests/test_terminus_conformance.py`

**Interfaces:**
- Consumes: Task 1 names.
- Produces (import paths used by Task 3):
  - `ScriptedReferenceTerminus(Terminus2)` — script `(reference_response(), COMPLETE, COMPLETE)`.
  - `MalformedTerminus(Terminus2)` — script of 6 copies of `"this is not json"`; never completes.
  - Both: `name() -> "scripted-terminus"`; `__init__(self, *args, **kwargs)` forces `max_turns=6, enable_summarize=False, record_terminal_session=False, llm_backend="scripted"` before `super().__init__`; `_init_llm(...)` returns `ScriptedLLM(self.SCRIPT)` and raises `ValueError` if `llm_backend != "scripted"`; `setup()` builds `PresenceCheckedTmuxSession` with the same arguments as upstream `Terminus2.setup` (no recording paths).

- [ ] **Step 1: Write failing tests:**
  - `test_agents_never_construct_litellm`: monkeypatch `harbor.agents.terminus_2.terminus_2.LiteLLM` to raise; constructing each agent with `model_name="placeholder", logs_dir=tmp_path` succeeds and its `_llm` is a `ScriptedLLM`.
  - `test_agents_force_finite_options`: `options.max_turns == 6`, `enable_summarize is False`, `record_terminal_session is False`, even when kwargs try to set them otherwise.
  - `test_reference_script_requires_confirmation`: the script is exactly reference, `COMPLETE`, `COMPLETE` (so Terminus2's "Are you sure?" confirmation is exercised).
  - `test_non_scripted_backend_is_rejected`: calling `_init_llm` with `llm_backend="litellm"` raises `ValueError`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `Add model-free scripted Terminus2 conformance agents`.

### Task 3: Live conformance script, derived task, CI job, docs

**Files:**
- Create: `scripts/terminus_conformance.py`, `docs/TERMINUS_CONFORMANCE.md`
- Modify: `.github/workflows/ci.yml` (new job `terminus-conformance`), `tests/test_terminus_conformance.py`, `docs/STATUS.md` (one factual line), `AGENTS.md` immediate-next-work pointer if it names #63.

**Interfaces:**
- Consumes: `harbor_spike.run_trial(task, agent, jobs_dir, job_name) -> nonce`; from `scripts/harbor_apps.py`: `accept_app`, `expected_outcomes`, `prepare_replay`/`record_replay` usage exactly as in `run_task`; `scripts/harbor_audit.py` audit as used by `harbor_apps.main`.
- Produces: `prepare_terminus_task(source: Path, destination: Path) -> None` — `shutil.copytree` the canonical task, then append to the copy's `environment/Dockerfile`, *before* `ENTRYPOINT`, exactly: `RUN apt-get update && apt-get install -y --no-install-recommends tmux && rm -rf /var/lib/apt/lists/*`. Output directory `.research/terminus-conformance` (refuse reuse; add it to `PARENTS` in `scripts/worker_host.py` so `DS_WORKER_HOST_REQUIRED=1` works).

- [ ] **Step 1: Write failing unit tests** for `prepare_terminus_task`: every file except `environment/Dockerfile` is byte-identical to the canonical task; the Dockerfile differs only by that one inserted line directly before `ENTRYPOINT`; the canonical task is unmodified.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** `scripts/terminus_conformance.py` with three controls:
  1. `scripted` — `ScriptedReferenceTerminus` on the derived task; accept with `expected_outcomes("invoice-read", "oracle")` (reward 1).
  2. `malformed` — `MalformedTerminus`; accept with `expected_outcomes("invoice-read", "nop")` (reward 0) — if Harbor records the agent exception, accept only when that exception is the scripted exhaustion/max-turns outcome.
  3. `replay` — seal the `scripted` bundle and replay with `nop` exactly as `run_task` does for `oracle`.
  Then run the existing boundary audit over all three trials and require `outcome == "pass"` and `own_filesystem` handling identical to `harbor_apps`. Write `summary.json` with built image IDs, Harbor version, `model_calls: 0`, scope string from Global Constraints.
- [ ] **Step 4: Run** unit tests — PASS; run the live script on the dedicated worker with `DS_WORKER_HOST_REQUIRED=1` — expect all three controls accepted and audits passing.
- [ ] **Step 5: CI** — job `terminus-conformance` (Ubuntu, 35-minute job timeout, 30-minute command timeout): start Docker, preload the pinned alpine probe image, `uv sync --locked --group harbor`, `REQUIRE_HARBOR_TESTS=1 uv run --locked --group harbor pytest tests/test_terminus_conformance.py -ra`, then `uv run --locked --group harbor python scripts/terminus_conformance.py`; upload `.research/terminus-conformance` as an artifact `if: always()`.
- [ ] **Step 6: Docs** — `docs/TERMINUS_CONFORMANCE.md`: what is proven (parser, tmux loop, confirmation, collector, separate verifier, sealing, audit), what is not (any model capability, research result, cost behavior), exact source/image identities from the worker run, and limitations.
- [ ] **Step 7: Commit** `Run model-free Terminus2 conformance through the audited invoice-read boundary`.
