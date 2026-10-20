# Runtime Lifecycle and Authenticated Admission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store v7 records the authenticated live trial lifecycle (dispatch intent → acknowledgement → sealing → verification challenge → authenticated result → settlement, plus reconciliation) in the same SQLite attempt/event stream, admits verifier results only through a live `VerifierSession` inside one fenced transaction, fences restored ledgers before dispatch, and projects runtime attempts onto the existing recovery policy.

**Architecture:** A pure reducer (`runtime_events.py`) owns runtime transitions and validation, mirroring the offline `_reduce`. `PlanStore` gains a runtime write API that runs every transition inside `_begin_write`, rejects mixing runtime and offline actions on one attempt, and replays both kinds on read. Results live in an immutable `runtime_results` table whose row commits with its event and state. A `restore_fences` table blocks new dispatch until an explicit reconciliation event.

**Tech Stack:** Python 3.12 standard library, SQLite (FULL sync), existing `objects`, `runtime_auth`, `recovery`, `backup` modules.

**Spec:** GitHub issue #62 acceptance list; `docs/PERSISTENCE.md` (attempt transitions, crash windows, budget); `docs/RUNTIME_AUTH.md`; ADR 0005/0006.

## Global Constraints

- Store `VERSION = 7`; v1–v6 open only with `migrate=True`, validating all old records first; old rows and canonical JSON bytes never change. No automatic migration.
- Every runtime write goes through `PlanStore._begin_write()` (generation fence before any effect).
- Runtime requests carry `"mode": "runtime"`; offline requests never do. One attempt is one mode for life.
- Global policy unchanged in spirit: any nonterminal attempt, any unsettled cost, any accounting stop, or any unreconciled restore fence blocks new preparation; a fence additionally blocks `dispatch_intent`.
- No API ever emits a second dispatch for the same attempt; `resolve` cannot change `runner_request_id` or `worker_id`.
- Completion only via `admit_result`; `completed` means complete coverage, not pass. Incomplete reports → `interrupted` with reason `incomplete_verification`, hold retained.
- Amounts integer cents; identifiers `[A-Za-z0-9_.:-]{1,128}`; hashes lowercase 64-hex; source revision 40-hex; request JSON ≤ 8 KiB.
- No model calls, dispatcher, Harbor import or CLI command in this change.

## Review Focus

1. Restart between `verify_intent` and admission → new generation ≠ committed challenge generation → admission refuses; attempt can only go `reconcile`→`interrupt`; hold retained.
2. Same `event_id` reused with a different runtime request (or a runtime event ID colliding with an offline accounting event ID) → persistent integrity stop, original untouched.
3. Offline `record_accounting`/`record_artifact`/`record_verification_intent`/`record_evidence` called on a runtime attempt → rejected with no effects.
4. Artifact object deleted or altered after sealing → every read, reopen and `budget_snapshot` raise; admission refuses.
5. A restored v7 ledger reopened repeatedly → fence still blocks dispatch until `reconcile_restore`, which itself requires no active (non-reconciling) runtime attempt.

---

### Task 1: Pure runtime reducer

**Files:** Create `src/democratize_security/runtime_events.py`; Test `tests/test_runtime_events.py`.

**Interfaces — Produces:**
- `RUNTIME_ACTIONS = ("prepare", "dispatch_intent", "acknowledge", "seal", "verify_intent", "reconcile", "resolve", "interrupt", "settle")` (admission is store-only, Task 4).
- `reduce_runtime(previous: dict | None, request: dict) -> dict` raising `StoreError` (import from `store`? no — define `RuntimeError_ = ValueError` subclass `RuntimeLedgerError` here; store wraps it as `StoreError`).
- State keys (all present, `None` until set): `mode="runtime"`, `attempt_id, campaign_id, trial_id, revision, phase, previous_phase, max_cost_cents, actual_cost_cents, receipt_id, reason, basis_sha256, source_revision, task_revision, verifier_sha256, protocol, config_sha256, runner_request_id, dispatch_deadline, worker_id, stop_observation_sha256, artifact_ref, verification_request_id, challenge_sha256, result_event_id`.
- Request fields per action (plus `mode, action, attempt_id, expected_revision`): prepare `{campaign_id, trial_id, max_cost_cents, basis_sha256, source_revision, task_revision, verifier_sha256, protocol, config_sha256}`; dispatch_intent `{runner_request_id, dispatch_deadline}` (ISO-8601 UTC); acknowledge `{runner_request_id, worker_id}`; seal `{runner_request_id, worker_id, stop_observation_sha256, artifact_ref}`; verify_intent `{verification_request_id, challenge}`; reconcile `{reason}`; resolve `{observation_sha256}`; interrupt `{reason}`; settle `{actual_cost_cents, receipt_id}`.
- Transition table exactly as PERSISTENCE.md, with: `resolve` only `reconciling → previous_phase`; `interrupt` from any nonterminal incl. `reconciling`; `settle` only terminal and unsettled.

- [ ] **Step 1: Tests** (one per row and per rejection): `test_happy_path_reaches_verifying_with_pinned_identities`; `test_acknowledge_requires_same_request`; `test_seal_requires_acknowledged_worker_and_request`; `test_reconcile_records_previous_phase_and_resolve_returns_only_there`; `test_resolve_cannot_change_request_or_worker`; `test_settle_only_after_terminal`; `test_stale_revision_rejected`; `test_unknown_or_extra_fields_rejected`; `test_offline_request_rejected`; `test_bad_hashes_amounts_deadlines_rejected`.
- [ ] **Step 2–4:** run (fail), implement, run (pass): `uv run --locked pytest tests/test_runtime_events.py -q`.
- [ ] **Step 5: Commit** `Add pure runtime attempt reducer`.

### Task 2: Store v7 schema, migration and mixed-mode replay

**Files:** Modify `src/democratize_security/store.py`; Test `tests/test_runtime_store.py`, adjust version assertions in existing store tests.

**Interfaces — Produces:** `VERSION = 7`; `V6_SCHEMA = dict(SCHEMA)` then new immutable tables (UPDATE/DELETE triggers like the others):
`runtime_results(event_id PK, attempt_id UNIQUE REFERENCES attempts, revision INTEGER, record_json TEXT, FOREIGN KEY(attempt_id, revision) REFERENCES attempt_events(attempt_id, revision))`;
`restore_fences(fence_id PK, created_at, record_json)`; `restore_reconciliations(event_id PK, fence_id UNIQUE REFERENCES restore_fences, created_at, record_json)`.
`attempts()` dispatches each event row to `reduce_runtime` when `request["mode"] == "runtime"`, else `_reduce`; mixing modes within one attempt is an error. Legacy writers (`record_accounting`, `record_artifact`, `record_verification_intent`, `record_evidence`) reject attempts whose state has `mode == "runtime"`.

- [ ] **Step 1: Tests:** `test_v6_store_requires_explicit_migration_and_preserves_bytes`; `test_mixed_mode_history_rejected_on_read`; `test_offline_writers_reject_runtime_attempts` (all four); `test_new_tables_are_immutable`; crash test `test_process_death_around_v7_migration_commit` (reuse the existing subprocess/`os._exit` helper).
- [ ] **Step 2–4:** fail → implement (validate v6 records before `BEGIN IMMEDIATE`, as v5→v6 does) → pass, plus the whole existing suite.
- [ ] **Step 5: Commit** `Add store v7 schema with explicit v6 migration`.

### Task 3: Fenced runtime transitions

**Files:** Modify `store.py`; Test `tests/test_runtime_store.py`.

**Interfaces — Produces:** `PlanStore.record_runtime(event_id: str, request: dict) -> dict` (detached state). Within `_begin_write`: exact event retry → original state; conflicting reuse (including offline event IDs) → persistent `accounting_stops` row then error. Store-level checks: `prepare` reuses `budget_snapshot` blocking (extended to runtime phases and unreconciled fences) and planned-trial identity; `dispatch_intent` refused while any fence lacks a reconciliation; `seal` reads `artifact_ref` with `objects.read_artifact`-equivalent validation from `objects_directory` and reconciles durability before commit; `verify_intent` requires `challenge` to be a valid public challenge (use `runtime_auth._challenge`) whose `context` equals `PlanStore.runtime_context(attempt_id, verification_request_id, expected_revision=state.revision + 1)`.
`PlanStore.runtime_context(attempt_id, verification_request_id, *, expected_revision) -> VerificationContext` derives every field from validated state, the current `controller_generation`, the sealed artifact object's payload and raw hashes, and `artifact_binding_sha256 = digest(artifact_ref)`.

- [ ] **Step 1: Tests:** `test_full_lifecycle_to_verifying`; `test_second_active_attempt_blocked`; `test_dispatch_blocked_by_unreconciled_fence`; `test_seal_rejects_missing_or_tampered_artifact`; `test_verify_intent_requires_store_derived_challenge` (mutate each context field → reject); `test_conflicting_event_reuse_persists_stop`; `test_exact_retry_across_reopen_returns_original`; `test_superseded_handle_runtime_write_has_no_effect`; crash tests before/after commit for `dispatch_intent` and `seal`.
- [ ] **Step 2–4:** fail → implement → pass.
- [ ] **Step 5: Commit** `Record fenced runtime transitions in the shared attempt ledger`.

### Task 4: Authenticated result admission

**Files:** Modify `store.py`; Test `tests/test_runtime_admission.py`.

**Interfaces — Consumes:** `VerifierSession`, `sign_report` (test fixture signer). **Produces:** `PlanStore.admit_result(event_id: str, attempt_id: str, expected_revision: int, session: VerifierSession, raw: bytes) -> dict` and `PlanStore.runtime_results() -> list[dict]`. In one fenced transaction: attempt in `verifying` at `expected_revision`; `session.public_challenge()["challenge_sha256"] == state["challenge_sha256"]` and its context equals `runtime_context(...)` recomputed now; `observation = session.authenticate(raw)`; record `{schema_version:1, kind:"runtime_result", event_id, observation: observation.public_record(), envelope_base64, coverage, outcome}`; event request `{"mode":"runtime","action":"admit","attempt_id","expected_revision","result_sha256"}` moves `verifying → completed` (complete) or `→ interrupted` with `reason="incomplete_verification"`; state `result_event_id` set. Readers re-hash `envelope_base64` against `envelope_sha256` and re-check linkage on every read/reopen.

- [ ] **Step 1: Tests:** `test_complete_failing_report_completes_and_keeps_outcome`; `test_partial_report_interrupts_and_keeps_hold`; `test_wrong_session_or_challenge_rejected`; `test_restart_cannot_admit_pre_crash_report` (new store generation + new session); `test_conflicting_second_report_rejected_without_effects`; `test_exact_admit_retry_returns_original`; `test_result_row_event_and_state_commit_together` (inject SQL failure on insert → nothing persisted); `test_tampered_result_row_rejected_on_reopen`.
- [ ] **Step 2–4:** fail → implement (extend `reduce_runtime` with store-only `admit`, unreachable through `record_runtime`) → pass.
- [ ] **Step 5: Commit** `Admit authenticated verifier results atomically with their event`.

### Task 5: Restore fencing and v7 backups

**Files:** Modify `store.py`, `src/democratize_security/backup.py`; Test `tests/test_backup.py`, `tests/test_runtime_store.py`; Docs `docs/BACKUP.md`.

**Interfaces — Produces:** `SUPPORTED_STORE_VERSIONS = frozenset({7})` (v6 archives get the same "restore with matching tool, migrate, re-backup" refusal v5 gets). `restore_backup` inserts one `restore_fences` row (fence_id = restore ID, record includes source manifest digest) into the restored database before it returns, without opening it as a controller. `PlanStore.reconcile_restore(event_id, fence_id, statement: str) -> dict` (fenced) requires every nonterminal runtime attempt to be `reconciling` or terminal.

- [ ] **Step 1: Tests:** `test_restored_v7_ledger_blocks_dispatch_until_reconciled`; `test_fence_survives_reopen`; `test_reconcile_restore_requires_reconciling_attempts`; `test_v6_backup_package_refused_with_instructions`; existing backup corruption tests updated to v7.
- [ ] **Step 2–4:** fail → implement → pass.
- [ ] **Step 5: Commit** `Fence restored v7 ledgers before dispatch`.

### Task 6: Recovery projection, docs and handoff

**Files:** Modify `store.py`, `docs/PERSISTENCE.md`, `docs/RUNTIME_AUTH.md`, `docs/RECOVERY.md`, `docs/STATUS.md`, `AGENTS.md` next-work pointer; Create `docs/decisions/0007-runtime-ledger.md`; Test `tests/test_runtime_store.py`.

**Interfaces — Produces:** `PlanStore.recovery_state(attempt_id: str) -> recovery.RecoveryState` mapping phase/previous_phase/identities/cost; `artifact_stage="referenced"` once sealed else `"none"`; `generation = controller_generation`; `integrity_ok=True` only after full validation (errors propagate instead).

- [ ] **Step 1: Tests:** `test_recovery_state_matches_each_runtime_phase` (feeds `recovery_decision` with a matching observation and asserts the decision preserves held/settled cents); `test_lost_acknowledgement_never_advises_resubmission`.
- [ ] **Step 2–4:** fail → implement → pass; full suite with PostgreSQL/Docker required; Ruff; build.
- [ ] **Step 5: Docs** — PERSISTENCE v7 section (tables, actions, crash windows covered by tests), ADR 0007 (same-ledger runtime mode, inline envelope storage, fence semantics), STATUS capability lines.
- [ ] **Step 6: Commit** `Project runtime attempts onto recovery decisions and document store v7`.
