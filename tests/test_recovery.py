"""Recovery safety cases from PERSISTENCE.md, without executing external work."""

from dataclasses import FrozenInstanceError, asdict, replace
from itertools import product

import pytest

from democratize_security.recovery import (
    RecoveryError,
    RecoveryObservation,
    RecoveryState,
    recovery_decision,
)


def state(phase="preparing", **changes):
    fields = dict(
        trial_id="trial",
        attempt_id="attempt",
        generation=2,
        revision=1,
        phase=phase,
        max_cost_cents=300,
    )
    if phase == "planned":
        fields.update(attempt_id=None, revision=0, max_cost_cents=0)
    if phase in {"dispatch_pending", "running", "sealed", "verifying", "completed"}:
        fields.update(runner_request_id="runner-request")
    if phase in {"sealed", "verifying", "completed"}:
        fields.update(artifact_stage="referenced")
    if phase in {"verifying", "completed"}:
        fields.update(verification_request_id="verifier-request")
    fields.update(changes)
    return RecoveryState(**fields)


def observed(saved, **changes):
    fields = {
        name: getattr(saved, name)
        for name in (
            "trial_id",
            "attempt_id",
            "generation",
            "revision",
            "runner_request_id",
            "verification_request_id",
        )
    }
    fields.update(changes)
    return RecoveryObservation(**fields)


@pytest.mark.parametrize(
    "saved,inspection,action,held",
    [
        # Import and preparation transactions commit all or none. No attempt is
        # inferred from a failed transaction; existing store tests prove atomicity.
        (state("planned"), {}, "inspect_plan", 0),
        (state(), {}, "review_preparation", 300),
        # Before/after send is indistinguishable with no durable acknowledgement.
        (state("dispatch_pending"), {}, "reconcile_runner", 300),
        (state("dispatch_pending"), {"runner_status": "not_found"}, "reconcile_runner", 300),
        (
            state("running", worker_id="worker"),
            {"runner_status": "active", "worker_id": "worker"},
            "observe_worker",
            300,
        ),
        (
            state("running", worker_id="worker"),
            {"runner_status": "active", "worker_id": "worker", "deadline_expired": True},
            "inspect_stop",
            300,
        ),
        (
            state("running"),
            {"runner_status": "not_found", "deadline_expired": True},
            "reconcile_runner",
            300,
        ),
        (
            state("running"),
            {"runner_status": "stopped", "worker_id": "worker", "workspace_verified": True},
            "review_collection",
            300,
        ),
        (
            state("running"),
            {"runner_status": "stopped", "worker_id": "worker"},
            "review_interruption",
            300,
        ),
        # Linked bytes, durable orphans and committed references are distinct.
        (
            state(artifact_stage="linked"),
            {"artifact_status": "valid"},
            "reconcile_publication",
            300,
        ),
        (
            state(artifact_stage="linked"),
            {"artifact_status": "missing"},
            "reconcile_publication",
            300,
        ),
        (state(artifact_stage="durable"), {"artifact_status": "valid"}, "review_orphan", 300),
        (state(artifact_stage="referenced"), {}, "revalidate_artifact", 300),
        (
            state("sealed"),
            {"runner_status": "stopped", "worker_id": "worker", "artifact_status": "valid"},
            "review_verification_intent",
            300,
        ),
        (
            state("verifying"),
            {
                "runner_status": "stopped",
                "worker_id": "worker",
                "artifact_status": "valid",
                "evidence_status": "partial",
            },
            "reconcile_verifier",
            300,
        ),
        (
            state("verifying"),
            {
                "runner_status": "stopped",
                "worker_id": "worker",
                "artifact_status": "valid",
                "evidence_status": "complete",
            },
            "reconcile_verifier",
            300,
        ),
        (
            state("completed"),
            {"artifact_status": "valid", "evidence_status": "complete"},
            "review_committed_result",
            300,
        ),
        # Unknown cost persists across terminal and interrupted settlement windows.
        (state("interrupted"), {}, "reconcile_billing", 300),
        (state("interrupted", actual_cost_cents=0), {}, "inspect_terminal", 0),
        (state("interrupted", actual_cost_cents=250), {}, "inspect_terminal", 0),
        (state("interrupted", actual_cost_cents=301), {}, "integrity_stop", 0),
    ],
)
def test_crash_windows(saved, inspection, action, held):
    observation = observed(saved, **inspection)
    before = (asdict(saved), asdict(observation))
    decision = recovery_decision(saved, observation)
    assert decision.action == action
    assert decision.held_cents == held
    assert decision.settled_cents == saved.actual_cost_cents
    assert decision.execution_enabled is False
    assert decision.dispatch_blocked is True
    assert recovery_decision(saved, observation) == decision
    assert (asdict(saved), asdict(observation)) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("trial_id", "foreign-trial"),
        ("attempt_id", "foreign-attempt"),
        ("generation", 1),
        ("generation", 3),
        ("revision", 0),
        ("revision", 2),
        ("runner_request_id", "foreign-request"),
        ("verification_request_id", "foreign-verification"),
        ("worker_id", "foreign-worker"),
    ],
)
def test_observation_binding_rejects_stale_or_foreign_callbacks(field, value):
    saved = state("verifying", worker_id="worker")
    observation = (
        observed(saved, worker_id="worker", **{field: value})
        if field != "worker_id"
        else observed(saved, worker_id=value)
    )
    with pytest.raises(RecoveryError, match=field):
        recovery_decision(saved, observation)


@pytest.mark.parametrize(
    "phase", ["preparing", "dispatch_pending", "running", "sealed", "verifying"]
)
def test_reconciling_retains_origin_phase_and_same_decision(phase):
    saved = state(phase)
    inspection = observed(saved)
    resumed = replace(saved, phase="reconciling", previous_phase=phase)
    assert recovery_decision(saved, inspection) == recovery_decision(resumed, inspection)


def test_deadline_missing_worker_and_report_coverage_never_release_hold():
    saved = state("verifying", max_cost_cents=137)
    for runner, deadline, coverage, artifact in product(
        ("unknown", "not_found", "active", "stopped"),
        (False, True),
        ("unknown", "missing", "partial", "complete", "invalid"),
        ("unknown", "missing", "valid", "invalid"),
    ):
        inspection = observed(
            saved,
            runner_status=runner,
            deadline_expired=deadline,
            worker_id="worker" if runner in {"active", "stopped"} else None,
            artifact_status=artifact,
            evidence_status=coverage,
        )
        decision = recovery_decision(saved, inspection)
        assert decision.held_cents == 137
        assert decision.settled_cents is None
        assert decision.dispatch_blocked and not decision.execution_enabled
        assert decision.action in {
            "integrity_stop",
            "reconcile_runner",
            "observe_worker",
            "inspect_stop",
            "revalidate_artifact",
            "reconcile_verifier",
        }


@pytest.mark.parametrize("phase", ["preparing", "interrupted", "completed"])
def test_integrity_stop_overrides_even_terminal_advice(phase):
    saved = state(phase, integrity_ok=False)
    assert recovery_decision(saved, observed(saved)).action == "integrity_stop"


def test_missing_referenced_bytes_stop_even_if_worker_is_running():
    saved = state("verifying")
    inspection = observed(
        saved, runner_status="active", worker_id="worker", artifact_status="missing"
    )
    assert recovery_decision(saved, inspection).reason == "referenced_artifact_missing"


def test_missing_committed_evidence_does_not_return_terminal_result():
    saved = state("completed", actual_cost_cents=0)
    result = recovery_decision(
        saved, observed(saved, artifact_status="valid", evidence_status="missing")
    )
    assert result.reason == "committed_evidence_missing"
    assert result.settled_cents == 0


def test_zero_hold_still_blocks_dispatch():
    saved = state(max_cost_cents=0)
    result = recovery_decision(saved, observed(saved))
    assert result.held_cents == 0 and result.settled_cents is None
    assert result.dispatch_blocked


def test_partial_report_conflicts_with_committed_complete_result():
    saved = state("completed")
    decision = recovery_decision(saved, observed(saved, evidence_status="partial"))
    assert decision.action == "integrity_stop"
    assert decision.reason == "committed_result_incomplete"


@pytest.mark.parametrize("phase", ["completed", "interrupted"])
def test_active_worker_conflicts_with_terminal_state(phase):
    saved = state(phase, runner_request_id="request")
    decision = recovery_decision(saved, observed(saved, runner_status="active", worker_id="worker"))
    assert decision.reason == "terminal_worker_active"
    assert decision.held_cents == 300


@pytest.mark.parametrize(
    "changes",
    [
        {"generation": True},
        {"generation": 0},
        {"revision": 1.0},
        {"revision": -1},
        {"max_cost_cents": True},
        {"max_cost_cents": -1},
        {"actual_cost_cents": 0},
        {"trial_id": "../trial"},
        {"attempt_id": None},
        {"attempt_id": "a" * 129},
        {"integrity_ok": 1},
        {"phase": "unknown"},
        {"artifact_stage": "accepted"},
        {"previous_phase": "running"},
        {"phase": "reconciling"},
        {"phase": "reconciling", "previous_phase": "completed"},
        {"phase": "running"},
        {"worker_id": "worker"},
        {"runner_request_id": "request"},
        {"verification_request_id": "verify"},
    ],
)
def test_invalid_state_is_rejected(changes):
    with pytest.raises(RecoveryError):
        replace(state(), **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"attempt_id": "attempt"},
        {"max_cost_cents": 1},
        {"revision": 1},
        {"actual_cost_cents": 0},
        {"artifact_stage": "linked"},
    ],
)
def test_uncommitted_attempt_cannot_be_inferred_from_planned_state(changes):
    with pytest.raises(RecoveryError):
        replace(state("planned"), **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"runner_status": "active"},
        {"runner_status": "stopped"},
        {"runner_status": "not_found"},
        {"workspace_verified": True},
        {"workspace_verified": 1},
        {"deadline_expired": 1},
        {"generation": False},
        {"revision": -1},
        {"worker_id": "worker"},
        {"artifact_status": "trusted"},
        {"evidence_status": "complete"},
        {"evidence_status": "pass"},
    ],
)
def test_invalid_observation_is_rejected(changes):
    with pytest.raises(RecoveryError):
        observed(state(), **changes)


def test_records_are_immutable_and_untyped_inputs_rejected():
    saved = state()
    with pytest.raises(FrozenInstanceError):
        saved.phase = "completed"
    with pytest.raises(RecoveryError):
        recovery_decision(asdict(saved), observed(saved))
    with pytest.raises(RecoveryError):
        recovery_decision(saved, {})
