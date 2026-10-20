"""Pure runtime attempt transitions (issue #62); no store, I/O or execution."""

import copy
import hashlib

import pytest

from democratize_security.runtime_auth import VerificationContext, VerifierSession
from democratize_security.runtime_events import (
    RuntimeLedgerError,
    reduce_runtime,
)

H = "a" * 64
ARTIFACT_REF = {
    "reference_version": 1,
    "kind": "sealed_artifact",
    "schema_version": 1,
    "object_sha256": "b" * 64,
    "byte_length": 128,
    "artifact_sha256": "c" * 64,
}


def request(action, revision, **fields):
    return {
        "mode": "runtime",
        "action": action,
        "attempt_id": "attempt-1",
        "expected_revision": revision,
        **fields,
    }


PREPARE = request(
    "prepare",
    0,
    campaign_id="campaign-1",
    trial_id="trial-1",
    max_cost_cents=125,
    basis_sha256=H,
    source_revision="d" * 40,
    task_revision="e" * 64,
    verifier_sha256="f" * 64,
    protocol="synthetic-reference-v3",
    config_sha256="1" * 64,
)


def context(state, generation=1, **changes):
    fields = {
        "campaign_id": state["campaign_id"],
        "trial_id": state["trial_id"],
        "attempt_id": state["attempt_id"],
        "runner_request_id": state["runner_request_id"],
        "worker_id": state["worker_id"],
        "verification_request_id": "verify-1",
        "controller_generation": generation,
        "expected_revision": state["revision"] + 1,
        "task_revision": state["task_revision"],
        "artifact_binding_sha256": "2" * 64,
        "artifact_sha256": ARTIFACT_REF["artifact_sha256"],
        "object_sha256": ARTIFACT_REF["object_sha256"],
        "verifier_sha256": state["verifier_sha256"],
    }
    fields.update(changes)
    return VerificationContext(**fields)


def run(*requests, previous=None):
    state = previous
    for item in requests:
        state = reduce_runtime(state, item)
    return state


def sealed():
    return run(
        PREPARE,
        request(
            "dispatch_intent",
            1,
            runner_request_id="run-1",
            dispatch_deadline="2026-10-20T20:00:00+00:00",
        ),
        request("acknowledge", 2, runner_request_id="run-1", worker_id="worker-1"),
        request(
            "seal",
            3,
            runner_request_id="run-1",
            worker_id="worker-1",
            stop_observation_sha256="3" * 64,
            artifact_ref=ARTIFACT_REF,
        ),
    )


def verifying():
    state = sealed()
    challenge = VerifierSession(context(state)).public_challenge()
    return run(
        request("verify_intent", 4, verification_request_id="verify-1", challenge=challenge),
        previous=state,
    ), challenge


def test_happy_path_reaches_verifying_with_pinned_identities():
    state, challenge = verifying()
    assert state["phase"] == "verifying"
    assert state["revision"] == 5
    assert state["mode"] == "runtime"
    assert state["runner_request_id"] == "run-1"
    assert state["worker_id"] == "worker-1"
    assert state["artifact_ref"] == ARTIFACT_REF
    assert state["challenge_sha256"] == challenge["challenge_sha256"]
    assert state["actual_cost_cents"] is None
    assert state["max_cost_cents"] == 125


def test_acknowledge_requires_same_request():
    state = run(
        PREPARE,
        request(
            "dispatch_intent",
            1,
            runner_request_id="run-1",
            dispatch_deadline="2026-10-20T20:00:00+00:00",
        ),
    )
    with pytest.raises(RuntimeLedgerError, match="request"):
        reduce_runtime(
            state, request("acknowledge", 2, runner_request_id="run-2", worker_id="worker-1")
        )


@pytest.mark.parametrize("field,value", [("runner_request_id", "run-2"), ("worker_id", "w-2")])
def test_seal_requires_acknowledged_worker_and_request(field, value):
    state = run(
        PREPARE,
        request(
            "dispatch_intent",
            1,
            runner_request_id="run-1",
            dispatch_deadline="2026-10-20T20:00:00+00:00",
        ),
        request("acknowledge", 2, runner_request_id="run-1", worker_id="worker-1"),
    )
    seal = request(
        "seal",
        3,
        runner_request_id="run-1",
        worker_id="worker-1",
        stop_observation_sha256="3" * 64,
        artifact_ref=ARTIFACT_REF,
    )
    seal[field] = value
    with pytest.raises(RuntimeLedgerError):
        reduce_runtime(state, seal)


def test_reconcile_records_previous_phase_and_resolve_returns_only_there():
    state = sealed()
    reconciling = reduce_runtime(state, request("reconcile", 4, reason="controller restart"))
    assert (reconciling["phase"], reconciling["previous_phase"]) == ("reconciling", "sealed")
    resolved = reduce_runtime(reconciling, request("resolve", 5, observation_sha256="4" * 64))
    assert (resolved["phase"], resolved["previous_phase"]) == ("sealed", None)
    assert resolved["runner_request_id"] == "run-1"
    assert resolved["worker_id"] == "worker-1"


def test_resolve_cannot_change_request_or_worker():
    reconciling = reduce_runtime(sealed(), request("reconcile", 4, reason="lost ack"))
    for extra in ({"runner_request_id": "run-2"}, {"worker_id": "w-2"}):
        with pytest.raises(RuntimeLedgerError, match="fields"):
            reduce_runtime(reconciling, request("resolve", 5, observation_sha256="4" * 64, **extra))


def test_interrupt_from_reconciling_retains_hold_then_settle():
    reconciling = reduce_runtime(sealed(), request("reconcile", 4, reason="lost ack"))
    stopped = reduce_runtime(reconciling, request("interrupt", 5, reason="abandoned"))
    assert stopped["phase"] == "interrupted"
    assert stopped["actual_cost_cents"] is None
    settled = reduce_runtime(
        stopped, request("settle", 6, actual_cost_cents=40, receipt_id="receipt-1")
    )
    assert (settled["phase"], settled["actual_cost_cents"]) == ("interrupted", 40)


def test_settle_only_after_terminal():
    with pytest.raises(RuntimeLedgerError, match="terminal"):
        reduce_runtime(sealed(), request("settle", 4, actual_cost_cents=1, receipt_id="r-1"))


def test_admission_is_unreachable_without_store_flag():
    state, _ = verifying()
    admit = request("admit", 5, result_sha256="5" * 64, coverage="complete")
    with pytest.raises(RuntimeLedgerError, match="admission"):
        reduce_runtime(state, admit)
    assert reduce_runtime(state, admit, admission=True)["phase"] == "completed"


def test_incomplete_admission_interrupts_and_keeps_hold():
    state, _ = verifying()
    admit = request("admit", 5, result_sha256="5" * 64, coverage="incomplete")
    result = reduce_runtime(state, admit, admission=True)
    assert (result["phase"], result["reason"]) == ("interrupted", "incomplete_verification")
    assert result["actual_cost_cents"] is None
    assert result["result_sha256"] == "5" * 64


def test_verify_intent_challenge_must_match_state():
    state = sealed()
    for changes in (
        {"attempt_id": "other"},
        {"worker_id": "w-2"},
        {"runner_request_id": "run-2"},
        {"expected_revision": state["revision"]},
        {"task_revision": "9" * 64},
        {"object_sha256": "9" * 64},
        {"artifact_sha256": "9" * 64},
        {"verification_request_id": "verify-2"},
    ):
        challenge = VerifierSession(context(state, **changes)).public_challenge()
        with pytest.raises(RuntimeLedgerError, match="challenge"):
            reduce_runtime(
                state,
                request(
                    "verify_intent", 4, verification_request_id="verify-1", challenge=challenge
                ),
            )


def test_altered_challenge_digest_rejected():
    state = sealed()
    challenge = VerifierSession(context(state)).public_challenge()
    challenge["nonce_sha256"] = hashlib.sha256(b"other").hexdigest()
    with pytest.raises(RuntimeLedgerError, match="challenge"):
        reduce_runtime(
            state,
            request("verify_intent", 4, verification_request_id="verify-1", challenge=challenge),
        )


def test_stale_revision_rejected():
    state = run(PREPARE)
    with pytest.raises(RuntimeLedgerError, match="revision"):
        reduce_runtime(
            state,
            request(
                "dispatch_intent",
                0,
                runner_request_id="run-1",
                dispatch_deadline="2026-10-20T20:00:00+00:00",
            ),
        )


def test_unknown_or_extra_fields_rejected():
    extra = copy.deepcopy(PREPARE)
    extra["unexpected"] = 1
    missing = copy.deepcopy(PREPARE)
    del missing["config_sha256"]
    for item in (extra, missing):
        with pytest.raises(RuntimeLedgerError, match="fields"):
            reduce_runtime(None, item)


def test_offline_request_rejected():
    offline = {k: v for k, v in PREPARE.items() if k != "mode"}
    with pytest.raises(RuntimeLedgerError, match="runtime"):
        reduce_runtime(None, offline)


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_cost_cents", -1),
        ("max_cost_cents", True),
        ("max_cost_cents", 1.5),
        ("basis_sha256", "A" * 64),
        ("source_revision", "d" * 64),
        ("config_sha256", "short"),
        ("protocol", "unknown-protocol"),
    ],
)
def test_bad_prepare_values_rejected(field, value):
    item = copy.deepcopy(PREPARE)
    item[field] = value
    with pytest.raises(RuntimeLedgerError):
        reduce_runtime(None, item)


@pytest.mark.parametrize(
    "deadline", ["2026-10-20T20:00:00", "2026-10-20T20:00:00+02:00", "tomorrow", 5]
)
def test_dispatch_deadline_must_be_explicit_utc(deadline):
    with pytest.raises(RuntimeLedgerError, match="deadline"):
        reduce_runtime(
            run(PREPARE),
            request("dispatch_intent", 1, runner_request_id="run-1", dispatch_deadline=deadline),
        )


def test_terminal_attempt_rejects_further_transitions():
    state, _ = verifying()
    done = reduce_runtime(
        state,
        request("admit", 5, result_sha256="5" * 64, coverage="complete"),
        admission=True,
    )
    for item in (
        request("reconcile", 6, reason="late"),
        request("interrupt", 6, reason="late"),
    ):
        with pytest.raises(RuntimeLedgerError):
            reduce_runtime(done, item)
