"""Pure runtime attempt transitions for store v8 (issues #62, #69).

`reduce_runtime(previous, request)` validates one runtime request and returns
the next attempt state, or raises. It performs no I/O and grants no authority:
the store applies it inside a fenced transaction, checks objects, budgets,
restore fences and the controller generation, and alone may pass
`admission=True` after authenticating a verifier report. Phases follow the
transition table in docs/PERSISTENCE.md. No action can issue a second dispatch,
change an acknowledged request or worker, or complete an attempt without an
admitted result. While running, each model request is reserved before it is
sent and then settled or recorded unknown; an unknown request keeps its
reserved maxima and blocks further requests and settlement.
"""

import re
from datetime import UTC, datetime

from democratize_security import objects as artifact_objects
from democratize_security.artifacts import ArtifactError
from democratize_security.runtime_auth import AuthenticationError, _challenge
from democratize_security.verification.report import PROTOCOLS

MODE = "runtime"
TERMINAL = frozenset({"completed", "interrupted"})
ACTIVE = frozenset({"preparing", "dispatch_pending", "running", "sealed", "verifying"})
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_HASH = re.compile(r"[0-9a-f]{64}")
_SOURCE = re.compile(r"[0-9a-f]{40}")

_FIELDS = {
    "prepare": {
        "campaign_id",
        "trial_id",
        "max_cost_cents",
        "basis_sha256",
        "source_revision",
        "task_revision",
        "verifier_sha256",
        "protocol",
        "config_sha256",
    },
    "dispatch_intent": {"runner_request_id", "dispatch_deadline"},
    "acknowledge": {"runner_request_id", "worker_id"},
    "seal": {"runner_request_id", "worker_id", "stop_observation_sha256", "artifact_ref"},
    "verify_intent": {"verification_request_id", "challenge"},
    "reconcile": {"reason"},
    "resolve": {"observation_sha256"},
    "interrupt": {"reason"},
    "settle": {"actual_cost_cents", "receipt_id"},
    "admit": {"result_sha256", "coverage"},
    "request_intent": {
        "request_id",
        "preflight_input_tokens",
        "max_output_tokens",
        "reserve_cents",
        "payload_sha256",
    },
    "request_settle": {
        "request_id",
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "cost_cents",
        "response_sha256",
    },
    "request_unknown": {"request_id", "reason"},
}
# Allowed source phase for each forward action; reconcile/interrupt/settle are general.
_FROM = {
    "dispatch_intent": "preparing",
    "acknowledge": "dispatch_pending",
    "seal": "running",
    "verify_intent": "sealed",
    "admit": "verifying",
    "request_intent": "running",
    "request_settle": "running",
    "request_unknown": "running",
}
_TO = {
    "dispatch_intent": "dispatch_pending",
    "acknowledge": "running",
    "seal": "sealed",
    "verify_intent": "verifying",
}
_STATE_KEYS = (
    "mode",
    "attempt_id",
    "campaign_id",
    "trial_id",
    "revision",
    "phase",
    "previous_phase",
    "max_cost_cents",
    "actual_cost_cents",
    "receipt_id",
    "reason",
    "basis_sha256",
    "source_revision",
    "task_revision",
    "verifier_sha256",
    "protocol",
    "config_sha256",
    "runner_request_id",
    "dispatch_deadline",
    "worker_id",
    "stop_observation_sha256",
    "artifact_ref",
    "verification_request_id",
    "challenge_sha256",
    "result_sha256",
    "request_count",
    "input_tokens",
    "output_tokens",
    "committed_cents",
    "open_request",
    "unknown_requests",
)


class RuntimeLedgerError(ValueError):
    """A runtime request is malformed, stale or not permitted from this state."""


def _identifier(value, name):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise RuntimeLedgerError(f"Invalid {name}")


def _hash(value, name, pattern=_HASH):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise RuntimeLedgerError(f"Invalid {name}")


def _amount(value, name):
    if type(value) is not int or not 0 <= value <= 10**12:
        raise RuntimeLedgerError(f"{name} must be a bounded nonnegative integer of cents")


def _tokens(value, name, minimum=0):
    if type(value) is not int or not minimum <= value <= 10**9:
        raise RuntimeLedgerError(f"{name} must be a bounded integer token count")


def _open(previous, request):
    """The single reserved request this settle/unknown must name."""
    current = previous["open_request"]
    if current is None or current["request_id"] != request["request_id"]:
        raise RuntimeLedgerError("Request does not name the open request")
    return current


def _reason(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise RuntimeLedgerError("A bounded reason is required")


def _deadline(value):
    try:
        parsed = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        parsed = None
    if parsed is None or parsed.utcoffset() != UTC.utcoffset(None):
        raise RuntimeLedgerError("dispatch_deadline must be an explicit UTC timestamp")


def _artifact(reference):
    try:
        artifact_objects._filename(reference)
    except ArtifactError as error:
        raise RuntimeLedgerError("Invalid artifact reference") from error


def _check_challenge(state, request):
    try:
        public = _challenge(request["challenge"])
    except AuthenticationError as error:
        raise RuntimeLedgerError("Invalid verification challenge") from error
    context = public["context"]
    expected = {
        "campaign_id": state["campaign_id"],
        "trial_id": state["trial_id"],
        "attempt_id": state["attempt_id"],
        "runner_request_id": state["runner_request_id"],
        "worker_id": state["worker_id"],
        "verification_request_id": request["verification_request_id"],
        "expected_revision": state["revision"] + 1,
        "task_revision": state["task_revision"],
        "artifact_sha256": state["artifact_ref"]["artifact_sha256"],
        "object_sha256": state["artifact_ref"]["object_sha256"],
        "verifier_sha256": state["verifier_sha256"],
        "protocol": state["protocol"],
    }
    if any(context[key] != value for key, value in expected.items()):
        raise RuntimeLedgerError("Verification challenge does not match the sealed attempt")
    return public["challenge_sha256"]


def reduce_runtime(previous: dict | None, request: dict, *, admission: bool = False) -> dict:
    """Validate one runtime request against `previous` and return the next state."""
    if not isinstance(request, dict) or request.get("mode") != MODE:
        raise RuntimeLedgerError("Expected a runtime request object")
    action = request.get("action")
    if not isinstance(action, str) or action not in _FIELDS:
        raise RuntimeLedgerError("Unsupported runtime action")
    if action == "admit" and not admission:
        raise RuntimeLedgerError("Results enter only through authenticated admission")
    if set(request) != _FIELDS[action] | {"mode", "action", "attempt_id", "expected_revision"}:
        raise RuntimeLedgerError("Unexpected or missing runtime request fields")
    _identifier(request["attempt_id"], "attempt_id")
    revision = request["expected_revision"]
    if type(revision) is not int or revision < 0:
        raise RuntimeLedgerError("Invalid expected revision")
    if revision != (previous["revision"] if previous else 0):
        raise RuntimeLedgerError("Stale expected revision")
    if action == "prepare":
        if previous is not None:
            raise RuntimeLedgerError("Attempt already exists")
        return _prepare(request)
    if previous is None:
        raise RuntimeLedgerError("Unknown attempt")
    if previous.get("mode") != MODE or request["attempt_id"] != previous["attempt_id"]:
        raise RuntimeLedgerError("Attempt identity or mode mismatch")
    phase = previous["phase"]
    state = {**previous, "revision": revision + 1}
    if action in _FROM:
        if phase != _FROM[action]:
            raise RuntimeLedgerError(f"{action} is not permitted from {phase}")
        if action in _TO:
            state["phase"] = _TO[action]
    if action == "dispatch_intent":
        _identifier(request["runner_request_id"], "runner_request_id")
        _deadline(request["dispatch_deadline"])
        state.update(
            runner_request_id=request["runner_request_id"],
            dispatch_deadline=request["dispatch_deadline"],
        )
    elif action == "acknowledge":
        if request["runner_request_id"] != previous["runner_request_id"]:
            raise RuntimeLedgerError("Acknowledgement names a different runner request")
        _identifier(request["worker_id"], "worker_id")
        state["worker_id"] = request["worker_id"]
    elif action == "request_intent":
        _identifier(request["request_id"], "request_id")
        _tokens(request["preflight_input_tokens"], "preflight_input_tokens", 1)
        _tokens(request["max_output_tokens"], "max_output_tokens", 1)
        _amount(request["reserve_cents"], "reserve_cents")
        _hash(request["payload_sha256"], "payload_sha256")
        if previous["unknown_requests"]:
            raise RuntimeLedgerError("An unknown request outcome blocks further requests")
        if previous["open_request"] is not None:
            raise RuntimeLedgerError("Another open request must settle first")
        committed = previous["committed_cents"] + request["reserve_cents"]
        if committed > previous["max_cost_cents"]:
            raise RuntimeLedgerError("Request reservation exceeds the attempt hold")
        state.update(
            request_count=previous["request_count"] + 1,
            input_tokens=previous["input_tokens"] + request["preflight_input_tokens"],
            output_tokens=previous["output_tokens"] + request["max_output_tokens"],
            committed_cents=committed,
            open_request={
                key: request[key]
                for key in (
                    "request_id",
                    "preflight_input_tokens",
                    "max_output_tokens",
                    "reserve_cents",
                )
            },
        )
    elif action == "request_settle":
        current = _open(previous, request)
        for key in ("input_tokens", "cached_input_tokens", "output_tokens"):
            _tokens(request[key], key)
        _amount(request["cost_cents"], "cost_cents")
        _hash(request["response_sha256"], "response_sha256")
        if request["cached_input_tokens"] > request["input_tokens"]:
            raise RuntimeLedgerError("cached input exceeds total input")
        if (
            request["cost_cents"] > current["reserve_cents"]
            or request["input_tokens"] > current["preflight_input_tokens"]
            or request["output_tokens"] > current["max_output_tokens"]
        ):
            raise RuntimeLedgerError("Settlement exceeds the request reservation")
        # Replace the reserved maxima with the settled amounts.
        state.update(
            input_tokens=previous["input_tokens"]
            - current["preflight_input_tokens"]
            + request["input_tokens"],
            output_tokens=previous["output_tokens"]
            - current["max_output_tokens"]
            + request["output_tokens"],
            committed_cents=previous["committed_cents"]
            - current["reserve_cents"]
            + request["cost_cents"],
            open_request=None,
        )
    elif action == "request_unknown":
        _open(previous, request)
        _reason(request["reason"])
        state.update(open_request=None, unknown_requests=previous["unknown_requests"] + 1)
    elif action == "seal":
        if previous["open_request"] is not None:
            raise RuntimeLedgerError("An open request must settle before sealing")
        if (request["runner_request_id"], request["worker_id"]) != (
            previous["runner_request_id"],
            previous["worker_id"],
        ):
            raise RuntimeLedgerError("Seal names a different runner request or worker")
        _hash(request["stop_observation_sha256"], "stop_observation_sha256")
        _artifact(request["artifact_ref"])
        state.update(
            stop_observation_sha256=request["stop_observation_sha256"],
            artifact_ref=request["artifact_ref"],
        )
    elif action == "verify_intent":
        _identifier(request["verification_request_id"], "verification_request_id")
        state.update(
            verification_request_id=request["verification_request_id"],
            challenge_sha256=_check_challenge(previous, request),
        )
    elif action == "admit":
        _hash(request["result_sha256"], "result_sha256")
        if request["coverage"] == "complete":
            state["phase"] = "completed"
        elif request["coverage"] == "incomplete":
            state.update(phase="interrupted", reason="incomplete_verification")
        else:
            raise RuntimeLedgerError("Invalid admitted coverage")
        state["result_sha256"] = request["result_sha256"]
    elif action == "reconcile":
        if phase not in ACTIVE:
            raise RuntimeLedgerError(f"reconcile is not permitted from {phase}")
        _reason(request["reason"])
        state.update(phase="reconciling", previous_phase=phase, reason=request["reason"])
    elif action == "resolve":
        if phase != "reconciling":
            raise RuntimeLedgerError("resolve requires a reconciling attempt")
        _hash(request["observation_sha256"], "observation_sha256")
        state.update(phase=previous["previous_phase"], previous_phase=None)
    elif action == "interrupt":
        if phase in TERMINAL:
            raise RuntimeLedgerError("Cannot transition a terminal attempt")
        _reason(request["reason"])
        state.update(phase="interrupted", previous_phase=None, reason=request["reason"])
    elif action == "settle":
        if phase not in TERMINAL or previous["actual_cost_cents"] is not None:
            raise RuntimeLedgerError("Settlement requires a terminal, unsettled attempt")
        _amount(request["actual_cost_cents"], "actual_cost_cents")
        _identifier(request["receipt_id"], "receipt_id")
        if previous["open_request"] is not None:
            raise RuntimeLedgerError("An open request outcome blocks settlement")
        if previous["unknown_requests"]:
            raise RuntimeLedgerError("An unknown request outcome blocks settlement")
        if request["actual_cost_cents"] != previous["committed_cents"]:
            raise RuntimeLedgerError("Settlement must equal the committed request costs")
        state.update(
            actual_cost_cents=request["actual_cost_cents"], receipt_id=request["receipt_id"]
        )
    return state


def _prepare(request):
    for key in ("campaign_id", "trial_id"):
        _identifier(request[key], key)
    _amount(request["max_cost_cents"], "max_cost_cents")
    for key in ("basis_sha256", "task_revision", "verifier_sha256", "config_sha256"):
        _hash(request[key], key)
    _hash(request["source_revision"], "source_revision", _SOURCE)
    if request["protocol"] not in PROTOCOLS:
        raise RuntimeLedgerError("Unsupported verifier protocol")
    state = dict.fromkeys(_STATE_KEYS)
    state.update({key: request[key] for key in _FIELDS["prepare"]})
    state.update(mode=MODE, attempt_id=request["attempt_id"], revision=1, phase="preparing")
    state.update(
        request_count=0,
        input_tokens=0,
        output_tokens=0,
        committed_cents=0,
        unknown_requests=0,
    )
    return state
