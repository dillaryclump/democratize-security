"""Pure offline recovery advice. Inputs are synthetic, not authenticated receipts.

No decision is an executable command or permission to dispatch. A future controller
must load validated state under durable ownership, authenticate observations, and
commit any resulting transitions separately. This module does none of those things.
"""

import re
from dataclasses import dataclass


class RecoveryError(ValueError):
    """Malformed state or an observation that does not match the current inspection."""


_PHASES = frozenset(
    {
        "planned",
        "preparing",
        "dispatch_pending",
        "running",
        "sealed",
        "verifying",
        "completed",
        "interrupted",
        "reconciling",
    }
)
_ACTIVE = _PHASES - {"planned", "completed", "interrupted", "reconciling"}


def _choice(value, choices, name):
    if not isinstance(value, str) or value not in choices:
        raise RecoveryError(f"invalid {name}")


def _number(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise RecoveryError(f"invalid {name}")


def _identifier(value, name, optional=False):
    if value is None and optional:
        return
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is None
    ):
        raise RecoveryError(f"invalid {name}")


@dataclass(frozen=True)
class RecoveryState:
    """Validated synthetic projection, not a PlanStore snapshot or persisted schema.

    generation is the *current inspecting controller*, not the original attempt's
    generation. A restarted controller must obtain fresh observations under its own
    generation. Actual cost means an already committed settlement, never an estimate.
    """

    trial_id: str
    attempt_id: str | None
    generation: int
    revision: int
    phase: str
    max_cost_cents: int = 0
    actual_cost_cents: int | None = None
    runner_request_id: str | None = None
    worker_id: str | None = None
    verification_request_id: str | None = None
    artifact_stage: str = "none"
    previous_phase: str | None = None
    integrity_ok: bool = True

    def __post_init__(self):
        _identifier(self.trial_id, "trial_id")
        for name in ("attempt_id", "runner_request_id", "worker_id", "verification_request_id"):
            _identifier(getattr(self, name), name, optional=True)
        _number(self.generation, "generation", 1)
        _number(self.revision, "revision")
        _number(self.max_cost_cents, "max_cost_cents")
        if self.actual_cost_cents is not None:
            _number(self.actual_cost_cents, "actual_cost_cents")
        if type(self.integrity_ok) is not bool:
            raise RecoveryError("invalid integrity_ok")
        _choice(self.phase, _PHASES, "phase")
        _choice(self.artifact_stage, {"none", "linked", "durable", "referenced"}, "artifact_stage")
        if self.phase == "reconciling":
            _choice(self.previous_phase, _ACTIVE, "previous_phase")
        elif self.previous_phase is not None:
            raise RecoveryError("previous_phase requires reconciling")
        phase = self.previous_phase if self.phase == "reconciling" else self.phase
        if phase == "planned":
            if (
                self.attempt_id is not None
                or self.revision != 0
                or self.max_cost_cents != 0
                or self.actual_cost_cents is not None
                or self.runner_request_id is not None
                or self.worker_id is not None
                or self.verification_request_id is not None
                or self.artifact_stage != "none"
            ):
                raise RecoveryError("planned state cannot contain attempt records")
        elif self.attempt_id is None or self.revision < 1:
            raise RecoveryError("attempt state requires identity and positive revision")
        if phase == "preparing" and self.runner_request_id is not None:
            raise RecoveryError("dispatch intent requires dispatch_pending or later phase")
        if phase in {"dispatch_pending", "running", "sealed", "verifying", "completed"}:
            if self.runner_request_id is None:
                raise RecoveryError("phase requires runner request identity")
        # A trusted acknowledgement binds the worker before running; without it,
        # any worker reported for the request would be accepted as this one.
        if phase in {"running", "sealed", "verifying", "completed"} and self.worker_id is None:
            raise RecoveryError("acknowledged phase requires worker identity")
        if self.worker_id is not None and self.runner_request_id is None:
            raise RecoveryError("worker requires runner request identity")
        if phase in {"sealed", "verifying", "completed"} and self.artifact_stage != "referenced":
            raise RecoveryError("phase requires referenced artifact")
        # The reference commits with running -> sealed and intent with
        # sealed -> verifying; earlier runtime phases cannot hold them.
        if phase in {"dispatch_pending", "running"} and self.artifact_stage == "referenced":
            raise RecoveryError("artifact reference requires sealed or later phase")
        if phase == "sealed" and self.verification_request_id is not None:
            raise RecoveryError("verification intent requires verifying or later phase")
        if phase in {"verifying", "completed"} and self.verification_request_id is None:
            raise RecoveryError("phase requires verification intent")
        if self.verification_request_id is not None and self.artifact_stage != "referenced":
            raise RecoveryError("verification intent requires referenced artifact")
        if self.actual_cost_cents is not None and self.phase not in {"completed", "interrupted"}:
            raise RecoveryError("settlement requires terminal attempt")


@dataclass(frozen=True)
class RecoveryObservation:
    """Inspection context supplied independently of the reports being inspected.

    'complete' describes coverage only, not authentication or result acceptance.
    'valid' describes byte validation only, not provenance or durable publication.
    """

    trial_id: str
    attempt_id: str | None
    generation: int
    revision: int
    runner_request_id: str | None = None
    verification_request_id: str | None = None
    worker_id: str | None = None
    runner_status: str = "unknown"
    workspace_verified: bool = False
    deadline_expired: bool = False
    artifact_status: str = "unknown"
    evidence_status: str = "unknown"

    def __post_init__(self):
        _identifier(self.trial_id, "trial_id")
        for name in ("attempt_id", "runner_request_id", "verification_request_id", "worker_id"):
            _identifier(getattr(self, name), name, optional=True)
        _number(self.generation, "generation", 1)
        _number(self.revision, "revision")
        for name in ("workspace_verified", "deadline_expired"):
            if type(getattr(self, name)) is not bool:
                raise RecoveryError(f"invalid {name}")
        _choice(self.runner_status, {"unknown", "not_found", "active", "stopped"}, "runner_status")
        _choice(self.artifact_status, {"unknown", "missing", "invalid", "valid"}, "artifact_status")
        _choice(
            self.evidence_status,
            {"unknown", "missing", "invalid", "partial", "complete"},
            "evidence_status",
        )
        if self.runner_status in {"active", "stopped"} and self.worker_id is None:
            raise RecoveryError("worker observation requires worker identity")
        if (
            self.worker_id is not None or self.runner_status != "unknown"
        ) and self.runner_request_id is None:
            raise RecoveryError("runner observation requires request identity")
        if self.workspace_verified and self.runner_status != "stopped":
            raise RecoveryError("workspace inspection requires stopped worker")
        if self.evidence_status != "unknown" and self.verification_request_id is None:
            raise RecoveryError("evidence observation requires verification request identity")


@dataclass(frozen=True)
class RecoveryDecision:
    """Inspection advice only; amounts reproduce the committed accounting state."""

    action: str
    reason: str
    held_cents: int
    settled_cents: int | None
    execution_enabled: bool = False
    dispatch_blocked: bool = True


def recovery_decision(state: RecoveryState, observation: RecoveryObservation) -> RecoveryDecision:
    """Deterministic advice with no I/O, mutation, settlement or state transition.

    Identity mismatch raises before using any observation. Callers must keep
    dispatch blocked on errors. This check alone is not durable controller fencing.
    """
    if type(state) is not RecoveryState or type(observation) is not RecoveryObservation:
        raise RecoveryError("expected recovery records")
    for name in (
        "trial_id",
        "attempt_id",
        "generation",
        "revision",
        "runner_request_id",
        "verification_request_id",
    ):
        if getattr(state, name) != getattr(observation, name):
            raise RecoveryError(f"observation does not match {name}")
    if state.worker_id is not None and observation.worker_id not in {None, state.worker_id}:
        raise RecoveryError("observation does not match worker_id")

    def advise(action, reason):
        return RecoveryDecision(
            action,
            reason,
            state.max_cost_cents if state.actual_cost_cents is None else 0,
            state.actual_cost_cents,
        )

    if (
        not state.integrity_ok
        or observation.artifact_status == "invalid"
        or observation.evidence_status == "invalid"
    ):
        return advise("integrity_stop", "integrity_failure")
    if state.artifact_stage == "referenced" and observation.artifact_status == "missing":
        return advise("integrity_stop", "referenced_artifact_missing")
    if state.phase == "completed" and observation.evidence_status == "missing":
        return advise("integrity_stop", "committed_evidence_missing")
    if state.phase == "completed" and observation.evidence_status == "partial":
        return advise("integrity_stop", "committed_result_incomplete")
    phase = state.previous_phase if state.phase == "reconciling" else state.phase
    if phase in {"completed", "interrupted"} and observation.runner_status == "active":
        return advise("integrity_stop", "terminal_worker_active")
    # Sealing required an observed stop of this worker, so activity now
    # contradicts the committed record rather than being a routine observation.
    if phase in {"sealed", "verifying"} and observation.runner_status == "active":
        return advise("integrity_stop", "sealed_worker_active")
    if state.actual_cost_cents is not None and state.actual_cost_cents > state.max_cost_cents:
        return advise("integrity_stop", "cost_overrun")

    if phase == "planned":
        return advise("inspect_plan", "no_committed_attempt")
    if phase in {"completed", "interrupted"}:
        if state.artifact_stage == "referenced" and observation.artifact_status != "valid":
            return advise("revalidate_artifact", "terminal_artifact_unchecked")
        if phase == "completed":
            # Even a complete report must be checked against an authenticated
            # committed result by the future acceptance layer. Never infer pass.
            return advise("review_committed_result", "terminal_result_requires_provenance")
        if state.actual_cost_cents is None:
            return advise("reconcile_billing", "terminal_cost_unknown")
        return advise("inspect_terminal", "settlement_already_committed")

    if state.runner_request_id is not None:
        if observation.runner_status in {"unknown", "not_found"}:
            return advise("reconcile_runner", "request_outcome_unknown")
        if observation.runner_status == "active":
            return advise(
                "inspect_stop" if observation.deadline_expired else "observe_worker",
                "deadline_expired" if observation.deadline_expired else "same_worker_active",
            )

    if state.artifact_stage == "linked":
        return advise("reconcile_publication", "link_is_not_durability")
    if state.artifact_stage == "durable":
        return advise("review_orphan", "object_is_not_committed_reference")
    if state.artifact_stage == "referenced":
        if observation.artifact_status != "valid":
            return advise("revalidate_artifact", "referenced_bytes_unchecked")
        if state.verification_request_id is not None:
            return advise("reconcile_verifier", "verification_requires_authenticated_result")
        return advise("review_verification_intent", "artifact_does_not_authorize_verifier_launch")
    if phase == "preparing":
        return advise("review_preparation", "no_dispatch_intent")
    if observation.workspace_verified:
        return advise("review_collection", "stopped_worker_and_original_workspace")
    return advise("review_interruption", "stopped_worker_without_verified_workspace")
