"""Bounded offline report envelopes. Hashes are not verifier authentication.

Supply an independently selected, revalidated PlanStore artifact binding and a
trusted expected verification request ID. No I/O, execution or result acceptance.
"""

import json
import re

from democratize_security.artifacts import MAX_BUNDLE_BYTES
from democratize_security.contracts import _unique_pairs, digest
from democratize_security.verification.report import PROTOCOL, validate_report

MAX_EVIDENCE_BYTES = 64 * 1024


class EvidenceError(ValueError):
    """Evidence cannot be bound to the expected offline context."""


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        raise EvidenceError("Invalid evidence identifier")


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise EvidenceError("A concrete SHA-256 is required")


def _context(binding: dict, request_id: str) -> dict:
    _identifier(request_id)
    if not isinstance(binding, dict) or set(binding) != {
        "schema_version",
        "event_id",
        "request",
        "binding_sha256",
    }:
        raise EvidenceError("Invalid expected binding")
    if type(binding["schema_version"]) is not int or binding["schema_version"] != 1:
        raise EvidenceError("Unsupported binding schema")
    _identifier(binding["event_id"])
    request = binding["request"]
    if not isinstance(request, dict) or set(request) != {
        "attempt_id",
        "expected_revision",
        "campaign_id",
        "trial_id",
        "task_revision",
        "verifier_sha256",
        "protocol",
        "artifact_ref",
    }:
        raise EvidenceError("Invalid binding request")
    for key in ("attempt_id", "campaign_id", "trial_id"):
        _identifier(request[key])
    if type(request["expected_revision"]) is not int or request["expected_revision"] < 1:
        raise EvidenceError("Invalid bound revision")
    for key in ("task_revision", "verifier_sha256"):
        _hash(request[key])
    if request["protocol"] != PROTOCOL:
        raise EvidenceError("Binding protocol does not match supported report")
    ref = request["artifact_ref"]
    if not isinstance(ref, dict) or set(ref) != {
        "reference_version",
        "kind",
        "schema_version",
        "object_sha256",
        "byte_length",
        "artifact_sha256",
    }:
        raise EvidenceError("Invalid bound artifact reference")
    for key in ("reference_version", "schema_version"):
        if type(ref[key]) is not int or ref[key] != 1:
            raise EvidenceError("Unsupported artifact reference")
    if (
        ref["kind"] != "sealed_artifact"
        or type(ref["byte_length"]) is not int
        or not 0 < ref["byte_length"] <= MAX_BUNDLE_BYTES
    ):
        raise EvidenceError("Invalid artifact kind or length")
    for key in ("object_sha256", "artifact_sha256"):
        _hash(ref[key])
    expected_hash = digest({k: binding[k] for k in ("schema_version", "event_id", "request")})
    if binding["binding_sha256"] != expected_hash:
        raise EvidenceError("Binding digest mismatch")
    return {
        "binding_sha256": expected_hash,
        "verification_request_id": request_id,
        "attempt_id": request["attempt_id"],
        "campaign_id": request["campaign_id"],
        "trial_id": request["trial_id"],
        "task_revision": request["task_revision"],
        "verifier_sha256": request["verifier_sha256"],
        "artifact_sha256": ref["artifact_sha256"],
        "object_sha256": ref["object_sha256"],
        "protocol": request["protocol"],
    }


def _encode(value: dict) -> bytes:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(data) > MAX_EVIDENCE_BYTES:
        raise EvidenceError("Evidence exceeds byte limit")
    return data


def bind_report(binding: dict, verification_request_id: str, report: dict) -> dict:
    """Bind a trusted synthetic observation; incomplete/failed outcomes stay so."""
    context = _context(binding, verification_request_id)
    validate_report(report)
    record = {"schema_version": 1, "kind": "offline_verifier_evidence", **context, "report": report}
    record["evidence_sha256"] = digest(record)
    return json.loads(_encode(record))


def validate_evidence(record: dict, binding: dict, verification_request_id: str) -> None:
    """Compare against trusted expected identities, never identities from the report."""
    if not isinstance(record, dict) or "report" not in record:
        raise EvidenceError("Invalid evidence envelope")
    expected = bind_report(binding, verification_request_id, record["report"])
    # Canonical bytes also distinguish booleans from integer schema versions.
    if _encode(record) != _encode(expected):
        raise EvidenceError("Evidence does not match expected binding, request or report")


def encode_evidence(record: dict, binding: dict, verification_request_id: str) -> bytes:
    validate_evidence(record, binding, verification_request_id)
    return _encode(record)


def decode_evidence(data: bytes, binding: dict, verification_request_id: str) -> dict:
    """Decode bounded canonical JSON; no caller-selected file or network access."""
    if not isinstance(data, bytes) or len(data) > MAX_EVIDENCE_BYTES:
        raise EvidenceError("Invalid evidence bytes or byte limit")

    def reject_constant(value):
        raise EvidenceError(f"Nonfinite JSON constant: {value}")

    try:
        record = json.loads(data, object_pairs_hook=_unique_pairs, parse_constant=reject_constant)
    except (ValueError, RecursionError) as error:
        raise EvidenceError(f"Invalid evidence JSON: {error}") from error
    if encode_evidence(record, binding, verification_request_id) != data:
        raise EvidenceError("Noncanonical evidence JSON")
    return record
