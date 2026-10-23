"""Protocol v4 alongside v3 in the report contract and runtime path (pilot, #57)."""

import pytest
from test_runtime_events import PREPARE

from democratize_security.runtime_auth import AuthenticationError, VerificationContext
from democratize_security.runtime_events import reduce_runtime
from democratize_security.verification.report import (
    PROTOCOL,
    PROTOCOL_V4,
    PROTOCOLS,
    REQUIRED,
    REQUIRED_V4,
    Check,
    ReportError,
    summarize,
    validate_report,
)

V4_ORDER = (
    "fixture_configuration",
    "authorized_reads",
    "foreign_reads",
    "list_search",
    "exports",
    "identity",
    "spoofing",
    "tenant_switching",
    "aggregates",
    "writes",
)


def test_protocol_table():
    assert PROTOCOL == "synthetic-reference-v3"
    assert PROTOCOL_V4 == "synthetic-reference-v4"
    assert REQUIRED_V4 == frozenset(V4_ORDER)
    assert PROTOCOLS == {PROTOCOL: REQUIRED, PROTOCOL_V4: REQUIRED_V4}


def test_v4_complete_report_round_trips():
    report = summarize([Check(name, "pass") for name in V4_ORDER], PROTOCOL_V4)
    assert (report["protocol"], report["coverage"], report["outcome"]) == (
        PROTOCOL_V4,
        "complete",
        "pass",
    )
    validate_report(report)


def test_v4_missing_writes_is_incomplete():
    report = summarize([Check(name, "pass") for name in V4_ORDER[:-1]], PROTOCOL_V4)
    assert (report["coverage"], report["outcome"]) == ("incomplete", "incomplete")
    validate_report(report)


def test_v3_and_v4_ids_cannot_mix():
    v4 = summarize([Check(name, "pass") for name in V4_ORDER], PROTOCOL_V4)
    v4["checks"][0] = {"id": "database_configuration", "outcome": "pass", "detail": ""}
    with pytest.raises(ReportError):
        validate_report(v4)
    v3 = summarize([Check(name, "pass") for name in sorted(REQUIRED)])
    v3["checks"].append({"id": "writes", "outcome": "pass", "detail": ""})
    with pytest.raises(ReportError):
        validate_report(v3)


def test_v3_summaries_unchanged():
    report = summarize([Check(name, "pass") for name in sorted(REQUIRED)])
    assert report["protocol"] == PROTOCOL and report["coverage"] == "complete"


def test_unknown_protocol_rejected():
    report = summarize([Check(name, "pass") for name in V4_ORDER], PROTOCOL_V4)
    report["protocol"] = "synthetic-reference-v5"
    with pytest.raises(ReportError):
        validate_report(report)
    with pytest.raises(ReportError):
        summarize([], "synthetic-reference-v5")


def test_runtime_prepare_accepts_v4():
    state = reduce_runtime(None, dict(PREPARE, protocol=PROTOCOL_V4))
    assert state["protocol"] == PROTOCOL_V4


def test_verification_context_accepts_v4():
    fields = dict(
        campaign_id="c",
        trial_id="t",
        attempt_id="a",
        runner_request_id="r",
        worker_id="w",
        verification_request_id="v",
        controller_generation=1,
        expected_revision=5,
        task_revision="e" * 64,
        artifact_binding_sha256="2" * 64,
        artifact_sha256="c" * 64,
        object_sha256="b" * 64,
        verifier_sha256="f" * 64,
    )
    assert VerificationContext(**fields, protocol=PROTOCOL_V4).protocol == PROTOCOL_V4
    with pytest.raises(AuthenticationError):
        VerificationContext(**fields, protocol="synthetic-reference-v5")


def test_report_protocol_must_match_challenge_context():
    from democratize_security.runtime_auth import VerifierSession, sign_report

    fields = dict(
        campaign_id="c",
        trial_id="t",
        attempt_id="a",
        runner_request_id="r",
        worker_id="w",
        verification_request_id="v",
        controller_generation=1,
        expected_revision=5,
        task_revision="e" * 64,
        artifact_binding_sha256="2" * 64,
        artifact_sha256="c" * 64,
        object_sha256="b" * 64,
        verifier_sha256="f" * 64,
    )
    session = VerifierSession(VerificationContext(**fields, protocol=PROTOCOL_V4))
    v3 = summarize([Check(name, "pass") for name in sorted(REQUIRED)])
    with pytest.raises(AuthenticationError, match="protocol"):
        sign_report(session.public_challenge(), session.verifier_nonce(), v3)
    v4 = summarize([Check(name, "pass") for name in V4_ORDER], PROTOCOL_V4)
    raw = sign_report(session.public_challenge(), session.verifier_nonce(), v4)
    assert session.authenticate(raw).complete
