"""Bridge sealed-replay app evidence into authenticated admission (issue #69)."""

import pytest
from test_runtime_admission import verifying
from test_runtime_store import build_case, open_store

from democratize_security.adapters.runners.report_signer import (
    SignerError,
    report_from_app_evidence,
    sign_via_subprocess,
)
from democratize_security.verification.report import REQUIRED


@pytest.fixture
def case(tmp_path):
    return build_case(tmp_path)


def evidence(outcomes=None, *, coverage="complete", details=None):
    checks = outcomes or dict.fromkeys(sorted(REQUIRED), "pass")
    complete = coverage == "complete"
    passed = complete and all(v == "pass" for v in checks.values())
    return {
        "schema_version": 3,
        "protocol": "synthetic-reference-v3",
        "artifact_sha256": "c" * 64,
        "app_started": True,
        "coverage": coverage,
        "outcome": "pass" if passed else ("fail" if complete else "incomplete"),
        "checks": checks,
        "details": details or {},
        "reward": int(passed),
        "mac": "0" * 64,
    }


def test_report_mirrors_checks_and_details():
    first = sorted(REQUIRED)[0]
    outcomes = dict.fromkeys(sorted(REQUIRED), "pass") | {first: "fail"}
    report = report_from_app_evidence(evidence(outcomes, details={first: "foreign row read"}))
    assert (report["coverage"], report["outcome"]) == ("complete", "fail")
    assert {c["id"]: c["outcome"] for c in report["checks"]} == outcomes
    assert next(c for c in report["checks"] if c["id"] == first)["detail"] == "foreign row read"


def test_not_evaluated_checks_give_incomplete_report():
    outcomes = dict.fromkeys(sorted(REQUIRED), "not_evaluated")
    report = report_from_app_evidence(evidence(outcomes, coverage="incomplete"))
    assert (report["coverage"], report["outcome"]) == ("incomplete", "incomplete")


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e["checks"].update(unknown_check="pass"),
        lambda e: e.update(coverage="incomplete"),
        lambda e: e.update(protocol="other"),
        lambda e: e["checks"].update({sorted(REQUIRED)[0]: "maybe"}),
    ],
)
def test_inconsistent_or_unknown_evidence_rejected(change):
    record = evidence()
    change(record)
    with pytest.raises(ValueError):
        report_from_app_evidence(record)


def test_long_details_are_truncated_to_report_limit():
    first = sorted(REQUIRED)[0]
    report = report_from_app_evidence(evidence(details={first: "x" * 5000}))
    assert len(next(c for c in report["checks"] if c["id"] == first)["detail"]) == 2048


@pytest.mark.parametrize("outcome", ["pass", "fail"])
def test_complete_pass_and_fail_reports_round_trip_through_admission(case, outcome):
    outcomes = dict.fromkeys(sorted(REQUIRED), "pass")
    if outcome == "fail":
        outcomes[sorted(REQUIRED)[0]] = "fail"
    with open_store(case) as store:
        session = verifying(case, store)
        raw = sign_via_subprocess(
            session.public_challenge(), session.verifier_nonce(), evidence(outcomes)
        )
        record = store.admit_result("admit", "r1", 5, session, raw)
        assert (record["coverage"], record["outcome"]) == ("complete", outcome)
        (state,) = store.attempts()
        assert state["phase"] == "completed"


def test_partial_evidence_interrupts_as_incomplete(case):
    outcomes = dict.fromkeys(sorted(REQUIRED), "pass") | {sorted(REQUIRED)[0]: "not_evaluated"}
    with open_store(case) as store:
        session = verifying(case, store)
        raw = sign_via_subprocess(
            session.public_challenge(),
            session.verifier_nonce(),
            evidence(outcomes, coverage="incomplete"),
        )
        store.admit_result("admit", "r1", 5, session, raw)
        (state,) = store.attempts()
        assert (state["phase"], state["reason"]) == ("interrupted", "incomplete_verification")


def test_signer_rejects_unknown_check_and_never_echoes_nonce(case):
    record = evidence()
    record["checks"]["unknown_check"] = "pass"
    with open_store(case) as store:
        session = verifying(case, store)
        nonce = session.verifier_nonce()
        with pytest.raises(SignerError) as raised:
            sign_via_subprocess(session.public_challenge(), nonce, record)
        assert nonce.hex() not in str(raised.value)
        assert nonce.hex() not in raised.value.stderr
