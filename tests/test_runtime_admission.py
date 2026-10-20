"""Authenticated runtime result admission in store v7 (issue #62)."""

import sqlite3

import pytest
from test_runtime_store import build_case, open_store, runtime, to_sealed, verify_request

from democratize_security.runtime_auth import VerifierSession, sign_report
from democratize_security.store import SCHEMA, StoreError
from democratize_security.verification.report import REQUIRED, Check, summarize


@pytest.fixture
def case(tmp_path):
    return build_case(tmp_path)


def report(outcome):
    if outcome == "incomplete":
        return summarize([Check(name, "pass") for name in sorted(REQUIRED)[:-1]])
    first = sorted(REQUIRED)[0]
    return summarize(
        [
            Check(name, "fail" if outcome == "fail" and name == first else "pass")
            for name in REQUIRED
        ]
    )


def verifying(case, store):
    to_sealed(case, store)
    session, request = verify_request(store)
    store.record_runtime("verify", request)
    return session


def signed(session, outcome="pass"):
    return sign_report(session.public_challenge(), session.verifier_nonce(), report(outcome))


@pytest.mark.parametrize("outcome", ["pass", "fail"])
def test_complete_report_completes_and_keeps_its_outcome(case, outcome):
    with open_store(case) as store:
        session = verifying(case, store)
        record = store.admit_result("admit", "r1", 5, session, signed(session, outcome))
        assert (record["coverage"], record["outcome"]) == ("complete", outcome)
        (state,) = store.attempts()
        assert (state["phase"], state["revision"]) == ("completed", 6)
        assert state["actual_cost_cents"] is None  # Unsettled cost stays held.
    with open_store(case) as store:
        assert store.runtime_results() == [record]
        settled = store.record_runtime(
            "settle", runtime("settle", 6, actual_cost_cents=0, receipt_id="receipt-1")
        )
        assert (settled["phase"], settled["actual_cost_cents"]) == ("completed", 0)


def test_partial_report_interrupts_and_keeps_hold(case):
    with open_store(case) as store:
        session = verifying(case, store)
        record = store.admit_result("admit", "r1", 5, session, signed(session, "incomplete"))
        assert (record["coverage"], record["outcome"]) == ("incomplete", "incomplete")
        (state,) = store.attempts()
        assert (state["phase"], state["reason"]) == ("interrupted", "incomplete_verification")
        assert store.budget_snapshot(state["campaign_id"])["blocked"] is True


def test_wrong_session_is_rejected_without_effects(case):
    with open_store(case) as store:
        verifying(case, store)
        context = store.runtime_context("r1", "verify-1", expected_revision=5)
        other = VerifierSession(context)  # Same context, different private nonce.
        before = list(store._db.iterdump())
        with pytest.raises(StoreError, match="committed challenge"):
            store.admit_result("admit", "r1", 5, other, signed(other))
        assert list(store._db.iterdump()) == before


def test_report_signed_for_another_session_is_rejected(case):
    with open_store(case) as store:
        session = verifying(case, store)
        context = store.runtime_context("r1", "verify-1", expected_revision=5)
        forged = signed(VerifierSession(context))
        with pytest.raises(StoreError, match="rejected"):
            store.admit_result("admit", "r1", 5, session, forged)
        assert store.attempts()[0]["phase"] == "verifying"


def test_restart_cannot_admit_pre_crash_report(case):
    with open_store(case) as store:
        session = verifying(case, store)
        raw = signed(session)
    with open_store(case) as store:
        # The original session is in this test's memory, but its challenge names the
        # previous controller generation, so the restarted store refuses it.
        with pytest.raises(StoreError, match="committed challenge"):
            store.admit_result("admit", "r1", 5, session, raw)
        fresh = VerifierSession(store.runtime_context("r1", "verify-1", expected_revision=5))
        with pytest.raises(StoreError, match="committed challenge"):
            store.admit_result("admit", "r1", 5, fresh, raw)
        reconciling = store.record_runtime("reconcile", runtime("reconcile", 5, reason="restart"))
        assert reconciling["phase"] == "reconciling"
        stopped = store.record_runtime("stop", runtime("interrupt", 6, reason="nonce lost"))
        assert (stopped["phase"], stopped["actual_cost_cents"]) == ("interrupted", None)


def test_conflicting_second_report_rejected_without_effects(case):
    with open_store(case) as store:
        session = verifying(case, store)
        record = store.admit_result("admit", "r1", 5, session, signed(session, "pass"))
        before = list(store._db.iterdump())
        with pytest.raises(StoreError):
            store.admit_result("admit-2", "r1", 6, session, signed(session, "fail"))
        assert list(store._db.iterdump()) == before
        assert store.runtime_results() == [record]


def test_exact_admit_retry_returns_original(case):
    with open_store(case) as store:
        session = verifying(case, store)
        raw = signed(session)
        record = store.admit_result("admit", "r1", 5, session, raw)
        assert store.admit_result("admit", "r1", 5, session, raw) == record
        assert len(store.runtime_results()) == 1


def test_reused_event_id_with_different_envelope_persists_stop(case):
    with open_store(case) as store:
        session = verifying(case, store)
        store.admit_result("admit", "r1", 5, session, signed(session))
        with pytest.raises(StoreError, match="Conflicting"):
            store.admit_result("admit", "r1", 5, session, b"{}")
    with open_store(case) as store:
        assert store._db.execute("SELECT count(*) FROM accounting_stops").fetchone() == (1,)


def test_result_row_event_and_state_commit_together(case):
    with open_store(case) as store:
        session = verifying(case, store)
        store._db.execute(
            "CREATE TEMP TRIGGER fail_result BEFORE INSERT ON runtime_results "
            "BEGIN SELECT RAISE(ABORT, 'injected'); END"
        )
        before = list(store._db.iterdump())
        with pytest.raises(sqlite3.IntegrityError, match="injected"):
            store.admit_result("admit", "r1", 5, session, signed(session))
        store._db.execute("DROP TRIGGER fail_result")
        assert list(store._db.iterdump()) == before
        assert store.attempts()[0]["phase"] == "verifying"
        assert store.runtime_results() == []


def test_tampered_result_row_rejected_on_reopen(case):
    with open_store(case) as store:
        session = verifying(case, store)
        store.admit_result("admit", "r1", 5, session, signed(session))
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        db.execute("DROP TRIGGER runtime_results_no_update")
        db.execute("UPDATE runtime_results SET record_json = replace(record_json, 'pass', 'PASS')")
        db.execute(SCHEMA["runtime_results_no_update"])
    with pytest.raises(StoreError, match="runtime result"):
        open_store(case)


@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
def test_runtime_results_are_immutable(case, operation):
    with open_store(case) as store:
        session = verifying(case, store)
        store.admit_result("admit", "r1", 5, session, signed(session))
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        statement = (
            "UPDATE runtime_results SET record_json = '{}'"
            if operation == "UPDATE"
            else "DELETE FROM runtime_results"
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable runtime record"):
            db.execute(statement)


def test_admission_requires_verifying_attempt_at_expected_revision(case):
    with open_store(case) as store:
        session = verifying(case, store)
        with pytest.raises(StoreError, match="expected revision"):
            store.admit_result("admit", "r1", 4, session, signed(session))
