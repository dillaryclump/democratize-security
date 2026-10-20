"""Store v7 runtime lifecycle in the shared attempt ledger (issue #62)."""

import fcntl
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from democratize_security import artifacts, objects
from democratize_security.contracts import digest
from democratize_security.runtime_auth import VerifierSession
from democratize_security.store import V6_SCHEMA, VERSION, PlanStore, StoreError

ROOT = Path(__file__).resolve().parents[1]
V7_TABLES = ("runtime_results", "restore_reconciliations", "restore_fences")


@pytest.fixture
def case(tmp_path):
    return build_case(tmp_path)


def build_case(tmp_path):
    ledger, artifact_dir, source = (tmp_path / n for n in ("ledger", "artifacts", "source"))
    for path in (ledger, artifact_dir, source):
        path.mkdir()
    (source / "app.py").write_text("print('synthetic runtime')\n")
    ref = objects.publish_artifact(artifact_dir, artifacts.seal(source, ["app.py"]))
    campaign = json.loads((ROOT / "campaigns/development.example.json").read_text())
    with PlanStore(ledger, objects_directory=artifact_dir) as store:
        plan = store.import_campaign(campaign)
    return {
        "ledger": ledger,
        "artifact_dir": artifact_dir,
        "ref": ref,
        "campaign": campaign,
        "plan": plan,
    }


def open_store(case, **kwargs):
    return PlanStore(case["ledger"], objects_directory=case["artifact_dir"], **kwargs)


def runtime(action, revision, attempt="r1", **fields):
    return {
        "mode": "runtime",
        "action": action,
        "attempt_id": attempt,
        "expected_revision": revision,
        **fields,
    }


def prepare(case, attempt="r1", index=0):
    trial = case["plan"]["trials"][index]
    return runtime(
        "prepare",
        0,
        attempt,
        campaign_id=case["plan"]["campaign_id"],
        trial_id=trial["trial_id"],
        max_cost_cents=0,
        basis_sha256="a" * 64,
        source_revision="d" * 40,
        task_revision=trial["task_revision"],
        verifier_sha256="f" * 64,
        protocol="synthetic-reference-v3",
        config_sha256="1" * 64,
    )


DISPATCH = runtime(
    "dispatch_intent", 1, runner_request_id="run-1", dispatch_deadline="2026-10-20T20:00:00+00:00"
)
ACK = runtime("acknowledge", 2, runner_request_id="run-1", worker_id="worker-1")


def seal(case):
    return runtime(
        "seal",
        3,
        runner_request_id="run-1",
        worker_id="worker-1",
        stop_observation_sha256="3" * 64,
        artifact_ref=case["ref"],
    )


def to_sealed(case, store):
    for event_id, request in (
        ("prep", prepare(case)),
        ("dispatch", DISPATCH),
        ("ack", ACK),
        ("seal", seal(case)),
    ):
        state = store.record_runtime(event_id, request)
    return state


def verify_request(store, session=None):
    context = store.runtime_context("r1", "verify-1", expected_revision=5)
    session = session or VerifierSession(context)
    return session, runtime(
        "verify_intent",
        4,
        verification_request_id="verify-1",
        challenge=session.public_challenge(),
    )


def dump(case):
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        return list(db.iterdump())


def test_full_lifecycle_to_verifying(case):
    with open_store(case) as store:
        state = to_sealed(case, store)
        assert (state["phase"], state["revision"]) == ("sealed", 4)
        _, request = verify_request(store)
        state = store.record_runtime("verify", request)
        assert state["phase"] == "verifying"
        assert state["challenge_sha256"] == request["challenge"]["challenge_sha256"]
        budget = store.budget_snapshot(case["plan"]["campaign_id"])
        assert budget["blocked"] is True
        assert budget["execution_enabled"] is False
    with open_store(case) as store:
        (reread,) = store.attempts()
        assert reread == state


def test_exact_retry_across_reopen_returns_original(case):
    with open_store(case) as store:
        first = store.record_runtime("prep", prepare(case))
        dispatched = store.record_runtime("dispatch", DISPATCH)
    before = dump(case)
    with open_store(case) as store:
        assert store.record_runtime("prep", prepare(case)) == first
        assert store.record_runtime("dispatch", DISPATCH) == dispatched
    after = [line for line in dump(case) if "controller_generations" not in line]
    assert after == [line for line in before if "controller_generations" not in line]


def test_conflicting_event_reuse_persists_stop(case):
    with open_store(case) as store:
        store.record_runtime("prep", prepare(case))
        changed = dict(DISPATCH, runner_request_id="run-2")
        store.record_runtime("dispatch", DISPATCH)
        with pytest.raises(StoreError, match="Conflicting"):
            store.record_runtime("dispatch", changed)
        with pytest.raises(StoreError, match="Conflicting"):
            store.record_runtime("prep", changed)
    with open_store(case) as store:
        assert store._db.execute("SELECT count(*) FROM accounting_stops").fetchone() == (2,)
        assert store.attempts()[0]["runner_request_id"] == "run-1"
        assert store.budget_snapshot(case["plan"]["campaign_id"])["blocked"] is True


def test_second_active_attempt_blocked(case):
    with open_store(case) as store:
        store.record_runtime("prep", prepare(case))
        with pytest.raises(StoreError, match="blocks preparation"):
            store.record_runtime("prep-2", prepare(case, attempt="r2", index=1))


def test_prepare_requires_the_planned_task_revision(case):
    request = prepare(case)
    request["task_revision"] = "9" * 64
    with open_store(case) as store:
        with pytest.raises(StoreError, match="planned trial"):
            store.record_runtime("prep", request)
        assert store.attempts() == []


def insert_fence(case, fence_id="restore-1"):
    record = {"fence_id": fence_id, "kind": "restore_fence", "schema_version": 1}
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        db.execute(
            "INSERT INTO restore_fences VALUES (?, ?, ?)",
            (
                fence_id,
                datetime.now(UTC).isoformat(),
                json.dumps(record, sort_keys=True, separators=(",", ":")),
            ),
        )


def test_dispatch_blocked_by_unreconciled_fence(case):
    with open_store(case) as store:
        store.record_runtime("prep", prepare(case))
    insert_fence(case)
    with open_store(case) as store:
        assert store.unreconciled_restore_fences() == ["restore-1"]
        with pytest.raises(StoreError, match="restore fence"):
            store.record_runtime("dispatch", DISPATCH)
        assert store.attempts()[0]["phase"] == "preparing"


def test_seal_rejects_missing_or_tampered_artifact(case):
    with open_store(case) as store:
        for event_id, request in (("prep", prepare(case)), ("dispatch", DISPATCH), ("ack", ACK)):
            store.record_runtime(event_id, request)
        wrong = seal(case)
        wrong["artifact_ref"] = dict(case["ref"], object_sha256="0" * 64)
        with pytest.raises((StoreError, ValueError, OSError)):
            store.record_runtime("seal", wrong)
        assert store.attempts()[0]["phase"] == "running"


def test_artifact_changed_after_seal_blocks_reopen_and_budget(case):
    with open_store(case) as store:
        to_sealed(case, store)
    (path,) = case["artifact_dir"].iterdir()
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(StoreError, match="missing or changed"):
        open_store(case)


def test_verify_intent_requires_store_derived_challenge(case):
    with open_store(case) as store:
        to_sealed(case, store)
        context = store.runtime_context("r1", "verify-1", expected_revision=5)
        for changes in (
            {"controller_generation": context.controller_generation + 1},
            {"artifact_binding_sha256": "9" * 64},
        ):
            session = VerifierSession(type(context)(**{**context.__dict__, **changes}))
            _, request = verify_request(store, session)
            with pytest.raises(StoreError, match="not bound to this controller"):
                store.record_runtime("verify", request)
        assert store.attempts()[0]["phase"] == "sealed"


def test_challenge_from_previous_controller_is_rejected(case):
    with open_store(case) as store:
        to_sealed(case, store)
        _, request = verify_request(store)
    with open_store(case) as store:
        with pytest.raises(StoreError, match="not bound to this controller"):
            store.record_runtime("verify", request)


def test_admission_action_is_not_reachable_through_record_runtime(case):
    with open_store(case) as store:
        with pytest.raises(StoreError, match="authenticated admission"):
            store.record_runtime(
                "admit", runtime("admit", 5, result_sha256="5" * 64, coverage="complete")
            )


def test_offline_writers_reject_runtime_attempts(case):
    with open_store(case) as store:
        store.record_runtime("prep", prepare(case))
        trial = case["plan"]["trials"][0]
        with pytest.raises(StoreError, match="runtime attempt"):
            store.record_accounting(
                "offline-interrupt",
                {"action": "interrupt", "attempt_id": "r1", "expected_revision": 1, "reason": "x"},
            )
        with pytest.raises(StoreError, match="runtime attempt"):
            store.record_artifact(
                "offline-artifact",
                {
                    "attempt_id": "r1",
                    "expected_revision": 1,
                    "campaign_id": case["plan"]["campaign_id"],
                    "trial_id": trial["trial_id"],
                    "task_revision": trial["task_revision"],
                    "verifier_sha256": "f" * 64,
                    "protocol": "synthetic-reference-v3",
                    "artifact_ref": case["ref"],
                },
            )
        for writer, request in (
            (
                store.record_verification_intent,
                {
                    "attempt_id": "r1",
                    "expected_revision": 1,
                    "artifact_binding_sha256": "2" * 64,
                    "verification_request_id": "verify-1",
                },
            ),
            (
                store.record_evidence,
                {
                    "attempt_id": "r1",
                    "expected_revision": 1,
                    "artifact_binding_sha256": "2" * 64,
                    "verification_request_id": "verify-1",
                    "verification_intent_sha256": "3" * 64,
                    "evidence_ref": {},
                },
            ),
        ):
            with pytest.raises(StoreError):
                writer("offline-other", request)
        (state,) = store.attempts()
        assert (state["phase"], state["revision"]) == ("preparing", 1)


def test_mixed_mode_history_rejected_on_read(case):
    with open_store(case) as store:
        store.record_runtime("prep", prepare(case))
    offline = {"action": "interrupt", "attempt_id": "r1", "expected_revision": 1, "reason": "x"}
    state = {"forged": True}
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        db.execute(
            "INSERT INTO attempt_events VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "forged",
                "r1",
                2,
                None,
                datetime.now(UTC).isoformat(),
                json.dumps(offline, sort_keys=True, separators=(",", ":")),
                json.dumps(state),
            ),
        )
    with pytest.raises(StoreError, match="mixes offline and runtime"):
        open_store(case)


def test_superseded_handle_runtime_write_has_no_effect(case):
    with open_store(case) as stale:
        stale.record_runtime("prep", prepare(case))
        fcntl.flock(stale._lock_fd, fcntl.LOCK_UN)
        with open_store(case) as current:
            before = list(current._db.iterdump())
            with pytest.raises(StoreError, match="Stale controller generation"):
                stale.record_runtime("dispatch", DISPATCH)
            with pytest.raises(StoreError, match="Stale controller generation"):
                stale.record_runtime("prep", prepare(case))
            assert list(current._db.iterdump()) == before


def make_v6(case):
    assert digest(V6_SCHEMA) == digest(
        {k: v for k, v in _schema(case).items() if not k.startswith(V7_TABLES)}
    )
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        for table in V7_TABLES:
            db.execute(f"DROP TABLE {table}")
        db.execute("PRAGMA user_version=6")
        return list(db.iterdump())


def _schema(case):
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        return dict(
            db.execute("SELECT name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'")
        )


def test_v6_store_requires_explicit_migration_and_preserves_bytes(case):
    before = make_v6(case)
    with pytest.raises(StoreError, match="Version 6 requires explicit"):
        open_store(case)
    assert dump(case) == before
    with open_store(case, migrate=True) as store:
        assert store._db.execute("PRAGMA user_version").fetchone() == (VERSION,)
        assert VERSION == 7
    kept = [
        line
        for line in dump(case)
        if not any(name in line for name in (*V7_TABLES, "controller_generations"))
    ]
    assert kept == [line for line in before if "controller_generations" not in line]


def test_corrupt_v6_generation_history_blocks_migration(case):
    make_v6(case)
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        db.execute("DROP TRIGGER controller_generations_no_update")
        db.execute("UPDATE controller_generations SET generation = 5")
        db.execute(V6_SCHEMA["controller_generations_no_update"])
    with pytest.raises(StoreError, match="generation history"):
        open_store(case, migrate=True)
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone() == (6,)


@pytest.mark.parametrize("table", ["restore_fences", "restore_reconciliations"])
@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
def test_new_tables_are_immutable(case, table, operation):
    insert_fence(case)
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        if table == "restore_reconciliations":
            db.execute("INSERT INTO restore_reconciliations VALUES ('e', 'restore-1', 't', '{}')")
        statement = (
            f"UPDATE {table} SET record_json = '{{}}'"
            if operation == "UPDATE"
            else f"DELETE FROM {table}"
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable runtime record"):
            db.execute(statement)
