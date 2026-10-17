import copy
import json
import sqlite3
import subprocess
import sys

import pytest
from test_store_evidence import build_case, finish_accounting, next_prepare, open_store, seed_intent

from democratize_security.contracts import digest
from democratize_security.store import V4_SCHEMA, VERSION, StoreError


@pytest.fixture
def pending(tmp_path):
    return build_case(tmp_path, with_intent=False)


def intent_request(case):
    return {k: v for k, v in case["request"].items() if k != "evidence_ref"}


def test_intent_is_durable_before_evidence_and_does_not_execute(pending):
    with open_store(pending) as store:
        before = store.attempts()
        with pytest.raises(StoreError, match="fields"):
            store.record_evidence("early", pending["request"])
        forged = {**pending["request"], "verification_intent_sha256": "0" * 64}
        with pytest.raises(StoreError, match="preexisting"):
            store.record_evidence("early", forged)
        intent = seed_intent(pending, store)
        assert store.attempts() == before
        assert store.evidence_bindings() == []
        assert store.verification_intents() == [intent]
        assert store.snapshot(pending["plan"]["campaign_id"])["execution_enabled"] is False
    with open_store(pending) as store:
        assert store.verification_intents() == [intent]
        request = {**pending["request"], "verification_intent_sha256": intent["intent_sha256"]}
        result = store.record_evidence("report", request)
        assert result["schema_version"] == 2
        assert result["request"]["verification_intent_sha256"] == intent["intent_sha256"]
        finish_accounting(store)
        before = list(store._db.iterdump())
        assert seed_intent(pending, store) == intent
        assert store.record_evidence("report", request) == result
        assert list(store._db.iterdump()) == before
    intent["request"]["verification_request_id"] = "changed"
    with open_store(pending) as store:
        assert store.verification_intents()[0]["request"]["verification_request_id"] == "verify-1"


@pytest.mark.parametrize(
    "key,value",
    [
        ("attempt_id", "missing"),
        ("expected_revision", True),
        ("expected_revision", 2),
        ("artifact_binding_sha256", "0" * 64),
        ("verification_request_id", ""),
        ("extra", 1),
    ],
)
def test_invalid_intent_never_writes(pending, key, value):
    with open_store(pending) as store:
        before = list(store._db.iterdump())
        with pytest.raises(StoreError):
            store.record_verification_intent("bad", {**intent_request(pending), key: value})
        assert list(store._db.iterdump()) == before


def test_intent_cannot_be_created_after_interruption(pending):
    with open_store(pending) as store:
        finish_accounting(store)
        with pytest.raises(StoreError, match="Stale"):
            seed_intent(pending, store)
        assert store.verification_intents() == []


@pytest.mark.parametrize("change", ["event", "attempt", "request", "binding"])
def test_conflicting_intent_stops_future_work_and_keeps_original(pending, change):
    request = intent_request(pending)
    event = "intent"
    with open_store(pending) as store:
        original = seed_intent(pending, store)
        if change == "event":
            event = "other"
        elif change == "attempt":
            request["attempt_id"] = "other-attempt"
            event = "other"
        elif change == "request":
            request["verification_request_id"] = "other-request"
        else:
            request["artifact_binding_sha256"] = "0" * 64
        with pytest.raises(StoreError, match="Conflicting"):
            store.record_verification_intent(event, request)
        assert store.verification_intents() == [original]
        finish_accounting(store)
    with open_store(pending) as store:
        with pytest.raises(StoreError, match="blocks preparation"):
            store.record_accounting("next", next_prepare(pending))
        assert store.budget_snapshot(pending["plan"]["campaign_id"])["blocked"]


@pytest.mark.parametrize("change", ["digest", "request"])
def test_evidence_cannot_change_preexisting_intent(pending, change):
    with open_store(pending) as store:
        intent = seed_intent(pending, store)
        request = {**pending["request"], "verification_intent_sha256": intent["intent_sha256"]}
        if change == "digest":
            request["verification_intent_sha256"] = "0" * 64
        else:
            request["verification_request_id"] = "other"
        with pytest.raises(StoreError, match="preexisting"):
            store.record_evidence("bad", request)
        assert store.evidence_bindings() == []


@pytest.mark.parametrize(
    "column,value",
    [
        ("verification_request_id", "other"),
        ("artifact_event_id", "other"),
        ("attempt_id", "other"),
        ("revision", 2),
        ("record_json", "{}"),
    ],
)
def test_intent_projection_tampering_blocks_read_budget_reopen(pending, column, value):
    with open_store(pending) as store:
        seed_intent(pending, store)
        for sql in (
            "DELETE FROM verification_intents",
            "UPDATE verification_intents SET revision=2",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                store._db.execute(sql)
        store._db.execute("DROP TRIGGER verification_intents_no_update")
        store._db.execute("PRAGMA foreign_keys=OFF")
        store._db.execute(f"UPDATE verification_intents SET {column}=?", (value,))
        for call in (
            store.verification_intents,
            store.evidence_bindings,
            lambda: store.budget_snapshot(pending["plan"]["campaign_id"]),
        ):
            with pytest.raises(StoreError):
                call()
    with pytest.raises(StoreError):
        open_store(pending)


def test_missing_artifact_blocks_pending_intent(pending):
    with open_store(pending) as store:
        seed_intent(pending, store)
        ref = pending["binding"]["request"]["artifact_ref"]
        (pending["artifact_dir"] / (ref["object_sha256"] + ".json")).unlink()
        with pytest.raises(StoreError):
            store.verification_intents()
        with pytest.raises(StoreError):
            seed_intent(pending, store)
    with pytest.raises(StoreError):
        open_store(pending)


def make_v4(case, *, legacy_evidence=True):
    assert digest(V4_SCHEMA) == "faaea6fd6f6ac9e0770d71bdbfbfa5ccb9b9dc2952b9847752709b77792cd9d2"
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        db.execute("DROP TABLE verification_intents")
        db.execute("PRAGMA user_version=4")
        if legacy_evidence:
            record = {
                "schema_version": 1,
                "kind": "offline_evidence_binding",
                "event_id": "legacy",
                "request": copy.deepcopy(case["request"]),
            }
            record["binding_sha256"] = digest(record)
            db.execute(
                "INSERT INTO evidence_bindings VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "legacy",
                    "a1",
                    "artifact",
                    "verify-1",
                    1,
                    json.dumps(record, sort_keys=True, separators=(",", ":")),
                ),
            )
        assert (
            dict(
                db.execute(
                    "SELECT name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
                ).fetchall()
            )
            == V4_SCHEMA
        )
        return list(db.iterdump())


def test_v4_migration_preserves_legacy_evidence_without_fabricating_intent(pending):
    before = make_v4(pending)
    with pytest.raises(StoreError, match="explicit"):
        open_store(pending)
    with open_store(pending, migrate=True) as store:
        assert store._db.execute("PRAGMA user_version").fetchone()[0] == VERSION
        assert [
            line for line in store._db.iterdump() if "verification_intents" not in line
        ] == before
        assert store.verification_intents() == []
        legacy = store.evidence_bindings()[0]
        assert legacy["schema_version"] == 1
        assert store.record_evidence("legacy", pending["request"]) == legacy
        with pytest.raises(StoreError, match="retrospective"):
            seed_intent(pending, store)
        assert store.verification_intents() == []


def test_v4_corrupt_evidence_prevents_migration(pending):
    before = make_v4(pending)
    ref = pending["request"]["evidence_ref"]
    (pending["evidence_dir"] / (ref["object_sha256"] + ".json")).unlink()
    with pytest.raises(StoreError):
        open_store(pending, migrate=True)
    with sqlite3.connect(pending["ledger"] / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4
        assert list(db.iterdump()) == before


@pytest.mark.parametrize("stage", ["insert", "commit"])
def test_intent_sql_failure_rolls_back(pending, monkeypatch, stage):
    original = sqlite3.connect

    class FailingConnection(sqlite3.Connection):
        armed = False

        def execute(self, sql, *args):
            if self.armed and (
                sql.startswith("INSERT INTO verification_intents")
                if stage == "insert"
                else sql == "COMMIT"
            ):
                raise sqlite3.OperationalError("injected failure")
            return super().execute(sql, *args)

    monkeypatch.setattr(
        sqlite3, "connect", lambda *a, **kw: original(*a, factory=FailingConnection, **kw)
    )
    with open_store(pending) as store:
        before = list(store._db.iterdump())
        store._db.armed = True
        with pytest.raises(sqlite3.OperationalError, match="injected"):
            seed_intent(pending, store)
        store._db.armed = False
        assert list(store._db.iterdump()) == before
        assert seed_intent(pending, store)


def test_v4_migration_sql_failure_preserves_old_schema(pending, monkeypatch):
    before = make_v4(pending)
    original = sqlite3.connect

    class FailingConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith("CREATE TRIGGER verification_intents"):
                raise sqlite3.OperationalError("injected migration failure")
            return super().execute(sql, *args)

    with monkeypatch.context() as patch:
        patch.setattr(
            sqlite3, "connect", lambda *a, **kw: original(*a, factory=FailingConnection, **kw)
        )
        with pytest.raises(sqlite3.OperationalError, match="injected"):
            open_store(pending, migrate=True)
    with sqlite3.connect(pending["ledger"] / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4
        assert list(db.iterdump()) == before


@pytest.mark.parametrize("operation", ["intent", "migration"])
@pytest.mark.parametrize("phase", ["before", "after"])
def test_process_crash_during_intent_or_migration_is_atomic(pending, operation, phase):
    if operation == "migration":
        make_v4(pending, legacy_evidence=False)
    program = """
import json, os, sqlite3, sys
from pathlib import Path
from democratize_security.store import PlanStore
original = sqlite3.connect
class Connection(sqlite3.Connection):
    def execute(self, sql, *args):
        if sql == 'COMMIT' and sys.argv[5] == 'before':
            os._exit(71)
        return super().execute(sql, *args)
sqlite3.connect = lambda *a, **kw: original(*a, factory=Connection, **kw)
store = PlanStore(Path(sys.argv[1]), objects_directory=Path(sys.argv[2]),
    evidence_directory=Path(sys.argv[3]), migrate=sys.argv[4] == 'migration')
if sys.argv[4] == 'intent':
    store.record_verification_intent('intent', json.loads(sys.argv[6]))
os._exit(72)
"""
    run = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(pending["ledger"]),
            str(pending["artifact_dir"]),
            str(pending["evidence_dir"]),
            operation,
            phase,
            json.dumps(intent_request(pending)),
        ],
        timeout=10,
        check=False,
    )
    assert run.returncode == (71 if phase == "before" else 72)
    with sqlite3.connect(pending["ledger"] / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == (
            4 if operation == "migration" and phase == "before" else VERSION
        )
    with open_store(pending, migrate=True) as store:
        assert len(store.verification_intents()) == (
            1 if operation == "intent" and phase == "after" else 0
        )
        intent = seed_intent(pending, store)
        request = {**pending["request"], "verification_intent_sha256": intent["intent_sha256"]}
        assert store.record_evidence("report", request)["schema_version"] == 2
        assert store.attempts()[0]["revision"] == 1
