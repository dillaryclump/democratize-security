import copy
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from democratize_security import artifacts, objects
from democratize_security.contracts import digest
from democratize_security.store import APPLICATION_ID, V2_SCHEMA, VERSION, PlanStore, StoreError

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def case(tmp_path):
    ledger = tmp_path / "ledger"
    ledger.mkdir()
    directory = tmp_path / "objects"
    directory.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('synthetic')\n")
    reference = objects.publish_artifact(directory, artifacts.seal(source, ["app.py"]))
    campaign = json.loads((ROOT / "campaigns/development.example.json").read_text())
    with PlanStore(ledger) as store:
        plan = store.import_campaign(campaign)
        trial = plan["trials"][0]
        store.record_accounting(
            "reserve",
            dict(
                action="prepare",
                attempt_id="synthetic-1",
                expected_revision=0,
                campaign_id=plan["campaign_id"],
                trial_id=trial["trial_id"],
                basis_sha256="a" * 64,
                max_cost_cents=0,
            ),
        )
    request = dict(
        attempt_id="synthetic-1",
        expected_revision=1,
        campaign_id=plan["campaign_id"],
        trial_id=trial["trial_id"],
        task_revision=trial["task_revision"],
        verifier_sha256="b" * 64,
        protocol="synthetic-reference-v3",
        artifact_ref=reference,
    )
    return ledger, directory, request


def open_store(case):
    return PlanStore(case[0], objects_directory=case[1])


def interrupt(store):
    store.record_accounting(
        "stop",
        dict(
            action="interrupt",
            attempt_id="synthetic-1",
            expected_revision=1,
            reason="synthetic abandonment",
        ),
    )


def test_binding_reopens_and_duplicate_after_interruption_is_noop(case):
    ledger, directory, request = case
    with open_store(case) as store:
        before = store.attempts()
        result = store.record_artifact("bind", request)
        assert store.attempts() == before
        assert store.artifact_bindings() == [result]
        interrupt(store)
        dump = list(store._db.iterdump())
        assert store.record_artifact("bind", request) == result
        assert list(store._db.iterdump()) == dump
    with open_store(case) as store:
        assert store.artifact_bindings() == [result]
        assert store.snapshot(request["campaign_id"])["execution_enabled"] is False
        assert store.attempts()[0]["phase"] == "interrupted"
    with pytest.raises(StoreError, match="objects_directory"):
        PlanStore(ledger)
    request["artifact_ref"]["artifact_sha256"] = "0" * 64
    result["request"]["protocol"] = "changed"
    with open_store(case) as store:
        assert store.artifact_bindings()[0]["request"]["protocol"] == "synthetic-reference-v3"


@pytest.mark.parametrize(
    "key,value",
    [
        ("campaign_id", "missing"),
        ("trial_id", "missing"),
        ("attempt_id", "missing"),
        ("task_revision", "c" * 64),
        ("verifier_sha256", "unknown"),
        ("protocol", ""),
        ("expected_revision", True),
        ("expected_revision", 2),
        ("extra", 1),
    ],
)
def test_invalid_binding_rolls_back(case, key, value):
    with open_store(case) as store:
        before = list(store._db.iterdump())
        request = {**case[2], key: value}
        with pytest.raises(StoreError):
            store.record_artifact("invalid", request)
        assert list(store._db.iterdump()) == before


def test_stale_preparation_revision_cannot_attach_after_interruption(case):
    with open_store(case) as store:
        interrupt(store)
        with pytest.raises(StoreError, match="Stale"):
            store.record_artifact("late", case[2])
        assert store.artifact_bindings() == []


@pytest.mark.parametrize(
    "key,value",
    [
        ("verifier_sha256", "c" * 64),
        ("protocol", "changed"),
        ("expected_revision", True),
    ],
)
def test_conflicting_binding_keeps_original_and_stops_preparation(case, key, value):
    with open_store(case) as store:
        original = store.record_artifact("bind", case[2])
        changed = {**case[2], key: value}
        with pytest.raises(StoreError, match="Conflicting"):
            store.record_artifact("bind", changed)
        assert store.artifact_bindings() == [original]
        interrupt(store)
        store.record_accounting(
            "bill",
            dict(
                action="settle",
                attempt_id="synthetic-1",
                expected_revision=2,
                actual_cost_cents=0,
                receipt_id="synthetic-zero",
            ),
        )
    with open_store(case) as store:
        assert store.budget_snapshot(case[2]["campaign_id"])["blocked"]
        assert store._db.execute("SELECT count(*) FROM accounting_stops").fetchone()[0] == 1


@pytest.mark.parametrize("mode", ["missing", "changed"])
def test_missing_or_changed_object_blocks_read_reopen_and_preparation(case, mode):
    ledger, directory, request = case
    with open_store(case) as store:
        store.record_artifact("bind", request)
        interrupt(store)
        store.record_accounting(
            "bill",
            dict(
                action="settle",
                attempt_id="synthetic-1",
                expected_revision=2,
                actual_cost_cents=0,
                receipt_id="synthetic-zero",
            ),
        )
        path = directory / (request["artifact_ref"]["object_sha256"] + ".json")
        if mode == "missing":
            path.unlink()
        else:
            data = path.read_bytes()
            path.write_bytes(b"X" + data[1:])
        for call in [
            store.artifact_bindings,
            lambda: store.budget_snapshot(request["campaign_id"]),
        ]:
            with pytest.raises(StoreError, match="Invalid artifact binding"):
                call()
        trial = store.snapshot(request["campaign_id"])["trials"][1]
        with pytest.raises(StoreError):
            store.record_accounting(
                "next",
                dict(
                    action="prepare",
                    attempt_id="synthetic-2",
                    expected_revision=0,
                    campaign_id=request["campaign_id"],
                    trial_id=trial["trial_id"],
                    basis_sha256="a" * 64,
                    max_cost_cents=0,
                ),
            )
        assert len(store.attempts()) == 1
    with pytest.raises(StoreError):
        open_store(case)


def test_failed_sync_or_sql_insert_never_commits_binding(case, monkeypatch):
    with open_store(case) as store:
        before = list(store._db.iterdump())

        def fail(fd):
            raise OSError("injected fsync failure")

        with monkeypatch.context() as patch:
            patch.setattr(os, "fsync", fail)
            with pytest.raises(OSError, match="injected"):
                store.record_artifact("bind", case[2])
        assert list(store._db.iterdump()) == before
        store._db.execute("""CREATE TRIGGER fail_binding BEFORE INSERT ON artifact_bindings
            BEGIN SELECT RAISE(ABORT, 'injected SQL failure'); END""")
        with pytest.raises(sqlite3.IntegrityError, match="injected"):
            store.record_artifact("bind", case[2])
        assert store.artifact_bindings() == []
        store._db.execute("DROP TRIGGER fail_binding")
        assert list(store._db.iterdump()) == before
        assert store.record_artifact("bind", case[2])


@pytest.mark.parametrize("phase", ["before", "after"])
def test_process_crash_keeps_binding_and_event_atomic(case, phase):
    ledger, directory, request = case
    program = """
import json, os, sys
from pathlib import Path
from democratize_security.store import PlanStore
store = PlanStore(Path(sys.argv[1]), objects_directory=Path(sys.argv[2]))
if sys.argv[3] == 'before':
    store._db.set_trace_callback(lambda sql: os._exit(71) if sql == 'COMMIT' else None)
store.record_artifact('bind', json.loads(sys.argv[4]))
os._exit(72)
"""
    run = subprocess.run(
        [sys.executable, "-c", program, str(ledger), str(directory), phase, json.dumps(request)],
        timeout=10,
        check=False,
    )
    assert run.returncode == (71 if phase == "before" else 72)
    with open_store(case) as store:
        assert len(store.artifact_bindings()) == (0 if phase == "before" else 1)
        result = store.record_artifact("bind", request)
        assert store.artifact_bindings() == [result]
        assert store.attempts()[0]["revision"] == 1


def test_immutable_binding_and_corruption_detection(case):
    with open_store(case) as store:
        store.record_artifact("bind", case[2])
        for sql in ["DELETE FROM artifact_bindings", "UPDATE artifact_bindings SET revision=2"]:
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                store._db.execute(sql)
        store._db.execute("DROP TRIGGER artifact_bindings_no_update")
        store._db.execute("UPDATE artifact_bindings SET record_json='{}'")
        with pytest.raises(StoreError):
            store.artifact_bindings()


def make_v2(case):
    # Preserve real campaign/attempt/event rows while constructing the pinned old schema.
    ledger = case[0]
    assert digest(V2_SCHEMA) == "183c0478e8b9ba7fa200b902dc4f49d4087adbec12e6c456107187c07b27e994"
    with sqlite3.connect(ledger / "ledger.sqlite3") as db:
        db.execute("DROP TABLE runtime_results")
        db.execute("DROP TABLE restore_reconciliations")
        db.execute("DROP TABLE restore_fences")
        db.execute("DROP TABLE controller_generations")
        db.execute("DROP TABLE verification_intents")
        db.execute("DROP TABLE evidence_bindings")
        db.execute("DROP TABLE artifact_bindings")
        db.execute("PRAGMA user_version=2")
        before = list(db.iterdump())
        assert db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
    return before


def test_v2_migration_preserves_rows_and_requires_opt_in(case):
    before = make_v2(case)
    with pytest.raises(StoreError, match="explicit"):
        open_store(case)
    with PlanStore(case[0], objects_directory=case[1], migrate=True) as store:
        assert store._db.execute("PRAGMA user_version").fetchone()[0] == VERSION
        old_dump = [
            line
            for line in store._db.iterdump()
            if "artifact_bindings" not in line
            and "evidence_bindings" not in line
            and "verification_intents" not in line
            and all(
                name not in line
                for name in (
                    "controller_generations",
                    "runtime_results",
                    "restore_fences",
                    "restore_reconciliations",
                )
            )
        ]
        assert old_dump == before
        assert store.record_artifact("bind", case[2])


def test_failed_v2_migration_and_corrupt_legacy_accounting_do_not_change_schema(case, monkeypatch):
    make_v2(case)
    original = sqlite3.connect

    class FailingConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith("CREATE TRIGGER artifact_bindings"):
                raise sqlite3.OperationalError("injected migration failure")
            return super().execute(sql, *args)

    with monkeypatch.context() as patch:
        patch.setattr(
            sqlite3, "connect", lambda *a, **kw: original(*a, factory=FailingConnection, **kw)
        )
        with pytest.raises(sqlite3.OperationalError, match="injected"):
            PlanStore(case[0], migrate=True)
    with sqlite3.connect(case[0] / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='artifact_bindings'"
        ).fetchone()
        db.execute("UPDATE attempts SET state_json='{}'")
    with pytest.raises(StoreError, match="projection"):
        PlanStore(case[0], migrate=True)
    with sqlite3.connect(case[0] / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2


def test_wrong_artifact_payload_identity_rejected_before_binding(case):
    request = copy.deepcopy(case[2])
    request["artifact_ref"]["artifact_sha256"] = "0" * 64
    with open_store(case) as store:
        with pytest.raises(artifacts.ArtifactError):
            store.record_artifact("bind", request)
        assert store.artifact_bindings() == []


@pytest.mark.parametrize("phase", ["before", "after"])
def test_v2_migration_process_crash_is_all_or_nothing(case, phase):
    make_v2(case)
    program = """
import os, sqlite3, sys
from pathlib import Path
from democratize_security.store import PlanStore
original = sqlite3.connect
class Connection(sqlite3.Connection):
    def execute(self, sql, *args):
        if sql == 'COMMIT' and sys.argv[2] == 'before':
            os._exit(71)
        return super().execute(sql, *args)
sqlite3.connect = lambda *a, **kw: original(*a, factory=Connection, **kw)
PlanStore(Path(sys.argv[1]), migrate=True)
os._exit(72)
"""
    run = subprocess.run(
        [sys.executable, "-c", program, str(case[0]), phase], timeout=10, check=False
    )
    assert run.returncode == (71 if phase == "before" else 72)
    with sqlite3.connect(case[0] / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == (
            2 if phase == "before" else VERSION
        )
        assert bool(
            db.execute("SELECT 1 FROM sqlite_master WHERE name='artifact_bindings'").fetchone()
        ) == (phase == "after")
    with PlanStore(case[0], objects_directory=case[1], migrate=True) as store:
        assert store.attempts()[0]["revision"] == 1
        assert store.record_artifact("bind", case[2])
