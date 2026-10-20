import copy
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from democratize_security import artifacts, evidence, evidence_objects, objects
from democratize_security.contracts import digest
from democratize_security.store import V3_SCHEMA, VERSION, PlanStore, StoreError
from democratize_security.verification.report import REQUIRED, Check, summarize

ROOT = Path(__file__).resolve().parents[1]


def seed_intent(case, store):
    return store.record_verification_intent(
        "intent",
        {
            "attempt_id": "a1",
            "expected_revision": 1,
            "artifact_binding_sha256": case["binding"]["binding_sha256"],
            "verification_request_id": "verify-1",
        },
    )


@pytest.fixture
def case(tmp_path):
    return build_case(tmp_path)


def build_case(tmp_path, *, with_intent=True):
    ledger, artifact_dir, evidence_dir, source = [
        tmp_path / name for name in ("ledger", "artifacts", "evidence", "source")
    ]
    for path in (ledger, artifact_dir, evidence_dir, source):
        path.mkdir()
    (source / "app.py").write_text("print('synthetic')\n")
    artifact_ref = objects.publish_artifact(artifact_dir, artifacts.seal(source, ["app.py"]))
    with PlanStore(
        ledger, objects_directory=artifact_dir, evidence_directory=evidence_dir
    ) as store:
        plan = store.import_campaign(
            json.loads((ROOT / "campaigns/development.example.json").read_text())
        )
        trial = plan["trials"][0]
        context = dict(attempt_id="a1", campaign_id=plan["campaign_id"], trial_id=trial["trial_id"])
        store.record_accounting(
            "prepare",
            dict(
                action="prepare",
                **context,
                expected_revision=0,
                max_cost_cents=0,
                basis_sha256="a" * 64,
            ),
        )
        binding = store.record_artifact(
            "artifact",
            dict(
                **context,
                expected_revision=1,
                task_revision=trial["task_revision"],
                verifier_sha256="b" * 64,
                protocol="synthetic-reference-v3",
                artifact_ref=artifact_ref,
            ),
        )
        intent = seed_intent({"binding": binding}, store) if with_intent else None
    report = summarize([Check(name, "pass") for name in sorted(REQUIRED)])
    record = evidence.bind_report(binding, "verify-1", report)
    ref = evidence_objects.publish_evidence(evidence_dir, record, binding, "verify-1")
    request = dict(
        attempt_id="a1",
        expected_revision=1,
        artifact_binding_sha256=binding["binding_sha256"],
        verification_request_id="verify-1",
        evidence_ref=ref,
    )
    if intent is not None:
        request["verification_intent_sha256"] = intent["intent_sha256"]
    return dict(
        ledger=ledger,
        artifact_dir=artifact_dir,
        evidence_dir=evidence_dir,
        binding=binding,
        request=request,
        record=record,
        plan=plan,
    )


def open_store(case, **kwargs):
    return PlanStore(
        case["ledger"],
        objects_directory=case["artifact_dir"],
        evidence_directory=case["evidence_dir"],
        **kwargs,
    )


def finish_accounting(store):
    store.record_accounting(
        "interrupt",
        dict(
            action="interrupt",
            attempt_id="a1",
            expected_revision=1,
            reason="synthetic interruption",
        ),
    )
    store.record_accounting(
        "settle",
        dict(
            action="settle",
            attempt_id="a1",
            expected_revision=2,
            actual_cost_cents=0,
            receipt_id="zero",
        ),
    )


def next_prepare(case):
    return dict(
        action="prepare",
        attempt_id="a2",
        expected_revision=0,
        campaign_id=case["plan"]["campaign_id"],
        trial_id=case["plan"]["trials"][1]["trial_id"],
        max_cost_cents=0,
        basis_sha256="a" * 64,
    )


@pytest.mark.parametrize("outcome", ["pass", "fail", "incomplete"])
def test_roundtrip_retains_reports_without_completing_or_releasing_budget(case, outcome):
    report = summarize(
        [Check(name, "fail" if outcome == "fail" else "pass") for name in sorted(REQUIRED)]
        if outcome != "incomplete"
        else []
    )
    record = evidence.bind_report(case["binding"], "verify-1", report)
    ref = evidence_objects.publish_evidence(
        case["evidence_dir"], record, case["binding"], "verify-1"
    )
    request = {**case["request"], "evidence_ref": ref}
    with open_store(case) as store:
        before, budget = store.attempts(), store.budget_snapshot(case["plan"]["campaign_id"])
        result = store.record_evidence("report", request)
        assert result["kind"] == "offline_evidence_binding"
        assert store.evidence_bindings() == [result]
        assert store.attempts() == before
        assert store.budget_snapshot(case["plan"]["campaign_id"]) == budget
        assert budget["unknown_cost_count"] == 1 and not budget["execution_enabled"]
        finish_accounting(store)
        dump = list(store._db.iterdump())
        assert store.record_evidence("report", request) == result
        assert list(store._db.iterdump()) == dump
    with open_store(case) as store:
        assert store.evidence_bindings() == [result]
        assert store.attempts()[0]["phase"] == "interrupted"
        assert (
            evidence_objects.read_evidence(case["evidence_dir"], ref, case["binding"], "verify-1")[
                "report"
            ]
            == report
        )
    request["evidence_ref"]["kind"] = "changed"
    result["request"]["attempt_id"] = "changed"
    with open_store(case) as store:
        assert store.evidence_bindings()[0]["request"]["attempt_id"] == "a1"
    with pytest.raises(StoreError, match="evidence_directory"):
        PlanStore(case["ledger"], objects_directory=case["artifact_dir"])


@pytest.mark.parametrize(
    "key,value",
    [
        ("attempt_id", "missing"),
        ("expected_revision", True),
        ("expected_revision", 2),
        ("artifact_binding_sha256", "f" * 64),
        ("verification_request_id", "other-request"),
        ("verification_request_id", ""),
        ("evidence_ref", {}),
        ("extra", "field"),
    ],
)
def test_invalid_requests_rollback(case, key, value):
    with open_store(case) as store:
        dump = list(store._db.iterdump())
        with pytest.raises(ValueError):
            store.record_evidence("bad", {**case["request"], key: value})
        assert list(store._db.iterdump()) == dump


def test_stale_new_evidence_rejected_but_exact_duplicate_allowed(case):
    with open_store(case) as store:
        finish_accounting(store)
        with pytest.raises(StoreError, match="Stale"):
            store.record_evidence("late", case["request"])
        assert store.evidence_bindings() == []


@pytest.mark.parametrize("change", ["event", "request", "attempt", "reference", "bool_revision"])
def test_conflicts_preserve_original_and_persist_stop(case, change):
    with open_store(case) as store:
        result = store.record_evidence("report", case["request"])
        request = copy.deepcopy(case["request"])
        event = "report"
        if change == "event":
            event = "other-event"
        elif change == "request":
            request["verification_request_id"] = "other-request"
        elif change == "attempt":
            event = "other-event"
            request["attempt_id"] = "a2"  # Collides solely on verification request.
        elif change == "reference":
            request["evidence_ref"]["evidence_sha256"] = "0" * 64
        else:
            request["expected_revision"] = True
        with pytest.raises(StoreError, match="Conflicting"):
            store.record_evidence(event, request)
        assert store.evidence_bindings() == [result]
        finish_accounting(store)
    with open_store(case) as store:
        assert store.budget_snapshot(case["plan"]["campaign_id"])["blocked"]
        with pytest.raises(StoreError, match="blocks preparation"):
            store.record_accounting("next", next_prepare(case))
        assert len(store.attempts()) == 1


@pytest.mark.parametrize(
    "which,mode", [(w, m) for w in ("evidence", "artifact") for m in ("missing", "changed")]
)
def test_corrupt_objects_block_read_reopen_and_new_preparation(case, which, mode):
    with open_store(case) as store:
        store.record_evidence("report", case["request"])
        finish_accounting(store)
        ref = (
            case["request"]["evidence_ref"]
            if which == "evidence"
            else case["binding"]["request"]["artifact_ref"]
        )
        directory = case["evidence_dir"] if which == "evidence" else case["artifact_dir"]
        path = directory / (ref["object_sha256"] + ".json")
        if mode == "missing":
            path.unlink()
        else:
            path.write_bytes(b"X" + path.read_bytes()[1:])
        for call in (
            store.evidence_bindings,
            lambda: store.budget_snapshot(case["plan"]["campaign_id"]),
            lambda: store.record_evidence("report", case["request"]),
            lambda: store.record_accounting("next", next_prepare(case)),
        ):
            with pytest.raises(StoreError):
                call()
        assert len(store.attempts()) == 1
    with pytest.raises(StoreError):
        open_store(case)


def test_sql_and_sync_failure_roll_back_entire_linkage(case, monkeypatch):
    with open_store(case) as store:
        before = list(store._db.iterdump())

        def fail(*args):
            raise OSError("injected sync failure")

        with monkeypatch.context() as patch:
            patch.setattr(os, "fsync", fail)
            with pytest.raises(OSError, match="injected"):
                store.record_evidence("report", case["request"])
        assert list(store._db.iterdump()) == before
        store._db.execute("""CREATE TRIGGER fail_evidence BEFORE INSERT ON evidence_bindings
            BEGIN SELECT RAISE(ABORT, 'injected SQL failure'); END""")
        with pytest.raises(sqlite3.IntegrityError, match="injected"):
            store.record_evidence("report", case["request"])
        assert store.evidence_bindings() == []
        store._db.execute("DROP TRIGGER fail_evidence")
        assert list(store._db.iterdump()) == before
        assert store.record_evidence("report", case["request"])


def test_immutable_rows_and_rehashed_projection_mismatch(case):
    with open_store(case) as store:
        result = store.record_evidence("report", case["request"])
        for sql in ("DELETE FROM evidence_bindings", "UPDATE evidence_bindings SET revision=2"):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                store._db.execute(sql)
        store._db.execute("DROP TRIGGER evidence_bindings_no_update")
        result["request"]["verification_request_id"] = "forged"
        result["binding_sha256"] = digest(
            {k: v for k, v in result.items() if k != "binding_sha256"}
        )
        store._db.execute(
            "UPDATE evidence_bindings SET record_json=?",
            (json.dumps(result, sort_keys=True, separators=(",", ":")),),
        )
        with pytest.raises(StoreError):
            store.evidence_bindings()


def make_v3(case):
    assert digest(V3_SCHEMA) == "b4ad26ef24500ea46a364e6890319a7524c21746088896ea5cca983ef95555ed"
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        db.execute("DROP TABLE controller_generations")
        db.execute("DROP TABLE verification_intents")
        db.execute("DROP TABLE evidence_bindings")
        db.execute("PRAGMA user_version=3")
        schema = dict(
            db.execute(
                "SELECT name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
            ).fetchall()
        )
        assert schema == V3_SCHEMA
        return list(db.iterdump())


def test_v3_migration_requires_opt_in_and_preserves_exact_records(case):
    before = make_v3(case)
    with pytest.raises(StoreError, match="explicit"):
        open_store(case)
    with open_store(case, migrate=True) as store:
        assert store._db.execute("PRAGMA user_version").fetchone()[0] == VERSION
        assert [
            line
            for line in store._db.iterdump()
            if "evidence_bindings" not in line
            and "verification_intents" not in line
            and "controller_generations" not in line
        ] == before
        seed_intent(case, store)
        assert store.record_evidence("report", case["request"])


def test_failed_migration_leaves_v3_intact(case, monkeypatch):
    before = make_v3(case)
    original = sqlite3.connect

    class FailingConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith("CREATE TRIGGER evidence_bindings"):
                raise sqlite3.OperationalError("injected migration failure")
            return super().execute(sql, *args)

    with monkeypatch.context() as patch:
        patch.setattr(
            sqlite3, "connect", lambda *a, **kw: original(*a, factory=FailingConnection, **kw)
        )
        with pytest.raises(sqlite3.OperationalError, match="injected"):
            open_store(case, migrate=True)
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 3
        assert list(db.iterdump()) == before


def test_v3_corrupt_artifact_blocks_migration_before_schema_change(case):
    before = make_v3(case)
    ref = case["binding"]["request"]["artifact_ref"]
    (case["artifact_dir"] / (ref["object_sha256"] + ".json")).unlink()
    with pytest.raises(StoreError):
        open_store(case, migrate=True)
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 3
        assert list(db.iterdump()) == before


@pytest.mark.parametrize("operation", ["bind", "migrate"])
@pytest.mark.parametrize("phase", ["before", "after"])
def test_process_death_keeps_schema_or_linkage_atomic(case, operation, phase):
    if operation == "migrate":
        make_v3(case)
    program = """
import json, os, sqlite3, sys
from pathlib import Path
from democratize_security.store import PlanStore
original = sqlite3.connect
class Connection(sqlite3.Connection):
    armed = sys.argv[4] in ('migrate', 'migration')
    def execute(self, sql, *args):
        if self.armed and sql == 'COMMIT' and sys.argv[5] == 'before':
            os._exit(71)
        return super().execute(sql, *args)
sqlite3.connect = lambda *a, **kw: original(*a, factory=Connection, **kw)
store = PlanStore(Path(sys.argv[1]), objects_directory=Path(sys.argv[2]),
    evidence_directory=Path(sys.argv[3]), migrate=sys.argv[4] == 'migrate')
store._db.armed = True
if sys.argv[4] == 'bind':
    store.record_evidence('report', json.loads(sys.argv[6]))
os._exit(72)
"""
    run = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(case["ledger"]),
            str(case["artifact_dir"]),
            str(case["evidence_dir"]),
            operation,
            phase,
            json.dumps(case["request"]),
        ],
        timeout=10,
        check=False,
    )
    assert run.returncode == (71 if phase == "before" else 72)
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == (
            3 if operation == "migrate" and phase == "before" else VERSION
        )
    with open_store(case, migrate=True) as store:
        assert len(store.evidence_bindings()) == (
            1 if operation == "bind" and phase == "after" else 0
        )
        seed_intent(case, store)
        result = store.record_evidence("report", case["request"])
        assert store.evidence_bindings() == [result]
        assert store.attempts()[0]["revision"] == 1


def test_object_alone_is_not_linked_evidence(case):
    with open_store(case) as store:
        assert list(case["evidence_dir"].iterdir())
        assert store.evidence_bindings() == []
        assert store.attempts()[0]["phase"] == "preparing"


def test_rehashed_foreign_context_cannot_be_linked(case):
    other = copy.deepcopy(case["binding"])
    other["request"]["verifier_sha256"] = "f" * 64
    other["binding_sha256"] = digest({k: v for k, v in other.items() if k != "binding_sha256"})
    record = evidence.bind_report(other, "verify-1", case["record"]["report"])
    ref = evidence_objects.publish_evidence(case["evidence_dir"], record, other, "verify-1")
    with open_store(case) as store:
        with pytest.raises(evidence.EvidenceError):
            store.record_evidence("foreign", {**case["request"], "evidence_ref": ref})
        assert store.evidence_bindings() == []


@pytest.mark.parametrize(
    "column,value",
    [
        ("attempt_id", "a2"),
        ("artifact_event_id", "other"),
        ("verification_request_id", "other"),
        ("revision", 2),
        ("record_json", "{}"),
    ],
)
def test_projection_corruption_detected(case, column, value):
    with open_store(case) as store:
        store.record_evidence("report", case["request"])
        store._db.execute("DROP TRIGGER evidence_bindings_no_update")
        store._db.execute("PRAGMA foreign_keys=OFF")
        store._db.execute(f"UPDATE evidence_bindings SET {column}=?", (value,))
        with pytest.raises(StoreError):
            store.evidence_bindings()


def test_request_size_and_type_rejected_without_writes(case):
    with open_store(case) as store:
        before = list(store._db.iterdump())
        for request in ([], {**case["request"], "extra": "x" * 4096}):
            with pytest.raises(StoreError):
                store.record_evidence("bad", request)
        assert list(store._db.iterdump()) == before


def test_existing_integrity_stop_blocks_new_evidence(case):
    with open_store(case) as store:
        with pytest.raises(StoreError, match="Conflicting"):
            store.record_artifact("artifact", {**case["binding"]["request"], "protocol": "changed"})
        with pytest.raises(StoreError, match="Integrity stop"):
            store.record_evidence("report", case["request"])
        assert store.evidence_bindings() == []
