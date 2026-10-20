"""Controller ownership survives crashes; stale and forked writers have no effects."""

import copy
import fcntl
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from democratize_security import artifacts, evidence, evidence_objects, objects
from democratize_security.contracts import digest
from democratize_security.store import V5_SCHEMA, VERSION, PlanStore, StoreError
from democratize_security.verification.report import REQUIRED, Check, summarize

ROOT = Path(__file__).resolve().parents[1]
STAGES = ("imported", "prepared", "artifact", "intent", "evidence", "interrupted", "settled")


def seeded(tmp_path, stage="settled"):
    ledger, artifact_dir, evidence_dir, source = [
        tmp_path / name for name in ("ledger", "artifacts", "evidence", "source")
    ]
    for directory in (ledger, artifact_dir, evidence_dir, source):
        directory.mkdir()
    (source / "app.py").write_text("# Synthetic ownership test\n")
    ref = objects.publish_artifact(artifact_dir, artifacts.seal(source, ["app.py"]))
    campaign = json.loads((ROOT / "campaigns/development.example.json").read_text())
    kwargs = dict(objects_directory=artifact_dir, evidence_directory=evidence_dir)
    requests, results = {}, {}
    with PlanStore(ledger, **kwargs) as store:
        planned = store.import_campaign(campaign)
        trial = planned["trials"][0]
        context = dict(
            attempt_id="a1", campaign_id=planned["campaign_id"], trial_id=trial["trial_id"]
        )
        requests["prepare"] = dict(
            action="prepare",
            **context,
            expected_revision=0,
            max_cost_cents=0,
            basis_sha256="a" * 64,
        )
        requests["artifact"] = dict(
            **context,
            expected_revision=1,
            task_revision=trial["task_revision"],
            verifier_sha256="b" * 64,
            protocol="synthetic-reference-v3",
            artifact_ref=ref,
        )
        if STAGES.index(stage) >= 1:
            results["prepare"] = store.record_accounting("prepare", requests["prepare"])
        if STAGES.index(stage) >= 2:
            results["artifact"] = store.record_artifact("artifact", requests["artifact"])
            requests["intent"] = dict(
                attempt_id="a1",
                expected_revision=1,
                artifact_binding_sha256=results["artifact"]["binding_sha256"],
                verification_request_id="verify-1",
            )
        if STAGES.index(stage) >= 3:
            results["intent"] = store.record_verification_intent("intent", requests["intent"])
            report = summarize([Check(name, "pass") for name in sorted(REQUIRED)])
            record = evidence.bind_report(results["artifact"], "verify-1", report)
            ref = evidence_objects.publish_evidence(
                evidence_dir, record, results["artifact"], "verify-1"
            )
            requests["evidence"] = dict(
                **requests["intent"],
                verification_intent_sha256=results["intent"]["intent_sha256"],
                evidence_ref=ref,
            )
        if STAGES.index(stage) >= 4:
            results["evidence"] = store.record_evidence("evidence", requests["evidence"])
        requests["interrupt"] = dict(
            action="interrupt", attempt_id="a1", expected_revision=1, reason="Synthetic stop"
        )
        requests["settle"] = dict(
            action="settle",
            attempt_id="a1",
            expected_revision=2,
            actual_cost_cents=0,
            receipt_id="receipt-1",
        )
        if STAGES.index(stage) >= 5:
            results["interrupt"] = store.record_accounting("interrupt", requests["interrupt"])
        if STAGES.index(stage) >= 6:
            results["settle"] = store.record_accounting("settle", requests["settle"])
    return ledger, kwargs, campaign, requests, results


# Each case reaches a different mutation/idempotency/conflict path with a valid
# owning handle. The stale version must fail before even returning an exact retry.
WRITERS = [
    ("imported", "import", "exact"),
    ("imported", "import", "new"),
    ("imported", "prepare", "new"),
    ("prepared", "interrupt", "new"),
    ("interrupted", "settle", "new"),
    ("settled", "prepare", "exact"),
    ("settled", "settle", "receipt"),
    ("settled", "prepare", "conflict"),
    ("settled", "settle", "conflict-receipt"),
    ("prepared", "artifact", "new"),
    ("artifact", "artifact", "exact"),
    ("artifact", "artifact", "conflict"),
    ("artifact", "artifact", "other-event"),
    ("artifact", "intent", "new"),
    ("intent", "intent", "exact"),
    ("intent", "intent", "conflict"),
    ("intent", "intent", "other-event"),
    ("intent", "intent", "request-conflict"),
    ("intent", "evidence", "new"),
    ("evidence", "evidence", "exact"),
    ("evidence", "evidence", "conflict"),
    ("evidence", "evidence", "other-event"),
    ("evidence", "evidence", "request-conflict"),
]


def writer_call(store, campaign, requests, action, variant):
    if action == "import":
        campaign = copy.deepcopy(campaign)
        if variant == "new":
            campaign["name"] += " other"
        return lambda: store.import_campaign(campaign)
    request = copy.deepcopy(requests[action])
    event_id = action
    if variant in ("other-event", "receipt", "conflict-receipt"):
        event_id = "other-event"
    if variant in ("conflict", "conflict-receipt"):
        # Same persistent identity, changed canonical payload.
        request["unexpected"] = "conflicting value"
    if variant == "request-conflict":
        request["attempt_id"] = "different-attempt"
        event_id = "different-event"
    method = {
        "prepare": store.record_accounting,
        "interrupt": store.record_accounting,
        "settle": store.record_accounting,
        "artifact": store.record_artifact,
        "intent": store.record_verification_intent,
        "evidence": store.record_evidence,
    }[action]
    return lambda: method(event_id, request)


@pytest.mark.parametrize("stage,action,variant", WRITERS)
def test_every_stale_writer_rejects_before_effects(tmp_path, monkeypatch, stage, action, variant):
    ledger, kwargs, campaign, requests, _ = seeded(tmp_path, stage)
    with PlanStore(ledger, **kwargs) as stale:
        previous = stale.controller_generation
        # Simulate prohibited lock loss without closing the old DB connection.
        fcntl.flock(stale._lock_fd, fcntl.LOCK_UN)
        with PlanStore(ledger, **kwargs) as current:
            assert current.controller_generation == previous + 1
            before = list(current._db.iterdump())
            before_files = {p: p.read_bytes() for d in kwargs.values() for p in d.iterdir()}

            def forbidden(*args, **kwargs):
                pytest.fail("Stale writer reached object durability publication")

            monkeypatch.setattr(objects, "publish_artifact", forbidden)
            monkeypatch.setattr(evidence_objects, "publish_evidence", forbidden)
            with pytest.raises(StoreError, match="Stale controller generation"):
                writer_call(stale, campaign, requests, action, variant)()
            assert not stale._db.in_transaction
            assert list(current._db.iterdump()) == before
            assert {p: p.read_bytes() for d in kwargs.values() for p in d.iterdir()} == before_files
            with pytest.raises(StoreError, match="Stale controller generation"):
                _ = stale.controller_generation
        # A closed successor must not make the obsolete handle usable again.
        with pytest.raises(StoreError, match="Stale controller generation"):
            writer_call(stale, campaign, requests, action, variant)()


@pytest.mark.parametrize("stage,action,variant", WRITERS)
def test_inherited_fork_handle_rejects_every_writer(tmp_path, stage, action, variant):
    ledger, kwargs, campaign, requests, _ = seeded(tmp_path, stage)
    with PlanStore(ledger, **kwargs) as store:
        before = list(store._db.iterdump())
        child = os.fork()
        if child == 0:
            try:
                writer_call(store, campaign, requests, action, variant)()
            except StoreError as error:
                os._exit(0 if "another process" in str(error) else 92)
            except BaseException:
                os._exit(93)
            os._exit(94)
        assert os.waitpid(child, 0)[1] == 0
        assert list(store._db.iterdump()) == before
        assert store.controller_generation >= 1


def test_readonly_generation_accessor_and_monotonic_reopen(tmp_path):
    with PlanStore(tmp_path) as first:
        assert first.controller_generation == 1
        with pytest.raises(AttributeError):
            first.controller_generation = 88
        assert first._db.execute("PRAGMA synchronous").fetchone() == (2,)
    with pytest.raises(StoreError, match="closed"):
        _ = first.controller_generation
    for expected in range(2, 6):
        with PlanStore(tmp_path) as store:
            assert store.controller_generation == expected
            assert store._db.execute(
                "SELECT * FROM controller_generations ORDER BY generation"
            ).fetchall() == [(i, os.getpid()) for i in range(1, expected + 1)]


@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
def test_generation_history_is_immutable(tmp_path, operation):
    with PlanStore(tmp_path) as store:
        sql = (
            "UPDATE controller_generations SET process_id=1"
            if operation == "UPDATE"
            else "DELETE FROM controller_generations"
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable controller generation"):
            store._db.execute(sql)
        assert store.controller_generation == 1


@pytest.mark.parametrize("defect", ["gap", "invalid_pid", "schema"])
def test_corrupt_generation_history_refuses_reopen_without_allocation(tmp_path, defect):
    with PlanStore(tmp_path):
        pass
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        if defect == "schema":
            db.execute("DROP TRIGGER controller_generations_no_update")
        elif defect == "gap":
            db.execute("INSERT INTO controller_generations VALUES (3, 1)")
        else:
            db.execute("INSERT INTO controller_generations VALUES (2, 'not-an-integer')")
        before = list(db.iterdump())
    for _ in range(2):
        with pytest.raises(StoreError, match="generation|schema"):
            PlanStore(tmp_path)
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        assert list(db.iterdump()) == before


def make_v5(ledger):
    # The pinned old schema cannot contain any ownership history.
    assert digest(V5_SCHEMA) == "83326229299be077b7f4ce08c4b790ac7ed635d88ba9cdb9682efaa51e16a337"
    with sqlite3.connect(ledger / "ledger.sqlite3") as db:
        db.execute("DROP TABLE runtime_results")
        db.execute("DROP TABLE restore_reconciliations")
        db.execute("DROP TABLE restore_fences")
        db.execute("DROP TABLE controller_generations")
        db.execute("PRAGMA user_version=5")
        assert (
            dict(
                db.execute(
                    "SELECT name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
                ).fetchall()
            )
            == V5_SCHEMA
        )
        return list(db.iterdump())


def test_v5_migration_requires_opt_in_and_preserves_every_historical_byte(tmp_path):
    ledger, kwargs, campaign, requests, results = seeded(tmp_path)
    before = make_v5(ledger)
    with pytest.raises(StoreError, match="Version 5 requires explicit"):
        PlanStore(ledger, **kwargs)
    with sqlite3.connect(ledger / "ledger.sqlite3") as db:
        assert list(db.iterdump()) == before
    with PlanStore(ledger, migrate=True, **kwargs) as store:
        assert store.controller_generation == 1
        assert store._db.execute("PRAGMA user_version").fetchone() == (VERSION,)
        assert [
            line
            for line in store._db.iterdump()
            if all(
                name not in line
                for name in (
                    "controller_generations",
                    "runtime_results",
                    "restore_fences",
                    "restore_reconciliations",
                )
            )
        ] == before
        before = list(store._db.iterdump())
        assert store.import_campaign(campaign)
        for action in requests:
            assert writer_call(store, campaign, requests, action, "exact")() == results[action]
        assert list(store._db.iterdump()) == before


@pytest.mark.parametrize("defect", ["plan", "accounting", "artifact", "intent", "evidence"])
def test_corrupt_v5_data_blocks_migration_before_schema_change(tmp_path, defect):
    ledger, kwargs, _, requests, _ = seeded(tmp_path)
    make_v5(ledger)
    with sqlite3.connect(ledger / "ledger.sqlite3") as db:
        if defect in ("plan", "accounting", "intent"):
            table, column = {
                "plan": ("campaigns", "plan_json"),
                "accounting": ("attempt_events", "state_json"),
                "intent": ("verification_intents", "record_json"),
            }[defect]
            trigger = f"{table}_no_update"
            sql = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (trigger,)).fetchone()[0]
            db.execute(f"DROP TRIGGER {trigger}")
            db.execute(f"UPDATE {table} SET {column}='{{}}'")
            db.execute(sql)
        else:
            ref = requests[defect]["artifact_ref" if defect == "artifact" else "evidence_ref"]
            directory = kwargs[
                "objects_directory" if defect == "artifact" else "evidence_directory"
            ]
            (directory / (ref["object_sha256"] + ".json")).unlink()
        before = list(db.iterdump())
    with pytest.raises(StoreError):
        PlanStore(ledger, migrate=True, **kwargs)
    with sqlite3.connect(ledger / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone() == (5,)
        assert list(db.iterdump()) == before


@pytest.mark.parametrize(
    "action", ["prepare", "interrupt", "settle", "artifact", "intent", "evidence"]
)
def test_exact_and_conflicting_retries_are_deliberate_across_generations(tmp_path, action):
    ledger, kwargs, campaign, requests, results = seeded(tmp_path)
    with PlanStore(ledger, **kwargs) as first:
        generation = first.controller_generation
        before = list(first._db.iterdump())
        assert writer_call(first, campaign, requests, action, "exact")() == results[action]
        assert list(first._db.iterdump()) == before
    with PlanStore(ledger, **kwargs) as successor:
        assert successor.controller_generation == generation + 1
        before = list(successor._db.iterdump())
        assert writer_call(successor, campaign, requests, action, "exact")() == results[action]
        assert list(successor._db.iterdump()) == before
        with pytest.raises(StoreError, match="Conflicting"):
            writer_call(successor, campaign, requests, action, "conflict")()
        assert successor._db.execute("SELECT * FROM accounting_stops").fetchall() == [
            (action, "conflicting_identity")
        ]
        # Historical results and reservations survive the stop without rewriting.
        assert writer_call(successor, campaign, requests, action, "exact")() == results[action]
        assert successor.attempts()[0]["actual_cost_cents"] == 0
    with PlanStore(ledger, **kwargs) as reopened:
        assert reopened._db.execute("SELECT * FROM accounting_stops").fetchall() == [
            (action, "conflicting_identity")
        ]


@pytest.mark.parametrize("phase", ["before_insert", "before_commit", "after_commit", "returned"])
def test_crash_allocation_never_reuses_a_committed_generation(tmp_path, phase):
    with PlanStore(tmp_path) as store:
        assert store.controller_generation == 1
    program = """
import os, sqlite3, sys
from pathlib import Path
from democratize_security.store import PlanStore
original = sqlite3.connect
class Connection(sqlite3.Connection):
    def execute(self, sql, *args):
        if sql.startswith('INSERT INTO controller_generations') and sys.argv[2] == 'before_insert':
            os._exit(71)
        if sql == 'COMMIT' and sys.argv[2] == 'before_commit':
            os._exit(72)
        result = super().execute(sql, *args)
        if sql == 'COMMIT' and sys.argv[2] == 'after_commit':
            os._exit(73)
        return result
sqlite3.connect = lambda *a, **kw: original(*a, factory=Connection, **kw)
store = PlanStore(Path(sys.argv[1]))
assert store.controller_generation == 2
os._exit(74)
"""
    run = subprocess.run(
        [sys.executable, "-c", program, str(tmp_path), phase], timeout=10, check=False
    )
    assert (
        run.returncode
        == ["before_insert", "before_commit", "after_commit", "returned"].index(phase) + 71
    )
    committed = phase in ("after_commit", "returned")
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        assert db.execute(
            "SELECT generation FROM controller_generations ORDER BY generation"
        ).fetchall() == ([(1,), (2,)] if committed else [(1,)])
    with PlanStore(tmp_path) as store:
        assert store.controller_generation == (3 if committed else 2)


@pytest.mark.parametrize("point", ["insert", "before_commit", "after_commit"])
def test_allocation_sql_failure_releases_lock_and_preserves_durable_tip(
    tmp_path, monkeypatch, point
):
    with PlanStore(tmp_path):
        pass
    original = sqlite3.connect

    class FailingConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            fail = (
                sql.startswith("INSERT INTO controller_generations")
                if point == "insert"
                else sql == "COMMIT"
            )
            if fail and point != "after_commit":
                raise sqlite3.OperationalError("injected allocation failure")
            result = super().execute(sql, *args)
            if fail:
                raise sqlite3.OperationalError("injected allocation acknowledgement failure")
            return result

    with monkeypatch.context() as patch:
        patch.setattr(
            sqlite3, "connect", lambda *a, **kw: original(*a, factory=FailingConnection, **kw)
        )
        with pytest.raises(sqlite3.OperationalError, match="injected allocation"):
            PlanStore(tmp_path)
    with PlanStore(tmp_path) as store:
        assert store.controller_generation == (3 if point == "after_commit" else 2)


@pytest.mark.parametrize("phase", ["before", "after"])
def test_v5_migration_crash_is_atomic_and_allocation_is_separate(tmp_path, phase):
    ledger, kwargs, _, _, _ = seeded(tmp_path)
    before = make_v5(ledger)
    program = """
import os, sqlite3, sys
from pathlib import Path
from democratize_security.store import PlanStore
original = sqlite3.connect
class Connection(sqlite3.Connection):
    def execute(self, sql, *args):
        if sql == 'COMMIT' and sys.argv[4] == 'before':
            os._exit(71)
        result = super().execute(sql, *args)
        if sql == 'COMMIT':
            os._exit(72)
        return result
sqlite3.connect = lambda *a, **kw: original(*a, factory=Connection, **kw)
PlanStore(Path(sys.argv[1]), objects_directory=Path(sys.argv[2]),
          evidence_directory=Path(sys.argv[3]), migrate=True)
"""
    run = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(ledger),
            str(kwargs["objects_directory"]),
            str(kwargs["evidence_directory"]),
            phase,
        ],
        timeout=10,
        check=False,
    )
    assert run.returncode == (71 if phase == "before" else 72)
    with sqlite3.connect(ledger / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone() == (
            5 if phase == "before" else VERSION,
        )
        assert [
            line
            for line in db.iterdump()
            if all(
                name not in line
                for name in (
                    "controller_generations",
                    "runtime_results",
                    "restore_fences",
                    "restore_reconciliations",
                )
            )
        ] == before
    with PlanStore(ledger, migrate=True, **kwargs) as store:
        assert store.controller_generation == 1


def test_fence_runs_inside_write_transaction_before_returning_an_exact_retry(tmp_path, monkeypatch):
    ledger, kwargs, campaign, _, _ = seeded(tmp_path)
    with PlanStore(ledger, **kwargs) as store:
        original_tip = store._generation_tip
        observed = []

        def checked_tip():
            observed.append(store._db.in_transaction)
            return original_tip()

        monkeypatch.setattr(store, "_generation_tip", checked_tip)
        assert store.import_campaign(campaign)
        assert observed == [True]


@pytest.mark.parametrize("point", ["table", "trigger", "version", "commit"])
def test_v5_migration_sql_failure_keeps_old_schema_and_records(tmp_path, monkeypatch, point):
    ledger, kwargs, _, _, _ = seeded(tmp_path)
    before = make_v5(ledger)
    original = sqlite3.connect
    targets = {
        "table": "CREATE TABLE controller_generations",
        "trigger": "CREATE TRIGGER controller_generations",
        "version": f"PRAGMA user_version={VERSION}",
        "commit": "COMMIT",
    }

    class FailingConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith(targets[point]):
                raise sqlite3.OperationalError("injected v5 migration failure")
            return super().execute(sql, *args)

    with monkeypatch.context() as patch:
        patch.setattr(
            sqlite3, "connect", lambda *a, **kw: original(*a, factory=FailingConnection, **kw)
        )
        with pytest.raises(sqlite3.OperationalError, match="injected v5 migration"):
            PlanStore(ledger, migrate=True, **kwargs)
    with sqlite3.connect(ledger / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone() == (5,)
        assert list(db.iterdump()) == before
    with PlanStore(ledger, migrate=True, **kwargs) as store:
        assert store.controller_generation == 1


def test_fresh_schema_crash_before_allocation_is_reopenable(tmp_path):
    program = """
import os, sqlite3, sys
from pathlib import Path
from democratize_security.store import PlanStore
original = sqlite3.connect
class Connection(sqlite3.Connection):
    def execute(self, sql, *args):
        result = super().execute(sql, *args)
        if sql == 'COMMIT':
            os._exit(71)
        return result
sqlite3.connect = lambda *a, **kw: original(*a, factory=Connection, **kw)
PlanStore(Path(sys.argv[1]))
"""
    run = subprocess.run([sys.executable, "-c", program, str(tmp_path)], timeout=10, check=False)
    assert run.returncode == 71
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        assert db.execute("SELECT * FROM controller_generations").fetchall() == []
    with PlanStore(tmp_path) as store:
        assert store.controller_generation == 1


def test_lock_contention_never_allocates_a_generation(tmp_path):
    program = """
import sys
from pathlib import Path
from democratize_security.store import PlanStore, StoreError
try:
    PlanStore(Path(sys.argv[1]))
except StoreError as error:
    sys.exit(71 if 'already owned' in str(error) else 72)
sys.exit(73)
"""
    with PlanStore(tmp_path) as store:
        run = subprocess.run(
            [sys.executable, "-c", program, str(tmp_path)], timeout=10, check=False
        )
        assert run.returncode == 71
        assert store._db.execute("SELECT generation FROM controller_generations").fetchall() == [
            (1,)
        ]
    with PlanStore(tmp_path) as store:
        assert store.controller_generation == 2
