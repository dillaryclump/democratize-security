import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from democratize_security.contracts import digest, plan
from democratize_security.store import APPLICATION_ID, V1_SCHEMA, PlanStore, StoreError

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def campaign():
    value = json.loads((ROOT / "campaigns/development.example.json").read_text())
    value["limits"]["max_cost_usd_cents"] = 100
    return value


def prepare(campaign, *, index=0, maximum=60):
    planned = plan(campaign)
    return dict(
        action="prepare",
        attempt_id=f"attempt-{index}",
        expected_revision=0,
        campaign_id=planned["campaign_id"],
        trial_id=planned["trials"][index]["trial_id"],
        max_cost_cents=maximum,
        basis_sha256="a" * 64,
    )


def interrupt(*, index=0, revision=1):
    return dict(
        action="interrupt",
        attempt_id=f"attempt-{index}",
        expected_revision=revision,
        reason="synthetic preparation abandoned; no external work was started",
    )


def settle(*, index=0, actual=40, revision=2):
    return dict(
        action="settle",
        attempt_id=f"attempt-{index}",
        expected_revision=revision,
        actual_cost_cents=actual,
        receipt_id=f"synthetic-receipt-{index}",
    )


def test_atomic_reservation_interruption_settlement_and_idempotency(tmp_path, campaign):
    with PlanStore(tmp_path) as store:
        planned = store.import_campaign(campaign)
        cid = planned["campaign_id"]
        prepared = store.record_accounting("reserve", prepare(campaign))
        assert prepared["actual_cost_cents"] is None
        assert store.budget_snapshot(cid)["held_cents"] == 60
        assert store.record_accounting("reserve", prepare(campaign)) == prepared
        stopped = store.record_accounting("stop", interrupt())
        assert stopped["phase"] == "interrupted"
        assert store.budget_snapshot(cid)["unknown_cost_count"] == 1
        assert store.budget_snapshot(cid)["held_cents"] == 60
        paid = store.record_accounting("bill", settle())
        assert paid["actual_cost_cents"] == 40
        assert paid["phase"] == "interrupted"
        assert store.record_accounting("bill", settle()) == paid
        assert store.record_accounting("same-receipt-new-event", settle()) == paid
        assert store._db.execute("SELECT count(*) FROM attempt_events").fetchone()[0] == 3
        budget = store.budget_snapshot(cid)
        assert budget == dict(
            limit_cents=100,
            held_cents=0,
            settled_cents=40,
            available_cents=60,
            unknown_cost_count=0,
            blocked=False,
            overrun=False,
            execution_enabled=False,
        )
        with pytest.raises(StoreError, match="Insufficient"):
            store.record_accounting("too-much", prepare(campaign, index=1, maximum=61))
        store.record_accounting("next", prepare(campaign, index=1, maximum=60))
        assert store.budget_snapshot(cid)["available_cents"] == 0
        assert store.snapshot(cid) == planned
    with PlanStore(tmp_path) as store:
        assert len(store.attempts()) == 2
        assert store.budget_snapshot(cid)["settled_cents"] == 40
        assert store.budget_snapshot(cid)["held_cents"] == 60


def test_unknown_cost_blocks_another_trial_and_campaign(tmp_path, campaign):
    with PlanStore(tmp_path) as store:
        store.import_campaign(campaign)
        other = {**campaign, "name": "another offline campaign"}
        store.import_campaign(other)
        store.record_accounting("reserve", prepare(campaign))
        for value in (prepare(campaign, index=1), prepare(other, index=1)):
            with pytest.raises(StoreError, match="blocks preparation"):
                store.record_accounting("other", value)
        store.record_accounting("stop", interrupt())
        with pytest.raises(StoreError, match="blocks preparation"):
            store.record_accounting("other", prepare(campaign, index=1))
        assert store.attempts()[0]["actual_cost_cents"] is None


def test_stale_revision_and_illegal_transition_change_nothing(tmp_path, campaign):
    with PlanStore(tmp_path) as store:
        store.import_campaign(campaign)
        store.record_accounting("reserve", prepare(campaign))
        before = list(store._db.iterdump())
        for request in (
            interrupt(revision=0),
            settle(revision=1),
            dict(action="completed", attempt_id="attempt-0", expected_revision=1),
        ):
            with pytest.raises(StoreError):
                store.record_accounting("invalid", request)
            assert list(store._db.iterdump()) == before
        store.record_accounting("stop", interrupt())
        with pytest.raises(StoreError, match="terminal"):
            store.record_accounting("stop-again", interrupt(revision=2))


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_cost_cents", True),
        ("max_cost_cents", -1),
        ("max_cost_cents", 1.5),
        ("expected_revision", True),
        ("basis_sha256", "unknown"),
        ("trial_id", "missing"),
    ],
)
def test_invalid_preparation_rolls_back(tmp_path, campaign, field, value):
    with PlanStore(tmp_path) as store:
        store.import_campaign(campaign)
        request = {**prepare(campaign), field: value}
        with pytest.raises(StoreError):
            store.record_accounting("invalid", request)
        assert store.attempts() == []
        assert store._db.execute("SELECT count(*) FROM attempt_events").fetchone()[0] == 0


def test_conflicting_receipt_retains_charge_and_persistent_stop(tmp_path, campaign):
    with PlanStore(tmp_path) as store:
        store.import_campaign(campaign)
        store.record_accounting("reserve", prepare(campaign))
        store.record_accounting("stop", interrupt())
        store.record_accounting("bill", settle())
        with pytest.raises(StoreError, match="Conflicting"):
            store.record_accounting("contradictory-bill", settle(actual=0))
        assert store.attempts()[0]["actual_cost_cents"] == 40
    with PlanStore(tmp_path) as store:
        assert store.budget_snapshot(plan(campaign)["campaign_id"])["blocked"]
        with pytest.raises(StoreError, match="blocks preparation"):
            store.record_accounting("next", prepare(campaign, index=1))


def test_overrun_is_not_clipped_and_blocks_preparation(tmp_path, campaign):
    with PlanStore(tmp_path) as store:
        store.import_campaign(campaign)
        store.record_accounting("reserve", prepare(campaign))
        store.record_accounting("stop", interrupt())
        result = store.record_accounting("bill", settle(actual=120))
        assert result["actual_cost_cents"] == 120
        budget = store.budget_snapshot(plan(campaign)["campaign_id"])
        assert budget["available_cents"] == -20 and budget["overrun"] and budget["blocked"]
        with pytest.raises(StoreError, match="blocks preparation"):
            store.record_accounting("next", prepare(campaign, index=1, maximum=0))


@pytest.mark.parametrize("action", ["prepare", "interrupt", "settle"])
def test_event_insert_failure_rolls_back_state_and_funds(tmp_path, campaign, action):
    with PlanStore(tmp_path) as store:
        store.import_campaign(campaign)
        if action != "prepare":
            store.record_accounting("reserve", prepare(campaign))
        if action == "settle":
            store.record_accounting("stop", interrupt())
        before = store.attempts()
        budget = store.budget_snapshot(plan(campaign)["campaign_id"])
        store._db.execute("""CREATE TRIGGER fail_event BEFORE INSERT ON attempt_events
            BEGIN SELECT RAISE(ABORT, 'injected failure'); END""")
        request = {"prepare": prepare(campaign), "interrupt": interrupt(), "settle": settle()}[
            action
        ]
        with pytest.raises(sqlite3.IntegrityError, match="injected"):
            store.record_accounting("failed", request)
        assert store.attempts() == before
        assert store.budget_snapshot(plan(campaign)["campaign_id"]) == budget
        store._db.execute("DROP TRIGGER fail_event")


@pytest.mark.parametrize("action", ["prepare", "interrupt", "settle"])
@pytest.mark.parametrize("phase", ["before", "after"])
def test_actual_process_crash_keeps_state_event_and_money_together(
    tmp_path, campaign, action, phase
):
    with PlanStore(tmp_path) as store:
        store.import_campaign(campaign)
        if action != "prepare":
            store.record_accounting("reserve", prepare(campaign))
        if action == "settle":
            store.record_accounting("stop", interrupt())
        before = store.attempts()
    request = {"prepare": prepare(campaign), "interrupt": interrupt(), "settle": settle()}[action]
    program = """
import json, os, sys
from pathlib import Path
from democratize_security.store import PlanStore
store = PlanStore(Path(sys.argv[1]))
if sys.argv[2] == 'before':
    store._db.set_trace_callback(lambda sql: os._exit(71) if sql == 'COMMIT' else None)
store.record_accounting('crash-event', json.loads(sys.argv[3]))
os._exit(72)
"""
    run = subprocess.run(
        [sys.executable, "-c", program, str(tmp_path), phase, json.dumps(request)],
        timeout=10,
        check=False,
    )
    assert run.returncode == (71 if phase == "before" else 72)
    with PlanStore(tmp_path) as store:
        if phase == "before":
            assert store.attempts() == before
        else:
            assert store.attempts() != before
        result = store.record_accounting("crash-event", request)
        assert store.attempts() == [result]
        assert (
            store._db.execute(
                "SELECT count(*) FROM attempt_events WHERE event_id = 'crash-event'"
            ).fetchone()[0]
            == 1
        )
        budget = store.budget_snapshot(plan(campaign)["campaign_id"])
        assert budget["held_cents"] == (0 if action == "settle" else 60)
        assert budget["settled_cents"] == (40 if action == "settle" else 0)


def create_v1(directory, campaign):
    # Pin the previously published v1 schema, so accidental edits cannot make
    # this fixture silently track the new implementation.
    assert digest(V1_SCHEMA) == "38f071459cfe676465908909f88ed17fa0f0bacec7e836a7c2f9c3015b878476"
    planned = plan(campaign)

    def encode(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    with sqlite3.connect(directory / "ledger.sqlite3") as db:
        for sql in V1_SCHEMA.values():
            db.execute(sql)
        db.execute(f"PRAGMA application_id={APPLICATION_ID}")
        db.execute("PRAGMA user_version=1")
        db.execute("INSERT INTO campaigns VALUES (?, ?)", (planned["campaign_id"], encode(planned)))
        for ordinal, trial in enumerate(planned["trials"]):
            tid = trial["trial_id"]
            db.execute(
                "INSERT INTO trials VALUES (?, ?, ?, ?)",
                (tid, planned["campaign_id"], ordinal, encode(trial)),
            )
            eid = digest(dict(trial_id=tid, sequence=0, kind="planned"))
            db.execute(
                "INSERT INTO events VALUES (?, ?, 0, 'planned', ?, ?)",
                (eid, tid, "2026-10-15T00:00:00+00:00", encode(trial)),
            )
    return planned


def old_records(directory):
    with sqlite3.connect(directory / "ledger.sqlite3") as db:
        return {
            table: db.execute(f"SELECT * FROM {table}").fetchall()
            for table in ("campaigns", "trials", "events")
        }


def test_explicit_migration_preserves_v1_records(tmp_path, campaign):
    planned = create_v1(tmp_path, campaign)
    before = old_records(tmp_path)
    with pytest.raises(StoreError, match="explicit"):
        PlanStore(tmp_path)
    assert old_records(tmp_path) == before
    with PlanStore(tmp_path, migrate=True) as store:
        assert store.snapshot(planned["campaign_id"]) == planned
        assert store.attempts() == []
        assert store._db.execute("PRAGMA user_version").fetchone()[0] == 2
        store.record_accounting("reserve", prepare(campaign))
    assert old_records(tmp_path) == before
    with PlanStore(tmp_path) as store:
        assert len(store.attempts()) == 1


@pytest.mark.parametrize("phase", ["before", "after"])
def test_crash_during_migration_is_all_or_nothing(tmp_path, campaign, phase):
    create_v1(tmp_path, campaign)
    before = old_records(tmp_path)
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
        [sys.executable, "-c", program, str(tmp_path), phase], timeout=10, check=False
    )
    assert run.returncode == (71 if phase == "before" else 72)
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == (1 if phase == "before" else 2)
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE name = 'attempts'").fetchone()
        assert bool(exists) == (phase == "after")
    assert old_records(tmp_path) == before
    with PlanStore(tmp_path, migrate=True) as store:
        assert store.attempts() == []


def test_projection_corruption_refuses_reopen(tmp_path, campaign):
    with PlanStore(tmp_path) as store:
        store.import_campaign(campaign)
        store.record_accounting("reserve", prepare(campaign))
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            store._db.execute("DELETE FROM attempt_events")
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        db.execute("UPDATE attempts SET state_json = '{}'")
    with pytest.raises(StoreError, match="projection"):
        PlanStore(tmp_path)


def test_old_request_replay_cannot_restore_a_hold_after_settlement(tmp_path, campaign):
    with PlanStore(tmp_path) as store:
        store.import_campaign(campaign)
        prepared = store.record_accounting("reserve", prepare(campaign))
        interrupted = store.record_accounting("stop", interrupt())
        settled = store.record_accounting("bill", settle())
    with PlanStore(tmp_path) as store:
        before = list(store._db.iterdump())
        assert store.record_accounting("reserve", prepare(campaign)) == prepared
        assert store.record_accounting("stop", interrupt()) == interrupted
        assert store.attempts() == [settled]
        assert list(store._db.iterdump()) == before
        budget = store.budget_snapshot(plan(campaign)["campaign_id"])
        assert budget["held_cents"] == 0
        assert budget["settled_cents"] == 40
        assert not budget["blocked"]


def test_migration_sql_failure_rolls_back_schema_and_releases_lock(tmp_path, campaign, monkeypatch):
    planned = create_v1(tmp_path, campaign)
    before = old_records(tmp_path)
    original_connect = sqlite3.connect

    class FailingConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith("CREATE TABLE attempt_events"):
                raise sqlite3.OperationalError("injected migration failure")
            return super().execute(sql, *args)

    def connect(*args, **kwargs):
        return original_connect(*args, factory=FailingConnection, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, "connect", connect)
        with pytest.raises(sqlite3.OperationalError, match="injected migration failure"):
            PlanStore(tmp_path, migrate=True)
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name = 'attempts'").fetchone()
    assert old_records(tmp_path) == before
    with PlanStore(tmp_path, migrate=True) as store:
        assert store.snapshot(planned["campaign_id"]) == planned
        assert store.attempts() == []


def test_corrupt_legacy_plan_is_rejected_before_migration(tmp_path, campaign):
    create_v1(tmp_path, campaign)
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        db.execute("DROP TRIGGER events_no_delete")
        db.execute("DELETE FROM events")
        db.execute(V1_SCHEMA["events_no_delete"])
    before = old_records(tmp_path)
    with pytest.raises(StoreError, match="event coverage"):
        PlanStore(tmp_path, migrate=True)
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name = 'attempts'").fetchone()
    assert old_records(tmp_path) == before
