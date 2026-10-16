import copy
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from democratize_security.contracts import plan
from democratize_security.store import PlanStore, StoreError

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def campaign():
    return json.loads((ROOT / "campaigns/development.example.json").read_text())


def test_complete_import_reopen_and_idempotence(tmp_path, campaign):
    expected = plan(campaign)
    with PlanStore(tmp_path) as store:
        assert store.import_campaign(campaign) == expected
        first = store._db.execute("SELECT * FROM events").fetchall()
        assert len(first) == len(expected["trials"]) == 12
        assert store.import_campaign(copy.deepcopy(campaign)) == expected
        assert store._db.execute("SELECT * FROM events").fetchall() == first
        result = store.snapshot(expected["campaign_id"])
        result["trials"].clear()
        assert store.snapshot(expected["campaign_id"]) == expected
    with PlanStore(tmp_path) as reopened:
        assert reopened.snapshot(expected["campaign_id"]) == expected
        assert expected["execution_enabled"] is False
        other = copy.deepcopy(campaign)
        other["name"] += " second campaign"
        assert reopened.import_campaign(other)["campaign_id"] != expected["campaign_id"]


@pytest.mark.parametrize("table", ["campaigns", "trials", "events"])
@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
def test_records_are_immutable(tmp_path, campaign, table, operation):
    with PlanStore(tmp_path) as store:
        store.import_campaign(campaign)
        sql = (
            f"DELETE FROM {table}"
            if operation == "DELETE"
            else {
                "campaigns": "UPDATE campaigns SET plan_json = '{}'",
                "trials": "UPDATE trials SET trial_json = '{}'",
                "events": "UPDATE events SET payload_json = '{}'",
            }[table]
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            store._db.execute(sql)
        assert store.snapshot(plan(campaign)["campaign_id"]) == plan(campaign)


def test_mid_import_error_rolls_back_every_record(tmp_path, campaign):
    with PlanStore(tmp_path) as store:
        store._db.execute("""CREATE TRIGGER fail_import BEFORE INSERT ON trials
            WHEN NEW.ordinal = 2 BEGIN SELECT RAISE(ABORT, 'injected failure'); END""")
        with pytest.raises(sqlite3.IntegrityError, match="injected failure"):
            store.import_campaign(campaign)
        for table in ("campaigns", "trials", "events"):
            assert store._db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
        store._db.execute("DROP TRIGGER fail_import")
        assert store.import_campaign(campaign) == plan(campaign)


@pytest.mark.parametrize("phase", ["before_commit", "after_commit"])
def test_process_death_retains_none_or_all(tmp_path, campaign, phase):
    # os._exit bypasses rollback/close handlers, unlike a Python exception.
    program = """
import json, os, sys
from pathlib import Path
from democratize_security.store import PlanStore
store = PlanStore(Path(sys.argv[1]))
campaign = json.loads(Path(sys.argv[2]).read_text())
if sys.argv[3] == 'before_commit':
    store._db.set_trace_callback(lambda sql: os._exit(71) if sql == 'COMMIT' else None)
store.import_campaign(campaign)
os._exit(72)
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(tmp_path),
            str(ROOT / "campaigns/development.example.json"),
            phase,
        ],
        check=False,
        timeout=10,
    )
    assert result.returncode == (71 if phase == "before_commit" else 72)
    with PlanStore(tmp_path) as store:
        count = store._db.execute("SELECT count(*) FROM campaigns").fetchone()[0]
        assert count == (0 if phase == "before_commit" else 1)
        assert store.import_campaign(campaign) == plan(campaign)
        assert store._db.execute("SELECT count(*) FROM events").fetchone()[0] == 12


def test_other_process_cannot_own_store_and_close_releases_lock(tmp_path):
    program = """
import sys
from pathlib import Path
from democratize_security.store import PlanStore, StoreError
try:
    with PlanStore(Path(sys.argv[1])):
        pass
except StoreError:
    sys.exit(73)
"""

    def probe():
        return subprocess.run(
            [sys.executable, "-c", program, str(tmp_path)], timeout=10, check=False
        ).returncode

    with PlanStore(tmp_path):
        assert probe() == 73
    assert probe() == 0


@pytest.mark.parametrize("defect", ["plan", "trial", "event", "missing_event", "schema"])
def test_corrupt_records_fail_closed(tmp_path, campaign, defect):
    with PlanStore(tmp_path) as store:
        store.import_campaign(campaign)
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        if defect == "schema":
            db.execute("DROP TRIGGER events_no_update")
        else:
            # Simulate privileged disk/owner corruption; restore the guard so
            # content validation, not just the schema check, must detect it.
            table, operation = {
                "plan": ("campaigns", "UPDATE"),
                "trial": ("trials", "UPDATE"),
                "event": ("events", "UPDATE"),
                "missing_event": ("events", "DELETE"),
            }[defect]
            name = f"{table}_no_{operation.lower()}"
            sql = db.execute("SELECT sql FROM sqlite_master WHERE name = ?", (name,)).fetchone()[0]
            db.execute(f"DROP TRIGGER {name}")
            mutation = {
                "plan": "UPDATE campaigns SET plan_json = '{}'",
                "trial": "UPDATE trials SET trial_json = '{}'",
                "event": "UPDATE events SET payload_json = '{}'",
                "missing_event": "DELETE FROM events",
            }[defect]
            db.execute(mutation)
            db.execute(sql)
    with pytest.raises(StoreError):
        PlanStore(tmp_path)


def test_unknown_version_is_not_rewritten_and_failed_open_releases_lock(tmp_path):
    with PlanStore(tmp_path):
        pass
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        db.execute("PRAGMA user_version=999")
    for _ in range(2):
        with pytest.raises(StoreError, match="Unknown ledger version"):
            PlanStore(tmp_path)
    with sqlite3.connect(tmp_path / "ledger.sqlite3") as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 999


def test_invalid_campaign_leaves_no_partial_import(tmp_path, campaign):
    campaign["limits"]["max_trials"] = 1
    with PlanStore(tmp_path) as store:
        with pytest.raises(ValueError):
            store.import_campaign(campaign)
        assert store._db.execute("SELECT count(*) FROM campaigns").fetchone()[0] == 0
    with pytest.raises(StoreError, match="closed"):
        store.snapshot("absent")


def test_oversized_plans_are_rejected_on_import_and_read(tmp_path, campaign, monkeypatch):
    from democratize_security import store as module

    with PlanStore(tmp_path) as store:
        expected = store.import_campaign(campaign)
        monkeypatch.setattr(module, "MAX_PLAN_BYTES", 1)
        with pytest.raises(StoreError, match="byte limit"):
            store.snapshot(expected["campaign_id"])
        with pytest.raises(StoreError, match="byte limit"):
            store.import_campaign(campaign)


@pytest.mark.parametrize("name", ["ledger.lock", "ledger.sqlite3"])
def test_symlink_store_files_rejected(tmp_path, name):
    outside = tmp_path / "outside"
    outside.write_bytes(b"do not modify")
    (tmp_path / name).symlink_to(outside)
    with pytest.raises(OSError):
        PlanStore(tmp_path)
    assert outside.read_bytes() == b"do not modify"
