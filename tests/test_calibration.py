"""Offline checks for the metered calibration driver (issue #69); no Docker or network.

The Docker dry run (`scripts/calibration.py --dry-run`) is its own CI job.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_model_meter import LIMITS, SOL

from democratize_security.contracts import load_campaign
from democratize_security.model_budget import trial_reservation_ceiling_cents
from democratize_security.model_meter import ScriptedProvider
from democratize_security.store import PlanStore

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
try:
    import calibration
finally:
    sys.path.remove(str(ROOT / "scripts"))


def test_campaign_caps_within_approved_budget():
    total = 0
    for path in calibration.CAMPAIGNS.values():
        campaign = load_campaign(path)
        rate, limits = calibration.rate_and_limits(campaign)
        hold = trial_reservation_ceiling_cents(rate, limits)
        assert campaign["limits"]["max_cost_usd_cents"] == 3 * hold
        assert campaign["limits"]["infrastructure_retries"] == 0
        assert campaign["limits"]["repair_attempts"] == 0
        assert campaign["conditions"] == ["rls_starter"]
        total += campaign["limits"]["max_cost_usd_cents"]
    assert (total, calibration.APPROVED_CENTS) == (777, 1000)


def test_task_revisions_match_trees():
    for path in calibration.CAMPAIGNS.values():
        for task in load_campaign(path)["tasks"]:
            directory = ROOT / "tasks/harbor" / task["family"]
            assert task["revision"] == calibration.task_tree_sha256(directory)


def test_task_tree_digest_changes_with_bytes_and_mode(tmp_path):
    (tmp_path / "a").write_text("x")
    first = calibration.task_tree_sha256(tmp_path)
    (tmp_path / "a").chmod(0o755)
    second = calibration.task_tree_sha256(tmp_path)
    (tmp_path / "a").write_text("y")
    assert len({first, second, calibration.task_tree_sha256(tmp_path)}) == 3


def test_harbor_env_scrubs_credentials(monkeypatch, tmp_path):
    for name in ("OPENAI_API_KEY", "FOO_API_KEY", "GH_TOKEN", "OPENAI_ORG", "ANTHROPIC_X"):
        monkeypatch.setenv(name, "secret")
    monkeypatch.setenv("KEEP_ME", "1")
    env = calibration.harbor_env(tmp_path / "model.sock")
    assert not any(value == "secret" for value in env.values())
    assert env["KEEP_ME"] == "1"
    assert env["DS_MODEL_BROKER_SOCKET"] == str(tmp_path / "model.sock")


def test_live_refuses_without_worker_host_flag(monkeypatch, tmp_path):
    monkeypatch.delenv("DS_WORKER_HOST_REQUIRED", raising=False)
    with pytest.raises(SystemExit, match="DS_WORKER_HOST_REQUIRED=1"):
        calibration.main(["--live", "--key-file", str(tmp_path / "k"), "--ledger", str(tmp_path)])


def test_mode_is_required():
    with pytest.raises(SystemExit):
        calibration.main([])


CLIENT = """
import json, os, socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(os.environ["DS_MODEL_BROKER_SOCKET"])
s.sendall(json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode() + b"\\n")
s.shutdown(socket.SHUT_WR)
print(s.recv(65536).decode())
"""


def fake_launch(task, agent, jobs_dir, job_name, env):
    """One brokered model request and exit, writing no Harbor job: collection fails."""
    return subprocess.Popen([sys.executable, "-c", CLIENT], env=env, stdout=subprocess.DEVNULL)


def test_collection_failure_interrupts_and_settles_committed(tmp_path):
    ledger, objects_dir = tmp_path / "ledger", tmp_path / "objects"
    ledger.mkdir()
    objects_dir.mkdir()
    campaign = load_campaign(calibration.CAMPAIGNS["sol"])
    with PlanStore(ledger, objects_directory=objects_dir) as store:
        plan = store.import_campaign(campaign)
        record = calibration.run_trial(
            store,
            plan,
            plan["trials"][0],
            ScriptedProvider(("an app",)),
            SOL,
            LIMITS,
            reasoning_effort="medium",
            workdir=tmp_path / "work",
            launch=fake_launch,
        )
        assert record["outcome"] == "interrupted"
        assert record["reason"].startswith("collection_failed")
        assert (record["requests"], record["committed_cents"], record["settled"]) == (1, 1, True)
        (state,) = store.attempts()
        assert (state["phase"], state["actual_cost_cents"]) == ("interrupted", 1)
        assert store.budget_snapshot(plan["campaign_id"])["blocked"] is False


def test_halted_transport_stops_without_settlement(tmp_path):
    ledger, objects_dir = tmp_path / "ledger", tmp_path / "objects"
    ledger.mkdir()
    objects_dir.mkdir()
    campaign = load_campaign(calibration.CAMPAIGNS["sol"])
    with PlanStore(ledger, objects_directory=objects_dir) as store:
        plan = store.import_campaign(campaign)
        record = calibration.run_trial(
            store,
            plan,
            plan["trials"][0],
            ScriptedProvider(()),  # The send fails after its intent: outcome unknown.
            SOL,
            LIMITS,
            reasoning_effort="medium",
            workdir=tmp_path / "work",
            launch=fake_launch,
        )
        assert (record["outcome"], record["settled"]) == ("interrupted", False)
        assert record["unknown_requests"] == 1
        assert record["stop_batch"] is True
        (state,) = store.attempts()
        assert state["actual_cost_cents"] is None
        assert store.budget_snapshot(plan["campaign_id"])["blocked"] is True


def test_summary_json_is_plain(tmp_path):
    record = {"attempt_id": "a", "requests": 1}
    path = tmp_path / "summary.json"
    calibration.write_summary(path, [record], mode="dry-run")
    data = json.loads(path.read_text())
    assert data["trials"] == [record] and data["mode"] == "dry-run"
    assert data["approved_cap_cents"] == 1000


def test_scrub_credentials_removes_them_from_this_process(monkeypatch):
    for name in ("OPENAI_API_KEY", "FOO_API_KEY", "GH_TOKEN", "ANTHROPIC_X"):
        monkeypatch.setenv(name, "secret")
    monkeypatch.setenv("KEEP_ME", "1")
    calibration.scrub_credentials()
    # harbor_spike.run_trial (the sealed replay) inherits os.environ directly.
    assert not any(value == "secret" for value in calibration.os.environ.values())
    assert calibration.os.environ["KEEP_ME"] == "1"
