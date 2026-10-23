"""Offline checks for the frozen pilot campaign, runner and report (no Docker, no network)."""

import json
import re
import sys
from collections import Counter
from pathlib import Path

import pytest

from democratize_security.contracts import load_campaign, plan
from democratize_security.model_budget import trial_reservation_ceiling_cents
from democratize_security.pilot import FAMILIES
from democratize_security.pilot.instructions import CONDITIONS
from democratize_security.store import PlanStore

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
try:
    import build_pilot_tasks
    import calibration
    import pilot
    import pilot_report
finally:
    sys.path.remove(str(ROOT / "scripts"))


def test_campaign_shape():
    campaign = load_campaign(pilot.CAMPAIGN)
    assert campaign["conditions"] == list(CONDITIONS)
    assert [t["family"] for t in campaign["tasks"]] == list(FAMILIES)
    assert campaign["repetitions"] == 2
    assert campaign["model"] == {
        "provider": "openai",
        "identifier": "gpt-6.1-sol",
        "settings": {
            "reasoning_effort": "medium",
            "service_tier": "default",
            "order_seed": 20261023,
        },
    }
    assert campaign["limits"]["max_trials"] == 48
    assert len(plan(campaign)["trials"]) == 48


def test_pilot_caps_and_limits():
    campaign = load_campaign(pilot.CAMPAIGN)
    rate, limits = pilot.rate_and_limits(campaign)
    assert trial_reservation_ceiling_cents(rate, limits) == 101
    assert campaign["limits"]["max_cost_usd_cents"] == 1500
    assert campaign["limits"]["concurrency"] == 1
    assert campaign["limits"]["infrastructure_retries"] == 0
    assert campaign["limits"]["repair_attempts"] == 0
    assert (
        limits.max_requests,
        limits.max_input_tokens_per_request,
        limits.max_output_tokens_per_request,
        limits.max_total_input_tokens,
        limits.max_total_output_tokens,
    ) == (12, 64000, 8000, 200000, 40000)


def test_task_revisions_match_variant_trees():
    for task in load_campaign(pilot.CAMPAIGN)["tasks"]:
        assert task["revision"] == pilot.family_revision(task["family"])
        assert task["split"] == "development"


def test_trial_order_seeded_and_block_balanced():
    planned = plan(load_campaign(pilot.CAMPAIGN))
    first = pilot.trial_order(planned, 20261023)
    assert first == pilot.trial_order(planned, 20261023)
    assert first != pilot.trial_order(planned, 7)
    assert [t["trial_id"] for t in first] != [t["trial_id"] for t in planned["trials"]]
    for block, repetition in ((first[:24], 0), (first[24:], 1)):
        assert {t["repetition"] for t in block} == {repetition}
        assert Counter((t["family"], t["condition"]) for t in block) == Counter(
            {(f, c): 1 for f in FAMILIES for c in CONDITIONS}
        )


def test_attempt_and_job_names_satisfy_helper():
    for trial in plan(load_campaign(pilot.CAMPAIGN))["trials"]:
        attempt = pilot.attempt_name(trial["family"], trial["condition"], trial["repetition"])
        for job in calibration.job_names(attempt):
            assert re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", job), job
    assert pilot.attempt_name("invoice-read", "full_tool", 0) == "pilot-invoice-read-full-tool-r1"


def test_variant_for_trial():
    trial = {"family": "invoice-update", "condition": "rls_starter"}
    assert pilot.variant_for(trial) == build_pilot_tasks.variant_dir(
        "invoice-update", "rls_starter"
    )
    assert "tests/variant.json" in pilot.TRUSTED_FILES


def test_live_refuses_without_worker_host_flag(monkeypatch, tmp_path):
    monkeypatch.delenv("DS_WORKER_HOST_REQUIRED", raising=False)
    with pytest.raises(SystemExit, match="DS_WORKER_HOST_REQUIRED=1"):
        pilot.main(["--live", "--key-file", str(tmp_path / "k"), "--ledger", str(tmp_path)])


def test_live_refuses_without_control_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("DS_WORKER_HOST_REQUIRED", "1")
    monkeypatch.setattr(pilot, "CONTROLS_OUTPUT", tmp_path / "missing")
    with pytest.raises(SystemExit, match="control evidence"):
        pilot.require_control_evidence("a" * 40)
    good = tmp_path / "controls"
    for family in FAMILIES:
        (good / family).mkdir(parents=True)
        (good / family / "summary.json").write_text(
            json.dumps(
                {
                    "family": family,
                    "protocol": "synthetic-reference-v4",
                    "source_revision": "a" * 40,
                    "model_calls": 0,
                    "audits": [{"outcome": "pass"}],
                }
            )
        )
    monkeypatch.setattr(pilot, "CONTROLS_OUTPUT", good)
    pilot.require_control_evidence("a" * 40)
    with pytest.raises(SystemExit, match="control evidence"):
        pilot.require_control_evidence("b" * 40)


def synthetic_ledger(tmp_path):
    """Three attempts: a pass, a security fail and an interruption; the rest unrun."""
    ledger, objects_dir = tmp_path / "ledger", tmp_path / "objects"
    ledger.mkdir()
    objects_dir.mkdir()
    with PlanStore(ledger, objects_directory=objects_dir) as store:
        planned = store.import_campaign(load_campaign(pilot.CAMPAIGN))
    return ledger, objects_dir, planned


def test_report_counts_every_scheduled_trial(tmp_path):
    _, _, planned = synthetic_ledger(tmp_path)
    passing = dict.fromkeys(pilot_report.ORDER, "pass")
    trials = planned["trials"]
    rows = {
        trials[0]["trial_id"]: {"phase": "completed", "checks": passing, "cents": 4},
        trials[1]["trial_id"]: {
            "phase": "completed",
            "checks": {**passing, "spoofing": "fail"},
            "cents": 5,
        },
        trials[2]["trial_id"]: {"phase": "interrupted", "checks": None, "cents": 2},
    }
    table = pilot_report.tabulate(planned, rows)
    assert table["scheduled"] == 48
    assert table["joint_success"] == 1
    assert table["not_run"] == 45
    assert table["incomplete"] == 1
    assert sum(cell["scheduled"] for cell in table["cells"].values()) == 48
    cell = table["cells"][(trials[1]["family"], trials[1]["condition"])]
    assert cell["isolation_failures"] >= 1
    markdown = pilot_report.render(table)
    assert "| invoice-read |" in markdown and "48 scheduled" in markdown
