"""Offline checks for the pilot Harbor control runner (Docker runs are a CI job)."""

import sys
from pathlib import Path

import pytest

from democratize_security.pilot import FAMILIES
from democratize_security.verification.report import PROTOCOL, PROTOCOL_V4, REQUIRED_V4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
try:
    import harbor_apps
    import pilot_controls
    import worker_host
finally:
    sys.path.remove(str(ROOT / "scripts"))


@pytest.mark.parametrize("family", FAMILIES)
def test_control_plan_per_family(family):
    plan = pilot_controls.control_plan(family)
    assert plan == [
        (condition, control)
        for condition in ("ordinary", "instructions", "rls_starter", "full_tool")
        for control in ("oracle", "nop", "unsafe")
    ] + [("full_tool", "tool-oracle"), ("full_tool", "tool-unsafe")]


def test_expected_outcomes_for_each_control():
    oracle = pilot_controls.expected("invoice-read", "ordinary", "oracle")
    assert oracle == dict.fromkeys(pilot_controls.ORDER, "pass")
    assert set(oracle) == REQUIRED_V4
    unsafe = pilot_controls.expected("invoice-read", "full_tool", "unsafe")
    assert unsafe == pilot_controls.expected("invoice-read", "full_tool", "tool-unsafe")
    assert unsafe["spoofing"] == "fail"
    assert pilot_controls.expected("invoice-read", "rls_starter", "tool-oracle") == oracle


def test_tool_solve_scripts():
    good = pilot_controls.solve_script("tool-oracle")
    bad = pilot_controls.solve_script("tool-unsafe")
    assert "/opt/tools/check-isolation" in good and "! /opt/tools/check-isolation" not in good
    assert "! /opt/tools/check-isolation" in bad
    assert good.startswith("#!/bin/sh\nset -eu\n") and bad.startswith("#!/bin/sh\nset -eu\n")


def test_job_names_satisfy_worker_helper():
    import re

    for family in FAMILIES:
        for condition, control in pilot_controls.control_plan(family):
            job = pilot_controls.job_name(condition, control)
            assert re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", job), job


def test_worker_allowlists_pilot_parents():
    for family in FAMILIES:
        assert f"pilot-controls/{family}" in worker_host.PARENTS
    assert {"pilot", "pilot-dry-run"} <= worker_host.PARENTS


def fake_evidence(schema_version, protocol, checks):
    return {
        "schema_version": schema_version,
        "protocol": protocol,
        "app_started": True,
        "coverage": "complete",
        "checks": checks,
        "outcome": "pass" if all(v == "pass" for v in checks.values()) else "fail",
    }, {"artifact_sha256": "a" * 64}


def test_accept_app_v4_requires_v4_evidence(monkeypatch, tmp_path):
    checks = dict.fromkeys(pilot_controls.ORDER, "pass")
    for evidence in (
        fake_evidence(3, PROTOCOL_V4, checks),
        fake_evidence(4, PROTOCOL, checks),
    ):
        monkeypatch.setattr(harbor_apps.harbor_spike, "accept_trial", lambda *a, e=evidence, **k: e)
        with pytest.raises(ValueError):
            harbor_apps.accept_app(
                tmp_path, "oracle", checks, "n", protocol=PROTOCOL_V4, schema_version=4
            )
    good = fake_evidence(4, PROTOCOL_V4, checks)
    monkeypatch.setattr(harbor_apps.harbor_spike, "accept_trial", lambda *a, **k: good)
    monkeypatch.setattr(harbor_apps, "write_new", lambda *a, **k: None)
    result = harbor_apps.accept_app(
        tmp_path, "oracle", checks, "n", protocol=PROTOCOL_V4, schema_version=4
    )
    assert result["outcome"] == "pass"
