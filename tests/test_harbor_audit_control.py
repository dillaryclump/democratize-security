"""Offline checks for the reviewed tamper control; live Docker runs only in CI."""

import json
import os
import runpy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def control():
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        yield runpy.run_path(str(ROOT / "scripts/harbor_audit.py"))
    finally:
        sys.path.remove(str(ROOT / "scripts"))


def test_generated_task_is_trusted_files_plus_reviewed_solution(control, tmp_path):
    task = tmp_path / "task"
    control["prepare_tamper"](task, 43210)
    files = sorted(p.relative_to(task).as_posix() for p in task.rglob("*") if p.is_file())
    assert files == sorted([*control["TRUSTED_FILES"], "solution/solve.sh"])
    for name in control["TRUSTED_FILES"]:
        assert (task / name).read_bytes() == (control["harbor_spike"].TASK / name).read_bytes()
    # Harbor's root chmod has no capabilities, so the bit must already be set.
    assert (task / "solution/solve.sh").stat().st_mode & 0o005 == 0o005
    solve = (task / "solution/solve.sh").read_text()
    assert "43210" in solve and "/logs/verifier/reward.json" in solve
    with pytest.raises(FileExistsError):
        control["prepare_tamper"](task, 43210)
    with pytest.raises(ValueError):
        control["prepare_tamper"](tmp_path / "other", 0)


def test_unsafe_policy_matches_task_image(control):
    dockerfile = (control["harbor_spike"].TASK / "environment/Dockerfile").read_text()
    assert control["UNSAFE_POLICY"].decode().strip() in dockerfile


def forged_trial(control, root, *, with_reward_json):
    trial = root / "trial"
    (trial / "verifier").mkdir(parents=True)
    (trial / "artifacts").mkdir()
    (trial / "artifacts/policy.json").write_bytes(control["UNSAFE_POLICY"])
    logs = {
        "source": "/logs/artifacts",
        "destination": "artifacts/agent-artifacts",
        "type": "directory",
        "status": "failed",
        "service": None,
    }
    (trial / "artifacts/manifest.json").write_text(json.dumps([logs]))
    for name, data in control["FORGED"].items():
        if with_reward_json or name != "reward.json":
            (trial / "verifier" / name).write_bytes(data)
    result = {
        "exception_info": None,
        "verifier_environment_mode": "separate",
        "agent_info": {"name": "oracle"},
        "finished_at": "2026-10-14",
        "verifier_result": {"rewards": {"reward": 1}},
    }
    (trial / "result.json").write_text(json.dumps(result))
    return trial


@pytest.mark.parametrize("with_reward_json", [True, False])
def test_surviving_forgery_is_rejected_without_the_verifier_nonce(
    control, tmp_path, with_reward_json
):
    forged_trial(control, tmp_path, with_reward_json=with_reward_json)
    with pytest.raises(ValueError, match="reward.json|nonce"):
        control["harbor_spike"].accept_result(tmp_path, "oracle", 1, "c" * 64)


def test_forgery_is_otherwise_a_complete_pass(control, tmp_path):
    # The control is meaningful: re-signed with a leaked nonce, the forged
    # evidence would pass every other acceptance check.
    trial = forged_trial(control, tmp_path, with_reward_json=False)
    spike = control["harbor_spike"]
    evidence = json.loads(control["FORGED"]["policy-evidence.json"])
    evidence["mac"] = spike.evidence_mac("c" * 64, evidence)
    (trial / "verifier/policy-evidence.json").write_text(json.dumps(evidence))
    accepted = spike.accept_result(tmp_path, "oracle", 1, "c" * 64)
    assert accepted["reward"] == 1 and all(accepted["checks"].values())


def test_committed_oracle_solution_is_executable_by_the_unprivileged_agent():
    # docker cp keeps the host owner (the CI runner), so Harbor's capability-less
    # root cannot chmod it; the committed mode must already allow execution.
    import subprocess

    path = "tasks/harbor/rls-policy/solution/solve.sh"
    staged = subprocess.run(
        ["git", "ls-files", "-s", path], capture_output=True, text=True, check=True, cwd=ROOT
    ).stdout
    assert staged.startswith("100755 ")
    assert (ROOT / path).stat().st_mode & 0o005 == 0o005


def fake_docker(tmp_path, monkeypatch, script):
    """A `docker` on PATH that runs `script`; only the watcher's helpers call it."""
    directory = tmp_path / "bin"
    directory.mkdir()
    docker = directory / "docker"
    docker.write_text(f"#!/bin/sh\n{script}\n")
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{directory}:{os.environ['PATH']}")


def bare_watcher(control):
    # No `docker events` process: only the per-container helpers are exercised.
    watcher = object.__new__(control["Watcher"])
    watcher.volumes, watcher.agent_log_bytes = {}, {}
    return watcher


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ("printf abc; printf de >&2", 5),
        # An unbounded log is read only just past the bound, never whole.
        ("head -c 67108864 /dev/zero", "over"),
        # A container already removed is not a measurement.
        ("echo 'No such container' >&2; exit 1", None),
    ],
)
def test_watcher_measures_agent_logs_within_a_bound(
    control, tmp_path, monkeypatch, script, expected
):
    fake_docker(tmp_path, monkeypatch, script)
    watcher = bare_watcher(control)
    watcher._measure_log("abc", "trial__env")
    measured = watcher.agent_log_bytes.get("trial__env")
    if expected == "over":
        limit = 4 * control["LOG_BYTES"]
        assert limit < measured <= limit + 65536
    else:
        assert measured == expected


def test_watcher_inspects_each_named_volume_once(control, tmp_path, monkeypatch):
    calls = tmp_path / "calls"
    fake_docker(
        tmp_path,
        monkeypatch,
        f'echo "$@" >> {calls}\n'
        'printf \'[{"Name": "%s", "Driver": "local", "Options": null}]\' "$3"',
    )
    watcher = bare_watcher(control)
    container = {
        "Mounts": [
            {"Type": "volume", "Name": "trial__env_candidate"},
            {"Type": "bind", "Source": "/x"},
            {"Type": "volume", "Name": "trial__env_candidate"},
        ]
    }
    watcher._inspect_volumes(container)
    watcher._inspect_volumes(container)
    assert watcher.volumes == {
        "trial__env_candidate": {
            "Name": "trial__env_candidate",
            "Driver": "local",
            "Options": None,
        }
    }
    assert calls.read_text() == "volume inspect trial__env_candidate\n"
