"""Offline checks for the reviewed tamper control; live Docker runs only in CI."""

import json
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
    solve = (task / "solution/solve.sh").read_text()
    assert "43210" in solve and "/logs/verifier/reward.json" in solve
    with pytest.raises(FileExistsError):
        control["prepare_tamper"](task, 43210)
    with pytest.raises(ValueError):
        control["prepare_tamper"](tmp_path / "other", 0)


def test_unsafe_policy_matches_task_image(control):
    dockerfile = (control["harbor_spike"].TASK / "environment/Dockerfile").read_text()
    assert control["UNSAFE_POLICY"].decode().strip() in dockerfile


def test_surviving_forgery_would_be_accepted_as_a_pass(control, tmp_path):
    # Shows the control is meaningful: if Harbor kept these files, host
    # acceptance alone could not distinguish them from a genuine verifier pass.
    trial = tmp_path / "trial"
    (trial / "verifier").mkdir(parents=True)
    (trial / "artifacts").mkdir()
    (trial / "artifacts/policy.json").write_bytes(control["UNSAFE_POLICY"])
    for name, data in control["FORGED"].items():
        (trial / "verifier" / name).write_bytes(data)
    result = {
        "exception_info": None,
        "verifier_environment_mode": "separate",
        "agent_info": {"name": "oracle"},
        "finished_at": "2026-10-14",
        "verifier_result": {"rewards": json.loads(control["FORGED"]["reward.json"])},
    }
    (trial / "result.json").write_text(json.dumps(result))
    accepted = control["harbor_spike"].accept_result(tmp_path, "oracle", 1)
    assert accepted["reward"] == 1 and all(accepted["checks"].values())
