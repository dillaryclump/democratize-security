"""Grade each application task's starter, oracle and reviewed unsafe control
against real PostgreSQL with the same protocol the Harbor verifier runs."""

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = json.loads((ROOT / "scripts/app_controls/expected.json").read_text())
CASES = {
    (task, control): path
    for task in EXPECTED
    for control, path in (
        ("oracle", ROOT / f"tasks/harbor/{task}/solution/app.py"),
        ("nop", ROOT / f"tasks/harbor/{task}/environment/app.py"),
        ("unsafe", ROOT / f"scripts/app_controls/{task}-unsafe.py"),
    )
}


@pytest.mark.parametrize("case", sorted(CASES), ids="/".join)
def test_control_outcomes_are_exact(database, serve, case):
    from democratize_security.verification.reference import REQUIRED, verify

    task, control = case
    with serve(database.runtime, CASES[case]) as client:
        result = verify(client, database.runtime)
    assert result["coverage"] == "complete", result
    outcomes = {check["id"]: check["outcome"] for check in result["checks"]}
    expected = EXPECTED[task].get(control, dict.fromkeys(REQUIRED, "pass"))
    assert outcomes == expected, result
    assert result["outcome"] == ("pass" if control == "oracle" else "fail")
