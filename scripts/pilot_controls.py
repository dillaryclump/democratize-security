"""Model-free controls for the pilot task variants through the audited Harbor boundary.

For one scenario family, each of its four condition variants runs:
- `oracle`: the reviewed reference; every v4 check must pass.
- `nop`: the unchanged starter; outcomes must equal the reviewed expectations.
- `unsafe`: the reviewed vulnerable endpoint; outcomes must equal the reviewed
  expectations. In plain-fixture variants it really leaks.

`full_tool` additionally runs `tool-oracle`, which must make `check-isolation`
exit 0 on the reference inside the real agent container, and `tool-unsafe`,
which must make it exit non-zero on the unsafe app. A failing solve script fails
the trial. Every trial must also pass the host-observed boundary audit. No
model, provider or spending is involved.

Usage: pilot_controls.py FAMILY
"""

import json
import os
import shutil
import subprocess
import sys

import harbor_apps
import harbor_audit
import harbor_spike

from democratize_security.adapters.runners.harbor_audit import (
    audit,
    declared_exec_users,
    declared_limits,
)
from democratize_security.pilot import CONTROLS, FAMILIES
from democratize_security.pilot.instructions import CONDITIONS, FIXTURE_OF
from democratize_security.policy_replay import write_record
from democratize_security.verification.report import ORDER_V4 as ORDER
from democratize_security.verification.report import PROTOCOL_V4

ROOT = harbor_spike.ROOT
TASKS = ROOT / "tasks/pilot"
OUTPUT = ROOT / ".research/pilot-controls"
EXPECTED = json.loads((CONTROLS / "expected.json").read_text())
TOOL_CONTROLS = ("tool-oracle", "tool-unsafe")


def control_plan(family: str) -> list[tuple[str, str]]:
    plan = [(c, control) for c in CONDITIONS for control in ("oracle", "nop", "unsafe")]
    return plan + [("full_tool", control) for control in TOOL_CONTROLS]


def expected(family: str, condition: str, control: str) -> dict:
    if control in {"oracle", "tool-oracle"}:
        return dict.fromkeys(ORDER, "pass")
    kind = "unsafe" if control == "tool-unsafe" else control
    return EXPECTED[family][FIXTURE_OF[condition]][kind]


def job_name(condition: str, control: str) -> str:
    return f"{condition.replace('_', '-')}-{control}"


def solve_script(control: str) -> str:
    """Install the solution, then require the self-check verdict inside the agent."""
    check = "/opt/tools/check-isolation"
    verdict = check if control == "tool-oracle" else f"! {check}"
    return (
        "#!/bin/sh\nset -eu\n"
        "test ! -e /tests/run.py\n"
        "cp /solution/app.py /candidate/app.py\n"
        f"{verdict}\n"
    )


def variant(family: str, condition: str):
    return TASKS / f"{family}-{condition.replace('_', '-')}"


def run_family(family, trials):
    output = OUTPUT / family
    # Refuse reuse so stale outputs cannot satisfy this run.
    output.mkdir(parents=True, exist_ok=False)
    fixture_of = FIXTURE_OF
    results = {}
    for condition, control in control_plan(family):
        task = variant(family, condition)
        job = job_name(condition, control)
        unsafe_app = (CONTROLS / f"{family}-{fixture_of[condition]}-unsafe.py").read_bytes()
        if control in {"oracle", "nop"}:
            task_dir, agent = task, control
        else:
            task_dir, agent = output / f"task-{job}", "oracle"
            app = (
                (task / "solution/app.py").read_bytes() if control == "tool-oracle" else unsafe_app
            )
            harbor_apps.prepare_control(task, task_dir, app)
            if control in TOOL_CONTROLS:
                solve = task_dir / "solution/solve.sh"
                solve.write_text(solve_script(control))
                solve.chmod(0o755)
        nonce = harbor_spike.run_trial(task_dir, agent, output, job)
        trials.append((output / job, task_dir, nonce))
        results[job] = harbor_apps.accept_app(
            output / job,
            agent,
            expected(family, condition, control),
            nonce,
            protocol=PROTOCOL_V4,
            schema_version=4,
        )
    return {"family": family, "controls": results}


def main(argv):
    from importlib.metadata import version

    if version("harbor") != "0.24.0":
        raise ValueError("unreviewed Harbor version")
    if len(argv) != 1 or argv[0] not in FAMILIES:
        raise SystemExit(f"usage: pilot_controls.py FAMILY  (one of {', '.join(FAMILIES)})")
    family = argv[0]
    listener = harbor_audit.Listener()
    watcher = harbor_audit.Watcher()
    trials = []
    try:
        control_connections = harbor_audit.positive_control(listener, watcher)
        summary = run_family(family, trials)
    finally:
        watcher.stop()
    egress = {"control_connections": control_connections, "trial_connections": listener.take()}
    listener.socket.close()
    audits = []
    for job, task_dir, nonce in trials:
        found = [path.parent for path in job.glob("*/result.json")]
        if len(found) != 1:
            raise ValueError("expected exactly one trial result")
        limits = declared_limits(task_dir / "task.toml")
        limits["app"] = harbor_audit.service_limits(task_dir / "tests/docker-compose.yaml", "app")
        limits["collector"] = harbor_audit.service_limits(
            task_dir / "environment/docker-compose.yaml", "collector"
        )
        audits.append(
            audit(
                found[0].name,
                found[0],
                list(watcher.inspections.values()),
                watcher.events,
                limits,
                egress,
                nonce,
                os.getuid(),
                declared_exec_users(task_dir / "task.toml"),
                watcher.volumes,
            )
        )
    summary["audits"] = audits
    summary["protocol"] = PROTOCOL_V4
    summary["model_calls"] = 0
    summary["source_revision"] = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    write_record(OUTPUT / family / "summary.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k != "audits"}, indent=2))
    failed = [
        record["trial_name"]
        for record in audits
        if record["outcome"] != "pass"
        or [c["role"] for c in record["containers"]].count("app") != 1
    ]
    if failed:
        raise ValueError(f"no passing audit with exactly one app container: {failed}")
    print(f"{family}: {len(audits)} control trials accepted and audited")


if __name__ == "__main__":
    shutil.which("harbor") or sys.exit("harbor CLI not found")
    main(sys.argv[1:])
