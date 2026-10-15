"""Model-free Harbor controls, audits and sealed replays for the application tasks.

For each requested task (default: all three), under trusted host observation:

- `oracle`: the reviewed reference app must pass every verifier check;
- `nop`: the unmodified starter must fail exactly its expected checks;
- `unsafe`: a reviewed insecure variant must fail exactly its security checks;
- replays of the sealed oracle and unsafe artifacts, built only from those bytes
  plus the trusted task files, must reproduce the same outcomes.

Every trial must also pass the host-observed boundary audit, with no host
listener connection during the whole run. Five finite trials per task, no retries.
"""

import json
import os
import re
import shutil
import sys

import harbor_audit
import harbor_spike

from democratize_security.adapters.runners.harbor_audit import (
    audit,
    declared_exec_users,
    declared_limits,
)
from democratize_security.artifacts import load, write_new
from democratize_security.policy_replay import (
    APP_TRUSTED_FILES,
    prepare_replay,
    record_replay,
    write_record,
)

TASKS = harbor_spike.ROOT / "tasks/harbor"
CONTROLS = harbor_spike.ROOT / "scripts/app_controls"
OUTPUT = harbor_spike.ROOT / ".research/harbor-apps"
# Reviewed exact outcomes; integration tests hold the same table against real
# PostgreSQL, so Harbor runs and direct runs cannot drift apart silently.
EXPECTED = json.loads((CONTROLS / "expected.json").read_text())
PROTOCOL = "synthetic-reference-v3"
EVIDENCE_KEYS = {
    "app_started",
    "artifact_sha256",
    "checks",
    "coverage",
    "details",
    "outcome",
    "protocol",
    "reward",
    "schema_version",
}
MAX_APP_BYTES = 65536


def expected_outcomes(task, control):
    nop = EXPECTED[task]["nop"]
    return dict.fromkeys(nop, "pass") if control == "oracle" else EXPECTED[task][control]


def accept_app(job, agent, expected, nonce, *, expected_bundle=None):
    """Accept one app trial only if its nonce-bound outcomes are exactly `expected`."""
    passed = all(outcome == "pass" for outcome in expected.values())
    evidence, bundle = harbor_spike.accept_trial(
        job,
        agent,
        int(passed),
        nonce,
        evidence="app-evidence.json",
        artifact="app.py",
        keys=EVIDENCE_KEYS,
        expected_bundle=expected_bundle,
    )
    if (
        evidence["schema_version"] != 3
        or evidence["protocol"] != PROTOCOL
        or evidence["app_started"] is not True
        or evidence["coverage"] != "complete"
        or evidence["checks"] != expected
        or evidence["outcome"] != ("pass" if passed else "fail")
    ):
        raise ValueError("verifier outcomes differ from the reviewed expectation")
    write_new(bundle, job / "app.bundle.json")
    return {
        "agent": agent,
        "reward": int(passed),
        "outcome": evidence["outcome"],
        "checks": evidence["checks"],
        "artifact_sha256": bundle["artifact_sha256"],
        "security_verdict": "not_evaluated",
        "scope": "public_harbor_application_control",
    }


def prepare_control(task, destination, app):
    """Copy the trusted task and substitute only the oracle solution's app bytes."""
    if len(app) > MAX_APP_BYTES:
        raise ValueError("control app too large")
    # copytree keeps solve.sh executable: Harbor's capability-less root chmod
    # cannot set the bit on a CI-runner-owned upload.
    shutil.copytree(task, destination)
    (destination / "solution/app.py").write_bytes(app)


def app_limits(compose):
    """The app service's declared limits, read from the trusted verifier compose."""
    import yaml

    app = yaml.safe_load(compose.read_text())["services"]["app"]
    memory = re.fullmatch(r"(\d+)m", str(app["mem_limit"]))
    if not memory or app["memswap_limit"] != app["mem_limit"]:
        raise ValueError("app memory must be declared in MiB without swap")
    return {"cpus": app["cpus"], "memory_mb": int(memory.group(1))}


def run_task(name, trials):
    task = TASKS / name
    output = OUTPUT / name
    # Refuse reuse so stale outputs cannot satisfy this run.
    output.mkdir(parents=True, exist_ok=False)
    results = {}

    def trial(control, task_dir, agent, job, expected_bundle=None):
        nonce = harbor_spike.run_trial(task_dir, agent, output, job)
        trials.append((output / job, task_dir, nonce))
        return accept_app(
            output / job,
            agent,
            expected_outcomes(name, control),
            nonce,
            expected_bundle=expected_bundle,
        )

    results["oracle"] = trial("oracle", task, "oracle", "oracle")
    results["nop"] = trial("nop", task, "nop", "nop")
    unsafe = output / "task-unsafe"
    prepare_control(task, unsafe, (CONTROLS / f"{name}-unsafe.py").read_bytes())
    results["unsafe"] = trial("unsafe", unsafe, "oracle", "unsafe")
    replays = []
    for control in ("oracle", "unsafe"):
        bundle = load(output / control / "app.bundle.json")
        replay = output / f"task-replay-{control}"
        manifest = prepare_replay(
            bundle,
            task,
            replay,
            artifact="app.py",
            max_bytes=MAX_APP_BYTES,
            trusted_files=APP_TRUSTED_FILES,
        )
        write_record(output / f"manifest-{control}.json", manifest)
        result = trial(control, replay, "nop", f"replay-{control}", expected_bundle=bundle)
        record = record_replay(bundle, manifest, result)
        write_record(output / f"evidence-{control}.json", record)
        replays.append(record)
    return {"task": name, "controls": results, "replays": replays}


def main(names):
    from importlib.metadata import version

    if version("harbor") != "0.24.0":
        raise ValueError("unreviewed Harbor version")
    if not names or not set(names) <= set(EXPECTED) or len(set(names)) != len(names):
        raise ValueError(f"choose tasks from {sorted(EXPECTED)}")
    listener = harbor_audit.Listener()
    watcher = harbor_audit.Watcher()
    trials, summaries = [], []
    try:
        control_connections = harbor_audit.positive_control(listener, watcher)
        for name in names:
            summaries.append(run_task(name, trials))
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
        limits["app"] = app_limits(task_dir / "tests/docker-compose.yaml")
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
            )
        )
    summary = {"tasks": summaries, "audits": audits}
    for name in names:
        write_record(OUTPUT / name / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    failed = [record["trial_name"] for record in audits if record["outcome"] != "pass"]
    if failed:
        raise ValueError(f"observed container boundary did not pass the audit: {failed}")


if __name__ == "__main__":
    main(sys.argv[1:] or sorted(EXPECTED))
