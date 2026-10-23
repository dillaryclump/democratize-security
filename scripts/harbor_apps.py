"""Model-free Harbor controls, audits and sealed replays for the application tasks.

For each requested task (default: all three), under trusted host observation:

- `oracle`: the reviewed reference app must pass every verifier check;
- `nop`: the unmodified starter must fail exactly its expected checks;
- `unsafe`: a reviewed insecure variant must fail exactly its security checks;
- replays of the sealed oracle and unsafe artifacts, built only from those bytes
  plus the trusted task files, must reproduce the same outcomes;
- hostile extraction controls leave a symlink to a host canary directory, a
  1 GiB sparse file or a FIFO at the artifact path. The trusted collector must
  reject each one, so nothing is collected and the verifier grades a bound zero.
  A valid app saved as 0600 must still pass, as must a valid app whose agent
  also left a sparse file, a link to the canary, a FIFO and an unreadable file
  in /logs/artifacts, none of which may be staged for the verifier;
- a storage control writes past every container-level bound the agent can
  reach (its submission volume, /tmp, /dev/shm and its container log) before
  submitting the reference app. Each write must stop at its bound, the log the
  daemon serves must stay within its cap, and the app must still pass.

Every trial must also pass the host-observed boundary audit, with no host
listener connection during the whole run. Twelve finite trials per task, no retries.
"""

import base64
import json
import os
import re
import secrets
import shlex
import shutil
import sys

import harbor_audit
import harbor_spike

from democratize_security.adapters.runners.harbor_audit import (
    LOG_BYTES,
    SHM_BYTES,
    audit,
    compose_project,
    declared_exec_users,
    declared_limits,
)
from democratize_security.artifacts import load, seal, write_new
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
# Reviewed hostile solutions; {canary} is a host directory absent from the agent.
# Each checks that its object is really in place, so a control cannot pass
# merely because the script failed before creating it.
EXTRACTION = {
    "symlink": (
        "rm -f /candidate/app.py\nln -s {canary} /candidate/app.py\ntest -L /candidate/app.py"
    ),
    "sparse": (
        'truncate -s 1G /candidate/app.py\ntest "$(stat -c %s /candidate/app.py)" -eq 1073741824'
    ),
    "fifo": "rm -f /candidate/app.py\nmkfifo /candidate/app.py\ntest -p /candidate/app.py",
}
# A valid reference app saved as 0600, which the verifier user could not read.
PRIVATE = (
    "rm -f /candidate/app.py\ninstall -m 600 /solution/app.py /candidate/app.py\n"
    'test "$(stat -c %a /candidate/app.py)" = 600'
)
# A valid app plus hostile files in the agent-written /logs/artifacts bind
# mount, which Harbor would otherwise copy into the verifier unchecked.
LOGS = (
    "truncate -s 1G /logs/artifacts/sparse\n"
    "ln -s {canary} /logs/artifacts/link\n"
    "mkfifo /logs/artifacts/fifo\n"
    "install -m 000 /dev/null /logs/artifacts/unreadable\n"
    # Separate lines: under set -e a failure before && would not stop the script.
    "test -p /logs/artifacts/fifo\n"
    "test -L /logs/artifacts/link\n"
    "cp /solution/app.py /candidate/app.py"
)
# Makes the agent's own container refuse Harbor's later execs by killing its
# init, forcing Harbor's unfiltered fallback copy of /logs/artifacts; host
# acceptance must detect it. The file is small: no disk is spent proving it.
FALLBACK = (
    "printf 'staged by fallback\\n' > /logs/artifacts/fallback.txt\n"
    "cp /solution/app.py /candidate/app.py\n"
    "echo '{marker}'\n"
    "kill -TERM 1"
)
MARKER = "extraction control in place"
# Fills each writable surface well past its bound (128 MiB requested), records
# where the write stopped, frees the space, then writes 8 MiB to its init's
# stdout, which is the container log, and submits the reference app.
FILL = (
    "fill() {{\n"
    '  dd if=/dev/zero of="$1" bs=65536 count=2048 2>/dev/null || true\n'
    '  size=$(stat -c %s "$1")\n'
    '  rm -f "$1"\n'
    '  echo "$size"\n'
    "}}\n"
    "candidate=$(fill /candidate/fill)\n"
    "tmp=$(fill /tmp/fill)\n"
    "shm=$(fill /dev/shm/fill)\n"
    "head -c 8388608 /dev/zero | tr '\\0' a > /proc/1/fd/1\n"
    "cp /solution/app.py /candidate/app.py\n"
    'echo "{marker} candidate=$candidate tmp=$tmp shm=$shm"'
)
# The agent compose file's bounds; a unit test holds them to it.
FILL_BOUNDS = {"candidate": 16 * 1024 * 1024, "tmp": 16 * 1024 * 1024, "shm": SHM_BYTES}


def expected_outcomes(task, control):
    nop = EXPECTED[task]["nop"]
    return dict.fromkeys(nop, "pass") if control == "oracle" else EXPECTED[task][control]


def accept_app(
    job, agent, expected, nonce, *, expected_bundle=None, protocol=PROTOCOL, schema_version=3
):
    """Accept one app trial only if its nonce-bound outcomes are exactly `expected`.

    Pilot tasks pass protocol v4 and evidence schema 4; the defaults are v3.
    """
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
        evidence["schema_version"] != schema_version
        or evidence["protocol"] != protocol
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


def prepare_extraction(task, destination, script, *, marker=True):
    """Copy the trusted task with the reference app and a reviewed hostile solve.sh."""
    prepare_control(task, destination, (task / "solution/app.py").read_bytes())
    solve = destination / "solution/solve.sh"
    ending = f"echo '{MARKER}'\n" if marker else ""
    solve.write_text(f"#!/bin/sh\nset -eu\n{script}\n{ending}")
    solve.chmod(0o755)


def accept_rejected(job, nonce, secret):
    """A hostile artifact must yield a bound zero with nothing collected or copied."""
    results = list(job.glob("*/result.json"))
    if len(results) != 1:
        raise ValueError("expected exactly one trial result")
    trial = results[0].parent
    result = json.loads(results[0].read_text())
    if (
        result.get("exception_info") is not None
        or result.get("verifier_environment_mode") != "separate"
        or result.get("verifier_result", {}).get("rewards") != {"reward": 0}
        or os.path.lexists(trial / "verifier/reward.json")
    ):
        raise ValueError("hostile artifact did not end in a clean zero")
    # Harbor records a failing solve.sh; the marker proves the object existed.
    log = seal(trial / "agent", ["oracle.txt"])["files"][0]["content_base64"]
    if os.path.lexists(trial / "agent/exit-code.txt") or MARKER not in base64.b64decode(log).decode(
        errors="replace"
    ):
        raise ValueError("hostile solution did not put its artifact in place")
    if os.path.lexists(trial / "artifacts/app.py"):
        raise ValueError("collector let a rejected artifact through")
    harbor_spike.check_staged_logs(trial)
    # Harbor 0.24.0 writes the collection manifest as a list of entries.
    manifest = json.loads((trial / "artifacts/manifest.json").read_text())
    entries = [e for e in manifest if e.get("source") == "/candidate/app.py"]
    if [(e["service"], e["status"]) for e in entries] != [("collector", "failed")]:
        raise ValueError("artifact was not collected only through the collector")
    sealed = seal(trial / "verifier", ["app-evidence.json"])["files"][0]["content_base64"]
    evidence = json.loads(base64.b64decode(sealed))
    if (
        set(evidence) != {*EVIDENCE_KEYS, "mac"}
        or evidence["mac"] != harbor_spike.evidence_mac(nonce, evidence)
        or (evidence["outcome"], evidence["reward"], evidence["artifact_sha256"])
        != ("invalid_submission", 0, None)
    ):
        raise ValueError("verifier did not bind a missing submission")
    # Without the collector, Harbor would have copied the canary directory.
    for path in trial.rglob("*"):
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as stream:
                if secret in stream.read(16 * 1024 * 1024):
                    raise ValueError("host canary reached the trial outputs")
    return {"outcome": evidence["outcome"], "reward": 0, "collected": False}


def accept_logs(job):
    """Nothing the agent wrote to /logs/artifacts may be staged for the verifier."""
    trials = [path.parent for path in job.glob("*/result.json")]
    if len(trials) != 1:
        raise ValueError("expected exactly one trial result")
    harbor_spike.check_staged_logs(trials[0])
    return "nothing staged"


def accept_fill(job, agent_log_bytes):
    """Every write must have stopped at its bound; the log must stay capped."""
    trials = [path.parent for path in job.glob("*/result.json")]
    if len(trials) != 1:
        raise ValueError("expected exactly one trial result")
    trial = trials[0]
    log = seal(trial / "agent", ["oracle.txt"])["files"][0]["content_base64"]
    match = re.search(
        rf"{MARKER} candidate=(\d+) tmp=(\d+) shm=(\d+)",
        base64.b64decode(log).decode(errors="replace"),
    )
    if not match:
        raise ValueError("storage control did not report its writes")
    written = dict(zip(FILL_BOUNDS, map(int, match.groups()), strict=True))
    # Half the bound or more shows the write ran into the bound, not an error.
    for surface, size in written.items():
        if not FILL_BOUNDS[surface] // 2 <= size <= FILL_BOUNDS[surface]:
            raise ValueError(f"{surface} write was not stopped at its bound")
    # Read from the daemon when the agent's container died, after 8 MiB.
    observed = agent_log_bytes.get(compose_project(f"{trial.name}__env"))
    if observed is None or observed > LOG_BYTES:
        raise ValueError("agent container log was not observed within its cap")
    return {**{f"{k}_bytes": v for k, v in written.items()}, "agent_log_bytes": observed}


def detect_fallback(job):
    """The fallback control must really force the copy, and acceptance must catch it."""
    trials = [path.parent for path in job.glob("*/result.json")]
    if len(trials) != 1:
        raise ValueError("expected exactly one trial result")
    staged = trials[0] / "artifacts/agent-artifacts"
    if not (staged / "fallback.txt").is_file() or (staged / "fallback.txt").is_symlink():
        raise ValueError("fallback control did not force Harbor's unfiltered copy")
    try:
        harbor_spike.check_staged_logs(trials[0])
    except ValueError:
        return "fallback staged and rejected"
    raise ValueError("acceptance missed a staged /logs/artifacts")


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
        record = record_replay(bundle, manifest, result, kind="sealed_app_replay")
        write_record(output / f"evidence-{control}.json", record)
        replays.append(record)
    canary = output / "canary"
    canary.mkdir()
    secret = secrets.token_hex(16).encode()
    (canary / "secret.txt").write_bytes(secret)
    extraction = {}
    for control, script in EXTRACTION.items():
        hostile = output / f"task-{control}"
        prepare_extraction(task, hostile, script.format(canary=shlex.quote(str(canary.resolve()))))
        nonce = harbor_spike.run_trial(hostile, "oracle", output, control)
        trials.append((output / control, hostile, nonce))
        extraction[control] = accept_rejected(output / control, nonce, secret)
    private = output / "task-private"
    prepare_extraction(task, private, PRIVATE)
    extraction["private"] = trial("oracle", private, "oracle", "private")
    logs = output / "task-logs"
    prepare_extraction(task, logs, LOGS.format(canary=shlex.quote(str(canary.resolve()))))
    extraction["logs"] = trial("oracle", logs, "oracle", "logs")
    extraction["logs"]["verifier_logs_artifacts"] = accept_logs(output / "logs")
    fallback = output / "task-logs-fallback"
    prepare_extraction(task, fallback, FALLBACK.format(marker=MARKER), marker=False)
    nonce = harbor_spike.run_trial(fallback, "oracle", output, "logs-fallback")
    trials.append((output / "logs-fallback", fallback, nonce))
    extraction["logs-fallback"] = detect_fallback(output / "logs-fallback")
    fill = output / "task-fill"
    prepare_extraction(task, fill, FILL.format(marker=MARKER), marker=False)
    extraction["fill"] = trial("oracle", fill, "oracle", "fill")
    return {"task": name, "controls": results, "replays": replays, "extraction": extraction}


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
    for summary in summaries:
        summary["extraction"]["fill"]["storage"] = accept_fill(
            OUTPUT / summary["task"] / "fill", watcher.agent_log_bytes
        )
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
    summary = {"tasks": summaries, "audits": audits}
    for name in names:
        write_record(OUTPUT / name / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    # Policy v3 applies its app rules only to observed app containers, so an
    # application trial must also show exactly one.
    failed = [
        record["trial_name"]
        for record in audits
        if record["outcome"] != "pass"
        or [c["role"] for c in record["containers"]].count("app") != 1
    ]
    if failed:
        raise ValueError(f"no passing audit with exactly one app container: {failed}")


if __name__ == "__main__":
    main(sys.argv[1:] or sorted(EXPECTED))
