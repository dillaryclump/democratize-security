"""Model-free Terminus2 transport conformance through the audited invoice-read boundary.

Issue #63. Three finite, retry-free trials under trusted host observation:

- `scripted`: a fixed script drives Harbor 0.24.0's real Terminus2 parser, tmux
  loop and two-step completion confirmation to write the reviewed reference app;
  the separate verifier must grade every check `pass`;
- `malformed`: a script of invalid JSON exhausts the turn limit; the starter is
  collected unchanged and must fail exactly the reviewed `nop` checks;
- `replay`: the sealed `scripted` artifact replayed with Harbor's `nop` agent must
  reproduce the same outcomes.

Each trial must pass the existing host-observed boundary audit. The copied task
differs from the canonical one only by a Dockerfile line that bakes tmux into
the candidate image at build time. No model, provider, key or spending is used;
results describe transport plumbing, never model capability.
"""

import json
import os
import shutil
import sys
from pathlib import Path

import harbor_apps
import harbor_audit
import harbor_spike

from democratize_security.adapters.runners.harbor_audit import (
    audit,
    declared_exec_users,
    declared_limits,
)
from democratize_security.artifacts import load
from democratize_security.policy_replay import (
    APP_TRUSTED_FILES,
    prepare_replay,
    record_replay,
    write_record,
)

TASK = harbor_spike.ROOT / "tasks/harbor/invoice-read"
OUTPUT = harbor_spike.ROOT / ".research/terminus-conformance"
AGENTS = "democratize_security.adapters.runners.terminus_conformance"
AGENT_NAME = "scripted-terminus"
TMUX = (
    "RUN apt-get update && apt-get install -y --no-install-recommends tmux"
    " && rm -rf /var/lib/apt/lists/*\n"
)
SCOPE = "model_free_transport_conformance"


def prepare_terminus_task(source: Path, destination: Path) -> None:
    """Copy the canonical task; bake tmux in directly before its ENTRYPOINT."""
    shutil.copytree(source, destination)
    dockerfile = destination / "environment/Dockerfile"
    lines = dockerfile.read_text().splitlines(keepends=True)
    entrypoints = [i for i, line in enumerate(lines) if line.startswith("ENTRYPOINT ")]
    if len(entrypoints) != 1:
        raise ValueError("expected exactly one ENTRYPOINT in the canonical Dockerfile")
    lines.insert(entrypoints[0], TMUX)
    dockerfile.write_text("".join(lines))


def main():
    from importlib.metadata import version

    if version("harbor") != "0.24.0":
        raise ValueError("unreviewed Harbor version")
    # Refuse reuse so stale outputs cannot satisfy this run.
    OUTPUT.mkdir(parents=True, exist_ok=False)
    task = OUTPUT / "task"
    prepare_terminus_task(TASK, task)
    listener = harbor_audit.Listener()
    watcher = harbor_audit.Watcher()
    trials, results = [], {}

    def trial(control, task_dir, agent, accepted_as, job, expected_bundle=None):
        nonce = harbor_spike.run_trial(task_dir, agent, OUTPUT, job)
        trials.append((OUTPUT / job, task_dir, nonce))
        result = harbor_apps.accept_app(
            OUTPUT / job,
            accepted_as,
            harbor_apps.expected_outcomes("invoice-read", control),
            nonce,
            expected_bundle=expected_bundle,
        )
        return {**result, "scope": SCOPE}

    try:
        control_connections = harbor_audit.positive_control(listener, watcher)
        results["scripted"] = trial(
            "oracle", task, f"{AGENTS}:ScriptedReferenceTerminus", AGENT_NAME, "scripted"
        )
        results["malformed"] = trial(
            "nop", task, f"{AGENTS}:MalformedTerminus", AGENT_NAME, "malformed"
        )
        bundle = load(OUTPUT / "scripted/app.bundle.json")
        replay = OUTPUT / "task-replay"
        manifest = prepare_replay(
            bundle,
            TASK,
            replay,
            artifact="app.py",
            max_bytes=harbor_apps.MAX_APP_BYTES,
            trusted_files=APP_TRUSTED_FILES,
        )
        write_record(OUTPUT / "manifest-replay.json", manifest)
        replayed = trial("oracle", replay, "nop", "nop", "replay", expected_bundle=bundle)
        results["replay"] = record_replay(bundle, manifest, replayed, kind="sealed_app_replay")
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
    summary = {
        "schema_version": 1,
        "scope": SCOPE,
        "harbor_version": version("harbor"),
        "model_calls": 0,
        "security_verdict": "not_evaluated",
        "controls": results,
        "audits": audits,
    }
    write_record(OUTPUT / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    failed = [
        record["trial_name"]
        for record in audits
        if record["outcome"] != "pass"
        or [c["role"] for c in record["containers"]].count("app") != 1
    ]
    if failed:
        raise ValueError(f"no passing audit with exactly one app container: {failed}")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("usage: terminus_conformance.py")
    main()
