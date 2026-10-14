"""Run exactly two reviewed, model-free Harbor infrastructure controls."""

import json
import subprocess
from pathlib import Path

from democratize_security.artifacts import seal, write_new

ROOT = Path(__file__).resolve().parents[1]
TASK = ROOT / "tasks/harbor/rls-policy"
CHECKS = {"authorized_a", "authorized_b", "missing_context_denied", "rls_enabled"}


def accept_result(job, agent, expected):
    results = list(job.glob("*/result.json"))
    if len(results) != 1:
        raise ValueError("expected exactly one trial result")
    trial = results[0].parent
    result = json.loads(results[0].read_text())
    if (
        result.get("exception_info") is not None
        or result.get("verifier_environment_mode") != "separate"
        or result.get("agent_info", {}).get("name") != agent
        or not result.get("finished_at")
        or result.get("verifier_result", {}).get("rewards") != {"reward": expected}
    ):
        raise ValueError("missing, failed, or unexpected Harbor result")
    evidence = json.loads((trial / "verifier/policy-evidence.json").read_text())
    checks = evidence.get("checks", {})
    if set(checks) != CHECKS or any(type(value) is not bool for value in checks.values()):
        raise ValueError("incomplete verifier coverage")
    if all(checks.values()) != bool(expected):
        raise ValueError("reward disagrees with checks")
    bundle = seal(trial / "artifacts", ["policy.json"])
    if bundle["files"][0]["sha256"] != evidence.get("artifact_sha256"):
        raise ValueError("collected policy differs from verifier input")
    write_new(bundle, job / "policy.bundle.json")
    return {
        "agent": agent,
        "reward": expected,
        "checks": checks,
        "artifact_sha256": bundle["artifact_sha256"],
        "security_verdict": "not_evaluated",
        "scope": "public_harbor_policy_spike",
    }


def main():
    from importlib.metadata import version

    from harbor.models.task.task import Task

    if version("harbor") != "0.24.0":
        raise ValueError("unreviewed Harbor version")
    task = Task(TASK)
    if task.config.verifier.environment_mode.value != "separate":
        raise ValueError("separate verifier required")
    output = ROOT / ".research/harbor-spike"
    # Refuse reuse so stale successful outputs cannot satisfy this run.
    output.mkdir(parents=True, exist_ok=False)
    summaries = []
    for agent, reward in (("oracle", 1), ("nop", 0)):
        subprocess.run(
            [
                "harbor",
                "run",
                "-p",
                str(TASK),
                "-a",
                agent,
                "-n",
                "1",
                "-k",
                "1",
                "-r",
                "0",
                "--jobs-dir",
                str(output),
                "--job-name",
                agent,
            ],
            check=True,
            timeout=600,
            cwd=ROOT,
        )
        summaries.append(accept_result(output / agent, agent, reward))
    (output / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
