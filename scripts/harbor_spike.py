"""Run exactly two reviewed, model-free Harbor infrastructure controls."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
from pathlib import Path

from democratize_security.artifacts import seal, validate, write_new

ROOT = Path(__file__).resolve().parents[1]
TASK = ROOT / "tasks/harbor/rls-policy"
CHECKS = {"authorized_a", "authorized_b", "missing_context_denied", "rls_enabled"}
EVIDENCE_KEYS = {"artifact_sha256", "checks", "reward", "schema_version"}
# Must not match Harbor's secret-name pattern, or Harbor redacts it in evidence.
NONCE = "DS_NONCE"


def evidence_mac(nonce, evidence):
    # Mirrors the verifiers' check.py and run.py, which cannot import project
    # code: the MAC covers every evidence field except itself.
    payload = {k: v for k, v in evidence.items() if k != "mac"}
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(nonce.encode(), data, hashlib.sha256).hexdigest()


def run_trial(task, agent, jobs_dir, job_name):
    """Run one finite, retry-free trial; return the nonce only its verifier saw."""
    nonce = secrets.token_hex(32)
    subprocess.run(
        ["harbor", "run", "-p", str(task), "-a", agent, "-n", "1", "-k", "1", "-r", "0"]
        + ["--jobs-dir", str(jobs_dir), "--job-name", job_name]
        # Harbor resolves the template from its own environment at verify time
        # and passes it only to the separate verifier's test exec, so the raw
        # value is never persisted in job configuration or shown to the agent.
        + ["--ve", f"{NONCE}=${{{NONCE}}}"],
        check=True,
        timeout=600,
        cwd=ROOT,
        env={**os.environ, NONCE: nonce},
    )
    return nonce


def check_staged_logs(trial):
    """Reject a trial that staged the agent-written /logs/artifacts for the verifier.

    Each task replaces Harbor's convention entry with an exclude-all one. If the
    agent made its container refuse execs (PID exhaustion, killing its init),
    Harbor's directory probe fails and it falls back to an unfiltered copy,
    recorded as a file entry or a non-empty staging directory.
    """
    manifest = json.loads((trial / "artifacts/manifest.json").read_text())
    entries = [
        (e.get("destination"), e.get("type"))
        for e in manifest
        if e.get("source") == "/logs/artifacts"
    ]
    staged = trial / "artifacts/agent-artifacts"
    if (
        entries != [("artifacts/agent-artifacts", "directory")]
        or os.path.islink(staged)
        or (os.path.lexists(staged) and (not staged.is_dir() or any(staged.iterdir())))
    ):
        raise ValueError("agent-written /logs/artifacts was staged for the verifier")


def accept_trial(job, agent, reward, nonce, *, evidence, artifact, keys, expected_bundle=None):
    """Shared host acceptance for one finite trial; returns (evidence, bundle).

    Requires one clean separate-verifier trial whose evidence, bound to this
    run's nonce, agrees with Harbor's reward and covers the collected bytes.
    """
    if expected_bundle is not None:
        validate(expected_bundle)
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
        or result.get("verifier_result", {}).get("rewards") != {"reward": reward}
    ):
        raise ValueError("missing, failed, or unexpected Harbor result")
    # Harbor grades from reward.json before reward.txt; these verifiers never
    # write one, so any reward.json is foreign.
    if os.path.lexists(trial / "verifier/reward.json"):
        raise ValueError("unexpected reward.json in verifier output")
    check_staged_logs(trial)
    sealed = seal(trial / "verifier", [evidence])["files"][0]["content_base64"]
    record = json.loads(base64.b64decode(sealed))
    if (
        not isinstance(record, dict)
        or set(record) != {*keys, "mac"}
        or not isinstance(record["mac"], str)
        or not hmac.compare_digest(record["mac"], evidence_mac(nonce, record))
    ):
        raise ValueError("evidence is not bound to this run's verifier nonce")
    if record["reward"] != reward:
        raise ValueError("evidence reward disagrees with Harbor")
    bundle = seal(trial / "artifacts", [artifact])
    if bundle["files"][0]["sha256"] != record["artifact_sha256"]:
        raise ValueError("collected artifact differs from verifier input")
    if expected_bundle is not None:
        if bundle["artifact_sha256"] != expected_bundle["artifact_sha256"]:
            raise ValueError("Replay differs from the pre-verification seal")
    return record, bundle


def accept_result(job, agent, expected, nonce, *, expected_bundle=None):
    evidence, bundle = accept_trial(
        job,
        agent,
        expected,
        nonce,
        evidence="policy-evidence.json",
        artifact="policy.json",
        keys=EVIDENCE_KEYS,
        expected_bundle=expected_bundle,
    )
    checks = evidence["checks"]
    if (
        evidence["schema_version"] != 2
        or not isinstance(checks, dict)
        or set(checks) != CHECKS
        or any(type(value) is not bool for value in checks.values())
    ):
        raise ValueError("incomplete verifier coverage")
    if all(checks.values()) != bool(expected):
        raise ValueError("reward disagrees with checks")
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
        nonce = run_trial(TASK, agent, output, agent)
        summaries.append(accept_result(output / agent, agent, reward, nonce))
    (output / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
