"""Three reviewed app replays in Harbor; no models or candidate code on the host."""

import base64
import hashlib
import hmac
import json
import os
import subprocess

import harbor_spike
from harbor_audit import Watcher

from democratize_security.adapters.runners.invoice_boundary import audit_application
from democratize_security.adapters.runners.invoice_task import control_source, prepare_task
from democratize_security.artifacts import bind_evidence, seal, write_new
from democratize_security.policy_replay import write_record


def accept(job, bundle, nonce, failed):
    paths = list(job.glob("*/result.json"))
    if len(paths) != 1:
        raise ValueError("Expected one trial")
    trial = paths[0].parent
    result = json.loads(paths[0].read_text())
    reward = int(failed is None)
    if (
        result.get("exception_info")
        or not result.get("finished_at")
        or result.get("verifier_environment_mode") != "separate"
        or result.get("agent_info", {}).get("name") != "nop"
        or result.get("verifier_result", {}).get("rewards") != {"reward": reward}
        or os.path.lexists(trial / "verifier/reward.json")
    ):
        raise ValueError("Incomplete or unexpected application trial")
    raw = seal(trial / "verifier", ["application-evidence.json"])["files"][0]["content_base64"]
    evidence = json.loads(base64.b64decode(raw))
    mac = evidence.pop("mac")
    expected = hmac.new(
        nonce.encode(),
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()
    if (
        not hmac.compare_digest(mac, expected)
        or evidence["app_sha256"] != bundle["files"][0]["sha256"]
    ):
        raise ValueError("Unbound verifier evidence")
    if seal(trial / "artifacts", ["app.py"])["artifact_sha256"] != bundle["artifact_sha256"]:
        raise ValueError("Transferred application differs from seal")
    outcome = evidence["result"]
    required = {
        "database_configuration",
        "authorized_reads",
        "foreign_reads",
        "list_search",
        "exports",
        "identity",
        "spoofing",
        "tenant_switching",
    }
    checks = outcome["checks"]
    if (
        evidence["schema_version"] != 1
        or evidence["reward"] != reward
        or outcome["protocol"] != "synthetic-reference-v2"
        or outcome["coverage"] != "complete"
        or outcome["outcome"] != ("fail" if failed else "pass")
        or len(checks) != len(required)
        or {c["id"] for c in checks} != required
        or any(c["outcome"] != ("fail" if c["id"] == failed else "pass") for c in checks)
    ):
        raise ValueError("Application checks did not have the expected complete outcome")
    return trial, outcome


def main():
    root = harbor_spike.ROOT
    output = root / ".research/harbor-invoice-read"
    output.mkdir(parents=True, exist_ok=False)
    requirements = subprocess.run(
        [
            "uv",
            "export",
            "--locked",
            "--extra",
            "reference",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements-txt",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        timeout=60,
    ).stdout
    original = (root / "src/democratize_security/reference/app.py").read_text()
    for control, failed in (
        ("protected", None),
        ("id_derived_tenant", "foreign_reads"),
        ("deny_all", "authorized_reads"),
    ):
        source = output / f"source-{control}"
        source.mkdir()
        (source / "app.py").write_text(control_source(original, control))
        bundle = seal(source, ["app.py"])
        write_new(bundle, output / f"{control}.bundle.json")
        (source / "app.py").write_text("raise RuntimeError('mutable source must not execute')")
        task = output / f"task-{control}"
        manifest = prepare_task(bundle, root, task, requirements)
        job = output / control
        watcher = Watcher(job)
        try:
            nonce = harbor_spike.run_trial(task, "nop", output, control)
        finally:
            watcher.stop()
        trial, result = accept(job, bundle, nonce, failed)
        boundary = audit_application(trial.name, list(watcher.inspections.values()), nonce)
        record = bind_evidence(
            bundle,
            manifest["verifier_sha256"],
            {"verification": result, "boundary": boundary, "manifest": manifest},
        )
        write_record(output / f"evidence-{control}.json", record)
        print(json.dumps({"control": control, "evidence": record}, indent=2))


if __name__ == "__main__":
    main()
