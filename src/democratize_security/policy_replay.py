"""Prepare reviewed single-artifact replays; no Harbor dependency or dispatch.

The caller supplies a trusted task template and a fresh controller-owned parent.
Only the validated artifact bytes (a declarative policy.json or an application
task's app.py) enter the agent build context. This does not harden Harbor's
extraction boundary for hostile workers.
"""

import base64
import hashlib
import json
import shutil
from pathlib import Path

from democratize_security.artifacts import bind_evidence, validate
from democratize_security.contracts import digest

TRUSTED_FILES = (
    "task.toml",
    "instruction.md",
    # Reviewed container hardening; a replay must not run with weaker isolation.
    "environment/docker-compose.yaml",
    # The trusted collector that extracts the artifact after the agent stops.
    "environment/collect.py",
    "environment/collector.Dockerfile",
    # The trusted entrypoint that seeds the size-bounded submission volume.
    "environment/seed.sh",
    "tests/Dockerfile",
    "tests/docker-compose.yaml",
    "tests/test.sh",
    "tests/check.py",
)
# Every verifier file of the application tasks, including the separate app
# container's build inputs; a unit test keeps this equal to their tests/ trees.
APP_TRUSTED_FILES = (
    "task.toml",
    "instruction.md",
    "environment/docker-compose.yaml",
    "environment/collect.py",
    "environment/collector.Dockerfile",
    "environment/seed.sh",
    "tests/Dockerfile",
    "tests/app.Dockerfile",
    "tests/app-requirements.txt",
    "tests/docker-compose.yaml",
    "tests/fixture.py",
    "tests/launch.py",
    "tests/run.py",
    "tests/test.sh",
    "tests/verifier-requirements.in",
    "tests/verifier-requirements.txt",
    "tests/verify.py",
)
# Same reviewed multi-arch index digest as the task's agent image. A tag alone
# can be repointed between runs; apt packages in the verifier image still can.
AGENT_BASE_IMAGE = (
    "python:3.12-slim-bookworm@sha256:"
    "34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258"
)


def replay_dockerfile(artifact: str) -> str:
    # The submission volume is a size-bounded tmpfs Docker does not populate
    # from the image, so the trusted entrypoint seeds the sealed bytes into it.
    return f"""FROM {AGENT_BASE_IMAGE}
WORKDIR /candidate
COPY {artifact} /opt/starter/{artifact}
RUN chmod 0755 /opt/starter && chmod 0444 /opt/starter/{artifact}
COPY --chmod=0555 seed.sh /opt/seed.sh
ENTRYPOINT ["/opt/seed.sh"]
"""


REPLAY_DOCKERFILE = replay_dockerfile("policy.json")


def prepare_replay(
    bundle: dict,
    template: Path,
    destination: Path,
    *,
    artifact: str = "policy.json",
    max_bytes: int = 4096,
    trusted_files: tuple[str, ...] = TRUSTED_FILES,
) -> dict:
    """Materialize a new Harbor task exclusively from sealed data + trusted code.

    Unknown files, tampering, and existing destinations are refused before writes.
    Source candidate paths and original solution scripts are never consulted.
    """
    summary = validate(bundle)
    if summary["paths"] != [artifact] or summary["total_bytes"] > max_bytes:
        raise ValueError(f"Replay requires exactly one {artifact} of at most {max_bytes} bytes")
    trusted = {name: (template / name).read_bytes() for name in trusted_files}
    dockerfile = replay_dockerfile(artifact)
    destination.mkdir(exist_ok=False)
    try:
        for name, content in trusted.items():
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        environment = destination / "environment"
        (environment / "Dockerfile").write_text(dockerfile)
        (environment / artifact).write_bytes(
            base64.b64decode(bundle["files"][0]["content_base64"], validate=True)
        )
    except BaseException:
        # Remove only the fresh tree created by this invocation.
        shutil.rmtree(destination)
        raise
    inputs = {name: hashlib.sha256(content).hexdigest() for name, content in trusted.items()}
    inputs["environment/Dockerfile"] = hashlib.sha256(dockerfile.encode()).hexdigest()
    inputs[f"environment/{artifact}"] = bundle["files"][0]["sha256"]
    return {
        "schema_version": 1,
        "artifact_sha256": summary["artifact_sha256"],
        "task_files": inputs,
        "task_sha256": digest(inputs),
        "verifier_sha256": digest(
            {name: value for name, value in inputs.items() if name.startswith("tests/")}
        ),
        "harbor_version": "0.24.0",
    }


def record_replay(
    bundle: dict, manifest: dict, replay_result: dict, *, kind: str = "sealed_policy_replay"
) -> dict:
    """Bind accepted replay evidence to the pre-existing bundle and verifier source."""
    validate(bundle)
    expected = bundle["artifact_sha256"]
    if manifest["artifact_sha256"] != expected or replay_result["artifact_sha256"] != expected:
        raise ValueError("Replay artifact does not match the sealed input")
    result = {**replay_result, "replay_manifest": manifest, "kind": kind}
    return bind_evidence(bundle, manifest["verifier_sha256"], result)


def write_record(path: Path, record: dict) -> None:
    """Refuse stale output reuse; interrupted records cannot pass JSON validation."""
    with path.open("x") as stream:
        stream.write(json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + "\n")
