"""Prepare reviewed declarative-policy replays; no Harbor dependency or dispatch.

The caller supplies a trusted task template and a fresh controller-owned parent.
Only validated policy.json bytes enter the agent build context. This does not
harden Harbor's extraction boundary for hostile workers.
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
    "tests/Dockerfile",
    "tests/test.sh",
    "tests/check.py",
)
REPLAY_DOCKERFILE = """FROM python:3.12-slim-bookworm
WORKDIR /candidate
COPY policy.json /candidate/policy.json
RUN chmod 444 /candidate/policy.json
"""


def prepare_replay(bundle: dict, template: Path, destination: Path) -> dict:
    """Materialize a new Harbor task exclusively from sealed data + trusted code.

    Unknown files, tampering, and existing destinations are refused before writes.
    Source candidate paths and original solution scripts are never consulted.
    """
    summary = validate(bundle)
    if summary["paths"] != ["policy.json"] or summary["total_bytes"] > 4096:
        raise ValueError("Replay requires exactly one policy.json of at most 4096 bytes")
    trusted = {name: (template / name).read_bytes() for name in TRUSTED_FILES}
    destination.mkdir(exist_ok=False)
    try:
        for name, content in trusted.items():
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        environment = destination / "environment"
        environment.mkdir()
        (environment / "Dockerfile").write_text(REPLAY_DOCKERFILE)
        (environment / "policy.json").write_bytes(
            base64.b64decode(bundle["files"][0]["content_base64"], validate=True)
        )
    except BaseException:
        # Remove only the fresh tree created by this invocation.
        shutil.rmtree(destination)
        raise
    inputs = {name: hashlib.sha256(content).hexdigest() for name, content in trusted.items()}
    inputs["environment/Dockerfile"] = hashlib.sha256(REPLAY_DOCKERFILE.encode()).hexdigest()
    inputs["environment/policy.json"] = bundle["files"][0]["sha256"]
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


def record_replay(bundle: dict, manifest: dict, replay_result: dict) -> dict:
    """Bind accepted replay evidence to the pre-existing bundle and verifier source."""
    validate(bundle)
    expected = bundle["artifact_sha256"]
    if manifest["artifact_sha256"] != expected or replay_result["artifact_sha256"] != expected:
        raise ValueError("Replay artifact does not match the sealed input")
    result = {**replay_result, "replay_manifest": manifest, "kind": "sealed_policy_replay"}
    return bind_evidence(bundle, manifest["verifier_sha256"], result)


def write_record(path: Path, record: dict) -> None:
    """Refuse stale output reuse; interrupted records cannot pass JSON validation."""
    with path.open("x") as stream:
        stream.write(json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + "\n")
