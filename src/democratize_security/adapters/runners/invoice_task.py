"""Build a reviewed Harbor task with a separate Unix-socket application sidecar."""

import base64
import hashlib
import json
import secrets
from pathlib import Path

from democratize_security.artifacts import validate
from democratize_security.contracts import digest
from democratize_security.policy_replay import AGENT_BASE_IMAGE


def control_source(source: str, control: str) -> str:
    original = "        found = rows(\n            organization,"
    if source.count(original) != 1:
        raise ValueError("Review invoice controls after changing the reference")
    if control == "protected":
        return source
    replacement = {
        "id_derived_tenant": '"org-a" if invoice_id in (1, 2) else "org-b"',
        "deny_all": '"no-such-organization"',
    }[control]
    return source.replace(original, "        found = rows(\n            " + replacement + ",")


def prepare_task(bundle: dict, root: Path, destination: Path, requirements: bytes) -> dict:
    summary = validate(bundle)
    if summary["paths"] != ["app.py"]:
        raise ValueError("Invoice task requires exactly app.py")
    source = base64.b64decode(bundle["files"][0]["content_base64"], validate=True)
    destination.mkdir(exist_ok=False)
    agent, verifier = destination / "environment", destination / "tests"
    agent.mkdir()
    (verifier / "application").mkdir(parents=True)
    template = root / "tasks/application/invoice-read/runtime"
    for name in (
        "Dockerfile",
        "test.sh",
        "check.py",
        "application/Dockerfile",
        "application/start.py",
    ):
        (verifier / name).write_bytes((template / name).read_bytes())
    (verifier / "reference.py").write_bytes(
        (root / "src/democratize_security/verification/reference.py").read_bytes()
    )
    (verifier / "expected.sha256").write_text(bundle["files"][0]["sha256"])
    for path in (agent / "app.py", verifier / "application/app.py"):
        path.write_bytes(source)
    for path in (verifier / "requirements.txt", verifier / "application/requirements.txt"):
        path.write_bytes(requirements)
    (agent / "Dockerfile").write_text(
        f"FROM {AGENT_BASE_IMAGE}\nWORKDIR /candidate\nCOPY --chmod=0444 app.py /candidate/app.py\n"
    )
    (agent / "docker-compose.yaml").write_bytes(
        (root / "tasks/harbor/rls-policy/environment/docker-compose.yaml").read_bytes()
    )
    password = secrets.token_hex(24)
    dsn = f"host=/dbsocket dbname=postgres user=invoice_runtime password={password}"
    hardening = {
        "network_mode": "none",
        "init": True,
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "pids_limit": 64,
        "mem_limit": "256m",
        "memswap_limit": "256m",
        "cpus": 1,
    }
    compose = {
        "services": {
            "main": {
                **hardening,
                "user": "postgres",
                "mem_limit": "512m",
                "memswap_limit": "512m",
                "pids_limit": 128,
                "cap_add": ["CHOWN", "DAC_OVERRIDE", "FOWNER"],
                "tmpfs": ["/tmp:rw,noexec,nosuid,size=128m"],
                "volumes": ["dbsocket:/dbsocket", "appsock:/appsock:ro"],
                "environment": {"DS_RUNTIME_PASSWORD": password, "REFERENCE_DATABASE_URL": dsn},
            },
            "app": {
                **hardening,
                "user": "10001:10001",
                "build": {"context": "${CONTEXT_DIR}/application"},
                "tmpfs": ["/tmp:rw,noexec,nosuid,size=16m"],
                "volumes": ["dbsocket:/dbsocket:ro", "appsock:/appsock"],
                "environment": {"REFERENCE_DATABASE_URL": dsn, "PYTHONDONTWRITEBYTECODE": "1"},
            },
        },
        "volumes": {"dbsocket": {}, "appsock": {}},
    }
    (verifier / "docker-compose.yaml").write_text(json.dumps(compose, indent=2))
    config = (root / "tasks/harbor/rls-policy/task.toml").read_text()
    config = config.replace("policy.json", "app.py").replace("rls-policy", "invoice-read")
    config = config.replace("timeout_sec = 90", "timeout_sec = 180")
    (destination / "task.toml").write_text(config)
    (destination / "instruction.md").write_text(
        "Reviewed sealed application replay. Leave /candidate/app.py unchanged.\n"
    )
    inputs = {
        p.relative_to(destination).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in destination.rglob("*")
        if p.is_file()
    }
    return {
        "schema_version": 1,
        "artifact_sha256": summary["artifact_sha256"],
        "app_sha256": bundle["files"][0]["sha256"],
        "task_sha256": digest(inputs),
        "verifier_sha256": digest(
            {
                k: v
                for k, v in inputs.items()
                if k.startswith("tests/") and not k.startswith("tests/application/")
            }
        ),
    }
