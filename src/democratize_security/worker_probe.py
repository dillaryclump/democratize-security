"""Offline Docker capability probe, not a Harbor adapter or security grader.

Requires a trusted local Linux Docker daemon and preloaded trusted Python image.
Only reviewed synthetic programs may be used until the worker-host gate passes.
"""

import base64
import hashlib
import json
import os
import re
import selectors
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from democratize_security.artifacts import validate

DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]


class WorkerError(RuntimeError):
    """Infrastructure failure; never a security verdict."""


def _docker(*args: str) -> str:
    result = subprocess.run([*DOCKER, *args], capture_output=True, timeout=15, check=False)
    if result.returncode:
        # Do not surface daemon errors that may contain environment details.
        raise WorkerError(f"Docker {args[0]} failed")
    return result.stdout.decode()


def _capture(name: str, timeout: float, limit: int) -> tuple[str, bytes]:
    process = subprocess.Popen(
        [*DOCKER, "start", "--attach", name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    output = bytearray()
    reason = "exited"
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.1)):
                    data = os.read(key.fileobj.fileno(), min(65536, limit + 1 - len(output)))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(data)
                    if len(output) > limit:
                        reason = "output_limit"
                        break
                if reason != "exited":
                    break
            if reason == "exited":
                try:
                    process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    reason = "timeout"
        if reason != "exited":
            _docker("kill", name)
        return reason, bytes(output[:limit])
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        process.stdout.close()


def run_probe(
    bundle: dict, image_id: str, *, timeout_seconds: int = 5, output_limit: int = 65536
) -> dict:
    """Execute main.py in a fresh restricted container, then remove the container.

    A zero exit code means program exit only. Output is untrusted bytes, never
    an authoritative verification result. No host environment is forwarded.
    """
    summary = validate(bundle)
    if "main.py" not in summary["paths"]:
        raise ValueError("Probe requires an allowlisted main.py")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("A preloaded immutable local image ID is required")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
        raise ValueError("Timeout must be 1–60 seconds")
    if type(output_limit) is not int or not 1 <= output_limit <= 1024 * 1024:
        raise ValueError("Output limit must be 1 byte–1 MiB")
    image = json.loads(_docker("image", "inspect", image_id))[0]
    if image["Id"] != image_id or image.get("Os") != "linux" or image["Config"].get("Volumes"):
        raise WorkerError("Image must be Linux, match its ID and declare no implicit volumes")
    name = "ds-probe-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="ds-probe-") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        for entry in bundle["files"]:
            target = root / entry["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(base64.b64decode(entry["content_base64"], validate=True))
            target.chmod(0o444)
        # A new controller-owned directory plus previously validated paths
        # avoids materializing into a candidate-owned directory tree.
        created = False
        try:
            created = True  # Cleanup also covers a create timeout with uncertain outcome.
            _docker(
                "create",
                "--name",
                name,
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--user",
                "65534:65534",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "32",
                "--memory",
                "128m",
                "--memory-swap",
                "128m",
                "--cpus",
                "0.5",
                "--ulimit",
                "nofile=64:64",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                "--shm-size",
                "1m",
                "--log-driver",
                "none",
                "--no-healthcheck",
                "--restart",
                "no",
                "--workdir",
                "/candidate",
                "--mount",
                f"type=bind,src={root},dst=/candidate,readonly",
                "--entrypoint",
                "/usr/bin/env",
                image_id,
                "-i",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "python",
                "-I",
                "-B",
                "/candidate/main.py",
            )
            before = json.loads(_docker("inspect", name))[0]
            started = time.monotonic()
            reason, output = _capture(name, timeout_seconds, output_limit)
            after = json.loads(_docker("inspect", name))[0]
            if after["State"]["Running"]:
                raise WorkerError("Worker did not stop")
            if not after["State"].get("StartedAt", "").startswith("20"):
                raise WorkerError("Worker never started")
            # Re-read controller-owned bytes after execution to catch tampering.
            for entry in bundle["files"]:
                if (
                    hashlib.sha256((root / entry["path"]).read_bytes()).hexdigest()
                    != entry["sha256"]
                ):
                    raise WorkerError("Staged artifact changed")
            return {
                "schema_version": 1,
                "kind": "execution_probe",
                "artifact_sha256": summary["artifact_sha256"],
                "image_id": image_id,
                "container_id": before["Id"],
                "container_name": name,
                "host_config": {
                    key: before["HostConfig"][key]
                    for key in (
                        "NetworkMode",
                        "ReadonlyRootfs",
                        "Memory",
                        "MemorySwap",
                        "NanoCpus",
                        "PidsLimit",
                        "CapDrop",
                        "SecurityOpt",
                    )
                },
                "termination": reason,
                "exit_code": after["State"]["ExitCode"],
                "oom_killed": after["State"]["OOMKilled"],
                "elapsed_seconds": time.monotonic() - started,
                "output_base64": base64.b64encode(output).decode(),
                "output_truncated": reason == "output_limit",
                "security_verdict": "not_evaluated",
            }
        finally:
            if created:
                # If cleanup fails, raise instead of returning an apparently
                # successful record with an unaccounted-for running container.
                _docker("rm", "--force", name)
