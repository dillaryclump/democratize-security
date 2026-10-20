"""Finite Linux-only host proof; no model calls and no Docker workload launch.

Run as the configured unprivileged controller after manual host installation.
It deliberately exits a child after preparation, then inspects the same mount,
proves ENOSPC, archives the synthetic bytes and releases only that job.
"""

import errno
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

HELPER = "/usr/local/libexec/ds-worker-host"
CAPACITY = 64 * 1024 * 1024


def command(action, parent, name):
    return ["sudo", "-n", HELPER, action, str(parent), name]


def call(action, parent, name):
    return json.loads(
        subprocess.run(
            command(action, parent, name), check=True, capture_output=True, text=True, timeout=90
        ).stdout
    )


def main():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise SystemExit("requires the configured non-root controller on dedicated Linux")
    checkout = Path(__file__).resolve().parents[2]
    parent = checkout / ".research/worker-host-check"
    parent.mkdir(parents=True, exist_ok=True)
    name = "check-" + uuid.uuid4().hex
    # The child disappears after the actual trusted helper's acknowledged mount.
    script = "import os,subprocess,sys; subprocess.run(sys.argv[1:],check=True); os._exit(17)"
    child = subprocess.run(
        [sys.executable, "-I", "-c", script, *command("prepare", parent, name)], timeout=90
    )
    if child.returncode != 17:
        raise ValueError("crash control did not reach preparation")
    observed = call("inspect", parent, name)
    if observed["status"] != "mounted" or not 0 < observed["capacity_bytes"] <= CAPACITY:
        raise ValueError("bounded mount missing after controller crash")
    duplicate = subprocess.run(command("prepare", parent, name), capture_output=True, timeout=90)
    if duplicate.returncode == 0:
        raise ValueError("stale job preparation was accepted")
    total = 0
    descriptor = os.open(
        parent / name / "synthetic-fill.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
    )
    try:
        while total <= CAPACITY:
            try:
                total += os.write(descriptor, b"x" * 65536)
            except OSError as error:
                if error.errno != errno.ENOSPC:
                    raise
                break
        else:
            raise ValueError("filesystem failed to enforce its bound")
    finally:
        os.close(descriptor)
    if not 0 < total <= CAPACITY:
        raise ValueError("unexpected overflow-control byte count")
    archive = call("archive", parent, name)
    released = call("release", parent, name)
    if os.path.ismount(parent / name) or released["status"] != "released":
        raise ValueError("job was not released")
    report = {
        "schema_version": 1,
        "control": "synthetic_host_storage",
        "mount": observed,
        "bounded_write_bytes": total,
        "stale_preparation_rejected": True,
        "archive": archive,
        "released": released,
        "model_calls": 0,
        "security_verdict": "not_evaluated",
    }
    report_path = parent / (name + ".json")
    with report_path.open("x") as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
