"""Materialize one sealed Python application without importing or executing it.

Execution containment belongs to the runner, not this byte-transfer helper.
Only use a fresh destination under a controller-owned parent directory.
"""

import base64
from pathlib import Path

from democratize_security.artifacts import validate


def materialize_application(bundle: dict, destination: Path) -> str:
    summary = validate(bundle)
    if summary["paths"] != ["app.py"]:
        raise ValueError("Application task requires exactly app.py")
    data = base64.b64decode(bundle["files"][0]["content_base64"], validate=True)
    destination.mkdir(exist_ok=False)
    destination.chmod(0o755)
    target = destination / "app.py"
    with target.open("xb") as stream:
        stream.write(data)
    target.chmod(0o444)
    return summary["artifact_sha256"]
