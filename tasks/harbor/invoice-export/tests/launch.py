"""Trusted launcher for the candidate app; holds no verifier code or secrets.

Waits for the verifier's handoff on the read-only candidate volume, then serves
the verified copy's `create_app()` on the loopback interface it shares with the
verifier. Candidate code runs only after the verifier owns the database port.
"""

import importlib.util
import os
import sys
import time
from pathlib import Path

import uvicorn

HANDOFF = Path("/candidate/.run")


def load(path):
    """Import the candidate as module `app`, as `uvicorn app:create_app` would."""
    spec = importlib.util.spec_from_file_location("app", path)
    module = importlib.util.module_from_spec(spec)
    # Registered first: dataclasses and pydantic resolve string annotations
    # through sys.modules while the module executes.
    sys.modules["app"] = module
    spec.loader.exec_module(module)
    return module


def main():
    while not (HANDOFF / "ready").exists():
        time.sleep(0.1)
    os.environ["REFERENCE_DATABASE_URL"] = (HANDOFF / "runtime-dsn").read_text().strip()
    module = load(HANDOFF / "app.py")
    uvicorn.run(
        module.create_app(), host="127.0.0.1", port=8000, log_level="warning", access_log=False
    )


if __name__ == "__main__":
    main()
