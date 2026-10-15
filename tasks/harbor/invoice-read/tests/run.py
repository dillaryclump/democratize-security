"""Trusted orchestrator for the separate application verifier.

Runs as the unprivileged verifier user beside a private PostgreSQL cluster. It
provisions a fresh synthetic database, hands the candidate only a restricted
runtime DSN and a validated copy of its app through the verifier-owned candidate
volume, and grades the app over loopback HTTP with the public reference
protocol. Candidate code runs only in the separate `app` container; this process
never imports or executes it.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import time
from pathlib import Path

# Isolated mode drops the script directory; the reviewed modules live beside it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx  # noqa: E402
from fixture import provision  # noqa: E402
from psycopg.conninfo import make_conninfo  # noqa: E402
from verify import PROTOCOL, REQUIRED, verify  # noqa: E402

# Supplied only to this verifier's exec by the controller (`harbor run --ve`).
NONCE = "DS_NONCE"
GRADES = ("reward.json", "reward.txt", "app-evidence.json")
CANDIDATE = Path("/candidate/app.py")
HANDOFF = Path("/candidate/.run")
MAX_BYTES = 65536
ADMIN_DSN = "host=/tmp/app-socket dbname=postgres user=postgres"
DATABASE, ROLE = "ds_app", "ds_runtime"
APP_URL = "http://127.0.0.1:8000"
READY_SECONDS = 60


def evidence_mac(nonce, payload):
    """Bind evidence to this run; neither the agent nor the app sees the nonce."""
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(nonce.encode(), data, hashlib.sha256).hexdigest()


def write_new(path, data, mode=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)


def read_candidate(path=CANDIDATE):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("candidate must be a regular file")
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("candidate too large")
    raw.decode("utf-8")
    return raw


def hand_off(raw, runtime_dsn, handoff=HANDOFF):
    """Publish exactly the validated bytes and the runtime DSN, readiness last."""
    handoff.mkdir()
    os.chmod(handoff, 0o755)
    write_new(handoff / "app.py", raw, 0o444)
    write_new(handoff / "runtime-dsn", runtime_dsn.encode(), 0o444)
    write_new(handoff / "ready", b"", 0o444)


def wait_until_ready(client, seconds=READY_SECONDS):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if client.get("/health").status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    return False


def grade(raw, handoff=HANDOFF, admin_dsn=ADMIN_DSN, url=APP_URL):
    if raw is None:
        return {"app_started": False, "outcome": "invalid_submission", "result": None}
    password = secrets.token_hex(24)
    # Infrastructure failures propagate: no reward is emitted.
    provision(admin_dsn, DATABASE, ROLE, password)
    runtime_dsn = make_conninfo(
        host="127.0.0.1",
        port=5432,
        dbname=DATABASE,
        user=ROLE,
        password=password,
        connect_timeout=5,
    )
    hand_off(raw, runtime_dsn, handoff)
    with httpx.Client(base_url=url, timeout=5, trust_env=False) as client:
        if not wait_until_ready(client):
            return {"app_started": False, "outcome": "app_not_started", "result": None}
        result = verify(client, runtime_dsn)
    return {"app_started": True, "outcome": result["outcome"], "result": result}


def main(output=Path("/logs/verifier"), environ=os.environ, candidate=CANDIDATE, **options):
    # The agent could write this shared directory. Never grade on top of a
    # planted file; unlinking removes a planted link without following it.
    for name in GRADES:
        try:
            os.unlink(output / name)
        except FileNotFoundError:
            pass
    nonce = environ.get(NONCE, "")
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        # Infrastructure failure: no reward is emitted.
        raise SystemExit("verifier nonce missing")
    try:
        raw = read_candidate(candidate)
    except (OSError, ValueError, UnicodeError):
        raw = None
    graded = grade(raw, **options)
    result = graded["result"]
    checks = (
        {check["id"]: check["outcome"] for check in result["checks"]}
        if result
        else dict.fromkeys(sorted(REQUIRED), "not_evaluated")
    )
    reward = 1 if graded["outcome"] == "pass" else 0
    payload = {
        "schema_version": 3,
        "protocol": PROTOCOL,
        "artifact_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
        "app_started": graded["app_started"],
        "coverage": result["coverage"] if result else "incomplete",
        "outcome": graded["outcome"],
        "checks": checks,
        # Fixed reviewed messages or exception type names only.
        "details": {c["id"]: c["detail"] for c in result["checks"] if c["detail"]}
        if result
        else {},
        "reward": reward,
    }
    evidence = {**payload, "mac": evidence_mac(nonce, payload)}
    write_new(output / "app-evidence.json", json.dumps(evidence, sort_keys=True).encode())
    write_new(output / "reward.txt", str(reward).encode())


if __name__ == "__main__":
    main()
