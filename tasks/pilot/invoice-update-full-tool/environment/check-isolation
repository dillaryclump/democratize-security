#!/opt/app/bin/python -I
"""full_tool self-check: grade `/candidate/app.py` against development data.

Installed as `/opt/tools/check-isolation` beside `fixture.py` and `verify.py` in
the full_tool agent image. It starts a private PostgreSQL cluster in `/tmp`
(Unix socket only; the agent container has no network), provisions the protected
fixture with the DEVELOPMENT dataset, serves the candidate's `create_app()` on
loopback, runs the same v4 probes as the grader, prints one line per check and
stops everything. It never uses the grading data and never prints response
bodies, SQL or connection details. Exit status is 0 only if every check passes.
"""

import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

try:  # Inside the package; the image copies fixture.py and verify.py beside this file.
    from democratize_security.pilot.fixture import DEVELOPMENT, provision
    from democratize_security.pilot.verify import verify
except ImportError:  # pragma: no cover - exercised in the full_tool image
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from fixture import DEVELOPMENT, provision
    from verify import verify

PG_BIN = Path("/usr/lib/postgresql/15/bin")
CLUSTER = Path("/tmp/ci-pg")
SOCKET = Path("/tmp/ci-sock")
CANDIDATE = Path("/candidate/app.py")
# Only fixed verifier messages or exception type names are ever echoed.
_SAFE_DETAIL = re.compile(r"[A-Za-z][A-Za-z ',/-]{0,120}")
_LABELS = {"pass": "PASS", "fail": "FAIL", "not_evaluated": "ERROR"}


def render(report: dict) -> list[str]:
    lines = []
    for check in report["checks"]:
        line = f"{_LABELS.get(check['outcome'], 'ERROR')} {check['id']}"
        detail = check.get("detail") or ""
        if check["outcome"] != "pass" and _SAFE_DETAIL.fullmatch(detail):
            line += f": {detail}"
        lines.append(line)
    return lines


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def check(app_path: Path, admin_dsn: str, python: str = sys.executable) -> dict:
    """Provision development data, serve the app, run the v4 probes, clean up."""
    name = "ci_" + uuid.uuid4().hex[:16]
    role, password = name + "_runtime", secrets.token_hex(16)
    setup = provision(admin_dsn, name, role, password, fixture="protected", dataset=DEVELOPMENT)
    settings = conninfo_to_dict(setup)
    settings.update(user=role, password=password)
    runtime_dsn = make_conninfo(**settings)
    port = _free_port()
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "REFERENCE_DATABASE_URL": runtime_dsn,
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    process = subprocess.Popen(
        [
            python,
            "-m",
            "uvicorn",
            f"{Path(app_path).stem}:create_app",
            "--factory",
            "--app-dir",
            str(Path(app_path).parent),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "critical",
            "--no-access-log",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        with httpx.Client(
            base_url=f"http://127.0.0.1:{port}", timeout=5, trust_env=False
        ) as client:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    if client.get("/health").status_code == 200:
                        break
                except httpx.TransportError:
                    time.sleep(0.1)
            return verify(client, runtime_dsn, fixture="protected", dataset=DEVELOPMENT)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        with psycopg.connect(admin_dsn, autocommit=True, connect_timeout=5) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )
            admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


def _cluster() -> str:
    """Start a private cluster owned by this user; return its admin DSN."""
    for path in (CLUSTER, SOCKET):
        shutil.rmtree(path, ignore_errors=True)
    SOCKET.mkdir(mode=0o700)
    subprocess.run(
        [
            PG_BIN / "initdb",
            "-D",
            CLUSTER,
            "-U",
            "ciadmin",
            "--auth=trust",
            "--encoding=UTF8",
            "--locale=C",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=120,
    )
    subprocess.run(
        [
            PG_BIN / "pg_ctl",
            "-D",
            CLUSTER,
            "-l",
            CLUSTER / "server.log",
            "-w",
            "-o",
            f"-c listen_addresses='' -c unix_socket_directories={SOCKET}",
            "start",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=120,
    )
    return f"host={SOCKET} dbname=postgres user=ciadmin"


def main() -> int:
    try:
        admin_dsn = _cluster()
    except (OSError, subprocess.SubprocessError) as error:
        print(f"ERROR setup: {type(error).__name__}")
        return 2
    try:
        report = check(CANDIDATE, admin_dsn)
    except Exception as error:  # Never echo messages that might contain data.
        print(f"ERROR setup: {type(error).__name__}")
        return 2
    finally:
        subprocess.run(
            [PG_BIN / "pg_ctl", "-D", CLUSTER, "-m", "immediate", "stop"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
        shutil.rmtree(CLUSTER, ignore_errors=True)
        shutil.rmtree(SOCKET, ignore_errors=True)
    for line in render(report):
        print(line)
    print("ALL PASS" if report["outcome"] == "pass" else f"RESULT {report['outcome']}")
    return 0 if report["outcome"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
