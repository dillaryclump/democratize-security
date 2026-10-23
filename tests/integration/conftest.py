"""Disposable database and separate reference process, never a production DSN."""

import os
import secrets
import socket
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from types import SimpleNamespace

import pytest


@pytest.fixture
def database():
    dsn = os.environ.get("TEST_POSTGRES_ADMIN_DSN")
    if not dsn:
        if os.environ.get("REQUIRE_POSTGRES_TESTS") == "1":
            pytest.fail("TEST_POSTGRES_ADMIN_DSN is required in the integration gate")
        pytest.skip("Set TEST_POSTGRES_ADMIN_DSN for disposable PostgreSQL integration tests")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    from democratize_security.verification.fixture import provision

    name = "ds_test_" + uuid.uuid4().hex
    role = name + "_runtime"
    password = secrets.token_hex(24)
    admin = psycopg.connect(dsn, autocommit=True, connect_timeout=5)
    try:
        setup_dsn = provision(dsn, name, role, password)
        settings = conninfo_to_dict(setup_dsn)
        settings.update(user=role, password=password)
        runtime_dsn = make_conninfo(**settings)
        yield SimpleNamespace(admin=setup_dsn, runtime=runtime_dsn, role=role)
    finally:
        # Only this fixture's random database/role is targeted.
        admin.execute(
            sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
        )
        admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        admin.close()


@pytest.fixture
def pilot_database():
    """Factory: a disposable pilot database for one fixture variant and dataset."""
    dsn = os.environ.get("TEST_POSTGRES_ADMIN_DSN")
    if not dsn:
        if os.environ.get("REQUIRE_POSTGRES_TESTS") == "1":
            pytest.fail("TEST_POSTGRES_ADMIN_DSN is required in the integration gate")
        pytest.skip("Set TEST_POSTGRES_ADMIN_DSN for disposable PostgreSQL integration tests")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    from democratize_security.pilot import fixture as pilot_fixture

    created = []

    def make(kind, dataset=None):
        name = "ds_pilot_" + uuid.uuid4().hex
        role = name + "_runtime"
        password = secrets.token_hex(24)
        created.append((name, role))
        setup_dsn = pilot_fixture.provision(
            dsn, name, role, password, fixture=kind, dataset=dataset or pilot_fixture.GRADING
        )
        settings = conninfo_to_dict(setup_dsn)
        settings.update(user=role, password=password)
        return SimpleNamespace(admin=setup_dsn, runtime=make_conninfo(**settings), role=role)

    yield make
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as admin:
        for name, role in created:
            # Only this fixture's random databases and roles are targeted.
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )
            admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


@pytest.fixture
def serve(tmp_path):
    @contextmanager
    def start(runtime_dsn, app_file=None):
        import httpx

        target = ["democratize_security.reference.app:create_app"]
        if app_file is not None:
            # A task starter, oracle or reviewed control, loaded from a fresh copy.
            directory = tmp_path / uuid.uuid4().hex
            directory.mkdir()
            (directory / "app.py").write_bytes(app_file.read_bytes())
            target = ["app:create_app", "--app-dir", str(directory)]
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT") if k in os.environ}
        env["REFERENCE_DATABASE_URL"] = runtime_dsn
        with (tmp_path / "reference.log").open("w+") as log:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    *target,
                    "--factory",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--no-access-log",
                ],
                env=env,
                stdout=log,
                stderr=log,
            )
            try:
                with httpx.Client(
                    base_url=f"http://127.0.0.1:{port}", timeout=5, trust_env=False
                ) as client:
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            pytest.fail("Reference process exited before readiness")
                        try:
                            if client.get("/health").status_code == 200:
                                break
                        except httpx.TransportError:
                            pass
                        time.sleep(0.05)
                    else:
                        pytest.fail("Reference process readiness timed out")
                    yield client
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    return start
