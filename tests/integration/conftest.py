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

    name = "ds_test_" + uuid.uuid4().hex
    role = name + "_runtime"
    password = secrets.token_hex(24)
    admin = psycopg.connect(dsn, autocommit=True, connect_timeout=5)
    try:
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOBYPASSRLS "
                "NOCREATEDB NOCREATEROLE NOREPLICATION"
            ).format(sql.Identifier(role), sql.Literal(password))
        )
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        settings = conninfo_to_dict(dsn)
        settings["dbname"] = name
        setup_dsn = make_conninfo(**settings)
        settings.update(user=role, password=password)
        runtime_dsn = make_conninfo(**settings)
        with psycopg.connect(setup_dsn, autocommit=True) as setup:
            setup.execute(
                sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(name))
            )
            setup.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(name), sql.Identifier(role)
                )
            )
            setup.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            setup.execute(
                sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role))
            )
            setup.execute("""
                CREATE TABLE public.invoices (
                    id integer PRIMARY KEY, tenant_id text NOT NULL,
                    description text NOT NULL,
                    amount_cents integer NOT NULL CHECK (amount_cents >= 0)
                );
                INSERT INTO public.invoices VALUES
                    (1, 'org-a', 'A consulting', 1200), (2, 'org-a', 'A support', 3400),
                    (3, 'org-b', 'B consulting', 5600), (4, 'org-b', 'B support', 7800);
                ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
                ALTER TABLE public.invoices FORCE ROW LEVEL SECURITY;
            """)
            setup.execute(
                sql.SQL("GRANT SELECT ON public.invoices TO {}").format(sql.Identifier(role))
            )
            setup.execute(
                sql.SQL("""
                CREATE POLICY tenant_read ON public.invoices FOR SELECT TO {}
                USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
            """).format(sql.Identifier(role))
            )
        yield SimpleNamespace(admin=setup_dsn, runtime=runtime_dsn, role=role)
    finally:
        # Only this fixture's random database/role is targeted.
        admin.execute(
            sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
        )
        admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        admin.close()


@pytest.fixture
def serve(tmp_path):
    @contextmanager
    def start(runtime_dsn):
        import httpx

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
                    "democratize_security.reference.app:create_app",
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
