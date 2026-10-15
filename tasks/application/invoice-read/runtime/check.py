"""Trusted independent verifier. Never imports or executes submitted app.py."""

import hashlib
import hmac
import json
import os
import re
import stat
import time
from pathlib import Path

import httpx
import psycopg
from psycopg import sql
from reference import verify


def file_hash(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("non-regular submission")
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("oversized submission")
    return hashlib.sha256(data).hexdigest()


def setup(password):
    with psycopg.connect("host=/dbsocket user=postgres dbname=postgres", autocommit=True) as conn:
        conn.execute(
            sql.SQL(
                "CREATE ROLE invoice_runtime LOGIN PASSWORD {} "
                "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION"
            ).format(sql.Literal(password))
        )
        conn.execute("""
            REVOKE ALL ON DATABASE postgres FROM PUBLIC;
            GRANT CONNECT ON DATABASE postgres TO invoice_runtime;
            REVOKE CREATE ON SCHEMA public FROM PUBLIC;
            GRANT USAGE ON SCHEMA public TO invoice_runtime;
            CREATE TABLE invoices (id integer PRIMARY KEY, tenant_id text NOT NULL,
                description text NOT NULL, amount_cents integer NOT NULL CHECK (amount_cents >= 0));
            INSERT INTO invoices VALUES
                (1, 'org-a', 'A consulting', 1200), (2, 'org-a', 'A support', 3400),
                (3, 'org-b', 'B consulting', 5600), (4, 'org-b', 'B support', 7800);
            ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
            ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
            GRANT SELECT ON invoices TO invoice_runtime;
            CREATE POLICY tenant_read ON invoices FOR SELECT TO invoice_runtime
                USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''));
        """)


def main():
    output = Path("/logs/verifier")
    for name in ("reward.json", "reward.txt", "application-evidence.json"):
        try:
            (output / name).unlink()
        except FileNotFoundError:
            pass
    nonce = os.environ.get("DS_NONCE", "")
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise ValueError("verifier nonce missing")
    actual = file_hash("/candidate/app.py")
    if actual != Path("/tests/expected.sha256").read_text().strip():
        raise ValueError("transferred submission differs from runtime image input")
    setup(os.environ["DS_RUNTIME_PASSWORD"])
    with httpx.Client(
        base_url="http://application",
        transport=httpx.HTTPTransport(uds="/appsock/app.sock"),
        timeout=5,
        trust_env=False,
    ) as client:
        for _ in range(120):
            try:
                if client.get("/health").status_code == 200:
                    break
            except httpx.TransportError:
                pass
            time.sleep(0.5)
        else:
            raise ValueError("application HTTP readiness failed")
        result = verify(client, os.environ["REFERENCE_DATABASE_URL"])
    payload = {
        "schema_version": 1,
        "app_sha256": actual,
        "result": result,
        "reward": int(result["outcome"] == "pass"),
    }
    mac = hmac.new(
        nonce.encode(),
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()
    evidence = {**payload, "mac": mac}
    for name, content in (
        ("application-evidence.json", json.dumps(evidence, sort_keys=True)),
        ("reward.txt", str(payload["reward"])),
    ):
        fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w") as stream:
            stream.write(content)


if __name__ == "__main__":
    main()
