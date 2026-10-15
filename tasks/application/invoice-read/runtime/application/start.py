"""Trusted launcher: wait for the restricted DB, then run code only in this container."""

import os
import time

import psycopg

for _ in range(120):
    try:
        with psycopg.connect(os.environ["REFERENCE_DATABASE_URL"], connect_timeout=2) as connection:
            connection.execute("SELECT id FROM invoices LIMIT 1")
        break
    except psycopg.Error:
        time.sleep(0.5)
else:
    raise SystemExit("application database readiness failed")
os.execvp(
    "python",
    [
        "python",
        "-B",
        "-m",
        "uvicorn",
        "app:create_app",
        "--factory",
        "--uds",
        "/appsock/app.sock",
        "--no-access-log",
    ],
)
