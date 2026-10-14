"""Independent HTTP/database checks for the fixed synthetic reference contract.

Does not import the app or accept candidate-authored grades. This public oracle
is intentionally narrow and is not a protected holdout evaluator.
"""

import argparse
import csv
import io
import json
import os
from dataclasses import asdict, dataclass

import httpx
import psycopg

REQUIRED = frozenset(
    {
        "database_configuration",
        "authorized_reads",
        "foreign_reads",
        "list_search",
        "exports",
        "identity",
        "spoofing",
        "tenant_switching",
    }
)
EXPECTED = {
    "fixture-alice": [
        {"id": 1, "description": "A consulting", "amount_cents": 1200},
        {"id": 2, "description": "A support", "amount_cents": 3400},
    ],
    "fixture-bob": [
        {"id": 3, "description": "B consulting", "amount_cents": 5600},
        {"id": 4, "description": "B support", "amount_cents": 7800},
    ],
}


@dataclass(frozen=True)
class Check:
    id: str
    outcome: str
    detail: str = ""


def summarize(checks: list[Check]) -> dict:
    ids = [check.id for check in checks]
    complete = (
        set(ids) == REQUIRED
        and len(ids) == len(REQUIRED)
        and all(c.outcome in {"pass", "fail"} for c in checks)
    )
    return {
        "schema_version": 1,
        "protocol": "synthetic-reference-v2",
        "coverage": "complete" if complete else "incomplete",
        "outcome": ("pass" if all(c.outcome == "pass" for c in checks) else "fail")
        if complete
        else "incomplete",
        "checks": [asdict(c) for c in checks],
    }


def _require(condition: bool, detail: str):
    if not condition:
        raise AssertionError(detail)


def verify(client: httpx.Client, runtime_dsn: str) -> dict:
    def get(path, token="fixture-alice", **kwargs):
        return client.get(path, headers={"Authorization": f"Bearer {token}"}, **kwargs)

    def configuration():
        with psycopg.connect(runtime_dsn, connect_timeout=5) as connection:
            role = connection.execute("""
                SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication
                FROM pg_roles WHERE rolname = current_user
            """).fetchone()
            _require(role == (False,) * 5, "Runtime role has privileged capabilities")
            memberships = connection.execute("""
                SELECT count(*) FROM pg_auth_members
                WHERE member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
            """).fetchone()[0]
            _require(memberships == 0, "Runtime role has inherited/settable roles")
            table = connection.execute("""
                SELECT relrowsecurity, relforcerowsecurity,
                       relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
                FROM pg_class WHERE oid = 'public.invoices'::regclass
            """).fetchone()
            _require(table == (True, True, False), "RLS/owner configuration is unsafe")
            _require(
                connection.execute("""
                SELECT count(*) FROM pg_policies
                WHERE schemaname = 'public' AND tablename = 'invoices'
            """).fetchone()[0]
                == 1,
                "Expected exactly one reviewed invoice policy",
            )
            _require(
                connection.execute("""
                SELECT has_table_privilege(current_user, 'public.invoices', 'SELECT'),
                       has_table_privilege(current_user, 'public.invoices',
                         'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'),
                       has_schema_privilege(current_user, 'public', 'CREATE'),
                       has_database_privilege(current_user, current_database(), 'CREATE')
            """).fetchone()
                == (True, False, False, False),
                "Runtime privileges are not read-only",
            )
            # Missing context must default deny even for the runtime connection.
            _require(
                connection.execute("SELECT count(*) FROM public.invoices").fetchone()[0] == 0,
                "Missing tenant context exposes rows",
            )

    def authorized():
        for token, invoices in EXPECTED.items():
            for invoice in invoices:
                response = get(f"/invoices/{invoice['id']}", token)
                _require(
                    response.status_code == 200 and response.json() == invoice,
                    "Authorized invoice is missing or altered",
                )

    def foreign():
        for token, other in (("fixture-alice", "fixture-bob"), ("fixture-bob", "fixture-alice")):
            for invoice in EXPECTED[other]:
                response = get(f"/invoices/{invoice['id']}", token)
                _require(
                    response.status_code == 404
                    and response.json() == {"detail": "Invoice not found"},
                    "Foreign invoice request not safely denied",
                )
            missing = get("/invoices/999999", token)
            _require(
                missing.status_code == 404 and missing.json() == {"detail": "Invoice not found"},
                "Missing/foreign responses differ",
            )

    def lists():
        for token, invoices in EXPECTED.items():
            for path, expected in (
                ("/invoices", invoices),
                ("/invoices?q=consulting", invoices[:1]),
                ("/invoices?limit=1&offset=1", invoices[1:]),
                ("/invoices?q=no-such-invoice", []),
                ("/invoices?q=%27%20OR%201%3D1--", []),
            ):
                response = get(path, token)
                _require(
                    response.status_code == 200 and response.json() == expected,
                    "List/search/pagination returned unexpected records",
                )

    def exports():
        for token, invoices in EXPECTED.items():
            response = get("/invoices/export", token)
            _require(response.status_code == 200, "Export failed")
            reader = csv.DictReader(io.StringIO(response.text))
            _require(
                reader.fieldnames == ["id", "description", "amount_cents"], "Unexpected CSV fields"
            )
            expected = [{k: str(v) for k, v in row.items()} for row in invoices]
            _require(list(reader) == expected, "Export missing authorized or exposing foreign data")

    def identity():
        for path in ("/invoices", "/invoices/1", "/invoices/export"):
            for headers in (
                {"Authorization": "Bearer"},
                {"Authorization": "Basic fixture-alice"},
                {"Authorization": "Bearer  fixture-alice"},
                {"Authorization": "Bearer fixture-alice, Bearer fixture-bob"},
                [
                    ("Authorization", "Bearer fixture-alice"),
                    ("Authorization", "Bearer fixture-bob"),
                ],
                [
                    ("Authorization", "Bearer fixture-bob"),
                    ("Authorization", "Bearer fixture-alice"),
                ],
                [
                    ("Authorization", "Bearer fixture-alice"),
                    ("Authorization", "Bearer fixture-alice"),
                ],
            ):
                response = client.get(path, headers=headers)
                _require(
                    response.status_code == 401
                    and response.json() == {"detail": "Authentication required"},
                    "Ambiguous authentication accepted",
                )
            for response, status, detail in (
                (client.get(path), 401, "Authentication required"),
                (get(path, "invalid"), 401, "Authentication required"),
                (get(path, "fixture-unassigned"), 403, "Organization membership required"),
            ):
                _require(
                    response.status_code == status and response.json() == {"detail": detail},
                    "Untrusted or unassigned identity received unexpected response",
                )

    def spoofing():
        response = client.get(
            "/invoices?tenant_id=org-b",
            headers={"Authorization": "Bearer fixture-alice", "X-Tenant-ID": "org-b"},
        )
        _require(
            response.status_code == 200 and response.json() == EXPECTED["fixture-alice"],
            "Client tenant input changed effective identity",
        )

    def switching():
        for token in ("fixture-alice", "fixture-bob") * 4:
            response = get("/invoices", token)
            _require(
                response.status_code == 200 and response.json() == EXPECTED[token],
                "Tenant context leaked between requests",
            )

    checks = []
    for name, callback in (
        ("database_configuration", configuration),
        ("authorized_reads", authorized),
        ("foreign_reads", foreign),
        ("list_search", lists),
        ("exports", exports),
        ("identity", identity),
        ("spoofing", spoofing),
        ("tenant_switching", switching),
    ):
        try:
            callback()
            checks.append(Check(name, "pass"))
        except AssertionError as error:
            checks.append(Check(name, "fail", str(error)))
        except Exception as error:
            # Do not persist connection strings, response bodies or secret-bearing errors.
            checks.append(Check(name, "not_evaluated", type(error).__name__))
    return summarize(checks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Loopback reference app URL")
    args = parser.parse_args()
    dsn = os.environ.get("REFERENCE_DATABASE_URL")
    if not dsn:
        parser.error("REFERENCE_DATABASE_URL is required (restricted runtime identity)")
    with httpx.Client(base_url=args.url, timeout=5, trust_env=False) as client:
        result = verify(client, dsn)
    print(json.dumps(result, indent=2))
    return 0 if result["outcome"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
