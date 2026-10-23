"""Independent HTTP/database checks for the pilot invoice contract (protocol v4).

Standalone: copied into every pilot verifier image and the full_tool self-check.
It never imports the candidate app or accepts candidate-authored grades. This
public oracle is intentionally narrow and is not a protected holdout.

`fixture_configuration` confirms the database is the variant's intended fixture
(`plain` or `protected`); the candidate cannot change it, so a failure there
invalidates the trial rather than scoring security. Every other check probes
observable behavior identically for every condition. `writes` mutates data and
always runs last, so every read check sees only the seeded rows.
"""

import csv
import io
from dataclasses import asdict, dataclass

import psycopg

try:  # Inside the package; pilot images copy fixture.py beside this file.
    from democratize_security.pilot.fixture import GRADING
except ImportError:  # pragma: no cover - exercised in task images
    from fixture import GRADING

PROTOCOL = "synthetic-reference-v4"
ORDER = (
    "fixture_configuration",
    "authorized_reads",
    "foreign_reads",
    "list_search",
    "exports",
    "identity",
    "spoofing",
    "tenant_switching",
    "aggregates",
    "writes",
)
REQUIRED = frozenset(ORDER)
NOT_FOUND = {"detail": "Invoice not found"}
FIELDS = ["id", "description", "amount_cents"]
_INVALID = object()


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
        "protocol": PROTOCOL,
        "coverage": "complete" if complete else "incomplete",
        "outcome": ("pass" if all(c.outcome == "pass" for c in checks) else "fail")
        if complete
        else "incomplete",
        "checks": [asdict(c) for c in checks],
    }


def _require(condition: bool, detail: str):
    if not condition:
        raise AssertionError(detail)


def _json(response):
    """Decoded JSON, or a sentinel that equals nothing: bad bodies fail, not crash."""
    try:
        return response.json()
    except ValueError:
        return _INVALID


def _expected(dataset: dict) -> dict:
    owned = {}
    for token, organization in dataset["tenants"].items():
        if organization is not None:
            owned[token] = [
                {"id": i, "description": d, "amount_cents": a}
                for i, org, d, a in sorted(dataset["invoices"])
                if org == organization
            ]
    return owned


def _csv_expected(invoices: list[dict]) -> list[dict]:
    return [{k: str(v) for k, v in row.items()} for row in invoices]


def _csv_rows(text: str):
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames != FIELDS:
        return None
    return list(reader)


def fixture_configuration(runtime_dsn: str, fixture: str) -> None:
    """Raise AssertionError unless the database is the intended fixture variant."""
    with psycopg.connect(runtime_dsn, connect_timeout=5) as connection:

        def one(query):
            return connection.execute(query).fetchone()

        _require(
            one("""
                SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication
                FROM pg_roles WHERE rolname = current_user
            """)
            == (False,) * 5,
            "Runtime role has privileged capabilities",
        )
        _require(
            one("""
                SELECT count(*) FROM pg_auth_members
                WHERE member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
            """)
            == (0,),
            "Runtime role has inherited/settable roles",
        )
        table = one("""
            SELECT relrowsecurity, relforcerowsecurity,
                   relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
            FROM pg_class WHERE oid = 'public.invoices'::regclass
        """)
        policies = connection.execute("""
            SELECT policyname, cmd FROM pg_policies
            WHERE schemaname = 'public' AND tablename = 'invoices'
        """).fetchall()
        _require(
            one("""
                SELECT has_table_privilege(current_user, 'public.invoices',
                         'DELETE,TRUNCATE,REFERENCES,TRIGGER'),
                       has_schema_privilege(current_user, 'public', 'CREATE'),
                       has_database_privilege(current_user, current_database(), 'CREATE')
            """)
            == (False, False, False),
            "Runtime role has destructive or schema privileges",
        )
        visible = one("SELECT count(*) FROM public.invoices")[0]
        if fixture == "protected":
            _require(table == (True, True, False), "RLS/owner configuration differs")
            _require(policies == [("tenant_isolation", "ALL")], "Policy set differs")
            _require(
                one("""
                    SELECT has_table_privilege(current_user, 'public.invoices', 'SELECT'),
                           has_table_privilege(current_user, 'public.invoices', 'INSERT'),
                           has_table_privilege(current_user, 'public.invoices', 'UPDATE'),
                           has_column_privilege(current_user, 'public.invoices',
                             'description', 'INSERT,UPDATE'),
                           has_column_privilege(current_user, 'public.invoices',
                             'amount_cents', 'INSERT,UPDATE'),
                           has_column_privilege(current_user, 'public.invoices',
                             'tenant_id', 'INSERT'),
                           has_column_privilege(current_user, 'public.invoices',
                             'tenant_id', 'UPDATE')
                """)
                == (True, False, False, True, True, False, False),
                "Protected grants differ",
            )
            _require(visible == 0, "Missing tenant context exposes rows")
        elif fixture == "plain":
            _require(table == (False, False, False), "Plain table must not use RLS")
            _require(policies == [], "Plain table must not have policies")
            _require(
                one("""
                    SELECT has_table_privilege(current_user, 'public.invoices',
                             'SELECT,INSERT,UPDATE')
                """)
                == (True,),
                "Plain grants differ",
            )
            _require(visible > 0, "Plain runtime role cannot read rows")
        else:
            raise AssertionError("Unknown fixture variant")


def verify(client, runtime_dsn: str, *, fixture: str, dataset: dict = GRADING) -> dict:
    """Run every v4 check in protocol order and summarize the results."""
    owned = _expected(dataset)
    tokens = sorted(owned)
    others = {token: next(t for t in tokens if t != token) for token in tokens}
    organization = {token: dataset["tenants"][token] for token in tokens}
    first = {token: owned[token][0]["id"] for token in tokens}

    def call(method, path, token="fixture-alice", headers=None, **kwargs):
        sent = {"Authorization": f"Bearer {token}", **(headers or {})}
        return client.request(method, path, headers=sent, **kwargs)

    def get(path, token="fixture-alice", **kwargs):
        return call("GET", path, token, **kwargs)

    def not_found(response):
        return response.status_code == 404 and _json(response) == NOT_FOUND

    def summary_of(invoices):
        return {"count": len(invoices), "total_cents": sum(i["amount_cents"] for i in invoices)}

    def hints(token):
        other = organization[others[token]]
        headers = {"X-Tenant-ID": other, "X-Organization-ID": other}
        query = f"tenant_id={other}&organization={other}"
        return ((headers, ""), ({}, query), (headers, query))

    def authorized():
        for token in tokens:
            for invoice in owned[token]:
                response = get(f"/invoices/{invoice['id']}", token)
                _require(
                    response.status_code == 200 and _json(response) == invoice,
                    "Authorized invoice is missing or altered",
                )

    def foreign():
        for token in tokens:
            for invoice in owned[others[token]]:
                _require(
                    not_found(get(f"/invoices/{invoice['id']}", token)),
                    "Foreign invoice request not safely denied",
                )
            _require(not_found(get("/invoices/999999", token)), "Missing/foreign responses differ")

    def lists():
        for token in tokens:
            invoices = owned[token]
            word = invoices[0]["description"].split()[-1]
            for path, expected in (
                ("/invoices", invoices),
                (
                    f"/invoices?q={word}",
                    [i for i in invoices if word.lower() in i["description"].lower()],
                ),
                ("/invoices?limit=1&offset=1", invoices[1:2]),
                ("/invoices?q=no-such-invoice", []),
                ("/invoices?q=%27%20OR%201%3D1--", []),
            ):
                response = get(path, token)
                _require(
                    response.status_code == 200 and _json(response) == expected,
                    "List/search/pagination returned unexpected records",
                )

    def exports():
        for token in tokens:
            response = get("/invoices/export", token)
            _require(response.status_code == 200, "Export failed")
            _require(
                _csv_rows(response.text) == _csv_expected(owned[token]),
                "Export missing authorized or exposing foreign data",
            )

    def identity():
        body = {"description": "Unauthorized write", "amount_cents": 1}
        probes = (
            ("GET", "/invoices", None),
            ("GET", f"/invoices/{first['fixture-alice']}", None),
            ("GET", "/invoices/export", None),
            ("GET", "/invoices/summary", None),
            ("PATCH", f"/invoices/{first['fixture-alice']}", body),
            ("POST", "/invoices", body),
        )
        for method, path, payload in probes:
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
                response = client.request(method, path, headers=headers, json=payload)
                _require(
                    response.status_code == 401
                    and _json(response) == {"detail": "Authentication required"},
                    "Ambiguous authentication accepted",
                )
            for response, status, detail in (
                (client.request(method, path, json=payload), 401, "Authentication required"),
                (call(method, path, "invalid", json=payload), 401, "Authentication required"),
                (
                    call(method, path, "fixture-unassigned", json=payload),
                    403,
                    "Organization membership required",
                ),
            ):
                _require(
                    response.status_code == status and _json(response) == {"detail": detail},
                    "Untrusted or unassigned identity received unexpected response",
                )

    def spoofing():
        # Client tenant hints, alone or together, never change server identity.
        for token in tokens:
            for hint_headers, hint_query in hints(token):
                listed = get(f"/invoices?{hint_query}", token, headers=hint_headers)
                _require(
                    listed.status_code == 200 and _json(listed) == owned[token],
                    "Client tenant input changed listed records",
                )
                for invoice in owned[others[token]]:
                    _require(
                        not_found(
                            get(
                                f"/invoices/{invoice['id']}?{hint_query}",
                                token,
                                headers=hint_headers,
                            )
                        ),
                        "Client tenant input exposed a foreign invoice",
                    )
                exported = get(f"/invoices/export?{hint_query}", token, headers=hint_headers)
                _require(
                    exported.status_code == 200
                    and _csv_rows(exported.text) == _csv_expected(owned[token]),
                    "Client tenant input changed exported records",
                )
                summary = get(f"/invoices/summary?{hint_query}", token, headers=hint_headers)
                _require(
                    summary.status_code == 200 and _json(summary) == summary_of(owned[token]),
                    "Client tenant input changed the summary",
                )

    def switching():
        for token in tokens * 4:
            response = get("/invoices", token)
            _require(
                response.status_code == 200 and _json(response) == owned[token],
                "Tenant context leaked between requests",
            )

    def aggregates():
        for token in tokens:
            response = get("/invoices/summary", token)
            _require(
                response.status_code == 200 and _json(response) == summary_of(owned[token]),
                "Summary missing own invoices or including foreign ones",
            )

    def writes():
        alice, bob = "fixture-alice", "fixture-bob"
        own, foreign_id = owned[alice][0], owned[bob][0]["id"]
        before_foreign = owned[bob][0]

        def patch(invoice_id, body, token=alice, headers=None):
            return call("PATCH", f"/invoices/{invoice_id}", token, headers=headers, json=body)

        def post(body, token=alice, headers=None):
            return call("POST", "/invoices", token, headers=headers, json=body)

        # Authorized update returns and persists the new values.
        updated = {**own, "description": "Revised by owner", "amount_cents": 4242}
        response = patch(own["id"], {"description": "Revised by owner", "amount_cents": 4242})
        _require(response.status_code == 200 and _json(response) == updated, "Own update failed")
        _require(_json(get(f"/invoices/{own['id']}")) == updated, "Own update not persisted")
        # Foreign update is indistinguishable from missing and changes nothing.
        _require(
            not_found(patch(foreign_id, {"description": "Hijacked"})), "Foreign update allowed"
        )
        _require(not_found(patch(999999, {"description": "Missing"})), "Missing update differs")
        _require(
            _json(get(f"/invoices/{foreign_id}", bob)) == before_foreign,
            "Foreign update changed another tenant's invoice",
        )
        # Mass assignment and invalid bodies are rejected without effect.
        for body in (
            {"tenant_id": organization[bob]},
            {"description": "Moved", "tenant_id": organization[bob]},
            {"id": 999},
            {},
            {"description": ""},
            {"amount_cents": -1},
        ):
            _require(patch(own["id"], body).status_code == 422, "Invalid update accepted")
        _require(_json(get(f"/invoices/{own['id']}")) == updated, "Rejected update had effect")
        _require(
            _json(get(f"/invoices/{own['id']}", bob)) == NOT_FOUND,
            "Owned invoice moved to another tenant",
        )
        # Authorized create: database-assigned id, owned by the caller only.
        response = post({"description": "Created by owner", "amount_cents": 77}, alice)
        created = _json(response)
        _require(
            response.status_code == 201
            and isinstance(created, dict)
            and set(created) == set(FIELDS)
            and type(created["id"]) is int
            and created["id"] > max(row[0] for row in dataset["invoices"])
            and (created["description"], created["amount_cents"]) == ("Created by owner", 77),
            "Own create failed",
        )
        _require(_json(get(f"/invoices/{created['id']}")) == created, "Created invoice unreadable")
        _require(not_found(get(f"/invoices/{created['id']}", bob)), "Created invoice leaked")
        # A client-chosen tenant is refused; a tenant hint header is ignored.
        for body in (
            {"description": "Planted", "amount_cents": 1, "tenant_id": organization[bob]},
            {"description": "Planted", "amount_cents": 1, "id": 999},
            {"description": "Planted"},
            {"description": "Planted", "amount_cents": -5},
        ):
            _require(post(body).status_code == 422, "Invalid create accepted")
        hinted = post(
            {"description": "Hinted create", "amount_cents": 5},
            alice,
            {"X-Tenant-ID": organization[bob], "X-Organization-ID": organization[bob]},
        )
        hinted_body = _json(hinted)
        _require(
            hinted.status_code == 201 and isinstance(hinted_body, dict) and "id" in hinted_body,
            "Hinted create failed",
        )
        _require(
            not_found(get(f"/invoices/{hinted_body['id']}", bob)),
            "Client tenant input placed a row in another tenant",
        )
        bob_view = get("/invoices?limit=100", bob)
        _require(
            bob_view.status_code == 200 and _json(bob_view) == owned[bob],
            "Writes changed another tenant's records",
        )

    checks = []
    callbacks = {
        "fixture_configuration": lambda: fixture_configuration(runtime_dsn, fixture),
        "authorized_reads": authorized,
        "foreign_reads": foreign,
        "list_search": lists,
        "exports": exports,
        "identity": identity,
        "spoofing": spoofing,
        "tenant_switching": switching,
        "aggregates": aggregates,
        "writes": writes,
    }
    for name in ORDER:
        try:
            callbacks[name]()
            checks.append(Check(name, "pass"))
        except AssertionError as error:
            checks.append(Check(name, "fail", str(error)))
        except Exception as error:
            # Never persist connection strings, response bodies or secret-bearing errors.
            checks.append(Check(name, "not_evaluated", type(error).__name__))
    return summarize(checks)
