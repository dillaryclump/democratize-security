"""Pilot plain/protected fixtures on disposable PostgreSQL (protocol v4)."""

import psycopg
import pytest

from democratize_security.pilot import fixture as pilot_fixture
from democratize_security.pilot import verify as pilot_verify
from democratize_security.verification.report import PROTOCOL_V4, REQUIRED_V4


def runtime(dsn, organization=None):
    connection = psycopg.connect(dsn, autocommit=False, connect_timeout=5)
    if organization is not None:
        connection.execute("SELECT set_config('app.tenant_id', %s, true)", (organization,))
    return connection


def test_verifier_constants_match_report_contract():
    assert pilot_verify.PROTOCOL == PROTOCOL_V4
    assert frozenset(pilot_verify.ORDER) == REQUIRED_V4
    assert pilot_verify.ORDER[-1] == "writes"
    assert len(pilot_verify.ORDER) == len(REQUIRED_V4)


def test_protected_fixture_catalog(pilot_database):
    db = pilot_database("protected")
    with runtime(db.runtime) as connection:
        assert connection.execute("SELECT count(*) FROM public.invoices").fetchone() == (0,)
    with runtime(db.runtime, "org-a") as connection:
        rows = connection.execute("SELECT id FROM public.invoices ORDER BY id").fetchall()
        assert rows == [(1,), (2,)]
        # Inserts take the tenant from context; a foreign tenant_id is refused.
        created = connection.execute(
            "INSERT INTO public.invoices (description, amount_cents) VALUES ('x', 1)"
            " RETURNING id, tenant_id"
        ).fetchone()
        assert created == (5, "org-a")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute(
                "INSERT INTO public.invoices (tenant_id, description, amount_cents)"
                " VALUES ('org-b', 'x', 1)"
            )
    with runtime(db.runtime, "org-a") as connection:
        # A foreign row is invisible to UPDATE; tenant_id is not updatable.
        assert (
            connection.execute("UPDATE public.invoices SET description = 'y' WHERE id = 3").rowcount
            == 0
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            connection.execute("UPDATE public.invoices SET tenant_id = 'org-b' WHERE id = 1")
    with psycopg.connect(db.admin, autocommit=True) as admin:
        assert admin.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class"
            " WHERE oid = 'public.invoices'::regclass"
        ).fetchone() == (True, True)
        assert admin.execute(
            "SELECT policyname, cmd FROM pg_policies WHERE tablename = 'invoices'"
        ).fetchall() == [("tenant_isolation", "ALL")]


def test_plain_fixture_catalog(pilot_database):
    db = pilot_database("plain")
    with runtime(db.runtime) as connection:
        assert connection.execute("SELECT count(*) FROM public.invoices").fetchone() == (4,)
        # The database does not protect anything: only application code can.
        assert connection.execute(
            "INSERT INTO public.invoices (tenant_id, description, amount_cents)"
            " VALUES ('org-b', 'x', 1) RETURNING id"
        ).fetchone() == (5,)
        assert (
            connection.execute(
                "UPDATE public.invoices SET tenant_id = 'org-a' WHERE id = 3"
            ).rowcount
            == 1
        )
    with psycopg.connect(db.admin, autocommit=True) as admin:
        assert admin.execute(
            "SELECT relrowsecurity FROM pg_class WHERE oid = 'public.invoices'::regclass"
        ).fetchone() == (False,)
        assert admin.execute(
            "SELECT count(*) FROM pg_policies WHERE tablename = 'invoices'"
        ).fetchone() == (0,)


@pytest.mark.parametrize("kind", ["plain", "protected"])
def test_fixture_configuration_check_per_variant(pilot_database, kind):
    db = pilot_database(kind)
    other = "plain" if kind == "protected" else "protected"
    pilot_verify.fixture_configuration(db.runtime, kind)
    with pytest.raises(AssertionError):
        pilot_verify.fixture_configuration(db.runtime, other)


def test_identity_restart_avoids_seed_ids(pilot_database):
    db = pilot_database("plain")
    with runtime(db.runtime) as connection:
        assert connection.execute(
            "INSERT INTO public.invoices (tenant_id, description, amount_cents)"
            " VALUES ('org-a', 'n', 0) RETURNING id"
        ).fetchone() == (5,)


def test_development_dataset_disjoint():
    grading, development = pilot_fixture.GRADING, pilot_fixture.DEVELOPMENT
    ids = {row[0] for row in grading["invoices"]}
    assert ids == {1, 2, 3, 4}
    assert not ids & {row[0] for row in development["invoices"]}
    assert not {row[2] for row in grading["invoices"]} & {row[2] for row in development["invoices"]}
    assert not {row[3] for row in grading["invoices"]} & {row[3] for row in development["invoices"]}
    # Tokens and organizations are fixed by the app's `tenant` dependency.
    assert development["tenants"] == grading["tenants"]


def test_development_dataset_provisions(pilot_database):
    db = pilot_database("protected", pilot_fixture.DEVELOPMENT)
    org = next(iter(sorted(set(pilot_fixture.DEVELOPMENT["tenants"].values()) - {None})))
    with runtime(db.runtime, org) as connection:
        rows = connection.execute("SELECT id FROM public.invoices ORDER BY id").fetchall()
        assert len(rows) == 2 and all(row[0] > 100 for row in rows)
