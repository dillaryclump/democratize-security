"""Pilot reference apps and reviewed controls graded by the v4 verifier."""

import json

import httpx
import psycopg
import pytest

from democratize_security.pilot import CONTROLS, ENDPOINTS, reference, starter
from democratize_security.pilot import verify as pilot_verify

SECURITY = ("foreign_reads", "spoofing", "exports", "aggregates", "writes")


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def outcomes(report):
    return {check["id"]: check["outcome"] for check in report["checks"]}


def grade(pilot_database, serve, app_file, fixture, verify_as=None):
    db = pilot_database(fixture)
    with serve(db.runtime, app_file) as client:
        return pilot_verify.verify(client, db.runtime, fixture=verify_as or fixture)


@pytest.mark.parametrize("fixture", ["plain", "protected"])
def test_reference_passes_its_fixture(pilot_database, serve, tmp_path, fixture):
    app = write(tmp_path, "reference.py", reference(fixture))
    report = grade(pilot_database, serve, app, fixture)
    assert (report["coverage"], report["outcome"]) == ("complete", "pass"), outcomes(report)


@pytest.mark.parametrize("control", ["nop", "unsafe"])
@pytest.mark.parametrize("fixture", ["plain", "protected"])
@pytest.mark.parametrize("family", sorted(ENDPOINTS))
def test_nop_and_unsafe_match_expected(pilot_database, serve, tmp_path, family, fixture, control):
    expected = json.loads((CONTROLS / "expected.json").read_text())[family][fixture][control]
    if control == "nop":
        data = starter(fixture, family)
    else:
        data = (CONTROLS / f"{family}-{fixture}-unsafe.py").read_bytes()
    report = grade(pilot_database, serve, write(tmp_path, "app.py", data), fixture)
    assert report["coverage"] == "complete"
    assert outcomes(report) == expected


@pytest.mark.parametrize("family", sorted(ENDPOINTS))
def test_plain_unsafe_leaks_and_protected_blocks_it(pilot_database, serve, tmp_path, family):
    # In the plain database the unsafe endpoint really exposes or changes foreign
    # data; the same plain-style query under forced RLS sees only its own rows.
    app = write(tmp_path, "app.py", (CONTROLS / f"{family}-plain-unsafe.py").read_bytes())
    plain = outcomes(grade(pilot_database, serve, app, "plain"))
    assert any(plain[check] == "fail" for check in SECURITY), plain
    db = pilot_database("protected")
    with psycopg.connect(db.runtime, autocommit=False) as connection:
        connection.execute("SELECT set_config('app.tenant_id', 'org-a', true)")
        assert connection.execute("SELECT tenant_id FROM public.invoices").fetchall() == [
            ("org-a",),
            ("org-a",),
        ]


def test_writes_run_last_and_reads_use_original_rows(pilot_database, serve, tmp_path):
    app = write(tmp_path, "reference.py", reference("protected"))
    db = pilot_database("protected")
    seen = []
    with serve(db.runtime, app) as client:
        original = client.request

        def recording(method, url, *args, **kwargs):
            response = original(method, url, *args, **kwargs)
            seen.append((method, str(url), response.status_code))
            return response

        client.request = recording
        report = pilot_verify.verify(client, db.runtime, fixture="protected")
    assert report["outcome"] == "pass"
    # Identity probes use write verbs but never succeed; the first successful
    # write starts the final `writes` check, after every read-only check.
    first = next(
        i for i, (m, _, status) in enumerate(seen) if m in {"PATCH", "POST"} and status < 300
    )
    later = [url for _, url, _ in seen[first:]]
    assert not [u for u in later if "/export" in u or "/summary" in u or "q=" in u]
    assert all(m != "GET" or "/invoices" in u for m, u, _ in seen[:first])


def test_fixture_configuration_detects_wrong_variant(pilot_database, serve, tmp_path):
    app = write(tmp_path, "reference.py", reference("protected"))
    report = grade(pilot_database, serve, app, "protected", verify_as="plain")
    failed = {k for k, v in outcomes(report).items() if v != "pass"}
    assert failed == {"fixture_configuration"}


def test_transport_failure_is_never_a_pass(pilot_database):
    db = pilot_database("plain")
    with httpx.Client(base_url="http://127.0.0.1:9", timeout=1, trust_env=False) as client:
        report = pilot_verify.verify(client, db.runtime, fixture="plain")
    assert report["outcome"] == "incomplete"
