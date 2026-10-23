"""The full_tool self-check on disposable PostgreSQL with the development dataset."""

import pytest

pytest.importorskip("httpx")
pytest.importorskip("psycopg")

import os  # noqa: E402

from democratize_security.pilot import CONTROLS, HERE  # noqa: E402
from democratize_security.pilot import check_isolation as tool  # noqa: E402
from democratize_security.pilot.fixture import DEVELOPMENT, GRADING  # noqa: E402

GRADING_VALUES = [row[2] for row in GRADING["invoices"]] + [
    str(row[3]) for row in GRADING["invoices"]
]


@pytest.fixture
def admin_dsn():
    dsn = os.environ.get("TEST_POSTGRES_ADMIN_DSN")
    if not dsn:
        if os.environ.get("REQUIRE_POSTGRES_TESTS") == "1":
            pytest.fail("TEST_POSTGRES_ADMIN_DSN is required in the integration gate")
        pytest.skip("Set TEST_POSTGRES_ADMIN_DSN for disposable PostgreSQL integration tests")
    return dsn


def test_check_isolation_clean_on_reference(admin_dsn, tmp_path):
    app = tmp_path / "app.py"
    app.write_bytes((HERE / "reference_protected.py").read_bytes())
    report = tool.check(app, admin_dsn)
    assert (report["coverage"], report["outcome"]) == ("complete", "pass")
    lines = tool.render(report)
    assert lines == [f"PASS {check['id']}" for check in report["checks"]]


def test_check_isolation_reports_unsafe_leak(admin_dsn, tmp_path):
    app = tmp_path / "app.py"
    app.write_bytes((CONTROLS / "invoice-read-protected-unsafe.py").read_bytes())
    report = tool.check(app, admin_dsn)
    outcomes = {check["id"]: check["outcome"] for check in report["checks"]}
    assert outcomes["spoofing"] == "fail"
    assert "FAIL spoofing: Client tenant input exposed a foreign invoice" in tool.render(report)


def test_check_isolation_uses_development_data(admin_dsn, tmp_path, monkeypatch):
    seen = []
    original = tool.verify

    def recording(client, runtime_dsn, *, fixture, dataset):
        seen.append((fixture, dataset))
        return original(client, runtime_dsn, fixture=fixture, dataset=dataset)

    monkeypatch.setattr(tool, "verify", recording)
    app = tmp_path / "app.py"
    app.write_bytes((HERE / "reference_protected.py").read_bytes())
    tool.check(app, admin_dsn)
    assert seen == [("protected", DEVELOPMENT)]


def test_check_isolation_dataset_disjoint_from_grading():
    source = (HERE / "check_isolation.py").read_text()
    assert "GRADING" not in source
    assert not [value for value in GRADING_VALUES if value in source]


def test_output_has_no_response_bodies():
    report = {
        "checks": [
            {
                "id": "foreign_reads",
                "outcome": "fail",
                "detail": "Foreign invoice request not safely denied",
            },
            {"id": "exports", "outcome": "fail", "detail": 'body {"id": 3, "description": "B"}'},
            {"id": "writes", "outcome": "not_evaluated", "detail": "ReadTimeout"},
            {"id": "identity", "outcome": "pass", "detail": ""},
        ]
    }
    assert tool.render(report) == [
        "FAIL foreign_reads: Foreign invoice request not safely denied",
        "FAIL exports",
        "ERROR writes: ReadTimeout",
        "PASS identity",
    ]
