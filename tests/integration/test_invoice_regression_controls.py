"""Orthogonal reviewed read defects against the canonical v3 verifier.

These subprocess fixtures share the development host; they are reviewed
mutations, never an execution path for arbitrary candidate submissions.
"""

from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REFERENCE = Path(__file__).resolve().parents[2] / "src/democratize_security/reference/app.py"
READ_CONTEXT = "        found = rows(\n            organization,\n"


@pytest.mark.parametrize(
    ("control", "context", "failed"),
    [
        ("protected", "organization", set()),
        (
            "id_derived_tenant",
            "'org-a' if invoice_id in (1, 2) else 'org-b'",
            {"foreign_reads", "spoofing"},
        ),
        ("deny_all", "'no-such-organization'", {"authorized_reads"}),
    ],
)
def test_read_context_controls(database, serve, tmp_path, control, context, failed):
    from democratize_security.verification.reference import REQUIRED, verify

    # Exactly one read-handler argument changes. Authentication, database role,
    # RLS, list/search and export remain the canonical protected reference.
    source = REFERENCE.read_text()
    assert source.count(READ_CONTEXT) == 1
    app_file = tmp_path / f"{control}.py"
    app_file.write_text(
        source.replace(READ_CONTEXT, f"        found = rows(\n            {context},\n")
    )
    with serve(database.runtime, app_file) as client:
        headers = {"Authorization": "Bearer fixture-alice"}
        own = client.get("/invoices/1", headers=headers)
        foreign = client.get("/invoices/3", headers=headers)
        if control == "deny_all":
            assert own.status_code == 404
            assert own.json() == {"detail": "Invoice not found"}
        else:
            assert own.status_code == 200
            assert own.json()["id"] == 1
        if control == "id_derived_tenant":
            assert foreign.status_code == 200
            assert foreign.json()["id"] == 3
        else:
            assert foreign.status_code == 404
            assert foreign.json() == {"detail": "Invoice not found"}
        result = verify(client, database.runtime)

    expected = {check: "fail" if check in failed else "pass" for check in REQUIRED}
    assert result["coverage"] == "complete", result
    assert {check["id"]: check["outcome"] for check in result["checks"]} == expected, result
    assert result["outcome"] == ("fail" if failed else "pass"), result
