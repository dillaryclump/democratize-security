"""Reviewed application controls only. Subprocess separation is NOT a sandbox."""

import hashlib
from pathlib import Path

import pytest

from democratize_security.application_artifacts import materialize_application
from democratize_security.artifacts import bind_evidence, seal, validate_evidence

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]


def control_source(control):
    source = (ROOT / "src/democratize_security/reference/app.py").read_text()
    original = """        found = rows(
            organization,"""
    assert source.count(original) == 1, "Review controls when the reference changes"
    if control == "id_derived_tenant":
        # Own reads remain correct, but an ID chooses identity, leaking foreign rows.
        return source.replace(
            original,
            """        found = rows(
            "org-a" if invoice_id in (1, 2) else "org-b",""",
        )
    if control == "deny_all":
        return source.replace(
            original,
            """        found = rows(
            "no-such-organization",""",
        )
    assert control == "protected"
    return source


@pytest.mark.parametrize("control", ["protected", "id_derived_tenant", "deny_all"])
def test_invoice_read_controls_replay_exact_sealed_application(database, serve, tmp_path, control):
    from democratize_security.verification.reference import verify

    source = tmp_path / "submission"
    source.mkdir()
    (source / "app.py").write_text(control_source(control))
    bundle = seal(source, ["app.py"])
    # Replay must not consult mutable source paths, even when they still exist.
    (source / "app.py").write_text("raise RuntimeError('unsealed source was executed')")
    verdicts = []
    for attempt in range(2):
        staged = tmp_path / f"replay-{attempt}"
        assert materialize_application(bundle, staged) == bundle["artifact_sha256"]
        with serve(database.runtime, application_directory=staged) as client:
            result = verify(client, database.runtime)
        assert seal(staged, ["app.py"])["artifact_sha256"] == bundle["artifact_sha256"]
        assert result["coverage"] == "complete", result
        checks = {c["id"]: c["outcome"] for c in result["checks"]}
        assert checks["database_configuration"] == "pass", result
        if control == "protected":
            assert result["outcome"] == "pass", result
        else:
            assert result["outcome"] == "fail", result
            failed = "foreign_reads" if control == "id_derived_tenant" else "authorized_reads"
            assert checks[failed] == "fail", result
            assert all(value == "pass" for key, value in checks.items() if key != failed), result
        verifier_hash = hashlib.sha256(
            (ROOT / "src/democratize_security/verification/reference.py").read_bytes()
        ).hexdigest()
        evidence = bind_evidence(bundle, verifier_hash, result)
        validate_evidence(evidence, bundle, verifier_hash)
        verdicts.append(result)
    assert verdicts[0] == verdicts[1]


def test_database_fixture_uses_utf8(database):
    import psycopg

    with psycopg.connect(database.runtime) as connection:
        assert connection.execute("SHOW server_encoding").fetchone() == ("UTF8",)
