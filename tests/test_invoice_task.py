import json
from pathlib import Path

import pytest

from democratize_security.adapters.runners.invoice_task import control_source, prepare_task
from democratize_security.artifacts import seal

ROOT = Path(__file__).resolve().parents[1]


def test_sealed_runtime_has_no_verifier_material(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    raw = b"raise RuntimeError('must only execute in app container')"
    (source / "app.py").write_bytes(raw)
    bundle = seal(source, ["app.py"])
    (source / "app.py").write_text("changed")
    task = tmp_path / "task"
    manifest = prepare_task(bundle, ROOT, task, b"# trusted requirements fixture\n")
    assert (task / "environment/app.py").read_bytes() == raw
    assert (task / "tests/application/app.py").read_bytes() == raw
    assert {p.name for p in (task / "tests/application").iterdir()} == {
        "app.py",
        "start.py",
        "Dockerfile",
        "requirements.txt",
    }
    compose = json.loads((task / "tests/docker-compose.yaml").read_text())
    assert compose["services"]["app"]["network_mode"] == "none"
    assert compose["services"]["app"]["volumes"] == ["dbsocket:/dbsocket:ro", "appsock:/appsock"]
    assert set(compose["services"]["app"]["environment"]) == {
        "REFERENCE_DATABASE_URL",
        "PYTHONDONTWRITEBYTECODE",
    }
    assert "DS_NONCE" not in (task / "tests/docker-compose.yaml").read_text()
    assert manifest["artifact_sha256"] == bundle["artifact_sha256"]


def test_builder_rejects_tampered_bundle_before_creating_context(tmp_path):
    (tmp_path / "app.py").write_text("pass")
    bundle = seal(tmp_path, ["app.py"])
    bundle["artifact_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        prepare_task(bundle, ROOT, tmp_path / "task", b"")
    assert not (tmp_path / "task").exists()


def test_control_replacements_are_exact():
    source = (ROOT / "src/democratize_security/reference/app.py").read_text()
    assert control_source(source, "protected") == source
    assert '"org-a" if invoice_id in (1, 2) else "org-b"' in control_source(
        source, "id_derived_tenant"
    )
    assert '"no-such-organization"' in control_source(source, "deny_all")
    with pytest.raises(ValueError):
        control_source("unexpected starter", "protected")
