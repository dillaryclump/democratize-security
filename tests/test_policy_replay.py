import copy
import json
from pathlib import Path

import pytest

from democratize_security.artifacts import seal, validate_evidence
from democratize_security.policy_replay import prepare_replay, record_replay, write_record

TEMPLATE = Path(__file__).resolve().parents[1] / "tasks/harbor/rls-policy"


def sealed(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "policy.json").write_text('{"enabled":true,"predicate":"tenant"}')
    return source, seal(source, ["policy.json"])


def test_replay_uses_sealed_bytes_after_source_changes(tmp_path):
    source, bundle = sealed(tmp_path)
    original = (source / "policy.json").read_bytes()
    (source / "policy.json").write_text("tampered after sealing")
    task = tmp_path / "replay"
    manifest = prepare_replay(bundle, TEMPLATE, task)
    assert (task / "environment/policy.json").read_bytes() == original
    assert sorted(p.name for p in (task / "environment").iterdir()) == ["Dockerfile", "policy.json"]
    assert not (task / "solution").exists()
    assert (task / "tests/check.py").read_bytes() == (TEMPLATE / "tests/check.py").read_bytes()
    result = {"artifact_sha256": bundle["artifact_sha256"], "security_verdict": "not_evaluated"}
    record = record_replay(bundle, manifest, result)
    validate_evidence(record, bundle, manifest["verifier_sha256"])
    write_record(tmp_path / "evidence.json", record)
    assert json.loads((tmp_path / "evidence.json").read_text()) == record
    with pytest.raises(FileExistsError):
        write_record(tmp_path / "evidence.json", record)


@pytest.mark.parametrize("change", ["digest", "content", "extra", "size"])
def test_invalid_bundle_never_materialized(tmp_path, change):
    source, bundle = sealed(tmp_path)
    if change == "digest":
        bundle["artifact_sha256"] = "0" * 64
    elif change == "content":
        bundle["files"][0]["content_base64"] = "e30="
    elif change == "extra":
        (source / "main.py").write_text("raise Exception()")
        bundle = seal(source, ["policy.json", "main.py"])
    else:
        (source / "policy.json").write_text("x" * 4097)
        bundle = seal(source, ["policy.json"])
    task = tmp_path / "replay"
    with pytest.raises(ValueError):
        prepare_replay(bundle, TEMPLATE, task)
    assert not task.exists()


def test_existing_task_untouched(tmp_path):
    _, bundle = sealed(tmp_path)
    task = tmp_path / "replay"
    task.mkdir()
    (task / "keep").write_text("existing")
    with pytest.raises(FileExistsError):
        prepare_replay(bundle, TEMPLATE, task)
    assert (task / "keep").read_text() == "existing"


def test_different_replay_artifact_cannot_be_bound(tmp_path):
    _, bundle = sealed(tmp_path)
    manifest = prepare_replay(bundle, TEMPLATE, tmp_path / "replay")
    other = copy.deepcopy(bundle)
    other["artifact_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="does not match"):
        record_replay(bundle, manifest, {"artifact_sha256": other["artifact_sha256"]})
