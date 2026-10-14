"""Offline checks for trusted spike code; Docker acceptance is a separate CI job."""

import hashlib
import json
import re
import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPIKE = runpy.run_path(str(ROOT / "scripts/harbor_spike.py"))
VERIFIER = runpy.run_path(str(ROOT / "tasks/harbor/rls-policy/tests/check.py"))


def fixture(tmp_path):
    trial = tmp_path / "trial"
    (trial / "verifier").mkdir(parents=True)
    (trial / "artifacts").mkdir()
    raw = b'{"enabled":true,"predicate":"tenant"}'
    (trial / "artifacts/policy.json").write_bytes(raw)
    result = {
        "exception_info": None,
        "verifier_environment_mode": "separate",
        "agent_info": {"name": "oracle"},
        "finished_at": "2026-10-14",
        "verifier_result": {"rewards": {"reward": 1}},
    }
    (trial / "result.json").write_text(json.dumps(result))
    evidence = {
        "checks": dict.fromkeys(SPIKE["CHECKS"], True),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
    }
    (trial / "verifier/policy-evidence.json").write_text(json.dumps(evidence))
    return trial, result, evidence


def test_accept_seals_matching_input(tmp_path):
    fixture(tmp_path)
    assert SPIKE["accept_result"](tmp_path, "oracle", 1)["security_verdict"] == "not_evaluated"
    assert (tmp_path / "policy.bundle.json").is_file()


@pytest.mark.parametrize("mutation", ["shared", "exception", "missing", "tampered", "coverage"])
def test_reject_incomplete_or_unbound_result(tmp_path, mutation):
    trial, result, evidence = fixture(tmp_path)
    if mutation == "shared":
        result["verifier_environment_mode"] = "shared"
    elif mutation == "exception":
        result["exception_info"] = {"exception_type": "Timeout"}
    elif mutation == "missing":
        result["verifier_result"] = {}
    elif mutation == "tampered":
        (trial / "artifacts/policy.json").write_text("{}")
    else:
        evidence["checks"].pop("authorized_a")
    (trial / "result.json").write_text(json.dumps(result))
    (trial / "verifier/policy-evidence.json").write_text(json.dumps(evidence))
    with pytest.raises(ValueError):
        SPIKE["accept_result"](tmp_path, "oracle", 1)


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b'{"enabled":1,"predicate":"tenant"}',
        b'{"enabled":true,"enabled":false,"predicate":"tenant"}',
        b'{"enabled":true,"predicate":"DROP TABLE invoices"}',
        b"x" * 4097,
    ],
)
def test_reject_invalid_policy(tmp_path, raw):
    path = tmp_path / "policy.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        VERIFIER["read_policy"](path)


def test_reject_policy_symlink(tmp_path):
    (tmp_path / "target").write_text('{"enabled":true,"predicate":"tenant"}')
    (tmp_path / "policy.json").symlink_to(tmp_path / "target")
    with pytest.raises(OSError):
        VERIFIER["read_policy"](tmp_path / "policy.json")


def test_replay_rejects_valid_result_for_different_sealed_input(tmp_path):
    from democratize_security.artifacts import seal

    trial, _, _ = fixture(tmp_path)
    source = tmp_path / "sealed-source"
    source.mkdir()
    (source / "policy.json").write_text('{"enabled":false,"predicate":"all"}')
    with pytest.raises(ValueError, match="pre-verification seal"):
        SPIKE["accept_result"](tmp_path, "oracle", 1, expected_bundle=seal(source, ["policy.json"]))
    assert not (tmp_path / "policy.bundle.json").exists()


def test_harbor_base_images_are_digest_pinned():
    from democratize_security.policy_replay import REPLAY_DOCKERFILE

    sources = [path.read_text() for path in (ROOT / "tasks/harbor").rglob("Dockerfile")]
    lines = [line for text in [*sources, REPLAY_DOCKERFILE] for line in text.splitlines()]
    bases = [line for line in lines if line.upper().startswith("FROM ")]
    assert len(bases) == len(sources) + 1
    assert all(re.fullmatch(r"FROM [a-z0-9./:_-]+@sha256:[0-9a-f]{64}", base) for base in bases)
