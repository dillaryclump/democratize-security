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
NONCE = "a" * 64


def sign(trial, evidence, nonce=NONCE):
    evidence = {k: v for k, v in evidence.items() if k != "mac"}
    evidence["mac"] = SPIKE["evidence_mac"](nonce, evidence)
    (trial / "verifier/policy-evidence.json").write_text(json.dumps(evidence))
    return evidence


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
        "reward": 1,
        "schema_version": 2,
    }
    return trial, result, sign(trial, evidence)


def test_accept_seals_matching_input(tmp_path):
    fixture(tmp_path)
    accepted = SPIKE["accept_result"](tmp_path, "oracle", 1, NONCE)
    assert accepted["security_verdict"] == "not_evaluated"
    assert (tmp_path / "policy.bundle.json").is_file()


@pytest.mark.parametrize(
    "mutation",
    [
        "shared",
        "exception",
        "missing",
        "tampered",
        "coverage",
        "wrong_nonce",
        "no_mac",
        "old_schema",
        "planted_reward_json",
        "evidence_reward",
        "evidence_symlink",
    ],
)
def test_reject_incomplete_or_unbound_result(tmp_path, mutation):
    trial, result, evidence = fixture(tmp_path)
    # Content mutations are re-signed with the right nonce so that each case
    # fails for its own reason, not incidentally on the MAC.
    if mutation == "shared":
        result["verifier_environment_mode"] = "shared"
    elif mutation == "exception":
        result["exception_info"] = {"exception_type": "Timeout"}
    elif mutation == "missing":
        result["verifier_result"] = {}
    elif mutation == "tampered":
        (trial / "artifacts/policy.json").write_text("{}")
    elif mutation == "coverage":
        evidence["checks"].pop("authorized_a")
        sign(trial, evidence)
    elif mutation == "wrong_nonce":
        sign(trial, evidence, nonce="b" * 64)
    elif mutation == "no_mac":
        del evidence["mac"]
        (trial / "verifier/policy-evidence.json").write_text(json.dumps(evidence))
    elif mutation == "old_schema":
        sign(trial, {**evidence, "schema_version": 1})
    elif mutation == "planted_reward_json":
        (trial / "verifier/reward.json").write_text('{"reward": 1}')
    elif mutation == "evidence_reward":
        sign(trial, {**evidence, "reward": 0})
    else:
        (trial / "verifier/policy-evidence.json").rename(trial / "real-evidence.json")
        (trial / "verifier/policy-evidence.json").symlink_to(trial / "real-evidence.json")
    (trial / "result.json").write_text(json.dumps(result))
    with pytest.raises((ValueError, OSError)):
        SPIKE["accept_result"](tmp_path, "oracle", 1, NONCE)


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
        SPIKE["accept_result"](
            tmp_path, "oracle", 1, NONCE, expected_bundle=seal(source, ["policy.json"])
        )
    assert not (tmp_path / "policy.bundle.json").exists()


def test_harbor_base_images_are_digest_pinned():
    from democratize_security.policy_replay import REPLAY_DOCKERFILE, replay_dockerfile

    paths = list((ROOT / "tasks/harbor").rglob("*Dockerfile"))
    # Includes the application tasks' separate candidate-runtime images.
    assert len([p for p in paths if p.name == "app.Dockerfile"]) == 3
    sources = [path.read_text() for path in paths]
    for text in [*sources, REPLAY_DOCKERFILE, replay_dockerfile("app.py")]:
        # Docker ignores case and leading whitespace; flags or stage references
        # in place of a pinned image fail closed.
        bases = re.findall(r"^\s*from\s+(\S+)", text, re.IGNORECASE | re.MULTILINE)
        assert bases
        assert all(re.fullmatch(r"[a-z0-9./:_-]+@sha256:[0-9a-f]{64}", base) for base in bases)


def planted(output, outside):
    output.mkdir()
    (output / "reward.json").write_text('{"reward": 1}')
    (output / "policy-evidence.json").write_text("{}")
    (output / "reward.txt").symlink_to(outside)


def test_verifier_discards_planted_grades_and_binds_evidence(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched")
    output = tmp_path / "verifier"
    planted(output, outside)
    # A missing submission avoids PostgreSQL and must still grade 0.
    VERIFIER["main"](output, tmp_path / "absent.json", {"DS_NONCE": NONCE})
    assert sorted(p.name for p in output.iterdir()) == ["policy-evidence.json", "reward.txt"]
    assert (output / "reward.txt").read_text() == "0" and not (output / "reward.txt").is_symlink()
    assert outside.read_text() == "untouched"
    evidence = json.loads((output / "policy-evidence.json").read_text())
    # The verifier and the host compute the MAC independently; they must agree.
    assert evidence["mac"] == SPIKE["evidence_mac"](NONCE, evidence)
    assert evidence["mac"] != SPIKE["evidence_mac"]("b" * 64, evidence)


@pytest.mark.parametrize("environ", [{}, {"DS_NONCE": ""}, {"DS_NONCE": "short"}])
def test_verifier_without_nonce_emits_no_reward(tmp_path, environ):
    output = tmp_path / "verifier"
    planted(output, tmp_path / "outside.txt")
    with pytest.raises(SystemExit):
        VERIFIER["main"](output, tmp_path / "absent.json", environ)
    assert list(output.iterdir()) == []
