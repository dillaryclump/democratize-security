import ast
import copy
import itertools
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import pytest

from democratize_security import evidence
from democratize_security.contracts import digest
from democratize_security.verification.report import (
    PROTOCOL,
    REQUIRED,
    Check,
    ReportError,
    summarize,
    validate_report,
)


@pytest.fixture
def binding():
    request = dict(
        attempt_id="attempt-1",
        expected_revision=1,
        campaign_id="campaign-1",
        trial_id="trial-1",
        task_revision="a" * 64,
        verifier_sha256="b" * 64,
        protocol=PROTOCOL,
        artifact_ref=dict(
            reference_version=1,
            schema_version=1,
            kind="sealed_artifact",
            object_sha256="c" * 64,
            artifact_sha256="d" * 64,
            byte_length=100,
        ),
    )
    record = dict(schema_version=1, event_id="bind-1", request=request)
    return {**record, "binding_sha256": digest(record)}


@pytest.fixture
def report():
    return summarize([Check(name, "pass") for name in sorted(REQUIRED)])


def rehash(record):
    record["evidence_sha256"] = digest({k: v for k, v in record.items() if k != "evidence_sha256"})
    return record


def test_scoring_parity_with_standalone_verifier_without_optional_dependencies():
    # The standalone verifier is copied into isolated tasks, so importing this
    # contract there would change their deployment boundary. Exercise its actual
    # report definitions without importing HTTP/database clients or running checks.
    path = (
        Path(__file__).resolve().parents[1] / "src/democratize_security/verification/reference.py"
    )
    tree = ast.parse(path.read_text())
    nodes = [
        node
        for node in tree.body
        if (
            isinstance(node, ast.ClassDef | ast.FunctionDef) and node.name in {"Check", "summarize"}
        )
        or (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id in {"PROTOCOL", "REQUIRED"}
                for target in node.targets
            )
        )
    ]
    namespace = {"dataclass": dataclass, "asdict": asdict}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    assert namespace["PROTOCOL"] == PROTOCOL
    assert namespace["REQUIRED"] == REQUIRED
    for outcomes in itertools.product(["pass", "fail", "not_evaluated"], repeat=len(REQUIRED)):
        values = list(zip(sorted(REQUIRED), outcomes, strict=True))
        expected = namespace["summarize"]([namespace["Check"](*item) for item in values])
        actual = summarize([Check(*item) for item in values])
        assert actual == expected
        validate_report(actual)
    for values in [
        [],
        [("authorized_reads", "pass")],
        [("unknown", "pass")],
        [("authorized_reads", "pass")] * 2,
    ]:
        assert summarize([Check(*v) for v in values]) == namespace["summarize"](
            [namespace["Check"](*v) for v in values]
        )


@pytest.mark.parametrize("mode", ["pass", "fail", "missing", "not_evaluated", "empty"])
def test_roundtrip_retains_outcome_and_is_detached(binding, report, mode):
    checks = [Check(**v) for v in report["checks"]]
    if mode == "missing":
        checks.pop()
    elif mode == "empty":
        checks = []
    elif mode != "pass":
        checks[0] = Check(checks[0].id, mode, "synthetic detail")
    report = summarize(checks)
    record = evidence.bind_report(binding, "verify-1", report)
    data = evidence.encode_evidence(record, binding, "verify-1")
    assert evidence.decode_evidence(data, binding, "verify-1") == record
    assert record["report"]["outcome"] == (mode if mode in {"pass", "fail"} else "incomplete")
    report["checks"].clear()
    assert evidence.decode_evidence(data, binding, "verify-1") == record


@pytest.mark.parametrize(
    "mode",
    [
        "duplicate",
        "unknown",
        "invalid_outcome",
        "detail",
        "extra_check",
        "false_pass",
        "false_complete",
        "schema_bool",
        "extra_field",
        "wrong_protocol",
    ],
)
def test_invalid_reports_rejected(binding, report, mode):
    if mode == "duplicate":
        report["checks"][-1] = copy.deepcopy(report["checks"][0])
    elif mode == "unknown":
        report["checks"][0]["id"] = "unknown"
    elif mode == "invalid_outcome":
        report["checks"][0]["outcome"] = True
    elif mode == "detail":
        report["checks"][0]["detail"] = "é" * 1025
    elif mode == "extra_check":
        report["checks"][0]["trusted"] = True
    elif mode == "false_pass":
        report["checks"][0]["outcome"] = "fail"
    elif mode == "false_complete":
        report["checks"].pop()
    elif mode == "schema_bool":
        report["schema_version"] = True
    elif mode == "extra_field":
        report["accepted"] = True
    else:
        report["protocol"] = "synthetic-reference-v2"
    with pytest.raises(ReportError):
        evidence.bind_report(binding, "verify-1", report)


@pytest.mark.parametrize(
    "field",
    [
        "binding_sha256",
        "attempt_id",
        "campaign_id",
        "trial_id",
        "task_revision",
        "verifier_sha256",
        "artifact_sha256",
        "object_sha256",
        "verification_request_id",
        "protocol",
        "kind",
        "schema_version",
    ],
)
def test_rehashing_cannot_change_expected_context(binding, report, field):
    record = evidence.bind_report(binding, "verify-1", report)
    record[field] = True if field == "schema_version" else "f" * 64
    rehash(record)
    with pytest.raises(evidence.EvidenceError):
        evidence.validate_evidence(record, binding, "verify-1")


def test_independently_selected_binding_and_request_are_required(binding, report):
    record = evidence.bind_report(binding, "verify-1", report)
    other = copy.deepcopy(binding)
    other["request"]["attempt_id"] = "attempt-2"
    other["binding_sha256"] = digest({k: v for k, v in other.items() if k != "binding_sha256"})
    with pytest.raises(evidence.EvidenceError):
        evidence.validate_evidence(record, other, "verify-1")
    with pytest.raises(evidence.EvidenceError):
        evidence.validate_evidence(record, binding, "verify-2")


@pytest.mark.parametrize(
    "data", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b"\xff", b"null", b"[" * 2000]
)
def test_invalid_json_rejected(binding, data):
    with pytest.raises(ValueError):
        evidence.decode_evidence(data, binding, "verify-1")


def test_noncanonical_and_oversized_input_rejected(binding, report, monkeypatch):
    record = evidence.bind_report(binding, "verify-1", report)
    with pytest.raises(evidence.EvidenceError, match="Noncanonical"):
        evidence.decode_evidence(json.dumps(record, indent=2).encode(), binding, "verify-1")
    monkeypatch.setattr(evidence, "MAX_EVIDENCE_BYTES", 10)
    with pytest.raises(evidence.EvidenceError, match="byte limit"):
        evidence.bind_report(binding, "verify-1", report)
    with pytest.raises(evidence.EvidenceError, match="byte limit"):
        evidence.decode_evidence(b" " * 11, binding, "verify-1")


def test_invalid_binding_or_request_never_creates_evidence(binding, report):
    with pytest.raises(evidence.EvidenceError):
        evidence.bind_report(binding, "", report)
    binding["request"]["verifier_sha256"] = "unknown"
    with pytest.raises(evidence.EvidenceError):
        evidence.bind_report(binding, "verify-1", report)


def test_real_store_binding_is_compatible(tmp_path, report):
    from democratize_security.artifacts import seal
    from democratize_security.objects import publish_artifact
    from democratize_security.store import PlanStore

    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('synthetic')")
    object_dir = tmp_path / "objects"
    object_dir.mkdir()
    reference = publish_artifact(object_dir, seal(source, ["app.py"]))
    campaign_path = Path(__file__).resolve().parents[1] / "campaigns/development.example.json"
    with PlanStore(tmp_path, objects_directory=object_dir) as store:
        planned = store.import_campaign(json.loads(campaign_path.read_text()))
        trial = planned["trials"][0]
        context = dict(
            attempt_id="a1", campaign_id=planned["campaign_id"], trial_id=trial["trial_id"]
        )
        store.record_accounting(
            "prepare",
            dict(
                action="prepare",
                **context,
                expected_revision=0,
                max_cost_cents=0,
                basis_sha256="e" * 64,
            ),
        )
        binding = store.record_artifact(
            "bind",
            dict(
                **context,
                expected_revision=1,
                task_revision=trial["task_revision"],
                verifier_sha256="f" * 64,
                protocol=PROTOCOL,
                artifact_ref=reference,
            ),
        )
        record = evidence.bind_report(binding, "verify-1", report)
        evidence.validate_evidence(record, store.artifact_bindings()[0], "verify-1")
        assert store.attempts()[0]["phase"] == "preparing"
        assert store.attempts()[0]["revision"] == 1


def test_valid_rehashed_report_is_not_authenticated(binding, report):
    record = evidence.bind_report(binding, "verify-1", report)
    record["report"]["checks"][0]["outcome"] = "fail"
    record["report"]["outcome"] = "fail"
    rehash(record)
    # Deliberate limit: the contract checks identity/consistency, not signatures
    # or whether any claimed observation was actually produced by a verifier.
    evidence.validate_evidence(record, binding, "verify-1")
