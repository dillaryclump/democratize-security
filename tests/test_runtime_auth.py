import copy
import hashlib
import json
import os
import pickle
import subprocess
import sys
from dataclasses import asdict, replace

import pytest

from democratize_security.contracts import digest
from democratize_security.runtime_auth import (
    MAX_AUTH_BYTES,
    AuthenticationError,
    VerificationContext,
    VerifierSession,
    sign_report,
)
from democratize_security.verification.report import PROTOCOL, REQUIRED, Check, summarize


@pytest.fixture
def context():
    return VerificationContext(
        campaign_id="campaign-1",
        trial_id="trial-1",
        attempt_id="attempt-1",
        runner_request_id="runner-request-1",
        worker_id="worker-1",
        verification_request_id="verifier-request-1",
        controller_generation=3,
        expected_revision=5,
        task_revision="a" * 64,
        artifact_binding_sha256="b" * 64,
        artifact_sha256="c" * 64,
        object_sha256="d" * 64,
        verifier_sha256="e" * 64,
    )


def report(outcome="pass", *, missing=None):
    return summarize([Check(name, outcome) for name in sorted(REQUIRED) if name != missing])


def signed(session, value=None):
    return sign_report(session.public_challenge(), session.verifier_nonce(), value or report())


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def test_private_pipe_interoperability_with_separate_trusted_verifier(context):
    session = VerifierSession(context)
    # This protocol fixture is trusted code, never a candidate. A private stdin
    # pipe carries the nonce; it appears in no command argument or environment.
    program = """
import json, sys
from democratize_security.runtime_auth import sign_report
request = json.load(sys.stdin)
sys.stdout.buffer.write(sign_report(request['challenge'], bytes.fromhex(request['nonce']),
                                    request['report']))
"""
    process = subprocess.run(
        [sys.executable, "-I", "-c", program],
        input=encode(
            {
                "challenge": session.public_challenge(),
                "nonce": session.verifier_nonce().hex(),
                "report": report(),
            }
        ),
        capture_output=True,
        env={key: os.environ[key] for key in ("PATH", "SYSTEMROOT") if key in os.environ},
        timeout=10,
        check=True,
    )
    observed = session.authenticate(process.stdout)
    assert observed.complete is True
    assert observed.context == context
    assert observed.report == report()
    assert observed.envelope_sha256 == hashlib.sha256(process.stdout).hexdigest()
    assert process.stderr == b""
    assert session.verifier_nonce().hex().encode() not in process.stdout


@pytest.mark.parametrize(
    "outcome,complete", [("pass", True), ("fail", True), ("not_evaluated", False)]
)
def test_authentication_preserves_complete_failures_and_incomplete_checks(
    context, outcome, complete
):
    session = VerifierSession(context)
    value = report(outcome)
    observed = session.authenticate(signed(session, value))
    assert observed.report == value
    assert observed.complete is complete
    assert observed.report["outcome"] == ("incomplete" if not complete else outcome)
    if outcome != "pass":
        assert observed.report["outcome"] != "pass"
    assert "accepted" not in observed.public_record()


def test_missing_required_check_stays_incomplete(context):
    session = VerifierSession(context)
    value = report(missing="spoofing")
    observed = session.authenticate(signed(session, value))
    assert observed.complete is False
    assert observed.report == value
    assert len(observed.report["checks"]) == 7


@pytest.mark.parametrize("field", list(VerificationContext.__dataclass_fields__))
def test_even_a_valid_mac_cannot_substitute_any_expected_context_field(context, field):
    session = VerifierSession(context)
    public = session.public_challenge()
    previous = public["context"][field]
    if field in {"controller_generation", "expected_revision"}:
        public["context"][field] = previous + 1
    elif field == "protocol":
        # Other protocols cannot even be signed by this contract.
        public["context"][field] = "synthetic-reference-v2"
    elif field.endswith("sha256") or field == "task_revision":
        public["context"][field] = "f" * 64
    else:
        public["context"][field] = previous + "-foreign"
    public["challenge_sha256"] = digest(
        {key: value for key, value in public.items() if key != "challenge_sha256"}
    )
    if field == "protocol":
        with pytest.raises(AuthenticationError, match="protocol"):
            sign_report(public, session.verifier_nonce(), report())
    else:
        forged = sign_report(public, session.verifier_nonce(), report())
        with pytest.raises(AuthenticationError, match="independently selected"):
            session.authenticate(forged)


def test_restart_or_another_request_cannot_reuse_previously_signed_evidence(context):
    old = VerifierSession(context)
    raw = signed(old)
    restarted = VerifierSession(context)
    assert restarted.public_challenge() != old.public_challenge()
    assert restarted.verifier_nonce() != old.verifier_nonce()
    with pytest.raises(AuthenticationError, match="independently selected"):
        restarted.authenticate(raw)
    foreign = VerifierSession(replace(context, verification_request_id="another-request"))
    with pytest.raises(AuthenticationError, match="independently selected"):
        foreign.authenticate(raw)


def test_rehashing_a_changed_report_cannot_replace_a_mac(context):
    session = VerifierSession(context)
    envelope = json.loads(signed(session))
    envelope["report"] = report("fail")
    with pytest.raises(AuthenticationError, match="authentication failed"):
        session.authenticate(encode(envelope))


@pytest.mark.parametrize("mac", [None, "", "f" * 63, "f" * 65, "g" * 64, True, "0" * 64])
def test_missing_malformed_and_guessed_macs_fail(context, mac):
    session = VerifierSession(context)
    envelope = json.loads(signed(session))
    envelope["mac"] = mac
    with pytest.raises(AuthenticationError):
        session.authenticate(encode(envelope))


@pytest.mark.parametrize("nonce", [None, b"", b"x" * 31, b"x" * 33, "0" * 64, b"x" * 32])
def test_nonce_is_required_and_must_match_committed_challenge(context, nonce):
    session = VerifierSession(context)
    with pytest.raises(AuthenticationError):
        sign_report(session.public_challenge(), nonce, report())


def test_exact_authentication_retry_is_detached_and_conflicts_stop_the_session(context):
    session = VerifierSession(context)
    raw = signed(session)
    first = session.authenticate(raw)
    value = first.report
    value["checks"].clear()
    exported = first.public_record()
    exported["context"]["attempt_id"] = "changed"
    exported["report"]["checks"].clear()
    assert first.report == report()
    assert session.authenticate(raw) == first
    conflicting = signed(session, report("fail"))
    with pytest.raises(AuthenticationError, match="Conflicting"):
        session.authenticate(conflicting)
    with pytest.raises(AuthenticationError, match="Conflicting"):
        session.authenticate(raw)


def test_public_exports_repr_and_json_do_not_expose_nonce_or_mutate_session(context):
    session = VerifierSession(context)
    public = session.public_challenge()
    secret = session.verifier_nonce()
    assert len(secret) == 32
    assert public["nonce_sha256"] == hashlib.sha256(secret).hexdigest()
    assert secret.hex() not in json.dumps(public)
    assert secret.hex() not in repr(session)
    public["context"]["attempt_id"] = "changed"
    assert session.public_challenge()["context"] == asdict(context)
    observed = session.authenticate(signed(session))
    assert secret.hex() not in json.dumps(observed.public_record())
    assert secret.hex() not in repr(observed)
    for operation in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError, match="cannot be serialized"):
            operation(session)


@pytest.mark.parametrize(
    "field,value",
    [
        ("attempt_id", ""),
        ("worker_id", "worker/foreign"),
        ("campaign_id", "x" * 129),
        ("controller_generation", True),
        ("controller_generation", 0),
        ("controller_generation", 2**63),
        ("expected_revision", 0),
        ("expected_revision", 1.0),
        ("artifact_sha256", "a" * 63),
        ("object_sha256", "g" * 64),
        ("verifier_sha256", None),
        ("protocol", "synthetic-reference-v2"),
    ],
)
def test_context_requires_concrete_bounded_identities(context, field, value):
    with pytest.raises(AuthenticationError):
        replace(context, **{field: value})


@pytest.mark.parametrize(
    "raw", [None, "{}", b"", b"\xff", b"[", b"NaN", b"x" * (MAX_AUTH_BYTES + 1)]
)
def test_bounded_strict_json_rejects_malformed_inputs(context, raw):
    with pytest.raises(AuthenticationError):
        VerifierSession(context).authenticate(raw)


def test_duplicate_noncanonical_unknown_and_wrong_typed_fields_fail(context):
    session = VerifierSession(context)
    raw = signed(session)
    variants = [
        raw + b"\n",
        raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1),
        json.dumps(json.loads(raw), indent=2).encode(),
    ]
    for field, value in [("unknown", 1), ("schema_version", True), ("kind", "offline_evidence")]:
        envelope = json.loads(raw)
        envelope[field] = value
        variants.append(encode(envelope))
    for value in variants:
        with pytest.raises(AuthenticationError):
            session.authenticate(value)


def test_inconsistent_reports_cannot_be_signed_or_accepted(context):
    session = VerifierSession(context)
    value = report("fail")
    value["outcome"] = "pass"
    with pytest.raises(AuthenticationError, match="Invalid verifier report"):
        signed(session, value)
    envelope = json.loads(signed(session))
    envelope["report"] = value
    with pytest.raises(AuthenticationError, match="Invalid verifier report"):
        session.authenticate(encode(envelope))


def test_unknown_challenge_fields_or_recomputed_commitment_do_not_authenticate(context):
    session = VerifierSession(context)
    public = session.public_challenge()
    public["nonce_sha256"] = "f" * 64
    public["challenge_sha256"] = digest(
        {key: value for key, value in public.items() if key != "challenge_sha256"}
    )
    with pytest.raises(AuthenticationError, match="Nonce does not match"):
        sign_report(public, session.verifier_nonce(), report())
    public = session.public_challenge()
    public["secret"] = "candidate-claim"
    with pytest.raises(AuthenticationError):
        sign_report(public, session.verifier_nonce(), report())


def test_expected_context_cannot_be_imported_from_an_incoming_dictionary(context):
    with pytest.raises(AuthenticationError, match="independently selected"):
        VerifierSession(asdict(context))
    assert context.protocol == PROTOCOL
