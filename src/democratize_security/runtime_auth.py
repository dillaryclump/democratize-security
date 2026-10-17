"""Per-request authentication for the trusted synthetic verifier.

The launcher independently selects context and privately supplies one fresh nonce
to one verifier. A signed report authenticates that request only. These contracts
do not launch a verifier, persist acceptance, transition a trial or grant dispatch.
"""

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import asdict, dataclass

from democratize_security.contracts import _unique_pairs, digest
from democratize_security.verification.report import PROTOCOL, validate_report

MAX_AUTH_BYTES = 64 * 1024
_DOMAIN = b"democratize-security/runtime-verifier-report/v1\x00"


class AuthenticationError(ValueError):
    """No authenticated observation can be obtained from these inputs."""


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        raise AuthenticationError("Invalid trusted context identifier")


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise AuthenticationError("A concrete SHA-256 is required")


def _encode(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError) as error:
        raise AuthenticationError("Invalid authentication record") from error
    if len(raw) > MAX_AUTH_BYTES:
        raise AuthenticationError("Authentication record exceeds byte limit")
    return raw


def _decode(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_AUTH_BYTES:
        raise AuthenticationError("Invalid authentication bytes or byte limit")

    def reject_constant(_):
        raise AuthenticationError("Nonfinite authentication JSON")

    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=reject_constant)
    except (ValueError, RecursionError) as error:
        raise AuthenticationError("Invalid authentication JSON") from error
    if _encode(value) != raw:
        raise AuthenticationError("Noncanonical authentication JSON")
    return value


@dataclass(frozen=True)
class VerificationContext:
    """Expected identities from trusted, revalidated controller/worker state.

    Construct this before reading a report. None of these fields can be selected
    from the incoming signed envelope, candidate files or candidate-written logs.
    The generation belongs to the currently inspecting controller.
    """

    campaign_id: str
    trial_id: str
    attempt_id: str
    runner_request_id: str
    worker_id: str
    verification_request_id: str
    controller_generation: int
    expected_revision: int
    task_revision: str
    artifact_binding_sha256: str
    artifact_sha256: str
    object_sha256: str
    verifier_sha256: str
    protocol: str = PROTOCOL

    def __post_init__(self):
        for key in (
            "campaign_id",
            "trial_id",
            "attempt_id",
            "runner_request_id",
            "worker_id",
            "verification_request_id",
        ):
            _identifier(getattr(self, key))
        for key in ("controller_generation", "expected_revision"):
            value = getattr(self, key)
            if type(value) is not int or not 1 <= value <= 2**63 - 1:
                raise AuthenticationError("Invalid controller generation or revision")
        for key in (
            "task_revision",
            "artifact_binding_sha256",
            "artifact_sha256",
            "object_sha256",
            "verifier_sha256",
        ):
            _hash(getattr(self, key))
        if self.protocol != PROTOCOL:
            raise AuthenticationError("Unsupported verifier protocol")


def _context(value):
    if not isinstance(value, dict) or set(value) != set(VerificationContext.__dataclass_fields__):
        raise AuthenticationError("Invalid trusted context fields")
    return VerificationContext(**value)


def _nonce(value):
    if not isinstance(value, bytes) or len(value) != 32:
        raise AuthenticationError("A private 256-bit verifier nonce is required")
    return value


def _report(value):
    try:
        validate_report(value)
    except (ValueError, TypeError, RecursionError) as error:
        raise AuthenticationError("Invalid verifier report") from error


def _challenge(value):
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "kind",
        "context",
        "nonce_sha256",
        "challenge_sha256",
    }:
        raise AuthenticationError("Invalid verification challenge")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise AuthenticationError("Unsupported challenge schema")
    if value["kind"] != "runtime_verification_challenge":
        raise AuthenticationError("Invalid challenge kind")
    _context(value["context"])
    _hash(value["nonce_sha256"])
    _hash(value["challenge_sha256"])
    expected = digest({key: item for key, item in value.items() if key != "challenge_sha256"})
    if not hmac.compare_digest(value["challenge_sha256"], expected):
        raise AuthenticationError("Challenge digest mismatch")
    return json.loads(_encode(value))


def sign_report(challenge: dict, nonce: bytes, report: dict) -> bytes:
    """Called only by the trusted verifier, after its independent checks.

    Supply the nonce through a private launcher channel, never a candidate
    mount, public job config or exported record. This function cannot establish
    that a caller is a verifier; launcher isolation establishes that authority.
    """
    public = _challenge(challenge)
    key = _nonce(nonce)
    if not hmac.compare_digest(public["nonce_sha256"], hashlib.sha256(key).hexdigest()):
        raise AuthenticationError("Nonce does not match verification intent")
    _report(report)
    body = {
        "schema_version": 1,
        "kind": "runtime_verifier_report",
        "challenge": public,
        "report": report,
    }
    mac = hmac.new(key, _DOMAIN + _encode(body), hashlib.sha256).hexdigest()
    return _encode({**body, "mac": mac})


@dataclass(frozen=True)
class AuthenticatedObservation:
    """Detached observation returned by authentication, not an accepted result.

    This trusted-process value is not an importable provenance credential.
    Persisting its public record does not make a subsequent untrusted copy
    authenticated; accepted-result admission must record that boundary atomically.
    """

    context: VerificationContext
    challenge_sha256: str
    envelope_sha256: str
    _report_bytes: bytes

    @property
    def report(self):
        return json.loads(self._report_bytes)

    @property
    def complete(self):
        return self.report["coverage"] == "complete"

    def public_record(self):
        return {
            "schema_version": 1,
            "kind": "runtime_authenticated_observation",
            "context": asdict(self.context),
            "challenge_sha256": self.challenge_sha256,
            "envelope_sha256": self.envelope_sha256,
            "report": self.report,
        }


class VerifierSession:
    """One in-memory nonce for one independently selected verifier request.

    Public exports contain a commitment only. Restarting creates a fresh session
    and cannot authenticate a pre-crash report. An exact same-report retry is
    idempotent; conflicting valid reports permanently stop this session.
    """

    __slots__ = ("_context", "_nonce", "_public", "_observation", "_conflict")

    def __init__(self, expected: VerificationContext):
        if not isinstance(expected, VerificationContext):
            raise AuthenticationError("An independently selected trusted context is required")
        self._context = expected
        self._nonce = secrets.token_bytes(32)
        public = {
            "schema_version": 1,
            "kind": "runtime_verification_challenge",
            "context": asdict(expected),
            "nonce_sha256": hashlib.sha256(self._nonce).hexdigest(),
        }
        public["challenge_sha256"] = digest(public)
        self._public = _encode(public)
        self._observation = None
        self._conflict = False

    def public_challenge(self):
        return json.loads(self._public)

    def __reduce_ex__(self, protocol):
        raise TypeError("Verifier sessions cannot be serialized or copied")

    def verifier_nonce(self):
        """Private launcher transport only; never persist or log this value."""
        return self._nonce

    def authenticate(self, raw: bytes) -> AuthenticatedObservation:
        if self._conflict:
            raise AuthenticationError("Conflicting verifier reports stopped this session")
        envelope = _decode(raw)
        if not isinstance(envelope, dict) or set(envelope) != {
            "schema_version",
            "kind",
            "challenge",
            "report",
            "mac",
        }:
            raise AuthenticationError("Invalid runtime verifier envelope")
        if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1:
            raise AuthenticationError("Unsupported runtime verifier envelope schema")
        if envelope["kind"] != "runtime_verifier_report":
            raise AuthenticationError("Invalid runtime verifier envelope kind")
        public = _challenge(envelope["challenge"])
        if _encode(public) != self._public:
            raise AuthenticationError("Report does not match independently selected request")
        _report(envelope["report"])
        _hash(envelope["mac"])
        body = {key: value for key, value in envelope.items() if key != "mac"}
        expected_mac = hmac.new(self._nonce, _DOMAIN + _encode(body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(envelope["mac"], expected_mac):
            raise AuthenticationError("Verifier report authentication failed")
        envelope_sha256 = hashlib.sha256(raw).hexdigest()
        if self._observation is not None:
            if self._observation.envelope_sha256 != envelope_sha256:
                self._conflict = True
                raise AuthenticationError("Conflicting verifier reports stopped this session")
            return self._observation
        self._observation = AuthenticatedObservation(
            context=self._context,
            challenge_sha256=public["challenge_sha256"],
            envelope_sha256=envelope_sha256,
            _report_bytes=_encode(envelope["report"]),
        )
        return self._observation
