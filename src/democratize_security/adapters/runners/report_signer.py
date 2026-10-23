"""Sign sealed-replay app evidence as an authenticated runtime report (issue #69).

Trust boundary: the replay's separate Harbor verifier binds its evidence to a
per-run Harbor nonce, which the controller checks before calling this bridge. A
short-lived signer process then receives the runtime verifier nonce only on its
stdin pipe and signs the equivalent `synthetic-reference-v3` report with
`runtime_auth.sign_report`. This is a bridge, not a verifier signing inside its
own container. It never echoes the nonce. Run with
`python -m democratize_security.adapters.runners.report_signer`.
"""

import json
import os
import subprocess
import sys

from democratize_security.runtime_auth import sign_report
from democratize_security.verification.report import PROTOCOLS, Check, summarize

MAX_DETAIL_CHARACTERS = 2048
OUTCOMES = frozenset({"pass", "fail", "not_evaluated"})
TIMEOUT_SECONDS = 60


class SignerError(RuntimeError):
    def __init__(self, message: str, stderr: str = ""):
        super().__init__(message)
        self.stderr = stderr


def report_from_app_evidence(evidence: dict) -> dict:
    """The verifier report equivalent to bound app evidence; reject any mismatch."""
    checks, details = evidence.get("checks"), evidence.get("details")
    protocol = evidence.get("protocol")
    if (
        not isinstance(protocol, str)
        or protocol not in PROTOCOLS
        or not isinstance(checks, dict)
        or not isinstance(details, dict)
    ):
        raise ValueError("unsupported app evidence")
    unknown = set(checks) - PROTOCOLS[protocol]
    if unknown or any(outcome not in OUTCOMES for outcome in checks.values()):
        raise ValueError("app evidence has unknown checks or outcomes")
    report = summarize(
        [
            Check(name, checks[name], str(details.get(name, ""))[:MAX_DETAIL_CHARACTERS])
            for name in sorted(checks)
        ],
        protocol,
    )
    if report["coverage"] != evidence.get("coverage"):
        raise ValueError("app evidence coverage disagrees with its checks")
    return report


def sign_via_subprocess(challenge: dict, nonce: bytes, evidence: dict) -> bytes:
    """Controller side: pass the nonce to a fresh signer over its stdin pipe only."""
    request = json.dumps({"challenge": challenge, "nonce_hex": nonce.hex(), "evidence": evidence})
    completed = subprocess.run(
        [sys.executable, "-m", "democratize_security.adapters.runners.report_signer"],
        input=request.encode(),
        capture_output=True,
        timeout=TIMEOUT_SECONDS,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        check=False,
    )
    stderr = completed.stderr.decode(errors="replace")[:4096].replace(nonce.hex(), "<nonce>")
    if completed.returncode != 0 or not completed.stdout:
        raise SignerError(f"report signer failed with exit {completed.returncode}", stderr)
    return completed.stdout


def main() -> int:
    try:
        request = json.loads(sys.stdin.buffer.read())
        report = report_from_app_evidence(request["evidence"])
        raw = sign_report(request["challenge"], bytes.fromhex(request["nonce_hex"]), report)
    except Exception as error:
        print(f"report signing failed: {type(error).__name__}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
