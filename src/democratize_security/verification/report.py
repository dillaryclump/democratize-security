"""Standard-library report contract for the existing synthetic v3 verifier."""

from dataclasses import asdict, dataclass

PROTOCOL = "synthetic-reference-v3"
REQUIRED = frozenset(
    {
        "database_configuration",
        "authorized_reads",
        "foreign_reads",
        "list_search",
        "exports",
        "identity",
        "spoofing",
        "tenant_switching",
    }
)


@dataclass(frozen=True)
class Check:
    id: str
    outcome: str
    detail: str = ""


def summarize(checks: list[Check]) -> dict:
    ids = [check.id for check in checks]
    complete = (
        set(ids) == REQUIRED
        and len(ids) == len(REQUIRED)
        and all(c.outcome in {"pass", "fail"} for c in checks)
    )
    return {
        "schema_version": 1,
        "protocol": PROTOCOL,
        "coverage": "complete" if complete else "incomplete",
        "outcome": ("pass" if all(c.outcome == "pass" for c in checks) else "fail")
        if complete
        else "incomplete",
        "checks": [asdict(c) for c in checks],
    }


class ReportError(ValueError):
    """A report cannot be represented as valid synthetic verifier evidence."""


def validate_report(report: dict) -> None:
    """Reject malformed reports and dishonest summary claims; do not grade code."""
    if not isinstance(report, dict) or set(report) != {
        "schema_version",
        "protocol",
        "coverage",
        "outcome",
        "checks",
    }:
        raise ReportError("Invalid report envelope")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise ReportError("Unsupported report schema")
    if report["protocol"] != PROTOCOL:
        raise ReportError("Unsupported verifier protocol")
    checks = report["checks"]
    if not isinstance(checks, list) or len(checks) > len(REQUIRED):
        raise ReportError("Invalid check count")
    seen = set()
    parsed = []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"id", "outcome", "detail"}:
            raise ReportError("Invalid check record")
        identifier, outcome, detail = check["id"], check["outcome"], check["detail"]
        if not isinstance(identifier, str) or identifier not in REQUIRED or identifier in seen:
            raise ReportError("Unknown or duplicate check")
        if not isinstance(outcome, str) or outcome not in {"pass", "fail", "not_evaluated"}:
            raise ReportError("Invalid check outcome")
        if not isinstance(detail, str) or len(detail.encode("utf-8")) > 2048:
            raise ReportError("Check detail exceeds byte limit")
        seen.add(identifier)
        parsed.append(Check(identifier, outcome, detail))
    if report != summarize(parsed):
        raise ReportError("Coverage or outcome disagrees with required checks")
