import pytest

pytest.importorskip("httpx")
pytest.importorskip("psycopg")

from democratize_security.verification.reference import REQUIRED, Check, summarize  # noqa: E402


def test_all_required_checks_must_pass():
    assert summarize([Check(name, "pass") for name in REQUIRED])["outcome"] == "pass"


@pytest.mark.parametrize("variant", ["empty", "missing", "duplicate", "unknown", "interrupted"])
def test_incomplete_verification_never_passes(variant):
    checks = [Check(name, "pass") for name in sorted(REQUIRED)]
    if variant == "empty":
        checks = []
    elif variant == "missing":
        checks.pop()
    elif variant == "duplicate":
        checks[-1] = checks[0]
    elif variant == "unknown":
        checks.append(Check("unexpected", "pass"))
    else:
        checks[-1] = Check(checks[-1].id, "not_evaluated")
    assert summarize(checks)["outcome"] == "incomplete"


def test_known_failure_is_reported_separately_from_missing_checks():
    checks = [Check(name, "pass") for name in sorted(REQUIRED)]
    checks[-1] = Check(checks[-1].id, "fail")
    result = summarize(checks)
    assert result["coverage"] == "complete"
    assert result["outcome"] == "fail"
