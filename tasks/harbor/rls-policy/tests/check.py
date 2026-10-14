"""Public fixed-fixture verifier. Interpret data only; never execute candidate code."""

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def read_policy(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("policy must be a regular file")
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError("policy too large")
    policy = json.loads(raw, object_pairs_hook=unique_object)
    if (
        not isinstance(policy, dict)
        or set(policy) != {"enabled", "predicate"}
        or type(policy["enabled"]) is not bool
        or policy["predicate"] not in ("tenant", "all", "none")
    ):
        raise ValueError("invalid policy")
    return policy, hashlib.sha256(raw).hexdigest()


def sql(statement):
    return subprocess.run(
        [
            "psql",
            "-X",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-h",
            "/tmp/spike-socket",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-c",
            statement,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


def evaluate(policy):
    # Only trusted constant SQL fragments can reach the database.
    predicate = {
        "tenant": "tenant = current_setting('app.tenant', true)",
        "all": "true",
        "none": "false",
    }[policy["predicate"]]
    sql(
        "CREATE ROLE invoice_runtime NOSUPERUSER NOBYPASSRLS; "
        "CREATE TABLE invoices (id integer, tenant text); "
        "INSERT INTO invoices VALUES (1, 'a'), (2, 'a'), (3, 'b'); "
        "GRANT SELECT ON invoices TO invoice_runtime; "
        f"CREATE POLICY tenant_policy ON invoices USING ({predicate});"
    )
    if policy["enabled"]:
        sql("ALTER TABLE invoices ENABLE ROW LEVEL SECURITY")
    rows = {}
    for tenant in ("a", "b", ""):
        rows[tenant] = sql(
            "BEGIN; SET LOCAL ROLE invoice_runtime; "
            f"SET LOCAL app.tenant = '{tenant}'; "
            "SELECT id FROM invoices ORDER BY id; COMMIT;"
        )
    return {
        "authorized_a": rows["a"] == "1\n2",
        "authorized_b": rows["b"] == "3",
        "missing_context_denied": rows[""] == "",
        "rls_enabled": sql("SELECT relrowsecurity FROM pg_class WHERE oid = 'invoices'::regclass")
        == "t",
    }


def main():
    output = Path("/logs/verifier")
    output.mkdir(parents=True, exist_ok=True)
    try:
        policy, digest = read_policy("/candidate/policy.json")
    except (OSError, ValueError, UnicodeError):
        checks, digest = {"valid_submission": False}, None
    else:
        # Infrastructure failures propagate: no reward is emitted.
        checks = evaluate(policy)
    evidence = {"schema_version": 1, "artifact_sha256": digest, "checks": checks}
    (output / "policy-evidence.json").write_text(json.dumps(evidence, sort_keys=True))
    (output / "reward.txt").write_text("1" if all(checks.values()) else "0")


if __name__ == "__main__":
    main()
