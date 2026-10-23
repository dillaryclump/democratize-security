"""The 24 generated pilot task variants (6 families x 4 conditions)."""

import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from democratize_security.pilot import ENDPOINTS, FAMILIES, reference, starter
from democratize_security.pilot.instructions import (
    BLOCKS,
    CONDITIONS,
    FIXTURE_OF,
    blocks_for,
    instruction,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
try:
    import build_pilot_tasks
finally:
    sys.path.remove(str(ROOT / "scripts"))

VARIANTS = [(f, c) for f in FAMILIES for c in CONDITIONS]
# Files that legitimately differ between variants of the shared skeleton.
VARIANT_SPECIFIC = {
    "instruction.md",
    "task.toml",
    "environment/app.py",
    "solution/app.py",
    "tests/variant.json",
}
# full_tool variants also get the self-check image and larger agent bounds (Task 5).
FULL_TOOL_SPECIFIC = {"environment/Dockerfile", "environment/docker-compose.yaml"}


def files(directory):
    return sorted(p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file())


def test_conditions_and_fixtures():
    assert CONDITIONS == ("ordinary", "instructions", "rls_starter", "full_tool")
    assert FIXTURE_OF == {
        "ordinary": "plain",
        "instructions": "plain",
        "rls_starter": "protected",
        "full_tool": "protected",
    }


def test_build_check_reproduces_committed_tree():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_pilot_tasks.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert sorted(p.name for p in (ROOT / "tasks/pilot").iterdir()) == sorted(
        f"{f}-{c.replace('_', '-')}" for f, c in VARIANTS
    )


@pytest.mark.parametrize("family", FAMILIES)
def test_ordinary_text_has_no_security_guidance(family):
    text = instruction(family, "ordinary")
    for phrase in ("X-Tenant-ID", "row-level security", "RLS", "parameterized", "client input"):
        assert phrase not in text


@pytest.mark.parametrize("family", FAMILIES)
def test_condition_text_is_additive(family):
    assert blocks_for("ordinary") == ("OWNERSHIP", "PLAIN_DATABASE")
    assert blocks_for("instructions") == ("OWNERSHIP", "PLAIN_DATABASE", "SECURITY")
    assert blocks_for("rls_starter") == ("OWNERSHIP", "STARTER")
    assert blocks_for("full_tool") == ("OWNERSHIP", "STARTER", "SECURITY", "TOOL")
    for condition in CONDITIONS:
        text = instruction(family, condition)
        for name, block in BLOCKS.items():
            assert (block in text) == (name in blocks_for(condition)), (condition, name)
    # The functional contract is identical for every condition.
    first = instruction(family, "ordinary").split(BLOCKS["OWNERSHIP"])[0]
    assert all(instruction(family, c).startswith(first) for c in CONDITIONS)


@pytest.mark.parametrize("family, condition", VARIANTS)
def test_variant_contents(family, condition):
    directory = build_pilot_tasks.variant_dir(family, condition)
    fixture = FIXTURE_OF[condition]
    assert (directory / "environment/app.py").read_bytes() == starter(fixture, family)
    assert (directory / "solution/app.py").read_bytes() == reference(fixture)
    assert (directory / "instruction.md").read_text() == instruction(family, condition)
    assert json.loads((directory / "tests/variant.json").read_text()) == {
        "family": family,
        "condition": condition,
        "fixture": fixture,
        "protocol": "synthetic-reference-v4",
    }
    toml = (directory / "task.toml").read_text()
    assert f'name = "democratize-security/pilot-{directory.name}"' in toml
    assert directory.name == f"{family}-{condition.replace('_', '-')}"
    sources = ROOT / "src/democratize_security/pilot"
    for name in ("verify.py", "fixture.py"):
        assert (directory / "tests" / name).read_bytes() == (sources / name).read_bytes()
    assert ENDPOINTS[family]  # every family removes exactly one known endpoint


def test_shared_files_identical_except_variant_specific():
    first = build_pilot_tasks.variant_dir(*VARIANTS[0])
    shared = [p for p in files(first) if p not in VARIANT_SPECIFIC | FULL_TOOL_SPECIFIC]
    for family, condition in VARIANTS:
        directory = build_pilot_tasks.variant_dir(family, condition)
        assert files(directory) == files(first)
        for path in shared:
            assert (directory / path).read_bytes() == (first / path).read_bytes(), path
            mode = (directory / path).stat().st_mode & stat.S_IXUSR
            assert mode == (first / path).stat().st_mode & stat.S_IXUSR, path


def test_skeleton_reuses_reviewed_harbor_files():
    first = build_pilot_tasks.variant_dir(*VARIANTS[0])
    canonical = ROOT / "tasks/harbor/invoice-read"
    for path in (
        "environment/collect.py",
        "environment/collector.Dockerfile",
        "environment/seed.sh",
        "environment/app-requirements.txt",
        "tests/launch.py",
        "tests/app.Dockerfile",
        "tests/docker-compose.yaml",
        "tests/test.sh",
        "tests/verifier-requirements.txt",
        "solution/solve.sh",
    ):
        assert (first / path).read_bytes() == (canonical / path).read_bytes(), path
