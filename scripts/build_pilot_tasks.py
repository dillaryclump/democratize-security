"""Generate the 24 pilot Harbor task variants into `tasks/pilot/`.

Each variant is the reviewed `tasks/harbor/invoice-read` skeleton with:
- the family's starter for the condition's fixture, and the matching reference
  app as the oracle solution;
- the condition's instruction text and task name;
- the pilot v4 verifier, fixture and orchestrator, plus a `variant.json`.

`--check` rebuilds into a temporary directory and exits 1 on any difference in
file set, bytes or executable bits, so the committed tree is provably generated.
"""

import filecmp
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from democratize_security.pilot import FAMILIES, HERE, reference, starter  # noqa: E402
from democratize_security.pilot.instructions import (  # noqa: E402
    CONDITIONS,
    FIXTURE_OF,
    instruction,
)

CANONICAL = ROOT / "tasks/harbor/invoice-read"
OUTPUT = ROOT / "tasks/pilot"
TASK_FILES = HERE / "task_files"
PROTOCOL = "synthetic-reference-v4"
# Reviewed skeleton files copied unchanged from the canonical application task.
SHARED = (
    "environment/Dockerfile",
    "environment/app-requirements.txt",
    "environment/collect.py",
    "environment/collector.Dockerfile",
    "environment/docker-compose.yaml",
    "environment/seed.sh",
    "solution/solve.sh",
    "tests/app-requirements.txt",
    "tests/app.Dockerfile",
    "tests/docker-compose.yaml",
    "tests/launch.py",
    "tests/test.sh",
    "tests/verifier-requirements.in",
    "tests/verifier-requirements.txt",
)


def name(family: str, condition: str) -> str:
    return f"{family}-{condition.replace('_', '-')}"


def variant_dir(family: str, condition: str, root: Path = OUTPUT) -> Path:
    return root / name(family, condition)


def _copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    shutil.copymode(source, target)


def _write(target: Path, data: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    target.chmod(0o644)


def build(root: Path = OUTPUT) -> None:
    for family in FAMILIES:
        for condition in CONDITIONS:
            fixture = FIXTURE_OF[condition]
            directory = variant_dir(family, condition, root)
            for path in SHARED:
                _copy(CANONICAL / path, directory / path)
            for path in ("tests/run.py", "tests/Dockerfile"):
                _copy(TASK_FILES / path, directory / path)
            _copy(HERE / "verify.py", directory / "tests/verify.py")
            _copy(HERE / "fixture.py", directory / "tests/fixture.py")
            for path in ("tests/run.py", "tests/verify.py", "tests/fixture.py"):
                (directory / path).chmod(0o644)
            _write(directory / "environment/app.py", starter(fixture, family))
            _write(directory / "solution/app.py", reference(fixture))
            _write(directory / "instruction.md", instruction(family, condition).encode())
            toml = (CANONICAL / "task.toml").read_text()
            old = 'name = "democratize-security/invoice-read"'
            assert toml.count(old) == 1
            toml = toml.replace(
                old, f'name = "democratize-security/pilot-{name(family, condition)}"'
            )
            _write(directory / "task.toml", toml.encode())
            variant = {
                "family": family,
                "condition": condition,
                "fixture": fixture,
                "protocol": PROTOCOL,
            }
            _write(
                directory / "tests/variant.json",
                (json.dumps(variant, indent=2, sort_keys=False) + "\n").encode(),
            )


def _differences(left: Path, right: Path) -> list[str]:
    def listing(root):
        return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())

    problems = []
    if listing(left) != listing(right):
        problems.append("file sets differ")
    for path in set(listing(left)) & set(listing(right)):
        a, b = left / path, right / path
        if not filecmp.cmp(a, b, shallow=False):
            problems.append(f"bytes differ: {path}")
        elif (a.stat().st_mode & 0o111) != (b.stat().st_mode & 0o111):
            problems.append(f"mode differs: {path}")
    return sorted(problems)


def main(argv: list[str]) -> int:
    if argv == ["--check"]:
        with tempfile.TemporaryDirectory() as temporary:
            build(Path(temporary))
            problems = _differences(Path(temporary), OUTPUT) if OUTPUT.exists() else ["missing"]
        for problem in problems:
            print(problem)
        return 1 if problems else 0
    if argv:
        raise SystemExit("usage: build_pilot_tasks.py [--check]")
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    build(OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
