"""Offline checks for the trusted artifact collector shared by every Harbor task."""

import os
import runpy
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TASKS = {
    "rls-policy": ("policy.json", 4096),
    "invoice-read": ("app.py", 65536),
    "invoice-search": ("app.py", 65536),
    "invoice-export": ("app.py", 65536),
}
SOURCE = ROOT / "tasks/harbor/rls-policy/environment/collect.py"
collect = runpy.run_path(str(SOURCE), run_name="collector")["collect"]


def test_every_task_uses_the_same_reviewed_collector():
    for task, (name, limit) in TASKS.items():
        environment = ROOT / "tasks/harbor" / task / "environment"
        for path in ("collect.py", "collector.Dockerfile", "docker-compose.yaml"):
            reference = ROOT / "tasks/harbor/rls-policy/environment" / path
            assert (environment / path).read_bytes() == reference.read_bytes(), (task, path)
        config = tomllib.loads((environment.parent / "task.toml").read_text())
        # Harbor transfers only the collector's checked copy, never the agent's path.
        assert config["artifacts"] == [
            # Replaces Harbor's implicit upload of the agent-written bind mount.
            {"source": "/logs/artifacts", "destination": "agent-artifacts", "exclude": ["*"]},
            {"source": f"/candidate/{name}", "destination": name, "service": "collector"},
        ]
        assert config["verifier"]["collect"] == [
            {
                "service": "collector",
                "command": (
                    f"python3 -I /opt/collect.py /agent-candidate/{name} /candidate/{name} {limit}"
                ),
                "timeout_sec": 30,
            }
        ]


def test_collector_service_is_hardened():
    compose = (ROOT / "tasks/harbor/rls-policy/environment/docker-compose.yaml").read_text()
    block = compose[compose.index("\n  collector:\n") : compose.index("\nvolumes:\n")]
    for line in (
        'network_mode: "none"',
        'user: "10001:10001"',
        "init: true",
        "read_only: true",
        "cap_drop: [ALL]",
        'security_opt: ["no-new-privileges:true"]',
        "pids_limit: 16",
        "mem_limit: 64m",
        "memswap_limit: 64m",
        "cpus: 1",
    ):
        assert f"\n    {line}\n" in block, line
    assert "\n      - candidate:/agent-candidate:ro\n" in block
    assert "cap_add" not in block and "tmpfs" not in block
    main = compose[compose.index("\n  main:\n") : compose.index("\n  collector:\n")]
    assert "\n      - candidate:/candidate\n" in main
    dockerfile = (ROOT / "tasks/harbor/rls-policy/environment/collector.Dockerfile").read_text()
    assert "COPY --chmod=0444 collect.py /opt/collect.py" in dockerfile


def test_valid_file_is_copied_read_only(tmp_path):
    source, target = tmp_path / "app.py", tmp_path / "out.py"
    source.write_bytes(b"print('ok')\n")
    source.chmod(0o600)  # Saved privately by the agent; the collector is its uid.
    assert collect(str(source), str(target), 64) == "collected 12 bytes"
    assert target.read_bytes() == b"print('ok')\n"
    assert target.stat().st_mode & 0o777 == 0o444
    with pytest.raises(FileExistsError):
        collect(str(source), str(target), 64)


@pytest.mark.parametrize(
    "kind", ["missing", "symlink", "symlink_to_file", "directory", "fifo", "hardlink", "large"]
)
def test_hostile_paths_are_rejected_without_output(tmp_path, kind):
    source, target = tmp_path / "app.py", tmp_path / "out.py"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("host data")
    if kind == "symlink":
        source.symlink_to(outside)
    elif kind == "symlink_to_file":
        # A valid small file behind a link: only O_NOFOLLOW rejects it.
        (outside / "small.py").write_text("x = 1\n")
        source.symlink_to(outside / "small.py")
    elif kind == "directory":
        source.mkdir()
    elif kind == "fifo":
        os.mkfifo(source)  # Opening must not block on a writer.
    elif kind == "hardlink":
        (outside / "linked").write_text("x")
        os.link(outside / "linked", source)
    elif kind == "large":
        source.write_bytes(b"x" * 65)
    assert collect(str(source), str(target), 64).startswith("rejected")
    assert not os.path.lexists(target)


def test_sparse_file_is_rejected_before_reading(tmp_path):
    source, target = tmp_path / "app.py", tmp_path / "out.py"
    with source.open("wb") as stream:
        stream.truncate(1 << 40)  # 1 TiB logical size, no blocks.
    assert collect(str(source), str(target), 65536) == "rejected: too large"
    assert not os.path.lexists(target)
