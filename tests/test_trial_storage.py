"""Offline checks that every Harbor task bounds the host storage its containers write."""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TASKS = ["rls-policy", "invoice-read", "invoice-search", "invoice-export"]
REFERENCE = ROOT / "tasks/harbor/rls-policy/environment"
LOGGING = '    logging:\n      driver: json-file\n      options: {max-size: "1m", max-file: "1"}\n'
# Name, mount options: the agent's submission and solution volumes and the
# collector's output, all tmpfs-backed with a declared size.
VOLUMES = {
    "candidate": "size=16m,nr_inodes=4096,mode=0755,uid=10001,gid=10001,nosuid,nodev",
    "solution": "size=16m,nr_inodes=4096,mode=0755,nosuid,nodev",
    "collected": "size=1m,nr_inodes=64,mode=0755,uid=10001,gid=10001,nosuid,nodev,noexec",
}


def services(compose):
    """Each service's block of a reviewed compose file, by service name."""
    end = compose.find("\nvolumes:\n")
    body = compose[compose.index("\nservices:\n") : end if end != -1 else len(compose)]
    names = list(re.finditer(r"^  ([a-z]+):\n", body, flags=re.MULTILINE))
    return {
        match.group(1): body[match.end() : following.start() if following else len(body)]
        for match, following in zip(names, [*names[1:], None], strict=True)
    }


@pytest.mark.parametrize("task", TASKS)
@pytest.mark.parametrize("compose", ["environment", "tests"])
def test_every_service_keeps_one_capped_log(task, compose):
    text = (ROOT / "tasks/harbor" / task / compose / "docker-compose.yaml").read_text()
    blocks = services(text)
    expected = {"main", "collector"} if compose == "environment" else {"main"}
    if compose == "tests" and task != "rls-policy":
        expected.add("app")
    assert set(blocks) == expected
    for name, block in blocks.items():
        assert LOGGING in block, (task, compose, name)
        # Docker's default /dev/shm (64 MiB) is the bound the audit enforces.
        assert "shm_size" not in block and "storage_opt" not in block


def test_agent_volumes_are_bounded_tmpfs():
    text = (REFERENCE / "docker-compose.yaml").read_text()
    volumes = text[text.index("\nvolumes:\n") :]
    assert volumes.count("\n  ") == 3 * 5
    for name, options in VOLUMES.items():
        declaration = (
            f"\n  {name}:\n    driver_opts:\n      type: tmpfs\n      device: tmpfs\n"
            f'      o: "{options}"\n'
        )
        assert declaration in volumes, name
    blocks = services(text)
    assert "\n      - candidate:/candidate\n      - solution:/solution\n" in blocks["main"]
    assert (
        "\n      - candidate:/agent-candidate:ro\n      - collected:/candidate\n"
        in (blocks["collector"])
    )
    # The agent's scratch space stays the same bounded, non-executable tmpfs.
    assert "\n      - /tmp:rw,noexec,nosuid,size=16m\n" in blocks["main"]


def test_harbor_waits_for_the_seeded_starter():
    main = services((REFERENCE / "docker-compose.yaml").read_text())["main"]
    healthcheck = main[main.index("    healthcheck:\n") :]
    for line in (
        'test: ["CMD", "test", "-e", "/tmp/.seeded"]',
        "interval: 24h",
        "retries: 1",
        "start_period: 60s",
        "start_interval: 1s",
    ):
        assert f"\n      {line}\n" in healthcheck, line


@pytest.mark.parametrize("task", TASKS)
def test_agent_images_seed_the_starter_through_the_entrypoint(task):
    environment = ROOT / "tasks/harbor" / task / "environment"
    assert (environment / "seed.sh").read_bytes() == (REFERENCE / "seed.sh").read_bytes()
    dockerfile = (environment / "Dockerfile").read_text()
    assert "COPY --chmod=0555 seed.sh /opt/seed.sh\n" in dockerfile
    assert dockerfile.rstrip().endswith('ENTRYPOINT ["/opt/seed.sh"]')
    assert "/opt/starter/" in dockerfile
    # Volumes come only from the compose file, where each has a size.
    for name in ("Dockerfile", "collector.Dockerfile"):
        assert "VOLUME" not in (environment / name).read_text()


def test_seed_copies_the_starter_then_runs_the_command(tmp_path):
    starter, candidate, marker = tmp_path / "starter", tmp_path / "candidate", tmp_path / "seeded"
    starter.mkdir()
    candidate.mkdir()
    (starter / "app.py").write_text("starter\n")
    (starter / "app.py").chmod(0o444)
    script = (REFERENCE / "seed.sh").read_text()
    for old, new in (
        ("/opt/starter/", f"{starter}/"),
        ("/candidate/", f"{candidate}/"),
        ("/tmp/.seeded", str(marker)),
    ):
        assert old in script
        script = script.replace(old, new)
    seed = tmp_path / "seed.sh"
    seed.write_text(script)
    result = subprocess.run(
        ["sh", str(seed), "sh", "-c", 'echo "ran $0"', "command"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == "ran command\n"
    assert (candidate / "app.py").read_text() == "starter\n"
    assert (candidate / "app.py").stat().st_mode & 0o777 == 0o444
    assert marker.exists()


def test_seed_failure_never_marks_the_container_ready(tmp_path):
    script = (REFERENCE / "seed.sh").read_text()
    marker = tmp_path / "seeded"
    script = script.replace("/opt/starter/", f"{tmp_path}/missing/")
    script = script.replace("/candidate/", f"{tmp_path}/candidate/")
    script = script.replace("/tmp/.seeded", str(marker))
    seed = tmp_path / "seed.sh"
    seed.write_text(script)
    result = subprocess.run(["sh", str(seed), "true"], capture_output=True)
    assert result.returncode != 0
    assert not marker.exists()
