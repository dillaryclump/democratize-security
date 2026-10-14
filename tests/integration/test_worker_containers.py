import base64
import os
import subprocess

import pytest

from democratize_security.artifacts import seal
from democratize_security.worker_probe import DOCKER, run_probe

pytestmark = pytest.mark.worker


@pytest.fixture
def image_id():
    image = os.environ.get("TEST_WORKER_IMAGE_ID")
    if not image:
        if os.environ.get("REQUIRE_DOCKER_TESTS") == "1":
            pytest.fail("TEST_WORKER_IMAGE_ID required")
        pytest.skip("Dedicated Docker probe CI supplies TEST_WORKER_IMAGE_ID")
    return image


def execute(tmp_path, image, source, **limits):
    (tmp_path / "main.py").write_text(source)
    bundle = seal(tmp_path, ["main.py"])
    result = run_probe(bundle, image, **limits)
    assert result["artifact_sha256"] == bundle["artifact_sha256"]
    assert result["image_id"] == image
    assert result["security_verdict"] == "not_evaluated"
    remaining = subprocess.run(
        [*DOCKER, "ps", "-aq", "--filter", f"name=^{result['container_name']}$"],
        capture_output=True,
        check=True,
        timeout=10,
    )
    assert remaining.stdout.strip() == b"", "Container must be removed"
    return result


@pytest.mark.parametrize(
    "source,exit_code,output",
    [
        ("print('first fixture')", 0, b"first fixture\n"),
        ("print(sum([2, 3, 5]))", 0, b"10\n"),
        ("raise SystemExit(7)", 7, b""),
    ],
)
def test_three_finite_programs(tmp_path, image_id, source, exit_code, output):
    result = execute(tmp_path, image_id, source)
    assert result["termination"] == "exited"
    assert result["exit_code"] == exit_code
    assert base64.b64decode(result["output_base64"]) == output


def test_permissions_and_resource_configuration(tmp_path, image_id, monkeypatch):
    monkeypatch.setenv("SYNTHETIC_CONTROLLER_SECRET", "must-not-enter-worker")
    result = execute(
        tmp_path,
        image_id,
        """
import os, pathlib, socket
assert os.getuid() == 65534
assert "SYNTHETIC_CONTROLLER_SECRET" not in os.environ
assert not pathlib.Path("/var/run/docker.sock").exists()
assert not pathlib.Path("/workspace").exists()
for target in ["/candidate/main.py", "/etc/probe-write"]:
    try:
        pathlib.Path(target).write_text("forbidden")
    except OSError:
        pass
    else:
        raise AssertionError("write unexpectedly succeeded")
with socket.socket() as sock:
    sock.settimeout(0.5)
    try:
        sock.connect(("192.0.2.1", 80))
    except OSError:
        pass
    else:
        raise AssertionError("external network available")
print("constraints-observed")
""",
    )
    assert result["exit_code"] == 0, result
    assert base64.b64decode(result["output_base64"]) == b"constraints-observed\n"
    config = result["host_config"]
    assert config["NetworkMode"] == "none"
    assert config["ReadonlyRootfs"] is True
    assert config["Memory"] == config["MemorySwap"] == 128 * 1024 * 1024
    assert config["NanoCpus"] == 500000000
    assert config["PidsLimit"] == 32
    assert config["CapDrop"] == ["ALL"]
    assert "no-new-privileges" in config["SecurityOpt"]


@pytest.mark.parametrize(
    "source,reason",
    [
        ("while True: pass", "timeout"),
        ("import os\nwhile True: os.write(1, b'x' * 4096)", "output_limit"),
    ],
)
def test_resource_stop_and_cleanup(tmp_path, image_id, source, reason):
    result = execute(tmp_path, image_id, source, timeout_seconds=2, output_limit=1024)
    assert result["termination"] == reason
    assert len(base64.b64decode(result["output_base64"])) <= 1024


def test_nested_files_with_restrictive_controller_umask(tmp_path, image_id):
    (tmp_path / "main.py").write_text(
        "from pathlib import Path\nprint(Path('/candidate/data/nested/value.txt').read_text())"
    )
    nested = tmp_path / "data" / "nested"
    nested.mkdir(parents=True)
    (nested / "value.txt").write_text("nested-fixture")
    bundle = seal(tmp_path, ["main.py", "data/nested/value.txt"])
    previous = os.umask(0o077)
    try:
        result = run_probe(bundle, image_id)
    finally:
        os.umask(previous)
    assert result["exit_code"] == 0, result
    assert base64.b64decode(result["output_base64"]) == b"nested-fixture\n"
