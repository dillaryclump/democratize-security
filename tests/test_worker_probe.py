import pytest

from democratize_security.artifacts import seal
from democratize_security.worker_probe import run_probe


@pytest.mark.parametrize(
    "image,timeout,limit",
    [
        ("python:latest", 5, 100),
        ("sha256:" + "a" * 64, True, 100),
        ("sha256:" + "a" * 64, 0, 100),
        ("sha256:" + "a" * 64, 5, 0),
    ],
)
def test_invalid_inputs_rejected_before_docker(tmp_path, monkeypatch, image, timeout, limit):
    (tmp_path / "main.py").write_text("print('fixture')")

    def forbidden(*args):
        pytest.fail("Docker must not be called")

    monkeypatch.setattr("democratize_security.worker_probe._docker", forbidden)
    with pytest.raises(ValueError):
        run_probe(seal(tmp_path, ["main.py"]), image, timeout_seconds=timeout, output_limit=limit)


def test_tampered_bundle_never_dispatched(tmp_path, monkeypatch):
    (tmp_path / "main.py").write_text("print('fixture')")
    bundle = seal(tmp_path, ["main.py"])
    bundle["artifact_sha256"] = "0" * 64

    def forbidden(*args):
        pytest.fail("Docker must not be called")

    monkeypatch.setattr("democratize_security.worker_probe._docker", forbidden)
    with pytest.raises(ValueError):
        run_probe(bundle, "sha256:" + "a" * 64)


@pytest.mark.parametrize("running", [False, True])
def test_limit_stop_race_requires_observed_stopped_state(monkeypatch, running):
    import json
    import subprocess
    import sys

    from democratize_security.worker_probe import WorkerError, _capture

    real_popen = subprocess.Popen

    def synthetic_process(*args, **kwargs):
        return real_popen([sys.executable, "-c", "print('x' * 4096)"], **kwargs)

    def docker(*args):
        if args[0] == "kill":
            raise WorkerError("synthetic stop race")
        assert args[0] == "inspect"
        return json.dumps([{"State": {"Running": running}}])

    monkeypatch.setattr("democratize_security.worker_probe.subprocess.Popen", synthetic_process)
    monkeypatch.setattr("democratize_security.worker_probe._docker", docker)
    if running:
        with pytest.raises(WorkerError, match="could not be stopped"):
            _capture("fixture", 5, 1024)
    else:
        reason, output = _capture("fixture", 5, 1024)
        assert reason == "output_limit"
        assert len(output) == 1024
