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
