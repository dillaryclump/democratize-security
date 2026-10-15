import pytest

from democratize_security.application_artifacts import materialize_application
from democratize_security.artifacts import seal


def test_materialization_is_data_only(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    raw = b"raise RuntimeError('must not be imported')\n"
    (source / "app.py").write_bytes(raw)
    bundle = seal(source, ["app.py"])
    output = tmp_path / "output"
    materialize_application(bundle, output)
    assert (output / "app.py").read_bytes() == raw
    assert (output / "app.py").stat().st_mode & 0o222 == 0
    with pytest.raises(FileExistsError):
        materialize_application(bundle, output)


@pytest.mark.parametrize("fault", ["tampered", "extra", "wrong_name"])
def test_invalid_application_rejected_before_writes(tmp_path, fault):
    (tmp_path / "app.py").write_text("pass")
    (tmp_path / "other.py").write_text("pass")
    paths = {"tampered": ["app.py"], "extra": ["app.py", "other.py"], "wrong_name": ["other.py"]}[
        fault
    ]
    bundle = seal(tmp_path, paths)
    if fault == "tampered":
        bundle["artifact_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        materialize_application(bundle, tmp_path / "output")
    assert not (tmp_path / "output").exists()
