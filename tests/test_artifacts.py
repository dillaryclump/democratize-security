import copy
import json
import os
import stat

import pytest

from democratize_security import artifacts as a
from democratize_security.cli import main


@pytest.fixture
def root(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_bytes(b"print('synthetic')\n")
    (source / "nested").mkdir()
    (source / "nested" / "data.bin").write_bytes(b"\x00\xff")
    return source


def test_stable_seal_and_explicit_allowlist(root):
    first = a.seal(root, ["app.py", "nested/data.bin"])
    assert first == a.seal(root, ["nested/data.bin", "app.py"])
    assert a.validate(first)["file_count"] == 2
    (root / "ignored-secret").write_text("never bundled")
    assert first == a.seal(root, ["app.py", "nested/data.bin"])
    (root / "app.py").write_text("changed")
    assert (
        first["artifact_sha256"] != a.seal(root, ["app.py", "nested/data.bin"])["artifact_sha256"]
    )


@pytest.mark.parametrize(
    "path",
    ["../secret", "/etc/passwd", "a/../b", "a//b", "./app.py", "a\\b", "a/", ".env", "a\x00b"],
)
def test_invalid_paths(root, path):
    with pytest.raises(a.ArtifactError):
        a.seal(root, [path])


@pytest.mark.parametrize("paths", [[], ["app.py", "app.py"], ["a", "A"], ["a", "a/b"]])
def test_invalid_allowlists(root, paths):
    with pytest.raises(a.ArtifactError):
        a.seal(root, paths)


def test_symlink_file_and_parent_rejected(root):
    (root / "link.py").symlink_to(root / "app.py")
    (root / "linkdir").symlink_to(root / "nested", target_is_directory=True)
    for path in ("link.py", "linkdir/data.bin"):
        with pytest.raises(OSError):
            a.seal(root, [path])


def test_hardlink_and_fifo_rejected_without_blocking(root):
    os.link(root / "app.py", root / "hard.py")
    os.mkfifo(root / "pipe")
    for path in ("hard.py", "pipe"):
        with pytest.raises(a.ArtifactError):
            a.seal(root, [path])


def test_limits(root, monkeypatch):
    monkeypatch.setattr(a, "MAX_FILE_BYTES", 1)
    with pytest.raises(a.ArtifactError):
        a.seal(root, ["app.py"])
    monkeypatch.setattr(a, "MAX_FILE_BYTES", 1024)
    monkeypatch.setattr(a, "MAX_TOTAL_BYTES", 1)
    with pytest.raises(a.ArtifactError):
        a.seal(root, ["app.py"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("size", True),
        ("size", 999),
        ("sha256", "0" * 64),
        ("content_base64", "!!!"),
        ("path", "../escape"),
    ],
)
def test_tampered_entry_rejected(root, field, value):
    bundle = a.seal(root, ["app.py"])
    bundle["files"][0][field] = value
    with pytest.raises(a.ArtifactError):
        a.validate(bundle)


def test_roundtrip_and_no_overwrite(root, tmp_path):
    bundle = a.seal(root, ["app.py"])
    output = tmp_path / "bundle.json"
    a.write_new(bundle, output)
    assert a.load(output) == bundle
    with pytest.raises(FileExistsError):
        a.write_new(bundle, output)
    assert a.load(output) == bundle
    assert not list(tmp_path.glob(".artifact-*"))


def test_duplicate_json_and_oversized_input(tmp_path, monkeypatch):
    path = tmp_path / "bundle.json"
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError):
        a.load(path)
    monkeypatch.setattr(a, "MAX_BUNDLE_BYTES", 1)
    with pytest.raises(a.ArtifactError):
        a.load(path)


def test_publication_syncs_contents_then_directory(root, tmp_path, monkeypatch):
    bundle = a.seal(root, ["app.py"])
    output = tmp_path / "bundle.json"
    real_fsync = os.fsync
    synced = []

    def observe_sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            assert a.load(output) == bundle
            assert not list(tmp_path.glob(".artifact-*"))
            synced.append("directory")
        else:
            assert not output.exists()
            synced.append("file")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", observe_sync)
    a.write_new(bundle, output)
    assert synced == ["file", "directory"]


@pytest.mark.parametrize("fail_directory", [False, True])
def test_sync_failure_is_not_success(root, tmp_path, monkeypatch, fail_directory):
    bundle = a.seal(root, ["app.py"])
    output = tmp_path / "bundle.json"
    real_fsync = os.fsync
    descriptors = []

    def fail_sync(fd):
        descriptors.append(fd)
        if stat.S_ISDIR(os.fstat(fd).st_mode) == fail_directory:
            raise OSError("injected sync failure")
        real_fsync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fail_sync)
        with pytest.raises(OSError, match="injected sync failure"):
            a.write_new(bundle, output)
    assert not list(tmp_path.glob(".artifact-*"))
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)
    if fail_directory:
        # Publication already happened. Keep the exact bytes for reconciliation;
        # a retry must never overwrite them or imply a new successful publication.
        assert a.load(output) == bundle
        with pytest.raises(FileExistsError):
            a.write_new(bundle, output)
        assert a.load(output) == bundle
    else:
        assert not output.exists()
        a.write_new(bundle, output)
        assert a.load(output) == bundle


def test_evidence_binding_and_caller_mutation(root):
    bundle = a.seal(root, ["app.py"])
    result = {"outcome": "incomplete"}
    evidence = a.bind_evidence(bundle, "a" * 64, result)
    result["outcome"] = "pass"
    assert evidence["result"]["outcome"] == "incomplete"
    a.validate_evidence(evidence, bundle, "a" * 64)
    tampered = copy.deepcopy(evidence)
    tampered["result"]["outcome"] = "pass"
    with pytest.raises(a.ArtifactError):
        a.validate_evidence(tampered, bundle, "a" * 64)
    with pytest.raises(a.ArtifactError):
        a.validate_evidence(evidence, bundle, "b" * 64)
    (root / "app.py").write_text("changed")
    with pytest.raises(a.ArtifactError):
        a.validate_evidence(evidence, a.seal(root, ["app.py"]), "a" * 64)


def test_cli(root, tmp_path, capsys):
    output = tmp_path / "sealed.json"
    assert main(["seal", str(root), "--file", "app.py", "--output", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["paths"] == ["app.py"]
    assert main(["inspect-artifact", str(output)]) == 0
    capsys.readouterr()
    assert main(["seal", str(root), "--file", "../outside", "--output", str(output)]) == 2
