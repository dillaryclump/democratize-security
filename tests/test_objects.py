import hashlib
import json
import os
import stat

import pytest

from democratize_security import artifacts, objects


@pytest.fixture
def sample(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('synthetic')\n")
    directory = tmp_path / "objects"
    directory.mkdir()
    return directory, artifacts.seal(source, ["app.py"])


def location(directory, reference):
    return directory / (reference["object_sha256"] + ".json")


def test_roundtrip_identities_and_exact_retry(sample):
    directory, bundle = sample
    reference = objects.publish_artifact(directory, bundle)
    path = location(directory, reference)
    assert reference["object_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert reference["artifact_sha256"] == bundle["artifact_sha256"]
    assert reference["object_sha256"] != reference["artifact_sha256"]
    inode = path.stat().st_ino
    assert objects.publish_artifact(directory, bundle) == reference
    assert path.stat().st_ino == inode
    assert objects.read_artifact(directory, reference) == bundle
    assert len(list(directory.iterdir())) == 1
    bundle["files"].clear()
    loaded = objects.read_artifact(directory, reference)
    loaded["files"].clear()
    assert objects.read_artifact(directory, reference)["files"]
    assert set(reference) == {
        "reference_version",
        "kind",
        "schema_version",
        "object_sha256",
        "byte_length",
        "artifact_sha256",
    }


@pytest.mark.parametrize(
    "change", ["missing", "truncated", "same_size", "symlink", "hardlink", "fifo"]
)
def test_reject_missing_changed_or_unsafe_object(sample, tmp_path, change):
    directory, bundle = sample
    reference = objects.publish_artifact(directory, bundle)
    path = location(directory, reference)
    data = path.read_bytes()
    path.unlink()
    if change == "truncated":
        path.write_bytes(data[:-1])
    elif change == "same_size":
        path.write_bytes(b"X" + data[1:])
    elif change in ("symlink", "hardlink"):
        target = tmp_path / "elsewhere"
        target.write_bytes(data)
        if change == "symlink":
            path.symlink_to(target)
        else:
            os.link(target, path)
    elif change == "fifo":
        os.mkfifo(path)
    with pytest.raises((OSError, ValueError)):
        objects.read_artifact(directory, reference)
    if change != "missing":
        with pytest.raises((OSError, ValueError)):
            objects.publish_artifact(directory, bundle)
        assert path.lstat()  # Never remove a corrupt existing destination.


@pytest.mark.parametrize(
    "key,value",
    [
        ("object_sha256", "../escape"),
        ("artifact_sha256", "a" * 64),
        ("byte_length", True),
        ("byte_length", 999999999),
        ("schema_version", True),
        ("reference_version", 2),
        ("kind", "verifier_result"),
        ("extra", "ignored"),
    ],
)
def test_reference_validation(sample, key, value):
    directory, bundle = sample
    reference = objects.publish_artifact(directory, bundle)
    reference[key] = value
    with pytest.raises(artifacts.ArtifactError):
        objects.read_artifact(directory, reference)


def test_noncanonical_bytes_rejected_even_with_matching_raw_hash(sample):
    directory, bundle = sample
    reference = objects.publish_artifact(directory, bundle)
    data = json.dumps(bundle, indent=2).encode()
    reference.update(object_sha256=hashlib.sha256(data).hexdigest(), byte_length=len(data))
    location(directory, reference).write_bytes(data)
    with pytest.raises(artifacts.ArtifactError, match="noncanonical"):
        objects.read_artifact(directory, reference)


def test_symlink_directory_rejected(sample, tmp_path):
    directory, bundle = sample
    reference = objects.publish_artifact(directory, bundle)
    link = tmp_path / "link"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(OSError):
        objects.publish_artifact(link, bundle)
    with pytest.raises(OSError):
        objects.read_artifact(link, reference)


@pytest.mark.parametrize("stage", ["file", "directory"])
def test_publication_sync_failure_and_retry_reconciliation(sample, monkeypatch, stage):
    directory, bundle = sample
    real_sync = os.fsync

    def fail(fd):
        is_directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        if is_directory == (stage == "directory"):
            raise OSError("injected sync failure")
        real_sync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fail)
        with pytest.raises(OSError, match="injected"):
            objects.publish_artifact(directory, bundle)
    assert len(list(directory.iterdir())) == (1 if stage == "directory" else 0)
    calls = []

    def record(fd):
        calls.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        real_sync(fd)

    monkeypatch.setattr(os, "fsync", record)
    reference = objects.publish_artifact(directory, bundle)
    assert calls[-2:] == ["file", "directory"]
    assert objects.read_artifact(directory, reference) == bundle


@pytest.mark.parametrize("stage", ["file", "directory"])
def test_existing_object_sync_failure_is_not_success(sample, monkeypatch, stage):
    directory, bundle = sample
    reference = objects.publish_artifact(directory, bundle)
    path = location(directory, reference)
    before = path.read_bytes()
    real_sync = os.fsync
    # Skip write_new's temporary-file sync; fail at existing-object reconciliation.
    monkeypatch.setattr(artifacts, "write_new", lambda *_: (_ for _ in ()).throw(FileExistsError()))

    def fail(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode) == (stage == "directory"):
            raise OSError("reconciliation sync failed")
        real_sync(fd)

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError, match="reconciliation"):
        objects.publish_artifact(directory, bundle)
    assert path.read_bytes() == before


def test_limits_apply_before_publication_and_read(sample, monkeypatch):
    directory, bundle = sample
    reference = objects.publish_artifact(directory, bundle)
    monkeypatch.setattr(artifacts, "MAX_BUNDLE_BYTES", 1)
    with pytest.raises(artifacts.ArtifactError):
        objects.publish_artifact(directory, bundle)
    with pytest.raises(artifacts.ArtifactError):
        objects.read_artifact(directory, reference)
    assert len(list(directory.iterdir())) == 1


def test_link_failure_leaves_no_acknowledged_object(sample, monkeypatch):
    directory, bundle = sample

    def fail(*args, **kwargs):
        raise OSError("injected link failure")

    monkeypatch.setattr(os, "link", fail)
    with pytest.raises(OSError, match="injected link"):
        objects.publish_artifact(directory, bundle)
    assert not list(directory.iterdir())


def test_post_publication_corruption_rejected_before_reference_return(sample, monkeypatch):
    directory, bundle = sample
    real_write = artifacts.write_new

    def corrupt(value, destination):
        real_write(value, destination)
        data = destination.read_bytes()
        destination.write_bytes(b"X" + data[1:])

    monkeypatch.setattr(artifacts, "write_new", corrupt)
    with pytest.raises(artifacts.ArtifactError, match="integrity"):
        objects.publish_artifact(directory, bundle)
    assert len(list(directory.iterdir())) == 1  # Retained orphan, not a result.


def test_reference_must_be_an_object(sample):
    directory, bundle = sample
    reference = objects.publish_artifact(directory, bundle)
    with pytest.raises(artifacts.ArtifactError):
        objects.read_artifact(directory, list(reference.items()))
