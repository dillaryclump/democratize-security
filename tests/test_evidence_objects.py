import copy
import hashlib
import json
import multiprocessing
import os
import stat

import pytest

from democratize_security import evidence
from democratize_security import evidence_objects as objects
from democratize_security.contracts import digest
from democratize_security.verification.report import PROTOCOL, REQUIRED, Check, summarize


@pytest.fixture
def sample(tmp_path):
    binding = dict(
        schema_version=1,
        event_id="bind-1",
        request=dict(
            attempt_id="attempt-1",
            expected_revision=1,
            campaign_id="campaign-1",
            trial_id="trial-1",
            task_revision="a" * 64,
            verifier_sha256="b" * 64,
            protocol=PROTOCOL,
            artifact_ref=dict(
                reference_version=1,
                schema_version=1,
                kind="sealed_artifact",
                object_sha256="c" * 64,
                artifact_sha256="d" * 64,
                byte_length=100,
            ),
        ),
    )
    binding["binding_sha256"] = digest(binding)
    report = summarize([Check(name, "pass") for name in sorted(REQUIRED)])
    record = evidence.bind_report(binding, "verify-1", report)
    directory = tmp_path / "objects"
    directory.mkdir()
    return directory, record, binding, "verify-1"


def location(directory, reference):
    return directory / (reference["object_sha256"] + ".json")


@pytest.mark.parametrize("outcome", ["pass", "fail", "incomplete"])
def test_roundtrip_and_retry(sample, outcome):
    directory, record, binding, request = sample
    if outcome != "pass":
        report = summarize([Check(name, "fail") for name in REQUIRED] if outcome == "fail" else [])
        record = evidence.bind_report(binding, request, report)
    ref = objects.publish_evidence(directory, record, binding, request)
    path = location(directory, ref)
    inode = path.stat().st_ino
    assert objects.publish_evidence(directory, record, binding, request) == ref
    assert path.stat().st_ino == inode
    assert ref["object_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert ref["evidence_sha256"] != ref["object_sha256"]
    loaded = objects.read_evidence(directory, ref, binding, request)
    assert loaded == record
    assert loaded["report"]["outcome"] == outcome
    loaded["report"].clear()
    assert objects.read_evidence(directory, ref, binding, request) == record
    assert len(list(directory.iterdir())) == 1


@pytest.mark.parametrize(
    "change", ["missing", "truncated", "same_size", "symlink", "hardlink", "fifo", "directory"]
)
def test_unsafe_or_changed_object(sample, tmp_path, change):
    directory, record, binding, request = sample
    ref = objects.publish_evidence(*sample)
    path = location(directory, ref)
    data = path.read_bytes()
    path.unlink()
    if change == "truncated":
        path.write_bytes(data[:-1])
    elif change == "same_size":
        path.write_bytes(b"X" + data[1:])
    elif change in ("symlink", "hardlink"):
        target = tmp_path / "target"
        target.write_bytes(data)
        path.symlink_to(target) if change == "symlink" else os.link(target, path)
    elif change == "fifo":
        os.mkfifo(path)
    elif change == "directory":
        path.mkdir()
    with pytest.raises((OSError, ValueError)):
        objects.read_evidence(directory, ref, binding, request)
    if change != "missing":
        with pytest.raises((OSError, ValueError)):
            objects.publish_evidence(*sample)
        assert path.lstat()


@pytest.mark.parametrize(
    "key,value",
    [
        ("object_sha256", "../escape"),
        ("evidence_sha256", "a" * 64),
        ("byte_length", True),
        ("byte_length", 65537),
        ("schema_version", True),
        ("reference_version", 2),
        ("kind", "sealed_artifact"),
        ("extra", 0),
    ],
)
def test_invalid_reference(sample, key, value):
    directory, _, binding, request = sample
    ref = objects.publish_evidence(*sample)
    ref[key] = value
    with pytest.raises(evidence.EvidenceError):
        objects.read_evidence(directory, ref, binding, request)


def test_context_and_canonical_bytes(sample):
    directory, record, binding, request = sample
    ref = objects.publish_evidence(*sample)
    other = copy.deepcopy(binding)
    other["request"]["attempt_id"] = "another-attempt"
    other["binding_sha256"] = digest({k: v for k, v in other.items() if k != "binding_sha256"})
    for expected_binding, expected_request in [(other, request), (binding, "other-request")]:
        with pytest.raises(evidence.EvidenceError):
            objects.read_evidence(directory, ref, expected_binding, expected_request)
        with pytest.raises(evidence.EvidenceError):
            objects.publish_evidence(directory, record, expected_binding, expected_request)
    data = json.dumps(record, indent=2).encode()
    ref.update(object_sha256=hashlib.sha256(data).hexdigest(), byte_length=len(data))
    location(directory, ref).write_bytes(data)
    with pytest.raises(evidence.EvidenceError, match="Noncanonical"):
        objects.read_evidence(directory, ref, binding, request)


def test_directory_symlink_and_limits(sample, tmp_path, monkeypatch):
    directory, record, binding, request = sample
    ref = objects.publish_evidence(*sample)
    link = tmp_path / "link"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(OSError):
        objects.publish_evidence(link, record, binding, request)
    with pytest.raises(OSError):
        objects.read_evidence(link, ref, binding, request)
    monkeypatch.setattr(evidence, "MAX_EVIDENCE_BYTES", 1)
    with pytest.raises(evidence.EvidenceError):
        objects.publish_evidence(*sample)
    with pytest.raises(evidence.EvidenceError):
        objects.read_evidence(directory, ref, binding, request)


@pytest.mark.parametrize("stage", ["file", "directory", "link"])
def test_publication_failure_and_retry(sample, monkeypatch, stage):
    directory, record, binding, request = sample
    real_sync = os.fsync

    def fail_sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode) == (stage == "directory"):
            raise OSError("injected sync")
        real_sync(fd)

    def fail_link(*args, **kwargs):
        raise OSError("injected link")

    with monkeypatch.context() as patch:
        patch.setattr(os, "link", fail_link) if stage == "link" else patch.setattr(
            os, "fsync", fail_sync
        )
        with pytest.raises(OSError, match="injected"):
            objects.publish_evidence(*sample)
    assert len(list(directory.iterdir())) == (1 if stage == "directory" else 0)
    calls = []

    def track(fd):
        calls.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        real_sync(fd)

    monkeypatch.setattr(os, "fsync", track)
    ref = objects.publish_evidence(*sample)
    assert calls[-2:] == ["file", "directory"]
    assert objects.read_evidence(directory, ref, binding, request) == record


@pytest.mark.parametrize("stage", ["file", "directory"])
def test_existing_object_reconciliation_failure(sample, monkeypatch, stage):
    ref = objects.publish_evidence(*sample)
    data = location(sample[0], ref).read_bytes()

    def exists(*args):
        raise FileExistsError()

    monkeypatch.setattr(objects, "_write_new", exists)
    real_sync = os.fsync

    def fail(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode) == (stage == "directory"):
            raise OSError("reconciliation failed")
        real_sync(fd)

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError, match="reconciliation"):
        objects.publish_evidence(*sample)
    assert location(sample[0], ref).read_bytes() == data


def crash_publish(sample, stage):
    real_sync, real_link = os.fsync, os.link

    def sync(fd):
        directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        if stage == "before_directory_sync" and directory:
            os._exit(71)
        real_sync(fd)
        if stage == "after_directory_sync" and directory:
            os._exit(71)
        if stage == "after_file_sync" and not directory:
            os._exit(71)

    def link(*args, **kwargs):
        real_link(*args, **kwargs)
        if stage == "after_link":
            os._exit(71)

    os.fsync, os.link = sync, link
    objects.publish_evidence(*sample)
    os._exit(72)


@pytest.mark.parametrize(
    "stage", ["after_file_sync", "after_link", "before_directory_sync", "after_directory_sync"]
)
def test_process_crash_windows(sample, stage):
    directory, record, binding, request = sample
    process = multiprocessing.get_context("fork").Process(
        target=crash_publish, args=(sample, stage)
    )
    process.start()
    process.join(10)
    if process.is_alive():
        process.kill()
        process.join()
        pytest.fail("publication process hung")
    assert process.exitcode == 71
    if stage == "after_link":
        # The temporary hardlink is retained; no automatic orphan deletion or
        # silent acceptance of a multiply-linked object after a process death.
        with pytest.raises(evidence.EvidenceError, match="singly linked"):
            objects.publish_evidence(*sample)
        assert len(list(directory.iterdir())) == 2
    else:
        ref = objects.publish_evidence(*sample)
        assert objects.read_evidence(directory, ref, binding, request) == record
        if stage == "after_file_sync":
            assert len(list(directory.glob(".evidence-*"))) == 1


def test_corruption_before_return(sample, monkeypatch):
    real_write = objects._write_new

    def corrupt(directory, root, name, data):
        real_write(directory, root, name, data)
        (directory / name).write_bytes(b"X" + data[1:])

    monkeypatch.setattr(objects, "_write_new", corrupt)
    with pytest.raises(evidence.EvidenceError, match="integrity"):
        objects.publish_evidence(*sample)
