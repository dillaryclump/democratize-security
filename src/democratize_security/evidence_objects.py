"""Durable offline evidence objects, without ledger or execution authority.

The caller owns an existing durable controller-only directory and keeps it and
its ancestors stable. Expected bindings/requests come from trusted state, never
from these files. Publication is not authentication or result acceptance.
"""

import hashlib
import os
import re
import stat
import tempfile
from pathlib import Path

from democratize_security import evidence
from democratize_security.evidence import EvidenceError


def _reference(record: dict, data: bytes) -> dict:
    return {
        "reference_version": 1,
        "kind": "offline_verifier_evidence",
        "schema_version": 1,
        "object_sha256": hashlib.sha256(data).hexdigest(),
        "byte_length": len(data),
        "evidence_sha256": record["evidence_sha256"],
    }


def _filename(reference: dict) -> str:
    if not isinstance(reference, dict) or set(reference) != {
        "reference_version",
        "kind",
        "schema_version",
        "object_sha256",
        "byte_length",
        "evidence_sha256",
    }:
        raise EvidenceError("Invalid evidence object reference")
    if (
        type(reference["reference_version"]) is not int
        or reference["reference_version"] != 1
        or type(reference["schema_version"]) is not int
        or reference["schema_version"] != 1
        or reference["kind"] != "offline_verifier_evidence"
        or type(reference["byte_length"]) is not int
        or not 0 < reference["byte_length"] <= evidence.MAX_EVIDENCE_BYTES
    ):
        raise EvidenceError("Unsupported evidence reference or length")
    for key in ("object_sha256", "evidence_sha256"):
        if not isinstance(reference[key], str) or not re.fullmatch(r"[0-9a-f]{64}", reference[key]):
            raise EvidenceError("Invalid evidence object digest")
    return reference["object_sha256"] + ".json"


def _read(root, reference, binding, request_id, *, reconcile=False):
    fd = os.open(_filename(reference), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise EvidenceError("Evidence object must be regular and singly linked")
        if before.st_size != reference["byte_length"]:
            raise EvidenceError("Evidence object length mismatch")
        chunks, size = [], 0
        while chunk := os.read(fd, reference["byte_length"] + 1 - size):
            chunks.append(chunk)
            size += len(chunk)
            if size > reference["byte_length"]:
                raise EvidenceError("Evidence object grew during read")
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise EvidenceError("Evidence object changed during read")
        data = b"".join(chunks)
        if (
            len(data) != reference["byte_length"]
            or hashlib.sha256(data).hexdigest() != reference["object_sha256"]
        ):
            raise EvidenceError("Evidence object integrity mismatch")
        record = evidence.decode_evidence(data, binding, request_id)
        if _reference(record, data) != reference:
            raise EvidenceError("Evidence object identity mismatch")
        if reconcile:
            os.fsync(fd)
            os.fsync(root)
        return record
    finally:
        os.close(fd)


def read_evidence(
    directory: Path, reference: dict, binding: dict, verification_request_id: str
) -> dict:
    """Revalidate bounded canonical bytes against independently selected context."""
    _filename(reference)
    root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return _read(root, dict(reference), binding, verification_request_id)
    finally:
        os.close(root)


def _write_new(directory, root, name, data):
    fd, temporary = tempfile.mkstemp(prefix=".evidence-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, name, dst_dir_fd=root, follow_symlinks=False)
    finally:
        os.unlink(temporary)
    os.fsync(root)


def publish_evidence(
    directory: Path, record: dict, binding: dict, verification_request_id: str
) -> dict:
    """Publish without replacement; reconcile exact existing objects with fsync.

    Failures may leave orphans, never accepted results. A process death between
    link and temporary-name removal leaves two links: reads/retries reject that
    object until explicit operator reconciliation. No orphan cleanup is automatic.
    """
    data = evidence.encode_evidence(record, binding, verification_request_id)
    frozen = evidence.decode_evidence(data, binding, verification_request_id)
    reference = _reference(frozen, data)
    root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            _write_new(directory, root, _filename(reference), data)
        except FileExistsError:
            _read(root, reference, binding, verification_request_id, reconcile=True)
        else:
            _read(root, reference, binding, verification_request_id)
        return reference
    finally:
        os.close(root)
