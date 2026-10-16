"""Content-addressed sealed artifacts, without ledger or execution authority.

The caller owns an existing durable local directory and keeps its pathname stable.
Candidate processes must never have access. Hashes detect changes, not provenance.
"""

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from democratize_security import artifacts
from democratize_security.contracts import _unique_pairs


def _encode(bundle: dict) -> bytes:
    artifacts.validate(bundle)
    data = json.dumps(bundle, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(data) > artifacts.MAX_BUNDLE_BYTES:
        raise artifacts.ArtifactError("Object exceeds encoded byte limit")
    return data


def _reference(bundle: dict, data: bytes) -> dict:
    return {
        "reference_version": 1,
        "kind": "sealed_artifact",
        "schema_version": 1,
        "object_sha256": hashlib.sha256(data).hexdigest(),
        "byte_length": len(data),
        "artifact_sha256": bundle["artifact_sha256"],
    }


def _filename(reference: dict) -> str:
    if not isinstance(reference, dict) or set(reference) != {
        "reference_version",
        "kind",
        "schema_version",
        "object_sha256",
        "byte_length",
        "artifact_sha256",
    }:
        raise artifacts.ArtifactError("Invalid object reference")
    if (
        type(reference["reference_version"]) is not int
        or reference["reference_version"] != 1
        or type(reference["schema_version"]) is not int
        or reference["schema_version"] != 1
        or reference["kind"] != "sealed_artifact"
        or type(reference["byte_length"]) is not int
        or not 0 < reference["byte_length"] <= artifacts.MAX_BUNDLE_BYTES
    ):
        raise artifacts.ArtifactError("Unsupported object reference or length")
    for key in ("object_sha256", "artifact_sha256"):
        if not isinstance(reference[key], str) or not re.fullmatch(r"[0-9a-f]{64}", reference[key]):
            raise artifacts.ArtifactError("Invalid object digest")
    return reference["object_sha256"] + ".json"


def _read(directory: Path, reference: dict, *, reconcile: bool = False) -> dict:
    name = _filename(reference)
    root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise artifacts.ArtifactError("Object must be regular and singly linked")
            if before.st_size != reference["byte_length"]:
                raise artifacts.ArtifactError("Object length mismatch")
            chunks = []
            size = 0
            while chunk := os.read(fd, min(65536, reference["byte_length"] + 1 - size)):
                chunks.append(chunk)
                size += len(chunk)
                if size > reference["byte_length"]:
                    raise artifacts.ArtifactError("Object grew during read")
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise artifacts.ArtifactError("Object changed during read")
            data = b"".join(chunks)
            if (
                len(data) != reference["byte_length"]
                or hashlib.sha256(data).hexdigest() != reference["object_sha256"]
            ):
                raise artifacts.ArtifactError("Object integrity mismatch")
            bundle = json.loads(data, object_pairs_hook=_unique_pairs)
            if _encode(bundle) != data or _reference(bundle, data) != reference:
                raise artifacts.ArtifactError("Object is noncanonical or has mismatched identity")
            if reconcile:
                # An earlier publication may have failed after linking. Exact
                # bytes alone are insufficient: finish both durability barriers.
                os.fsync(fd)
                os.fsync(root)
            return bundle
        finally:
            os.close(fd)
    finally:
        os.close(root)


def read_artifact(directory: Path, reference: dict) -> dict:
    """Revalidate bounded bytes and both identities; never infer a passed result."""
    _filename(reference)
    return _read(directory, dict(reference))


def publish_artifact(directory: Path, bundle: dict) -> dict:
    """Publish or reconcile exact existing bytes, returning a detached reference.

    Errors may leave an orphan, which is never a ledger reference or a result.
    No existing object is replaced or deleted, including a corrupt destination.
    """
    data = _encode(bundle)
    frozen = json.loads(data)
    reference = _reference(frozen, data)
    # Reject a symlink directory before pathname-based write_new. The trusted
    # owner must keep this directory and all its ancestors stable throughout.
    root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    os.close(root)
    try:
        artifacts.write_new(frozen, directory / _filename(reference))
    except FileExistsError:
        _read(directory, reference, reconcile=True)
    else:
        _read(directory, reference)
    return reference
