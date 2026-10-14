"""Bounded, non-executable candidate transfer format for a stopped worker.

The controller chooses the allowlist and owns the output directory. Hashes do
not provide sandboxing, signatures, or evidence that these bytes were executed.
"""

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path

from democratize_security.contracts import _unique_pairs, digest

MAX_FILES = 128
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_BUNDLE_BYTES = 12 * 1024 * 1024


class ArtifactError(ValueError):
    """The candidate artifact cannot be accepted."""


def _path(value: str) -> list[str]:
    if not isinstance(value, str) or len(value) > 240:
        raise ArtifactError("Invalid artifact path")
    parts = value.split("/")
    if any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", p) for p in parts):
        raise ArtifactError("Paths must be relative portable names without traversal")
    return parts


def _paths(paths: list[str]) -> list[str]:
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_FILES:
        raise ArtifactError("An explicit allowlist of 1–128 files is required")
    for path in paths:
        _path(path)
    ordered = sorted(paths)
    if len({p.casefold() for p in ordered}) != len(ordered):
        raise ArtifactError("Duplicate or case-colliding paths")
    for path in ordered:
        if any(other.casefold().startswith(path.casefold() + "/") for other in ordered):
            raise ArtifactError("File/directory path collision")
    return ordered


def _read(root_fd: int, path: str) -> bytes:
    # Walk using directory descriptors. A replaced parent cannot redirect a
    # later pathname lookup outside the already-opened directory.
    descriptor = os.dup(root_fd)
    try:
        parts = _path(path)
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ArtifactError("Only regular, non-hardlinked files are allowed")
            if before.st_size > MAX_FILE_BYTES:
                raise ArtifactError("File exceeds byte limit")
            chunks = []
            size = 0
            while chunk := os.read(file_fd, min(65536, MAX_FILE_BYTES + 1 - size)):
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise ArtifactError("File grew beyond byte limit")
            after = os.fstat(file_fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) or size != after.st_size:
                raise ArtifactError("File changed during sealing; stop the worker first")
            return b"".join(chunks)
        finally:
            os.close(file_fd)
    finally:
        os.close(descriptor)


def seal(root: Path, allowlist: list[str]) -> dict:
    paths = _paths(allowlist)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ArtifactError("Safe sealing requires a POSIX host with O_NOFOLLOW")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        files = []
        total = 0
        for path in paths:
            data = _read(root_fd, path)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise ArtifactError("Artifact exceeds total byte limit")
            files.append(
                {
                    "path": path,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "content_base64": base64.b64encode(data).decode("ascii"),
                }
            )
        payload = {"schema_version": 1, "files": files}
        return {"artifact_sha256": digest(payload), **payload}
    finally:
        os.close(root_fd)


def validate(bundle: dict) -> dict:
    if not isinstance(bundle, dict) or set(bundle) != {
        "schema_version",
        "files",
        "artifact_sha256",
    }:
        raise ArtifactError("Invalid artifact envelope")
    if type(bundle["schema_version"]) is not int or bundle["schema_version"] != 1:
        raise ArtifactError("Unsupported artifact version")
    files = bundle["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ArtifactError("Invalid file count")
    total = 0
    paths = []
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "size",
            "sha256",
            "content_base64",
        }:
            raise ArtifactError("Invalid file entry")
        paths.append(entry["path"])
        if type(entry["size"]) is not int or not 0 <= entry["size"] <= MAX_FILE_BYTES:
            raise ArtifactError("Invalid file size")
        content = entry["content_base64"]
        if not isinstance(content, str) or len(content) > 4 * ((MAX_FILE_BYTES + 2) // 3):
            raise ArtifactError("Invalid encoded file size")
        try:
            data = base64.b64decode(content, validate=True)
        except ValueError as error:
            raise ArtifactError("Invalid base64") from error
        if base64.b64encode(data).decode("ascii") != content:
            raise ArtifactError("Noncanonical base64")
        if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ArtifactError("File integrity mismatch")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ArtifactError("Artifact exceeds total byte limit")
    if paths != _paths(paths):
        raise ArtifactError("Files must be canonically ordered")
    if bundle["artifact_sha256"] != digest({"schema_version": 1, "files": files}):
        raise ArtifactError("Artifact integrity mismatch")
    return {
        "artifact_sha256": bundle["artifact_sha256"],
        "file_count": len(files),
        "total_bytes": total,
        "paths": paths,
    }


def load(path: Path) -> dict:
    with path.open("rb") as stream:
        data = stream.read(MAX_BUNDLE_BYTES + 1)
    if len(data) > MAX_BUNDLE_BYTES:
        raise ArtifactError("Bundle exceeds encoded byte limit")
    bundle = json.loads(data, object_pairs_hook=_unique_pairs)
    validate(bundle)
    return bundle


def write_new(bundle: dict, destination: Path) -> None:
    """Publish a complete file without ever replacing an existing artifact."""
    validate(bundle)
    data = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()
    fd, name = tempfile.mkstemp(prefix=".artifact-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(name, destination)  # Atomic publication, fails if destination exists.
    finally:
        os.unlink(name)


def bind_evidence(bundle: dict, verifier_sha256: str, result: dict) -> dict:
    """Record a trusted verifier's result; does not authorize or perform grading."""
    validate(bundle)
    if not isinstance(verifier_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", verifier_sha256):
        raise ArtifactError("A concrete verifier SHA-256 is required")
    if not isinstance(result, dict):
        raise ArtifactError("Verifier result must be a JSON object")
    record = {
        "schema_version": 1,
        "artifact_sha256": bundle["artifact_sha256"],
        "verifier_sha256": verifier_sha256,
        "result": result,
    }
    # Round-trip so later caller mutations cannot change the stored record.
    return json.loads(json.dumps({"evidence_sha256": digest(record), **record}, allow_nan=False))


def validate_evidence(record: dict, bundle: dict, verifier_sha256: str) -> None:
    if not isinstance(record, dict) or set(record) != {
        "schema_version",
        "artifact_sha256",
        "verifier_sha256",
        "result",
        "evidence_sha256",
    }:
        raise ArtifactError("Invalid evidence envelope")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        raise ArtifactError("Unsupported evidence version")
    expected = bind_evidence(bundle, verifier_sha256, record["result"])
    if record != expected:
        raise ArtifactError("Evidence does not match artifact, verifier or result")
