"""Verified offline ledger snapshots. No runtime, secret or execution authority.

Callers own stable local paths and pause external work before backing up. New
destinations are never replaced: an interrupted operation leaves an incomplete
directory for explicit operator inspection. Publication is acknowledged only
after validation and file/directory durability barriers.
"""

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from democratize_security.artifacts import MAX_BUNDLE_BYTES
from democratize_security.contracts import _unique_pairs, digest
from democratize_security.evidence import MAX_EVIDENCE_BYTES
from democratize_security.store import VERSION, PlanStore

# Added schemas require reviewed object, ownership and restoration semantics.
SUPPORTED_STORE_VERSIONS = frozenset({7})
MAX_DATABASE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_BACKUP_FILES = 100_001
_HASH = re.compile(r"[0-9a-f]{64}")


class BackupError(ValueError):
    """A snapshot or restore cannot be acknowledged safely."""


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    return fd


def _sync_directory(path):
    fd = _directory(path)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_file(path, limit, *, copy_to=None, capture=False):
    """Read only bounded, regular, singly linked files; detect concurrent changes."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    output = None
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= limit
        ):
            raise BackupError("Invalid backup file type, links or byte length")
        if copy_to is not None:
            output = os.open(copy_to, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        hasher, size, chunks = hashlib.sha256(), 0, []
        while chunk := os.read(fd, min(1024 * 1024, limit + 1 - size)):
            size += len(chunk)
            if size > limit:
                raise BackupError("Backup file exceeded its byte limit")
            hasher.update(chunk)
            if capture:
                chunks.append(chunk)
            if output is not None:
                remaining = memoryview(chunk)
                while remaining:
                    written = os.write(output, remaining)
                    if written <= 0:
                        raise BackupError("Incomplete backup file write")
                    remaining = remaining[written:]
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
        ) or size != before.st_size:
            raise BackupError("Backup file changed during read")
        if output is not None:
            os.fsync(output)
        identity = {"byte_length": size, "sha256": hasher.hexdigest()}
        return (identity, b"".join(chunks)) if capture else identity
    finally:
        if output is not None:
            os.close(output)
        os.close(fd)


def _write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _new_destination(destination):
    destination = Path(destination).absolute()
    # Existing directories, symlinks and partial operations are all refused.
    destination.mkdir(mode=0o700)
    for name in ("ledger", "artifacts", "evidence"):
        (destination / name).mkdir(mode=0o700)
    _sync_directory(destination)
    _sync_directory(destination.parent)
    return destination


def _references(store):
    """Only this explicitly supported schema's referenced object kinds are copied."""
    if VERSION not in SUPPORTED_STORE_VERSIONS:
        raise BackupError("Store version requires a reviewed backup implementation")
    _ = store.controller_generation  # Revalidate ownership before snapshot admission.
    campaigns = [
        campaign_id
        for (campaign_id,) in store._connection().execute(
            "SELECT campaign_id FROM campaigns ORDER BY campaign_id"
        )
    ]
    for campaign_id in campaigns:
        store.snapshot(campaign_id)
    refs = {}
    for record in store.artifact_bindings():
        ref = record["request"]["artifact_ref"]
        refs[f"artifacts/{ref['object_sha256']}.json"] = ref["byte_length"]
    for record in store.evidence_bindings():
        ref = record["request"]["evidence_ref"]
        refs[f"evidence/{ref['object_sha256']}.json"] = ref["byte_length"]
    store.runtime_results()  # Revalidate admitted results; their envelopes are inline.
    for state in store.attempts():
        ref = state.get("artifact_ref")
        if state.get("mode") == "runtime" and ref is not None:
            refs[f"artifacts/{ref['object_sha256']}.json"] = ref["byte_length"]
    if len(refs) + 1 > MAX_BACKUP_FILES:
        raise BackupError("Backup file count exceeded")
    return campaigns, refs


def _limit(path):
    if path == "ledger/ledger.sqlite3":
        return MAX_DATABASE_BYTES
    if re.fullmatch(r"artifacts/[0-9a-f]{64}\.json", path):
        return MAX_BUNDLE_BYTES
    if re.fullmatch(r"evidence/[0-9a-f]{64}\.json", path):
        return MAX_EVIDENCE_BYTES
    raise BackupError("Unexpected backup file path")


def _manifest(directory):
    path = directory / "manifest.json"
    _, data = _read_file(path, MAX_MANIFEST_BYTES, capture=True)
    try:
        record = json.loads(data, object_pairs_hook=_unique_pairs)
        if _encode(record) != data:
            raise BackupError("Manifest must be finite canonical JSON")
        if not isinstance(record, dict) or set(record) != {
            "schema_version",
            "kind",
            "store_version",
            "campaign_ids",
            "files",
            "execution_enabled",
            "restore_requires_reconciliation",
        }:
            raise BackupError("Invalid backup manifest fields")
        if type(record["store_version"]) is int and record["store_version"] in (5, 6):
            raise BackupError(
                f"Version {record['store_version']} backup requires its matching backup tool: "
                "restore there, explicitly migrate that ledger, then create a new version "
                f"{VERSION} backup"
            )
        if (
            type(record["schema_version"]) is not int
            or record["schema_version"] != 1
            or record["kind"] != "offline_store_backup"
            or type(record["store_version"]) is not int
            or record["store_version"] not in SUPPORTED_STORE_VERSIONS
            or record["store_version"] != VERSION
            or record["execution_enabled"] is not False
            or record["restore_requires_reconciliation"] is not True
        ):
            raise BackupError("Unsupported backup schema, store version or authority")
        campaigns, files = record["campaign_ids"], record["files"]
        if (
            not isinstance(campaigns, list)
            or any(not isinstance(c, str) or not _HASH.fullmatch(c) for c in campaigns)
            or campaigns != sorted(set(campaigns))
            or not isinstance(files, list)
            or not 1 <= len(files) <= MAX_BACKUP_FILES
        ):
            raise BackupError("Invalid campaign or file inventory")
        paths = []
        for entry in files:
            if not isinstance(entry, dict) or set(entry) != {"path", "byte_length", "sha256"}:
                raise BackupError("Invalid file inventory entry")
            name, length, sha = entry["path"], entry["byte_length"], entry["sha256"]
            if (
                not isinstance(name, str)
                or type(length) is not int
                or not 0 < length <= _limit(name)
                or not isinstance(sha, str)
                or not _HASH.fullmatch(sha)
            ):
                raise BackupError("Invalid file identity or byte limit")
            paths.append(name)
        if paths != sorted(set(paths)) or "ledger/ledger.sqlite3" not in paths:
            raise BackupError("Invalid or duplicate file inventory")
        return record
    except (TypeError, ValueError, RecursionError) as error:
        raise BackupError(f"Invalid backup manifest: {error}") from error


def _check_files(directory, manifest, *, published):
    expected_root = {"ledger", "artifacts", "evidence"} | (
        {"manifest.json"} if published else set()
    )
    if {p.name for p in directory.iterdir()} != expected_root:
        raise BackupError("Unexpected or missing backup directory entry")
    expected = {entry["path"]: entry for entry in manifest["files"]}
    actual = set()
    for name in ("ledger", "artifacts", "evidence"):
        fd = _directory(directory / name)
        os.close(fd)
        for path in (directory / name).iterdir():
            relative = f"{name}/{path.name}"
            if relative not in expected:
                raise BackupError("Unexpected backup file")
            if _read_file(path, _limit(relative)) != {
                key: expected[relative][key] for key in ("byte_length", "sha256")
            }:
                raise BackupError("Backup file integrity mismatch")
            actual.add(relative)
    if actual != set(expected):
        raise BackupError("Missing backup file")


def _validate_payload(directory, manifest):
    # Store v6 allocates a controller generation on every successful open.
    # Validate a private copy, preserving the frozen snapshot and its history.
    with tempfile.TemporaryDirectory(prefix="ds-backup-validation-") as temporary:
        ledger = Path(temporary) / "ledger"
        ledger.mkdir(mode=0o700)
        _read_file(
            directory / "ledger/ledger.sqlite3",
            MAX_DATABASE_BYTES,
            copy_to=ledger / "ledger.sqlite3",
        )
        with PlanStore(
            ledger,
            objects_directory=directory / "artifacts",
            evidence_directory=directory / "evidence",
        ) as store:
            campaigns, refs = _references(store)
            expected = {"ledger/ledger.sqlite3", *refs}
            actual = {entry["path"] for entry in manifest["files"]}
            if campaigns != manifest["campaign_ids"] or expected != actual:
                raise BackupError("Manifest does not match validated ledger references")


def verify_backup(directory: Path) -> dict:
    """Validate complete inventory, hashes, SQLite schema/events and all references."""
    directory = Path(directory).absolute()
    fd = _directory(directory)
    os.close(fd)
    manifest = _manifest(directory)
    _check_files(directory, manifest, published=True)
    _validate_payload(directory, manifest)
    _check_files(directory, manifest, published=True)
    if _manifest(directory) != manifest:
        raise BackupError("Manifest changed during verification")
    return manifest


def create_backup(
    ledger_directory: Path,
    destination: Path,
    *,
    objects_directory: Path | None = None,
    evidence_directory: Path | None = None,
) -> dict:
    """Snapshot a quiescent offline store under its exclusive process lock.

    No migration is performed. Orphans, locks, secrets and unreferenced files are
    excluded. All existing destination paths are refused, including empty ones.
    """
    if VERSION not in SUPPORTED_STORE_VERSIONS:
        raise BackupError("Store version requires a reviewed backup implementation")
    ledger_directory = Path(ledger_directory).absolute()
    fd = _directory(ledger_directory)
    os.close(fd)
    _read_file(ledger_directory / "ledger.sqlite3", MAX_DATABASE_BYTES)
    with PlanStore(
        ledger_directory, objects_directory=objects_directory, evidence_directory=evidence_directory
    ) as store:
        campaigns, refs = _references(store)
        destination = _new_destination(destination)
        database = destination / "ledger/ledger.sqlite3"
        _write_new(database, b"")
        # SQLite's backup API snapshots the connection, rather than copying a
        # live database file. PlanStore retains exclusive ownership throughout.
        with closing(sqlite3.connect(database)) as target:
            store._connection().backup(target)
        _read_file(database, MAX_DATABASE_BYTES)
        fd = os.open(database, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        for relative, length in refs.items():
            group, filename = relative.split("/")
            source = objects_directory if group == "artifacts" else evidence_directory
            copied = _read_file(
                Path(source) / filename, _limit(relative), copy_to=destination / relative
            )
            if copied["byte_length"] != length or copied["sha256"] != filename[:-5]:
                raise BackupError("Copied object differs from ledger reference")
        files = [
            {"path": relative, **_read_file(destination / relative, _limit(relative))}
            for relative in sorted({"ledger/ledger.sqlite3", *refs})
        ]
        manifest = {
            "schema_version": 1,
            "kind": "offline_store_backup",
            "store_version": VERSION,
            "campaign_ids": campaigns,
            "files": files,
            "execution_enabled": False,
            "restore_requires_reconciliation": True,
        }
        encoded = _encode(manifest)
        if len(encoded) > MAX_MANIFEST_BYTES:
            raise BackupError("Backup manifest exceeds byte limit")
        _check_files(destination, manifest, published=False)
        _validate_payload(destination, manifest)
        for name in ("ledger", "artifacts", "evidence"):
            _sync_directory(destination / name)
        _write_new(destination / "manifest.json", encoded)
        _sync_directory(destination)
        _sync_directory(destination.parent)
        return verify_backup(destination)


def _fence(database: Path, fence_id: str, backup_sha256: str) -> None:
    """Durably add one restore fence to a validated, not-yet-opened restored ledger."""
    fence = {
        "schema_version": 1,
        "kind": "restore_fence",
        "fence_id": fence_id,
        "backup_sha256": backup_sha256,
    }
    with closing(sqlite3.connect(database, isolation_level=None)) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute(
                "INSERT INTO restore_fences VALUES (?, ?, ?)",
                (
                    fence_id,
                    datetime.now(UTC).isoformat(),
                    json.dumps(fence, sort_keys=True, separators=(",", ":"), allow_nan=False),
                ),
            )
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
    fd = os.open(database, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def restore_backup(directory: Path, destination: Path) -> dict:
    """Validate first, then restore to a fresh directory and fence its ledger.

    External work may postdate the backup, so the restored ledger durably carries
    a restore fence: no runtime dispatch until `PlanStore.reconcile_restore`
    records an explicit reconciliation. This function never executes work.
    """
    directory = Path(directory).absolute()
    manifest = verify_backup(directory)
    destination = _new_destination(destination)
    for entry in manifest["files"]:
        relative = entry["path"]
        copied = _read_file(directory / relative, _limit(relative), copy_to=destination / relative)
        if copied != {key: entry[key] for key in ("byte_length", "sha256")}:
            raise BackupError("Backup changed during restore")
    _validate_payload(destination, manifest)
    _check_files(destination, manifest, published=False)
    backup_sha256 = digest(manifest)
    fence_id = f"restore-{backup_sha256}"
    _fence(destination / "ledger/ledger.sqlite3", fence_id, backup_sha256)
    record = {
        "schema_version": 1,
        "kind": "offline_store_restore",
        "backup_sha256": backup_sha256,
        "store_version": VERSION,
        "restore_fence_id": fence_id,
        "execution_enabled": False,
        "reconciliation_required": True,
    }
    _write_new(destination / "restore.json", _encode(record))
    for name in ("ledger", "artifacts", "evidence"):
        _sync_directory(destination / name)
    _sync_directory(destination)
    _sync_directory(destination.parent)
    return record
