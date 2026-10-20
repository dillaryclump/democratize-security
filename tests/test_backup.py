import hashlib
import json
import os
import sqlite3
import stat
import subprocess
import sys

import pytest
from test_store_evidence import build_case, open_store

from democratize_security import backup, evidence_objects
from democratize_security import evidence as evidence_contract
from democratize_security.contracts import digest
from democratize_security.store import VERSION, PlanStore, StoreError
from democratize_security.verification.report import REQUIRED, Check, summarize


@pytest.fixture
def case(tmp_path):
    case = build_case(tmp_path)
    with open_store(case) as store:
        store.record_evidence("report", case["request"])
        store.record_accounting(
            "stop",
            {
                "action": "interrupt",
                "attempt_id": "a1",
                "expected_revision": 1,
                "reason": "synthetic interruption with unknown final cost",
            },
        )
    return case


def create(case, destination):
    return backup.create_backup(
        case["ledger"],
        destination,
        objects_directory=case["artifact_dir"],
        evidence_directory=case["evidence_dir"],
    )


def rewrite_manifest(directory, change):
    manifest = json.loads((directory / "manifest.json").read_bytes())
    change(manifest)
    (directory / "manifest.json").write_bytes(backup._encode(manifest))


def historical_dump(connection):
    """All pre-v6 record/schema bytes stay unchanged; ownership is separately asserted."""
    return [line for line in connection.iterdump() if "controller_generations" not in line]


def generation_rows(connection):
    return connection.execute(
        "SELECT generation, process_id FROM controller_generations ORDER BY generation"
    ).fetchall()


def test_verified_roundtrip_preserves_full_ledger_references_and_unknown_cost(case, tmp_path):
    snapshot, restored = tmp_path / "snapshot", tmp_path / "restored"
    (case["artifact_dir"] / "orphan.json").write_text("not referenced")
    (case["evidence_dir"] / ".evidence-orphan").write_text("not referenced")
    with open_store(case) as store:
        original = historical_dump(store._connection())
        generation = store.controller_generation
        history = generation_rows(store._connection())
        budget = store.budget_snapshot(case["plan"]["campaign_id"])
        attempts = store.attempts()
    manifest = create(case, snapshot)
    assert manifest == backup.verify_backup(snapshot)
    assert manifest["restore_requires_reconciliation"] is True
    assert manifest["execution_enabled"] is False
    assert manifest["store_version"] == VERSION == 6
    with sqlite3.connect(snapshot / "ledger/ledger.sqlite3") as db:
        snapshot_history = generation_rows(db)
        assert historical_dump(db) == original
        assert snapshot_history == [*history, (generation + 1, os.getpid())]
    assert len(manifest["files"]) == 3
    assert all("orphan" not in entry["path"] for entry in manifest["files"])
    with open_store(case) as store:
        assert historical_dump(store._connection()) == original
        assert generation_rows(store._connection()) == [
            *snapshot_history,
            (generation + 2, os.getpid()),
        ]
    provenance = backup.restore_backup(snapshot, restored)
    assert provenance["backup_sha256"] == digest(manifest)
    assert provenance["execution_enabled"] is False
    assert provenance["reconciliation_required"] is True
    # Restore validates scratch ownership; its real DB stays byte-identical until open.
    for entry in manifest["files"]:
        assert (snapshot / entry["path"]).read_bytes() == (restored / entry["path"]).read_bytes()
    with sqlite3.connect(restored / "ledger/ledger.sqlite3") as db:
        assert generation_rows(db) == snapshot_history
    with PlanStore(
        restored / "ledger",
        objects_directory=restored / "artifacts",
        evidence_directory=restored / "evidence",
    ) as store:
        assert historical_dump(store._connection()) == original
        assert generation_rows(store._connection()) == [
            *snapshot_history,
            (generation + 2, os.getpid()),
        ]
        assert store.controller_generation == generation + 2
        assert store.snapshot(case["plan"]["campaign_id"]) == case["plan"]
        assert store.attempts() == attempts
        assert store.budget_snapshot(case["plan"]["campaign_id"]) == budget
        assert budget["unknown_cost_count"] == 1 and budget["blocked"]
        assert store.evidence_bindings()[0]["request"] == case["request"]
        assert len(store.verification_intents()) == 1
    for root in (snapshot, restored):
        for path in (root, *root.rglob("*")):
            assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
    assert backup.verify_backup(snapshot) == manifest


def test_empty_ledger_and_coincident_object_directories(tmp_path):
    ledger, objects = tmp_path / "ledger", tmp_path / "objects"
    ledger.mkdir()
    objects.mkdir()
    with PlanStore(ledger):
        pass
    result = backup.create_backup(
        ledger, tmp_path / "snapshot", objects_directory=objects, evidence_directory=objects
    )
    assert result["campaign_ids"] == [] and len(result["files"]) == 1


def test_missing_source_is_not_silently_initialized(tmp_path):
    ledger, destination = tmp_path / "ledger", tmp_path / "snapshot"
    ledger.mkdir()
    with pytest.raises(FileNotFoundError):
        backup.create_backup(ledger, destination)
    assert not (ledger / "ledger.sqlite3").exists() and not destination.exists()


@pytest.mark.parametrize("operation", ["backup", "restore"])
@pytest.mark.parametrize("kind", ["directory", "file", "symlink", "partial"])
def test_never_replaces_any_existing_destination(case, tmp_path, operation, kind):
    snapshot, destination = tmp_path / "snapshot", tmp_path / "existing"
    create(case, snapshot)
    if kind in {"directory", "partial"}:
        destination.mkdir()
        if kind == "partial":
            (destination / "important").write_text("retained")
    elif kind == "file":
        destination.write_text("retained")
    else:
        destination.symlink_to(tmp_path / "missing-target")
    with pytest.raises(FileExistsError):
        if operation == "backup":
            create(case, destination)
        else:
            backup.restore_backup(snapshot, destination)
    if kind == "partial":
        assert (destination / "important").read_text() == "retained"
    if kind == "file":
        assert destination.read_text() == "retained"
    if kind == "symlink":
        assert destination.is_symlink()


def test_live_other_process_ownership_blocks_snapshot(case, tmp_path):
    program = """
import sys
from pathlib import Path
from democratize_security.store import PlanStore
with PlanStore(Path(sys.argv[1]), objects_directory=Path(sys.argv[2]),
               evidence_directory=Path(sys.argv[3])):
    print('owned', flush=True)
    sys.stdin.read(1)
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            program,
            str(case["ledger"]),
            str(case["artifact_dir"]),
            str(case["evidence_dir"]),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout.readline().strip() == "owned"
        with pytest.raises(StoreError, match="owned"):
            create(case, tmp_path / "snapshot")
        assert not (tmp_path / "snapshot").exists()
    finally:
        process.communicate("x", timeout=5)
    assert process.returncode == 0


@pytest.mark.parametrize("damage", ["missing", "changed", "symlink", "hardlink", "fifo"])
def test_source_object_corruption_refuses_before_destination_creation(case, tmp_path, damage):
    path = next(case["artifact_dir"].glob("*.json"))
    if damage == "changed":
        path.write_text("changed")
    elif damage == "hardlink":
        os.link(path, tmp_path / "second-link")
    else:
        path.unlink()
        if damage == "symlink":
            path.symlink_to(case["ledger"] / "ledger.sqlite3")
        if damage == "fifo":
            os.mkfifo(path)
    with pytest.raises((StoreError, OSError)):
        create(case, tmp_path / "snapshot")
    assert not (tmp_path / "snapshot").exists()


def test_source_projection_corruption_is_not_backed_up(case, tmp_path):
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        db.execute("UPDATE attempts SET state_json = '{}' ")
    with pytest.raises(StoreError, match="projection"):
        create(case, tmp_path / "snapshot")
    assert not (tmp_path / "snapshot").exists()


@pytest.mark.parametrize("damage", ["missing", "truncated", "symlink", "hardlink", "fifo"])
def test_tampered_snapshot_never_creates_a_restore(case, tmp_path, damage):
    snapshot, restored = tmp_path / "snapshot", tmp_path / "restored"
    create(case, snapshot)
    path = next((snapshot / "evidence").glob("*.json"))
    if damage == "truncated":
        path.write_bytes(path.read_bytes()[:-1])
    elif damage == "hardlink":
        os.link(path, tmp_path / "second-link")
    else:
        path.unlink()
        if damage == "symlink":
            path.symlink_to(case["ledger"] / "ledger.sqlite3")
        if damage == "fifo":
            os.mkfifo(path)
    with pytest.raises((backup.BackupError, OSError)):
        backup.restore_backup(snapshot, restored)
    assert not restored.exists()


@pytest.mark.parametrize(
    "change",
    [
        lambda m: m.update(schema_version=True),
        lambda m: m.update(store_version=VERSION + 1),
        lambda m: m.update(extra="unexpected"),
        lambda m: m.update(execution_enabled=True),
        lambda m: m.update(restore_requires_reconciliation=False),
        lambda m: m["files"].append(m["files"][0]),
        lambda m: m["files"][0].update(path="../escape"),
        lambda m: m["files"][0].update(byte_length=True),
        lambda m: m["files"].reverse(),
        lambda m: m.update(campaign_ids=[]),
    ],
)
def test_manifest_authority_paths_types_inventory_and_plan_must_match(case, tmp_path, change):
    snapshot = tmp_path / "snapshot"
    create(case, snapshot)
    rewrite_manifest(snapshot, change)
    with pytest.raises(backup.BackupError):
        backup.verify_backup(snapshot)


@pytest.mark.parametrize("data", [b'{"kind":1,"kind":2}', b'{"value":NaN}', b"{}\n"])
def test_noncanonical_duplicate_and_nonfinite_json_rejected(case, tmp_path, data):
    snapshot = tmp_path / "snapshot"
    create(case, snapshot)
    (snapshot / "manifest.json").write_bytes(data)
    with pytest.raises(backup.BackupError):
        backup.verify_backup(snapshot)


@pytest.mark.parametrize("extra", ["unknown", "ledger/ledger.lock", "artifacts/extra.json"])
def test_uninventoried_snapshot_entries_are_rejected(case, tmp_path, extra):
    snapshot = tmp_path / "snapshot"
    create(case, snapshot)
    (snapshot / extra).write_text("not inventoried")
    with pytest.raises(backup.BackupError, match="Unexpected"):
        backup.verify_backup(snapshot)


def test_rehashed_corrupt_database_still_fails_event_and_schema_validation(case, tmp_path):
    snapshot = tmp_path / "snapshot"
    create(case, snapshot)
    database = snapshot / "ledger/ledger.sqlite3"
    with sqlite3.connect(database) as db:
        db.execute("UPDATE attempts SET state_json = '{}' ")

    def rehash(manifest):
        for entry in manifest["files"]:
            if entry["path"] == "ledger/ledger.sqlite3":
                entry.update(backup._read_file(database, backup.MAX_DATABASE_BYTES))

    rewrite_manifest(snapshot, rehash)
    with pytest.raises(StoreError, match="projection"):
        backup.verify_backup(snapshot)


def test_rehashed_manifest_cannot_drop_a_referenced_object(case, tmp_path):
    snapshot = tmp_path / "snapshot"
    manifest = create(case, snapshot)
    removed = next(e for e in manifest["files"] if e["path"].startswith("artifacts/"))
    (snapshot / removed["path"]).unlink()
    rewrite_manifest(snapshot, lambda m: m["files"].remove(removed))
    with pytest.raises(StoreError, match="artifact"):
        backup.verify_backup(snapshot)


def test_snapshot_verification_does_not_modify_database(case, tmp_path, monkeypatch):
    snapshot = tmp_path / "snapshot"
    create(case, snapshot)
    original = (snapshot / "ledger/ledger.sqlite3").read_bytes()
    real = backup.PlanStore
    opened = []

    class TrackingStore(real):
        def __init__(self, directory, **kwargs):
            opened.append(directory)
            super().__init__(directory, **kwargs)
            # Real v6 startup appends only to this scratch ownership history.
            assert self.controller_generation >= 1

    monkeypatch.setattr(backup, "PlanStore", TrackingStore)
    backup.verify_backup(snapshot)
    assert opened and all(path != snapshot / "ledger" for path in opened)
    assert (snapshot / "ledger/ledger.sqlite3").read_bytes() == original


@pytest.mark.parametrize("when", ["object", "manifest", "directory_sync"])
def test_write_or_durability_failure_is_never_acknowledged(case, tmp_path, monkeypatch, when):
    snapshot = tmp_path / "snapshot"
    original_read, original_write, original_sync = (
        backup._read_file,
        backup._write_new,
        backup._sync_directory,
    )

    def read(path, limit, **kwargs):
        if when == "object" and kwargs.get("copy_to") == snapshot / "artifacts" / path.name:
            raise OSError("synthetic object failure")
        return original_read(path, limit, **kwargs)

    def write(path, data):
        if when == "manifest" and path == snapshot / "manifest.json":
            raise OSError("synthetic manifest failure")
        return original_write(path, data)

    def sync(path):
        if when == "directory_sync" and path == snapshot and (snapshot / "manifest.json").exists():
            raise OSError("synthetic sync failure")
        return original_sync(path)

    monkeypatch.setattr(backup, "_read_file", read)
    monkeypatch.setattr(backup, "_write_new", write)
    monkeypatch.setattr(backup, "_sync_directory", sync)
    with pytest.raises(OSError, match="synthetic"):
        create(case, snapshot)
    assert snapshot.exists()
    if when != "directory_sync":
        assert not (snapshot / "manifest.json").exists()
    with pytest.raises(FileExistsError):
        create(case, snapshot)
    with open_store(case) as store:
        assert len(store.evidence_bindings()) == 1


@pytest.mark.parametrize("boundary", ["before_manifest", "after_manifest", "after_backup"])
def test_process_death_keeps_partial_or_complete_snapshot_never_partial_success(
    case, tmp_path, boundary
):
    snapshot = tmp_path / "snapshot"
    program = """
import os, sys
from pathlib import Path
from democratize_security import backup
ledger, artifacts, evidence, target = map(Path, sys.argv[1:5])
boundary = sys.argv[5]
original = backup._write_new
def write(path, data):
    if path == target / 'manifest.json' and boundary == 'before_manifest':
        os._exit(69)
    original(path, data)
    if path == target / 'manifest.json' and boundary == 'after_manifest':
        os._exit(69)
backup._write_new = write
backup.create_backup(ledger, target, objects_directory=artifacts, evidence_directory=evidence)
os._exit(69)
"""
    process = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(case["ledger"]),
            str(case["artifact_dir"]),
            str(case["evidence_dir"]),
            str(snapshot),
            boundary,
        ],
        timeout=10,
    )
    assert process.returncode == 69
    if boundary == "before_manifest":
        with pytest.raises(FileNotFoundError):
            backup.verify_backup(snapshot)
    else:
        assert backup.verify_backup(snapshot)["campaign_ids"] == [case["plan"]["campaign_id"]]
    with pytest.raises(FileExistsError):
        create(case, snapshot)


def test_unknown_future_store_schemas_refuse_without_creating_destination(
    case, tmp_path, monkeypatch
):
    monkeypatch.setattr(backup, "VERSION", 7)
    with pytest.raises(backup.BackupError, match="reviewed"):
        create(case, tmp_path / "snapshot")
    assert not (tmp_path / "snapshot").exists()


def test_source_change_during_copy_detected(case, tmp_path, monkeypatch):
    original = os.read
    changed = False
    target = next(case["artifact_dir"].glob("*.json"))

    def read(fd, count):
        nonlocal changed
        data = original(fd, count)
        if not changed and os.fstat(fd).st_ino == target.stat().st_ino:
            # Trigger only the backup copy, after the source's validation reads.
            if (tmp_path / "snapshot").exists():
                changed = True
                with target.open("ab") as stream:
                    stream.write(b" ")
        return data

    monkeypatch.setattr(os, "read", read)
    with pytest.raises(backup.BackupError, match="changed"):
        create(case, tmp_path / "snapshot")
    assert changed and not (tmp_path / "snapshot/manifest.json").exists()


def test_restore_detects_source_change_after_initial_verification(case, tmp_path, monkeypatch):
    snapshot, restored = tmp_path / "snapshot", tmp_path / "restored"
    create(case, snapshot)
    original = backup.verify_backup

    def verify(path):
        manifest = original(path)
        target = next((snapshot / "evidence").glob("*.json"))
        raw = target.read_bytes()
        target.write_bytes(raw[:-1] + (b" " if raw[-1:] != b" " else b"x"))
        return manifest

    monkeypatch.setattr(backup, "verify_backup", verify)
    with pytest.raises(backup.BackupError, match="changed"):
        backup.restore_backup(snapshot, restored)
    assert not (restored / "restore.json").exists()


def test_object_hash_is_preserved_independently_of_manifest(case, tmp_path):
    snapshot = tmp_path / "snapshot"
    create(case, snapshot)
    for group in ("artifacts", "evidence"):
        path = next((snapshot / group).glob("*.json"))
        assert hashlib.sha256(path.read_bytes()).hexdigest() == path.stem


@pytest.mark.parametrize("outcome", ["fail", "not_evaluated"])
def test_failed_and_incomplete_reports_remain_so_after_restore(tmp_path, outcome):
    case = build_case(tmp_path)
    checks = [
        Check(name, outcome if index == 0 else "pass")
        for index, name in enumerate(sorted(REQUIRED))
    ]
    report = summarize(checks)
    record = evidence_contract.bind_report(case["binding"], "verify-1", report)
    ref = evidence_objects.publish_evidence(
        case["evidence_dir"], record, case["binding"], "verify-1"
    )
    case["request"]["evidence_ref"] = ref
    with open_store(case) as store:
        binding = store.record_evidence("report", case["request"])
    snapshot, restored = tmp_path / "snapshot", tmp_path / "restored"
    create(case, snapshot)
    backup.restore_backup(snapshot, restored)
    with PlanStore(
        restored / "ledger",
        objects_directory=restored / "artifacts",
        evidence_directory=restored / "evidence",
    ) as store:
        assert store.evidence_bindings() == [binding]
        assert store.attempts()[0]["phase"] == "preparing"
        preserved = evidence_objects.read_evidence(
            restored / "evidence", ref, case["binding"], "verify-1"
        )
        assert preserved["report"] == report
        assert preserved["report"]["outcome"] != "pass"


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "fifo", "oversize"])
def test_manifest_is_bounded_regular_and_singly_linked(case, tmp_path, monkeypatch, damage):
    snapshot = tmp_path / "snapshot"
    create(case, snapshot)
    manifest = snapshot / "manifest.json"
    if damage == "hardlink":
        os.link(manifest, tmp_path / "linked-manifest")
    elif damage == "oversize":
        monkeypatch.setattr(backup, "MAX_MANIFEST_BYTES", 8)
    else:
        manifest.unlink()
        if damage == "symlink":
            manifest.symlink_to(case["ledger"] / "ledger.sqlite3")
        else:
            os.mkfifo(manifest)
    with pytest.raises((backup.BackupError, OSError)):
        backup.verify_backup(snapshot)


@pytest.mark.parametrize("where", ["root", "artifacts"])
def test_snapshot_directory_symlinks_are_rejected(case, tmp_path, where):
    snapshot = tmp_path / "snapshot"
    create(case, snapshot)
    if where == "root":
        linked = tmp_path / "linked-snapshot"
        linked.symlink_to(snapshot, target_is_directory=True)
    else:
        target = snapshot / "artifacts"
        target.rename(tmp_path / "external-artifacts")
        target.symlink_to(tmp_path / "external-artifacts", target_is_directory=True)
        linked = snapshot
    with pytest.raises(OSError):
        backup.verify_backup(linked)


def test_database_limit_refuses_before_creating_backup(case, tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "MAX_DATABASE_BYTES", 8)
    with pytest.raises(backup.BackupError, match="length"):
        create(case, tmp_path / "snapshot")
    assert not (tmp_path / "snapshot").exists()


@pytest.mark.parametrize("after_copy", [False, True])
def test_sqlite_snapshot_failure_never_publishes_manifest(case, tmp_path, monkeypatch, after_copy):
    real = backup.PlanStore

    class FailingConnection:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def backup(self, target):
            if after_copy:
                self.connection.backup(target)
            raise sqlite3.OperationalError("synthetic snapshot interruption")

    class FailingStore(real):
        def _connection(self):
            return FailingConnection(super()._connection())

    monkeypatch.setattr(backup, "PlanStore", FailingStore)
    snapshot = tmp_path / "snapshot"
    with pytest.raises(sqlite3.OperationalError, match="synthetic"):
        create(case, snapshot)
    assert not (snapshot / "manifest.json").exists()
    with open_store(case) as store:
        assert len(store.evidence_bindings()) == 1


@pytest.mark.parametrize("boundary", ["before_marker", "after_marker", "after_restore"])
def test_process_death_during_restore_leaves_fresh_destination_without_reuse(
    case,
    tmp_path,
    boundary,
):
    snapshot, restored = tmp_path / "snapshot", tmp_path / "restored"
    manifest = create(case, snapshot)
    program = """
import os, sys
from pathlib import Path
from democratize_security import backup
source, target = map(Path, sys.argv[1:3])
boundary = sys.argv[3]
original = backup._write_new
def write(path, data):
    if path == target / 'restore.json' and boundary == 'before_marker':
        os._exit(69)
    original(path, data)
    if path == target / 'restore.json' and boundary == 'after_marker':
        os._exit(69)
backup._write_new = write
backup.restore_backup(source, target)
os._exit(69)
"""
    process = subprocess.run(
        [sys.executable, "-c", program, str(snapshot), str(restored), boundary], timeout=10
    )
    assert process.returncode == 69
    assert (restored / "restore.json").exists() == (boundary != "before_marker")
    for entry in manifest["files"]:
        assert (restored / entry["path"]).read_bytes() == (snapshot / entry["path"]).read_bytes()
    assert backup.verify_backup(snapshot) == manifest
    with pytest.raises(FileExistsError):
        backup.restore_backup(snapshot, restored)


def damage_generation_history(database, damage):
    with sqlite3.connect(database) as db:
        if damage == "gap":
            last = db.execute("SELECT max(generation) FROM controller_generations").fetchone()[0]
            db.execute("INSERT INTO controller_generations VALUES (?, ?)", (last + 2, os.getpid()))
        elif damage == "pid":
            trigger = "controller_generations_no_update"
            sql = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (trigger,)).fetchone()[0]
            db.execute(f"DROP TRIGGER {trigger}")
            db.execute(
                "UPDATE controller_generations SET process_id='invalid-pid' WHERE generation=1"
            )
            db.execute(sql)
        else:
            db.execute("DROP TRIGGER controller_generations_no_delete")


@pytest.mark.parametrize("damage", ["gap", "pid", "schema"])
def test_corrupt_v6_source_generation_history_refuses_before_snapshot_creation(
    case, tmp_path, damage
):
    database = case["ledger"] / "ledger.sqlite3"
    damage_generation_history(database, damage)
    with sqlite3.connect(database) as db:
        before = list(db.iterdump())
    with pytest.raises(StoreError, match="generation|schema"):
        create(case, tmp_path / "snapshot")
    assert not (tmp_path / "snapshot").exists()
    with sqlite3.connect(database) as db:
        assert list(db.iterdump()) == before


@pytest.mark.parametrize("damage", ["gap", "pid", "schema"])
def test_rehashed_v6_generation_corruption_rejects_verify_and_restore(case, tmp_path, damage):
    snapshot, restored = tmp_path / "snapshot", tmp_path / "restored"
    create(case, snapshot)
    database = snapshot / "ledger/ledger.sqlite3"
    damage_generation_history(database, damage)
    rewrite_manifest(
        snapshot,
        lambda manifest: next(
            entry for entry in manifest["files"] if entry["path"] == "ledger/ledger.sqlite3"
        ).update(backup._read_file(database, backup.MAX_DATABASE_BYTES)),
    )
    before = database.read_bytes()
    with pytest.raises(StoreError, match="generation|schema"):
        backup.verify_backup(snapshot)
    with pytest.raises(StoreError, match="generation|schema"):
        backup.restore_backup(snapshot, restored)
    assert database.read_bytes() == before
    assert not restored.exists()


def test_v6_scratch_allocations_never_change_frozen_or_restored_ownership(
    case, tmp_path, monkeypatch
):
    snapshot, restored = tmp_path / "snapshot", tmp_path / "restored"
    manifest = create(case, snapshot)
    database = snapshot / "ledger/ledger.sqlite3"
    original = database.read_bytes()
    with sqlite3.connect(database) as db:
        saved = generation_rows(db)
    real = backup.PlanStore
    allocations = []

    class TrackingStore(real):
        def __init__(self, directory, **kwargs):
            super().__init__(directory, **kwargs)
            allocations.append((directory, generation_rows(self._connection())))

    monkeypatch.setattr(backup, "PlanStore", TrackingStore)
    for _ in range(3):
        assert backup.verify_backup(snapshot) == manifest
    backup.restore_backup(snapshot, restored)
    assert len(allocations) == 5  # Three verifications, source and restored validation.
    assert all(
        directory not in (snapshot / "ledger", restored / "ledger") for directory, _ in allocations
    )
    assert all(rows == [*saved, (saved[-1][0] + 1, os.getpid())] for _, rows in allocations)
    assert database.read_bytes() == original
    assert (restored / "ledger/ledger.sqlite3").read_bytes() == original
    with sqlite3.connect(case["ledger"] / "ledger.sqlite3") as db:
        assert generation_rows(db) == saved
    with PlanStore(
        restored / "ledger",
        objects_directory=restored / "artifacts",
        evidence_directory=restored / "evidence",
    ) as store:
        assert generation_rows(store._connection()) == allocations[-1][1]
        assert store.controller_generation == saved[-1][0] + 1


def test_v5_source_and_archive_require_explicit_migration_not_implicit_relabeling(case, tmp_path):
    snapshot, restored = tmp_path / "snapshot", tmp_path / "restored"
    create(case, snapshot)
    database = snapshot / "ledger/ledger.sqlite3"
    for path in (case["ledger"] / "ledger.sqlite3", database):
        with sqlite3.connect(path) as db:
            db.execute("DROP TABLE controller_generations")
            db.execute("PRAGMA user_version=5")

    def legacy_manifest(manifest):
        manifest["store_version"] = 5
        next(
            entry for entry in manifest["files"] if entry["path"] == "ledger/ledger.sqlite3"
        ).update(backup._read_file(database, backup.MAX_DATABASE_BYTES))

    rewrite_manifest(snapshot, legacy_manifest)
    original = {path: path.read_bytes() for path in (case["ledger"] / "ledger.sqlite3", database)}
    with pytest.raises(StoreError, match="Version 5 requires explicit migrate=True"):
        create(case, tmp_path / "new-snapshot")
    for operation in (
        lambda: backup.verify_backup(snapshot),
        lambda: backup.restore_backup(snapshot, restored),
    ):
        with pytest.raises(backup.BackupError, match="matching backup tool.*explicitly migrate"):
            operation()
    assert not (tmp_path / "new-snapshot").exists() and not restored.exists()
    assert {path: path.read_bytes() for path in original} == original
    with open_store(case, migrate=True) as store:
        assert store.controller_generation == 1
    assert create(case, tmp_path / "migrated-snapshot")["store_version"] == 6
