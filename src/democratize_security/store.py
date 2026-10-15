"""Offline whole-plan ledger. No attempts, dispatch, grading or budget authority.

The caller supplies an existing trusted local directory with a stable pathname.
One POSIX process owns it until close; files are not safe against their owner.
"""

import fcntl
import json
import os
import sqlite3
import stat
from datetime import UTC, datetime
from pathlib import Path

from democratize_security.contracts import _unique_pairs, digest, plan

VERSION = 1
APPLICATION_ID = 0x44534C31
MAX_PLAN_BYTES = 16 * 1024 * 1024
SCHEMA = {
    "campaigns": """CREATE TABLE campaigns (
        campaign_id TEXT PRIMARY KEY NOT NULL, plan_json TEXT NOT NULL
    )""",
    "trials": """CREATE TABLE trials (
        trial_id TEXT PRIMARY KEY NOT NULL,
        campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
        ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
        trial_json TEXT NOT NULL,
        UNIQUE (campaign_id, ordinal)
    )""",
    "events": """CREATE TABLE events (
        event_id TEXT PRIMARY KEY NOT NULL,
        trial_id TEXT NOT NULL UNIQUE REFERENCES trials(trial_id),
        sequence INTEGER NOT NULL CHECK (sequence = 0),
        kind TEXT NOT NULL CHECK (kind = 'planned'),
        created_at TEXT NOT NULL,
        payload_json TEXT NOT NULL
    )""",
}
for _table in ("campaigns", "trials", "events"):
    for _operation in ("UPDATE", "DELETE"):
        _name = f"{_table}_no_{_operation.lower()}"
        SCHEMA[_name] = (
            f"CREATE TRIGGER {_name} BEFORE {_operation} ON {_table} "
            "BEGIN SELECT RAISE(ABORT, 'immutable ledger record'); END"
        )


class StoreError(ValueError):
    """The ledger cannot be safely used."""


def _json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _event_id(trial_id: str) -> str:
    return digest({"trial_id": trial_id, "sequence": 0, "kind": "planned"})


class PlanStore:
    """Import and read deterministic offline plans, retaining every trial."""

    def __init__(self, directory: Path):
        self._lock_fd = None
        self._db = None
        directory = directory.resolve(strict=True)
        try:
            self._lock_fd = os.open(
                directory / "ledger.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
            )
            info = os.fstat(self._lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise StoreError("Lock must be a regular, singly linked file")
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise StoreError("Ledger is already owned by another controller") from error
            path = directory / "ledger.sqlite3"
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise StoreError("Database must be a regular, singly linked file")
            finally:
                os.close(fd)
            self._db = sqlite3.connect(path, isolation_level=None)
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            application = self._db.execute("PRAGMA application_id").fetchone()[0]
            objects = self._schema()
            fresh = version == 0 and application == 0 and not objects
            if not fresh and (version != VERSION or application != APPLICATION_ID):
                raise StoreError("Unknown ledger version or application; no automatic migration")
            if not fresh and objects != SCHEMA:
                raise StoreError("Ledger schema does not match its declared version")
            self._db.execute("PRAGMA foreign_keys=ON")
            journal = self._db.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            self._db.execute("PRAGMA synchronous=FULL")
            if (
                journal != "delete"
                or self._db.execute("PRAGMA synchronous").fetchone()[0] != 2
                or self._db.execute("PRAGMA foreign_keys").fetchone()[0] != 1
            ):
                raise StoreError("Required SQLite durability settings unavailable")
            if fresh:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    for statement in SCHEMA.values():
                        self._db.execute(statement)
                    self._db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                    self._db.execute(f"PRAGMA user_version={VERSION}")
                    self._db.execute("COMMIT")
                except BaseException:
                    self._db.execute("ROLLBACK")
                    raise
            # Persist database/lock directory entries before acknowledging open.
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            if self._db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise StoreError("Ledger integrity check failed")
            if self._db.execute("PRAGMA foreign_key_check").fetchall():
                raise StoreError("Ledger contains orphan records")
            for (campaign_id,) in self._db.execute("SELECT campaign_id FROM campaigns").fetchall():
                self.snapshot(campaign_id)
        except BaseException:
            self.close()
            raise

    def _schema(self) -> dict:
        return dict(
            self._db.execute(
                "SELECT name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
        )

    def _connection(self):
        if self._db is None:
            raise StoreError("Ledger is closed")
        return self._db

    def import_campaign(self, campaign: dict) -> dict:
        """Atomically import the complete plan; exact re-import is a no-op."""
        expected = plan(campaign)
        serialized = _json(expected)
        if len(serialized.encode("utf-8")) > MAX_PLAN_BYTES:
            raise StoreError("Plan exceeds ledger byte limit")
        campaign_id = expected["campaign_id"]
        db = self._connection()
        db.execute("BEGIN IMMEDIATE")
        try:
            if db.execute(
                "SELECT 1 FROM campaigns WHERE campaign_id = ?", (campaign_id,)
            ).fetchone():
                if self.snapshot(campaign_id) != expected:
                    raise StoreError("Stored plan conflicts with the supplied campaign")
            else:
                db.execute("INSERT INTO campaigns VALUES (?, ?)", (campaign_id, serialized))
                timestamp = datetime.now(UTC).isoformat()
                for ordinal, trial in enumerate(expected["trials"]):
                    trial_id = trial["trial_id"]
                    payload = _json(trial)
                    db.execute(
                        "INSERT INTO trials VALUES (?, ?, ?, ?)",
                        (trial_id, campaign_id, ordinal, payload),
                    )
                    db.execute(
                        "INSERT INTO events VALUES (?, ?, 0, 'planned', ?, ?)",
                        (_event_id(trial_id), trial_id, timestamp, payload),
                    )
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        return self.snapshot(campaign_id)

    def snapshot(self, campaign_id: str) -> dict:
        """Validate all stored rows against the deterministic plan before returning."""
        db = self._connection()
        size = db.execute(
            "SELECT length(CAST(plan_json AS BLOB)) FROM campaigns WHERE campaign_id = ?",
            (campaign_id,),
        ).fetchone()
        if size is not None and size[0] > MAX_PLAN_BYTES:
            raise StoreError("Persisted plan exceeds ledger byte limit")
        row = db.execute(
            "SELECT plan_json FROM campaigns WHERE campaign_id = ?", (campaign_id,)
        ).fetchone()
        if row is None:
            raise StoreError("Unknown campaign")
        try:
            stored = json.loads(row[0], object_pairs_hook=_unique_pairs)
            expected = plan(stored["campaign"])
            if expected["campaign_id"] != campaign_id or row[0] != _json(expected):
                raise StoreError("Stored campaign identity or plan mismatch")
            rows = db.execute(
                "SELECT trial_id, ordinal, trial_json FROM trials "
                "WHERE campaign_id = ? ORDER BY ordinal",
                (campaign_id,),
            ).fetchall()
            required = [(t["trial_id"], i, _json(t)) for i, t in enumerate(expected["trials"])]
            if rows != required:
                raise StoreError("Stored trial coverage or content mismatch")
            events = db.execute(
                "SELECT e.event_id, e.trial_id, e.sequence, e.kind, e.payload_json "
                "FROM events e JOIN trials t ON t.trial_id = e.trial_id "
                "WHERE t.campaign_id = ? ORDER BY t.ordinal",
                (campaign_id,),
            ).fetchall()
            required_events = [
                (_event_id(tid), tid, 0, "planned", data) for tid, _, data in required
            ]
            if events != required_events:
                raise StoreError("Stored import event coverage or content mismatch")
            return expected
        except (KeyError, TypeError, ValueError) as error:
            raise StoreError(f"Invalid persisted plan: {error}") from error

    def close(self):
        try:
            if self._db is not None:
                self._db.close()
        finally:
            self._db = None
            if self._lock_fd is not None:
                os.close(self._lock_fd)
                self._lock_fd = None

    def __enter__(self):
        self._connection()
        return self

    def __exit__(self, *_):
        self.close()
