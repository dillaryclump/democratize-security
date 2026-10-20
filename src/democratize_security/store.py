"""Offline plan/attempt accounting. No dispatch, grading or spending authority.

The caller supplies an existing trusted local directory with a stable pathname.
One POSIX process owns it until close; files are not safe against their owner.
"""

import base64
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from democratize_security import evidence_objects
from democratize_security import objects as artifact_objects
from democratize_security.contracts import _unique_pairs, digest, plan
from democratize_security.recovery import RecoveryError, RecoveryState
from democratize_security.runtime_auth import (
    MAX_AUTH_BYTES,
    AuthenticationError,
    VerificationContext,
    VerifierSession,
)
from democratize_security.runtime_events import MODE as RUNTIME_MODE
from democratize_security.runtime_events import RuntimeLedgerError, reduce_runtime

VERSION = 7
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

V1_SCHEMA = dict(SCHEMA)
SCHEMA.update(
    {
        "attempts": """CREATE TABLE attempts (
            attempt_id TEXT PRIMARY KEY NOT NULL,
            trial_id TEXT NOT NULL UNIQUE REFERENCES trials(trial_id),
            campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
            state_json TEXT NOT NULL
        )""",
        "attempt_events": """CREATE TABLE attempt_events (
            event_id TEXT PRIMARY KEY NOT NULL,
            attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
            revision INTEGER NOT NULL CHECK (revision >= 1),
            receipt_id TEXT UNIQUE,
            created_at TEXT NOT NULL,
            request_json TEXT NOT NULL,
            state_json TEXT NOT NULL,
            UNIQUE (attempt_id, revision)
        )""",
        "attempts_no_delete": """CREATE TRIGGER attempts_no_delete BEFORE DELETE ON attempts
            BEGIN SELECT RAISE(ABORT, 'immutable attempt identity'); END""",
        "accounting_stops": """CREATE TABLE accounting_stops (
            event_id TEXT PRIMARY KEY NOT NULL,
            reason TEXT NOT NULL CHECK (reason = 'conflicting_identity')
        )""",
    }
)
for _operation in ("UPDATE", "DELETE"):
    _name = f"attempt_events_no_{_operation.lower()}"
    SCHEMA[_name] = (
        f"CREATE TRIGGER {_name} BEFORE {_operation} ON attempt_events "
        "BEGIN SELECT RAISE(ABORT, 'immutable ledger record'); END"
    )
    _name = f"accounting_stops_no_{_operation.lower()}"
    SCHEMA[_name] = (
        f"CREATE TRIGGER {_name} BEFORE {_operation} ON accounting_stops "
        "BEGIN SELECT RAISE(ABORT, 'immutable ledger record'); END"
    )


V2_SCHEMA = dict(SCHEMA)
SCHEMA["artifact_bindings"] = """CREATE TABLE artifact_bindings (
    event_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(attempt_id),
    revision INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    FOREIGN KEY (attempt_id, revision) REFERENCES attempt_events(attempt_id, revision)
)"""
for _operation in ("UPDATE", "DELETE"):
    _name = f"artifact_bindings_no_{_operation.lower()}"
    SCHEMA[_name] = (
        f"CREATE TRIGGER {_name} BEFORE {_operation} ON artifact_bindings "
        "BEGIN SELECT RAISE(ABORT, 'immutable artifact binding'); END"
    )


V3_SCHEMA = dict(SCHEMA)
SCHEMA["evidence_bindings"] = """CREATE TABLE evidence_bindings (
    event_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(attempt_id),
    artifact_event_id TEXT NOT NULL UNIQUE REFERENCES artifact_bindings(event_id),
    verification_request_id TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    FOREIGN KEY (attempt_id, revision) REFERENCES attempt_events(attempt_id, revision)
)"""
for _operation in ("UPDATE", "DELETE"):
    _name = f"evidence_bindings_no_{_operation.lower()}"
    SCHEMA[_name] = (
        f"CREATE TRIGGER {_name} BEFORE {_operation} ON evidence_bindings "
        "BEGIN SELECT RAISE(ABORT, 'immutable offline evidence binding'); END"
    )


V4_SCHEMA = dict(SCHEMA)
SCHEMA["verification_intents"] = """CREATE TABLE verification_intents (
    event_id TEXT PRIMARY KEY NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(attempt_id),
    artifact_event_id TEXT NOT NULL UNIQUE REFERENCES artifact_bindings(event_id),
    verification_request_id TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    FOREIGN KEY (attempt_id, revision) REFERENCES attempt_events(attempt_id, revision)
)"""
for _operation in ("UPDATE", "DELETE"):
    _name = f"verification_intents_no_{_operation.lower()}"
    SCHEMA[_name] = (
        f"CREATE TRIGGER {_name} BEFORE {_operation} ON verification_intents "
        "BEGIN SELECT RAISE(ABORT, 'immutable verification intent'); END"
    )


V5_SCHEMA = dict(SCHEMA)
SCHEMA["controller_generations"] = """CREATE TABLE controller_generations (
    generation INTEGER PRIMARY KEY NOT NULL CHECK (generation >= 1),
    process_id INTEGER NOT NULL CHECK (process_id >= 1)
)"""
for _operation in ("UPDATE", "DELETE"):
    _name = f"controller_generations_no_{_operation.lower()}"
    SCHEMA[_name] = (
        f"CREATE TRIGGER {_name} BEFORE {_operation} ON controller_generations "
        "BEGIN SELECT RAISE(ABORT, 'immutable controller generation'); END"
    )


V6_SCHEMA = dict(SCHEMA)
SCHEMA.update(
    {
        "runtime_results": """CREATE TABLE runtime_results (
            event_id TEXT PRIMARY KEY NOT NULL,
            attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(attempt_id),
            revision INTEGER NOT NULL,
            record_json TEXT NOT NULL,
            FOREIGN KEY (attempt_id, revision) REFERENCES attempt_events(attempt_id, revision)
        )""",
        "restore_fences": """CREATE TABLE restore_fences (
            fence_id TEXT PRIMARY KEY NOT NULL,
            created_at TEXT NOT NULL,
            record_json TEXT NOT NULL
        )""",
        "restore_reconciliations": """CREATE TABLE restore_reconciliations (
            event_id TEXT PRIMARY KEY NOT NULL,
            fence_id TEXT NOT NULL UNIQUE REFERENCES restore_fences(fence_id),
            created_at TEXT NOT NULL,
            record_json TEXT NOT NULL
        )""",
    }
)
for _table in ("runtime_results", "restore_fences", "restore_reconciliations"):
    for _operation in ("UPDATE", "DELETE"):
        _name = f"{_table}_no_{_operation.lower()}"
        SCHEMA[_name] = (
            f"CREATE TRIGGER {_name} BEFORE {_operation} ON {_table} "
            "BEGIN SELECT RAISE(ABORT, 'immutable runtime record'); END"
        )


class StoreError(ValueError):
    """The ledger cannot be safely used."""


def _json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _event_id(trial_id: str) -> str:
    return digest({"trial_id": trial_id, "sequence": 0, "kind": "planned"})


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        raise StoreError("Invalid ledger identifier")


def _amount(value):
    if type(value) is not int or not 0 <= value <= 10**12:
        raise StoreError("Cost must be a bounded nonnegative integer number of cents")


def _replay(previous: dict | None, request: dict) -> dict:
    """Replay one stored event with the reducer for its attempt's single mode."""
    runtime = isinstance(request, dict) and request.get("mode") == RUNTIME_MODE
    if previous is not None and (previous.get("mode") == RUNTIME_MODE) != runtime:
        raise StoreError("Attempt history mixes offline and runtime events")
    if runtime:
        return reduce_runtime(previous, request, admission=request.get("action") == "admit")
    return _reduce(previous, request)


def _reduce(previous: dict | None, request: dict) -> dict:
    """Pure offline accounting transitions; deliberately no dispatch or success state."""
    if not isinstance(request, dict):
        raise StoreError("Expected an accounting request object")
    if "mode" in request or (previous is not None and "mode" in previous):
        raise StoreError("Offline accounting cannot act on a runtime attempt")
    action = request.get("action")
    fields = {
        "prepare": {"campaign_id", "trial_id", "max_cost_cents", "basis_sha256"},
        "interrupt": {"reason"},
        "settle": {"actual_cost_cents", "receipt_id"},
    }
    if not isinstance(action, str) or action not in fields:
        raise StoreError("Unsupported offline accounting action")
    if set(request) != fields[action] | {"action", "attempt_id", "expected_revision"}:
        raise StoreError("Unexpected or missing accounting request fields")
    _identifier(request["attempt_id"])
    revision = request["expected_revision"]
    if type(revision) is not int or revision < 0:
        raise StoreError("Invalid expected revision")
    if revision != (previous["revision"] if previous else 0):
        raise StoreError("Stale expected revision")
    if previous and request["attempt_id"] != previous["attempt_id"]:
        raise StoreError("Attempt identity mismatch")
    if action == "prepare":
        if previous is not None:
            raise StoreError("Attempt already exists; retries are not implemented")
        for key in ("campaign_id", "trial_id"):
            _identifier(request[key])
        _amount(request["max_cost_cents"])
        basis = request["basis_sha256"]
        if not isinstance(basis, str) or not re.fullmatch(r"[0-9a-f]{64}", basis):
            raise StoreError("A concrete reservation-basis SHA-256 is required")
        return {
            "attempt_id": request["attempt_id"],
            "campaign_id": request["campaign_id"],
            "trial_id": request["trial_id"],
            "basis_sha256": basis,
            "revision": 1,
            "phase": "preparing",
            "max_cost_cents": request["max_cost_cents"],
            "actual_cost_cents": None,
            "reason": None,
            "receipt_id": None,
        }
    if previous is None:
        raise StoreError("Unknown attempt")
    state = {**previous, "revision": revision + 1}
    if action == "interrupt":
        if previous["phase"] != "preparing":
            raise StoreError("Cannot transition a terminal attempt")
        reason = request["reason"]
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 512:
            raise StoreError("A bounded interruption reason is required")
        state.update(phase="interrupted", reason=reason)
    else:
        if previous["phase"] != "interrupted" or previous["actual_cost_cents"] is not None:
            raise StoreError("Settlement requires an interrupted, unsettled attempt")
        _amount(request["actual_cost_cents"])
        _identifier(request["receipt_id"])
        state.update(
            actual_cost_cents=request["actual_cost_cents"], receipt_id=request["receipt_id"]
        )
    return state


class PlanStore:
    """Import and read deterministic offline plans, retaining every trial."""

    def __init__(
        self,
        directory: Path,
        *,
        migrate: bool = False,
        objects_directory: Path | None = None,
        evidence_directory: Path | None = None,
    ):
        self._lock_fd = None
        self._db = None
        self._owner_pid = os.getpid()
        self._generation = None
        self._objects_directory = (
            objects_directory.absolute() if objects_directory is not None else None
        )
        self._evidence_directory = (
            evidence_directory.absolute() if evidence_directory is not None else None
        )
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
            legacy = version in (1, 2, 3, 4, 5, 6) and application == APPLICATION_ID
            old_schema = {
                1: V1_SCHEMA,
                2: V2_SCHEMA,
                3: V3_SCHEMA,
                4: V4_SCHEMA,
                5: V5_SCHEMA,
                6: V6_SCHEMA,
            }.get(version, SCHEMA)
            if legacy and not migrate:
                raise StoreError(f"Version {version} requires explicit migrate=True")
            if not fresh and (
                version not in (1, 2, 3, 4, 5, 6, VERSION) or application != APPLICATION_ID
            ):
                raise StoreError("Unknown ledger version or application; no automatic migration")
            if not fresh and objects != old_schema:
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
            if legacy and version >= 2:
                self.attempts()  # Reject corrupt accounting before changing the schema.
            if legacy and version >= 3:
                self.artifact_bindings()  # Validate old objects before migration commits.
            if legacy and version == 4:
                self._read_evidence_bindings([])  # Do not invent intents for v4 observations.
            if legacy and version in (5, 6):
                self.evidence_bindings()  # Validate intents and evidence before migration.
            if legacy and version == 6:
                self._generation_tip()  # Validate ownership history before migration.
            if legacy:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    for name, statement in SCHEMA.items():
                        if name not in old_schema:
                            self._db.execute(statement)
                    self._db.execute(f"PRAGMA user_version={VERSION}")
                    self._db.execute("COMMIT")
                except BaseException:
                    if self._db.in_transaction:
                        self._db.execute("ROLLBACK")
                    raise
            self._validate_runtime_objects(self.attempts())
            self.evidence_bindings()
            self.unreconciled_restore_fences()
            self.runtime_results()
            self._allocate_generation()
        except BaseException:
            self.close()
            raise

    def _schema(self) -> dict:
        return dict(
            self._db.execute(
                "SELECT name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"
            ).fetchall()
        )

    def _connection(self):
        if self._db is None:
            raise StoreError("Ledger is closed")
        if os.getpid() != self._owner_pid:
            raise StoreError("Ledger handle belongs to another process; reopen after fork")
        return self._db

    def _generation_tip(self) -> tuple[int, int] | None:
        """Validate the append-only ownership history, including gaps and SQL types."""
        rows = (
            self._connection()
            .execute(
                "SELECT generation, process_id FROM controller_generations ORDER BY generation"
            )
            .fetchall()
        )
        for expected, (generation, process_id) in enumerate(rows, 1):
            if (
                type(generation) is not int
                or generation != expected
                or (type(process_id) is not int or process_id < 1)
            ):
                raise StoreError("Invalid controller generation history")
        return rows[-1] if rows else None

    def _allocate_generation(self):
        """Publish ownership only after its own FULL-sync allocation transaction commits."""
        db = self._connection()
        db.execute("BEGIN IMMEDIATE")
        try:
            tip = self._generation_tip()
            generation = tip[0] + 1 if tip else 1
            if generation > 2**63 - 1:
                raise StoreError("Controller generation exhausted")
            db.execute(
                "INSERT INTO controller_generations VALUES (?, ?)",
                (generation, self._owner_pid),
            )
            db.execute("COMMIT")
            # No caller can observe a speculative, rolled-back generation.
            self._generation = generation
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise

    @property
    def controller_generation(self) -> int:
        """Validated current ownership for trusted callers; no execution authority."""
        self._connection()
        if (
            self._lock_fd is None
            or self._generation is None
            or self._generation_tip() != (self._generation, self._owner_pid)
        ):
            raise StoreError("Stale controller generation")
        return self._generation

    def _begin_write(self):
        """Fence before retries, integrity stops, object sync or any persistent mutation.

        Keep the SQLite write lock until COMMIT/ROLLBACK. A successor cannot
        allocate its generation between this check and the transaction's effects.
        """
        db = self._connection()
        db.execute("BEGIN IMMEDIATE")
        try:
            _ = self.controller_generation
        except BaseException:
            db.execute("ROLLBACK")
            raise
        return db

    def import_campaign(self, campaign: dict) -> dict:
        """Atomically import the complete plan; exact re-import is a no-op."""
        expected = plan(campaign)
        serialized = _json(expected)
        if len(serialized.encode("utf-8")) > MAX_PLAN_BYTES:
            raise StoreError("Plan exceeds ledger byte limit")
        campaign_id = expected["campaign_id"]
        db = self._begin_write()
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

    def attempts(self) -> list[dict]:
        """Rebuild each attempt from its immutable events; reject projection drift."""
        db = self._connection()
        states = []
        for attempt_id, trial_id, campaign_id, encoded in db.execute(
            "SELECT attempt_id, trial_id, campaign_id, state_json FROM attempts ORDER BY attempt_id"
        ).fetchall():
            previous = None
            rows = db.execute(
                "SELECT event_id, revision, receipt_id, created_at, request_json, state_json "
                "FROM attempt_events WHERE attempt_id = ? ORDER BY revision",
                (attempt_id,),
            ).fetchall()
            try:
                for event_id, revision, receipt, timestamp, request_json, state_json in rows:
                    _identifier(event_id)
                    if datetime.fromisoformat(timestamp).utcoffset() != UTC.utcoffset(None):
                        raise StoreError("Event timestamp must be UTC")
                    request = json.loads(request_json, object_pairs_hook=_unique_pairs)
                    previous = _replay(previous, request)
                    if (
                        request_json != _json(request)
                        or state_json != _json(previous)
                        or revision != previous["revision"]
                        or receipt != request.get("receipt_id")
                    ):
                        raise StoreError("Accounting event mismatch")
                if (
                    previous is None
                    or encoded != _json(previous)
                    or (attempt_id, trial_id, campaign_id)
                    != (previous["attempt_id"], previous["trial_id"], previous["campaign_id"])
                ):
                    raise StoreError("Attempt projection does not match its event history")
                trial = db.execute(
                    "SELECT campaign_id FROM trials WHERE trial_id = ?", (trial_id,)
                ).fetchone()
                if trial != (campaign_id,):
                    raise StoreError("Attempt does not belong to its campaign's trial")
                states.append(previous)
            except (TypeError, ValueError, KeyError) as error:
                raise StoreError(f"Invalid attempt ledger: {error}") from error
        return states

    def _artifact_request(self, request: dict) -> dict:
        """Check pinned synthetic intent against the immutable plan and prepare event."""
        if not isinstance(request, dict) or set(request) != {
            "attempt_id",
            "expected_revision",
            "campaign_id",
            "trial_id",
            "task_revision",
            "verifier_sha256",
            "protocol",
            "artifact_ref",
        }:
            raise StoreError("Invalid artifact binding request fields")
        for key in ("attempt_id", "campaign_id", "trial_id", "protocol"):
            _identifier(request[key])
        for key in ("task_revision", "verifier_sha256"):
            if not isinstance(request[key], str) or not re.fullmatch(r"[0-9a-f]{64}", request[key]):
                raise StoreError("A concrete task/verifier SHA-256 is required")
        revision = request["expected_revision"]
        if type(revision) is not int or revision < 1:
            raise StoreError("Invalid artifact binding revision")
        row = (
            self._connection()
            .execute(
                "SELECT state_json FROM attempt_events WHERE attempt_id = ? AND revision = ?",
                (request["attempt_id"], revision),
            )
            .fetchone()
        )
        if row is None:
            raise StoreError("Unknown artifact binding attempt/revision")
        state = json.loads(row[0], object_pairs_hook=_unique_pairs)
        if state.get("mode") == RUNTIME_MODE:
            raise StoreError("Offline artifact binding cannot act on a runtime attempt")
        if state["phase"] != "preparing" or any(
            state[key] != request[key] for key in ("attempt_id", "campaign_id", "trial_id")
        ):
            raise StoreError("Artifact binding does not match preparing attempt")
        planned = self.snapshot(request["campaign_id"])
        trial = next(t for t in planned["trials"] if t["trial_id"] == request["trial_id"])
        if trial["task_revision"] != request["task_revision"]:
            raise StoreError("Artifact task revision mismatch")
        if self._objects_directory is None:
            raise StoreError("Artifact bindings require objects_directory")
        return artifact_objects.read_artifact(self._objects_directory, request["artifact_ref"])

    def artifact_bindings(self) -> list[dict]:
        """Revalidate every referenced object; a binding is never an accepted result."""
        self.attempts()
        records = []
        rows = (
            self._connection()
            .execute(
                "SELECT event_id, attempt_id, revision, record_json FROM artifact_bindings "
                "ORDER BY event_id"
            )
            .fetchall()
        )
        for event_id, attempt_id, revision, encoded in rows:
            try:
                if len(encoded.encode()) > 8192:
                    raise StoreError("Artifact binding exceeds byte limit")
                record = json.loads(encoded, object_pairs_hook=_unique_pairs)
                if not isinstance(record, dict) or set(record) != {
                    "schema_version",
                    "event_id",
                    "request",
                    "binding_sha256",
                }:
                    raise StoreError("Invalid artifact binding envelope")
                _identifier(event_id)
                request = record["request"]
                self._artifact_request(request)
                expected = {"schema_version": 1, "event_id": event_id, "request": request}
                expected["binding_sha256"] = digest(expected)
                if (
                    encoded != _json(expected)
                    or attempt_id != request["attempt_id"]
                    or revision != request["expected_revision"]
                ):
                    raise StoreError("Artifact binding identity mismatch")
                records.append(record)
            except (ValueError, TypeError, KeyError, OSError, StopIteration) as error:
                raise StoreError(f"Invalid artifact binding: {error}") from error
        return records

    def record_artifact(self, event_id: str, request: dict) -> dict:
        """Pin an artifact and synthetic verifier intent, without changing accounting.

        One immutable row is both the reference and its event. No success phase,
        verifier result or execution provenance is inferred from this operation.
        """
        _identifier(event_id)
        if not isinstance(request, dict):
            raise StoreError("Expected an artifact binding request")
        encoded = _json(request)
        if len(encoded.encode()) > 4096:
            raise StoreError("Artifact binding request exceeds byte limit")
        request = json.loads(encoded)
        db = self._begin_write()
        try:
            records = self.artifact_bindings()
            duplicates = [
                r
                for r in records
                if r["event_id"] == event_id
                or r["request"]["attempt_id"] == request.get("attempt_id")
            ]
            if duplicates:
                if any(
                    r["event_id"] != event_id or _json(r["request"]) != encoded for r in duplicates
                ):
                    db.execute(
                        "INSERT OR IGNORE INTO accounting_stops VALUES (?, 'conflicting_identity')",
                        (event_id,),
                    )
                    db.execute("COMMIT")
                    raise StoreError("Conflicting artifact event or attempt binding")
                result = duplicates[0]
            else:
                if db.execute("SELECT 1 FROM accounting_stops LIMIT 1").fetchone():
                    raise StoreError("Integrity stop blocks artifact binding")
                bundle = self._artifact_request(request)
                current = next(
                    s for s in self.attempts() if s["attempt_id"] == request["attempt_id"]
                )
                if current["revision"] != request["expected_revision"]:
                    raise StoreError("Stale expected artifact revision")
                # Reconcile file and directory durability before committing a reference.
                if (
                    artifact_objects.publish_artifact(self._objects_directory, bundle)
                    != request["artifact_ref"]
                ):
                    raise StoreError("Artifact publication identity mismatch")
                result = {"schema_version": 1, "event_id": event_id, "request": request}
                result["binding_sha256"] = digest(result)
                db.execute(
                    "INSERT INTO artifact_bindings VALUES (?, ?, ?, ?)",
                    (event_id, request["attempt_id"], request["expected_revision"], _json(result)),
                )
            db.execute("COMMIT")
            return result
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise

    def _intent_request(self, request: dict, bindings: list[dict]) -> dict:
        if not isinstance(request, dict) or set(request) != {
            "attempt_id",
            "expected_revision",
            "artifact_binding_sha256",
            "verification_request_id",
        }:
            raise StoreError("Invalid verification intent fields")
        _identifier(request["attempt_id"])
        _identifier(request["verification_request_id"])
        if type(request["expected_revision"]) is not int or request["expected_revision"] < 1:
            raise StoreError("Invalid verification intent revision")
        binding = next(
            (b for b in bindings if b["request"]["attempt_id"] == request["attempt_id"]), None
        )
        if (
            binding is None
            or binding["binding_sha256"] != request["artifact_binding_sha256"]
            or binding["request"]["expected_revision"] != request["expected_revision"]
        ):
            raise StoreError("Verification intent does not match artifact binding")
        return binding

    def verification_intents(self) -> list[dict]:
        """Read durable offline intent, not evidence of dispatch or verifier execution."""
        bindings = self.artifact_bindings()
        records = []
        rows = (
            self._connection()
            .execute(
                "SELECT event_id, attempt_id, artifact_event_id, verification_request_id, "
                "revision, record_json FROM verification_intents ORDER BY event_id"
            )
            .fetchall()
        )
        for event_id, attempt_id, artifact_event_id, request_id, revision, encoded in rows:
            try:
                if len(encoded.encode()) > 4096:
                    raise StoreError("Verification intent exceeds byte limit")
                record = json.loads(encoded, object_pairs_hook=_unique_pairs)
                if not isinstance(record, dict) or set(record) != {
                    "schema_version",
                    "kind",
                    "event_id",
                    "request",
                    "intent_sha256",
                }:
                    raise StoreError("Invalid verification intent envelope")
                _identifier(event_id)
                request = record["request"]
                binding = self._intent_request(request, bindings)
                expected = {
                    "schema_version": 1,
                    "kind": "offline_verification_intent",
                    "event_id": event_id,
                    "request": request,
                }
                expected["intent_sha256"] = digest(expected)
                if (
                    encoded != _json(expected)
                    or attempt_id != request["attempt_id"]
                    or artifact_event_id != binding["event_id"]
                    or request_id != request["verification_request_id"]
                    or revision != request["expected_revision"]
                ):
                    raise StoreError("Verification intent identity mismatch")
                records.append(record)
            except (ValueError, TypeError, KeyError) as error:
                raise StoreError(f"Invalid verification intent: {error}") from error
        return records

    def record_verification_intent(self, event_id: str, request: dict) -> dict:
        """Commit expected verification identity before admitting any new evidence.

        No external action, secret, accepted result or accounting change is created.
        Existing legacy evidence cannot acquire an intent retrospectively.
        """
        _identifier(event_id)
        if not isinstance(request, dict):
            raise StoreError("Expected a verification intent request")
        encoded = _json(request)
        if len(encoded.encode()) > 2048:
            raise StoreError("Verification intent request exceeds byte limit")
        request = json.loads(encoded)
        db = self._begin_write()
        try:
            self.evidence_bindings()
            records = self.verification_intents()
            duplicates = [
                r
                for r in records
                if r["event_id"] == event_id
                or r["request"]["attempt_id"] == request.get("attempt_id")
                or r["request"]["verification_request_id"] == request.get("verification_request_id")
            ]
            if duplicates:
                if any(
                    r["event_id"] != event_id or _json(r["request"]) != encoded for r in duplicates
                ):
                    db.execute(
                        "INSERT OR IGNORE INTO accounting_stops VALUES (?, 'conflicting_identity')",
                        (event_id,),
                    )
                    db.execute("COMMIT")
                    raise StoreError("Conflicting verification intent identity")
                result = duplicates[0]
            else:
                if db.execute("SELECT 1 FROM accounting_stops LIMIT 1").fetchone():
                    raise StoreError("Integrity stop blocks verification intent")
                binding = self._intent_request(request, self.artifact_bindings())
                if db.execute(
                    "SELECT 1 FROM evidence_bindings "
                    "WHERE attempt_id=? OR verification_request_id=?",
                    (request["attempt_id"], request["verification_request_id"]),
                ).fetchone():
                    raise StoreError("Cannot create retrospective verification intent")
                current = next(
                    s for s in self.attempts() if s["attempt_id"] == request["attempt_id"]
                )
                if (
                    current["phase"] != "preparing"
                    or current["revision"] != request["expected_revision"]
                ):
                    raise StoreError("Stale verification intent revision")
                result = {
                    "schema_version": 1,
                    "kind": "offline_verification_intent",
                    "event_id": event_id,
                    "request": request,
                }
                result["intent_sha256"] = digest(result)
                db.execute(
                    "INSERT INTO verification_intents VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        request["attempt_id"],
                        binding["event_id"],
                        request["verification_request_id"],
                        request["expected_revision"],
                        _json(result),
                    ),
                )
            db.execute("COMMIT")
            return result
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise

    def _evidence_request(
        self, request: dict, bindings: list[dict], intents: list[dict], *, version: int
    ) -> tuple[dict, dict]:
        """Resolve expected context from the ledger, never from evidence file fields."""
        fields = {
            "attempt_id",
            "expected_revision",
            "artifact_binding_sha256",
            "verification_request_id",
            "evidence_ref",
        }
        if type(version) is not int or version not in (1, 2):
            raise StoreError("Unsupported offline evidence binding schema")
        if version == 2:
            fields.add("verification_intent_sha256")
        if not isinstance(request, dict) or set(request) != fields:
            raise StoreError("Invalid offline evidence request fields")
        _identifier(request["attempt_id"])
        _identifier(request["verification_request_id"])
        revision = request["expected_revision"]
        if type(revision) is not int or revision < 1:
            raise StoreError("Invalid offline evidence revision")
        binding = next(
            (b for b in bindings if b["request"]["attempt_id"] == request["attempt_id"]), None
        )
        if binding is None or binding["binding_sha256"] != request["artifact_binding_sha256"]:
            raise StoreError("Unknown or mismatched artifact binding for evidence")
        if binding["request"]["expected_revision"] != revision:
            raise StoreError("Evidence revision does not match artifact binding")
        intent = next(
            (i for i in intents if i["request"]["attempt_id"] == request["attempt_id"]), None
        )
        if version == 2:
            if (
                intent is None
                or intent["intent_sha256"] != request["verification_intent_sha256"]
                or any(
                    intent["request"][key] != request[key]
                    for key in (
                        "attempt_id",
                        "expected_revision",
                        "artifact_binding_sha256",
                        "verification_request_id",
                    )
                )
            ):
                raise StoreError("Evidence requires matching preexisting verification intent")
        elif any(
            i["request"]["attempt_id"] == request["attempt_id"]
            or i["request"]["verification_request_id"] == request["verification_request_id"]
            for i in intents
        ):
            raise StoreError("Legacy evidence cannot claim verification intent")
        if self._evidence_directory is None:
            raise StoreError("Offline evidence bindings require evidence_directory")
        record = evidence_objects.read_evidence(
            self._evidence_directory,
            request["evidence_ref"],
            binding,
            request["verification_request_id"],
        )
        return binding, record

    def evidence_bindings(self) -> list[dict]:
        """Revalidate offline observations and artifacts; never infer accepted results."""
        return self._read_evidence_bindings(self.verification_intents())

    def _read_evidence_bindings(self, intents: list[dict]) -> list[dict]:
        bindings = self.artifact_bindings()
        records = []
        rows = (
            self._connection()
            .execute(
                "SELECT event_id, attempt_id, artifact_event_id, verification_request_id, "
                "revision, record_json FROM evidence_bindings ORDER BY event_id"
            )
            .fetchall()
        )
        for event_id, attempt_id, artifact_event_id, request_id, revision, encoded in rows:
            try:
                if len(encoded.encode()) > 8192:
                    raise StoreError("Offline evidence binding exceeds byte limit")
                record = json.loads(encoded, object_pairs_hook=_unique_pairs)
                if not isinstance(record, dict) or set(record) != {
                    "schema_version",
                    "kind",
                    "event_id",
                    "request",
                    "binding_sha256",
                }:
                    raise StoreError("Invalid offline evidence binding envelope")
                _identifier(event_id)
                request = record["request"]
                binding, _ = self._evidence_request(
                    request, bindings, intents, version=record["schema_version"]
                )
                expected = {
                    "schema_version": record["schema_version"],
                    "kind": "offline_evidence_binding",
                    "event_id": event_id,
                    "request": request,
                }
                expected["binding_sha256"] = digest(expected)
                if (
                    encoded != _json(expected)
                    or attempt_id != request["attempt_id"]
                    or artifact_event_id != binding["event_id"]
                    or request_id != request["verification_request_id"]
                    or revision != request["expected_revision"]
                ):
                    raise StoreError("Offline evidence binding identity mismatch")
                records.append(record)
            except (ValueError, TypeError, KeyError, OSError) as error:
                raise StoreError(f"Invalid offline evidence binding: {error}") from error
        return records

    def record_evidence(self, event_id: str, request: dict) -> dict:
        """Attach a synthetic offline report, without completing or accepting a trial.

        New records require previously committed intent, which is not authentication.
        One immutable row is both reference and event, unchanged by later accounting.
        """
        _identifier(event_id)
        if not isinstance(request, dict):
            raise StoreError("Expected an offline evidence binding request")
        encoded = _json(request)
        if len(encoded.encode()) > 4096:
            raise StoreError("Offline evidence request exceeds byte limit")
        request = json.loads(encoded)
        db = self._begin_write()
        try:
            records = self.evidence_bindings()
            duplicates = [
                r
                for r in records
                if r["event_id"] == event_id
                or r["request"]["attempt_id"] == request.get("attempt_id")
                or r["request"]["verification_request_id"] == request.get("verification_request_id")
            ]
            if duplicates:
                if any(
                    r["event_id"] != event_id or _json(r["request"]) != encoded for r in duplicates
                ):
                    db.execute(
                        "INSERT OR IGNORE INTO accounting_stops VALUES (?, 'conflicting_identity')",
                        (event_id,),
                    )
                    db.execute("COMMIT")
                    raise StoreError(
                        "Conflicting offline evidence event, attempt or request identity"
                    )
                result = duplicates[0]
            else:
                if db.execute("SELECT 1 FROM accounting_stops LIMIT 1").fetchone():
                    raise StoreError("Integrity stop blocks offline evidence binding")
                binding, record = self._evidence_request(
                    request, self.artifact_bindings(), self.verification_intents(), version=2
                )
                current = next(
                    s for s in self.attempts() if s["attempt_id"] == request["attempt_id"]
                )
                if (
                    current["phase"] != "preparing"
                    or current["revision"] != request["expected_revision"]
                ):
                    raise StoreError("Stale expected offline evidence revision")
                if (
                    evidence_objects.publish_evidence(
                        self._evidence_directory,
                        record,
                        binding,
                        request["verification_request_id"],
                    )
                    != request["evidence_ref"]
                ):
                    raise StoreError("Offline evidence publication identity mismatch")
                result = {
                    "schema_version": 2,
                    "kind": "offline_evidence_binding",
                    "event_id": event_id,
                    "request": request,
                }
                result["binding_sha256"] = digest(result)
                db.execute(
                    "INSERT INTO evidence_bindings VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        request["attempt_id"],
                        binding["event_id"],
                        request["verification_request_id"],
                        request["expected_revision"],
                        _json(result),
                    ),
                )
            db.execute("COMMIT")
            return result
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise

    def budget_snapshot(self, campaign_id: str) -> dict:
        """Account for synthetic costs; this is not permission to spend."""
        planned = self.snapshot(campaign_id)
        self.evidence_bindings()
        states = self.attempts()
        self._validate_runtime_objects(states)
        self.runtime_results()
        fenced = bool(self.unreconciled_restore_fences())
        own = [s for s in states if s["campaign_id"] == campaign_id]
        held = sum(s["max_cost_cents"] for s in own if s["actual_cost_cents"] is None)
        spent = sum(s["actual_cost_cents"] for s in own if s["actual_cost_cents"] is not None)
        overrun = any(
            s["actual_cost_cents"] is not None and s["actual_cost_cents"] > s["max_cost_cents"]
            for s in own
        )
        limit = planned["campaign"]["limits"]["max_cost_usd_cents"]
        return {
            "limit_cents": limit,
            "held_cents": held,
            "settled_cents": spent,
            "available_cents": limit - held - spent,
            "unknown_cost_count": sum(s["actual_cost_cents"] is None for s in own),
            "blocked": overrun
            or fenced
            or bool(self._connection().execute("SELECT 1 FROM accounting_stops LIMIT 1").fetchone())
            or any(
                s["phase"] not in ("completed", "interrupted") or s["actual_cost_cents"] is None
                for s in states
            ),
            "overrun": overrun,
            "restore_fenced": fenced,
            "execution_enabled": False,
        }

    def unreconciled_restore_fences(self) -> list[str]:
        """Restore fences without a reconciliation event; each blocks dispatch."""
        db = self._connection()
        fences = {}
        for fence_id, created_at, encoded in db.execute(
            "SELECT fence_id, created_at, record_json FROM restore_fences ORDER BY fence_id"
        ).fetchall():
            _identifier(fence_id)
            record = json.loads(encoded, object_pairs_hook=_unique_pairs)
            if (
                encoded != _json(record)
                or record.get("fence_id") != fence_id
                or record.get("kind") != "restore_fence"
                or datetime.fromisoformat(created_at).utcoffset() != UTC.utcoffset(None)
            ):
                raise StoreError("Invalid restore fence record")
            fences[fence_id] = record
        for event_id, fence_id, encoded in db.execute(
            "SELECT event_id, fence_id, record_json FROM restore_reconciliations"
        ).fetchall():
            record = json.loads(encoded, object_pairs_hook=_unique_pairs)
            if (
                encoded != _json(record)
                or record.get("event_id") != event_id
                or record.get("fence_id") != fence_id
                or fence_id not in fences
            ):
                raise StoreError("Invalid restore reconciliation record")
            del fences[fence_id]
        return sorted(fences)

    def _validate_runtime_objects(self, states: list[dict]) -> None:
        """Every sealed runtime artifact must still exist with its exact bytes."""
        for state in states:
            if state.get("mode") == RUNTIME_MODE and state["artifact_ref"] is not None:
                if self._objects_directory is None:
                    raise StoreError("Runtime artifacts require objects_directory")
                try:
                    artifact_objects.read_artifact(self._objects_directory, state["artifact_ref"])
                except (OSError, ValueError) as error:
                    raise StoreError(f"Runtime artifact is missing or changed: {error}") from error

    def recovery_state(self, attempt_id: str) -> RecoveryState:
        """Project one fully validated runtime attempt for pure recovery advice.

        Every attempt is replayed and every sealed artifact re-read first; integrity
        errors propagate, so a returned projection always has `integrity_ok=True`.
        `generation` is this inspecting controller, never the attempt's original one,
        so observations must be gathered fresh under the current ownership.
        """
        _identifier(attempt_id)
        states = self.attempts()
        self._validate_runtime_objects(states)
        matches = [s for s in states if s["attempt_id"] == attempt_id]
        if not matches or matches[0].get("mode") != RUNTIME_MODE:
            raise StoreError("Unknown runtime attempt")
        state = matches[0]
        try:
            return RecoveryState(
                trial_id=state["trial_id"],
                attempt_id=attempt_id,
                generation=self.controller_generation,
                revision=state["revision"],
                phase=state["phase"],
                max_cost_cents=state["max_cost_cents"],
                actual_cost_cents=state["actual_cost_cents"],
                runner_request_id=state["runner_request_id"],
                worker_id=state["worker_id"],
                verification_request_id=state["verification_request_id"],
                artifact_stage="none" if state["artifact_ref"] is None else "referenced",
                previous_phase=state["previous_phase"],
            )
        except RecoveryError as error:
            raise StoreError(f"Runtime attempt cannot be projected: {error}") from error

    def runtime_context(
        self, attempt_id: str, verification_request_id: str, *, expected_revision: int
    ) -> VerificationContext:
        """Trusted verifier context derived only from validated store state."""
        states = self.attempts()
        self._validate_runtime_objects(states)
        state = next((s for s in states if s["attempt_id"] == attempt_id), None)
        if state is None or state.get("mode") != RUNTIME_MODE:
            raise StoreError("Unknown runtime attempt")
        if state["phase"] not in ("sealed", "verifying"):
            raise StoreError("Verifier context requires a sealed attempt")
        reference = state["artifact_ref"]
        return VerificationContext(
            campaign_id=state["campaign_id"],
            trial_id=state["trial_id"],
            attempt_id=attempt_id,
            runner_request_id=state["runner_request_id"],
            worker_id=state["worker_id"],
            verification_request_id=verification_request_id,
            controller_generation=self.controller_generation,
            expected_revision=expected_revision,
            task_revision=state["task_revision"],
            artifact_binding_sha256=digest(reference),
            artifact_sha256=reference["artifact_sha256"],
            object_sha256=reference["object_sha256"],
            verifier_sha256=state["verifier_sha256"],
            protocol=state["protocol"],
        )

    def _commit_attempt_event(self, db, event_id, previous, request, result) -> None:
        """Persist one transition: projection and immutable event, same transaction."""
        if previous is None:
            db.execute(
                "INSERT INTO attempts VALUES (?, ?, ?, ?)",
                (result["attempt_id"], result["trial_id"], result["campaign_id"], _json(result)),
            )
        else:
            db.execute(
                "UPDATE attempts SET state_json = ? WHERE attempt_id = ?",
                (_json(result), result["attempt_id"]),
            )
        db.execute(
            "INSERT INTO attempt_events VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                result["attempt_id"],
                result["revision"],
                request.get("receipt_id"),
                datetime.now(UTC).isoformat(),
                _json(request),
                _json(result),
            ),
        )

    def _existing_event(self, db, event_id, request):
        """Exact repeat -> stored state; any conflicting reuse -> durable integrity stop."""
        encoded = _json(request)
        duplicates = db.execute(
            "SELECT request_json, state_json FROM attempt_events "
            "WHERE event_id = ? OR receipt_id = ?",
            (event_id, request.get("receipt_id")),
        ).fetchall()
        if not duplicates:
            return None
        if any(row[0] != encoded for row in duplicates):
            db.execute(
                "INSERT OR IGNORE INTO accounting_stops VALUES (?, 'conflicting_identity')",
                (event_id,),
            )
            db.execute("COMMIT")
            raise StoreError("Conflicting runtime event or receipt identity")
        return json.loads(duplicates[0][1])

    def runtime_results(self) -> list[dict]:
        """Admitted results, revalidated against their event, attempt and envelope bytes."""
        db = self._connection()
        states = {s["attempt_id"]: s for s in self.attempts()}
        results = []
        seen = set()
        for event_id, attempt_id, revision, encoded in db.execute(
            "SELECT event_id, attempt_id, revision, record_json FROM runtime_results "
            "ORDER BY event_id"
        ).fetchall():
            try:
                record = json.loads(encoded, object_pairs_hook=_unique_pairs)
                raw = base64.b64decode(record["envelope_base64"], validate=True)
                observation = record["observation"]
                state = states[attempt_id]
                event = db.execute(
                    "SELECT event_id, request_json FROM attempt_events "
                    "WHERE attempt_id = ? AND revision = ?",
                    (attempt_id, revision),
                ).fetchone()
                request = json.loads(event[1])
                if (
                    encoded != _json(record)
                    or set(record)
                    != {
                        "schema_version",
                        "kind",
                        "event_id",
                        "attempt_id",
                        "observation",
                        "envelope_base64",
                        "coverage",
                        "outcome",
                    }
                    or record["schema_version"] != 1
                    or record["kind"] != "runtime_result"
                    or (record["event_id"], record["attempt_id"]) != (event_id, attempt_id)
                    or event[0] != event_id
                    or request.get("action") != "admit"
                    or request.get("result_sha256") != digest(record)
                    or state.get("result_sha256") != digest(record)
                    or observation["envelope_sha256"] != hashlib.sha256(raw).hexdigest()
                    or observation["context"]["attempt_id"] != attempt_id
                    or observation["report"]["coverage"] != record["coverage"]
                    or observation["report"]["outcome"] != record["outcome"]
                    or request.get("coverage") != record["coverage"]
                ):
                    raise StoreError("Runtime result does not match its event or envelope")
            except (KeyError, TypeError, ValueError) as error:
                raise StoreError(f"Invalid runtime result: {error}") from error
            seen.add(attempt_id)
            results.append(record)
        if any(s.get("result_sha256") and a not in seen for a, s in states.items()):
            raise StoreError("Admitted attempt is missing its runtime result")
        return results

    def admit_result(
        self,
        event_id: str,
        attempt_id: str,
        expected_revision: int,
        session: VerifierSession,
        raw: bytes,
    ) -> dict:
        """Authenticate a verifier report with its live session and admit it atomically.

        The expected context is rebuilt from validated store state and the current
        controller generation; the session must carry the exact committed challenge.
        A complete report completes the attempt with its outcome (pass or fail); a
        partial one interrupts it as incomplete and keeps the cost hold. The result
        row, event and attempt state commit together or not at all.
        """
        _identifier(event_id)
        if not isinstance(session, VerifierSession):
            raise StoreError("A live verifier session is required")
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_AUTH_BYTES:
            raise StoreError("Verifier envelope must be bounded bytes")
        db = self._begin_write()
        try:
            states = self.attempts()
            self._validate_runtime_objects(states)
            existing = [r for r in self.runtime_results() if r["event_id"] == event_id]
            if existing:
                (record,) = existing
                if (
                    record["attempt_id"] != attempt_id
                    or record["observation"]["envelope_sha256"] != hashlib.sha256(raw).hexdigest()
                ):
                    db.execute(
                        "INSERT OR IGNORE INTO accounting_stops VALUES (?, 'conflicting_identity')",
                        (event_id,),
                    )
                    db.execute("COMMIT")
                    raise StoreError("Conflicting runtime result identity")
                db.execute("COMMIT")
                return record
            if db.execute(
                "SELECT 1 FROM attempt_events WHERE event_id = ?", (event_id,)
            ).fetchone():
                db.execute(
                    "INSERT OR IGNORE INTO accounting_stops VALUES (?, 'conflicting_identity')",
                    (event_id,),
                )
                db.execute("COMMIT")
                raise StoreError("Conflicting runtime result identity")
            state = next((s for s in states if s["attempt_id"] == attempt_id), None)
            if (
                state is None
                or state.get("mode") != RUNTIME_MODE
                or state["phase"] != "verifying"
                or state["revision"] != expected_revision
            ):
                raise StoreError("Admission requires a verifying attempt at the expected revision")
            challenge = session.public_challenge()
            expected = self.runtime_context(
                attempt_id, state["verification_request_id"], expected_revision=state["revision"]
            )
            if challenge["challenge_sha256"] != state["challenge_sha256"] or challenge[
                "context"
            ] != asdict(expected):
                raise StoreError("Session does not hold this attempt's committed challenge")
            try:
                observation = session.authenticate(raw)
            except AuthenticationError as error:
                raise StoreError(f"Verifier report rejected: {error}") from error
            report = observation.report
            record = {
                "schema_version": 1,
                "kind": "runtime_result",
                "event_id": event_id,
                "attempt_id": attempt_id,
                "observation": observation.public_record(),
                "envelope_base64": base64.b64encode(raw).decode(),
                "coverage": report["coverage"],
                "outcome": report["outcome"],
            }
            request = {
                "mode": RUNTIME_MODE,
                "action": "admit",
                "attempt_id": attempt_id,
                "expected_revision": expected_revision,
                "result_sha256": digest(record),
                "coverage": report["coverage"],
            }
            result = reduce_runtime(state, request, admission=True)
            self._commit_attempt_event(db, event_id, state, request, result)
            db.execute(
                "INSERT INTO runtime_results VALUES (?, ?, ?, ?)",
                (event_id, attempt_id, result["revision"], _json(record)),
            )
            db.execute("COMMIT")
            return json.loads(_json(record))
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise

    def reconcile_restore(self, event_id: str, fence_id: str, statement: str) -> dict:
        """Explicitly clear one restore fence after reconciling external work.

        Every nonterminal runtime attempt must already be `reconciling` (or
        terminal), so no restored attempt silently resumes. The statement records
        how the operator established that no unrecorded external work remains.
        """
        _identifier(event_id)
        _identifier(fence_id)
        if not isinstance(statement, str) or not statement.strip() or len(statement) > 1024:
            raise StoreError("A bounded reconciliation statement is required")
        record = {
            "schema_version": 1,
            "kind": "restore_reconciliation",
            "event_id": event_id,
            "fence_id": fence_id,
            "statement": statement,
        }
        db = self._begin_write()
        try:
            existing = db.execute(
                "SELECT record_json FROM restore_reconciliations "
                "WHERE event_id = ? OR fence_id = ?",
                (event_id, fence_id),
            ).fetchall()
            if existing:
                if any(row[0] != _json(record) for row in existing):
                    db.execute(
                        "INSERT OR IGNORE INTO accounting_stops VALUES (?, 'conflicting_identity')",
                        (event_id,),
                    )
                    db.execute("COMMIT")
                    raise StoreError("Conflicting restore reconciliation identity")
                db.execute("COMMIT")
                return record
            if fence_id not in self.unreconciled_restore_fences():
                raise StoreError("Unknown restore fence")
            active = [
                s["attempt_id"]
                for s in self.attempts()
                if s.get("mode") == RUNTIME_MODE
                and s["phase"] not in ("reconciling", "completed", "interrupted")
            ]
            if active:
                raise StoreError(f"Reconcile restored runtime attempts first: {active}")
            db.execute(
                "INSERT INTO restore_reconciliations VALUES (?, ?, ?, ?)",
                (event_id, fence_id, datetime.now(UTC).isoformat(), _json(record)),
            )
            db.execute("COMMIT")
            return record
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise

    def record_runtime(self, event_id: str, request: dict) -> dict:
        """Fenced runtime transition in the shared attempt ledger (store v7).

        The caller must persist `dispatch_intent` before any external submission
        and may never submit again for the same attempt. Admission of results uses
        `admit_result`; this API cannot complete an attempt.
        """
        _identifier(event_id)
        if not isinstance(request, dict) or request.get("mode") != RUNTIME_MODE:
            raise StoreError("Expected a runtime request object")
        if request.get("action") == "admit":
            raise StoreError("Results enter only through authenticated admission")
        encoded = _json(request)
        if len(encoded.encode()) > 8192:
            raise StoreError("Runtime request exceeds byte limit")
        request = json.loads(encoded)
        db = self._begin_write()
        try:
            states = self.attempts()
            self._validate_runtime_objects(states)
            existing = self._existing_event(db, event_id, request)
            if existing is not None:
                db.execute("COMMIT")
                return existing
            previous = next(
                (s for s in states if s["attempt_id"] == request.get("attempt_id")), None
            )
            try:
                result = reduce_runtime(previous, request)
            except RuntimeLedgerError as error:
                raise StoreError(str(error)) from error
            action = request["action"]
            if action == "prepare":
                budget = self.budget_snapshot(result["campaign_id"])
                if budget["blocked"]:
                    raise StoreError(
                        "Unresolved attempt, cost, stop or restore fence blocks preparation"
                    )
                if result["max_cost_cents"] > budget["available_cents"]:
                    raise StoreError("Insufficient unreserved budget")
                planned = self.snapshot(result["campaign_id"])
                trial = next(
                    (t for t in planned["trials"] if t["trial_id"] == result["trial_id"]), None
                )
                if trial is None or trial["task_revision"] != result["task_revision"]:
                    raise StoreError("Runtime attempt does not match a planned trial revision")
            elif action == "dispatch_intent":
                if self.unreconciled_restore_fences():
                    raise StoreError("Unreconciled restore fence blocks dispatch")
                if db.execute("SELECT 1 FROM accounting_stops LIMIT 1").fetchone():
                    raise StoreError("Integrity stop blocks dispatch")
            elif action == "seal":
                if self._objects_directory is None:
                    raise StoreError("Sealing requires objects_directory")
                bundle = artifact_objects.read_artifact(
                    self._objects_directory, result["artifact_ref"]
                )
                # Reconcile file and directory durability before committing the reference.
                if (
                    artifact_objects.publish_artifact(self._objects_directory, bundle)
                    != result["artifact_ref"]
                ):
                    raise StoreError("Artifact publication identity mismatch")
            elif action == "verify_intent":
                context = request["challenge"]["context"]
                if context["controller_generation"] != self.controller_generation or context[
                    "artifact_binding_sha256"
                ] != digest(result["artifact_ref"]):
                    raise StoreError("Verification challenge is not bound to this controller")
            self._commit_attempt_event(db, event_id, previous, request, result)
            db.execute("COMMIT")
            return result
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise

    def record_accounting(self, event_id: str, request: dict) -> dict:
        """Atomic offline prepare/interrupt/settle; exact event/receipt repeats are no-ops.

        The trusted caller supplies synthetic accounting observations. This API
        neither authenticates provider receipts nor satisfies live dispatch gates.
        """
        _identifier(event_id)
        if not isinstance(request, dict):
            raise StoreError("Expected an accounting request object")
        encoded_request = _json(request)
        if len(encoded_request) > 4096:
            raise StoreError("Accounting request exceeds byte limit")
        # Detach from caller-owned values before the transaction.
        request = json.loads(encoded_request)
        db = self._begin_write()
        try:
            states = self.attempts()
            duplicates = db.execute(
                "SELECT request_json, state_json FROM attempt_events "
                "WHERE event_id = ? OR receipt_id = ?",
                (event_id, request.get("receipt_id")),
            ).fetchall()
            if duplicates:
                if any(row[0] != encoded_request for row in duplicates):
                    # Retain an integrity stop across restart. Never rewrite the
                    # original event, receipt, reservation or measured charge.
                    db.execute(
                        "INSERT OR IGNORE INTO accounting_stops VALUES (?, 'conflicting_identity')",
                        (event_id,),
                    )
                    db.execute("COMMIT")
                    raise StoreError("Conflicting event or receipt identity")
                result = json.loads(duplicates[0][1])
            else:
                previous = next(
                    (s for s in states if s["attempt_id"] == request.get("attempt_id")), None
                )
                result = _reduce(previous, request)
                if previous is None:
                    budget = self.budget_snapshot(result["campaign_id"])
                    if budget["blocked"]:
                        raise StoreError("Unresolved attempt, cost or overrun blocks preparation")
                    if result["max_cost_cents"] > budget["available_cents"]:
                        raise StoreError("Insufficient unreserved budget")
                    trial = db.execute(
                        "SELECT campaign_id FROM trials WHERE trial_id = ?", (result["trial_id"],)
                    ).fetchone()
                    if trial != (result["campaign_id"],):
                        raise StoreError("Trial is not in the requested campaign")
                    db.execute(
                        "INSERT INTO attempts VALUES (?, ?, ?, ?)",
                        (
                            result["attempt_id"],
                            result["trial_id"],
                            result["campaign_id"],
                            _json(result),
                        ),
                    )
                else:
                    db.execute(
                        "UPDATE attempts SET state_json = ? WHERE attempt_id = ?",
                        (_json(result), result["attempt_id"]),
                    )
                db.execute(
                    "INSERT INTO attempt_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        result["attempt_id"],
                        result["revision"],
                        request.get("receipt_id"),
                        datetime.now(UTC).isoformat(),
                        encoded_request,
                        _json(result),
                    ),
                )
            db.execute("COMMIT")
            return result
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise

    def __enter__(self):
        self._connection()
        return self

    def __exit__(self, *_):
        self.close()
