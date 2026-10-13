"""Strict v1 campaign inputs and deterministic, offline trial planning.

These contracts describe intent. Validation does not authorize spending or
establish runtime isolation, benchmark compatibility, or security effectiveness.
"""

import hashlib
import json
import re
from itertools import product
from pathlib import Path
from typing import Any

CONDITIONS = ("ordinary", "instructions", "rls_starter", "full_tool")
SPLITS = ("development", "selection", "final")


class ContractError(ValueError):
    """An input cannot be used to produce a valid plan."""


def digest(value: Any) -> str:
    """Stable identity independent of JSON formatting and dictionary ordering."""
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode()).hexdigest()


def _object(value: Any, fields: set[str], where: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise ContractError(f"{where}: expected exactly these fields: {sorted(fields)}")


def _text(value: Any, where: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{where}: expected nonempty text")


def _integer(value: Any, minimum: int, maximum: int, where: str) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError(f"{where}: expected integer from {minimum} to {maximum}")


def validate(campaign: Any) -> dict:
    _object(
        campaign,
        {
            "schema_version",
            "name",
            "hypothesis",
            "source_revision",
            "scoring_version",
            "model",
            "conditions",
            "repetitions",
            "tasks",
            "limits",
            "stopping_rule",
        },
        "campaign",
    )
    if type(campaign["schema_version"]) is not int or campaign["schema_version"] != 1:
        raise ContractError("schema_version: only integer 1 is supported")
    for key in ("name", "hypothesis", "source_revision", "scoring_version", "stopping_rule"):
        _text(campaign[key], key)
    if not re.fullmatch(r"[0-9a-f]{40}", campaign["source_revision"]):
        raise ContractError("source_revision: expected a full lowercase Git commit SHA")
    _object(campaign["model"], {"provider", "identifier", "settings"}, "model")
    for key in ("provider", "identifier"):
        _text(campaign["model"][key], f"model.{key}")
    if not isinstance(campaign["model"]["settings"], dict):
        raise ContractError("model.settings: expected an object")
    conditions = campaign["conditions"]
    if not isinstance(conditions, list) or not conditions:
        raise ContractError("conditions: expected nonempty list")
    if any(not isinstance(c, str) or c not in CONDITIONS for c in conditions):
        raise ContractError(f"conditions: supported values are {CONDITIONS}")
    if len(set(conditions)) != len(conditions):
        raise ContractError("conditions: duplicates are not allowed")
    _integer(campaign["repetitions"], 1, 100, "repetitions")
    limits = campaign["limits"]
    _object(
        limits,
        {
            "max_trials",
            "max_cost_usd_cents",
            "timeout_seconds",
            "infrastructure_retries",
            "repair_attempts",
            "concurrency",
        },
        "limits",
    )
    for key, minimum, maximum in (
        ("max_trials", 1, 10000),
        ("max_cost_usd_cents", 0, 1000000),
        ("timeout_seconds", 1, 86400),
        ("infrastructure_retries", 0, 1),
        ("repair_attempts", 0, 10),
        ("concurrency", 1, 1),
    ):
        _integer(limits[key], minimum, maximum, f"limits.{key}")
    tasks = campaign["tasks"]
    if not isinstance(tasks, list) or not tasks:
        raise ContractError("tasks: expected nonempty list")
    ids: set[str] = set()
    families: dict[str, str] = {}
    for task in tasks:
        _object(task, {"id", "family", "split", "revision"}, "task")
        for key in task:
            _text(task[key], f"task.{key}")
        if task["split"] not in SPLITS:
            raise ContractError(f"task.split: supported values are {SPLITS}")
        if task["id"] in ids:
            raise ContractError("tasks: duplicate task ID")
        ids.add(task["id"])
        previous = families.setdefault(task["family"], task["split"])
        if previous != task["split"]:
            raise ContractError("tasks: a scenario family cannot cross splits")
        if not re.fullmatch(r"[0-9a-f]{64}", task["revision"]):
            raise ContractError("task.revision: expected SHA-256 task-manifest digest")
    count = len(tasks) * len(conditions) * campaign["repetitions"]
    if count > limits["max_trials"]:
        raise ContractError(f"planned {count} trials exceeds max_trials")
    try:
        digest(campaign)
    except (ValueError, TypeError) as error:
        raise ContractError(f"campaign must contain finite JSON values: {error}") from error
    return campaign


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_campaign(path: Path) -> dict:
    return validate(json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs))


def plan(campaign: dict) -> dict:
    validate(campaign)
    campaign_id = digest(campaign)
    trials = []
    for task, condition, repetition in product(
        campaign["tasks"], campaign["conditions"], range(campaign["repetitions"])
    ):
        identity = {
            "campaign_id": campaign_id,
            "task_id": task["id"],
            "family": task["family"],
            "split": task["split"],
            "task_revision": task["revision"],
            "condition": condition,
            "repetition": repetition,
        }
        trials.append({"trial_id": digest(identity), **identity, "status": "planned"})
    return {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "execution_enabled": False,
        "campaign": campaign,
        "trials": trials,
    }
