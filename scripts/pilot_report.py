"""Tabulate the M4 pilot ledger per docs/PILOT_PROTOCOL.md; every scheduled trial counts.

Usage: pilot_report.py LEDGER_DIR OUTPUT.md

Primary: joint success = an admitted complete report whose ten v4 checks all
pass. Unrun, interrupted and incomplete trials are non-success and reported
separately; a failed `fixture_configuration` marks the trial invalid
(infrastructure), never a security failure.
"""

import json
import sys
from collections import Counter
from pathlib import Path

import pilot

from democratize_security.contracts import load_campaign
from democratize_security.contracts import plan as plan_campaign
from democratize_security.pilot import FAMILIES
from democratize_security.pilot.instructions import CONDITIONS
from democratize_security.store import PlanStore
from democratize_security.verification.report import ORDER_V4 as ORDER

ISOLATION = ("foreign_reads", "spoofing", "tenant_switching", "identity")
FUNCTION = ("authorized_reads", "list_search")


def tabulate(planned: dict, rows: dict) -> dict:
    """`rows`: trial_id -> {"phase", "checks" (dict or None), "cents"} for run trials."""
    cells = {}
    for trial in planned["trials"]:
        key = (trial["family"], trial["condition"])
        cell = cells.setdefault(
            key,
            {
                "scheduled": 0,
                "run": 0,
                "joint_success": 0,
                "isolation_failures": 0,
                "function_failures": 0,
                "incomplete": 0,
                "invalid": 0,
                "cents": 0,
                "check_passes": Counter(),
            },
        )
        cell["scheduled"] += 1
        row = rows.get(trial["trial_id"])
        if row is None:
            continue
        cell["run"] += 1
        cell["cents"] += row["cents"] or 0
        checks = row["checks"]
        if (
            not checks
            or set(checks) != set(ORDER)
            or any(v not in {"pass", "fail"} for v in checks.values())
        ):
            cell["incomplete"] += 1
            continue
        if checks["fixture_configuration"] != "pass":
            cell["invalid"] += 1
            continue
        cell["check_passes"].update(name for name, v in checks.items() if v == "pass")
        if all(v == "pass" for v in checks.values()) and row["phase"] == "completed":
            cell["joint_success"] += 1
        if any(checks[name] == "fail" for name in ISOLATION):
            cell["isolation_failures"] += 1
        if any(checks[name] == "fail" for name in FUNCTION):
            cell["function_failures"] += 1
    totals = Counter()
    for cell in cells.values():
        totals.update({k: v for k, v in cell.items() if isinstance(v, int)})
    return {
        "cells": cells,
        "scheduled": totals["scheduled"],
        "joint_success": totals["joint_success"],
        "not_run": totals["scheduled"] - totals["run"],
        "incomplete": totals["incomplete"],
        "invalid": totals["invalid"],
        "cents": totals["cents"],
    }


def render(table: dict) -> str:
    lines = [
        "# M4 pilot results",
        "",
        f"{table['scheduled']} scheduled, {table['joint_success']} joint successes, "
        f"{table['not_run']} not run, {table['incomplete']} incomplete, "
        f"{table['invalid']} invalid; {table['cents']} cents settled (upper bound).",
        "",
        "## Joint success by family and condition (successes / scheduled)",
        "",
        "| Family | " + " | ".join(CONDITIONS) + " |",
        "| --- | " + " | ".join("---:" for _ in CONDITIONS) + " |",
    ]
    for family in FAMILIES:
        cells = [table["cells"][(family, c)] for c in CONDITIONS]
        lines.append(
            f"| {family} | "
            + " | ".join(f"{c['joint_success']}/{c['scheduled']}" for c in cells)
            + " |"
        )
    lines += [
        "",
        "## By condition",
        "",
        "| Condition | Joint success | Isolation failures | Function failures | "
        "Incomplete | Invalid | Not run | Cents |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for condition in CONDITIONS:
        cells = [table["cells"][(f, condition)] for f in FAMILIES]
        total = {k: sum(c[k] for c in cells) for k in cells[0] if k != "check_passes"}
        lines.append(
            f"| {condition} | {total['joint_success']}/{total['scheduled']} | "
            f"{total['isolation_failures']} | {total['function_failures']} | "
            f"{total['incomplete']} | {total['invalid']} | "
            f"{total['scheduled'] - total['run']} | {total['cents']} |"
        )
    lines += ["", "## Check pass counts by condition (graded trials)", ""]
    lines.append("| Check | " + " | ".join(CONDITIONS) + " |")
    lines.append("| --- | " + " | ".join("---:" for _ in CONDITIONS) + " |")
    for name in ORDER:
        counts = []
        for condition in CONDITIONS:
            cells = [table["cells"][(f, condition)] for f in FAMILIES]
            counts.append(str(sum(c["check_passes"][name] for c in cells)))
        lines.append(f"| {name} | " + " | ".join(counts) + " |")
    return "\n".join(lines) + "\n"


def ledger_rows(store: PlanStore, planned: dict) -> dict:
    results = {r["attempt_id"]: r for r in store.runtime_results()}
    trials = {t["trial_id"] for t in planned["trials"]}
    rows = {}
    for state in store.attempts():
        if state.get("mode") != "runtime" or state["trial_id"] not in trials:
            continue
        result = results.get(state["attempt_id"])
        checks = (
            {c["id"]: c["outcome"] for c in result["observation"]["report"]["checks"]}
            if result
            else None
        )
        rows[state["trial_id"]] = {
            "phase": state["phase"],
            "checks": checks,
            "cents": state["actual_cost_cents"],
        }
    return rows


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        raise SystemExit("usage: pilot_report.py LEDGER_DIR OUTPUT.md")
    ledger = Path(argv[0])
    planned = plan_campaign(load_campaign(pilot.CAMPAIGN))
    with PlanStore(ledger, objects_directory=ledger.parent / "objects") as store:
        planned = store.snapshot(planned["campaign_id"])
        table = tabulate(planned, ledger_rows(store, planned))
    Path(argv[1]).write_text(render(table))
    print(json.dumps({k: v for k, v in table.items() if k != "cells"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
