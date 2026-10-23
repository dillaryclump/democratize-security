"""The owner-approved 48-trial M4 pilot (#57): 6 families x 4 conditions x 2 repetitions.

The frozen campaign is `campaigns/pilot.v1.json` (gpt-6.1-sol, medium reasoning,
1500-cent hard cap) and the pre-registered analysis is `docs/PILOT_PROTOCOL.md`.
Each trial is one metered v8 runtime attempt through `calibration.run_trial` on
its generated variant in `tasks/pilot/`, graded by protocol v4 on a sealed
replay and admitted only through authenticated signing. Trials run one at a
time in a seeded, repetition-balanced order; the batch stops at the first
unknown request outcome or integrity error, or when less than one trial hold
remains under the cap.

`--dry-run`: one full_tool invoice-read trial with a scripted model-free
provider (Docker, no key or network). `--live`: real spending, dedicated worker
only, after the pilot controls passed on this exact commit.
"""

import argparse
import base64
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

import build_pilot_tasks
import calibration

from democratize_security.contracts import digest, load_campaign
from democratize_security.model_budget import (
    TrialLimits,
    load_json,
    trial_reservation_ceiling_cents,
    validate_pricing,
)
from democratize_security.pilot import FAMILIES, HERE
from democratize_security.pilot.instructions import CONDITIONS
from democratize_security.policy_replay import APP_TRUSTED_FILES, write_record
from democratize_security.store import PlanStore
from democratize_security.verification.report import PROTOCOL_V4

ROOT = calibration.ROOT
CAMPAIGN = ROOT / "campaigns/pilot.v1.json"
LIMITS = ROOT / "campaigns/proposals/pilot-limits.v1.json"
PRICING = calibration.PRICING
OUTPUT = ROOT / ".research/pilot"
DRY_RUN_OUTPUT = ROOT / ".research/pilot-dry-run"
CONTROLS_OUTPUT = ROOT / ".research/pilot-controls"
APPROVED_CENTS = 1500
# Sealed replays must carry the variant's fixture selection.
TRUSTED_FILES = (*APP_TRUSTED_FILES, "tests/variant.json")


def rate_and_limits(campaign: dict):
    rates = validate_pricing(load_json(PRICING))
    rate = rates[(campaign["model"]["provider"], campaign["model"]["identifier"])]
    return rate, TrialLimits(**load_json(LIMITS))


def family_revision(family: str) -> str:
    """One campaign revision per family: the four condition variant trees."""
    return digest(
        [
            calibration.task_tree_sha256(build_pilot_tasks.variant_dir(family, condition))
            for condition in CONDITIONS
        ]
    )


def variant_for(trial: dict) -> Path:
    return build_pilot_tasks.variant_dir(trial["family"], trial["condition"])


def attempt_name(family: str, condition: str, repetition: int) -> str:
    return f"pilot-{family}-{condition.replace('_', '-')}-r{repetition + 1}"


def trial_order(plan: dict, seed: int) -> list[dict]:
    """Shuffle within each repetition block with one seeded generator."""
    generator = random.Random(seed)
    ordered = []
    for repetition in sorted({t["repetition"] for t in plan["trials"]}):
        block = [t for t in plan["trials"] if t["repetition"] == repetition]
        generator.shuffle(block)
        ordered.extend(block)
    return ordered


def require_control_evidence(revision: str) -> None:
    """Every family's model-free controls must have passed on this commit."""
    for family in FAMILIES:
        path = CONTROLS_OUTPUT / family / "summary.json"
        try:
            summary = json.loads(path.read_text())
        except (OSError, ValueError):
            raise SystemExit(f"missing pilot control evidence for {family}") from None
        if (
            summary.get("family") != family
            or summary.get("protocol") != PROTOCOL_V4
            or summary.get("source_revision") != revision
            or summary.get("model_calls") != 0
            or not summary.get("audits")
            or any(a.get("outcome") != "pass" for a in summary["audits"])
        ):
            raise SystemExit(f"pilot control evidence for {family} does not cover {revision}")


def install_response(app: bytes) -> list[str]:
    """Scripted Terminus2 turns that write `app` in chunks, then confirm twice."""
    encoded = base64.b64encode(app).decode()
    chunks = [encoded[i : i + 3000] for i in range(0, len(encoded), 3000)]
    commands = [{"keystrokes": "rm -f /tmp/app.b64\n", "duration": 0.5}]
    commands += [
        {"keystrokes": f"printf '%s' '{chunk}' >> /tmp/app.b64\n", "duration": 0.5}
        for chunk in chunks
    ]
    commands.append({"keystrokes": "base64 -d /tmp/app.b64 > /candidate/app.py\n", "duration": 1.0})
    install = json.dumps(
        {
            "analysis": "Scripted dry run: install the reviewed reference app.",
            "plan": "Decode the fixed reference bytes into the candidate path.",
            "commands": commands,
            "task_complete": False,
        }
    )
    complete = json.dumps(
        {"analysis": "done", "plan": "confirm", "commands": [], "task_complete": True}
    )
    return [install, complete, complete]


def run(store, plan, provider, rate, limits, *, effort, workdir, trials, stop_below=None):
    records = []
    for trial in trials:
        if stop_below is not None:
            budget = store.budget_snapshot(plan["campaign_id"])
            if budget["blocked"] or budget["available_cents"] < stop_below:
                print("stopping: less than one trial hold remains or budget is blocked")
                break
        attempt = attempt_name(trial["family"], trial["condition"], trial["repetition"])
        if any(s["attempt_id"] == attempt for s in store.attempts()):
            print(f"skipping {attempt}: attempt already recorded")
            continue
        record = calibration.run_trial(
            store,
            plan,
            trial,
            provider,
            rate,
            limits,
            reasoning_effort=effort,
            workdir=workdir,
            task_source=variant_for(trial),
            attempt_id=attempt,
            protocol=PROTOCOL_V4,
            trusted_files=TRUSTED_FILES,
        )
        record.update(condition=trial["condition"], repetition=trial["repetition"])
        records.append(record)
        print(json.dumps(record, sort_keys=True), flush=True)
        if record["stop_batch"]:
            print("unknown request outcome: batch stopped, holds retained")
            break
    return records


def summary(path: Path, records: list[dict], mode: str) -> None:
    write_record(
        path,
        {
            "schema_version": 1,
            "scope": "m4_pilot",
            "mode": mode,
            "approved_cap_cents": APPROVED_CENTS,
            "security_verdict": "not_evaluated",
            "trials": records,
        },
    )


def dry_run() -> list[dict]:
    from democratize_security.model_meter import ScriptedProvider

    DRY_RUN_OUTPUT.mkdir(parents=True, exist_ok=False)
    ledger, objects_dir = DRY_RUN_OUTPUT / "ledger", DRY_RUN_OUTPUT / "objects"
    ledger.mkdir()
    objects_dir.mkdir()
    campaign = load_campaign(CAMPAIGN)
    rate, limits = rate_and_limits(campaign)
    provider = ScriptedProvider(
        tuple(install_response((HERE / "reference_protected.py").read_bytes()))
    )
    with PlanStore(ledger, objects_directory=objects_dir) as store:
        plan = store.import_campaign(campaign)
        trial = next(
            t
            for t in plan["trials"]
            if (t["family"], t["condition"], t["repetition"]) == ("invoice-read", "full_tool", 0)
        )
        records = run(
            store,
            plan,
            provider,
            rate,
            limits,
            effort="medium",
            workdir=DRY_RUN_OUTPUT,
            trials=[trial],
        )
    summary(DRY_RUN_OUTPUT / "summary.json", records, "dry-run")
    (record,) = records
    if (record["outcome"], record.get("coverage"), record["settled"]) != ("pass", "complete", True):
        raise SystemExit("dry run did not admit a complete passing v4 result")
    return records


def live(key_file: Path, ledger: Path) -> list[dict]:
    if os.environ.get("DS_WORKER_HOST_REQUIRED") != "1":
        raise SystemExit("live pilot requires DS_WORKER_HOST_REQUIRED=1")
    campaign = load_campaign(CAMPAIGN)
    if campaign["limits"]["max_cost_usd_cents"] != APPROVED_CENTS:
        raise SystemExit("campaign cap differs from the approved 1500 cents")
    for task in campaign["tasks"]:
        if task["revision"] != family_revision(task["family"]):
            raise SystemExit(f"{task['family']} variants changed since the campaign was frozen")
    if subprocess.run(
        ["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip():
        raise SystemExit("live pilot requires a clean checkout")
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    require_control_evidence(revision)
    calibration.scrub_credentials()
    from democratize_security.adapters.providers.openai_responses import (
        OpenAIResponsesProvider,
        load_key,
    )

    provider = OpenAIResponsesProvider(load_key(key_file))
    rate, limits = rate_and_limits(campaign)
    hold = trial_reservation_ceiling_cents(rate, limits)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    objects_dir = ledger.parent / "objects"
    objects_dir.mkdir(exist_ok=True)
    with PlanStore(ledger, objects_directory=objects_dir) as store:
        plan = store.import_campaign(campaign)
        if store.budget_snapshot(plan["campaign_id"])["blocked"]:
            raise SystemExit("pilot budget is blocked; reconcile before running")
        order = trial_order(plan, campaign["model"]["settings"]["order_seed"])
        records = run(
            store,
            plan,
            provider,
            rate,
            limits,
            effort=campaign["model"]["settings"]["reasoning_effort"],
            workdir=OUTPUT,
            trials=order,
            stop_below=hold,
        )
    summary(OUTPUT / f"summary-{int(time.time())}.json", records, "live")
    return records


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--ledger", type=Path)
    args = parser.parse_args(argv)
    if args.dry_run:
        return dry_run()
    if args.key_file is None or args.ledger is None:
        raise SystemExit("--live needs --key-file and --ledger")
    return live(args.key_file, args.ledger)


if __name__ == "__main__":
    from importlib.metadata import version

    if version("harbor") != "0.24.0":
        raise ValueError("unreviewed Harbor version")
    main(sys.argv[1:])
