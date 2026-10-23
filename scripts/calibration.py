"""Metered six-trial development calibration under the store v8 lifecycle (issue #69).

Owner-approved scope (#57, 2026-10-20): at most $10 of model spend for the three
public invoice tasks, each once with GPT-6.1 Sol and GPT-6 Luna, medium reasoning,
no retries or repairs. Each trial is a durable runtime attempt:

prepare -> dispatch intent -> launch Harbor (MeteredTerminus) -> acknowledge ->
broker every model request through the meter -> collect -> seal -> verify intent
-> sealed replay with a fresh verifier -> sign and admit -> settle.

`--dry-run` runs one trial with a scripted model-free provider; it needs Docker
and the Harbor group but no key or network. `--live` spends real money and
refuses unless the dedicated worker host is required and every cap fits.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import harbor_apps
import harbor_spike
import terminus_conformance

from democratize_security import objects
from democratize_security.adapters.runners.report_signer import sign_via_subprocess
from democratize_security.contracts import digest, load_campaign
from democratize_security.model_broker import Broker
from democratize_security.model_budget import (
    TrialLimits,
    load_json,
    trial_reservation_ceiling_cents,
    validate_pricing,
)
from democratize_security.model_meter import Meter
from democratize_security.policy_replay import APP_TRUSTED_FILES, prepare_replay, write_record
from democratize_security.runtime_auth import VerifierSession
from democratize_security.store import PlanStore
from democratize_security.verification.report import PROTOCOL

ROOT = harbor_spike.ROOT
TASKS = ROOT / "tasks/harbor"
OUTPUT = ROOT / ".research/calibration"
DRY_RUN_OUTPUT = ROOT / ".research/calibration-dry-run"
CAMPAIGNS = {
    "sol": ROOT / "campaigns/calibration-sol.v1.json",
    "luna": ROOT / "campaigns/calibration-luna.v1.json",
}
PROPOSAL = ROOT / "campaigns/proposals/calibration.v1.json"
PRICING = ROOT / "campaigns/proposals/pricing.2026-10-17.v1.json"
APPROVED_CENTS = 1000
AGENT = "democratize_security.adapters.runners.metered_terminus:MeteredTerminus"
AGENT_NAME = "metered-terminus"
SOCKET_ENV = "DS_MODEL_BROKER_SOCKET"
TRIAL_DEADLINE = timedelta(minutes=30)
SECRET_PREFIXES = ("OPENAI_", "ANTHROPIC_")
SECRET_SUFFIXES = ("_API_KEY", "_TOKEN")


def task_tree_sha256(path: Path) -> str:
    """Digest of every task file's relative path, bytes and executable bit."""
    entries = []
    for file in sorted(p for p in Path(path).rglob("*") if p.is_file()):
        if "__pycache__" in file.parts:
            continue
        entries.append(
            [
                file.relative_to(path).as_posix(),
                hashlib.sha256(file.read_bytes()).hexdigest(),
                bool(file.stat().st_mode & 0o111),
            ]
        )
    return digest(entries)


def rate_and_limits(campaign: dict):
    rates = validate_pricing(load_json(PRICING))
    rate = rates[(campaign["model"]["provider"], campaign["model"]["identifier"])]
    return rate, TrialLimits(**load_json(PROPOSAL)["limits"])


def _credential(name: str) -> bool:
    return name.startswith(SECRET_PREFIXES) or name.endswith(SECRET_SUFFIXES)


def scrub_credentials() -> None:
    """Drop credential-like variables from this process; every child inherits less."""
    for name in [name for name in os.environ if _credential(name)]:
        del os.environ[name]


def harbor_env(socket_path: Path) -> dict:
    """Host environment for `harbor run`, minus every credential-like variable."""
    env = {name: value for name, value in os.environ.items() if not _credential(name)}
    env[SOCKET_ENV] = str(socket_path)
    return env


def launch_harbor(task, agent, jobs_dir, job_name, env):
    harbor_spike.prepare_storage(jobs_dir, job_name)
    return subprocess.Popen(
        harbor_spike.trial_argv(task, agent, jobs_dir, job_name), cwd=ROOT, env=env
    )


def _source_revision() -> str:
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        revision = ""
    return revision if len(revision) == 40 else "0" * 40


def _event(store, attempt_id, step, action, state, **fields):
    return store.record_runtime(
        f"{attempt_id}-{step}",
        {
            "mode": "runtime",
            "action": action,
            "attempt_id": attempt_id,
            "expected_revision": state["revision"],
            **fields,
        },
    )


def _state(store, attempt_id):
    return next(s for s in store.attempts() if s["attempt_id"] == attempt_id)


def _finish(store, attempt_id, record, reason=None):
    """Interrupt (if still open), settle when every request is known, and summarize."""
    state = _state(store, attempt_id)
    if state["phase"] not in ("completed", "interrupted"):
        state = _event(store, attempt_id, "interrupt", "interrupt", state, reason=reason[:500])
    settled = False
    if state["unknown_requests"] == 0 and state["open_request"] is None:
        state = _event(
            store,
            attempt_id,
            "settle",
            "settle",
            state,
            actual_cost_cents=state["committed_cents"],
            receipt_id=f"{attempt_id}-ledger",
        )
        settled = True
    record.update(
        reason=state["reason"] if state["phase"] == "interrupted" else None,
        requests=state["request_count"],
        input_tokens=state["input_tokens"],
        output_tokens=state["output_tokens"],
        committed_cents=state["committed_cents"],
        unknown_requests=state["unknown_requests"],
        settled=settled,
        stop_batch=not settled,
    )
    if state["phase"] == "interrupted":
        record["outcome"] = "interrupted"
    return record


def attempt_name(model: str, family: str) -> str:
    """Attempt identity; also the job-name stem, so it obeys the worker helper."""
    return re.sub(r"[^a-z0-9_-]", "-", f"cal-{model}-{family}".lower())


def job_names(attempt_id: str) -> tuple[str, str]:
    """Generation and sealed-replay Harbor job names for one attempt."""
    return f"{attempt_id}-gen", f"{attempt_id}-replay"


def run_trial(
    store,
    plan,
    trial,
    provider,
    rate,
    limits,
    *,
    reasoning_effort,
    workdir: Path,
    launch=launch_harbor,
):
    """Run one calibration trial through the full lifecycle; return its summary."""
    family = trial["family"]
    attempt_id = attempt_name(rate.model, family)
    job, replay_job = job_names(attempt_id)
    record = {"attempt_id": attempt_id, "model": rate.model, "family": family, "outcome": None}
    workdir.mkdir(parents=True, exist_ok=True)
    task = workdir / f"{attempt_id}-task"
    terminus_conformance.prepare_terminus_task(TASKS / family, task)
    config = {
        "limits": limits.__dict__,
        "model": rate.model,
        "reasoning_effort": reasoning_effort,
        "pricing_sha256": hashlib.sha256(PRICING.read_bytes()).hexdigest(),
    }
    state = store.record_runtime(
        f"{attempt_id}-prepare",
        {
            "mode": "runtime",
            "action": "prepare",
            "attempt_id": attempt_id,
            "expected_revision": 0,
            "campaign_id": plan["campaign_id"],
            "trial_id": trial["trial_id"],
            "max_cost_cents": trial_reservation_ceiling_cents(rate, limits),
            "basis_sha256": digest(plan),
            "source_revision": _source_revision(),
            "task_revision": trial["task_revision"],
            "verifier_sha256": task_tree_sha256(TASKS / family / "tests"),
            "protocol": PROTOCOL,
            "config_sha256": digest(config),
        },
    )
    deadline = datetime.now(UTC) + TRIAL_DEADLINE
    state = _event(
        store,
        attempt_id,
        "dispatch",
        "dispatch_intent",
        state,
        runner_request_id=job,
        dispatch_deadline=deadline.isoformat(),
    )
    meter = Meter(store, attempt_id, rate, limits, provider, reasoning_effort=reasoning_effort)
    # AF_UNIX paths are short; a private mkdtemp directory keeps this one bounded.
    socket_root = Path(tempfile.mkdtemp(prefix="ds-broker-"))
    broker = Broker(meter, socket_root / "broker" / "model.sock")
    nonce = secrets.token_hex(32)
    try:
        env = {**harbor_env(broker.socket_path), harbor_spike.NONCE: nonce}
        try:
            process = launch(task, AGENT, workdir, job, env)
        except Exception as error:
            return _finish(store, attempt_id, record, f"launch_failed: {type(error).__name__}")
        state = _event(
            store,
            attempt_id,
            "acknowledge",
            "acknowledge",
            state,
            runner_request_id=job,
            worker_id=f"harbor:{job}",
        )
        outcome = broker.serve(process, deadline=time.monotonic() + TRIAL_DEADLINE.total_seconds())
    finally:
        broker.close()
        shutil.rmtree(socket_root)
    if outcome != "exited":
        return _finish(store, attempt_id, record, f"transport_{outcome}")
    try:
        evidence, bundle = harbor_spike.accept_trial(
            workdir / job,
            AGENT_NAME,
            None,
            nonce,
            evidence="app-evidence.json",
            artifact="app.py",
            keys=harbor_apps.EVIDENCE_KEYS,
        )
        record["generation_outcome"] = evidence["outcome"]
        reference = objects.publish_artifact(store._objects_directory, bundle)
        result = sorted((workdir / job).glob("*/result.json"))[0].read_bytes()
    except Exception as error:
        return _finish(store, attempt_id, record, f"collection_failed: {error}")
    state = _state(store, attempt_id)
    state = _event(
        store,
        attempt_id,
        "seal",
        "seal",
        state,
        runner_request_id=job,
        worker_id=f"harbor:{job}",
        stop_observation_sha256=digest(
            {"returncode": process.returncode, "result_sha256": hashlib.sha256(result).hexdigest()}
        ),
        artifact_ref=reference,
    )
    try:
        verification_id = f"{attempt_id}-verify"
        session = VerifierSession(
            store.runtime_context(
                attempt_id, verification_id, expected_revision=state["revision"] + 1
            )
        )
        state = _event(
            store,
            attempt_id,
            "verify-intent",
            "verify_intent",
            state,
            verification_request_id=verification_id,
            challenge=session.public_challenge(),
        )
        replay = workdir / f"{attempt_id}-replay-task"
        prepare_replay(
            bundle,
            TASKS / family,
            replay,
            artifact="app.py",
            max_bytes=harbor_apps.MAX_APP_BYTES,
            trusted_files=APP_TRUSTED_FILES,
        )
        replay_nonce = harbor_spike.run_trial(replay, "nop", workdir, replay_job)
        replayed, _ = harbor_spike.accept_trial(
            workdir / replay_job,
            "nop",
            None,
            replay_nonce,
            evidence="app-evidence.json",
            artifact="app.py",
            keys=harbor_apps.EVIDENCE_KEYS,
            expected_bundle=bundle,
        )
        raw = sign_via_subprocess(session.public_challenge(), session.verifier_nonce(), replayed)
        admitted = store.admit_result(
            f"{attempt_id}-admit", attempt_id, state["revision"], session, raw
        )
    except Exception as error:
        return _finish(store, attempt_id, record, f"verification_failed: {type(error).__name__}")
    record.update(outcome=admitted["outcome"], coverage=admitted["coverage"])
    return _finish(store, attempt_id, record)


def write_summary(path: Path, trials: list[dict], *, mode: str) -> None:
    summary = {
        "schema_version": 1,
        "scope": "metered_development_calibration",
        "mode": mode,
        "approved_cap_cents": APPROVED_CENTS,
        "security_verdict": "not_evaluated",
        "trials": trials,
    }
    write_record(path, summary)


def dry_run() -> list[dict]:
    from democratize_security.adapters.runners.terminus_conformance import (
        COMPLETE,
        reference_response,
    )
    from democratize_security.model_meter import ScriptedProvider

    DRY_RUN_OUTPUT.mkdir(parents=True, exist_ok=False)
    ledger, objects_dir = DRY_RUN_OUTPUT / "ledger", DRY_RUN_OUTPUT / "objects"
    ledger.mkdir()
    objects_dir.mkdir()
    campaign = load_campaign(CAMPAIGNS["sol"])
    rate, limits = rate_and_limits(campaign)
    provider = ScriptedProvider((reference_response(), COMPLETE, COMPLETE))
    with PlanStore(ledger, objects_directory=objects_dir) as store:
        plan = store.import_campaign(campaign)
        record = run_trial(
            store,
            plan,
            plan["trials"][0],
            provider,
            rate,
            limits,
            reasoning_effort="medium",
            workdir=DRY_RUN_OUTPUT,
        )
    write_summary(DRY_RUN_OUTPUT / "summary.json", [record], mode="dry-run")
    print(json.dumps(record, indent=2, sort_keys=True))
    if (record["outcome"], record.get("coverage"), record["settled"]) != ("pass", "complete", True):
        raise SystemExit("dry run did not admit a complete passing result")
    if not record["committed_cents"] > 0:
        raise SystemExit("dry run committed no metered cost")
    return [record]


def live(key_file: Path, ledger: Path) -> list[dict]:
    if os.environ.get("DS_WORKER_HOST_REQUIRED") != "1":
        raise SystemExit("live calibration requires DS_WORKER_HOST_REQUIRED=1")
    # The key comes only from --key-file; the replay Harbor run inherits os.environ.
    scrub_credentials()
    campaigns = {name: load_campaign(path) for name, path in CAMPAIGNS.items()}
    if sum(c["limits"]["max_cost_usd_cents"] for c in campaigns.values()) > APPROVED_CENTS:
        raise SystemExit("campaign caps exceed the approved budget")
    for campaign in campaigns.values():
        for task in campaign["tasks"]:
            if task["revision"] != task_tree_sha256(TASKS / task["family"]):
                raise SystemExit(f"task {task['family']} changed since the campaign was frozen")
    if subprocess.run(
        ["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip():
        raise SystemExit("live calibration requires a clean checkout")
    # Imported only after every refusal check: httpx is not a core dependency.
    from democratize_security.adapters.providers.openai_responses import (
        OpenAIResponsesProvider,
        load_key,
    )

    provider = OpenAIResponsesProvider(load_key(key_file))
    OUTPUT.mkdir(parents=True, exist_ok=True)
    objects_dir = ledger.parent / "objects"
    objects_dir.mkdir(exist_ok=True)
    records = []
    with PlanStore(ledger, objects_directory=objects_dir) as store:
        for name, campaign in campaigns.items():
            plan = store.import_campaign(campaign)
            if store.budget_snapshot(plan["campaign_id"])["blocked"]:
                raise SystemExit(f"{name} budget is blocked; reconcile before running")
            rate, limits = rate_and_limits(campaign)
            for trial in plan["trials"]:
                done = [s for s in store.attempts() if s["trial_id"] == trial["trial_id"]]
                if done:
                    print(f"skipping {trial['trial_id']}: attempt already recorded")
                    continue
                record = run_trial(
                    store,
                    plan,
                    trial,
                    provider,
                    rate,
                    limits,
                    reasoning_effort=campaign["model"]["settings"]["reasoning_effort"],
                    workdir=OUTPUT,
                )
                records.append(record)
                print(json.dumps(record, sort_keys=True))
                if record["stop_batch"]:
                    write_summary(OUTPUT / f"summary-{int(time.time())}.json", records, mode="live")
                    raise SystemExit("unknown request outcome: batch stopped, holds retained")
    write_summary(OUTPUT / f"summary-{int(time.time())}.json", records, mode="live")
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
