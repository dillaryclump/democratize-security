"""Durable per-request metering (issue #69); fake providers only, no network."""

import json
from fractions import Fraction
from pathlib import Path

import pytest
from test_runtime_store import ACK, DISPATCH, runtime

from democratize_security import artifacts, objects
from democratize_security.model_budget import (
    TrialLimits,
    Usage,
    ceiling_cents,
    load_json,
    validate_pricing,
)
from democratize_security.model_meter import (
    Meter,
    MeterRefused,
    ProviderError,
    ProviderResult,
    ScriptedProvider,
)
from democratize_security.store import PlanStore

ROOT = Path(__file__).resolve().parents[1]
RATES = validate_pricing(load_json(ROOT / "campaigns/proposals/pricing.2026-10-17.v1.json"))
SOL = RATES[("openai", "gpt-6.1-sol")]
LIMITS = TrialLimits(**load_json(ROOT / "campaigns/proposals/calibration.v1.json")["limits"])
MESSAGES = [{"role": "user", "content": "Write the app."}]


@pytest.fixture
def case(tmp_path):
    ledger, artifact_dir, source = (tmp_path / n for n in ("ledger", "artifacts", "source"))
    for path in (ledger, artifact_dir, source):
        path.mkdir()
    (source / "app.py").write_text("print('synthetic')\n")
    objects.publish_artifact(artifact_dir, artifacts.seal(source, ["app.py"]))
    campaign = json.loads((ROOT / "campaigns/development.example.json").read_text())
    campaign["limits"]["max_cost_usd_cents"] = 1000
    with PlanStore(ledger, objects_directory=artifact_dir) as store:
        plan = store.import_campaign(campaign)
    return {"ledger": ledger, "artifact_dir": artifact_dir, "plan": plan}


def running(case, store, max_cost_cents=236):
    trial = case["plan"]["trials"][0]
    store.record_runtime(
        "prep",
        runtime(
            "prepare",
            0,
            campaign_id=case["plan"]["campaign_id"],
            trial_id=trial["trial_id"],
            max_cost_cents=max_cost_cents,
            basis_sha256="a" * 64,
            source_revision="d" * 40,
            task_revision=trial["task_revision"],
            verifier_sha256="f" * 64,
            protocol="synthetic-reference-v3",
            config_sha256="1" * 64,
        ),
    )
    store.record_runtime("dispatch", DISPATCH)
    store.record_runtime("ack", ACK)


def open_store(case):
    return PlanStore(case["ledger"], objects_directory=case["artifact_dir"])


def meter(store, provider, rate=SOL):
    return Meter(store, "r1", rate, LIMITS, provider, reasoning_effort="medium")


def attempt(store):
    (state,) = store.attempts()
    return state


class Recording(ScriptedProvider):
    """Scripted provider that records what the ledger held at send time."""

    def __init__(self, store, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.store = store
        self.seen = []

    def create(self, payload):
        self.seen.append(attempt(self.store)["open_request"])
        return super().create(payload)


class Failing(ScriptedProvider):
    def __init__(self, error=None, result=None):
        super().__init__(("unused",))
        self.error, self.result, self.sent = error, result, 0

    def create(self, payload):
        self.sent += 1
        if self.error:
            raise self.error
        return self.result


def test_generate_reserves_before_send(case):
    with open_store(case) as store:
        running(case, store)
        provider = Recording(store, ("hello",))
        assert meter(store, provider).generate(MESSAGES) == "hello"
        (held,) = provider.seen
        assert held["request_id"] == "r1-req-01"
        assert held["preflight_input_tokens"] == 1000
        assert held["max_output_tokens"] == 25000
        state = attempt(store)
        assert state["open_request"] is None
        assert (state["request_count"], state["input_tokens"], state["output_tokens"]) == (
            1,
            1000,
            200,
        )


def test_payload_is_complete_and_stateless(case):
    with open_store(case) as store:
        running(case, store)
        provider = Recording(store, ("hello",))
        meter(store, provider).generate(MESSAGES)
        (payload,) = provider.payloads
        assert payload == {
            "model": "gpt-6.1-sol",
            "input": MESSAGES,
            "reasoning": {"effort": "medium"},
            "max_output_tokens": 25000,
            "store": False,
        }


def test_settlement_is_upper_bound_cost(case):
    with open_store(case) as store:
        running(case, store)
        meter(store, ScriptedProvider(("hello",))).generate(MESSAGES)
        expected = ceiling_cents(Fraction(1000 * 2500000 + 200 * 10000000, 10**12))
        assert expected == 1
        assert attempt(store)["committed_cents"] == expected


def test_preflight_over_cap_refuses_without_intent(case):
    with open_store(case) as store:
        running(case, store)
        provider = Failing(result=None)
        provider.input_tokens = 64001
        before = attempt(store)
        with pytest.raises(MeterRefused):
            meter(store, provider).generate(MESSAGES)
        assert attempt(store) == before
        assert provider.sent == 0


def test_send_failure_after_intent_records_unknown_and_latches(case):
    with open_store(case) as store:
        running(case, store)
        provider = Failing(error=TimeoutError("read timed out"))
        metered = meter(store, provider)
        with pytest.raises(ProviderError):
            metered.generate(MESSAGES)
        state = attempt(store)
        assert (state["unknown_requests"], state["open_request"]) == (1, None)
        # The worst-case reservation stays held: 1000 * $2.50/M + 25000 * $10/M, rounded up.
        assert state["committed_cents"] == 26
        assert (state["input_tokens"], state["output_tokens"]) == (1000, 25000)
        assert metered.latched
        with pytest.raises(MeterRefused):
            metered.generate(MESSAGES)
        assert provider.sent == 1


@pytest.mark.parametrize(
    "change",
    [
        {"status": "incomplete"},
        {"usage": None},
        {"model": "gpt-6-luna"},
        {"usage": Usage(1000, 0, 0, 25001)},
        {"usage": Usage(1001, 0, 0, 10)},
    ],
)
def test_incomplete_or_invalid_result_is_unknown(case, change):
    fields = {
        "content": "x",
        "status": "completed",
        "model": "gpt-6.1-sol-2026-10-01",
        "usage": Usage(1000, 0, 0, 10),
        "response_sha256": "6" * 64,
        **change,
    }
    with open_store(case) as store:
        running(case, store)
        provider = Failing(result=ProviderResult(**fields))
        with pytest.raises(ProviderError):
            meter(store, provider).generate(MESSAGES)
        assert attempt(store)["unknown_requests"] == 1


def test_valid_dated_model_snapshot_is_accepted(case):
    result = ProviderResult(
        "ok", "completed", "gpt-6.1-sol-2026-10-01", Usage(10, 0, 0, 1), "6" * 64
    )
    with open_store(case) as store:
        running(case, store)
        assert meter(store, Failing(result=result)).generate(MESSAGES) == "ok"


def test_twelfth_request_allowed_thirteenth_refused(case):
    with open_store(case) as store:
        running(case, store)
        provider = ScriptedProvider(("ok",) * 13, input_tokens=100, output_tokens=10)
        metered = meter(store, provider)
        for _ in range(12):
            metered.generate(MESSAGES)
        with pytest.raises(MeterRefused, match="request limit"):
            metered.generate(MESSAGES)
        assert attempt(store)["request_count"] == 12
        assert provider.sent == 12


def test_remaining_budget_refuses_quote(case):
    with open_store(case) as store:
        running(case, store, max_cost_cents=1)
        provider = ScriptedProvider(("ok",))
        with pytest.raises(MeterRefused, match="budget"):
            meter(store, provider).generate(MESSAGES)
        assert attempt(store)["request_count"] == 0
        assert provider.sent == 0


def test_requires_running_runtime_attempt(case):
    with open_store(case) as store:
        with pytest.raises(MeterRefused):
            meter(store, ScriptedProvider(("ok",))).generate(MESSAGES)


@pytest.mark.parametrize(
    "messages",
    [
        [],
        [{"role": "tool", "content": "x"}],
        [{"role": "user", "content": 3}],
        [{"role": "user", "content": "x", "extra": 1}],
        [{"role": "user", "content": "x"}] * 513,
        "not a list",
    ],
)
def test_malformed_messages_refused_before_preflight(case, messages):
    with open_store(case) as store:
        running(case, store)
        provider = ScriptedProvider(("ok",))
        with pytest.raises(MeterRefused):
            meter(store, provider).generate(messages)
        assert provider.counted == 0
