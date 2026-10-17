import copy
import json
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import pytest

from democratize_security.contracts import ContractError, digest
from democratize_security.model_budget import (
    TrialLimits,
    Usage,
    actual_cost,
    ceiling_cents,
    estimate_proposal,
    load_json,
    main,
    quote_next_request,
    trial_ceiling,
    trial_reservation_ceiling_cents,
    validate_pricing,
)

ROOT = Path(__file__).resolve().parents[1]
PRICING = ROOT / "campaigns/proposals/pricing.2026-10-17.v1.json"
PROPOSAL = ROOT / "campaigns/proposals/calibration.v1.json"


@pytest.fixture
def pricing():
    return load_json(PRICING)


@pytest.fixture
def proposal():
    return load_json(PROPOSAL)


@pytest.fixture
def limits(proposal):
    return TrialLimits(**proposal["limits"])


@pytest.fixture
def sol(pricing):
    return validate_pricing(pricing)["openai", "gpt-6.1-sol"]


def test_cost_accounts_for_disjoint_input_categories_and_inclusive_output(sol):
    # 300 ordinary + 400 cached + 500 write = 1200 total input, not 2400.
    # $0.000600 + $0.000040 + $0.001250 + $0.002000 = $0.003890.
    assert actual_cost(sol, Usage(1200, 400, 500, 200)) == Fraction("0.003890")


def test_input_categories_partition_cost_without_double_charge(sol):
    ordinary = actual_cost(sol, Usage(1000, 0, 0, 0))
    cached = actual_cost(sol, Usage(1000, 1000, 0, 0))
    written = actual_cost(sol, Usage(1000, 0, 1000, 0))
    assert ordinary == Fraction("0.002")
    assert cached == Fraction("0.0001")
    assert written == Fraction("0.0025")
    assert actual_cost(sol, Usage(3000, 1000, 1000, 0)) == ordinary + cached + written


def test_one_tiny_cached_token_never_rounds_down_to_free(sol):
    value = actual_cost(sol, Usage(1, 1, 0, 0))
    assert value == Fraction(1, 10_000_000)
    assert ceiling_cents(value) == 1
    assert ceiling_cents(Fraction("0.01")) == 1
    assert ceiling_cents(Fraction("0.0100001")) == 2


@pytest.mark.parametrize(
    "counts", [(1, 1, 1, 0), (1, -1, 0, 0), (True, 0, 0, 0), (1, 0, 0, None), (1, 0, 0, 1.0)]
)
def test_unknown_negative_overlapping_or_inexact_usage_is_rejected(counts):
    with pytest.raises(ContractError):
        Usage(*counts)


def test_unknown_write_rate_cannot_be_interpreted_as_zero(sol):
    with pytest.raises(ContractError, match="no verified rate"):
        actual_cost(replace(sol, cache_write=None), Usage(1, 0, 1, 0))


def test_missing_usage_is_incomplete_not_a_zero_charge(sol):
    with pytest.raises(ContractError, match="complete explicit Usage"):
        actual_cost(sol, None)


def test_long_context_cannot_use_short_context_prices(sol):
    with pytest.raises(ContractError, match="applicable request range"):
        actual_cost(sol, Usage(272001, 0, 0, 1))


def test_ceiling_uses_cumulative_limits_and_highest_input_price(sol, limits):
    assert trial_ceiling(sol, limits) == Fraction("2.25")
    assert trial_ceiling(sol, replace(limits, max_requests=1)) == Fraction("0.41")
    # A provider with no separately billed cache writes uses ordinary input.
    assert trial_ceiling(replace(sol, cache_write=None), limits) == Fraction("2")


def test_highest_input_price_is_not_assumed_to_be_cache_write(sol, limits):
    rate = replace(sol, cached_input=3_000_000)
    assert trial_ceiling(rate, limits) == Fraction("2.5")


@pytest.mark.parametrize(
    "changes", [{"max_input_tokens_per_request": 272001}, {"max_output_tokens_per_request": 128001}]
)
def test_request_limits_must_fit_actual_rate_range_and_model_limit(sol, limits, changes):
    with pytest.raises(ContractError):
        trial_ceiling(sol, replace(limits, **changes))


def quote(sol, limits, **changes):
    args = {
        "previous_requests": 0,
        "previous_input_tokens": 0,
        "previous_output_tokens": 0,
        "preflight_input_tokens": 64000,
        "max_output_tokens": 25000,
        "remaining_usd": Fraction("0.41"),
    }
    return quote_next_request(sol, limits, **(args | changes))


def test_next_request_reserves_input_overhead_and_all_output(sol, limits):
    assert quote(sol, limits) == Fraction("0.41")
    # One extra input formatting token crosses the per-call input limit.
    with pytest.raises(ContractError, match="preflight_input_tokens"):
        quote(sol, limits, preflight_input_tokens=64001)
    with pytest.raises(ContractError, match="insufficient budget"):
        quote(sol, limits, remaining_usd=Fraction("0.4099999999"))


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"previous_requests": 12}, "request limit exhausted"),
        ({"previous_requests": 11, "previous_input_tokens": 436001}, "cumulative input"),
        ({"previous_requests": 4, "previous_output_tokens": 75001}, "cumulative output"),
        ({"remaining_usd": 0.41}, "exact Fraction"),
        ({"preflight_input_tokens": None}, "preflight_input_tokens"),
    ],
)
def test_no_call_can_cross_an_independent_limit(sol, limits, changes, message):
    with pytest.raises(ContractError, match=message):
        quote(sol, limits, **changes)


def test_repairs_and_retries_do_not_multiply_the_cumulative_allowance(sol, limits):
    enabled = replace(limits, infrastructure_retries=1, repair_attempts=1)
    assert trial_ceiling(sol, enabled) == trial_ceiling(sol, limits)
    with pytest.raises(ContractError, match="request limit exhausted"):
        quote(sol, enabled, previous_requests=12)


def test_inconsistent_counters_cannot_be_used_to_quote_more_spend(sol, limits):
    with pytest.raises(ContractError, match="recorded request count"):
        quote(sol, limits, previous_input_tokens=1)


def test_six_trial_proposal_has_reproducible_exact_costs(proposal, pricing):
    result = estimate_proposal(proposal, pricing)
    assert result == estimate_proposal(copy.deepcopy(proposal), copy.deepcopy(pricing))
    assert result["trial_count"] == 6
    assert result["execution_enabled"] is False
    assert result["status"] == "unapproved_proposal"
    assert result["token_cost_ceiling_usd"] == "7.0875"
    assert result["token_cost_ceiling_usd_cents"] == 709
    assert result["reservation_ceiling_usd_cents"] == 777
    assert result["usage_scenarios"][0]["batch_cost_usd"] == "0.70875"
    assert result["usage_scenarios"][1]["batch_cost_usd"] == "2.12625"
    assert result["unresolved_requirements"] == proposal["unresolved_requirements"]


def test_future_48_trial_sol_ceiling_is_108_dollars(sol, limits):
    # This arithmetic creates no fake task families or runnable campaign.
    assert 48 * trial_ceiling(sol, limits) == Fraction(108)
    assert 48 * trial_reservation_ceiling_cents(sol, limits) == 11328


@pytest.mark.parametrize("cap,valid", [(709, False), (776, False), (777, True), (1000, True)])
def test_batch_cap_checks_aggregate_and_rounds_up(proposal, pricing, cap, valid):
    proposal["max_cost_usd_cents"] = cap
    if valid:
        assert estimate_proposal(proposal, pricing)["trial_count"] == 6
    else:
        with pytest.raises(ContractError, match="below the pessimistic"):
            estimate_proposal(proposal, pricing)


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema_version", True),
        ("status", "approved"),
        ("execution_enabled", True),
        ("execution_enabled", 0),
        ("unresolved_requirements", []),
        ("concurrency", 2),
        ("max_cost_usd_cents", True),
        ("pricing_snapshot_sha256", "0" * 64),
        ("groups", []),
    ],
)
def test_no_approval_or_execution_can_be_smuggled_into_proposal(proposal, pricing, key, value):
    proposal[key] = value
    with pytest.raises(ContractError):
        estimate_proposal(proposal, pricing)


def test_pricing_changes_invalidate_proposal_binding(proposal, pricing):
    pricing["rates"][0]["prices"]["input"] += 1
    with pytest.raises(ContractError, match="exact canonical pricing"):
        estimate_proposal(proposal, pricing)
    proposal["pricing_snapshot_sha256"] = digest(pricing)
    assert estimate_proposal(proposal, pricing)["proposal_sha256"] == digest(proposal)


@pytest.mark.parametrize(
    "change",
    [
        "unknown_field",
        "missing_field",
        "unknown_model",
        "duplicate_tasks",
        "duplicate_group",
        "unknown_limits",
        "scenario_exceeds_limits",
    ],
)
def test_malformed_or_unpriced_proposals_fail(proposal, pricing, change):
    if change == "unknown_field":
        proposal["api_key"] = "synthetic-secret-must-not-be-a-field"
    elif change == "missing_field":
        del proposal["status"]
    elif change == "unknown_model":
        proposal["groups"][0]["model"] = "new-unpriced-model"
    elif change == "duplicate_tasks":
        proposal["groups"][0]["task_labels"].append("invoice-read")
    elif change == "duplicate_group":
        proposal["groups"].append(copy.deepcopy(proposal["groups"][0]))
    elif change == "unknown_limits":
        proposal["limits"]["unbounded_extra_calls"] = 10
    else:
        proposal["usage_scenarios"][0]["output_tokens"] = 100001
    with pytest.raises(ContractError):
        estimate_proposal(proposal, pricing)


@pytest.mark.parametrize(
    "change",
    [
        "fractional_price",
        "bool_price",
        "negative_price",
        "duplicate",
        "currency",
        "date",
        "tier",
        "source",
    ],
)
def test_malformed_pricing_cannot_silently_select_a_cheaper_interpretation(pricing, change):
    if change == "fractional_price":
        pricing["rates"][0]["prices"]["input"] = 2.0
    elif change == "bool_price":
        pricing["rates"][0]["prices"]["cache_write"] = False
    elif change == "negative_price":
        pricing["rates"][0]["prices"]["output"] = -1
    elif change == "duplicate":
        pricing["rates"].append(copy.deepcopy(pricing["rates"][0]))
    elif change == "currency":
        pricing["currency"] = "EUR"
    elif change == "date":
        pricing["verified_on"] = "2026-02-30"
    elif change == "tier":
        pricing["rates"][0]["service_tier"] = "batch"
    else:
        pricing["rates"][0]["source_urls"] = ["https://user:password@example.com/rates"]
    with pytest.raises(ContractError):
        validate_pricing(pricing)


@pytest.mark.parametrize(
    "text", ['{"a": 1, "a": 2}', '{"a": NaN}', "{" * 10, '"' + "x" * 262145 + '"']
)
def test_ambiguous_nonfinite_malformed_and_oversized_json_fails(tmp_path, text):
    path = tmp_path / "invalid.json"
    path.write_text(text)
    with pytest.raises(ContractError):
        load_json(path)


def test_estimator_command_is_offline_and_never_emits_execution_authority(capsys):
    assert main([str(PROPOSAL), str(PRICING)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["execution_enabled"] is False
    assert result["token_cost_ceiling_usd"] == "7.0875"


def test_command_reports_missing_input_without_traceback(tmp_path, capsys):
    assert main([str(tmp_path / "missing"), str(PRICING)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "Invalid model-budget proposal" in output.err


def test_core_has_no_provider_or_harbor_dependency():
    # The estimator uses project contracts and stdlib only.
    import ast

    source = (ROOT / "src/democratize_security/model_budget.py").read_text()
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not imported.intersection({"harbor", "litellm", "openai", "anthropic", "httpx"})


def test_rate_card_rejects_boolean_limits(sol):
    with pytest.raises(ContractError):
        replace(sol, max_input_tokens=True)
