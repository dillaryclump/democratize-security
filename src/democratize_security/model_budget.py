"""Exact, provider-independent offline model-cost proposals; no execution authority.

Rates are integer micro-USD per million tokens. Input totals include cached and
cache-write tokens; output totals already include reasoning/formatting tokens.
Quotes do not reserve money durably or authorize any request.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, localcontext
from fractions import Fraction
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from democratize_security.contracts import ContractError, digest

_DOLLAR_DENOMINATOR = 1_000_000_000_000
_RATE_FIELDS = {"input", "cached_input", "cache_write", "output"}
_LIMIT_FIELDS = {
    "max_requests",
    "max_input_tokens_per_request",
    "max_output_tokens_per_request",
    "max_total_input_tokens",
    "max_total_output_tokens",
    "agent_timeout_seconds",
    "verifier_timeout_seconds",
    "infrastructure_retries",
    "repair_attempts",
}


def _object(value: Any, fields: set[str], where: str) -> None:
    if type(value) is not dict or set(value) != fields:
        raise ContractError(f"{where}: expected exactly {sorted(fields)}")


def _integer(value: Any, minimum: int, maximum: int, where: str) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError(f"{where}: expected integer from {minimum} to {maximum}")


def _text(value: Any, where: str) -> None:
    if type(value) is not str or not value.strip() or len(value) > 4096:
        raise ContractError(f"{where}: expected bounded nonempty text")


def _list(value: Any, where: str) -> None:
    if type(value) is not list or not 1 <= len(value) <= 10000:
        raise ContractError(f"{where}: expected bounded nonempty list")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
    value: dict = {}
    for key, item in pairs:
        if key in value:
            raise ContractError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_json(path: Path) -> dict:
    """Read a bounded JSON document without ambiguous keys or non-finite values."""
    with path.open("rb") as stream:
        data = stream.read(262145)
    if len(data) > 262144:
        raise ContractError("budget document exceeds 256 KiB")

    def invalid_constant(value: str) -> None:
        raise ContractError(f"non-finite JSON value: {value}")

    try:
        return json.loads(data, object_pairs_hook=_unique_pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError) as error:
        raise ContractError(f"invalid budget JSON: {error}") from error


@dataclass(frozen=True)
class RateCard:
    provider: str
    model: str
    input: int
    cached_input: int
    cache_write: int | None
    output: int
    max_input_tokens: int
    max_output_tokens: int

    def __post_init__(self) -> None:
        for name in ("provider", "model"):
            _text(getattr(self, name), name)
        for name in ("input", "cached_input", "output"):
            _integer(getattr(self, name), 0, 10**12, name)
        if self.cache_write is not None:
            _integer(self.cache_write, 0, 10**12, "cache_write")
        for name in ("max_input_tokens", "max_output_tokens"):
            _integer(getattr(self, name), 1, 10**8, name)

    @property
    def maximum_input_price(self) -> int:
        return max(self.input, self.cached_input, self.cache_write or 0)


@dataclass(frozen=True)
class Usage:
    """One provider response's explicit inclusive counts, never inferred zeros."""

    input_tokens: int
    cached_input_tokens: int
    cache_write_tokens: int
    output_tokens: int

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            _integer(getattr(self, name), 0, 10**12, name)
        if self.cached_input_tokens + self.cache_write_tokens > self.input_tokens:
            raise ContractError("cached and cache-write counts exceed total input")


@dataclass(frozen=True)
class TrialLimits:
    """Cumulative limits cover all generation, retry, repair and summary calls."""

    max_requests: int
    max_input_tokens_per_request: int
    max_output_tokens_per_request: int
    max_total_input_tokens: int
    max_total_output_tokens: int
    agent_timeout_seconds: int
    verifier_timeout_seconds: int
    infrastructure_retries: int
    repair_attempts: int

    def __post_init__(self) -> None:
        _integer(self.max_requests, 1, 10000, "max_requests")
        for name in (
            "max_input_tokens_per_request",
            "max_output_tokens_per_request",
            "max_total_input_tokens",
            "max_total_output_tokens",
        ):
            _integer(getattr(self, name), 1, 10**9, name)
        for name in ("agent_timeout_seconds", "verifier_timeout_seconds"):
            _integer(getattr(self, name), 1, 86400, name)
        _integer(self.infrastructure_retries, 0, 1, "infrastructure_retries")
        _integer(self.repair_attempts, 0, 10, "repair_attempts")


def _compatible(rate: RateCard, limits: TrialLimits) -> None:
    if limits.max_input_tokens_per_request > rate.max_input_tokens:
        raise ContractError("request input exceeds this rate card's context-price range")
    if limits.max_output_tokens_per_request > rate.max_output_tokens:
        raise ContractError("request output exceeds this rate card's model limit")


def actual_cost(rate: RateCard, usage: Usage) -> Fraction:
    """Price complete trusted usage once; this does not authenticate its origin."""
    if type(usage) is not Usage:
        raise ContractError("complete explicit Usage is required")
    if usage.input_tokens > rate.max_input_tokens or usage.output_tokens > rate.max_output_tokens:
        raise ContractError("usage exceeds this rate card's applicable request range")
    if usage.cache_write_tokens and rate.cache_write is None:
        raise ContractError("cache-write usage has no verified rate")
    ordinary = usage.input_tokens - usage.cached_input_tokens - usage.cache_write_tokens
    return Fraction(
        ordinary * rate.input
        + usage.cached_input_tokens * rate.cached_input
        + usage.cache_write_tokens * (rate.cache_write or 0)
        + usage.output_tokens * rate.output,
        _DOLLAR_DENOMINATOR,
    )


def trial_ceiling(rate: RateCard, limits: TrialLimits) -> Fraction:
    """Pessimistic token-cost ceiling, conditional on enforcing every limit."""
    _compatible(rate, limits)
    inputs = min(
        limits.max_total_input_tokens, limits.max_requests * limits.max_input_tokens_per_request
    )
    outputs = min(
        limits.max_total_output_tokens, limits.max_requests * limits.max_output_tokens_per_request
    )
    return Fraction(inputs * rate.maximum_input_price + outputs * rate.output, _DOLLAR_DENOMINATOR)


def quote_next_request(
    rate: RateCard,
    limits: TrialLimits,
    *,
    previous_requests: int,
    previous_input_tokens: int,
    previous_output_tokens: int,
    preflight_input_tokens: int,
    max_output_tokens: int,
    remaining_usd: Fraction,
) -> Fraction:
    """Validate exact full-payload preflight counts and quote the next reservation.

    The caller must atomically persist the quote and request intent before any
    send. Counters must include ambiguous requests at their reserved maxima.
    This pure function performs no network, reservation or runtime dispatch.
    """
    _compatible(rate, limits)
    _integer(previous_requests, 0, limits.max_requests, "previous_requests")
    _integer(previous_input_tokens, 0, limits.max_total_input_tokens, "previous_input_tokens")
    _integer(previous_output_tokens, 0, limits.max_total_output_tokens, "previous_output_tokens")
    if (
        previous_input_tokens > previous_requests * limits.max_input_tokens_per_request
        or previous_output_tokens > previous_requests * limits.max_output_tokens_per_request
    ):
        raise ContractError("previous counters cannot fit the recorded request count")
    _integer(
        preflight_input_tokens, 1, limits.max_input_tokens_per_request, "preflight_input_tokens"
    )
    _integer(max_output_tokens, 1, limits.max_output_tokens_per_request, "max_output_tokens")
    if type(remaining_usd) is not Fraction or remaining_usd < 0:
        raise ContractError("remaining_usd must be a nonnegative exact Fraction")
    if previous_requests >= limits.max_requests:
        raise ContractError("upstream request limit exhausted")
    if previous_input_tokens + preflight_input_tokens > limits.max_total_input_tokens:
        raise ContractError("cumulative input limit exceeded")
    if previous_output_tokens + max_output_tokens > limits.max_total_output_tokens:
        raise ContractError("cumulative output limit exceeded")
    quote = Fraction(
        preflight_input_tokens * rate.maximum_input_price + max_output_tokens * rate.output,
        _DOLLAR_DENOMINATOR,
    )
    if quote > remaining_usd:
        raise ContractError("insufficient budget for the worst-case next request")
    return quote


def dollars(value: Fraction) -> str:
    """Exact decimal dollars for costs with the module's terminating denominator."""
    with localcontext() as context:
        context.prec = 80
        return format(Decimal(value.numerator) / Decimal(value.denominator), "f")


def ceiling_cents(value: Fraction) -> int:
    return -(-value.numerator * 100 // value.denominator)


def trial_reservation_ceiling_cents(rate: RateCard, limits: TrialLimits) -> int:
    """Safe allowance if a future ledger rounds each request cost up to cents.

    For at most N nonnegative costs, sum(ceil(cost_i)) is at most
    ceil(sum(cost_i)) + N - 1. This is conservative, not a billing prediction.
    """
    return ceiling_cents(trial_ceiling(rate, limits)) + limits.max_requests - 1


def validate_pricing(snapshot: Any) -> dict[tuple[str, str], RateCard]:
    _object(snapshot, {"schema_version", "verified_on", "currency", "units", "rates"}, "pricing")
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
        raise ContractError("pricing schema_version must be integer 1")
    if snapshot["currency"] != "USD" or snapshot["units"] != "micro-USD per 1000000 tokens":
        raise ContractError("unsupported pricing currency/units")
    _text(snapshot["verified_on"], "verified_on")
    try:
        if date.fromisoformat(snapshot["verified_on"]).isoformat() != snapshot["verified_on"]:
            raise ValueError("not canonical ISO date")
    except ValueError as error:
        raise ContractError("verified_on must be an ISO date") from error
    _list(snapshot["rates"], "rates")
    cards: dict[tuple[str, str], RateCard] = {}
    for entry in snapshot["rates"]:
        _object(
            entry,
            {
                "provider",
                "model",
                "service_tier",
                "max_input_tokens",
                "max_output_tokens",
                "prices",
                "source_urls",
            },
            "rate",
        )
        if entry["service_tier"] != "standard":
            raise ContractError("only standard token pricing is supported")
        _object(entry["prices"], _RATE_FIELDS, "prices")
        _list(entry["source_urls"], "source_urls")
        for source in entry["source_urls"]:
            _text(source, "source URL")
            try:
                parsed = urlsplit(source)
            except ValueError as error:
                raise ContractError("invalid pricing source URL") from error
            if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
                raise ContractError("pricing source must be a public HTTPS URL")
        card = RateCard(
            provider=entry["provider"],
            model=entry["model"],
            **entry["prices"],
            max_input_tokens=entry["max_input_tokens"],
            max_output_tokens=entry["max_output_tokens"],
        )
        key = (card.provider, card.model)
        if key in cards:
            raise ContractError("duplicate provider/model rate card")
        cards[key] = card
    return cards


def estimate_proposal(proposal: Any, snapshot: Any) -> dict:
    """Validate a finite, explicitly unapproved proposal and estimate token costs."""
    cards = validate_pricing(snapshot)
    _object(
        proposal,
        {
            "schema_version",
            "status",
            "execution_enabled",
            "name",
            "scope",
            "pricing_snapshot_sha256",
            "concurrency",
            "max_cost_usd_cents",
            "limits",
            "groups",
            "usage_scenarios",
            "unresolved_requirements",
        },
        "proposal",
    )
    if type(proposal["schema_version"]) is not int or proposal["schema_version"] != 1:
        raise ContractError("proposal schema_version must be integer 1")
    if proposal["status"] != "unapproved_proposal" or proposal["execution_enabled"] is not False:
        raise ContractError("only unapproved, execution-disabled proposals are supported")
    for name in ("name", "scope"):
        _text(proposal[name], name)
    if proposal["pricing_snapshot_sha256"] != digest(snapshot):
        raise ContractError("proposal does not bind this exact canonical pricing snapshot")
    _integer(proposal["concurrency"], 1, 1, "concurrency")
    _integer(proposal["max_cost_usd_cents"], 0, 1_000_000, "max_cost_usd_cents")
    _object(proposal["limits"], _LIMIT_FIELDS, "limits")
    limits = TrialLimits(**proposal["limits"])
    _list(proposal["unresolved_requirements"], "unresolved_requirements")
    for requirement in proposal["unresolved_requirements"]:
        _text(requirement, "unresolved requirement")
    _list(proposal["groups"], "groups")
    groups = []
    selected: list[tuple[RateCard, int]] = []
    labels: set[str] = set()
    total = Fraction()
    reservation_cents = 0
    trial_count = 0
    for group in proposal["groups"]:
        _object(group, {"label", "provider", "model", "reasoning_effort", "task_labels"}, "group")
        for key in ("label", "provider", "model", "reasoning_effort"):
            _text(group[key], f"group.{key}")
        if group["label"] in labels:
            raise ContractError("duplicate group label")
        labels.add(group["label"])
        _list(group["task_labels"], "task_labels")
        for label in group["task_labels"]:
            _text(label, "task label")
        if len(set(group["task_labels"])) != len(group["task_labels"]):
            raise ContractError("duplicate task label within group")
        rate = cards.get((group["provider"], group["model"]))
        if rate is None:
            raise ContractError("missing provider/model pricing")
        count = len(group["task_labels"])
        ceiling = trial_ceiling(rate, limits)
        total += count * ceiling
        reservation_cents += count * trial_reservation_ceiling_cents(rate, limits)
        trial_count += count
        selected.append((rate, count))
        groups.append(
            {
                "label": group["label"],
                "trial_count": count,
                "per_trial_ceiling_usd": dollars(ceiling),
            }
        )
    _integer(trial_count, 1, 10000, "total trial count")
    if reservation_cents > proposal["max_cost_usd_cents"]:
        raise ContractError("proposed batch cap is below the pessimistic reservation ceiling")
    _list(proposal["usage_scenarios"], "usage_scenarios")
    scenarios = []
    labels.clear()
    for scenario in proposal["usage_scenarios"]:
        _object(scenario, {"label", "input_tokens", "output_tokens"}, "usage scenario")
        _text(scenario["label"], "scenario label")
        if scenario["label"] in labels:
            raise ContractError("duplicate scenario label")
        labels.add(scenario["label"])
        _integer(
            scenario["input_tokens"],
            0,
            min(
                limits.max_total_input_tokens,
                limits.max_requests * limits.max_input_tokens_per_request,
            ),
            "scenario input",
        )
        _integer(
            scenario["output_tokens"],
            0,
            min(
                limits.max_total_output_tokens,
                limits.max_requests * limits.max_output_tokens_per_request,
            ),
            "scenario output",
        )
        value = sum(
            (
                Fraction(
                    count
                    * (
                        scenario["input_tokens"] * rate.maximum_input_price
                        + scenario["output_tokens"] * rate.output
                    ),
                    _DOLLAR_DENOMINATOR,
                )
                for rate, count in selected
            ),
            Fraction(),
        )
        scenarios.append({**scenario, "batch_cost_usd": dollars(value)})
    return {
        "schema_version": 1,
        "status": "unapproved_proposal",
        "execution_enabled": False,
        "proposal_sha256": digest(proposal),
        "pricing_snapshot_sha256": digest(snapshot),
        "pricing_verified_on": snapshot["verified_on"],
        "trial_count": trial_count,
        "groups": groups,
        "token_cost_ceiling_usd": dollars(total),
        "token_cost_ceiling_usd_cents": ceiling_cents(total),
        "reservation_ceiling_usd_cents": reservation_cents,
        "proposed_max_cost_usd_cents": proposal["max_cost_usd_cents"],
        "usage_scenarios": scenarios,
        "unresolved_requirements": proposal["unresolved_requirements"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proposal", type=Path)
    parser.add_argument("pricing", type=Path)
    args = parser.parse_args(argv)
    try:
        result = estimate_proposal(load_json(args.proposal), load_json(args.pricing))
    except (OSError, ContractError) as error:
        print(f"Invalid model-budget proposal: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
