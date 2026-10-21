"""Durable per-request model metering for runtime attempts (issue #69).

`Meter.generate` sends one model request only after the ledger durably holds its
worst-case reservation, sends it exactly once, then settles it from the
provider's explicit usage or records its outcome as unknown. Any refusal or
failure latches the meter, so a caller's retry can never produce a second send.
Provider adapters live under `adapters/providers`; this core module imports only
the standard library and the project's own contracts.
"""

import hashlib
from dataclasses import dataclass
from fractions import Fraction
from typing import Protocol

from democratize_security.contracts import ContractError, digest
from democratize_security.model_budget import (
    RateCard,
    TrialLimits,
    Usage,
    actual_cost,
    ceiling_cents,
    quote_next_request,
)
from democratize_security.runtime_events import MODE as RUNTIME_MODE
from democratize_security.store import PlanStore, StoreError

MAX_MESSAGES = 512
ROLES = frozenset({"system", "user", "assistant"})


class MeterRefused(Exception):
    """Nothing was sent; no unknown outcome exists for this call."""


class ProviderError(Exception):
    """The provider outcome is unknown or unusable; its reservation stays held."""


@dataclass(frozen=True)
class ProviderResult:
    content: str
    status: str
    model: str
    usage: Usage | None
    response_sha256: str


class Provider(Protocol):
    def count_input_tokens(self, payload: dict) -> int: ...

    def create(self, payload: dict) -> ProviderResult: ...


class ScriptedProvider:
    """Model-free provider returning fixed responses with fixed explicit usage."""

    def __init__(self, responses: tuple[str, ...], *, input_tokens=1000, output_tokens=200):
        if type(responses) is not tuple or not all(type(r) is str for r in responses):
            raise TypeError("scripted responses must be a fixed tuple of strings")
        self.responses = responses
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.counted = 0
        self.sent = 0
        self.payloads = []

    def count_input_tokens(self, payload: dict) -> int:
        self.counted += 1
        return self.input_tokens

    def create(self, payload: dict) -> ProviderResult:
        if self.sent >= len(self.responses):
            raise RuntimeError("scripted provider exhausted")
        content = self.responses[self.sent]
        self.sent += 1
        self.payloads.append(payload)
        return ProviderResult(
            content,
            "completed",
            payload["model"],
            Usage(self.input_tokens, 0, 0, self.output_tokens),
            hashlib.sha256(content.encode()).hexdigest(),
        )


def _messages(value) -> list[dict]:
    if not isinstance(value, list) or not 0 < len(value) <= MAX_MESSAGES:
        raise MeterRefused("messages must be a nonempty bounded list")
    for message in value:
        if (
            not isinstance(message, dict)
            or set(message) != {"role", "content"}
            or message["role"] not in ROLES
            or type(message["content"]) is not str
        ):
            raise MeterRefused("each message needs only a known role and string content")
    return [dict(message) for message in value]


class Meter:
    """Meter every model request of one running runtime attempt."""

    def __init__(
        self,
        store: PlanStore,
        attempt_id: str,
        rate: RateCard,
        limits: TrialLimits,
        provider: Provider,
        *,
        reasoning_effort: str,
    ):
        self._store = store
        self._attempt_id = attempt_id
        self._rate = rate
        self._limits = limits
        self._provider = provider
        self._effort = reasoning_effort
        self.latched = False

    def _state(self) -> dict:
        state = next(
            (s for s in self._store.attempts() if s["attempt_id"] == self._attempt_id), None
        )
        if state is None or state.get("mode") != RUNTIME_MODE or state["phase"] != "running":
            raise MeterRefused("metering requires a running runtime attempt")
        return state

    def _record(self, event_id: str, action: str, state: dict, **fields) -> dict:
        return self._store.record_runtime(
            event_id,
            {
                "mode": RUNTIME_MODE,
                "action": action,
                "attempt_id": self._attempt_id,
                "expected_revision": state["revision"],
                **fields,
            },
        )

    def generate(self, messages: list[dict]) -> str:
        if self.latched:
            raise MeterRefused("meter is latched after an earlier refusal or failure")
        try:
            payload = {
                "model": self._rate.model,
                "input": _messages(messages),
                "reasoning": {"effort": self._effort},
                "max_output_tokens": self._limits.max_output_tokens_per_request,
                "store": False,
            }
            state = self._state()
            preflight = self._provider.count_input_tokens(payload)
            quote = quote_next_request(
                self._rate,
                self._limits,
                previous_requests=state["request_count"],
                previous_input_tokens=state["input_tokens"],
                previous_output_tokens=state["output_tokens"],
                preflight_input_tokens=preflight,
                max_output_tokens=payload["max_output_tokens"],
                remaining_usd=Fraction(state["max_cost_cents"] - state["committed_cents"], 100),
            )
            request_id = f"{self._attempt_id}-req-{state['request_count'] + 1:02d}"
            state = self._record(
                f"{request_id}-intent",
                "request_intent",
                state,
                request_id=request_id,
                preflight_input_tokens=preflight,
                max_output_tokens=payload["max_output_tokens"],
                reserve_cents=ceiling_cents(quote),
                payload_sha256=digest(payload),
            )
        except MeterRefused:
            self.latched = True
            raise
        except (ContractError, StoreError, ValueError, TypeError, OSError) as error:
            self.latched = True
            raise MeterRefused(f"request refused before sending: {error}") from None
        except Exception as error:
            # Preflight failures carry no reservation; nothing was generated.
            self.latched = True
            raise MeterRefused(f"preflight failed: {type(error).__name__}") from None
        # The intent is durable; from here every failure leaves an unknown outcome.
        self.latched = True
        try:
            result = self._provider.create(payload)
            usage = self._validated(result, preflight, payload["max_output_tokens"])
            cost = actual_cost(self._rate, usage)
            self._record(
                f"{request_id}-settle",
                "request_settle",
                state,
                request_id=request_id,
                input_tokens=usage.input_tokens,
                cached_input_tokens=usage.cached_input_tokens,
                output_tokens=usage.output_tokens,
                cost_cents=ceiling_cents(cost),
                response_sha256=result.response_sha256,
            )
        except BaseException as error:
            self._unknown(request_id, state, type(error).__name__)
            if not isinstance(error, Exception):
                raise
            raise ProviderError(f"request {request_id} outcome unknown") from None
        self.latched = False
        return result.content

    def _validated(self, result, preflight: int, max_output: int) -> Usage:
        if type(result) is not ProviderResult or type(result.content) is not str:
            raise ProviderError("invalid provider result")
        if result.status != "completed" or not result.model.startswith(self._rate.model):
            raise ProviderError("incomplete response or unexpected model")
        usage = result.usage
        if type(usage) is not Usage:
            raise ProviderError("missing usage")
        if usage.input_tokens > preflight or usage.output_tokens > max_output:
            raise ProviderError("usage exceeds the reservation")
        # Uncached input is priced at the dearer of input and cache-write rates,
        # because providers do not report cache writes separately: an upper bound.
        uncached = usage.input_tokens - usage.cached_input_tokens
        if self._rate.cache_write is not None and self._rate.cache_write >= self._rate.input:
            return Usage(
                usage.input_tokens, usage.cached_input_tokens, uncached, usage.output_tokens
            )
        return Usage(usage.input_tokens, usage.cached_input_tokens, 0, usage.output_tokens)

    def _unknown(self, request_id: str, state: dict, reason: str) -> None:
        try:
            self._record(
                f"{request_id}-unknown",
                "request_unknown",
                state,
                request_id=request_id,
                reason=f"provider outcome unknown: {reason}"[:512],
            )
        except Exception:
            # The open reservation itself still blocks sealing and further requests.
            pass
