"""Retry-free OpenAI Responses transport for `model_meter.Meter` (issue #69).

Synchronous Standard-processing calls only: no streaming, background jobs,
hosted tools, stored responses, response chaining or client retries. The key
lives in this object alone; it never appears in its repr, exception messages or
exception chains. Usage missing any explicit field is reported as `None`, so the
meter records the outcome as unknown instead of treating it as zero.
"""

import hashlib
import json
import os
import stat
from pathlib import Path

import httpx

from democratize_security.model_budget import Usage
from democratize_security.model_meter import MeterRefused, ProviderError, ProviderResult

BASE_URL = "https://api.openai.com/v1"
MAX_KEY_BYTES = 512
MAX_BODY_BYTES = 16 * 1024 * 1024


def load_key(path: Path) -> str:
    """Read a single-token key from a regular private file owned by this user."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ValueError(f"key file unavailable: {type(error).__name__}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError("key file must be a regular, singly linked file owned by this user")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("key file mode must be 0600")
        data = os.read(fd, MAX_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_KEY_BYTES:
        raise ValueError("key file is too large")
    try:
        key = data.decode("ascii").strip()
    except UnicodeDecodeError:
        raise ValueError("key file must be ASCII") from None
    if not key or any(c.isspace() for c in key):
        raise ValueError("key file must hold exactly one token")
    return key


def _count(value):
    return value if type(value) is int and value >= 0 else None


def _usage(body) -> Usage | None:
    usage = body.get("usage")
    if not isinstance(usage, dict) or not isinstance(usage.get("input_tokens_details"), dict):
        return None
    total = _count(usage.get("input_tokens"))
    cached = _count(usage["input_tokens_details"].get("cached_tokens"))
    output = _count(usage.get("output_tokens"))
    if None in (total, cached, output) or cached > total:
        return None
    return Usage(total, cached, 0, output)


def _text(body) -> str:
    parts = []
    for item in body.get("output") or []:
        if isinstance(item, dict) and item.get("type") == "message":
            for content in item.get("content") or []:
                if isinstance(content, dict) and content.get("type") == "output_text":
                    if type(content.get("text")) is not str:
                        raise ProviderError("invalid output text")
                    parts.append(content["text"])
    return "".join(parts)


class OpenAIResponsesProvider:
    """Implements `model_meter.Provider` against the OpenAI Responses API."""

    def __init__(self, api_key: str, *, transport=None, timeout_seconds: float = 300.0):
        if type(api_key) is not str or not api_key:
            raise ValueError("an API key is required")
        self.__key = api_key
        self._client = httpx.Client(
            base_url=BASE_URL, transport=transport, timeout=timeout_seconds, follow_redirects=False
        )

    def __repr__(self) -> str:
        return "OpenAIResponsesProvider(<key withheld>)"

    __str__ = __repr__

    def _post(self, path: str, body: dict) -> tuple[int, bytes]:
        response = self._client.post(
            path,
            content=json.dumps(body, separators=(",", ":")).encode(),
            headers={
                "authorization": f"Bearer {self.__key}",
                "content-type": "application/json",
            },
        )
        return response.status_code, response.content[: MAX_BODY_BYTES + 1]

    def count_input_tokens(self, payload: dict) -> int:
        body = {"model": payload["model"], "input": payload["input"]}
        try:
            status, raw = self._post("/responses/input_tokens", body)
            count = json.loads(raw).get("input_tokens") if status == 200 else None
        except Exception as error:
            raise MeterRefused(f"input-token preflight failed: {type(error).__name__}") from None
        if type(count) is not int or count < 1:
            raise MeterRefused(f"input-token preflight rejected (HTTP {status})")
        return count

    def create(self, payload: dict) -> ProviderResult:
        try:
            status, raw = self._post("/responses", {**payload, "service_tier": "default"})
        except Exception as error:
            raise ProviderError(f"request failed: {type(error).__name__}") from None
        if status != 200 or len(raw) > MAX_BODY_BYTES:
            raise ProviderError(f"provider returned HTTP {status}")
        try:
            body = json.loads(raw)
        except ValueError:
            raise ProviderError("provider returned invalid JSON") from None
        if not isinstance(body, dict) or type(body.get("status")) is not str:
            raise ProviderError("provider returned an invalid response object")
        if type(body.get("model")) is not str:
            raise ProviderError("provider response names no model")
        return ProviderResult(
            content=_text(body),
            status=body["status"],
            model=body["model"],
            usage=_usage(body),
            response_sha256=hashlib.sha256(raw).hexdigest(),
        )
