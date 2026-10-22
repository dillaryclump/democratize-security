"""OpenAI Responses provider adapter (issue #69): mock transport only, never the network."""

import json
import os

import pytest

httpx = pytest.importorskip("httpx")

from democratize_security.adapters.providers.openai_responses import (  # noqa: E402
    OpenAIResponsesProvider,
    load_key,
)
from democratize_security.model_budget import Usage  # noqa: E402
from democratize_security.model_meter import MeterRefused, ProviderError  # noqa: E402

KEY = "sk-test-SECRET"
PAYLOAD = {
    "model": "gpt-6.1-sol",
    "input": [{"role": "user", "content": "hi"}],
    "reasoning": {"effort": "medium"},
    "max_output_tokens": 25000,
    "store": False,
}
RESPONSE = {
    "id": "resp_1",
    "object": "response",
    "status": "completed",
    "model": "gpt-6.1-sol-2026-10-01",
    "output": [
        {"type": "reasoning", "summary": []},
        {
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "output_text", "text": "Hello "},
                {"type": "output_text", "text": "world"},
            ],
        },
    ],
    "usage": {
        "input_tokens": 120,
        "input_tokens_details": {"cached_tokens": 20},
        "output_tokens": 30,
        "output_tokens_details": {"reasoning_tokens": 10},
        "total_tokens": 150,
    },
}


def provider(handler):
    return OpenAIResponsesProvider(KEY, transport=httpx.MockTransport(handler))


def recorder(body=RESPONSE, status=200, count=99):
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/v1/responses/input_tokens":
            return httpx.Response(
                200, json={"object": "response.input_tokens", "input_tokens": count}
            )
        return httpx.Response(status, content=json.dumps(body).encode())

    return handler, seen


def test_count_and_create_map_usage():
    handler, seen = recorder()
    client = provider(handler)
    assert client.count_input_tokens(PAYLOAD) == 99
    result = client.create(PAYLOAD)
    assert result.content == "Hello world"
    assert (result.status, result.model) == ("completed", "gpt-6.1-sol-2026-10-01")
    assert result.usage == Usage(120, 20, 0, 30)
    assert len(result.response_sha256) == 64
    assert [r.url.path for r in seen] == ["/v1/responses/input_tokens", "/v1/responses"]
    assert all(r.headers["authorization"] == f"Bearer {KEY}" for r in seen)


def test_request_body_has_no_previous_response_id_and_store_false():
    handler, seen = recorder()
    client = provider(handler)
    client.count_input_tokens(PAYLOAD)
    client.create(PAYLOAD)
    counted, created = (json.loads(r.content) for r in seen)
    assert counted == {"model": "gpt-6.1-sol", "input": PAYLOAD["input"]}
    assert created == {**PAYLOAD, "service_tier": "default"}
    assert "previous_response_id" not in created


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b.pop("usage"),
        lambda b: b["usage"].pop("output_tokens"),
        lambda b: b["usage"].pop("input_tokens_details"),
        lambda b: b["usage"].update(input_tokens="120"),
        lambda b: b["usage"].update(output_tokens=True),
    ],
)
def test_missing_usage_fields_give_none(change):
    body = json.loads(json.dumps(RESPONSE))
    change(body)
    handler, _ = recorder(body)
    assert provider(handler).create(PAYLOAD).usage is None


def test_incomplete_status_is_reported_not_hidden():
    body = {**RESPONSE, "status": "incomplete"}
    handler, _ = recorder(body)
    assert provider(handler).create(PAYLOAD).status == "incomplete"


@pytest.mark.parametrize("status", [400, 429, 500, 503])
def test_http_errors_raise_provider_error(status):
    handler, _ = recorder({"error": {"message": "nope"}}, status=status)
    with pytest.raises(ProviderError):
        provider(handler).create(PAYLOAD)


@pytest.mark.parametrize(
    "error", [httpx.ReadTimeout("timed out"), httpx.ConnectError("reset"), ValueError("x")]
)
def test_transport_failures_raise_provider_error(error):
    def handler(request):
        raise error

    with pytest.raises(ProviderError):
        provider(handler).create(PAYLOAD)


def test_invalid_json_raises_provider_error():
    def handler(request):
        return httpx.Response(200, content=b"{not json")

    with pytest.raises(ProviderError):
        provider(handler).create(PAYLOAD)


@pytest.mark.parametrize("body", [{"input_tokens": "9"}, {}, {"input_tokens": -1}, "oops"])
def test_count_failures_refuse_before_any_send(body):
    def handler(request):
        if isinstance(body, str):
            return httpx.Response(500, content=body.encode())
        return httpx.Response(200, json=body)

    with pytest.raises(MeterRefused):
        provider(handler).count_input_tokens(PAYLOAD)


def test_errors_never_contain_key():
    client = provider(lambda r: httpx.Response(500, content=f"echo {KEY}".encode()))
    texts = [repr(client), str(client)]
    for call in (client.create, client.count_input_tokens):
        with pytest.raises((ProviderError, MeterRefused)) as raised:
            call(PAYLOAD)
        error = raised.value
        texts += [str(error), repr(error), repr(error.__cause__), repr(error.__context__)]
    assert not any(KEY in text for text in texts)


def test_load_key_reads_private_file(tmp_path):
    path = tmp_path / "openai-api-key"
    path.write_text(f"  {KEY}\n")
    path.chmod(0o600)
    assert load_key(path) == KEY


def test_load_key_rejects_group_readable_and_symlink(tmp_path):
    path = tmp_path / "openai-api-key"
    path.write_text(KEY)
    path.chmod(0o640)
    with pytest.raises(ValueError, match="0600"):
        load_key(path)
    path.chmod(0o600)
    link = tmp_path / "link"
    os.symlink(path, link)
    with pytest.raises(ValueError):
        load_key(link)


@pytest.mark.parametrize("content", ["", "\n", "sk-a sk-b", "x" * 513])
def test_load_key_rejects_empty_multiword_or_oversized(tmp_path, content):
    path = tmp_path / "openai-api-key"
    path.write_text(content)
    path.chmod(0o600)
    with pytest.raises(ValueError):
        load_key(path)
