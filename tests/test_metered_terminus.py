"""Harbor Terminus2 client of the controller's model broker (issue #69).

No model, provider or network: a local test socket stands in for the broker.
Set REQUIRE_HARBOR_TESTS=1 so an unavailable Harbor fails rather than skips.
"""

import asyncio
import json
import os
import socket
import threading
from types import SimpleNamespace

import pytest

if os.environ.get("REQUIRE_HARBOR_TESTS") == "1":
    import harbor  # noqa: F401
else:
    pytest.importorskip("harbor")

from harbor.agents.terminus_2 import terminus_2 as upstream  # noqa: E402
from harbor.llms.base import ContextLengthExceededError  # noqa: E402
from harbor.llms.chat import Chat  # noqa: E402

from democratize_security.adapters.runners import metered_terminus as mt  # noqa: E402


class FakeBroker:
    """Answer each connection with the next scripted reply and record requests."""

    live = []

    def __init__(self, path, replies):
        self.path, self.replies, self.requests = path, list(replies), []
        self.stopped = threading.Event()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(path))
        self.sock.listen(4)
        self.sock.settimeout(0.05)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        FakeBroker.live.append(self)

    def stop(self):
        self.stopped.set()
        self.thread.join(timeout=5)
        self.sock.close()

    def _run(self):
        while self.replies and not self.stopped.is_set():
            try:
                connection, _ = self.sock.accept()
            except TimeoutError:
                continue
            connection.settimeout(None)
            with connection:
                data = b""
                while not data.endswith(b"\n"):
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                self.requests.append(json.loads(data))
                connection.sendall(json.dumps(self.replies.pop(0)).encode() + b"\n")

    @property
    def accepts(self):
        return len(self.requests)


@pytest.fixture(autouse=True)
def stop_fake_brokers():
    # No thread may outlive its test: later tests fork the process.
    yield
    while FakeBroker.live:
        FakeBroker.live.pop().stop()


@pytest.fixture
def broker_path(tmp_path, monkeypatch):
    path = tmp_path / "model.sock"
    monkeypatch.setenv(mt.SOCKET_ENV, str(path))
    return path


@pytest.fixture
def no_litellm(monkeypatch):
    def forbidden(*_, **__):
        raise AssertionError("LiteLLM must never be constructed")

    monkeypatch.setattr(upstream, "LiteLLM", forbidden)


def test_call_sends_complete_history_and_returns_content(broker_path):
    fake = FakeBroker(broker_path, [{"content": "next step"}])
    llm = mt.BrokeredLLM()
    history = [{"role": "user", "content": "task"}, {"role": "assistant", "content": "ok"}]
    response = asyncio.run(
        llm.call("screen", message_history=history, previous_response_id="resp_ignored")
    )
    assert response.content == "next step"
    assert response.usage is None
    assert fake.requests == [{"messages": [*history, {"role": "user", "content": "screen"}]}]


def test_latched_client_never_contacts_broker_again(broker_path):
    fake = FakeBroker(broker_path, [{"error": "unknown"}, {"content": "must not be used"}])
    llm = mt.BrokeredLLM()
    with pytest.raises(mt.TransportHalted):
        asyncio.run(llm.call("p"))
    with pytest.raises(mt.TransportHalted):
        asyncio.run(llm.call("p"))
    assert fake.accepts == 1
    assert issubclass(mt.TransportHalted, ContextLengthExceededError)


def test_missing_broker_latches(broker_path):
    llm = mt.BrokeredLLM()
    with pytest.raises(mt.TransportHalted):
        asyncio.run(llm.call("p"))
    FakeBroker(broker_path, [{"content": "late"}])
    with pytest.raises(mt.TransportHalted):
        asyncio.run(llm.call("p"))


def test_unknown_history_roles_latch_without_contact(broker_path):
    fake = FakeBroker(broker_path, [{"content": "unused"}])
    llm = mt.BrokeredLLM()
    with pytest.raises(mt.TransportHalted):
        asyncio.run(llm.call("p", message_history=[{"role": "tool", "content": "x"}]))
    assert fake.accepts == 0


def test_transport_halted_is_not_retried_by_query_llm(broker_path):
    fake = FakeBroker(broker_path, [{"error": "refused"}, {"content": "a"}, {"content": "b"}])
    agent = SimpleNamespace(
        _llm_call_kwargs={},
        _api_request_times=[],
        options=SimpleNamespace(enable_summarize=False),
        logger=SimpleNamespace(debug=lambda *a, **k: None, error=lambda *a, **k: None),
    )
    chat = Chat(mt.BrokeredLLM())
    with pytest.raises(mt.TransportHalted):
        asyncio.run(upstream.Terminus2._query_llm(agent, chat, "prompt"))
    assert fake.accepts == 1


def test_metered_terminus_forces_finite_options(tmp_path, broker_path, no_litellm):
    agent = mt.MeteredTerminus(
        logs_dir=tmp_path,
        model_name="ignored-provider/model",
        max_turns=500,
        enable_summarize=True,
        record_terminal_session=True,
        llm_backend="litellm",
    )
    assert agent.options.max_turns == 12
    assert agent.options.enable_summarize is False
    assert agent.options.proactive_summarization_threshold == 0
    assert agent.options.record_terminal_session is False
    assert agent.options.llm_backend == "metered"
    assert isinstance(agent._llm, mt.BrokeredLLM)
    assert mt.MeteredTerminus.name() == "metered-terminus"


def test_limits_match_calibration_caps():
    llm = mt.BrokeredLLM()
    assert llm.get_model_context_limit() == 64000
    assert llm.get_model_output_limit() == 25000
