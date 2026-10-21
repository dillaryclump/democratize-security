"""Controller-side model broker socket (issue #69); scripted providers, no network."""

import json
import stat
import subprocess
import sys
import time

import pytest
from test_model_meter import LIMITS, SOL, build_case, running

from democratize_security.model_broker import MAX_REQUEST_BYTES, Broker
from democratize_security.model_meter import Meter, ScriptedProvider
from democratize_security.store import PlanStore

CLIENT = """
import socket, sys
path, data = sys.argv[1], sys.stdin.buffer.read()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(path)
s.sendall(data)
s.shutdown(socket.SHUT_WR)
reply = b""
while chunk := s.recv(65536):
    reply += chunk
sys.stdout.buffer.write(reply)
"""


@pytest.fixture
def setup(tmp_path):
    case = build_case(tmp_path)
    with PlanStore(case["ledger"], objects_directory=case["artifact_dir"]) as store:
        running(case, store)
        yield case, store


def make(store, tmp_path, provider):
    meter = Meter(store, "r1", SOL, LIMITS, provider, reasoning_effort="medium")
    return Broker(meter, tmp_path / "broker" / "model.sock")


def exchange(broker, data: bytes, timeout=30):
    process = subprocess.Popen(
        [sys.executable, "-c", CLIENT, str(broker.socket_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    process.stdin.write(data)
    process.stdin.close()
    outcome = broker.serve(process, deadline=time.monotonic() + timeout)
    return outcome, process.stdout.read()


def request(messages):
    return json.dumps({"messages": messages}).encode() + b"\n"


def test_broker_round_trip_with_scripted_meter(setup, tmp_path):
    _, store = setup
    provider = ScriptedProvider(("hello from the model",))
    outcome, reply = exchange(
        make(store, tmp_path, provider), request([{"role": "user", "content": "hi"}])
    )
    assert outcome == "exited"
    assert json.loads(reply) == {"content": "hello from the model"}
    (state,) = store.attempts()
    assert state["request_count"] == 1 and state["open_request"] is None


@pytest.mark.parametrize(
    "data",
    [
        b"x" * (MAX_REQUEST_BYTES + 1),
        b"{not json}\n",
        b'{"messages": "hi"}\n',
        b'{"messages": [], "extra": 1}\n',
        b"[]\n",
    ],
    # Short ids: pytest copies the test id into the child's environment.
    ids=["oversized", "not-json", "messages-not-list", "extra-field", "not-object"],
)
def test_broker_rejects_oversized_and_malformed_requests_without_meter_call(setup, tmp_path, data):
    _, store = setup
    provider = ScriptedProvider(("unused",))
    outcome, reply = exchange(make(store, tmp_path, provider), data)
    assert outcome == "exited"
    assert json.loads(reply) == {"error": "refused"}
    assert (provider.counted, provider.sent) == (0, 0)


def test_unknown_outcome_reports_halted(setup, tmp_path):
    _, store = setup
    provider = ScriptedProvider(())  # Exhausted: the send itself fails after the intent.
    outcome, reply = exchange(
        make(store, tmp_path, provider), request([{"role": "user", "content": "hi"}])
    )
    assert json.loads(reply) == {"error": "unknown"}
    assert outcome == "halted"
    (state,) = store.attempts()
    assert state["unknown_requests"] == 1


def test_broker_deadline_kills_process(setup, tmp_path):
    _, store = setup
    broker = make(store, tmp_path, ScriptedProvider(()))
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    started = time.monotonic()
    assert broker.serve(process, deadline=started + 1) == "deadline"
    assert process.poll() is not None
    assert time.monotonic() - started < 20


def test_socket_dir_private(setup, tmp_path):
    _, store = setup
    broker = make(store, tmp_path, ScriptedProvider(()))
    assert stat.S_IMODE(broker.socket_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(broker.socket_path.stat().st_mode) == 0o600
    assert stat.S_ISSOCK(broker.socket_path.stat().st_mode)


def test_existing_socket_directory_is_refused(setup, tmp_path):
    _, store = setup
    (tmp_path / "broker").mkdir()
    with pytest.raises(FileExistsError):
        make(store, tmp_path, ScriptedProvider(()))


def test_close_removes_socket(setup, tmp_path):
    _, store = setup
    broker = make(store, tmp_path, ScriptedProvider(()))
    broker.close()
    assert not broker.socket_path.exists()
