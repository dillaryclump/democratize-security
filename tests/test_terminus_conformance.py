"""Model-free Terminus2 transport conformance fixtures (issue #63).

These need the optional Harbor group. The dedicated CI job sets
REQUIRE_HARBOR_TESTS=1 so an unavailable Harbor fails rather than skips.
"""

import asyncio
import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

if os.environ.get("REQUIRE_HARBOR_TESTS") == "1":
    import harbor  # noqa: F401
else:
    pytest.importorskip("harbor")

from harbor.agents.terminus_2 import terminus_2 as upstream  # noqa: E402
from harbor.agents.terminus_2.terminus_json_plain_parser import (  # noqa: E402
    TerminusJSONPlainParser,
)

from democratize_security.adapters.runners import terminus_conformance as tc  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "tasks/harbor/invoice-read/solution/app.py"


def test_scripted_llm_returns_fixed_responses_then_exhausts():
    llm = tc.ScriptedLLM(("first", "second"))
    assert asyncio.run(llm.call("prompt")).content == "first"
    response = asyncio.run(llm.call("prompt"))
    assert response.content == "second"
    assert response.usage is None
    with pytest.raises(tc.ScriptExhausted):
        asyncio.run(llm.call("prompt"))
    assert llm.calls == 2
    assert llm.get_model_context_limit() == 32768
    assert llm.get_model_output_limit() == 4096


def test_scripted_llm_requires_a_fixed_tuple_of_strings():
    with pytest.raises(TypeError):
        tc.ScriptedLLM(["mutable"])
    with pytest.raises(TypeError):
        tc.ScriptedLLM(("ok", 3))


def test_reference_response_parses_with_real_terminus_parser():
    result = TerminusJSONPlainParser().parse_response(tc.reference_response())
    assert result.error == ""
    assert result.is_task_complete is False
    assert len(result.commands) == 1
    keystrokes = result.commands[0].keystrokes
    assert keystrokes.endswith(" | base64 -d > /candidate/app.py\n")
    prefix, fmt, space, encoded, suffix = keystrokes.split("'")
    assert (prefix, fmt, space) == ("printf ", "%s", " ")
    assert base64.b64decode(encoded, validate=True) == ORACLE.read_bytes()


def test_reference_payload_fits_tmux_message_limit():
    # tmux rejects client commands above roughly 16 KiB; keep a wide margin.
    assert len(tc.reference_response().encode()) < 12 * 1024


def test_completion_response_confirms_with_no_commands():
    result = TerminusJSONPlainParser().parse_response(tc.COMPLETE)
    assert result.error == ""
    assert result.is_task_complete is True
    assert result.commands == []


class FakeEnvironment:
    default_user = "agent"

    def __init__(self, return_code):
        self.return_code = return_code
        self.calls = []

    async def exec(self, command, user=None, **_):
        self.calls.append((command, user))
        return SimpleNamespace(return_code=self.return_code, stdout="tmux 3.3a", stderr="")


def session(environment):
    return tc.PresenceCheckedTmuxSession(
        session_name="scripted-terminus",
        environment=environment,
        logging_path=Path("/logs/agent/terminus_2.pane"),
        local_asciinema_recording_path=None,
        remote_asciinema_recording_path=None,
        pane_width=160,
        pane_height=40,
        extra_env=None,
        user=environment.default_user,
    )


def test_presence_check_runs_unprivileged_and_passes_when_tmux_exists():
    environment = FakeEnvironment(0)
    asyncio.run(session(environment)._attempt_tmux_installation())
    assert environment.calls == [("tmux -V", "agent")]


def test_presence_check_fails_closed_without_root_install():
    environment = FakeEnvironment(1)
    with pytest.raises(RuntimeError, match="tmux missing for unprivileged agent user"):
        asyncio.run(session(environment)._attempt_tmux_installation())
    assert all(user != "root" for _, user in environment.calls)
    assert len(environment.calls) == 1


@pytest.fixture
def no_litellm(monkeypatch):
    def forbidden(*_, **__):
        raise AssertionError("LiteLLM must never be constructed")

    monkeypatch.setattr(upstream, "LiteLLM", forbidden)


@pytest.mark.parametrize("agent", [tc.ScriptedReferenceTerminus, tc.MalformedTerminus])
def test_agents_never_construct_litellm(agent, tmp_path, no_litellm):
    instance = agent(logs_dir=tmp_path)
    assert isinstance(instance._llm, tc.ScriptedLLM)
    assert instance._llm.calls == 0
    assert agent.name() == "scripted-terminus"


@pytest.mark.parametrize("agent", [tc.ScriptedReferenceTerminus, tc.MalformedTerminus])
def test_agents_force_finite_options(agent, tmp_path, no_litellm):
    instance = agent(
        logs_dir=tmp_path,
        model_name="ignored-provider/model",
        max_turns=500,
        enable_summarize=True,
        record_terminal_session=True,
        llm_backend="litellm",
    )
    assert instance.options.max_turns == 6
    assert instance.options.enable_summarize is False
    assert instance.options.record_terminal_session is False
    assert instance.options.llm_backend == "scripted"


def test_reference_script_requires_confirmation():
    assert tc.ScriptedReferenceTerminus.SCRIPT == (
        tc.reference_response(),
        tc.COMPLETE,
        tc.COMPLETE,
    )


def test_malformed_script_never_completes_within_the_turn_limit():
    script = tc.MalformedTerminus.SCRIPT
    assert len(script) == 6
    for response in script:
        with pytest.raises(json.JSONDecodeError):
            json.loads(response)


def test_non_scripted_backend_is_rejected(tmp_path, no_litellm):
    instance = tc.ScriptedReferenceTerminus(logs_dir=tmp_path)
    with pytest.raises(ValueError, match="scripted"):
        instance._init_llm(
            llm_backend="litellm",
            model_name="x",
            temperature=None,
            collect_rollout_details=False,
            llm_kwargs=None,
            api_base=None,
            session_id=None,
            max_thinking_tokens=None,
            reasoning_effort=None,
            model_info=None,
            use_responses_api=False,
        )


def test_reference_bytes_match_every_task_oracle():
    for name in ("invoice-read", "invoice-search", "invoice-export"):
        assert (ROOT / f"tasks/harbor/{name}/solution/app.py").read_bytes() == tc.REFERENCE_APP


@pytest.fixture(scope="module")
def conformance():
    import runpy
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        yield runpy.run_path(str(ROOT / "scripts/terminus_conformance.py"))
    finally:
        sys.path.remove(str(ROOT / "scripts"))


def test_derived_task_differs_only_by_baked_tmux(conformance, tmp_path):
    canonical = ROOT / "tasks/harbor/invoice-read"
    before = {p: p.read_bytes() for p in canonical.rglob("*") if p.is_file()}
    derived = tmp_path / "task"
    conformance["prepare_terminus_task"](canonical, derived)
    assert {p: p.read_bytes() for p in canonical.rglob("*") if p.is_file()} == before
    files = sorted(p.relative_to(derived) for p in derived.rglob("*") if p.is_file())
    assert files == sorted(p.relative_to(canonical) for p in before)
    for relative in files:
        if relative.as_posix() != "environment/Dockerfile":
            assert (derived / relative).read_bytes() == (canonical / relative).read_bytes()
    original = (canonical / "environment/Dockerfile").read_text().splitlines(keepends=True)
    changed = (derived / "environment/Dockerfile").read_text().splitlines(keepends=True)
    entry = next(i for i, line in enumerate(original) if line.startswith("ENTRYPOINT "))
    assert changed == original[:entry] + [conformance["TMUX"]] + original[entry:]
    assert (derived / "solution/solve.sh").stat().st_mode & 0o111


def test_conformance_output_is_allowlisted_for_bounded_worker_storage():
    import runpy

    helper = runpy.run_path(str(ROOT / "scripts/worker_host.py"))
    assert "terminus-conformance" in helper["PARENTS"]
