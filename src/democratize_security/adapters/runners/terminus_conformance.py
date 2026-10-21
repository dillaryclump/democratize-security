"""Model-free Terminus2 transport conformance fixtures for pinned Harbor 0.24.0.

Trusted infrastructure checks only (issue #63). A fixed in-process script stands
in for the model, so Harbor's real Terminus2 parser, tmux command loop and
completion confirmation drive the audited candidate container without any
provider, client, key or network request. Scripted output is never evidence of
model capability or a research result. This module imports Harbor; the rest of
the core package must not import it.
"""

import base64
import json
from pathlib import Path

from harbor.agents.terminus_2.terminus_2 import Terminus2
from harbor.agents.terminus_2.tmux_session import TmuxSession
from harbor.llms.base import BaseLLM, LLMResponse
from harbor.models.trial.paths import EnvironmentPaths

REFERENCE_APP = (Path(__file__).resolve().parents[2] / "reference/app.py").read_bytes()
SCRIPTED_BACKEND = "scripted"
MAX_TURNS = 6
COMPLETE = json.dumps(
    {"analysis": "done", "plan": "confirm", "commands": [], "task_complete": True}
)


class ScriptExhausted(RuntimeError):
    """The fixed script has no response left; the trial must not be accepted."""


class ScriptedLLM(BaseLLM):
    """Return a fixed tuple of responses in order, then refuse further calls."""

    def __init__(self, responses: tuple[str, ...]):
        if type(responses) is not tuple or not all(type(r) is str for r in responses):
            raise TypeError("scripted responses must be a fixed tuple of strings")
        super().__init__()
        self._responses = responses
        self._calls = 0

    @property
    def calls(self) -> int:
        return self._calls

    async def call(self, prompt: str, **kwargs) -> LLMResponse:
        if self._calls >= len(self._responses):
            raise ScriptExhausted(f"script exhausted after {self._calls} responses")
        response = self._responses[self._calls]
        self._calls += 1
        return LLMResponse(content=response, model_name=SCRIPTED_BACKEND, usage=None)

    def get_model_context_limit(self) -> int:
        return 32768

    def get_model_output_limit(self) -> int | None:
        return 4096


class PresenceCheckedTmuxSession(TmuxSession):
    """Require tmux baked into the image; never fall back to Harbor's root install."""

    async def _attempt_tmux_installation(self) -> None:
        result = await self.environment.exec(command="tmux -V", user=self._user)
        if result.return_code != 0:
            raise RuntimeError("tmux missing for unprivileged agent user")


def reference_response() -> str:
    """Write the reviewed reference app through one terminal command."""
    encoded = base64.b64encode(REFERENCE_APP).decode()
    command = f"printf '%s' '{encoded}' | base64 -d > /candidate/app.py\n"
    return json.dumps(
        {
            "analysis": "Scripted conformance: install the reviewed reference app.",
            "plan": "Decode the fixed reference bytes into the candidate path.",
            "commands": [{"keystrokes": command, "duration": 1.0}],
            "task_complete": False,
        }
    )


class PresenceCheckedTerminus(Terminus2):
    """Terminus2 whose tmux session must already exist in the image."""

    async def setup(self, environment) -> None:
        self._session = PresenceCheckedTmuxSession(
            session_name=self.name(),
            environment=environment,
            logging_path=EnvironmentPaths.agent_dir / "terminus_2.pane",
            local_asciinema_recording_path=None,
            remote_asciinema_recording_path=None,
            pane_width=self.options.tmux_pane_width,
            pane_height=self.options.tmux_pane_height,
            extra_env=self._extra_env,
            user=environment.default_user,
        )
        await self._session.start()


class _ScriptedTerminus(PresenceCheckedTerminus):
    SCRIPT: tuple[str, ...] = ()

    def __init__(self, logs_dir: Path, *args, **kwargs):
        # Fixed, finite options regardless of what a caller passes.
        kwargs.update(
            model_name="scripted-conformance",
            max_turns=MAX_TURNS,
            enable_summarize=False,
            record_terminal_session=False,
            suppress_max_turns_warning=True,
            llm_backend=SCRIPTED_BACKEND,
        )
        super().__init__(logs_dir, *args, **kwargs)

    @staticmethod
    def name() -> str:
        return "scripted-terminus"

    def _init_llm(self, llm_backend, **_) -> BaseLLM:
        if llm_backend != SCRIPTED_BACKEND:
            raise ValueError("conformance agents only use the scripted backend")
        return ScriptedLLM(self.SCRIPT)


class ScriptedReferenceTerminus(_ScriptedTerminus):
    """Install the reference app, then confirm completion twice as Terminus2 requires."""

    SCRIPT = (reference_response(), COMPLETE, COMPLETE)


class MalformedTerminus(_ScriptedTerminus):
    """Never produce valid JSON; the turn limit ends the trial with the starter intact."""

    SCRIPT = ("this is not json",) * MAX_TURNS
