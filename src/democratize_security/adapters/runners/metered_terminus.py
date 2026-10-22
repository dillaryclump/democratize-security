"""Terminus2 agent whose model calls go only through the controller's broker (#69).

Runs inside the `harbor run` subprocess on the trusted host. It holds no provider
key or client: each call sends the complete message list to the controller's
`model_broker` socket, which meters, sends and settles the request. Any refusal,
unknown outcome or socket failure latches the client and raises
`TransportHalted`, a `ContextLengthExceededError`, which Terminus2's retry does
not retry; with summarization disabled the trial ends without another request.
This module imports Harbor; the core package must not.
"""

import asyncio
import json
import os
import socket

from harbor.llms.base import BaseLLM, ContextLengthExceededError, LLMResponse

from democratize_security.adapters.runners.terminus_conformance import PresenceCheckedTerminus

SOCKET_ENV = "DS_MODEL_BROKER_SOCKET"
METERED_BACKEND = "metered"
MAX_TURNS = 12
CONTEXT_LIMIT = 64000
OUTPUT_LIMIT = 25000
REPLY_TIMEOUT_SECONDS = 900
MAX_REPLY_BYTES = 16 * 1024 * 1024
ROLES = frozenset({"system", "user", "assistant"})


class TransportHalted(ContextLengthExceededError):
    """The broker refused or lost a request; no further model call is possible."""


class BrokeredLLM(BaseLLM):
    def __init__(self):
        super().__init__()
        self._latched = False

    def _exchange(self, messages: list[dict]) -> dict:
        path = os.environ.get(SOCKET_ENV)
        if not path:
            raise OSError("model broker socket is not configured")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(REPLY_TIMEOUT_SECONDS)
            connection.connect(path)
            connection.sendall(json.dumps({"messages": messages}).encode() + b"\n")
            connection.shutdown(socket.SHUT_WR)
            data = b""
            while len(data) <= MAX_REPLY_BYTES:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                data += chunk
        reply = json.loads(data)
        if not isinstance(reply, dict):
            raise ValueError("invalid broker reply")
        return reply

    async def call(self, prompt: str, message_history: list | None = None, **_) -> LLMResponse:
        if self._latched:
            raise TransportHalted("model transport halted earlier in this trial")
        try:
            messages = []
            for message in [*(message_history or []), {"role": "user", "content": prompt}]:
                role, content = message.get("role"), message.get("content")
                if role not in ROLES or type(content) is not str:
                    raise ValueError("unsupported message in history")
                messages.append({"role": role, "content": content})
            reply = await asyncio.to_thread(self._exchange, messages)
            if set(reply) != {"content"} or type(reply["content"]) is not str:
                raise ValueError(f"broker did not return content: {reply.get('error')}")
        except Exception as error:
            self._latched = True
            raise TransportHalted(f"model transport halted: {type(error).__name__}") from None
        # Harbor's usage/cost fields are never authoritative; the ledger is.
        return LLMResponse(content=reply["content"], model_name=METERED_BACKEND, usage=None)

    def get_model_context_limit(self) -> int:
        return CONTEXT_LIMIT

    def get_model_output_limit(self) -> int | None:
        return OUTPUT_LIMIT


class MeteredTerminus(PresenceCheckedTerminus):
    def __init__(self, logs_dir, *args, **kwargs):
        # Fixed, finite options regardless of what a caller passes.
        kwargs.update(
            model_name="metered-terminus",
            max_turns=MAX_TURNS,
            enable_summarize=False,
            proactive_summarization_threshold=0,
            record_terminal_session=False,
            suppress_max_turns_warning=True,
            llm_backend=METERED_BACKEND,
        )
        super().__init__(logs_dir, *args, **kwargs)

    @staticmethod
    def name() -> str:
        return "metered-terminus"

    def _init_llm(self, llm_backend, **_) -> BaseLLM:
        if llm_backend != METERED_BACKEND:
            raise ValueError("metered agents only use the brokered backend")
        return BrokeredLLM()
