"""Controller-owned model broker for a Harbor subprocess (issue #69).

The controller holds the ledger, provider key and `Meter`; the agent process
reaches the model only by sending its complete message list over a private Unix
socket. One request is served at a time in the controller's own thread, so the
ledger connection never crosses threads. Replies are `{"content": ...}` or
`{"error": "refused" | "unknown"}`; an unknown outcome marks the run halted.
"""

import json
import os
import select
import socket
import struct
import subprocess
import time
from pathlib import Path

from democratize_security.model_meter import Meter, MeterRefused

MAX_REQUEST_BYTES = 8 * 1024 * 1024
_DRAIN_LIMIT = 8 * MAX_REQUEST_BYTES
_READ_TIMEOUT_SECONDS = 30


def _peer_uid(connection) -> int:
    credentials = connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    return struct.unpack("3i", credentials)[1]


def _read_request(connection) -> bytes | None:
    """Read one newline- or EOF-terminated request; None if it is oversized."""
    connection.settimeout(_READ_TIMEOUT_SECONDS)
    chunks, size = [], 0
    while size <= _DRAIN_LIMIT:
        chunk = connection.recv(65536)
        if not chunk:
            break
        size += len(chunk)
        if size <= MAX_REQUEST_BYTES + 1:
            chunks.append(chunk)
        if b"\n" in chunk:
            break
    data = b"".join(chunks)
    return None if size > MAX_REQUEST_BYTES else data


def _messages(data: bytes | None):
    if data is None:
        return None
    try:
        request = json.loads(data)
    except ValueError:
        return None
    if not isinstance(request, dict) or set(request) != {"messages"}:
        return None
    return request["messages"] if isinstance(request["messages"], list) else None


class Broker:
    def __init__(self, meter: Meter, socket_path: Path):
        self.socket_path = Path(socket_path)
        # A fresh private directory: nothing else may already own this path.
        self.socket_path.parent.mkdir(mode=0o700)
        os.chmod(self.socket_path.parent, 0o700)
        self._meter = meter
        self._halted = False
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self._socket.listen(1)

    def _handle(self, connection) -> None:
        with connection:
            try:
                if _peer_uid(connection) != os.getuid():
                    return
                messages = _messages(_read_request(connection))
            except OSError:
                return
            if messages is None:
                reply = {"error": "refused"}
            else:
                try:
                    reply = {"content": self._meter.generate(messages)}
                except MeterRefused:
                    reply = {"error": "refused"}
                except Exception:
                    self._halted = True
                    reply = {"error": "unknown"}
            try:
                connection.sendall(json.dumps(reply).encode() + b"\n")
            except OSError:
                pass

    def serve(self, process: subprocess.Popen, *, deadline: float) -> str:
        """Serve requests until the process exits or the deadline passes."""
        while True:
            if process.poll() is not None:
                return "halted" if self._halted else "exited"
            if time.monotonic() >= deadline:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                return "deadline"
            ready, _, _ = select.select([self._socket], [], [], 1.0)
            if ready:
                connection, _ = self._socket.accept()
                self._handle(connection)

    def close(self) -> None:
        self._socket.close()
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
