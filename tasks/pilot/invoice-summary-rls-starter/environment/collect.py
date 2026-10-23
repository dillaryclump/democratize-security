"""Trusted artifact collector, run by Harbor in its own container after the
agent's container has stopped (a `[[verifier.collect]]` hook).

Reads one agent-written path without following links and requires a regular,
singly linked file within the size bound. Writes a fresh read-only copy, the
only thing Harbor collects and moves through the host. Anything else yields no
artifact, which the verifier grades as a missing submission.
"""

import os
import stat
import sys


def collect(source, target, limit):
    try:
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        return f"rejected: {type(error).__name__}"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return "rejected: not a regular, singly linked file"
        # Checked before reading, so a sparse file is never streamed.
        if info.st_size > limit:
            return "rejected: too large"
        chunks, size = [], 0
        while size <= limit:
            chunk = os.read(fd, limit + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    if size > limit:
        return "rejected: too large"
    data = b"".join(chunks)
    out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(out, "wb") as stream:
        os.fchmod(stream.fileno(), 0o444)
        stream.write(data)
    return f"collected {len(data)} bytes"


if __name__ == "__main__":
    print(collect(sys.argv[1], sys.argv[2], int(sys.argv[3])))
