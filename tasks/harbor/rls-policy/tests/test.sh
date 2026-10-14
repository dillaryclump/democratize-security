#!/bin/bash
set -euo pipefail
# A fresh private cluster owned by the unprivileged verifier user; no network
# listener, no external credentials and no privilege changes.
export PGDATA=/tmp/spike-postgres
mkdir -p "$PGDATA" /tmp/spike-socket
initdb -D "$PGDATA" --auth=trust > /tmp/initdb.log
trap 'pg_ctl -D "$PGDATA" -m immediate stop >/dev/null 2>&1 || true' EXIT
pg_ctl -D "$PGDATA" -l /tmp/spike-postgres.log \
    -o "-c listen_addresses='' -c unix_socket_directories=/tmp/spike-socket" -w start
python3 /tests/check.py
