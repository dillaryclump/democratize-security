#!/bin/bash
set -euo pipefail
# A fresh private cluster; no network listener and no external credentials.
export PGDATA=/tmp/spike-postgres
install -d -o postgres -g postgres "$PGDATA" /tmp/spike-socket
runuser -u postgres -- initdb -D "$PGDATA" --auth=trust > /tmp/initdb.log
trap 'runuser -u postgres -- pg_ctl -D "$PGDATA" -m immediate stop >/dev/null 2>&1 || true' EXIT
runuser -u postgres -- pg_ctl -D "$PGDATA" -l /tmp/spike-postgres.log \
    -o "-c listen_addresses='' -c unix_socket_directories=/tmp/spike-socket" -w start
python3 /tests/check.py
