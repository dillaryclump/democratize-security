#!/bin/bash
set -euo pipefail
# A fresh private cluster owned by the unprivileged verifier user. Its TCP
# listener is on the loopback interface shared only with the candidate app
# container, and only the restricted runtime role may log in there, with a
# per-run password. Setup uses the Unix socket in this container's private /tmp.
export PGDATA=/tmp/app-postgres
mkdir -p "$PGDATA" /tmp/app-socket
initdb -D "$PGDATA" --auth-local=peer --auth-host=reject --encoding=UTF8 --locale=C \
    > /tmp/initdb.log
printf '%s\n' 'local all postgres peer' \
    'host ds_app ds_runtime 127.0.0.1/32 scram-sha-256' > "$PGDATA/pg_hba.conf"
trap 'pg_ctl -D "$PGDATA" -m immediate stop >/dev/null 2>&1 || true' EXIT
pg_ctl -D "$PGDATA" -l /tmp/app-postgres.log -o "-c listen_addresses=127.0.0.1 \
    -c port=5432 -c unix_socket_directories=/tmp/app-socket" -w start
/opt/verifier/bin/python -I /tests/run.py
