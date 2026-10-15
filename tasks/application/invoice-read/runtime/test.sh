#!/bin/bash
set -euo pipefail
export PGDATA=/tmp/application-db
initdb -D "$PGDATA" --encoding=UTF8 --auth-local=peer --auth-host=scram-sha-256 >/tmp/initdb.log
# Only the restricted role authenticates by password. Peer auth prevents the
# application's uid 10001 from impersonating this container's postgres uid.
sed -i '1i local all invoice_runtime scram-sha-256' "$PGDATA/pg_hba.conf"
trap 'pg_ctl -D "$PGDATA" -m immediate stop >/dev/null 2>&1 || true' EXIT
pg_ctl -D "$PGDATA" -l /tmp/postgres.log -o "-c listen_addresses='' -c unix_socket_directories=/dbsocket" -w start
python -B /tests/check.py
