#!/bin/bash
# Model-free worker acceptance run (issue #54). Run as the configured controller
# inside a fresh /srv/democratize-security copy on the dedicated worker, after
# bootstrap.sh and check_host.py. Launches no model and needs no credentials.
#
# Archive and release happen in this same session: a WSL2 distro that goes idle
# is stopped, which drops loop mounts like a reboot, and the helper deliberately
# does not reconcile after reboot.
set -uo pipefail
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
REPO=/srv/democratize-security
HELPER=/usr/local/libexec/ds-worker-host
LOGS=${1:?usage: regressions.sh NEW_LOG_DIRECTORY}
mkdir "$LOGS" || exit 1
cd "$REPO" || exit 1
D=(docker --host unix:///var/run/docker.sock)
note() { echo "$*" | tee -a "$LOGS/SUMMARY"; }

"${D[@]}" pull -q alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 > "$LOGS/pull.log" 2>&1
"${D[@]}" pull -q python:3.12-slim >> "$LOGS/pull.log" 2>&1
"${D[@]}" pull -q postgres:17 >> "$LOGS/pull.log" 2>&1
TEST_WORKER_IMAGE_ID=$("${D[@]}" image inspect python:3.12-slim --format '{{.Id}}')
export TEST_WORKER_IMAGE_ID
note "images python:3.12-slim=$TEST_WORKER_IMAGE_ID postgres:17=$("${D[@]}" image inspect postgres:17 --format '{{.Id}}')"

# Full suite with real PostgreSQL and Docker required; a skip fails the run.
uv sync --locked --extra reference > "$LOGS/sync-reference.log" 2>&1
database=ds-worker-pg-$$
"${D[@]}" run --rm --name "$database" -e POSTGRES_PASSWORD=synthetic-local-only \
  -p 127.0.0.1:55432:5432 -d postgres:17 > /dev/null
for _ in $(seq 1 30); do "${D[@]}" exec "$database" pg_isready -q && break; sleep 2; done
TEST_POSTGRES_ADMIN_DSN='postgresql://postgres:synthetic-local-only@127.0.0.1:55432/postgres' \
REQUIRE_POSTGRES_TESTS=1 REQUIRE_DOCKER_TESTS=1 \
  uv run --locked --extra reference pytest -ra -p no:cacheprovider > "$LOGS/pytest.log" 2>&1
note "pytest rc=$? $(tail -1 "$LOGS/pytest.log")"
"${D[@]}" stop "$database" > /dev/null

# Harbor controls with mandatory per-trial bounded job filesystems.
uv sync --locked --group harbor > "$LOGS/sync-harbor.log" 2>&1
export DS_WORKER_HOST_REQUIRED=1
run() {
  local name
  name=$(echo "$*" | tr ' /' '__')
  uv run --locked --group harbor python "$@" > "$LOGS/$name.log" 2>&1
  note "$name rc=$?"
}
run scripts/harbor_replay.py
run scripts/harbor_audit.py
for task in invoice-read invoice-search invoice-export; do run scripts/harbor_apps.py "$task"; done

# Archive, then release, every job this run mounted. The helper refuses while
# any container still references a job; such jobs stay mounted for inspection.
for parent in harbor-spike harbor-replay harbor-audit harbor-apps/invoice-read \
  harbor-apps/invoice-search harbor-apps/invoice-export; do
  directory=$REPO/.research/$parent
  [ -d "$directory" ] || continue
  for job in "$directory"/*/; do
    job=${job%/}
    mountpoint -q "$job" || continue
    name=$(basename "$job")
    if sudo -n "$HELPER" archive "$directory" "$name" >> "$LOGS/archive.log" 2>&1 \
      && sudo -n "$HELPER" release "$directory" "$name" >> "$LOGS/archive.log" 2>&1; then
      note "released $parent/$name"
    else
      note "RETAINED $parent/$name (archive or release refused; inspect)"
    fi
  done
done
note "remaining job mounts: $(findmnt -rn -o TARGET | grep -c "^$REPO/.research/")"
note ALL-DONE
