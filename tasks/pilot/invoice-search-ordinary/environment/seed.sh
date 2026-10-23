#!/bin/sh
# Trusted entrypoint of the agent image. Docker does not populate the
# size-bounded tmpfs submission volume from the image, so this copies the
# reviewed starter in before Harbor's command runs. The compose healthcheck
# holds Harbor's `up --wait`, and so the agent, until the marker exists.
set -eu
cp -R --preserve=mode,timestamps /opt/starter/. /candidate/
: > /tmp/.seeded
exec "$@"
