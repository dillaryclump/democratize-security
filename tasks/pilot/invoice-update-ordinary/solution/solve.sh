#!/bin/sh
set -eu
# Separate verifier source must not have been copied into the agent container.
test ! -e /tests/run.py
# The reviewed reference app is the oracle for every application task.
cp /solution/app.py /candidate/app.py
