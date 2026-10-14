#!/bin/sh
set -eu
# Separate verifier source must not have been copied into the agent container.
test ! -e /tests/check.py
printf '%s\n' '{"enabled":true,"predicate":"tenant"}' > /candidate/policy.json
