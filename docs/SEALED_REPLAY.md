# Sealed policy replay

This M2 prerequisite adds fresh Harbor verification of pre-existing sealed policy
bytes. It remains a public declarative fixture, not the three application tasks.

## Run

```bash
uv sync --locked --group harbor
uv run --locked --group harbor python scripts/harbor_replay.py
```

Use a disposable Linux Docker host and fresh checkout. The command performs four
finite, sequential, model-free trials with no retries: oracle and nop generation
controls, then one nop replay for each sealed output. Each process is bounded to
600 seconds. Existing output directories cause refusal. The `harbor-spike` CI
job runs the whole sequence, with a 30-minute job deadline.

## What is authoritative

The first two grades are diagnostic. Their captured policy files are sealed by
the existing bounded artifact module. Replay loads and validates those bundles
before creating any task. Only the single `policy.json` file, at most 4096 bytes,
is accepted. A fresh task copies trusted verifier/configuration files and puts
only sealed policy bytes plus a fixed Dockerfile in the agent build context.
It never copies the original solution or consults the original candidate file.
The replay agent is always nop; it cannot call a model or modify the submission.

Harbor performs the fresh run with the separate verifier. Host acceptance requires
complete expected checks and equality between the replayed artifact and the
pre-verification seal, as well as the verifier's input hash. Mismatches prevent
publication of accepted replay evidence. A record binds the original artifact,
trusted verifier source hash, generated task manifest and accepted result using
the existing evidence envelope. `security_verdict` remains `not_evaluated` because
this is infrastructure evidence, not an application assessment.

Code: `policy_replay.py` prepares and binds data without importing Harbor;
`scripts/harbor_replay.py` owns the fixed trial sequence. Existing
`scripts/harbor_spike.py` checks actual Harbor results.

## Limits

The seal is now an input to replay verification, rather than only a post-hoc
comparison. However, Harbor still collects/transfers files before host acceptance;
this change does not make its extraction safe for arbitrary hostile workers.
The code supports reviewed JSON policies only. Image tags and apt packages remain
mutable; task/verifier source hashes do not identify the entire runtime image.
No dedicated-host approval, protected tests, model budget, persistence/recovery,
or application-task gate is implied. Outputs on hosted CI runners are ephemeral;
checked summaries are printed to logs, with observed evidence recorded below.

Next: pin runtime images and audit actual mounts/resource controls, then integrate
three real application tasks with independent HTTP/database checks. Preserve this
small replay regression when expanding the runner.

## Validation

Local locked environment: 82 tests passed, 20 optional/infrastructure tests skipped;
Ruff passed. Pinned Harbor successfully loads a generated replay task. Regression
checks cover changed source after sealing, malformed/tampered/oversized bundles,
extra files, stale destinations, evidence overwrite and mismatched replay output.
Live Docker acceptance is pending CI; local skips are not execution evidence.
