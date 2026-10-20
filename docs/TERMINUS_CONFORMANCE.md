# Model-free Terminus2 transport conformance

Issue #63. This proves that Harbor 0.24.0's real Terminus2 agent loop can drive
the audited invoice-read candidate container end to end: JSON parsing, tmux
command execution as the unprivileged agent user, and Terminus2's two-step
completion confirmation, followed by the trusted collector, separate verifier,
sealing, sealed replay and host-observed boundary audit. It is an infrastructure
prerequisite for real agent trials, **not** evidence of any model's capability,
a research result, or a cost measurement.

## What runs

`src/democratize_security/adapters/runners/terminus_conformance.py` is the only
module that imports Harbor for this purpose.

- `ScriptedLLM` replaces Terminus2's model. It returns a fixed tuple of
  responses in order and raises `ScriptExhausted` after the last. No LiteLLM,
  provider client, API key or network request is constructed; unit tests
  replace `LiteLLM` with a function that fails if called.
- The agents force `max_turns=6`, no summarization, no terminal recording and
  the `scripted` backend, whatever options a caller passes. Any other backend is
  rejected.
- `PresenceCheckedTmuxSession` replaces Terminus2's root `apt`/`pip` tool
  install with `tmux -V` run as the environment's default (unprivileged) user,
  and fails closed if tmux is missing. The candidate stays rootless, read-only
  and offline, so tmux must be baked into the image at build time.

`scripts/terminus_conformance.py` copies `tasks/harbor/invoice-read` to
`.research/terminus-conformance/task` and inserts one Dockerfile line before
`ENTRYPOINT` that installs tmux. Every other task file is byte-identical, which a
unit test checks; the canonical task is never modified. It then runs:

| Control | Agent | Expectation |
| --- | --- | --- |
| `scripted` | `ScriptedReferenceTerminus`: one command decodes the reviewed reference app into `/candidate/app.py`, then `task_complete` twice | every verifier check `pass`, reward 1 |
| `malformed` | `MalformedTerminus`: six invalid-JSON responses | starter collected unchanged; exactly the reviewed `nop` outcomes, reward 0 |
| `replay` | Harbor `nop` on a task rebuilt from the sealed `scripted` artifact | same outcomes and artifact hash as the seal |

Acceptance reuses `harbor_apps.accept_app` (nonce-bound evidence, exact
expected check outcomes, collected-artifact hash) and the v5 boundary audit,
which must pass for every trial with exactly one app container. The script
refuses a reused output directory and Harbor versions other than 0.24.0. With
`DS_WORKER_HOST_REQUIRED=1`, `.research/terminus-conformance` jobs get bounded
filesystems on the dedicated worker (see [WORKER_HOST.md](WORKER_HOST.md)).

The `terminus-conformance` CI job runs the unit tests with
`REQUIRE_HARBOR_TESTS=1` (a missing Harbor fails rather than skips) and then the
three live controls, with a 30-minute command and 35-minute job ceiling.

## Observed

Local run, 2026-10-20, source `90d8acc`, Docker Engine 29.9.1 on the WSL2 dev
distro (no bounded job storage, so the audit also reports
`trial_storage_unbounded`):

- `scripted`: four trajectory steps, the prompt, one `bash_command` through
  tmux, then two `mark_task_complete` calls; reward 1, all checks pass.
- `malformed`: six invalid responses, no command executed; reward 0 with the
  exact `nop` outcomes.
- `replay`: reward 1 with the sealed artifact hash.
- All three audits passed with complete coverage, zero trial egress connections
  and the candidate container at uid 10001, read-only root filesystem,
  `network: none` and all capabilities dropped. Built candidate image
  `sha256:d113ab72a22fd35f5ba895c7ac7ca6e530f0c534d806d8a0a828bfad2ba74507`.

Dedicated worker run, 2026-10-20, source `1561d26` (`git archive` SHA-256
`3bc375d8...0f3a`), with `DS_WORKER_HOST_REQUIRED=1`: all three controls
accepted with the same outcomes; all three audits passed with complete coverage
and `own_filesystem: true` at 58,675,200 bytes, leaving only the two documented
verifier gaps; all three jobs were archived and released in the same session.
Built candidate image
`sha256:483b5f607bf5d45043ac5a764cbc8ec1c47a26ce2cfff628c118b07a68bc9030`.
Full suite on that head: 1082 passed with PostgreSQL, Docker and Harbor tests required.

## Limitations

- tmux is installed from the Debian archive at image build time, so the built
  image is recorded per run rather than reproducible from a digest alone.
- The scripted response embeds the reference app as base64 in one tmux command;
  a unit test keeps that payload under 12 KiB, below tmux's message limit.
- This exercises one task (invoice-read) and one parser format (JSON). It does
  not measure tokens, cost, retries, context limits or summarization, all of
  which are disabled or fixed here.
- No result is admitted into the store; runtime lifecycle and authenticated
  admission are #62.
