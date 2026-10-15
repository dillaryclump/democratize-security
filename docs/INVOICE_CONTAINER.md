# Invoice application container integration

This adds a Harbor replay for the reviewed invoice-read application controls.
It is not approval for generated or hostile code, and does not complete M2.

## Topology

Harbor's agent receives a sealed app.py and runs nop. It stops before the separate
verifier environment starts. That environment has two distinct containers:

- `main`: trusted PostgreSQL setup, independent HTTP/database verifier, and the
  per-run grading nonce delivered only to the verifier exec.
- `app`: the sealed application plus a trusted readiness launcher. It receives
  only the restricted runtime DSN. It has no verifier code, logs, nonce, database
  files, host socket or repository mount.

Both use `network_mode: none`. PostgreSQL listens only on `/dbsocket`, a shared
volume writable by the verifier and read-only to the app. Runtime authentication
uses SCRAM; peer authentication for postgres prevents the app's uid 10001 from
impersonating the setup role. PostgreSQL data lives in the verifier's private
bounded tmpfs. The app serves HTTP on `/appsock/app.sock`, with that shared volume
writable by the app and read-only to the verifier. Socket access does not require
an IP network. The app cannot alter either container's read-only root.

The verifier main retains Harbor's reviewed housekeeping capabilities. The app
runs as 10001:10001, drops every capability, disallows privilege gain, has one CPU,
256 MiB RAM with no extra swap, 64 PIDs and a bounded temporary filesystem.
Named socket volumes still lack enforced disk quotas. Shared kernel risks remain.

## Artifact and grade binding

`scripts/harbor_invoice_read.py` runs exactly three finite nop trials, no retries
or models: correct application, ID-derived-tenant leak, and deny-all. Each source
is sealed, then replaced with a crashing sentinel. `invoice_task.prepare_task`
uses only the validated bundle to build the agent file and application image.
Only app.py, a trusted launcher, Dockerfile and locked requirements enter the
application build context. No submitted build instructions run.

The independent verifier never imports app.py. It checks the transferred file's
hash against the application image input recorded by the trusted task builder,
then runs all eight synthetic-reference-v2 HTTP/database checks. It emits a
nonce-authenticated result. Host acceptance requires complete coverage, exactly
the intended check outcomes, authentic evidence and equality with the original
seal. The controller records artifact, task and verifier source hashes.

A Docker event observer captures the app and verifier configurations. An additional
application-boundary check requires their distinct images, users, networking,
resource restrictions, paired socket mounts, and absence of the nonce in container
configuration. It is supplemental to the existing policy forgery audit, which
remains a separate CI gate. The new topology is not claimed to pass the old
policy-only audit unchanged. Image IDs are recorded; base images and pip package
hashes are pinned. Requirements are exported from uv.lock for the reference extra.

## Reproduce

On a disposable Linux Docker host:

```bash
uv sync --locked --group harbor
uv run --locked --group harbor python scripts/harbor_invoice_read.py
```

Output `.research/harbor-invoice-read` must not exist. Each trial has the existing
600-second host deadline; the verifier phase has 180 seconds. CI job
`harbor-invoice-read` has a 25-minute outer deadline. The only credentials generated
here are disposable synthetic runtime passwords and verifier nonces. Runtime
passwords exist in local generated task configuration; no production data is used.

## Status and next work

Local: 173 passed, 23 infrastructure skips, Ruff passes, generated task loads with
pinned Harbor 0.24.0. Live CI is pending. Remaining work includes task-generation
rather than nop replay, list/search and CSV task families, stronger lifecycle/
mount auditing for the expanded topology, enforced volume storage bounds, durable
records, recovery and explicit dedicated-host/model-budget gates. Do not run
arbitrary app.py through this reviewed-control integration.
