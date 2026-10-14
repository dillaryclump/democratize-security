# Harbor worker boundary audit

Status: M2 prerequisite, audit policy `harbor-docker-boundary-v2`. This records
what one trusted Docker daemon actually configured for one reviewed, model-free
Harbor 0.24.0 trial. It is not a container-escape proof and does not approve
hostile or model-generated candidates.

## Run

```bash
uv sync --locked --group harbor
uv run --locked --group harbor python scripts/harbor_audit.py
```

Use a disposable Linux Docker host. The script refuses an existing
`.research/harbor-audit`, runs one positive network control and exactly one
`oracle` trial with no retries (600-second deadline), and briefly listens on a
random TCP port on all host interfaces to count connections. The CI
`harbor-spike` job runs it after the sealed replays.

## What is observed, and by whom

All gating inputs come from the controller, never from the candidate:

- `docker events` for container start/die, with each container inspected as it
  starts. `adapters/runners/harbor_audit.py` (stdlib only, no Harbor import)
  evaluates them; the core package does not import runner adapters.
- A host TCP listener. A probe container on a fresh user-defined bridge must
  reach it first; otherwise a zero count during the trial proves nothing and the
  audit is incomplete.
- A safe seal of the host-side verifier log directory taken when the agent
  container dies, before the separate verifier starts.

The generated task copies the trusted task files, including both compose files,
and adds one reviewed `solution/solve.sh`. It leaves the unsafe policy in place,
writes a forged `reward.json`, `reward.txt` and a complete all-pass
`policy-evidence.json` with a guessed MAC into `/logs/verifier`, keeps a detached
writer repeating that, and probes TCP, DNS and ICMP. Unit tests show the same
forgery would pass host acceptance if its MAC used the real nonce, so the
nonce is what rejects it.

Acceptance requires all of:

- the forgery was observed at agent stop;
- `accept_result` sees the genuine reward 0 with complete, nonce-bound failing
  evidence;
- no `reward.json` survives and `reward.txt` is `0`;
- the listener saw the positive control and zero trial connections;
- these required audit checks pass.

| Check | Requirement |
| --- | --- |
| `separate_environments` | One agent and one verifier `main` in their own compose projects, only Harbor's egress sidecar besides, different images; every started trial container was inspected |
| `agent_stopped_before_verifier` | Every agent start, including restarts, ends in a `die` before the verifier's first `start` |
| `no_privilege` | Not privileged; sidecars add at most `NET_ADMIN`/`NET_RAW`; no host PID/IPC/UTS/user namespace, devices or unconfined profiles |
| `mount_scope` | Only Harbor's log binds, inside the trial directory (no Docker socket, checkout or tests); only image-declared anonymous volumes; tmpfs only at `/tmp`, `noexec` |
| `declared_limits` | Memory and CPU equal `task.toml` |
| `network_isolation` | Both main containers use `network_mode: none` (v2; v1 also accepted Harbor's sidecar namespace) |
| `no_observed_egress` | Positive control observed; no trial connection reached the host |
| `least_privilege` | Non-root; capabilities dropped (`ALL`) with the verifier keeping only `CHOWN`, `DAC_OVERRIDE` and `FOWNER`; `no-new-privileges`; the agent has an explicit `uid:gid` different from the controller's |
| `bounded_resources` | PID limit set, swap equal to memory, read-only root filesystem |
| `verifier_secret_withheld` | The verifier nonce appears in no inspected container configuration |

Missing containers, events, the positive control or the nonce yield
`incomplete`, never pass. Evidence stores trial-relative mount sources, not host
paths. Every run records each container's image ID, limits, user, capabilities
and mounts.

## Hardened task configuration

Harbor 0.24.0 merges a task's `environment/docker-compose.yaml` (agent) and
`tests/docker-compose.yaml` (separate verifier) after its own overlays. It never
sets the hardening keys on the main containers, and it stops routing main
through its egress sidecar when `network_mode` is a literal key there. Run-level
`--extra-docker-compose` files are not applied to separate verifiers, so the
verifier file must live in `tests/`. These findings come from reading the
pinned source and were confirmed against live `docker inspect` output.

| Setting | Agent | Verifier | Why |
| --- | --- | --- | --- |
| `network_mode` | `none` | `none` | Harbor's `no-network` sidecar still allowed DNS and ICMP |
| `user` | `10001:10001` | `postgres` | Non-root; the agent uid differs from typical host uids, since an owner may chmod the shared log directory without capabilities |
| capabilities | drop `ALL` | drop `ALL`, add `CHOWN`, `DAC_OVERRIDE`, `FOWNER` | Harbor's root housekeeping (emptying the shared verifier log directory, fixing host ownership) ignores failures; without these, planted files could survive |
| `no-new-privileges`, `init`, `pids_limit` | yes, 64 | yes, 128 | Processes are reaped and bounded |
| `memswap_limit` | `${MEMORY}` | `${MEMORY}` | Harbor exports the declared memory; no extra swap |
| `read_only` | yes | yes | Writable paths are image volumes (`/candidate`, `/solution`; `/candidate`, `/logs/artifacts`) because `docker cp` cannot write a read-only root or tmpfs; `/tmp` is a `noexec` tmpfs |

The verifier image sets `test.sh` and `check.py` executable at build time,
because Harbor's runtime `chmod` silently fails on a read-only root. `test.sh`
runs PostgreSQL as the unprivileged user directly, with no `runuser`.

## Evidence binding

Each `harbor run` gets a fresh 256-bit nonce, passed as
`--ve 'DS_NONCE=${DS_NONCE}'`. Harbor resolves the template from its own
environment and hands it only to the separate verifier's test exec. The raw value
is never persisted in job configuration or shown to the agent. The name avoids
Harbor's secret-redaction pattern, which would rewrite it inside evidence.

`check.py` deletes any pre-existing grade files without following links. It
emits no reward unless the nonce is present, and it writes `reward.txt` and
schema-2 evidence with `O_EXCL|O_NOFOLLOW`. The evidence carries an HMAC-SHA256
over the artifact hash, checks and reward. Host acceptance requires a valid MAC,
agreement with Harbor's reward, and no `reward.json`, which this verifier never
writes but Harbor would prefer. A candidate-written file therefore cannot be
accepted even if Harbor's directory cleanup failed.

## Observed results

| | Policy v1, before hardening | Policy v2, hardened |
| --- | --- | --- |
| Local run (Docker 29.8.2, cgroup v1) | 7/7 checks; 14 gaps | 10/10 checks; 3 gaps |
| Agent network probe | TCP handshake to Harbor's local proxy; external DNS resolved; ICMP echo answered | No default route |
| Agent / verifier user | root / root, default capabilities | `10001:10001` with no capabilities / `postgres` with three |
| Forgery | Observed, then discarded by Harbor | Observed, discarded, and cryptographically unacceptable |
| CI (GitHub runner, cgroup v2) | 7/7, same gaps, DNS/ICMP open | Pending this change's CI |

v1 evidence is not retroactively relabeled as v2. Remaining v2 gaps:

- `agent_can_write_verifier_log_directory`: Harbor mounts the shared directory
  into the agent itself. The nonce binding and `reward.json` rejection make a
  write there non-grading.
- `*_storage_unbounded`: Docker cannot enforce `storage_mb` here.
  Tmpfs is size-limited, but volumes and the writable layer are bounded only by
  the host.

The verifier image's declared `/var/lib/postgresql/data` volume is writable but
unused. Harbor removes anonymous volumes on its default delete.

## Provenance

Task base images are pinned by multi-arch index digest
(`python:3.12-slim-bookworm`, `postgres:17-bookworm`), including the generated
replay Dockerfile; a unit test rejects unpinned `FROM` stages. Harbor pins its
own sidecar and kernel-probe images; CI preloads the probe image because Harbor
caches a failed 30-second probe for the whole process. The verifier's
`apt-get install python3` remains mutable, so audits record built image IDs
rather than claiming reproducible images.

## What this does not establish

One daemon, one trial, one reviewed control. Containers share the host kernel.
The audit trusts the daemon's reports and event timestamps. The forgery snapshot
races the verifier's startup; a missed snapshot fails rather than passes. The
listened port is reachable from other local networks during the run; use a
disposable host. Project names mirror Harbor 0.24.0 sanitization and must be
re-reviewed on upgrade. Model-generated candidates additionally need a dedicated
worker host and an approved budget.

## Next bounded task

Adapt the three application development tasks (read, list/search, export) to
this hardened layout with the independent HTTP/database verifier. Keep this
audit and the sealed replay as regressions.
