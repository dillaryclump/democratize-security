# Harbor worker boundary audit

Status: M2 prerequisite, audit policy `harbor-docker-boundary-v5`. This records
what one trusted Docker daemon actually configured for one reviewed, model-free
Harbor 0.24.0 trial. It is not a container-escape proof and does not approve
hostile or model-generated candidates. v3 is v2 plus rules for the application
tasks' candidate `app` container ([APPLICATION_TASKS.md](APPLICATION_TASKS.md)).
For the policy task, which has no app, it applies v2's rules, with one addition:
every verifier-project container, Harbor's sidecar included, must have an
observed start event after the agent stopped. The named candidate volume is
admitted only when an app is observed. v4 adds the agent-side trusted
`collector` ([Trusted artifact collection](#trusted-artifact-collection)), held
to the same standards as main containers, and requires that it extracted only
after the agent's container died. v5 requires bounded container storage
([Bounded storage](#bounded-storage)) and measures whether the trial directory
is its own bounded filesystem.

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

- `docker events` for container start, die and exec, with each container inspected as it
  starts, and each named volume it mounts inspected while it exists.
  `adapters/runners/harbor_audit.py` (stdlib only, no Harbor import)
  evaluates them; the core package does not import runner adapters.
- The trial directory's filesystem (`statvfs`), and whether its job directory
  is a mount of its own.
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
| `separate_environments` | One agent and one verifier `main` in their own compose projects, only Harbor's egress sidecar besides plus at most one `collector` in the agent project and one `app` in the verifier project; agent, verifier, app and collector images all differ; neither app nor collector shares a PID, IPC or UTS namespace; every started trial container was inspected |
| `agent_stopped_before_verifier` | Every agent start, including restarts, ends in a `die` before any verifier-project container (main, app or sidecar) first starts; v4: at least one exec into the collector, and every one after that `die`, so extraction happened only after the worker stopped |
| `no_privilege` | Not privileged; sidecars add at most `NET_ADMIN`/`NET_RAW`; no host PID/IPC/UTS/user namespace, devices or unconfined profiles |
| `mount_scope` | Only Harbor's log binds, inside the trial directory (no Docker socket, checkout or tests); only image-declared anonymous volumes; tmpfs only at `/tmp` on main containers, with `noexec` as the last exec flag. v3: the app mounts nothing but the local `<verifier project>_candidate` volume at `/candidate`, read-only, which the verifier main mounts read-write, and its only tmpfs is a `noexec` `/tmp`; v4: with a collector present, the agent main mounts the local `<agent project>_candidate` volume read-write at `/candidate` and the collector mounts it read-only at `/agent-candidate`, plus its own output volume, nothing else and no tmpfs; v5: the agent main may also mount `<agent project>_solution` read-write at `/solution`, and the collector's output is `<agent project>_collected` at `/candidate`; no other named volume anywhere |
| `declared_limits` | Memory and CPU equal `task.toml`; the app's and collector's equal their compose declarations (a missing declaration is incomplete) |
| `network_isolation` | Both main containers use `network_mode: none` (v2; v1 also accepted Harbor's sidecar namespace); v3: the app joins only the verifier main's namespace (`container:<main id>`), so it has loopback only; v4: the collector uses `network_mode: none` |
| `no_observed_egress` | Positive control observed; no trial connection reached the host |
| `least_privilege` | Non-root (numeric forms such as `00` count as root); capabilities dropped (`ALL`) with the verifier keeping only `CHOWN`, `DAC_OVERRIDE` and `FOWNER` and the app and collector none; the last `no-new-privileges` option is true; the agent, app and collector have explicit `uid:gid` users different from the controller's, and the app's uid differs from the verifier's, which must then be numeric; task.toml sets no exec user |
| `bounded_resources` | PID limit set, swap equal to memory, read-only root filesystem, for main containers, the app and the collector |
| `verifier_secret_withheld` | The verifier nonce appears in no inspected container configuration, the app's and collector's included |
| `bounded_container_storage` | v5: for main containers, the app and the collector, every container log is one `json-file` of at most 1 MiB (or none), `/dev/shm` is at most 64 MiB, every tmpfs declares a size of at most 256 MiB and no `nr_blocks=` (which the kernel applies in order and reads 0 as unlimited), and the root filesystem is read-only. Besides binds inside the trial directory, every writable volume of the agent, app and collector is a local volume whose type and device are `tmpfs`, with no `bind` flag and the same size rule, and its inspection observed; the verifier's own volumes are reported, not required |

Missing containers, events, the positive control or the nonce yield
`incomplete`, never pass. Evidence stores trial-relative mount sources, not host
paths. Every run records each container's image ID, limits, user, capabilities,
mounts, log configuration, `/dev/shm` size and unbounded storage surfaces, and
the trial filesystem's capacity.

## Hardened task configuration

Harbor 0.24.0 merges a task's `environment/docker-compose.yaml` (agent) and
`tests/docker-compose.yaml` (separate verifier) after its resources and build
files, then adds its environment, mounts and egress-sidecar overlays. None of
those overlays set the hardening keys on the main containers. Harbor stops
routing main through its egress sidecar only when `network_mode` is a literal key
in the task file. Run-level
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
| `read_only` | yes | yes | Writable paths are volumes (agent: `/candidate`, a named volume the trusted collector reads, and `/solution`; verifier: `/candidate`, `/logs/artifacts`) because `docker cp` cannot write a read-only root or a `--tmpfs` mount; `/tmp` is a `noexec` tmpfs |
| `logging` | `json-file`, one 1 MiB file | same | Container logs are host files; the agent can write its init's stdout and the app its own |
| volumes | `candidate`, `solution`: tmpfs, 16 MiB, 4096 inodes | Harbor's and the image's | The agent's volumes are size-bounded tmpfs that `docker cp` can still write |
| `healthcheck` | `/tmp/.seeded` exists | none | Docker does not copy image content into a tmpfs volume; the trusted entrypoint seeds the starter, and Harbor's `up --wait` holds the agent until it has |

The verifier image sets `test.sh` and `check.py` executable at build time,
because Harbor's runtime `chmod` silently fails on a read-only root. `test.sh`
runs PostgreSQL as the unprivileged user directly, with no `runuser`. The oracle
and tamper `solve.sh` files are executable before upload. `docker cp` keeps
the host owner (the CI runner), so Harbor's capability-less root `chmod` cannot
set the bit, and the agent would otherwise get `Permission denied` and a silent
reward of 0. This was reproduced with a uid-1001-owned copy and fixed. task.toml
sets no `[agent]` or `[verifier]` user, because Harbor would pass it as `exec -u`
and override the audited container user. The audit fails if one appears.

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
| CI (GitHub runner uid 1001, cgroup v2) | 7/7 with the same gaps and DNS/ICMP open: [run 38598202622](https://github.com/dillaryclump/democratize-security/actions/runs/38598202622) at `a655e35` | 10/10 with the same 3 gaps, no default route, forgery discarded, genuine reward 0: [run 38640538700](https://github.com/dillaryclump/democratize-security/actions/runs/38640538700) at `cd5c433` |

The network probe row is the reviewed control's self-reported diagnostic, not
listener-verified. For v2 it is corroborated by the daemon-observed
`network_mode: none`. v1 evidence is not retroactively relabeled as v2.
Remaining v2 gaps:

- `agent_can_write_verifier_log_directory`: Harbor mounts the shared directory
  into the agent itself. The nonce binding and `reward.json` rejection make a
  write there non-grading.
- `*_storage_unbounded`: Docker cannot enforce `storage_mb` here.
  Tmpfs is size-limited, but volumes and the writable layer are bounded only by
  the host. v5 narrows this; see [Bounded storage](#bounded-storage).

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

## Application tasks

`scripts/harbor_apps.py` audits every trial it runs (twelve per task: oracle,
nop, unsafe, both replays, the six extraction controls and the storage control)
under v5, with one
positive control and one host listener for the whole run, and fails unless all
pass with zero trial connections and exactly one app. App and collector limits
(memory, CPU and PIDs) come from the trusted verifier and agent compose files.
Under v4 the app and collector added the gaps `app_storage_unbounded` and
`collector_storage_unbounded`; v5 bounds both and requires it. Results are in
APPLICATION_TASKS.md.

## Trusted artifact collection

Harbor 0.24.0 copies each artifact path out of the agent container to the host
and later into the verifier, with no type or size check: a symlink is resolved
on the host at upload, so a host directory it names is copied into the
verifier, and a sparse file is streamed in full. Every task (the policy task
and the three application tasks) therefore collects only through a trusted
`collector` service in the agent's compose project, satisfying ARCHITECTURE.md
runtime step 5 for that submission artifact:

1. The agent's `/candidate` is a named volume; the collector mounts it
   read-only at `/agent-candidate`.
2. After the agent's work, Harbor stops the agent's `main` container (separate
   verifier mode), then runs the task's `[[verifier.collect]]` hook in the
   collector: `collect.py` opens the one allowlisted path with `O_NOFOLLOW`
   and `O_NONBLOCK`, requires a regular, singly linked file whose size is
   within the task's bound (4096 bytes for `policy.json`, 65536 for `app.py`)
   before reading, and writes a fresh `0444` copy into its own 1 MiB tmpfs
   volume.
3. The task's only artifact entry names `service = "collector"`, so Harbor
   moves only that checked copy through the host. Anything rejected leaves no
   file; the verifier then grades a missing submission, a bound zero.

The collector runs as the agent's uid, so a file the agent saved as `0600` is
still collected (and normalized to `0444`), while one it made unreadable to
itself is rejected. It has no network or capabilities, a read-only root, 64 MiB
without swap and 16 PIDs. Audit v4 checks all of that against the compose
declaration and, from `exec_start` events, that the collector was only exec'd
into after the agent's container died. `scripts/harbor_apps.py` proves it for
each application task with hostile controls: a symlink to a host canary
directory, a 1 GiB sparse file and a FIFO each end in a bound zero with no
collected file and the canary absent from all trial output, and a valid `0600`
app passes. Each hostile script checks that its object is in place before
printing a marker that acceptance requires. The policy task uses the
byte-identical collector, covered by its unit tests and the tamper control.
Harbor would also re-upload the agent's bind-mounted `/logs/artifacts`
directory into the verifier unchecked. Every task replaces that convention
entry with an explicit one (`exclude = ["*"]`, fresh `destination`), so while
the agent's container accepts execs at most an empty directory is staged; the
`logs` control proves it with a sparse file, a canary link, a FIFO and an
unreadable file left there. An agent that makes its container refuse execs
forces Harbor's unfiltered fallback copy, which no task setting prevents: host
acceptance (`check_staged_logs`, on every trial of both task families) rejects
it, the `logs-fallback` control proves that detection, and the storage the copy
used is the remaining availability limit. CI
[run 38795922164](https://github.com/dillaryclump/democratize-security/actions/runs/38795922164)
at `e546181` passed all of this, with every trial audited under v4.

## Bounded storage

Under v4 a candidate could fill host disk through several channels. v5 bounds
each one a container can reach, in every task (policy and application):

| Channel | Writer | Bound |
| --- | --- | --- |
| The agent's `/candidate` and `/solution` | agent (the solution volume is root-owned) | tmpfs volumes of 16 MiB and 4096 inodes each, freed with the trial |
| The collector's output | trusted collector | tmpfs volume of 1 MiB |
| `/tmp` | agent, app, verifier | tmpfs of 16 MiB (agent, app), 128 MiB (policy verifier) or 256 MiB (application verifier), unchanged |
| `/dev/shm` | any process | Docker's default 64 MiB, now checked |
| Container logs | the agent (writing its init's stdout), the app (its own stdout) | one `json-file` of 1 MiB per container |
| Root filesystems | none | read-only (unchanged) |

All tmpfs pages are also charged to the writing container's memory limit. The
tmpfs-backed volumes would start empty, since Docker copies image content only
into ordinary volumes, so each agent image (and each generated replay image)
seeds its starter through a trusted entrypoint (`environment/seed.sh`), and a
healthcheck makes Harbor's `up --wait` hold the agent until the starter is in
place. The nop controls, which grade the unmodified starter, depend on that.

The `fill` control of `scripts/harbor_apps.py` proves the bounds live. Its
agent requests 128 MiB on each of `/candidate`, `/tmp` and `/dev/shm`, and
records where each write stopped. It writes 8 MiB to its init's stdout and then
submits the reference app. Acceptance requires each write to have stopped
between half its bound and the bound. The container log, read from the daemon
when the agent's container died, must hold at most 1 MiB. The app must still
pass every check.

Two surfaces remain bounded only by the host:

- The trial directory. Harbor bind-mounts it into the containers (`/logs/*`)
  and copies artifacts into it, including its unfiltered fallback copy of the
  agent's `/logs/artifacts`. Bounding it per trial needs host privilege:
  mounting each job directory on its own filesystem of at most 64 MiB before
  Harbor runs. The audit measures this and reports `trial_storage_unbounded`
  until a worker host does it. A filesystem reporting no capacity (ramfs, or
  tmpfs with `size=0`) has no block limit and counts as unbounded. The scripts in this repository do not mount
  anything.
- The verifier's own volumes (`verifier_storage_unbounded`). Only Harbor,
  copying from the trial directory, and the trusted verifier write them.

## Next bounded task

Keep this audit, the hostile extraction and storage controls and the sealed
replays as regressions. A dedicated worker host must give each trial a bounded
filesystem of its own, which closes `trial_storage_unbounded`. Model-generated
candidates still need that host and an approved budget.
