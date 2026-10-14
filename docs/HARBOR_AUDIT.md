# Harbor worker boundary audit

Status: M2 prerequisite. This records what one trusted Docker daemon actually
configured for one reviewed, model-free Harbor 0.24.0 trial. It is not a container
escape proof and does not approve hostile or model-generated candidates.

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
  starts. `harbor_audit.py` (stdlib only, no Harbor import) evaluates them.
- A host TCP listener. A probe container on a fresh user-defined bridge must
  reach it first; otherwise a zero count during the trial proves nothing and the
  audit is incomplete.
- A safe seal of the host-side verifier log directory taken when the agent
  container dies, before the separate verifier starts.

The generated task copies trusted task files and adds one reviewed
`solution/solve.sh`. It leaves the unsafe policy in place, writes a forged
`reward.json`, `reward.txt` and internally consistent all-pass
`policy-evidence.json` into `/logs/verifier`, keeps a detached writer repeating
that, and probes the network. A unit test shows host acceptance alone would
accept those forged files as a pass if they survived.

Acceptance requires: the forgery was observed at agent stop; the existing
`accept_result` sees the genuine reward 0 with complete failing evidence; no
`reward.json` survives and `reward.txt` is `0`; the listener saw the positive
control and zero trial connections; and these required audit checks pass:

| Check | Requirement |
| --- | --- |
| `separate_environments` | One agent and one verifier `main` in their own compose projects, only Harbor's egress sidecar besides, different images |
| `agent_stopped_before_verifier` | Agent `die` event precedes verifier `start` event |
| `no_privilege` | Not privileged; no added capabilities except the sidecar's `NET_ADMIN`/`NET_RAW`; no host PID/IPC/UTS/user namespace, devices or unconfined profiles |
| `mount_scope` | Only Harbor's log binds, inside the trial directory (no Docker socket, checkout or tests); only image-declared anonymous volumes |
| `declared_limits` | Memory and CPU equal `task.toml` |
| `network_isolation` | `none`, or the namespace of the same project's egress sidecar |
| `no_observed_egress` | Positive control observed; no trial connection reached the host |

Missing containers, events or the positive control yield `incomplete`, never
pass. Evidence stores trial-relative mount sources, not host paths. Every run
records each container's image ID, limits, user, capabilities and mounts.

## Observed Harbor 0.24.0 behavior

Local run on 2026-10-14 (Docker 29.8.2, cgroup v1): all seven checks passed,
the forgery was observed and then discarded, and the genuine reward was 0. The
same run recorded these gaps, now listed in every audit record:

| Observation | Consequence |
| --- | --- |
| The trial's host `verifier/` directory is bind-mounted **read-write into the agent container** at `/logs/verifier` | A candidate can write the files Harbor grades from, and Harbor reads `reward.json` before `reward.txt`. Protection relies on Harbor stopping the agent before verification and emptying the directory inside the verifier. A failed `compose down` is only a logged warning, so the ordering check is a required guard |
| `no-network` shares a sidecar network namespace; the sidecar (`NET_ADMIN`) redirects all TCP to a local transparent proxy and **accepts DNS and ICMP** | TCP handshakes complete locally but nothing reached the host. Inside the agent, external DNS resolved and an ICMP echo got a reply. These are exfiltration channels; not `--network none` |
| Agent and verifier run as root with Docker's default capabilities (including `NET_RAW`), writable root filesystem and no PID limit | Raw sockets and unbounded process creation are available to candidate code |
| Memory equals the declared value but swap is twice it | Effective memory+swap exceeds the declared limit |
| `storage_mb` produces no Docker storage limit | Disk use is bounded only by the host |

Network behavior comes from Harbor's pinned sidecar (`entrypoint.sh`,
`bin/network-policy`, `gost.yaml`) and was reproduced with its image and entrypoint
on a plain bridge as a comparison. DNS/ICMP results are the reviewed control's own
diagnostic output, not listener-verified; external TCP egress beyond the host
gateway is not independently observed.

## Provenance changes

Task base images are now pinned by multi-arch index digest
(`python:3.12-slim-bookworm`, `postgres:17-bookworm`), including the generated
replay Dockerfile; a unit test rejects unpinned `FROM` lines. Harbor pins its
own sidecar and kernel-probe images. The verifier's `apt-get install python3`
remains mutable, so audits record built image IDs rather than claiming
reproducible images.

## What this does not establish

One daemon, one trial, one reviewed control. Containers share the host kernel.
The audit trusts the daemon's reports and event timestamps. The forgery snapshot
races the verifier's startup; a missed snapshot fails rather than passes. The
listened port is reachable from other local networks during the run; use a
disposable host. Project names mirror Harbor 0.24.0 sanitization and must be
re-reviewed on upgrade.

## Next bounded task

The recorded gaps block model-generated or hostile candidates. Proposed next
step, not implemented: a reviewed task `environment/docker-compose.yaml` setting
`network_mode: none`, non-root user, `cap_drop: [ALL]`, `pids_limit`,
`read_only` with explicit tmpfs and `memswap_limit`, then rerun this audit to show
which gaps disappear without breaking the controls. Harbor documents that
task-authored `network_mode` bypasses its sidecar; whether its phase network
policy accepts that is untested. Separately, pass a controller nonce only to
the verifier (`harbor run --ve`) and require it in evidence so forged files
cannot match. Then adapt the three application tasks.
