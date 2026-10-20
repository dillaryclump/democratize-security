# Dedicated Linux worker preparation

Status: host helper and opt-in Harbor hookup, issue #54, exercised on the
dedicated WSL2 worker Dillon selected (see below and STATUS.md for the measured
run at `2a6ed57`). No model execution or M2 owner acceptance is established by
this change; acceptance stays in #19.
The helper does not dispatch work, authenticate verifier results, implement
controller recovery, or authorize spending.

## Worker boundary

Use a disposable Linux host or a dedicated Linux VM with rootful Docker Engine,
Compose v2 and a local `/var/run/docker.sock`. Run the trusted controller there,
not against a remote Docker context from the Mac. Copy only an approved source
revision; do not mount a personal home directory, checkout, credentials, Docker
Desktop data or final assessment material into the VM. Candidates retain the
existing `network_mode: none`, distinct identities, collector and verifier layout.

The helper creates **one 64 MiB ext4 image and loop mount per Harbor job**, not one
shared filesystem for `.research`. Current controls have exactly one trial per
job. An ext4 filesystem's usable capacity is slightly smaller; both the helper
and the existing v5 audit measure actual capacity. The controller, SQLite store,
objects and root-owned host state remain outside candidate-writable filesystems.

Application declarations require 512 MiB for the agent, 64 MiB for the collector,
1024 MiB for the separate verifier and 256 MiB for its app, plus sidecars, Docker,
controller and build overhead. Agent and verifier phases are separate. Size the
chosen host from measured peak use; one active trial remains the rule. Retained
images and archives also consume disk: budget up to 64 MiB + 80 MiB archive +
8 MiB metadata per job, besides image/build caches. Stop allocations before the
host or VM storage fills. These bounds are not cloud or model spending approval.

## Install on the selected Linux host

Ubuntu 24.04 provides Python 3.12. Install rootful Engine and Compose using
[Docker's signed Ubuntu apt repository](https://docs.docker.com/engine/install/ubuntu/),
record exact installed package versions, then install helper prerequisites:

```bash
sudo apt-get install python3 python3-venv e2fsprogs util-linux sudo
docker --host unix:///var/run/docker.sock info
docker compose version
```

Give only the trusted controller access to Docker. No candidate receives Docker,
sudo, host helper files or the host configuration. Docker group membership is
host administrative authority, not a candidate permission.

On the source machine, archive the approved full commit after review:

```bash
git archive --format=tar --output=/tmp/ds-worker-source.tar APPROVED_COMMIT
```

Transfer that archive explicitly and extract into a fresh controller-owned
`/srv/democratize-security` on Linux. `git archive` excludes `.git`, `.research`,
untracked `.env` and local credentials. Record the commit and archive SHA-256
outside the worker, and verify the transferred bytes before extraction. This is
a public synthetic source copy, not a transfer of private/final tests.

From that checkout as the configured non-root controller:

```bash
sudo bash infra/worker/bootstrap.sh /srv/democratize-security "$(id -u)" "$(id -g)"
uv sync --locked --group harbor
uv run --locked --group harbor python infra/worker/check_host.py
```

Install the CI-pinned `uv==0.12.23` in the guest first. Bootstrap installs only
the root-owned helper, configuration, private state directory and narrow sudoers
entry. It refuses existing installations rather than replacing another setup.
It does not install packages, start Docker, launch trials, create a VM, or enable
automatic boot. Review and repair any partial installation explicitly.

`check_host.py` performs one finite synthetic storage control: a child dies after
preparation, a fresh helper inspects the real mount, duplicate preparation is
rejected, a bounded write reaches `ENOSPC`, and the same job is archived/released.
It launches no workload or model. It requires actual Linux privilege; unit tests
that mock the kernel and Docker observations are not this acceptance evidence.

## Run existing model-free regressions

Use fresh output directories. The following opt-in is mandatory on the dedicated
worker; failed preparation or an unobserved/oversize mount blocks Harbor launch.
Leaving it unset preserves the existing CI infrastructure runs, whose audits
continue reporting unbounded trial storage where applicable.

```bash
export DS_WORKER_HOST_REQUIRED=1
uv run --locked --group harbor python scripts/harbor_replay.py
uv run --locked --group harbor python scripts/harbor_audit.py
uv run --locked --group harbor python scripts/harbor_apps.py invoice-read
uv run --locked --group harbor python scripts/harbor_apps.py invoice-search
uv run --locked --group harbor python scripts/harbor_apps.py invoice-export
```

Preload Harbor's pinned egress probe image as in `.github/workflows/ci.yml`.
Builds need network access and may require the host's reviewed proxy CA; record
such differences and built image IDs. Run the separate seven-test worker probe
with `REQUIRE_DOCKER_TESTS=1` and a preloaded immutable `TEST_WORKER_IMAGE_ID`.
Retain all failed/incomplete outcomes. No model key is needed for these controls.

The submission collector, nonce binding, hostile extraction/storage controls,
separate verifier and sealed replays are unchanged. The v5 audit must observe
`own_filesystem: true`, positive capacity at most 67108864 bytes, and no
`trial_storage_unbounded` on every trial. Do not infer this from a helper marker
or a passing aggregate audit: that gap is separately reported. The other known
gaps, including the verifier's own volumes and writable non-grading verifier log
directory, still need owner review in #19.

## Archive, release and inspect after interruption

Keep every job mounted through the script's acceptance and audits. After Docker
teardown, archive and then release each job explicitly, for example:

```bash
sudo -n /usr/local/libexec/ds-worker-host inspect /srv/democratize-security/.research/harbor-apps/invoice-read oracle
sudo -n /usr/local/libexec/ds-worker-host archive /srv/democratize-security/.research/harbor-apps/invoice-read oracle
sudo -n /usr/local/libexec/ds-worker-host release /srv/democratize-security/.research/harbor-apps/invoice-read oracle
```

Repeat for every job, including failed controls. The helper refuses archive and
release while any Docker container, even a stopped one, references the job.
Remove only this run's known containers through trusted teardown. Never kill
unrelated workloads or unmount a guessed path.

Root-owned state under `/var/lib/ds-worker-host` binds the exact allowlisted path
to the image. Actual kernel mount, loop backing file, filesystem type, options
and capacity are rechecked before use. Host operations use a nonblocking lock,
fixed commands, a cleared command environment and isolated Python. Workloads
receive none of this authority.

The tar archive has an 80 MiB cap; its sidecar lists every inspected entry.
Links, FIFOs, other special files and excessive logical sparse-file contents are
recorded explicitly as metadata only, without following or reading them. The
original 64 MiB image remains retained after release, along with the archive and
SHA-256 manifest. These are administrative preservation records, never accepted
verifier results. Never extract untrusted archives as root or onto the source
checkout. Copy retained evidence to a reviewed durable backup before retiring
the worker; ignored local files are not a backup policy.

Existing jobs are never automatically reused or resumed. On interruption,
inspect the exact same job first. An empty preparation can be explicitly
`abort`ed only before durable mount intent exists and with no mount, loop device,
archive or Docker reference. Once mounting may have happened, uncertain state
retains its image for operator inspection. A partial archive, missing manifest,
corrupt image, unknown mount, or failed unmount blocks cleanup. Do not bypass
these failures or dispatch a replacement trial. Reboot recovery and automated
mount reconciliation are not implemented here; this is not runtime M3 recovery.
Use a new reviewed checkout/host configuration for another full run; current
Harbor scripts already refuse reused output directories.

## Dedicated WSL2 distro on Windows

Dillon selected a separate WSL2 distro as the first dedicated worker. Create it
from the official image, never by exporting a personal distro:

```powershell
wsl --install Ubuntu-24.04 --name ds-worker --location <dedicated directory> --no-launch
```

As root, create a non-root `controller` user (uid outside 999/10001/20001),
install [`infra/worker/wsl.conf`](../infra/worker/wsl.conf) as `/etc/wsl.conf`,
then `wsl --terminate ds-worker`. Confirm that no `drvfs`/`9p` Windows drive is
mounted, that `/proc/sys/fs/binfmt_misc/WSLInterop` is absent and that `PATH` has
no Windows entries. Install Engine, Compose and helper prerequisites as above, and
uv 0.12.23 for the controller.

Transfer the source through stdin; the worker has no Windows drive to read from.
On Windows, Git's `core.autocrlf=true` also rewrites `git archive` output, so
create the archive with `git -c core.autocrlf=false archive`. Compare SHA-256 on
both sides, then extract as the controller into a fresh `/srv/democratize-security`.

Platform constraints, recorded rather than assumed away:

- **Kernel.** All WSL2 distros share one utility-VM kernel. Harbor's Docker
  environment rejects `no-network` tasks unless the engine kernel has
  `CONFIG_NFT_FIB_INET`, which the stock WSL kernel lacks. Build Microsoft's
  matching `WSL2-Linux-Kernel` tag with `NFT_FIB`, `NFT_FIB_IPV4`, `NFT_FIB_IPV6`
  and `NFT_FIB_INET` enabled, plus its modules VHDX, and set `kernel=` and
  `kernelModules=` in `.wslconfig`. Containers still share that host kernel.
- **One Docker daemon.** WSL2 distros share a network namespace, so two Docker
  Engines would contend for bridges and nftables rules. Run Engine only in the
  worker during a worker run, and stop other distros' daemons first. Do not use
  Docker Desktop's WSL integration: its bridge gateway is in another namespace,
  so the audit's egress positive control can never reach the host listener and
  every audit stays `incomplete`.
- **Shared WSL plumbing.** The distro still sees WSL's shared `/mnt/wsl` tmpfs,
  read-only GPU driver files and WSLg sockets. Candidates do not: they run in
  Docker containers that mount none of these.
- **Idle stop acts as a reboot.** WSL stops a distro once no session process
  remains, which drops every loop mount. The helper does not reconcile after a
  reboot, so run trials, audits, archive and release in one session with
  [`infra/worker/regressions.sh`](../infra/worker/regressions.sh), launched
  detached (for example with `setsid nohup`) so the run itself keeps the distro alive.

## Optional Apple Silicon VM configuration

`infra/worker/lima.yaml` is an optional 2 CPU / 3 GiB RAM / 16 GiB disk VZ
configuration with a digest-pinned arm64 Ubuntu 24.04 image. On an 8 GiB Mac,
running it alongside a 4 GiB Docker Desktop VM would create memory pressure;
do not stop unrelated workloads to make room. This route is currently deferred.

If explicitly resumed, install stable Lima with `brew install lima` and use a
fresh dedicated `LIMA_HOME`. [VZ](https://lima-vm.io/docs/config/vmtype/vz/) uses
Apple's hypervisor without QEMU. [Plain mode](https://lima-vm.io/docs/config/plain/)
disables home mounts, dynamic forwarding, containerd and SSH-agent forwarding;
the config also explicitly excludes mounts and forwards. It does not isolate
VM outbound networking from the Mac/LAN or prove resistance to VM escape.

```bash
LIMA_HOME=/absolute/dedicated/lima-state limactl start --tty=false --name=ds-worker infra/worker/lima.yaml
LIMA_HOME=/absolute/dedicated/lima-state limactl shell ds-worker uname -a
LIMA_HOME=/absolute/dedicated/lima-state limactl stop ds-worker
```

Do not add the stock Docker template's home mount or forwarded Docker socket.
Transfer the source archive explicitly; execute the controller inside Linux.
For the current Mac plan, initial free space must be at least 20 GiB and
allocations stop below 10 GiB. Actual image/cache requirements and peak memory
remain unmeasured until the selected host executes the finite controls.

## Validation and next gate

Unit tests cover path/name and symlink rejection, retained intent on preparation
failure, actual-mount mismatches, stale-job refusal, detached-Docker requirements,
bounded archival of hostile metadata, corruption, lock ownership and fail-closed
Harbor preflight.

Observed on the dedicated WSL2 worker, 2026-10-20, source `2a6ed57`
(`git archive` SHA-256 `c3cee1fb...81d8`), Docker Engine 29.9.1 with cgroup v2,
`python:3.12-slim` `sha256:a6e34c59...11b1`, `postgres:17` `sha256:2d2b8998...f9e3`:

- `check_host.py`: real 64 MiB ext4 loop mount (58,675,200 usable bytes),
  crash-surviving preparation inspected, duplicate preparation rejected,
  ENOSPC after 57,307,136 written bytes, archived and released.
- `regressions.sh`: full suite 1000 passed with PostgreSQL and Docker required;
  replay, audit and all three application tasks passed with
  `DS_WORKER_HOST_REQUIRED=1`. All 37 audited trials reported
  `own_filesystem: true` and no `trial_storage_unbounded`; the remaining gaps
  were `agent_can_write_verifier_log_directory` and `verifier_storage_unbounded`.
  All 41 jobs were archived and released in the run's session; none retained.
- An earlier run on the same host showed the idle-stop behaviour above: its jobs
  were left unmounted with images retained, which is why `regressions.sh` now
  archives in-session. That run's state is retained for inspection.

The WSL2 VM has no explicit CPU/memory bound unless `.wslconfig` sets one, and
containers share its kernel. These results are not M2 owner acceptance (#19).
Runtime provenance/recovery and a finite approved model budget still gate model
execution.
