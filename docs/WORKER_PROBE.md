# Offline worker capability probe

Status: M2 infrastructure spike, not a coding-agent runner or security evaluator.

Harbor remains the preferred agent runner, subject to its three-task integration gate. This small Docker probe tests the lower-level host controls and sealed-artifact handoff independently of model access. It does not substitute three trivial programs for the three actual research tasks required by M2.

## Operation

`worker_probe.run_probe(bundle, image_id)` validates a bundle containing main.py, writes its bytes into a new controller-owned temporary directory, mounts only that directory read-only, and executes Python in a fresh container. No application code is imported into the controller. Inputs require a preloaded immutable local `sha256:...` image ID; the runner does not pull or build images. The image is trusted and must be Linux without declared volumes.

The prototype explicitly targets the local Linux Docker socket at `/var/run/docker.sock`. Remote Docker contexts and rootless alternate sockets are not supported. Docker authority stays in the trusted controller; no socket, home directory, checkout, verifier tests or controller credentials are mounted in the workload.

Controls: UID/GID 65534, no network, read-only root and candidate mount, all capabilities dropped, no-new-privileges, default Docker seccomp, 0.5 CPU, 128 MiB RAM with no additional swap, 32 PIDs, 64 file descriptors, 16 MiB no-exec temporary storage and 1 MiB shared memory. Python runs with a cleared environment and isolated mode. Only the fixed PATH is supplied. Image health checks are disabled; no restart and no persistent container log driver are enabled.

The controller bounds wall time and captured output, kills interrupted programs and removes containers before returning. Failed cleanup raises an infrastructure error. The output remains base64-encoded untrusted bytes. Exit zero is not a pass grade; `security_verdict` is always `not_evaluated`.

## Evidence

The execution record includes the artifact hash, image ID, container ID/name, selected daemon-reported controls, termination reason, exit code, OOM state, elapsed time and bounded output. Controller-owned staged files are rehashed after execution. This records which fixed command and artifact were handed to a trusted daemon. It is not remote attestation or proof against a compromised daemon/host.

## CI and limitations

The dedicated `worker-probe` job preloads the official Python image, resolves its immutable local ID, then runs only reviewed synthetic tests. Tests cover three finite programs, non-root/read-only/network/environment constraints, timeout, output limits and container cleanup. Core tests reject tampered bundles and invalid settings before Docker access. The live tag used to preload the CI image is not a frozen campaign image; campaigns must approve and retain exact image provenance.

No real model calls, internet-enabled candidate, PostgreSQL sidecar integration, install/build hooks, hidden verifier, durable run store or autonomous campaign exists here. Containers share the host kernel and do not constitute proof against escape. Abrupt controller death can still leave a container; crash leases/reconciliation remain M3 work. Use a disposable dedicated host without personal data before expanding beyond reviewed synthetic probes.

## Next gate

Pin and inspect Harbor's separate-verifier behavior, integrate three real public development tasks, and demonstrate sealed output transfer into a fresh verifier environment without candidate access to tests or authoritative grades. Choose/approve the worker host and finite model budget before paid execution. Keep the probe as a host conformance test or retire it when equivalent adapter tests exist; do not grow a competing orchestration framework.

References: [Docker resource controls](https://docs.docker.com/engine/containers/run/), [Docker security](https://docs.docker.com/engine/security/), [Harbor task configuration](https://github.com/harbor-framework/harbor/blob/main/docs/content/docs/tasks/index.mdx).

## Observed regression fixes and validation

The initial stdout-flood test revealed that stopping consumption while leaving Docker attached could stall `docker kill`. The controller now closes the attach process/pipe before signalling the workload. If kill races with normal exit, only a daemon-confirmed stopped state permits a record. Staging explicitly makes nested directories searchable by the unprivileged runtime regardless of the controller umask.

On 2026-10-14, [CI run 38573021390](https://github.com/dillaryclump/democratize-security/actions/runs/38573021390) passed all seven real-container tests in 3.67 seconds; the separate PostgreSQL job passed 81 tests in 9.24 seconds, with its seven Docker tests delegated to the container job. Both Python matrix jobs passed. The tested code revision is `626074628cef551810216096839958a52464aa4a`. See STATUS.md for local skips and remaining gates.
