"""Host-observed Harbor 0.24.0 Docker boundary audit; no Harbor import or dispatch.

The trusted controller supplies `docker inspect` documents and lifecycle events it
captured while one trial ran, plus its own egress-listener counts. Candidate
self-reports are never inputs. Passing records what one daemon configured for one
reviewed trial; it is not a container-escape proof or hostile-workload approval.
"""

import re
import tomllib
from pathlib import Path

POLICY = "harbor-docker-boundary-v1"
SIDECAR = "harbor-docker-egress-control-sidecar"
SIDECAR_CAPS = {"CAP_NET_ADMIN", "CAP_NET_RAW"}
# Harbor-owned log binds, by container target, relative to the trial directory.
AGENT_BINDS = {
    "/logs/agent": "agent",
    "/logs/verifier": "verifier",
    "/logs/artifacts": "artifacts/logs/artifacts",
}
VERIFIER_BINDS = {"/logs/verifier": "verifier"}
REQUIRED = (
    "separate_environments",
    "agent_stopped_before_verifier",
    "no_privilege",
    "mount_scope",
    "declared_limits",
    "network_isolation",
    "no_observed_egress",
)


class Unavailable(Exception):
    """Required observation is missing; the check cannot be evaluated."""


def compose_project(session_id: str) -> str:
    # Mirrors Harbor 0.24.0 `_sanitize_docker_compose_project_name`.
    name = session_id.lower()
    if not re.match(r"^[a-z0-9]", name):
        name = "0" + name
    return re.sub(r"[^a-z0-9_-]", "-", name)


def declared_limits(task_toml: Path) -> dict:
    config = tomllib.loads(task_toml.read_text())
    return {
        role: {"cpus": section["cpus"], "memory_mb": section["memory_mb"]}
        for role, section in (
            ("agent", config["environment"]),
            ("verifier", config["verifier"]["environment"]),
        )
    }


def _labels(container: dict) -> tuple[str, str]:
    labels = container["Config"].get("Labels") or {}
    return labels.get("com.docker.compose.project", ""), labels.get(
        "com.docker.compose.service", ""
    )


def _relative(source: str, trial_dir: Path) -> str | None:
    try:
        return Path(source).resolve().relative_to(trial_dir.resolve()).as_posix()
    except ValueError:
        return None


def _summary(role: str, container: dict, trial_dir: Path) -> dict:
    host = container["HostConfig"]
    network = host.get("NetworkMode", "")
    mounts = []
    for mount in container.get("Mounts") or []:
        if mount["Type"] == "bind":
            source = _relative(mount["Source"], trial_dir) or "<outside-trial-directory>"
        else:
            source = f"<{mount['Type']}>"
        mounts.append(
            {
                "type": mount["Type"],
                "source": source,
                "target": mount["Destination"],
                "writable": mount["RW"],
            }
        )
    return {
        "role": role,
        "image": container["Config"].get("Image"),
        "image_id": container["Image"],
        "network": "egress_sidecar_namespace" if network.startswith("container:") else network,
        "user": container["Config"].get("User") or "",
        "privileged": host.get("Privileged"),
        "cap_add": sorted(host.get("CapAdd") or []),
        "cap_drop": sorted(host.get("CapDrop") or []),
        "readonly_rootfs": host.get("ReadonlyRootfs"),
        "memory_bytes": host.get("Memory"),
        "memory_swap_bytes": host.get("MemorySwap"),
        "nano_cpus": host.get("NanoCpus"),
        "pids_limit": host.get("PidsLimit"),
        "mounts": sorted(mounts, key=lambda m: m["target"]),
    }


def audit(
    trial_name: str,
    trial_dir: Path,
    inspections: list[dict],
    events: list[dict],
    limits: dict,
    egress: dict,
) -> dict:
    """Evaluate one trial's observed containers. Missing evidence is incomplete."""
    agent_project = compose_project(f"{trial_name}__env")
    verifier_project = compose_project(f"{trial_name}__verifier__trial")
    roles = {agent_project: "agent", verifier_project: "verifier"}
    by_project: dict[str, list[dict]] = {agent_project: [], verifier_project: []}
    for container in inspections:
        project, _ = _labels(container)
        if project in by_project:
            by_project[project].append(container)

    def main(project: str) -> dict:
        found = [c for c in by_project[project] if _labels(c)[1] == "main"]
        if not found:
            raise Unavailable(f"No {roles[project]} main container observed")
        if len(found) != 1:
            raise AssertionError(f"Expected one {roles[project]} main container")
        return found[0]

    def sidecar_of(project: str) -> dict | None:
        found = [c for c in by_project[project] if _labels(c)[1] == SIDECAR]
        return found[0] if len(found) == 1 else None

    def separate():
        agent, verifier = main(agent_project), main(verifier_project)
        # A container that started but was never inspected could be an extra
        # service this check cannot see, so its absence is missing evidence.
        started = {
            e["Actor"]["ID"]
            for e in events
            if e.get("Action") == "start"
            and e.get("Actor", {}).get("Attributes", {}).get("com.docker.compose.project")
            in by_project
        }
        if started - {c["Id"] for c in inspections}:
            raise Unavailable("A trial container started without an observed inspection")
        for project in by_project:
            services = [_labels(c)[1] for c in by_project[project]]
            if sorted(set(services)) != sorted(services) or not set(services) <= {
                "main",
                SIDECAR,
            }:
                raise AssertionError("Unexpected or duplicate compose services in trial")
        if agent["Image"] == verifier["Image"]:
            raise AssertionError("Agent and verifier share one image")

    def ordering():
        agent, verifier = main(agent_project), main(verifier_project)

        def moments(container: dict, action: str) -> list[int]:
            times = [
                int(e["timeNano"])
                for e in events
                if e.get("Action") == action and e.get("Actor", {}).get("ID") == container["Id"]
            ]
            if not times:
                raise Unavailable(f"No observed {action} event")
            return times

        # Every agent start, including any restart, must end in a die before
        # the verifier first starts.
        if not (
            max(moments(agent, "start"))
            < max(moments(agent, "die"))
            < min(moments(verifier, "start"))
        ):
            raise AssertionError("Agent container was running when verification started")

    def privilege():
        for project in by_project:
            for container in by_project[project]:
                host = container["HostConfig"]
                allowed = SIDECAR_CAPS if _labels(container)[1] == SIDECAR else set()
                if (
                    host.get("Privileged")
                    or not set(host.get("CapAdd") or []) <= allowed
                    or any("unconfined" in o for o in host.get("SecurityOpt") or [])
                    or "host" in {host.get(k) for k in ("PidMode", "IpcMode", "UTSMode")}
                    or host.get("UsernsMode") == "host"
                    or host.get("Devices")
                ):
                    raise AssertionError(f"Elevated privilege in {roles[project]} environment")

    def mounts():
        expected = {agent_project: AGENT_BINDS, verifier_project: VERIFIER_BINDS}
        for project in by_project:
            main(project)  # Both environments must have been observed.
        for project in by_project:
            for container in by_project[project]:
                is_main = _labels(container)[1] == "main"
                declared = set(container["Config"].get("Volumes") or {})
                binds = {}
                for mount in container.get("Mounts") or []:
                    if mount["Type"] == "volume" and mount["Destination"] in declared:
                        # Anonymous image-declared volume (e.g. PostgreSQL data).
                        if not re.fullmatch(r"[0-9a-f]{64}", mount.get("Name") or ""):
                            raise AssertionError("Named volume attached to trial container")
                        continue
                    if mount["Type"] != "bind" or not is_main:
                        raise AssertionError("Unexpected mount in trial container")
                    binds[mount["Destination"]] = _relative(mount["Source"], trial_dir)
                if is_main and binds != expected[project]:
                    raise AssertionError(f"{roles[project]} binds differ from Harbor log dirs")

    def resources():
        for project, role in roles.items():
            host = main(project)["HostConfig"]
            if (
                host.get("Memory") != limits[role]["memory_mb"] * 1024 * 1024
                or host.get("NanoCpus") != limits[role]["cpus"] * 1_000_000_000
            ):
                raise AssertionError(f"{role} limits differ from task configuration")

    def network():
        for project, role in roles.items():
            mode = main(project)["HostConfig"].get("NetworkMode")
            sidecar = sidecar_of(project)
            if mode != "none" and (sidecar is None or mode != f"container:{sidecar['Id']}"):
                raise AssertionError(f"{role} main container has a network path")

    def egress_observed():
        if egress.get("control_connections", 0) < 1:
            raise Unavailable("Host listener did not observe the positive control")
        if egress.get("trial_connections") != 0:
            raise AssertionError("Host listener observed a connection during the trial")

    checks = []
    for name, callback in zip(
        REQUIRED,
        (separate, ordering, privilege, mounts, resources, network, egress_observed),
        strict=True,
    ):
        try:
            callback()
            checks.append({"id": name, "outcome": "pass", "detail": ""})
        except AssertionError as error:
            checks.append({"id": name, "outcome": "fail", "detail": str(error)})
        except (Unavailable, KeyError, TypeError, ValueError) as error:
            checks.append({"id": name, "outcome": "not_evaluated", "detail": str(error)})

    containers = []
    gaps = set()
    for project, role in roles.items():
        for container in by_project[project]:
            service = _labels(container)[1]
            summary = _summary(
                role if service == "main" else f"{role}_sidecar", container, trial_dir
            )
            containers.append(summary)
            if service != "main":
                continue
            if summary["network"] == "egress_sidecar_namespace":
                gaps.add("network_via_net_admin_sidecar")
            if summary["user"] in {"", "0", "root", "0:0", "root:root"}:
                gaps.add(f"{role}_runs_as_root")
            if "ALL" not in summary["cap_drop"]:
                gaps.add(f"{role}_default_capabilities")
            if summary["pids_limit"] in {None, 0, -1}:
                gaps.add(f"{role}_no_pids_limit")
            if not summary["readonly_rootfs"]:
                gaps.add(f"{role}_writable_rootfs")
            if summary["memory_swap_bytes"] != summary["memory_bytes"]:
                gaps.add(f"{role}_swap_allowed")
            if not (container["HostConfig"].get("StorageOpt") or {}).get("size"):
                gaps.add(f"{role}_storage_unbounded")
            if role == "agent" and any(
                m["target"] == "/logs/verifier" and m["writable"] for m in summary["mounts"]
            ):
                gaps.add("agent_can_write_verifier_log_directory")
    complete = all(c["outcome"] in {"pass", "fail"} for c in checks)
    return {
        "schema_version": 1,
        "policy": POLICY,
        "harbor_version": "0.24.0",
        "trial_name": trial_name,
        "coverage": "complete" if complete else "incomplete",
        "outcome": ("pass" if all(c["outcome"] == "pass" for c in checks) else "fail")
        if complete
        else "incomplete",
        "checks": checks,
        "observed_gaps": sorted(gaps),
        "containers": sorted(containers, key=lambda c: c["role"]),
        "egress": {k: egress.get(k) for k in ("control_connections", "trial_connections")},
        "security_verdict": "not_evaluated",
    }
