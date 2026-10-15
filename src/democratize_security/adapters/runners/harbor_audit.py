"""Host-observed Harbor 0.24.0 Docker boundary audit; no Harbor import or dispatch.

The trusted controller supplies `docker inspect` documents and lifecycle events it
captured while one trial ran, plus its own egress-listener counts. Candidate
self-reports are never inputs. Passing records what one daemon configured for one
reviewed trial; it is not a container-escape proof or hostile-workload approval.

Policy v3 also admits the application tasks' optional verifier-side `app`
service, where candidate code runs: it must join only the verifier main's
loopback-only namespace, mount only the project's candidate volume read-only
(plus a `noexec` `/tmp` tmpfs), and be unprivileged and bounded like the main
containers.
"""

import json
import re
import tomllib
from pathlib import Path

POLICY = "harbor-docker-boundary-v3"
SIDECAR = "harbor-docker-egress-control-sidecar"
SIDECAR_CAPS = {"CAP_NET_ADMIN", "CAP_NET_RAW"}
# The verifier keeps only what Harbor's root housekeeping (emptying the shared
# verifier log directory, fixing host ownership) needs; the agent keeps none.
ROLE_CAPS = {
    "agent": set(),
    "verifier": {"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER"},
    "app": set(),
}
TMPFS = {"/tmp"}
# The candidate-runtime service of the application tasks' separate verifier and
# the named volume (`<verifier project>_candidate`) it shares with main.
APP = "app"
CANDIDATE = "/candidate"
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
    "least_privilege",
    "bounded_resources",
    "verifier_secret_withheld",
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


def declared_exec_users(task_toml: Path) -> list[tuple[str, object]]:
    """task.toml users Harbor would pass as `exec -u`, overriding the audited
    container user. The hardened layout requires none."""
    config = tomllib.loads(task_toml.read_text())
    sections = [config] + config.get("steps", [])
    return [
        (role, section[role]["user"])
        for section in sections
        for role in ("agent", "verifier")
        if "user" in section.get(role, {})
    ]


def _is_root(user: str) -> bool:
    # Docker resolves numeric strings (including "00" or "+0") as uids.
    name = user.split(":")[0].strip()
    return name in {"", "root"} or bool(re.fullmatch(r"[+-]?\d+", name) and int(name) == 0)


def _last_flag(values, flags: set[str]) -> str | None:
    # Docker applies repeated security and mount options in order; the last wins.
    matches = [value for value in values if value.split("=")[0].split(":")[0] in flags]
    return matches[-1] if matches else None


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


def _summary(role: str, container: dict, trial_dir: Path, verifier_id: str | None) -> dict:
    host = container["HostConfig"]
    network = host.get("NetworkMode", "")
    if verifier_id and network == f"container:{verifier_id}":
        network = "verifier_main_namespace"
    mounts = []
    for mount in container.get("Mounts") or []:
        if mount["Type"] == "bind":
            source = _relative(mount["Source"], trial_dir) or "<outside-trial-directory>"
        elif mount["Type"] == "volume" and not re.fullmatch(
            r"[0-9a-f]{64}", mount.get("Name") or ""
        ):
            source = f"<volume:{mount.get('Name')}>"
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
    secret: str,
    host_uid: int,
    exec_users: list,
) -> dict:
    """Evaluate one trial's observed containers. Missing evidence is incomplete.

    `secret` is the verifier-only nonce; no container configuration may hold it.
    `host_uid` owns the trial directories Harbor bind-mounts into both containers.
    `exec_users` are task.toml users that would override the containers' own.
    `limits` may declare an `app` entry from the verifier compose file.
    """
    agent_project = compose_project(f"{trial_name}__env")
    verifier_project = compose_project(f"{trial_name}__verifier__trial")
    roles = {agent_project: "agent", verifier_project: "verifier"}
    by_project: dict[str, list[dict]] = {agent_project: [], verifier_project: []}
    for container in inspections:
        project, _ = _labels(container)
        if project in by_project:
            by_project[project].append(container)

    candidate_volume = f"{verifier_project}_candidate"

    def apps() -> list[dict]:
        return [c for c in by_project[verifier_project] if _labels(c)[1] == APP]

    def main(project: str) -> dict:
        found = [c for c in by_project[project] if _labels(c)[1] == "main"]
        if not found:
            raise Unavailable(f"No {roles[project]} main container observed")
        if len(found) != 1:
            raise AssertionError(f"Expected one {roles[project]} main container")
        return found[0]

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
        allowed = {agent_project: {"main", SIDECAR}, verifier_project: {"main", SIDECAR, APP}}
        for project in by_project:
            services = [_labels(c)[1] for c in by_project[project]]
            if sorted(set(services)) != sorted(services) or not set(services) <= allowed[project]:
                raise AssertionError("Unexpected or duplicate compose services in trial")
        images = [agent["Image"], verifier["Image"], *(c["Image"] for c in apps())]
        if len(set(images)) != len(images):
            raise AssertionError("Agent, verifier and app containers share an image")

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
        # any verifier-side container, including the candidate app, starts.
        moments(verifier, "start")
        verifier_starts = [
            moment
            for container in by_project[verifier_project]
            for moment in moments(container, "start")
        ]
        if not (max(moments(agent, "start")) < max(moments(agent, "die")) < min(verifier_starts)):
            raise AssertionError("Agent container was running when verification started")

    def privilege():
        for project in by_project:
            for container in by_project[project]:
                host = container["HostConfig"]
                # Main containers' capability sets are checked by least_privilege.
                sidecar = _labels(container)[1] == SIDECAR
                if (
                    host.get("Privileged")
                    or (sidecar and not set(host.get("CapAdd") or []) <= SIDECAR_CAPS)
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
        shared = {}
        for project in by_project:
            for container in by_project[project]:
                service = _labels(container)[1]
                is_main = service == "main"
                is_app = project == verifier_project and service == APP
                tmpfs = container["HostConfig"].get("Tmpfs") or {}
                if not set(tmpfs) <= (TMPFS if is_main or is_app else set()) or any(
                    _last_flag(options.split(","), {"exec", "noexec"}) != "noexec"
                    for options in tmpfs.values()
                ):
                    raise AssertionError("Unexpected or executable tmpfs in trial container")
                declared = set(container["Config"].get("Volumes") or {})
                binds = {}
                for mount in container.get("Mounts") or []:
                    if (
                        project == verifier_project
                        and (is_main or is_app)
                        and mount["Type"] == "volume"
                        and mount.get("Name") == candidate_volume
                        and mount.get("Driver") == "local"
                        and mount["Destination"] == CANDIDATE
                        and mount["RW"] is is_main
                    ):
                        # Only the verifier writes; candidate code reads.
                        shared[service] = mount["Name"]
                        continue
                    if is_app:
                        raise AssertionError("Unexpected mount in app container")
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
        if apps() and set(shared) != {"main", APP}:
            raise AssertionError("app and verifier do not share only the candidate volume")

    def resources():
        for project, role in roles.items():
            host = main(project)["HostConfig"]
            if (
                host.get("Memory") != limits[role]["memory_mb"] * 1024 * 1024
                or host.get("NanoCpus") != limits[role]["cpus"] * 1_000_000_000
            ):
                raise AssertionError(f"{role} limits differ from task configuration")
        for container in apps():
            if "app" not in limits:
                raise Unavailable("No declared app limits")
            host = container["HostConfig"]
            if (
                host.get("Memory") != limits["app"]["memory_mb"] * 1024 * 1024
                or host.get("NanoCpus") != limits["app"]["cpus"] * 1_000_000_000
            ):
                raise AssertionError("app limits differ from its compose declaration")

    def network():
        # Harbor's sidecar namespace still allows DNS and ICMP; require none.
        for project, role in roles.items():
            if main(project)["HostConfig"].get("NetworkMode") != "none":
                raise AssertionError(f"{role} main container has a network namespace")
        # The app may only join the verifier's loopback-only namespace.
        verifier = main(verifier_project)["Id"]
        for container in apps():
            if container["HostConfig"].get("NetworkMode") != f"container:{verifier}":
                raise AssertionError("app is not confined to the verifier's namespace")

    def egress_observed():
        if egress.get("control_connections", 0) < 1:
            raise Unavailable("Host listener did not observe the positive control")
        if egress.get("trial_connections") != 0:
            raise AssertionError("Host listener observed a connection during the trial")

    def least_privilege():
        if exec_users:
            # Harbor would run agent or verifier commands as this user instead
            # of the container user observed below.
            raise AssertionError("task.toml overrides the audited container user")
        observed = [(role, main(project)) for project, role in roles.items()]
        for role, container in observed + [("app", c) for c in apps()]:
            host = container["HostConfig"]
            user = container["Config"].get("User") or ""
            if _is_root(user):
                raise AssertionError(f"{role} container runs as root")
            # An owner may chmod a directory without capabilities, so an agent
            # sharing the host uid could lock the verifier log directory.
            if role in {"agent", "app"} and (
                not re.fullmatch(r"\d+:\d+", user) or int(user.split(":")[0]) == host_uid
            ):
                raise AssertionError(f"{role} needs an explicit uid:gid other than the host's")
            if (
                "ALL" not in (host.get("CapDrop") or [])
                or not set(host.get("CapAdd") or []) <= ROLE_CAPS[role]
            ):
                raise AssertionError(f"{role} capabilities exceed its allowance")
            last = _last_flag(host.get("SecurityOpt") or [], {"no-new-privileges"})
            if last not in {
                "no-new-privileges",
                "no-new-privileges:true",
                "no-new-privileges=true",
            }:
                raise AssertionError(f"{role} may gain privileges")

    def bounded():
        observed = [(role, main(project)) for project, role in roles.items()]
        for role, container in observed + [("app", c) for c in apps()]:
            host = container["HostConfig"]
            if (
                type(host.get("PidsLimit")) is not int
                or host["PidsLimit"] <= 0
                or host.get("MemorySwap") != host.get("Memory")
                or host.get("ReadonlyRootfs") is not True
            ):
                raise AssertionError(f"{role} processes, swap or root filesystem unbounded")

    def secret_withheld():
        if not isinstance(secret, str) or not re.fullmatch(r"[0-9a-f]{64}", secret):
            raise Unavailable("No verifier nonce supplied to the audit")
        for project in by_project:
            main(project)
            if any(secret in json.dumps(c) for c in by_project[project]):
                raise AssertionError(f"Verifier nonce present in {roles[project]} configuration")

    checks = []
    for name, callback in zip(
        REQUIRED,
        (
            separate,
            ordering,
            privilege,
            mounts,
            resources,
            network,
            egress_observed,
            least_privilege,
            bounded,
            secret_withheld,
        ),
        strict=True,
    ):
        try:
            callback()
            checks.append({"id": name, "outcome": "pass", "detail": ""})
        except AssertionError as error:
            checks.append({"id": name, "outcome": "fail", "detail": str(error)})
        except (Unavailable, KeyError, TypeError, ValueError) as error:
            checks.append({"id": name, "outcome": "not_evaluated", "detail": str(error)})

    verifier_mains = [c for c in by_project[verifier_project] if _labels(c)[1] == "main"]
    verifier_id = verifier_mains[0]["Id"] if len(verifier_mains) == 1 else None
    containers = []
    gaps = set()
    for project, role in roles.items():
        for container in by_project[project]:
            service = _labels(container)[1]
            if service == APP and project == verifier_project:
                role = "app"
            elif service != "main":
                role = f"{roles[project]}_sidecar"
            else:
                role = roles[project]
            summary = _summary(role, container, trial_dir, verifier_id)
            containers.append(summary)
            if role.endswith("_sidecar"):
                continue
            if summary["network"] == "egress_sidecar_namespace":
                gaps.add("network_via_net_admin_sidecar")
            if _is_root(summary["user"]):
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
