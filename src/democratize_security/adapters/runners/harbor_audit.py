"""Host-observed Harbor 0.24.0 Docker boundary audit; no Harbor import or dispatch.

The trusted controller supplies `docker inspect` documents and lifecycle events it
captured while one trial ran, plus its own egress-listener counts. Candidate
self-reports are never inputs. Passing records what one daemon configured for one
reviewed trial; it is not a container-escape proof or hostile-workload approval.

Policy v3 also admits the application tasks' optional verifier-side `app`
service, where candidate code runs: it must join only the verifier main's
loopback-only namespace, mount only the project's candidate volume read-only
(plus a `noexec` `/tmp` tmpfs), and be unprivileged and bounded like the main
containers. Policy v4 admits the agent-side trusted `collector`, which must be
isolated and bounded the same way, read the agent's candidate volume only
read-only, and be exec'd into only after the agent's container has died.

Policy v5 requires bounded container storage. Every container log must be one
capped file, and every `/dev/shm` and tmpfs must declare a size. Beyond those
and Harbor's binds of the trial directory, the agent, app and collector may
write only to tmpfs-backed volumes with a declared size. The verifier's own
volumes are a reported gap: only Harbor, copying from the trial directory, and
the trusted verifier write them. The trial directory is measured, not required:
unless its job directory is its own filesystem of at most
`TRIAL_STORAGE_BYTES`, the record reports `trial_storage_unbounded`, which
needs host privilege to close.
"""

import json
import os
import re
import tomllib
from pathlib import Path

POLICY = "harbor-docker-boundary-v5"
SIDECAR = "harbor-docker-egress-control-sidecar"
SIDECAR_CAPS = {"CAP_NET_ADMIN", "CAP_NET_RAW"}
# The verifier keeps only what Harbor's root housekeeping (emptying the shared
# verifier log directory, fixing host ownership) needs; the agent keeps none.
ROLE_CAPS = {
    "agent": set(),
    "verifier": {"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER"},
    "app": set(),
    "collector": set(),
}
TMPFS = {"/tmp"}
# The candidate-runtime service of the application tasks' separate verifier and
# the named volume (`<verifier project>_candidate`) it shares with main.
APP = "app"
CANDIDATE = "/candidate"
# The agent-side trusted collector and where it sees the agent's candidate
# volume (`<agent project>_candidate`), read-only.
COLLECTOR = "collector"
AGENT_CANDIDATE = "/agent-candidate"
# Harbor uploads the oracle's solution into the agent's `<project>_solution`
# volume; the collector writes its checked copy to `<project>_collected`.
SOLUTION = "/solution"
# Storage bounds (v5). Docker's default /dev/shm is 64 MiB; the separate
# verifier keeps its PostgreSQL cluster in a 256 MiB tmpfs. A worker host closes
# `trial_storage_unbounded` by mounting each job directory at most this large.
TRIAL_STORAGE_BYTES = 64 * 1024 * 1024
TMPFS_BYTES = 256 * 1024 * 1024
SHM_BYTES = 64 * 1024 * 1024
LOG_BYTES = 1024 * 1024
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
    "bounded_container_storage",
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


def _bytes(value) -> int | None:
    """A Docker or tmpfs size ("1m", "16384k", "67108864") in bytes; None if unbounded."""
    match = re.fullmatch(r"(\d+)([kmg]?)b?", str(value).strip().lower())
    if not match or int(match.group(1)) <= 0:
        return None
    return int(match.group(1)) * 1024 ** " kmg".index(match.group(2) or " ")


def _tmpfs_size(options: str) -> int | None:
    """The declared tmpfs size in bytes; None if unbounded or not a plain size.

    The kernel applies `size=` and `nr_blocks=` in order, last wins, and treats
    0 as unlimited, so any `nr_blocks=` is refused rather than modelled.
    """
    parts = options.split(",")
    if any(o.startswith("nr_blocks=") for o in parts):
        return None
    sizes = [o.split("=", 1)[1] for o in parts if o.startswith("size=")]
    return _bytes(sizes[-1]) if sizes else None


def _trial_filesystem(trial_dir: Path) -> tuple[bool, int]:
    """Whether the trial's job directory is its own mount, and that filesystem's size."""
    stats = os.statvfs(trial_dir)
    return os.path.ismount(trial_dir.parent), stats.f_blocks * stats.f_frsize


def _unbounded(container: dict, volumes: dict, trial_dir: Path) -> list[tuple[str, str]]:
    """Writable host-storage surfaces without a size bound, as (kind, target).

    Binds inside the trial directory are left to the separate measurement of
    the trial filesystem (`trial_storage_unbounded`).
    """
    host = container["HostConfig"]
    found = []
    if host.get("ReadonlyRootfs") is not True and not _bytes(
        (host.get("StorageOpt") or {}).get("size", "")
    ):
        found.append(("rootfs", "/"))
    log = host.get("LogConfig") or {}
    config = log.get("Config") or {}
    size = _bytes(config.get("max-size", ""))
    if log.get("Type") != "none" and not (
        log.get("Type") == "json-file"
        and size is not None
        and size <= LOG_BYTES
        and str(config.get("max-file", "1")) == "1"
    ):
        found.append(("log", ""))
    shm = host.get("ShmSize")
    if host.get("IpcMode") != "none" and not (type(shm) is int and 0 < shm <= SHM_BYTES):
        found.append(("shm", "/dev/shm"))
    tmpfs = host.get("Tmpfs") or {}
    for target, options in tmpfs.items():
        size = _tmpfs_size(options)
        if size is None or size > TMPFS_BYTES:
            found.append(("tmpfs", target))
    for mount in container.get("Mounts") or []:
        if not mount["RW"] or mount["Destination"] in tmpfs:
            continue
        if mount["Type"] == "bind" and _relative(mount["Source"], trial_dir) is not None:
            continue
        volume = volumes.get(mount.get("Name") or "") if mount["Type"] == "volume" else None
        options = (volume or {}).get("Options") or {}
        flags = set(options.get("o", "").split(","))
        # A `bind` flag would mount a host directory whatever the type says.
        tmpfs_volume = (
            options.get("type") == "tmpfs"
            and options.get("device") == "tmpfs"
            and not flags & {"bind", "rbind"}
        )
        size = _tmpfs_size(options.get("o", "")) if tmpfs_volume else None
        if (volume or {}).get("Driver") == "local" and size is not None and size <= TMPFS_BYTES:
            continue
        found.append((mount["Type"], mount["Destination"]))
    return found


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
        "pid_mode": host.get("PidMode") or "",
        "ipc_mode": host.get("IpcMode") or "",
        "shm_size_bytes": host.get("ShmSize"),
        "log_config": host.get("LogConfig"),
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
    volumes: dict,
) -> dict:
    """Evaluate one trial's observed containers. Missing evidence is incomplete.

    `secret` is the verifier-only nonce; no container configuration may hold it.
    `host_uid` owns the trial directories Harbor bind-mounts into both containers.
    `exec_users` are task.toml users that would override the containers' own.
    `limits` may declare an `app` entry from the verifier compose file.
    `volumes` maps volume names to `docker volume inspect` documents captured
    while the trial's containers ran.
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
    agent_volume = f"{agent_project}_candidate"
    solution_volume = f"{agent_project}_solution"
    collected_volume = f"{agent_project}_collected"

    def apps() -> list[dict]:
        return [c for c in by_project[verifier_project] if _labels(c)[1] == APP]

    def collectors() -> list[dict]:
        return [c for c in by_project[agent_project] if _labels(c)[1] == COLLECTOR]

    def extra() -> list[tuple[str, dict]]:
        """Non-main containers held to main-container standards."""
        return [("app", c) for c in apps()] + [("collector", c) for c in collectors()]

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
        allowed = {
            agent_project: {"main", SIDECAR, COLLECTOR},
            verifier_project: {"main", SIDECAR, APP},
        }
        for project in by_project:
            services = [_labels(c)[1] for c in by_project[project]]
            if sorted(set(services)) != sorted(services) or not set(services) <= allowed[project]:
                raise AssertionError("Unexpected or duplicate compose services in trial")
        images = [agent["Image"], verifier["Image"], *(c["Image"] for _, c in extra())]
        if len(set(images)) != len(images):
            raise AssertionError("Agent, verifier, app and collector share an image")
        # Candidate code may share only the network namespace: a shared PID or
        # IPC namespace would expose the verifier's processes and its nonce.
        # Checked from both sides, so main joining a sidecar is caught too.
        mains = [agent, verifier]
        for container in mains + [c for _, c in extra()]:
            host = container["HostConfig"]
            if (
                host.get("PidMode") not in {"", "private"}
                or host.get("IpcMode") not in {"", "private", "shareable", "none"}
                or host.get("UTSMode") not in {"", None}
            ):
                raise AssertionError("A trial container shares a PID, IPC or UTS namespace")

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
        agent_stopped = max(moments(agent, "die"))
        if not (max(moments(agent, "start")) < agent_stopped < min(verifier_starts)):
            raise AssertionError("Agent container was running when verification started")
        # Extraction happens only after the worker stopped: every exec into the
        # collector (the collect hook, Harbor's file probes) follows the die.
        for container in collectors():
            execs = [
                int(e["timeNano"])
                for e in events
                if str(e.get("Action", "")).startswith("exec_start")
                and e.get("Actor", {}).get("ID") == container["Id"]
            ]
            if not execs or min(execs) <= agent_stopped:
                raise AssertionError("Collector did not extract only after the agent stopped")

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
                is_collector = project == agent_project and service == COLLECTOR
                tmpfs = container["HostConfig"].get("Tmpfs") or {}
                if not set(tmpfs) <= (TMPFS if is_main or is_app else set()) or any(
                    _last_flag(options.split(","), {"exec", "noexec"}) != "noexec"
                    for options in tmpfs.values()
                ):
                    raise AssertionError("Unexpected or executable tmpfs in trial container")
                declared = set(container["Config"].get("Volumes") or {})
                binds = {}
                for mount in container.get("Mounts") or []:
                    # Only with an app present; otherwise v2's volume rule holds.
                    if (
                        project == verifier_project
                        and apps()
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
                    # Only with a collector present; it reads what the agent wrote.
                    if (
                        project == agent_project
                        and collectors()
                        and mount["Type"] == "volume"
                        and mount.get("Name") == agent_volume
                        and mount.get("Driver") == "local"
                        and (
                            (is_main and mount["Destination"] == CANDIDATE and mount["RW"] is True)
                            or (
                                is_collector
                                and mount["Destination"] == AGENT_CANDIDATE
                                and mount["RW"] is False
                            )
                        )
                    ):
                        shared[f"agent_{service}"] = mount["Name"]
                        continue
                    # Harbor's solution upload target and the collector's output.
                    if (
                        project == agent_project
                        and mount["Type"] == "volume"
                        and mount.get("Driver") == "local"
                        and mount["RW"] is True
                        and (
                            (
                                is_main
                                and mount.get("Name") == solution_volume
                                and mount["Destination"] == SOLUTION
                            )
                            or (
                                is_collector
                                and mount.get("Name") == collected_volume
                                and mount["Destination"] == CANDIDATE
                            )
                        )
                    ):
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
        if apps() and {"main", APP} - set(shared):
            raise AssertionError("app and verifier do not share only the candidate volume")
        if collectors() and {"agent_main", "agent_collector"} - set(shared):
            raise AssertionError("collector does not read only the agent's candidate volume")

    def resources():
        for project, role in roles.items():
            host = main(project)["HostConfig"]
            if (
                host.get("Memory") != limits[role]["memory_mb"] * 1024 * 1024
                or host.get("NanoCpus") != limits[role]["cpus"] * 1_000_000_000
            ):
                raise AssertionError(f"{role} limits differ from task configuration")
        for role, container in extra():
            if role not in limits:
                raise Unavailable(f"No declared {role} limits")
            host = container["HostConfig"]
            if (
                host.get("Memory") != limits[role]["memory_mb"] * 1024 * 1024
                or host.get("NanoCpus") != limits[role]["cpus"] * 1_000_000_000
                or host.get("PidsLimit") != limits[role]["pids"]
            ):
                raise AssertionError(f"{role} limits differ from its compose declaration")

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
        for container in collectors():
            if container["HostConfig"].get("NetworkMode") != "none":
                raise AssertionError("collector has a network namespace")

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
        for role, container in observed + extra():
            host = container["HostConfig"]
            user = container["Config"].get("User") or ""
            if _is_root(user):
                raise AssertionError(f"{role} container runs as root")
            # An owner may chmod a directory without capabilities, so an agent
            # sharing the host uid could lock the verifier log directory.
            if role in {"agent", "app", "collector"} and (
                not re.fullmatch(r"\d+:\d+", user) or int(user.split(":")[0]) == host_uid
            ):
                raise AssertionError(f"{role} needs an explicit uid:gid other than the host's")
            # Same-uid processes can signal each other and read /proc entries.
            if role == "app":
                verifier_user = main(verifier_project)["Config"].get("User") or ""
                if not re.fullmatch(r"\d+:\d+", verifier_user) or int(
                    verifier_user.split(":")[0]
                ) == int(user.split(":")[0]):
                    raise AssertionError("app needs a numeric uid other than the verifier's")
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
        for role, container in observed + extra():
            host = container["HostConfig"]
            if (
                type(host.get("PidsLimit")) is not int
                or host["PidsLimit"] <= 0
                or host.get("MemorySwap") != host.get("Memory")
                or host.get("ReadonlyRootfs") is not True
            ):
                raise AssertionError(f"{role} processes, swap or root filesystem unbounded")

    def storage():
        observed = [(role, main(project)) for project, role in roles.items()]
        for role, container in observed + extra():
            for kind, target in _unbounded(container, volumes, trial_dir):
                # Only Harbor, from the bounded trial directory, and the trusted
                # verifier write the verifier's own volumes; reported as a gap.
                if role == "verifier" and kind == "volume":
                    continue
                raise AssertionError(f"{role} storage unbounded: {kind} {target}".strip())

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
            storage,
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
            elif service == COLLECTOR and project == agent_project:
                role = "collector"
            elif service != "main":
                role = f"{roles[project]}_sidecar"
            else:
                role = roles[project]
            summary = _summary(role, container, trial_dir, verifier_id)
            containers.append(summary)
            if role.endswith("_sidecar"):
                continue
            unbounded = _unbounded(container, volumes, trial_dir)
            summary["unbounded_storage"] = [
                f"{kind} {target}".strip() for kind, target in unbounded
            ]
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
            if unbounded:
                gaps.add(f"{role}_storage_unbounded")
            if role == "agent" and any(
                m["target"] == "/logs/verifier" and m["writable"] for m in summary["mounts"]
            ):
                gaps.add("agent_can_write_verifier_log_directory")
    # Harbor bind-mounts the trial directory and copies artifacts into it,
    # including its unfiltered fallback copy of the agent's /logs/artifacts.
    try:
        own, capacity = _trial_filesystem(trial_dir)
        trial_storage = {"own_filesystem": own, "capacity_bytes": capacity}
    except OSError:
        own, trial_storage = False, None
    # Filesystems without a block limit (ramfs, tmpfs with size=0) report 0.
    if not own or not 0 < trial_storage["capacity_bytes"] <= TRIAL_STORAGE_BYTES:
        gaps.add("trial_storage_unbounded")
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
        "trial_storage": trial_storage,
        "containers": sorted(containers, key=lambda c: c["role"]),
        "egress": {k: egress.get(k) for k in ("control_connections", "trial_connections")},
        "security_verdict": "not_evaluated",
    }
