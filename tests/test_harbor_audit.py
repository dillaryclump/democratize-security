"""Offline audit checks using inspect documents shaped like hardened Harbor 0.24.0 output."""

import copy
import json
from pathlib import Path

import pytest

from democratize_security.adapters.runners import harbor_audit
from democratize_security.adapters.runners.harbor_audit import (
    REQUIRED,
    SIDECAR,
    TRIAL_STORAGE_BYTES,
    audit,
    compose_project,
    declared_exec_users,
    declared_limits,
)

ROOT = Path(__file__).resolve().parents[1]
TRIAL = "rls-policy__AbC123"
LIMITS = {
    "agent": {"cpus": 1, "memory_mb": 256},
    "verifier": {"cpus": 1, "memory_mb": 512},
    "collector": {"cpus": 1, "memory_mb": 64, "pids": 16},
}
EGRESS = {"control_connections": 1, "trial_connections": 0}
PROJECT = "com.docker.compose.project"
SECRET = "d" * 64
HOST_UID = 1001
AGENT_PROJECT = compose_project(f"{TRIAL}__env")


def tmpfs_volume(name, options):
    """Shaped like `docker volume inspect` for the reviewed tmpfs-backed volumes."""
    return {
        "Name": name,
        "Driver": "local",
        "Options": {"type": "tmpfs", "device": "tmpfs", "o": options},
    }


VOLUMES = {
    f"{AGENT_PROJECT}_candidate": tmpfs_volume(
        f"{AGENT_PROJECT}_candidate", "size=16m,nr_inodes=4096,mode=0755,uid=10001,gid=10001"
    ),
    f"{AGENT_PROJECT}_solution": tmpfs_volume(
        f"{AGENT_PROJECT}_solution", "size=16m,nr_inodes=4096,mode=0755,nosuid,nodev"
    ),
    f"{AGENT_PROJECT}_collected": tmpfs_volume(
        f"{AGENT_PROJECT}_collected", "size=1m,nr_inodes=64,mode=0755,uid=10001,gid=10001"
    ),
}


def container(cid, project, service, *, image, user="", memory=0, binds=(), volumes=()):
    """Shaped like the containers observed live under the reviewed compose files."""
    main = service == "main"
    return {
        "Id": cid,
        "Image": image,
        "Config": {
            "Image": f"{project}-{service}",
            "User": user,
            "Env": ["PATH=/usr/bin"],
            "Labels": {PROJECT: project, "com.docker.compose.service": service},
            "Volumes": dict.fromkeys(volumes, {}) or None,
        },
        "HostConfig": {
            "NetworkMode": "none" if main else f"{project}_default",
            "Privileged": False,
            "CapAdd": None if main else ["CAP_NET_ADMIN", "CAP_NET_RAW"],
            "CapDrop": ["ALL"] if main else None,
            "SecurityOpt": ["no-new-privileges:true"] if main else None,
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "UsernsMode": "",
            "Devices": None,
            "ReadonlyRootfs": main,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m"} if main else None,
            "Memory": memory,
            "MemorySwap": memory,
            "NanoCpus": 1_000_000_000 if memory else 0,
            "PidsLimit": 64 if main else None,
            "StorageOpt": None,
            "ShmSize": 64 * 1024 * 1024,
            "LogConfig": {"Type": "json-file", "Config": {"max-file": "1", "max-size": "1m"}},
        },
        "Mounts": [
            {"Type": "bind", "Source": str(source), "Destination": target, "RW": True}
            for target, source in binds
        ]
        + [
            {"Type": "volume", "Name": f"{index:x}" * 64, "Destination": target, "RW": True}
            for index, target in enumerate(volumes, start=1)
        ],
    }


def volume_mount(name, target, *, writable):
    return {
        "Type": "volume",
        "Name": name,
        "Driver": "local",
        "Destination": target,
        "RW": writable,
    }


def event(action, cid, project, service, moment):
    # Docker events carry container labels as actor attributes.
    labels = {PROJECT: project, "com.docker.compose.service": service}
    return {"Action": action, "Actor": {"ID": cid, "Attributes": labels}, "timeNano": moment}


@pytest.fixture
def observed(tmp_path):
    trial = tmp_path / "job" / TRIAL
    agent_project = compose_project(f"{TRIAL}__env")
    verifier_project = compose_project(f"{TRIAL}__verifier__trial")
    sidecar_image = "sha256:" + "5" * 64
    agent = container(
        "agent",
        agent_project,
        "main",
        image="sha256:" + "a" * 64,
        user="10001:10001",
        memory=256 * 1024 * 1024,
        binds=[
            ("/logs/agent", trial / "agent"),
            ("/logs/verifier", trial / "verifier"),
            ("/logs/artifacts", trial / "artifacts/logs/artifacts"),
        ],
    )
    verifier = container(
        "verifier",
        verifier_project,
        "main",
        image="sha256:" + "b" * 64,
        user="postgres",
        memory=512 * 1024 * 1024,
        binds=[("/logs/verifier", trial / "verifier")],
        volumes=["/candidate", "/logs/artifacts", "/var/lib/postgresql/data"],
    )
    verifier["HostConfig"]["CapAdd"] = ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER"]
    verifier["HostConfig"]["PidsLimit"] = 128
    # The submission is in a named volume the trusted collector reads; Harbor
    # uploads the oracle's solution into another. Both are bounded tmpfs.
    agent_volume = f"{agent_project}_candidate"
    agent["Mounts"].append(volume_mount(agent_volume, "/candidate", writable=True))
    agent["Mounts"].append(volume_mount(f"{agent_project}_solution", "/solution", writable=True))
    collector = container(
        "collector",
        agent_project,
        "collector",
        image="sha256:" + "e" * 64,
        user="10001:10001",
        memory=64 * 1024 * 1024,
    )
    collector["Mounts"].append(
        volume_mount(f"{agent_project}_collected", "/candidate", writable=True)
    )
    collector["HostConfig"].update(
        NetworkMode="none",
        CapAdd=None,
        CapDrop=["ALL"],
        SecurityOpt=["no-new-privileges:true"],
        ReadonlyRootfs=True,
        PidsLimit=16,
    )
    collector["Mounts"].append(volume_mount(agent_volume, "/agent-candidate", writable=False))
    events = [
        event("start", "as", agent_project, SIDECAR, 0),
        event("start", "agent", agent_project, "main", 1),
        event("start", "collector", agent_project, "collector", 1),
        event("die", "agent", agent_project, "main", 2),
        # Harbor's collect hook, after it stopped the agent's container.
        event("exec_start: python3 -I /opt/collect.py", "collector", agent_project, "collector", 3),
        event("start", "vs", verifier_project, SIDECAR, 3),
        event("start", "verifier", verifier_project, "main", 4),
        event("die", "verifier", verifier_project, "main", 5),
    ]
    containers = {
        "agent": agent,
        "agent_sidecar": container("as", agent_project, SIDECAR, image=sidecar_image),
        "collector": collector,
        "verifier": verifier,
        "verifier_sidecar": container("vs", verifier_project, SIDECAR, image=sidecar_image),
    }
    return trial, containers, events


def run(
    trial,
    containers,
    events,
    egress=EGRESS,
    secret=SECRET,
    exec_users=(),
    limits=LIMITS,
    volumes=VOLUMES,
):
    inspections = list(containers.values())
    return audit(
        TRIAL,
        trial,
        inspections,
        events,
        limits,
        egress,
        secret,
        HOST_UID,
        list(exec_users),
        volumes,
    )


def outcomes(record):
    return {check["id"]: check["outcome"] for check in record["checks"]}


def test_hardened_harbor_shape_passes_with_only_harbor_owned_gaps(observed, tmp_path):
    record = run(*observed)
    assert record["outcome"] == "pass", record
    assert record["policy"] == "harbor-docker-boundary-v5"
    assert [c["id"] for c in record["checks"]] == list(REQUIRED)
    assert record["security_verdict"] == "not_evaluated"
    # Gaps that remain: Harbor's shared log mount, the verifier's own volumes
    # and a trial directory that is not its own bounded filesystem.
    assert record["observed_gaps"] == [
        "agent_can_write_verifier_log_directory",
        "trial_storage_unbounded",
        "verifier_storage_unbounded",
    ]
    verifier = next(c for c in record["containers"] if c["role"] == "verifier")
    assert verifier["unbounded_storage"] == [
        "volume /candidate",
        "volume /logs/artifacts",
        "volume /var/lib/postgresql/data",
    ]
    assert {
        c["role"]: c["unbounded_storage"]
        for c in record["containers"]
        if c is not verifier and not c["role"].endswith("_sidecar")
    } == {"agent": [], "collector": []}
    # Evidence carries trial-relative mount sources, never host paths.
    assert str(tmp_path) not in json.dumps(record)
    agent = next(c for c in record["containers"] if c["role"] == "agent")
    assert {m["source"] for m in agent["mounts"] if m["type"] == "bind"} == {
        "agent",
        "verifier",
        "artifacts/logs/artifacts",
    }


@pytest.mark.parametrize(
    ("mutation", "check"),
    [
        ("privileged", "no_privilege"),
        ("sidecar_cap", "no_privilege"),
        ("host_pid", "no_privilege"),
        ("unconfined", "no_privilege"),
        ("docker_socket", "mount_scope"),
        ("outside_trial", "mount_scope"),
        ("verifier_tests_in_agent", "mount_scope"),
        ("sidecar_bind", "mount_scope"),
        ("named_volume", "mount_scope"),
        ("undeclared_volume", "mount_scope"),
        ("extra_tmpfs", "mount_scope"),
        ("executable_tmpfs", "mount_scope"),
        ("memory", "declared_limits"),
        ("cpus", "declared_limits"),
        ("public_network", "network_isolation"),
        ("sidecar_namespace", "network_isolation"),
        ("overlap", "agent_stopped_before_verifier"),
        ("restart_during_verification", "agent_stopped_before_verifier"),
        ("restart_and_die_during_verification", "agent_stopped_before_verifier"),
        ("extra_service", "separate_environments"),
        ("duplicate_main", "separate_environments"),
        ("shared_image", "separate_environments"),
        ("egress", "no_observed_egress"),
        ("agent_root", "least_privilege"),
        ("verifier_root", "least_privilege"),
        ("agent_named_user", "least_privilege"),
        ("agent_host_uid", "least_privilege"),
        ("agent_cap", "least_privilege"),
        ("verifier_extra_cap", "least_privilege"),
        ("caps_not_dropped", "least_privilege"),
        ("new_privileges", "least_privilege"),
        ("late_new_privileges", "least_privilege"),
        ("zero_padded_root", "least_privilege"),
        ("signed_root", "least_privilege"),
        ("toml_exec_user", "least_privilege"),
        ("late_exec_tmpfs", "mount_scope"),
        ("sidecar_tmpfs", "mount_scope"),
        ("unlimited_pids", "bounded_resources"),
        ("no_pids_limit", "bounded_resources"),
        ("swap", "bounded_resources"),
        ("writable_root", "bounded_resources"),
        ("nonce_in_env", "verifier_secret_withheld"),
    ],
)
def test_boundary_violation_fails(observed, mutation, check):
    trial, containers, events = copy.deepcopy(observed)
    agent, verifier = containers["agent"], containers["verifier"]
    host = {"agent": agent["HostConfig"], "verifier": verifier["HostConfig"]}
    egress, exec_users = EGRESS, ()
    if mutation == "privileged":
        host["verifier"]["Privileged"] = True
    elif mutation == "sidecar_cap":
        containers["agent_sidecar"]["HostConfig"]["CapAdd"].append("CAP_SYS_ADMIN")
    elif mutation == "host_pid":
        host["agent"]["PidMode"] = "host"
    elif mutation == "unconfined":
        host["agent"]["SecurityOpt"].append("seccomp=unconfined")
    elif mutation == "docker_socket":
        agent["Mounts"].append(
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "RW": True,
            }
        )
    elif mutation == "outside_trial":
        agent["Mounts"][0]["Source"] = str(trial.parent / "other-trial/agent")
    elif mutation == "verifier_tests_in_agent":
        agent["Mounts"].append(
            {"Type": "bind", "Source": str(trial / "tests"), "Destination": "/tests", "RW": False}
        )
    elif mutation == "sidecar_bind":
        containers["agent_sidecar"]["Mounts"] = [dict(agent["Mounts"][0])]
    elif mutation == "named_volume":
        verifier["Mounts"][-1]["Name"] = "shared-cache"
    elif mutation == "undeclared_volume":
        verifier["Config"]["Volumes"].pop("/var/lib/postgresql/data")
    elif mutation == "extra_tmpfs":
        host["agent"]["Tmpfs"]["/candidate"] = "rw,noexec,size=1m"
    elif mutation == "executable_tmpfs":
        host["verifier"]["Tmpfs"]["/tmp"] = "rw,exec,size=128m"
    elif mutation == "memory":
        host["agent"]["Memory"] = host["agent"]["MemorySwap"] = 0
    elif mutation == "cpus":
        host["verifier"]["NanoCpus"] = 4_000_000_000
    elif mutation == "public_network":
        host["agent"]["NetworkMode"] = "bridge"
    elif mutation == "sidecar_namespace":
        # Harbor's default no-network: allows DNS and ICMP, so v2 rejects it.
        host["verifier"]["NetworkMode"] = "container:vs"
    elif mutation == "overlap":
        died = next(e for e in events if e["Action"] == "die" and e["Actor"]["ID"] == "agent")
        died["timeNano"] = 6
    elif mutation == "restart_during_verification":
        events.append(event("start", "agent", agent["Config"]["Labels"][PROJECT], "main", 6))
    elif mutation == "restart_and_die_during_verification":
        events.append(event("start", "agent", agent["Config"]["Labels"][PROJECT], "main", 6))
        events.append(event("die", "agent", agent["Config"]["Labels"][PROJECT], "main", 7))
    elif mutation == "extra_service":
        containers["candidate_service"] = copy.deepcopy(containers["agent_sidecar"])
        containers["candidate_service"]["Config"]["Labels"]["com.docker.compose.service"] = "db"
    elif mutation == "duplicate_main":
        containers["second_agent"] = copy.deepcopy(agent)
    elif mutation == "shared_image":
        verifier["Image"] = agent["Image"]
    elif mutation == "egress":
        egress = {"control_connections": 1, "trial_connections": 1}
    elif mutation == "agent_root":
        agent["Config"]["User"] = ""
    elif mutation == "verifier_root":
        verifier["Config"]["User"] = "0:0"
    elif mutation == "agent_named_user":
        agent["Config"]["User"] = "nobody"
    elif mutation == "agent_host_uid":
        agent["Config"]["User"] = f"{HOST_UID}:{HOST_UID}"
    elif mutation == "agent_cap":
        host["agent"]["CapAdd"] = ["CAP_CHOWN"]
    elif mutation == "verifier_extra_cap":
        host["verifier"]["CapAdd"].append("CAP_SETUID")
    elif mutation == "caps_not_dropped":
        host["verifier"]["CapDrop"] = None
    elif mutation == "new_privileges":
        host["agent"]["SecurityOpt"] = None
    elif mutation == "late_new_privileges":
        # Docker applies options in order, so the last entry wins.
        host["verifier"]["SecurityOpt"].append("no-new-privileges:false")
    elif mutation == "zero_padded_root":
        agent["Config"]["User"] = "00:00"
    elif mutation == "signed_root":
        verifier["Config"]["User"] = "+0"
    elif mutation == "toml_exec_user":
        # Harbor would `exec -u root`, overriding the observed container user.
        exec_users = [("agent", "root")]
    elif mutation == "late_exec_tmpfs":
        host["agent"]["Tmpfs"]["/tmp"] = "rw,noexec,nosuid,exec,size=16m"
    elif mutation == "sidecar_tmpfs":
        containers["verifier_sidecar"]["HostConfig"]["Tmpfs"] = {"/tmp": "rw,noexec"}
    elif mutation == "unlimited_pids":
        host["agent"]["PidsLimit"] = 0
    elif mutation == "no_pids_limit":
        host["verifier"]["PidsLimit"] = None
    elif mutation == "swap":
        host["agent"]["MemorySwap"] = 2 * host["agent"]["Memory"]
    elif mutation == "writable_root":
        host["verifier"]["ReadonlyRootfs"] = False
    else:
        agent["Config"]["Env"].append(f"DS_NONCE={SECRET}")
    record = run(trial, containers, events, egress, exec_users=exec_users)
    assert record["outcome"] == "fail", record
    assert outcomes(record)[check] == "fail", record


@pytest.mark.parametrize(
    "missing", ["verifier", "events", "positive_control", "uninspected_service", "secret"]
)
def test_missing_observation_is_incomplete(observed, missing):
    trial, containers, events = copy.deepcopy(observed)
    egress, secret = EGRESS, SECRET
    if missing == "verifier":
        del containers["verifier"]
    elif missing == "events":
        events = []
    elif missing == "uninspected_service":
        # A started extra service whose inspection failed must not be invisible.
        project = containers["agent"]["Config"]["Labels"][PROJECT]
        events.append(event("start", "ghost", project, "db", 1))
    elif missing == "positive_control":
        egress = {"control_connections": 0, "trial_connections": 0}
    else:
        secret = ""
    record = run(trial, containers, events, egress, secret)
    assert record["coverage"] == "incomplete"
    assert record["outcome"] == "incomplete"


def test_unrelated_containers_are_ignored(observed):
    trial, containers, events = copy.deepcopy(observed)
    containers["other"] = copy.deepcopy(containers["agent"])
    containers["other"]["Config"]["Labels"][PROJECT] = "other__env"
    containers["other"]["HostConfig"]["Privileged"] = True
    assert run(trial, containers, events)["outcome"] == "pass"


def test_project_names_and_declared_limits_follow_pinned_harbor():
    assert compose_project("RLS-Policy__AbC.1__env") == "rls-policy__abc-1__env"
    assert compose_project("_x") == "0_x"
    # The collector's limits come from its compose declaration, not task.toml.
    declared = declared_limits(ROOT / "tasks/harbor/rls-policy/task.toml")
    assert declared == {role: LIMITS[role] for role in ("agent", "verifier")}


def test_declared_exec_users_cover_task_and_steps(tmp_path):
    assert declared_exec_users(ROOT / "tasks/harbor/rls-policy/task.toml") == []
    toml = tmp_path / "task.toml"
    toml.write_text(
        '[agent]\nuser = "root"\n[verifier]\ntimeout_sec = 1\n'
        "[[steps]]\nname = 'one'\n[steps.verifier]\nuser = 0\n"
    )
    assert declared_exec_users(toml) == [("agent", "root"), ("verifier", 0)]


APP_LIMITS = {**LIMITS, "app": {"cpus": 1, "memory_mb": 256, "pids": 64}}


def candidate_mount(volume, *, writable):
    return {
        "Type": "volume",
        "Name": volume,
        "Driver": "local",
        "Destination": "/candidate",
        "RW": writable,
    }


@pytest.fixture
def observed_app(observed):
    """The application tasks' verifier: main plus the candidate `app` service."""
    trial, containers, events = copy.deepcopy(observed)
    verifier_project = compose_project(f"{TRIAL}__verifier__trial")
    volume = f"{verifier_project}_candidate"
    verifier = containers["verifier"]
    # The application tasks run the verifier as the image's numeric postgres uid.
    verifier["Config"]["User"] = "999:999"
    verifier["Config"]["Volumes"].pop("/candidate")
    verifier["Mounts"] = [m for m in verifier["Mounts"] if m["Destination"] != "/candidate"]
    verifier["Mounts"].append(candidate_mount(volume, writable=True))
    app = container(
        "app",
        verifier_project,
        "app",
        image="sha256:" + "c" * 64,
        user="20001:20001",
        memory=256 * 1024 * 1024,
    )
    app["HostConfig"].update(
        NetworkMode="container:verifier",
        CapAdd=None,
        CapDrop=["ALL"],
        SecurityOpt=["no-new-privileges:true"],
        ReadonlyRootfs=True,
        PidsLimit=64,
        Tmpfs={"/tmp": "rw,noexec,nosuid,size=16m"},
    )
    app["Mounts"] = [candidate_mount(volume, writable=False)]
    containers["app"] = app
    events.insert(5, event("start", "app", verifier_project, "app", 4))
    return trial, containers, events


def test_app_container_shape_passes(observed_app, tmp_path):
    record = run(*observed_app, limits=APP_LIMITS)
    assert record["outcome"] == "pass", record
    app = next(c for c in record["containers"] if c["role"] == "app")
    assert app["network"] == "verifier_main_namespace"
    assert (app["pid_mode"], app["ipc_mode"]) == ("", "private")
    volume = compose_project(f"{TRIAL}__verifier__trial") + "_candidate"
    assert app["mounts"] == [
        {
            "type": "volume",
            "source": f"<volume:{volume}>",
            "target": "/candidate",
            "writable": False,
        }
    ]
    assert "app_storage_unbounded" not in record["observed_gaps"]
    assert str(tmp_path) not in json.dumps(record)


@pytest.mark.parametrize(
    ("mutation", "check"),
    [
        ("bridge", "network_isolation"),
        ("agent_namespace", "network_isolation"),
        ("writable_candidate", "mount_scope"),
        ("log_bind", "mount_scope"),
        ("other_volume", "mount_scope"),
        ("anonymous_volume", "mount_scope"),
        ("executable_tmpfs", "mount_scope"),
        ("other_tmpfs", "mount_scope"),
        ("verifier_without_candidate", "mount_scope"),
        ("verifier_read_only_candidate", "mount_scope"),
        ("pid_shared", "separate_environments"),
        ("ipc_shared", "separate_environments"),
        ("uts_host", "separate_environments"),
        ("verifier_joins_app", "separate_environments"),
        ("verifier_uid", "least_privilege"),
        ("named_verifier_user", "least_privilege"),
        ("root", "least_privilege"),
        ("named_user", "least_privilege"),
        ("host_uid", "least_privilege"),
        ("cap", "least_privilege"),
        ("new_privileges", "least_privilege"),
        ("memory", "declared_limits"),
        ("cpus", "declared_limits"),
        ("swap", "bounded_resources"),
        ("no_pids_limit", "bounded_resources"),
        ("writable_root", "bounded_resources"),
        ("shared_image", "separate_environments"),
        ("in_agent_project", "separate_environments"),
        ("duplicate", "separate_environments"),
        ("started_with_agent", "agent_stopped_before_verifier"),
        ("privileged", "no_privilege"),
        ("nonce", "verifier_secret_withheld"),
    ],
)
def test_app_boundary_violation_fails(observed_app, mutation, check):
    trial, containers, events = copy.deepcopy(observed_app)
    app, host = containers["app"], containers["app"]["HostConfig"]
    if mutation == "bridge":
        host["NetworkMode"] = "bridge"
    elif mutation == "agent_namespace":
        host["NetworkMode"] = "container:agent"
    elif mutation == "writable_candidate":
        app["Mounts"][0]["RW"] = True
    elif mutation == "log_bind":
        app["Mounts"].append(
            {
                "Type": "bind",
                "Source": str(trial / "verifier"),
                "Destination": "/logs/verifier",
                "RW": True,
            }
        )
    elif mutation == "other_volume":
        app["Mounts"][0]["Name"] = "other__verifier__trial_candidate"
    elif mutation == "anonymous_volume":
        app["Config"]["Volumes"] = {"/data": {}}
        app["Mounts"].append(
            {"Type": "volume", "Name": "e" * 64, "Destination": "/data", "RW": True}
        )
    elif mutation == "executable_tmpfs":
        host["Tmpfs"]["/tmp"] = "rw,noexec,exec,size=16m"
    elif mutation == "other_tmpfs":
        host["Tmpfs"]["/candidate"] = "rw,noexec"
    elif mutation == "verifier_without_candidate":
        containers["verifier"]["Mounts"].pop()
    elif mutation == "verifier_read_only_candidate":
        containers["verifier"]["Mounts"][-1]["RW"] = False
    elif mutation == "pid_shared":
        # A shared PID namespace would expose run.py's environment and nonce.
        host["PidMode"] = "container:verifier"
    elif mutation == "ipc_shared":
        host["IpcMode"] = "container:verifier"
    elif mutation == "uts_host":
        host["UTSMode"] = "host"
    elif mutation == "verifier_joins_app":
        containers["verifier"]["HostConfig"]["IpcMode"] = "container:app"
    elif mutation == "verifier_uid":
        app["Config"]["User"] = "999:20001"
    elif mutation == "named_verifier_user":
        containers["verifier"]["Config"]["User"] = "postgres"
    elif mutation == "root":
        app["Config"]["User"] = "0:0"
    elif mutation == "named_user":
        app["Config"]["User"] = "nobody"
    elif mutation == "host_uid":
        app["Config"]["User"] = f"{HOST_UID}:{HOST_UID}"
    elif mutation == "cap":
        host["CapAdd"] = ["CAP_NET_RAW"]
    elif mutation == "new_privileges":
        host["SecurityOpt"] = None
    elif mutation == "memory":
        host["Memory"] = host["MemorySwap"] = 512 * 1024 * 1024
    elif mutation == "cpus":
        host["NanoCpus"] = 2_000_000_000
    elif mutation == "swap":
        host["MemorySwap"] = 2 * host["Memory"]
    elif mutation == "no_pids_limit":
        host["PidsLimit"] = None
    elif mutation == "writable_root":
        host["ReadonlyRootfs"] = False
    elif mutation == "shared_image":
        app["Image"] = containers["verifier"]["Image"]
    elif mutation == "in_agent_project":
        app["Config"]["Labels"][PROJECT] = compose_project(f"{TRIAL}__env")
    elif mutation == "duplicate":
        containers["second_app"] = copy.deepcopy(app)
        containers["second_app"]["Id"] = "app2"
        events.append(event("start", "app2", app["Config"]["Labels"][PROJECT], "app", 4))
    elif mutation == "started_with_agent":
        events.append(event("start", "app", app["Config"]["Labels"][PROJECT], "app", 1))
    elif mutation == "privileged":
        host["Privileged"] = True
    else:
        app["Config"]["Env"].append(f"REFERENCE_DATABASE_URL=x DS_NONCE={SECRET}")
    record = run(trial, containers, events, limits=APP_LIMITS)
    assert record["outcome"] == "fail", record
    assert outcomes(record)[check] == "fail", record


def test_candidate_volume_needs_an_app(observed):
    # Without an app the verifier keeps v2's rule: no named volumes at all.
    trial, containers, events = copy.deepcopy(observed)
    verifier = containers["verifier"]
    volume = compose_project(f"{TRIAL}__verifier__trial") + "_candidate"
    verifier["Config"]["Volumes"].pop("/candidate")
    verifier["Mounts"] = [m for m in verifier["Mounts"] if m["Destination"] != "/candidate"]
    verifier["Mounts"].append(candidate_mount(volume, writable=True))
    record = run(trial, containers, events)
    assert outcomes(record)["mount_scope"] == "fail", record


def test_app_without_declared_limits_is_incomplete(observed_app):
    record = run(*observed_app)
    assert outcomes(record)["declared_limits"] == "not_evaluated"
    assert record["outcome"] == "incomplete"


@pytest.mark.parametrize(
    ("mutation", "check"),
    [
        ("bridge", "network_isolation"),
        ("writable_agent_volume", "mount_scope"),
        ("log_bind", "mount_scope"),
        ("other_volume", "mount_scope"),
        ("tmpfs", "mount_scope"),
        ("agent_without_volume", "mount_scope"),
        ("root", "least_privilege"),
        ("host_uid", "least_privilege"),
        ("cap", "least_privilege"),
        ("new_privileges", "least_privilege"),
        ("memory", "declared_limits"),
        ("swap", "bounded_resources"),
        ("writable_root", "bounded_resources"),
        ("pid_shared", "separate_environments"),
        ("agent_joins_collector", "separate_environments"),
        ("shared_image", "separate_environments"),
        ("in_verifier_project", "separate_environments"),
        ("pids", "declared_limits"),
        ("exec_while_agent_ran", "agent_stopped_before_verifier"),
        ("never_exec", "agent_stopped_before_verifier"),
        ("privileged", "no_privilege"),
        ("nonce", "verifier_secret_withheld"),
    ],
)
def test_collector_boundary_violation_fails(observed, mutation, check):
    trial, containers, events = copy.deepcopy(observed)
    collector, host = containers["collector"], containers["collector"]["HostConfig"]
    if mutation == "bridge":
        host["NetworkMode"] = "bridge"
    elif mutation == "writable_agent_volume":
        collector["Mounts"][-1]["RW"] = True
    elif mutation == "log_bind":
        collector["Mounts"].append(
            {
                "Type": "bind",
                "Source": str(trial / "verifier"),
                "Destination": "/logs/verifier",
                "RW": False,
            }
        )
    elif mutation == "other_volume":
        collector["Mounts"][-1]["Name"] = "other__env_candidate"
    elif mutation == "tmpfs":
        host["Tmpfs"] = {"/tmp": "rw,noexec"}
    elif mutation == "agent_without_volume":
        agent = containers["agent"]
        agent["Mounts"] = [m for m in agent["Mounts"] if m["Destination"] != "/candidate"]
    elif mutation == "root":
        collector["Config"]["User"] = "0:0"
    elif mutation == "host_uid":
        collector["Config"]["User"] = f"{HOST_UID}:{HOST_UID}"
    elif mutation == "cap":
        host["CapAdd"] = ["CAP_DAC_READ_SEARCH"]
    elif mutation == "new_privileges":
        host["SecurityOpt"] = None
    elif mutation == "memory":
        host["Memory"] = host["MemorySwap"] = 512 * 1024 * 1024
    elif mutation == "swap":
        host["MemorySwap"] = 2 * host["Memory"]
    elif mutation == "writable_root":
        host["ReadonlyRootfs"] = False
    elif mutation == "pid_shared":
        host["PidMode"] = "container:agent"
    elif mutation == "agent_joins_collector":
        # The reverse direction: the agent reads the collector's processes.
        containers["agent"]["HostConfig"]["PidMode"] = "container:collector"
    elif mutation == "pids":
        host["PidsLimit"] = 1024
    elif mutation == "shared_image":
        collector["Image"] = containers["agent"]["Image"]
    elif mutation == "in_verifier_project":
        project = compose_project(f"{TRIAL}__verifier__trial")
        collector["Config"]["Labels"][PROJECT] = project
        for item in events:
            if item["Actor"]["ID"] == "collector":
                item["Actor"]["Attributes"][PROJECT] = project
    elif mutation == "exec_while_agent_ran":
        project = compose_project(f"{TRIAL}__env")
        events.append(event("exec_start: sh", "collector", project, "collector", 1))
    elif mutation == "never_exec":
        events[:] = [e for e in events if not e["Action"].startswith("exec_start")]
    elif mutation == "privileged":
        host["Privileged"] = True
    else:
        collector["Config"]["Env"].append(f"DS_NONCE={SECRET}")
    record = run(trial, containers, events)
    assert record["outcome"] == "fail", record
    assert outcomes(record)[check] == "fail", record


def test_collector_without_declared_limits_is_incomplete(observed):
    limits = {k: v for k, v in LIMITS.items() if k != "collector"}
    record = run(*observed, limits=limits)
    assert outcomes(record)["declared_limits"] == "not_evaluated"


def test_collector_is_summarized(observed):
    record = run(*observed)
    collector = next(c for c in record["containers"] if c["role"] == "collector")
    assert {(m["source"], m["target"], m["writable"]) for m in collector["mounts"]} == {
        (f"<volume:{AGENT_PROJECT}_collected>", "/candidate", True),
        (f"<volume:{AGENT_PROJECT}_candidate>", "/agent-candidate", False),
    }


@pytest.mark.parametrize(
    ("role", "mutation"),
    [
        ("agent", "log_unbounded"),
        ("agent", "log_two_files"),
        ("agent", "log_too_large"),
        ("agent", "log_local_driver"),
        ("agent", "shm_too_large"),
        ("agent", "shm_unset"),
        ("agent", "tmpfs_without_size"),
        ("agent", "tmpfs_percentage"),
        ("agent", "tmpfs_too_large"),
        ("agent", "candidate_plain_volume"),
        ("agent", "candidate_uninspected"),
        ("agent", "candidate_too_large"),
        ("agent", "solution_plain_volume"),
        ("agent", "anonymous_volume"),
        ("collector", "collected_plain_volume"),
        ("collector", "log_unbounded"),
        ("verifier", "log_unbounded"),
        ("verifier", "tmpfs_without_size"),
        ("app", "log_unbounded"),
        ("app", "shm_too_large"),
    ],
)
def test_unbounded_storage_fails(observed_app, role, mutation):
    trial, containers, events = copy.deepcopy(observed_app)
    volumes = copy.deepcopy(VOLUMES)
    container, host = containers[role], containers[role]["HostConfig"]
    if mutation == "log_unbounded":
        host["LogConfig"] = {"Type": "json-file", "Config": {}}
    elif mutation == "log_two_files":
        host["LogConfig"]["Config"]["max-file"] = "2"
    elif mutation == "log_too_large":
        host["LogConfig"]["Config"]["max-size"] = "2m"
    elif mutation == "log_local_driver":
        # The local driver keeps five 20 MiB files by default.
        host["LogConfig"] = {"Type": "local", "Config": {}}
    elif mutation == "shm_too_large":
        host["ShmSize"] = 1024 * 1024 * 1024
    elif mutation == "shm_unset":
        host["ShmSize"] = None
    elif mutation == "tmpfs_without_size":
        host["Tmpfs"]["/tmp"] = "rw,noexec,nosuid"
    elif mutation == "tmpfs_percentage":
        host["Tmpfs"]["/tmp"] = "rw,noexec,nosuid,size=50%"
    elif mutation == "tmpfs_too_large":
        host["Tmpfs"]["/tmp"] = "rw,noexec,nosuid,size=1g"
    elif mutation == "candidate_plain_volume":
        volumes[f"{AGENT_PROJECT}_candidate"]["Options"] = None
    elif mutation == "candidate_uninspected":
        del volumes[f"{AGENT_PROJECT}_candidate"]
    elif mutation == "candidate_too_large":
        volumes[f"{AGENT_PROJECT}_candidate"]["Options"]["o"] = "size=1g,uid=10001"
    elif mutation == "solution_plain_volume":
        volumes[f"{AGENT_PROJECT}_solution"]["Options"] = {}
    elif mutation == "anonymous_volume":
        # Admitted by mount_scope as image-declared, but unbounded host storage.
        container["Config"]["Volumes"] = {"/cache": {}}
        container["Mounts"].append(
            {"Type": "volume", "Name": "f" * 64, "Destination": "/cache", "RW": True}
        )
    else:
        volumes[f"{AGENT_PROJECT}_collected"]["Options"]["type"] = "none"
    record = run(trial, containers, events, limits=APP_LIMITS, volumes=volumes)
    assert record["outcome"] == "fail", record
    assert {c["id"]: c["outcome"] for c in record["checks"] if c["outcome"] != "pass"} == {
        "bounded_container_storage": "fail"
    }
    assert f"{role}_storage_unbounded" in record["observed_gaps"]


def test_app_task_shape_has_bounded_container_storage(observed_app):
    record = run(*observed_app, limits=APP_LIMITS)
    assert outcomes(record)["bounded_container_storage"] == "pass"
    # The verifier's candidate handoff volume is only the verifier's to write.
    verifier = next(c for c in record["containers"] if c["role"] == "verifier")
    assert "volume /candidate" in verifier["unbounded_storage"]


@pytest.mark.parametrize(
    ("observation", "gap"),
    [
        ((True, TRIAL_STORAGE_BYTES), False),
        ((True, 1024 * 1024), False),
        ((True, TRIAL_STORAGE_BYTES + 4096), True),
        ((False, 1024 * 1024), True),
        (OSError(), True),
    ],
)
def test_trial_filesystem_is_measured(observed, monkeypatch, observation, gap):
    def measure(trial_dir):
        if isinstance(observation, Exception):
            raise observation
        return observation

    monkeypatch.setattr(harbor_audit, "_trial_filesystem", measure)
    record = run(*observed)
    # A measurement, not a required check: closing it needs host privilege.
    assert record["outcome"] == "pass", record
    assert ("trial_storage_unbounded" in record["observed_gaps"]) is gap
    if isinstance(observation, Exception):
        assert record["trial_storage"] is None
    else:
        assert record["trial_storage"] == {
            "own_filesystem": observation[0],
            "capacity_bytes": observation[1],
        }


def test_trial_filesystem_reads_the_job_directory_mount(tmp_path):
    trial = tmp_path / "job" / "trial"
    trial.mkdir(parents=True)
    own, capacity = harbor_audit._trial_filesystem(trial)
    assert own is False and capacity > 0


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1m", 1024 * 1024),
        ("16384k", 16 * 1024 * 1024),
        ("67108864", 64 * 1024 * 1024),
        ("1g", 1024**3),
        ("1MB", 1024 * 1024),
        ("0", None),
        ("50%", None),
        ("1.5m", None),
        ("", None),
        (None, None),
    ],
)
def test_sizes_parse_like_docker_and_tmpfs(value, expected):
    assert harbor_audit._bytes(value) == expected


@pytest.mark.parametrize("mutation", ["solution_on_collector", "collected_on_main", "read_only"])
def test_agent_volumes_are_admitted_only_where_reviewed(observed, mutation):
    trial, containers, events = copy.deepcopy(observed)
    agent, collector = containers["agent"], containers["collector"]
    if mutation == "solution_on_collector":
        collector["Mounts"].append(
            volume_mount(f"{AGENT_PROJECT}_solution", "/solution", writable=True)
        )
    elif mutation == "collected_on_main":
        agent["Mounts"].append(
            volume_mount(f"{AGENT_PROJECT}_collected", "/collected", writable=True)
        )
    else:
        next(m for m in agent["Mounts"] if m["Destination"] == "/solution")["RW"] = False
    record = run(trial, containers, events)
    assert outcomes(record)["mount_scope"] == "fail", record
