"""Offline audit checks using inspect documents shaped like Harbor 0.24.0 output."""

import copy
import json
from pathlib import Path

import pytest

from democratize_security.harbor_audit import (
    REQUIRED,
    SIDECAR,
    audit,
    compose_project,
    declared_limits,
)

ROOT = Path(__file__).resolve().parents[1]
TRIAL = "rls-policy__AbC123"
LIMITS = {"agent": {"cpus": 1, "memory_mb": 256}, "verifier": {"cpus": 1, "memory_mb": 512}}
EGRESS = {"control_connections": 1, "trial_connections": 0}


def container(cid, project, service, *, image, memory=0, network="bridge", binds=(), cap_add=None):
    return {
        "Id": cid,
        "Image": image,
        "Config": {
            "Image": f"{project}-{service}",
            "User": "",
            "Labels": {
                "com.docker.compose.project": project,
                "com.docker.compose.service": service,
            },
            "Volumes": None,
        },
        "HostConfig": {
            "NetworkMode": network,
            "Privileged": False,
            "CapAdd": cap_add,
            "CapDrop": None,
            "SecurityOpt": None,
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "UsernsMode": "",
            "Devices": None,
            "ReadonlyRootfs": False,
            "Memory": memory,
            "MemorySwap": memory * 2,
            "NanoCpus": 1_000_000_000 if memory else 0,
            "PidsLimit": None,
            "StorageOpt": None,
        },
        "Mounts": [
            {"Type": "bind", "Source": str(source), "Destination": target, "RW": True}
            for target, source in binds
        ],
    }


@pytest.fixture
def observed(tmp_path):
    trial = tmp_path / "job" / TRIAL
    agent_project = compose_project(f"{TRIAL}__env")
    verifier_project = compose_project(f"{TRIAL}__verifier__trial")
    caps = ["CAP_NET_ADMIN", "CAP_NET_RAW"]
    agent_sidecar = container(
        "as", agent_project, SIDECAR, image="sha256:" + "5" * 64, cap_add=caps
    )
    agent = container(
        "agent",
        agent_project,
        "main",
        image="sha256:" + "a" * 64,
        memory=256 * 1024 * 1024,
        network="container:as",
        binds=[
            ("/logs/agent", trial / "agent"),
            ("/logs/verifier", trial / "verifier"),
            ("/logs/artifacts", trial / "artifacts/logs/artifacts"),
        ],
    )
    verifier_sidecar = container(
        "vs", verifier_project, SIDECAR, image="sha256:" + "5" * 64, cap_add=caps
    )
    verifier = container(
        "verifier",
        verifier_project,
        "main",
        image="sha256:" + "b" * 64,
        memory=512 * 1024 * 1024,
        network="container:vs",
        binds=[("/logs/verifier", trial / "verifier")],
    )
    verifier["Config"]["Volumes"] = {"/var/lib/postgresql/data": {}}
    verifier["Mounts"].append(
        {"Type": "volume", "Name": "c" * 64, "Destination": "/var/lib/postgresql/data", "RW": True}
    )
    events = [
        {"Action": "start", "Actor": {"ID": "agent"}, "timeNano": 1},
        {"Action": "die", "Actor": {"ID": "agent"}, "timeNano": 2},
        {"Action": "start", "Actor": {"ID": "verifier"}, "timeNano": 3},
        {"Action": "die", "Actor": {"ID": "verifier"}, "timeNano": 4},
    ]
    containers = {"agent": agent, "agent_sidecar": agent_sidecar}
    containers |= {"verifier": verifier, "verifier_sidecar": verifier_sidecar}
    return trial, containers, events


def run(trial, containers, events, egress=EGRESS):
    return audit(TRIAL, trial, list(containers.values()), events, LIMITS, egress)


def outcomes(record):
    return {check["id"]: check["outcome"] for check in record["checks"]}


def test_observed_harbor_shape_passes_and_records_gaps(observed, tmp_path):
    record = run(*observed)
    assert record["outcome"] == "pass", record
    assert [c["id"] for c in record["checks"]] == list(REQUIRED)
    assert record["security_verdict"] == "not_evaluated"
    assert {
        "agent_runs_as_root",
        "agent_no_pids_limit",
        "agent_swap_allowed",
        "agent_can_write_verifier_log_directory",
        "network_via_net_admin_sidecar",
    } <= set(record["observed_gaps"])
    # Evidence carries trial-relative mount sources, never host paths.
    assert str(tmp_path) not in json.dumps(record)
    agent = next(c for c in record["containers"] if c["role"] == "agent")
    assert {m["source"] for m in agent["mounts"]} == {
        "agent",
        "verifier",
        "artifacts/logs/artifacts",
    }


@pytest.mark.parametrize(
    ("mutation", "check"),
    [
        ("privileged", "no_privilege"),
        ("main_cap", "no_privilege"),
        ("sidecar_cap", "no_privilege"),
        ("host_pid", "no_privilege"),
        ("unconfined", "no_privilege"),
        ("docker_socket", "mount_scope"),
        ("outside_trial", "mount_scope"),
        ("verifier_tests_in_agent", "mount_scope"),
        ("sidecar_bind", "mount_scope"),
        ("named_volume", "mount_scope"),
        ("memory", "declared_limits"),
        ("cpus", "declared_limits"),
        ("public_network", "network_isolation"),
        ("foreign_namespace", "network_isolation"),
        ("overlap", "agent_stopped_before_verifier"),
        ("extra_service", "separate_environments"),
        ("duplicate_main", "separate_environments"),
        ("shared_image", "separate_environments"),
        ("egress", "no_observed_egress"),
    ],
)
def test_boundary_violation_fails(observed, mutation, check):
    trial, containers, events = copy.deepcopy(observed)
    agent, verifier = containers["agent"], containers["verifier"]
    egress = EGRESS
    if mutation == "privileged":
        verifier["HostConfig"]["Privileged"] = True
    elif mutation == "main_cap":
        agent["HostConfig"]["CapAdd"] = ["CAP_SYS_ADMIN"]
    elif mutation == "sidecar_cap":
        containers["agent_sidecar"]["HostConfig"]["CapAdd"].append("CAP_SYS_ADMIN")
    elif mutation == "host_pid":
        agent["HostConfig"]["PidMode"] = "host"
    elif mutation == "unconfined":
        agent["HostConfig"]["SecurityOpt"] = ["seccomp=unconfined"]
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
    elif mutation == "memory":
        agent["HostConfig"]["Memory"] = 0
    elif mutation == "cpus":
        verifier["HostConfig"]["NanoCpus"] = 4_000_000_000
    elif mutation == "public_network":
        agent["HostConfig"]["NetworkMode"] = "bridge"
    elif mutation == "foreign_namespace":
        agent["HostConfig"]["NetworkMode"] = "container:vs"
    elif mutation == "overlap":
        events[1]["timeNano"] = 5
    elif mutation == "extra_service":
        containers["candidate_service"] = copy.deepcopy(containers["agent_sidecar"])
        containers["candidate_service"]["Config"]["Labels"]["com.docker.compose.service"] = "db"
    elif mutation == "duplicate_main":
        containers["second_agent"] = copy.deepcopy(agent)
    elif mutation == "shared_image":
        verifier["Image"] = agent["Image"]
    else:
        egress = {"control_connections": 1, "trial_connections": 1}
    record = run(trial, containers, events, egress)
    assert record["outcome"] == "fail", record
    assert outcomes(record)[check] == "fail", record


@pytest.mark.parametrize("missing", ["verifier", "events", "positive_control"])
def test_missing_observation_is_incomplete(observed, missing):
    trial, containers, events = copy.deepcopy(observed)
    egress = EGRESS
    if missing == "verifier":
        del containers["verifier"]
    elif missing == "events":
        events = []
    else:
        egress = {"control_connections": 0, "trial_connections": 0}
    record = run(trial, containers, events, egress)
    assert record["coverage"] == "incomplete"
    assert record["outcome"] == "incomplete"


def test_unrelated_containers_are_ignored(observed):
    trial, containers, events = copy.deepcopy(observed)
    containers["other"] = copy.deepcopy(containers["agent"])
    containers["other"]["Config"]["Labels"]["com.docker.compose.project"] = "other__env"
    containers["other"]["HostConfig"]["Privileged"] = True
    assert run(trial, containers, events)["outcome"] == "pass"


def test_project_names_and_declared_limits_follow_pinned_harbor():
    assert compose_project("RLS-Policy__AbC.1__env") == "rls-policy__abc-1__env"
    assert compose_project("_x") == "0_x"
    assert declared_limits(ROOT / "tasks/harbor/rls-policy/task.toml") == LIMITS
