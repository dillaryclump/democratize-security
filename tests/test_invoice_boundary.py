import copy

import pytest

from democratize_security.adapters.runners.invoice_boundary import audit_application


def inspections():
    project = "trial__verifier__trial"

    def mounts(writable):
        return [
            {"Destination": "/appsock", "Source": "volume-a", "Type": "volume", "RW": writable},
            {
                "Destination": "/dbsocket",
                "Source": "volume-b",
                "Type": "volume",
                "RW": not writable,
            },
            {"Destination": "/tmp", "Source": "", "Type": "tmpfs", "RW": True},
        ]

    app = {
        "Id": "app-id",
        "Image": "sha256:app",
        "Config": {
            "User": "10001:10001",
            "Env": [],
            "Labels": {"com.docker.compose.project": project, "com.docker.compose.service": "app"},
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": [],
            "SecurityOpt": ["no-new-privileges:true"],
            "Memory": 256 * 1024 * 1024,
            "MemorySwap": 256 * 1024 * 1024,
            "PidsLimit": 64,
            "NanoCpus": 1000000000,
        },
        "Mounts": mounts(True),
    }
    verifier = copy.deepcopy(app)
    verifier.update(Id="verifier-id", Image="sha256:verifier", Mounts=mounts(False))
    verifier["Config"]["User"] = "postgres"
    verifier["Config"]["Labels"]["com.docker.compose.service"] = "main"
    verifier["HostConfig"].update(
        CapAdd=["CHOWN", "DAC_OVERRIDE", "FOWNER"],
        Memory=512 * 1024 * 1024,
        MemorySwap=512 * 1024 * 1024,
        PidsLimit=128,
    )
    return [app, verifier]


def test_observed_socket_boundary_passes():
    result = audit_application("trial", inspections(), "nonce-value")
    assert result["outcome"] == "pass"
    assert result["application_image_id"] != result["verifier_image_id"]


@pytest.mark.parametrize(
    "fault",
    [
        "root",
        "network",
        "secret",
        "mount",
        "writable_db",
        "verifier_network",
        "missing",
        "privilege_override",
    ],
)
def test_application_boundary_rejects_unsafe_observations(fault):
    observed = inspections()
    app, verifier = observed
    if fault == "root":
        app["Config"]["User"] = "root"
    elif fault == "network":
        app["HostConfig"]["NetworkMode"] = "bridge"
    elif fault == "secret":
        app["Config"]["Env"] = ["STOLEN=nonce-value"]
    elif fault == "mount":
        app["Mounts"].append({"Destination": "/logs/verifier"})
    elif fault == "writable_db":
        app["Mounts"][1]["RW"] = True
    elif fault == "verifier_network":
        verifier["HostConfig"]["NetworkMode"] = "host"
    elif fault == "missing":
        observed.pop()
    else:
        app["HostConfig"]["SecurityOpt"].append("no-new-privileges:false")
    with pytest.raises(ValueError):
        audit_application("trial", observed, "nonce-value")
