"""Host-observed checks for the added application sidecar, not an escape proof."""

import json

from democratize_security.adapters.runners.harbor_audit import compose_project


def audit_application(trial_name, inspections, nonce):
    project = compose_project(f"{trial_name}__verifier__trial")
    members = [
        c
        for c in inspections
        if (c["Config"].get("Labels") or {}).get("com.docker.compose.project") == project
    ]
    apps = [c for c in members if c["Config"]["Labels"].get("com.docker.compose.service") == "app"]
    verifiers = [
        c for c in members if c["Config"]["Labels"].get("com.docker.compose.service") == "main"
    ]
    if len(apps) != 1 or len(verifiers) != 1:
        raise ValueError("Missing or duplicate application/verifier inspection")
    app, verifier = apps[0], verifiers[0]
    host = app["HostConfig"]

    def caps(xs):
        return {x.removeprefix("CAP_") for x in xs or []}

    if (
        app["Config"]["User"] != "10001:10001"
        or host["NetworkMode"] != "none"
        or not host["ReadonlyRootfs"]
        or host["Privileged"]
        or host.get("Devices")
        or caps(host.get("CapDrop")) != {"ALL"}
        or host.get("CapAdd")
        or not any(
            s in ("no-new-privileges", "no-new-privileges:true")
            for s in host.get("SecurityOpt") or []
        )
        or host["Memory"] != 256 * 1024 * 1024
        or host["MemorySwap"] != host["Memory"]
        or host["PidsLimit"] != 64
        or host["NanoCpus"] != 1000000000
        or host.get("PidMode") == "host"
        or host.get("IpcMode") == "host"
        or app["Image"] == verifier["Image"]
        or not nonce
        or nonce in json.dumps(app)
        or nonce in json.dumps(verifier)
    ):
        raise ValueError("Unsafe application container or exposed verifier nonce")
    vh = verifier["HostConfig"]
    if (
        verifier["Config"]["User"] != "postgres"
        or vh["NetworkMode"] != "none"
        or not vh["ReadonlyRootfs"]
        or vh["Privileged"]
        or vh.get("Devices")
        or caps(vh.get("CapDrop")) != {"ALL"}
        or caps(vh.get("CapAdd")) != {"CHOWN", "DAC_OVERRIDE", "FOWNER"}
        or vh["Memory"] != 512 * 1024 * 1024
        or vh["MemorySwap"] != vh["Memory"]
        or vh["PidsLimit"] != 128
        or vh["NanoCpus"] != 1000000000
    ):
        raise ValueError("Unsafe verifier container")
    for cfg in (host, vh):
        flags = [s for s in cfg.get("SecurityOpt") or [] if s.startswith("no-new-privileges")]
        if (
            not flags
            or flags[-1] not in ("no-new-privileges", "no-new-privileges:true")
            or any("unconfined" in s for s in cfg.get("SecurityOpt") or [])
            or any(cfg.get(k) == "host" for k in ("PidMode", "IpcMode", "UTSMode", "UsernsMode"))
        ):
            raise ValueError("Unsafe namespace or security options")
    mounts = {m["Destination"]: m for m in app["Mounts"]}
    if set(mounts) != {"/appsock", "/dbsocket", "/tmp"}:
        raise ValueError("Application has unexpected mounts")
    for path, writable in (("/appsock", True), ("/dbsocket", False)):
        if mounts[path]["Type"] != "volume" or mounts[path]["RW"] != writable:
            raise ValueError("Incorrect application socket mount")
        peer = next((m for m in verifier["Mounts"] if m["Destination"] == path), None)
        if peer is None or peer["Source"] != mounts[path]["Source"] or peer["RW"] == writable:
            raise ValueError("Socket sharing does not match the reviewed topology")
    if mounts["/tmp"]["Type"] != "tmpfs":
        raise ValueError("Application temporary storage is not tmpfs")
    env = app["Config"].get("Env") or []
    if any(e.startswith(("DS_NONCE=", "DS_RUNTIME_PASSWORD=", "POSTGRES_PASSWORD=")) for e in env):
        raise ValueError("Unexpected credential in application environment")
    return {
        "policy": "invoice-application-boundary-v1",
        "outcome": "pass",
        "application_image_id": app["Image"],
        "verifier_image_id": verifier["Image"],
        "application_container_id": app["Id"],
        "verifier_container_id": verifier["Id"],
        "limitations": ["reviewed_controls_only", "storage_unbounded", "shared_host_kernel"],
    }
