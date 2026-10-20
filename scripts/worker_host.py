#!/usr/bin/python3 -I
"""Trusted Linux host storage helper; never installed in a workload image.

Only the root-owned installed copy is suitable for sudo. This is filesystem
administration, not a dispatcher, recovery controller or result acceptance API.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from contextlib import contextmanager
from pathlib import Path

CAPACITY = 64 * 1024 * 1024
ARCHIVE_LIMIT = 80 * 1024 * 1024
METADATA_LIMIT = 8 * 1024 * 1024
CONFIG = Path("/etc/ds-worker-host.json")
STATE = Path("/var/lib/ds-worker-host")
HELPER = "/usr/local/libexec/ds-worker-host"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
PARENTS = {
    "harbor-spike",
    "harbor-replay",
    "harbor-audit",
    "harbor-apps/invoice-read",
    "harbor-apps/invoice-search",
    "harbor-apps/invoice-export",
    "worker-host-check",
    "terminus-conformance",
}


def run(*args):
    return subprocess.run(
        args, check=True, capture_output=True, text=True, timeout=60, env=ENV, cwd="/"
    ).stdout


def plain_path(path):
    """Reject symbolic ancestors, including the final component if it exists."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute paths without parent traversal are required")
    for component in reversed((path, *path.parents)):
        if component.is_symlink():
            raise ValueError("symlink in host path")
    return path


def trusted_file(path, owner, *, limit=4096):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != owner
            or info.st_mode & 0o022
            or info.st_size > limit
        ):
            raise ValueError("untrusted host metadata")
        return stream.read(limit + 1)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new(path, value):
    data = (json.dumps(value, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def load_config(path=CONFIG, owner=0):
    plain_path(path)
    config = json.loads(trusted_file(path, owner))
    if (
        not isinstance(config, dict)
        or set(config) != {"schema_version", "checkout", "uid", "gid"}
        or type(config["schema_version"]) is not int
        or config["schema_version"] != 1
    ):
        raise ValueError("invalid host configuration")
    for key in ("uid", "gid"):
        if type(config[key]) is not int or not 0 < config[key] < 2**31:
            raise ValueError("controller must have an explicit non-root uid and gid")
    if config["uid"] in {999, 10001, 20001}:
        raise ValueError("controller uid must differ from workload identities")
    checkout = plain_path(Path(config["checkout"]))
    if not checkout.is_dir():
        raise ValueError("checkout missing")
    return config


class Host:
    def __init__(self, checkout, directory, uid, gid):
        self.checkout = plain_path(Path(checkout))
        self.directory = plain_path(Path(directory))
        self.uid, self.gid, self.owner = uid, gid, os.geteuid()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.stat()
        if info.st_uid != self.owner or info.st_mode & 0o077:
            raise ValueError("host state must be private and owned by the helper")

    @contextmanager
    def lock(self):
        path = self.directory / "host.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.owner:
                raise ValueError("untrusted host lock")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(descriptor)

    def context(self, jobs_dir, name):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name):
            raise ValueError("invalid job name")
        parent = plain_path(Path(jobs_dir))
        relative = parent.relative_to(self.checkout / ".research").as_posix()
        if relative not in PARENTS or not parent.is_dir():
            raise ValueError("job parent is not allowlisted")
        for component in (parent, *parent.parents):
            info = component.stat()
            if info.st_uid not in {self.owner, self.uid} or info.st_mode & 0o022:
                raise ValueError("job ancestors must be writable only by trusted owners")
            if component == self.checkout:
                break
        job = plain_path(parent / name)
        digest = hashlib.sha256(str(job).encode()).hexdigest()
        return job, self.directory / digest

    def record(self, job, prefix):
        record = json.loads(trusted_file(prefix.with_suffix(".json"), self.owner))
        if record != {"schema_version": 1, "job": str(job), "capacity": CAPACITY}:
            raise ValueError("host state does not match this job")
        return record

    def mounted(self, job, prefix):
        """Check the kernel mount and actual backing image, never a saved marker."""
        image = prefix.with_suffix(".img")
        info = image.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != self.owner
            or info.st_mode & 0o077
            or info.st_size != CAPACITY
        ):
            raise ValueError("invalid filesystem image")
        observed = json.loads(run("findmnt", "--json", "--mountpoint", str(job)))
        mounts = observed.get("filesystems", [])
        if len(mounts) != 1:
            raise ValueError("expected one job mount")
        mount = mounts[0]
        devices = run("losetup", "--associated", str(image), "--noheadings", "--output", "NAME")
        if (
            mount.get("target") != str(job)
            or mount.get("fstype") != "ext4"
            or devices.split() != [mount.get("source")]
            or not re.fullmatch(r"/dev/loop[0-9]+", mount.get("source", ""))
            or not {"rw", "nodev", "nosuid", "noexec"} <= set(mount.get("options", "").split(","))
            or not os.path.ismount(job)
        ):
            raise ValueError("job mount provenance or options mismatch")
        stats = os.statvfs(job)
        capacity = stats.f_blocks * stats.f_frsize
        if not 0 < capacity <= CAPACITY:
            raise ValueError("job filesystem is unbounded")
        return {"job": str(job), "own_filesystem": True, "capacity_bytes": capacity}

    def prepare(self, jobs_dir, name):
        job, prefix = self.context(jobs_dir, name)
        # An existing record, mount or directory is inspection-only: never resume.
        if job.exists() or any(self.directory.glob(prefix.name + ".*")):
            raise ValueError("job already exists; inspect and release explicitly")
        write_new(
            prefix.with_suffix(".json"),
            {"schema_version": 1, "job": str(job), "capacity": CAPACITY},
        )
        job.mkdir(mode=0o700)
        image = prefix.with_suffix(".img")
        descriptor = os.open(image, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.ftruncate(descriptor, CAPACITY)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        sync_directory(self.directory)
        run("mkfs.ext4", "-q", "-F", "-m", "0", str(image))
        # Persist before the external mount. Once it may have been sent, an
        # unmounted directory alone cannot prove this image never held evidence.
        write_new(prefix.with_suffix(".mount-intent.json"), {"job": str(job)})
        run("mount", "-o", "loop,nodev,nosuid,noexec", str(image), str(job))
        observation = self.mounted(job, prefix)
        os.chown(job, self.uid, self.gid)
        os.chmod(job, 0o700)
        return {**observation, "status": "prepared", "execution_enabled": False}

    def inspect(self, jobs_dir, name):
        job, prefix = self.context(jobs_dir, name)
        self.record(job, prefix)
        stages = {
            "mount_intent_present": prefix.with_suffix(".mount-intent.json").exists(),
            "archive_present": prefix.with_suffix(".tar").exists(),
            "archive_manifest_present": prefix.with_suffix(".archive.json").exists(),
            "partial_archive_present": prefix.with_suffix(".partial").exists(),
        }
        if not os.path.ismount(job):
            return {**stages, "job": str(job), "status": "unmounted", "execution_enabled": False}
        return {
            **stages,
            **self.mounted(job, prefix),
            "status": "mounted",
            "execution_enabled": False,
        }

    def require_detached(self, job):
        identities = run("docker", "--host", "unix:///var/run/docker.sock", "ps", "-aq").split()
        if not identities:
            return
        if len(identities) > 256 or any(
            not re.fullmatch(r"[a-f0-9]{12,64}", i) for i in identities
        ):
            raise ValueError("unexpected Docker inventory")
        containers = json.loads(
            run("docker", "--host", "unix:///var/run/docker.sock", "inspect", *identities)
        )
        for container in containers:
            for mount in container.get("Mounts", []):
                source = Path(mount.get("Source", "/"))
                if source == job or job in source.parents or source in job.parents:
                    raise ValueError("a Docker container still references this job")

    def archive(self, jobs_dir, name):
        job, prefix = self.context(jobs_dir, name)
        self.record(job, prefix)
        self.mounted(job, prefix)
        self.require_detached(job)
        target = prefix.with_suffix(".tar")
        manifest = prefix.with_suffix(".archive.json")
        if target.exists() or manifest.exists():
            raise ValueError("archive already exists; inspect it before release")
        partial = prefix.with_suffix(".partial")
        if os.path.lexists(partial):
            raise ValueError("partial archive already exists; retain it for inspection")
        total, count, metadata = 0, 0, []
        created = False
        try:
            with partial.open("xb") as output, tarfile.open(fileobj=output, mode="w|") as archive:
                created = True
                os.chmod(partial, 0o600)
                for path in sorted(job.rglob("*")):
                    relative = path.relative_to(job).as_posix()
                    info = path.lstat()
                    count += 1
                    if count > 4096 or len(relative.encode()) > 512:
                        raise ValueError("archive metadata limit")
                    item = {"path": relative, "mode": info.st_mode, "size": info.st_size}
                    metadata.append(item)
                    if stat.S_ISDIR(info.st_mode):
                        item["content"] = "directory"
                        continue
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        item["content"] = "metadata_only_link_or_special"
                        if stat.S_ISLNK(info.st_mode):
                            item["link_target"] = os.readlink(path)
                        continue
                    if total + info.st_size > CAPACITY:
                        # Harbor controls deliberately leave sparse, FIFO and
                        # symlink logs. Record them without reading/following;
                        # the original bounded image is retained after release.
                        item["content"] = "metadata_only_logical_byte_limit"
                        continue
                    if output.tell() + info.st_size + 2048 > ARCHIVE_LIMIT:
                        raise ValueError("archive byte limit")
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(descriptor, "rb") as stream:
                        opened = os.fstat(stream.fileno())
                        if (opened.st_dev, opened.st_ino, opened.st_size) != (
                            info.st_dev,
                            info.st_ino,
                            info.st_size,
                        ):
                            raise ValueError("archive input changed")
                        entry = tarfile.TarInfo(relative)
                        entry.size, entry.mode = info.st_size, 0o600
                        archive.addfile(entry, stream)
                        item["content"] = "archived"
                        total += info.st_size
                archive.close()
                output.flush()
                os.fsync(output.fileno())
            if partial.stat().st_size > ARCHIVE_LIMIT:
                raise ValueError("archive byte limit")
            with partial.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            os.link(partial, target, follow_symlinks=False)
            partial.unlink()
            sync_directory(self.directory)
            record = {
                "schema_version": 1,
                "job": str(job),
                "archive_sha256": digest,
                "archive_bytes": target.stat().st_size,
                "files": count,
                "entries": metadata,
            }
            if len(json.dumps(record).encode()) > METADATA_LIMIT - 1:
                raise ValueError("archive metadata byte limit")
            write_new(manifest, record)
            return {"archive": str(target), "sha256": digest, "status": "archived"}
        finally:
            if created:
                partial.unlink(missing_ok=True)

    def release(self, jobs_dir, name):
        job, prefix = self.context(jobs_dir, name)
        self.record(job, prefix)
        self.mounted(job, prefix)
        self.require_detached(job)
        manifest = json.loads(
            trusted_file(prefix.with_suffix(".archive.json"), self.owner, limit=METADATA_LIMIT)
        )
        archive = prefix.with_suffix(".tar")
        data = trusted_file(archive, self.owner, limit=ARCHIVE_LIMIT)
        if (
            manifest.get("job") != str(job)
            or manifest.get("archive_bytes") != len(data)
            or manifest.get("archive_sha256") != hashlib.sha256(data).hexdigest()
        ):
            raise ValueError("archive is missing or corrupt; retain mount")
        run("umount", str(job))
        if os.path.ismount(job):
            raise ValueError("job mount did not stop")
        # Keep root-owned image/record/archive for explicit inspection, never dispatch.
        return {
            "job": str(job),
            "archive": str(archive),
            "status": "released",
            "execution_enabled": False,
        }

    def abort(self, jobs_dir, name):
        """Explicitly discard only a never-mounted, empty preparation after a crash."""
        job, prefix = self.context(jobs_dir, name)
        self.record(job, prefix)
        self.require_detached(job)
        if os.path.ismount(job) or (job.exists() and any(job.iterdir())):
            raise ValueError("preparation has a mount or data; retain for inspection")
        image = prefix.with_suffix(".img")
        if image.exists() and run("losetup", "--associated", str(image), "--noheadings").strip():
            raise ValueError("preparation has a loop device; retain for inspection")
        if any(prefix.with_suffix(suffix).exists() for suffix in (".tar", ".archive.json")):
            raise ValueError("archived job cannot be discarded as a preparation")
        if prefix.with_suffix(".mount-intent.json").exists():
            raise ValueError("mount outcome may be unresolved; retain filesystem image")
        image.unlink(missing_ok=True)
        if job.exists():
            job.rmdir()
        prefix.with_suffix(".json").unlink()
        sync_directory(self.directory)
        return {"job": str(job), "status": "aborted", "execution_enabled": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "inspect", "archive", "release", "abort"))
    parser.add_argument("jobs_dir")
    parser.add_argument("job_name")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires the trusted root-owned helper on a dedicated Linux host")
    config = load_config()
    if int(os.environ.get("SUDO_UID", "0")) not in {0, config["uid"]}:
        raise ValueError("caller is not the configured controller")
    host = Host(config["checkout"], STATE, config["uid"], config["gid"])
    with host.lock():
        print(json.dumps(getattr(host, args.action)(args.jobs_dir, args.job_name), sort_keys=True))


if __name__ == "__main__":
    main()
