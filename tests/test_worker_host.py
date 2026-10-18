"""Host storage lifecycle with synthetic kernel/Docker observations, never sudo."""

import errno
import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("worker_host", ROOT / "scripts/worker_host.py")
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)


@pytest.fixture
def host(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    jobs = checkout / ".research/harbor-spike"
    jobs.mkdir(parents=True)
    controller = HOST.Host(checkout, tmp_path / "state", os.getuid(), os.getgid())
    observed = SimpleNamespace(
        mounts=set(),
        calls=[],
        capacity=60 * 1024 * 1024,
        containers=[],
        fail=None,
        filesystem="ext4",
        options="rw,nodev,nosuid,noexec",
        source="/dev/loop7",
    )

    def run(*args):
        observed.calls.append(args)
        if args[0] == observed.fail:
            raise subprocess.CalledProcessError(1, args)
        if args[0] == "mount":
            observed.mounts.add(Path(args[-1]))
        elif args[0] == "umount":
            observed.mounts.remove(Path(args[-1]))
        elif args[0] == "findmnt":
            return json.dumps(
                {
                    "filesystems": [
                        {
                            "target": args[-1],
                            "source": observed.source,
                            "fstype": observed.filesystem,
                            "options": observed.options,
                        }
                    ]
                }
            )
        elif args[0] == "losetup":
            return "/dev/loop7\n" if observed.mounts else ""
        elif args[0] == "docker":
            if "ps" in args:
                return "abcdef012345\n" if observed.containers else ""
            return json.dumps(observed.containers)
        return ""

    original_stats = os.statvfs
    monkeypatch.setattr(HOST, "run", run)
    monkeypatch.setattr(HOST.os.path, "ismount", lambda path: Path(path) in observed.mounts)
    monkeypatch.setattr(
        HOST.os,
        "statvfs",
        lambda path: (
            SimpleNamespace(f_blocks=observed.capacity // 4096, f_frsize=4096)
            if Path(path) in observed.mounts
            else original_stats(path)
        ),
    )
    return controller, jobs, observed


def test_prepare_measures_real_mount_and_never_authorizes_execution(host):
    controller, jobs, observed = host
    result = controller.prepare(jobs, "oracle")
    assert result == {
        "job": str(jobs / "oracle"),
        "own_filesystem": True,
        "capacity_bytes": observed.capacity,
        "status": "prepared",
        "execution_enabled": False,
    }
    assert observed.calls[:2][0][0] == "mkfs.ext4"
    assert observed.calls[:2][1][:3] == ("mount", "-o", "loop,nodev,nosuid,noexec")
    assert controller.inspect(jobs, "oracle")["status"] == "mounted"
    before = list(observed.calls)
    with pytest.raises(ValueError, match="already exists"):
        controller.prepare(jobs, "oracle")
    assert observed.calls == before


@pytest.mark.parametrize("name", ["../escape", "a/b", "-o", "", "a b", "x" * 65])
def test_bad_job_names_cannot_invoke_commands(host, name):
    controller, jobs, observed = host
    with pytest.raises(ValueError):
        controller.prepare(jobs, name)
    assert not observed.calls


def test_unapproved_parent_and_symlink_ancestors_rejected(host):
    controller, jobs, observed = host
    outside = jobs.parent / "other"
    outside.mkdir()
    with pytest.raises(ValueError, match="allowlisted"):
        controller.prepare(outside, "oracle")
    target = jobs / "oracle"
    target.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        controller.prepare(jobs, "oracle")
    assert not observed.calls


def test_untrusted_output_parent_cannot_receive_a_privileged_mount(host):
    controller, jobs, observed = host
    jobs.chmod(0o777)
    with pytest.raises(ValueError, match="trusted owners"):
        controller.prepare(jobs, "oracle")
    assert not observed.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("capacity", HOST.CAPACITY + 4096),
        ("capacity", 0),
        ("filesystem", "tmpfs"),
        ("source", "/dev/loop8"),
        ("options", "rw,nodev,nosuid"),
    ],
)
def test_saved_record_does_not_override_mount_observation(host, field, value):
    controller, jobs, observed = host
    controller.prepare(jobs, "oracle")
    setattr(observed, field, value)
    with pytest.raises(ValueError):
        controller.inspect(jobs, "oracle")


def test_mkfs_failure_retains_intent_and_explicit_empty_abort(host):
    controller, jobs, observed = host
    observed.fail = "mkfs.ext4"
    with pytest.raises(subprocess.CalledProcessError):
        controller.prepare(jobs, "oracle")
    assert not observed.mounts
    assert controller.inspect(jobs, "oracle")["status"] == "unmounted"
    with pytest.raises(ValueError, match="already exists"):
        controller.prepare(jobs, "oracle")
    observed.fail = None
    assert controller.abort(jobs, "oracle")["status"] == "aborted"
    assert not (jobs / "oracle").exists()
    assert not list(controller.directory.glob("*.img"))


def test_abort_never_removes_a_mounted_or_nonempty_job(host):
    controller, jobs, observed = host
    controller.prepare(jobs, "oracle")
    with pytest.raises(ValueError, match="mount or data"):
        controller.abort(jobs, "oracle")
    observed.mounts.clear()
    (jobs / "oracle/evidence.json").write_text("{}")
    with pytest.raises(ValueError, match="mount or data"):
        controller.abort(jobs, "oracle")


def test_mount_intent_blocks_abort_even_when_mount_outcome_is_unknown(host):
    controller, jobs, observed = host
    observed.fail = "mount"
    with pytest.raises(subprocess.CalledProcessError):
        controller.prepare(jobs, "oracle")
    assert not observed.mounts
    with pytest.raises(ValueError, match="outcome may be unresolved"):
        controller.abort(jobs, "oracle")
    assert list(controller.directory.glob("*.img"))


def test_unmount_failure_preserves_mount_image_and_archive(host):
    controller, jobs, observed = host
    controller.prepare(jobs, "oracle")
    controller.archive(jobs, "oracle")
    observed.fail = "umount"
    with pytest.raises(subprocess.CalledProcessError):
        controller.release(jobs, "oracle")
    assert observed.mounts
    assert list(controller.directory.glob("*.img"))
    assert list(controller.directory.glob("*.tar"))


def test_controller_crash_requires_inspection_and_preserves_evidence(host):
    controller, jobs, observed = host
    controller.prepare(jobs, "oracle")
    (jobs / "oracle/result.json").write_text('{"outcome":"incomplete"}')
    # New helper process/object observes kernel state; it cannot auto-prepare.
    reopened = HOST.Host(controller.checkout, controller.directory, os.getuid(), os.getgid())
    with pytest.raises(ValueError, match="already exists"):
        reopened.prepare(jobs, "oracle")
    assert reopened.inspect(jobs, "oracle")["status"] == "mounted"
    archive = reopened.archive(jobs, "oracle")
    assert Path(archive["archive"]).is_file()
    result = reopened.release(jobs, "oracle")
    assert result["status"] == "released"
    assert not observed.mounts
    assert reopened.inspect(jobs, "oracle")["status"] == "unmounted"


def test_archive_and_release_refuse_any_docker_reference_including_stopped(host):
    controller, jobs, observed = host
    controller.prepare(jobs, "oracle")
    observed.containers = [
        {
            "State": {"Running": False},
            "Mounts": [
                {
                    "Source": str(jobs / "oracle/trial/verifier"),
                }
            ],
        }
    ]
    with pytest.raises(ValueError, match="still references"):
        controller.archive(jobs, "oracle")
    assert jobs / "oracle" in observed.mounts
    observed.containers = []
    controller.archive(jobs, "oracle")
    observed.containers = [{"Mounts": [{"Source": str(jobs / "oracle")}]}]
    with pytest.raises(ValueError, match="still references"):
        controller.release(jobs, "oracle")
    assert jobs / "oracle" in observed.mounts


@pytest.mark.parametrize("source", ["parent", "checkout", "root"])
def test_ancestor_bind_also_blocks_archival(host, source):
    controller, jobs, observed = host
    controller.prepare(jobs, "oracle")
    path = {"parent": jobs, "checkout": controller.checkout, "root": Path("/")}[source]
    observed.containers = [{"State": {"Running": False}, "Mounts": [{"Source": str(path)}]}]
    with pytest.raises(ValueError, match="still references"):
        controller.archive(jobs, "oracle")
    assert jobs / "oracle" in observed.mounts


def test_crash_partial_is_not_deleted_by_archive_retry(host):
    controller, jobs, observed = host
    controller.prepare(jobs, "oracle")
    _, prefix = controller.context(jobs, "oracle")
    partial = prefix.with_suffix(".partial")
    partial.write_bytes(b"retained interrupted synthetic archive")
    with pytest.raises(ValueError, match="partial archive already exists"):
        controller.archive(jobs, "oracle")
    assert partial.read_bytes() == b"retained interrupted synthetic archive"
    assert controller.inspect(jobs, "oracle")["partial_archive_present"] is True
    assert jobs / "oracle" in observed.mounts


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "sparse"])
def test_hostile_archive_input_records_metadata_without_following_or_reading(host, kind):
    controller, jobs, observed = host
    controller.prepare(jobs, "oracle")
    target = jobs / "oracle/hostile"
    if kind == "symlink":
        target.symlink_to("/etc/passwd")
    elif kind == "hardlink":
        sibling = jobs / "oracle/sibling"
        sibling.write_text("synthetic")
        os.link(sibling, target)
    elif kind == "fifo":
        os.mkfifo(target)
    else:
        with target.open("wb") as stream:
            stream.truncate(HOST.CAPACITY + 1)
    controller.archive(jobs, "oracle")
    _, prefix = controller.context(jobs, "oracle")
    record = json.loads(prefix.with_suffix(".archive.json").read_bytes())
    entry = next(item for item in record["entries"] if item["path"] == "hostile")
    assert entry["content"].startswith("metadata_only_")
    assert jobs / "oracle" in observed.mounts
    assert not list(controller.directory.glob("*.partial"))
    assert list(controller.directory.glob("*.tar"))
    assert controller.release(jobs, "oracle")["status"] == "released"
    assert prefix.with_suffix(".img").is_file(), "Preserve original bounded filesystem"


def test_release_requires_intact_archive_and_retains_mount_on_failure(host):
    controller, jobs, observed = host
    controller.prepare(jobs, "oracle")
    with pytest.raises(FileNotFoundError):
        controller.release(jobs, "oracle")
    archived = controller.archive(jobs, "oracle")
    Path(archived["archive"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="archive is missing or corrupt"):
        controller.release(jobs, "oracle")
    assert jobs / "oracle" in observed.mounts


def test_root_state_rejects_corruption_and_metadata_links(host):
    controller, jobs, observed = host
    controller.prepare(jobs, "oracle")
    _, prefix = controller.context(jobs, "oracle")
    record = prefix.with_suffix(".json")
    value = json.loads(record.read_bytes())
    value["job"] = "/other"
    record.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="does not match"):
        controller.inspect(jobs, "oracle")
    record.unlink()
    record.symlink_to("/etc/passwd")
    with pytest.raises(OSError) as error:
        controller.inspect(jobs, "oracle")
    assert error.value.errno == errno.ELOOP


def test_nonblocking_host_lock(host):
    controller, _, _ = host
    with controller.lock(), pytest.raises(BlockingIOError), controller.lock():
        pass


def test_configuration_requires_private_writer_identity_and_exact_fields(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    config = tmp_path / "host.json"
    value = {"schema_version": 1, "checkout": str(checkout), "uid": 1000, "gid": 1000}
    config.write_text(json.dumps(value))
    config.chmod(0o644)
    assert HOST.load_config(config, os.getuid()) == value
    config.chmod(0o666)
    with pytest.raises(ValueError, match="untrusted"):
        HOST.load_config(config, os.getuid())
    config.chmod(0o644)
    value["uid"] = 10001
    config.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="workload identities"):
        HOST.load_config(config, os.getuid())


@pytest.mark.parametrize("setting", ["1", "0", "invalid"])
def test_required_host_storage_precedes_harbor_and_never_falls_back(monkeypatch, tmp_path, setting):
    spec = importlib.util.spec_from_file_location("worker_spike", ROOT / "scripts/harbor_spike.py")
    spike = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(spike)
    monkeypatch.setenv("DS_WORKER_HOST_REQUIRED", setting)
    calls = []

    def invoke(arguments, **kwargs):
        calls.append(arguments)
        if arguments[0] == "sudo":
            raise subprocess.CalledProcessError(1, arguments)

    monkeypatch.setattr(spike.subprocess, "run", invoke)
    if setting == "1":
        with pytest.raises(subprocess.CalledProcessError):
            spike.run_trial(tmp_path, "nop", tmp_path, "oracle")
        assert len(calls) == 1 and calls[0][:4] == ["sudo", "-n", HOST.HELPER, "prepare"]
    elif setting == "invalid":
        with pytest.raises(ValueError):
            spike.run_trial(tmp_path, "nop", tmp_path, "oracle")
        assert not calls
    else:
        spike.run_trial(tmp_path, "nop", tmp_path, "oracle")
        assert len(calls) == 1 and calls[0][0] == "harbor"


@pytest.mark.parametrize(
    "mounted,capacity",
    [(False, HOST.CAPACITY), (True, 0), (True, HOST.CAPACITY + 1), (True, HOST.CAPACITY)],
)
def test_required_hook_independently_measures_filesystem(monkeypatch, tmp_path, mounted, capacity):
    spec = importlib.util.spec_from_file_location("worker_spike", ROOT / "scripts/harbor_spike.py")
    spike = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(spike)
    monkeypatch.setenv("DS_WORKER_HOST_REQUIRED", "1")
    calls = []
    monkeypatch.setattr(
        spike.subprocess, "run", lambda arguments, **kwargs: calls.append(arguments)
    )
    monkeypatch.setattr(spike.os.path, "ismount", lambda path: mounted)
    monkeypatch.setattr(
        spike.os, "statvfs", lambda path: SimpleNamespace(f_blocks=capacity, f_frsize=1)
    )
    if mounted and capacity == HOST.CAPACITY:
        spike.run_trial(tmp_path, "nop", tmp_path, "oracle")
        assert [call[0] for call in calls] == ["sudo", "harbor"]
    else:
        with pytest.raises(ValueError, match="not observed"):
            spike.run_trial(tmp_path, "nop", tmp_path, "oracle")
        assert [call[0] for call in calls] == ["sudo"]
