"""Offline checks that the three application tasks stay consistent and reviewed.

Harbor needs each task directory to be self-contained, so verifier files are
copied; these tests make every copy provably identical to its single source.
"""

import ast
import json
import os
import re
import runpy
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from democratize_security.policy_replay import APP_TRUSTED_FILES

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "src/democratize_security/reference/app.py"
# The endpoint each task's starter omits.
TASKS = {"invoice-read": "invoice", "invoice-search": "invoices", "invoice-export": "export"}
CONTROLS = json.loads((ROOT / "scripts/app_controls/expected.json").read_text())


def task(name):
    return ROOT / "tasks/harbor" / name


def files(directory):
    return sorted(p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file())


# Statements an unsafe control may add beside its endpoint, by task.
UNSAFE_EXTRAS = {"invoice-search": ["cache = {}"]}


def create_app(tree):
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "create_app")


def app_module(source, *, drop=(), extras=(), docstring=True):
    """Whole-module AST dump, minus named create_app functions and allowed extras."""
    tree = ast.parse(source)
    if not docstring:
        tree.body = [n for n in tree.body if not isinstance(n, ast.Expr)]
    extra = {ast.dump(ast.parse(statement).body[0]) for statement in extras}
    create = create_app(tree)
    create.body = [
        node
        for node in create.body
        if not (isinstance(node, ast.FunctionDef) and node.name in drop)
        and ast.dump(node) not in extra
    ]
    return ast.dump(tree)


def endpoint(source, name):
    create = create_app(ast.parse(source))
    return next(n for n in create.body if isinstance(n, ast.FunctionDef) and n.name == name)


def test_every_task_has_exactly_the_reviewed_files():
    for name in TASKS:
        assert files(task(name)) == sorted(
            [
                *APP_TRUSTED_FILES,
                "environment/Dockerfile",
                "environment/app.py",
                "environment/app-requirements.txt",
                "solution/app.py",
                "solution/solve.sh",
            ]
        )


def test_verifier_and_shared_files_are_identical_copies():
    first = task("invoice-read")
    for name in TASKS:
        for path in [*APP_TRUSTED_FILES, "environment/Dockerfile", "solution/solve.sh"]:
            if path not in {"task.toml", "instruction.md"}:
                assert (task(name) / path).read_bytes() == (first / path).read_bytes(), path
        tests = task(name) / "tests"
        sources = ROOT / "src/democratize_security/verification"
        assert (tests / "verify.py").read_bytes() == (sources / "reference.py").read_bytes()
        assert (tests / "fixture.py").read_bytes() == (sources / "fixture.py").read_bytes()
        assert (task(name) / "solution/app.py").read_bytes() == REFERENCE.read_bytes()
        assert (task(name) / "environment/app-requirements.txt").read_bytes() == (
            tests / "app-requirements.txt"
        ).read_bytes()
    environment = (first / "environment/docker-compose.yaml").read_bytes()
    assert (
        environment
        == (ROOT / "tasks/harbor/rls-policy/environment/docker-compose.yaml").read_bytes()
    )


def test_task_configuration_is_separate_and_isolated():
    for name in TASKS:
        config = tomllib.loads((task(name) / "task.toml").read_text())
        assert config["task"]["name"] == f"democratize-security/{name}"
        assert config["artifacts"][1:] == [
            {"source": "/candidate/app.py", "destination": "app.py", "service": "collector"}
        ]
        assert config["verifier"]["environment_mode"] == "separate"
        for section in (config["environment"], config["verifier"]["environment"]):
            assert section["network_mode"] == "no-network"
        # Harbor would `exec -u` as these users, overriding the audited ones.
        assert "user" not in config["agent"] and "user" not in config["verifier"]


@pytest.mark.parametrize("name", sorted(TASKS))
def test_starter_is_the_reference_minus_one_endpoint(name):
    # Everything else, docstring, tenant(), lifespan and handlers included, is equal.
    reference = REFERENCE.read_text()
    starter = app_module((task(name) / "environment/app.py").read_text())
    assert starter == app_module(reference, drop={TASKS[name]})
    assert starter != app_module(reference)


@pytest.mark.parametrize("name", sorted(TASKS))
def test_unsafe_control_changes_only_its_endpoint(name):
    reference = REFERENCE.read_text()
    unsafe = (ROOT / f"scripts/app_controls/{name}-unsafe.py").read_text()
    assert app_module(
        unsafe, drop={TASKS[name]}, extras=UNSAFE_EXTRAS.get(name, ()), docstring=False
    ) == app_module(reference, drop={TASKS[name]}, docstring=False)
    ours, theirs = endpoint(reference, TASKS[name]), endpoint(unsafe, TASKS[name])
    assert [ast.dump(d) for d in theirs.decorator_list] == [
        ast.dump(d) for d in ours.decorator_list
    ]
    assert ast.dump(theirs) != ast.dump(ours)


def test_control_expectations_cover_the_protocol(apps):
    verification = pytest.importorskip("democratize_security.verification.reference")
    assert apps["PROTOCOL"] == verification.PROTOCOL
    assert set(CONTROLS) == set(TASKS)
    for controls in CONTROLS.values():
        assert set(controls) == {"nop", "unsafe"}
        for control, outcomes in controls.items():
            assert set(outcomes) == verification.REQUIRED
            # Each control is a genuine failure; unsafe ones fail a security check.
            assert "fail" in outcomes.values()
            if control == "unsafe":
                assert outcomes["authorized_reads"] == "pass"
                assert {"spoofing", "tenant_switching"} & {
                    k for k, v in outcomes.items() if v == "fail"
                }


def test_solutions_are_executable_by_the_unprivileged_agent():
    # docker cp keeps the host owner (the CI runner), so Harbor's capability-less
    # root cannot chmod it; the committed mode must already allow execution.
    for name in TASKS:
        path = f"tasks/harbor/{name}/solution/solve.sh"
        staged = subprocess.run(
            ["git", "ls-files", "-s", path], capture_output=True, text=True, check=True, cwd=ROOT
        ).stdout
        assert staged.startswith("100755 "), path


def test_app_image_holds_no_verifier_code():
    dockerfile = (task("invoice-read") / "tests/app.Dockerfile").read_text()
    lines = re.sub(r"\\\n", " ", dockerfile).splitlines()
    instructions = [line.split() for line in lines if line.strip() and line.lstrip()[0] != "#"]
    copies = [words for words in instructions if words[0].upper() in {"COPY", "ADD"}]
    assert all(words[0].upper() == "COPY" for words in copies)
    assert not any(word.startswith("--from") for words in copies for word in words)
    sources = [s for words in copies for s in [w for w in words[1:] if w[:2] != "--"][:-1]]
    assert sorted(sources) == ["app-requirements.txt", "launch.py"]
    verifier = (task("invoice-read") / "tests/Dockerfile").read_text()
    assert "app.py" not in verifier and "launch.py" not in verifier


def test_app_service_is_hardened_and_confined():
    compose = (task("invoice-read") / "tests/docker-compose.yaml").read_text()
    app = compose[compose.index("\n  app:\n") : compose.index("\nvolumes:\n")]
    for line in (
        'network_mode: "service:main"',
        'user: "20001:20001"',
        "init: true",
        "read_only: true",
        "cap_drop: [ALL]",
        'security_opt: ["no-new-privileges:true"]',
        "pids_limit: 64",
        "mem_limit: 256m",
        "memswap_limit: 256m",
        "cpus: 1",
    ):
        assert f"\n    {line}\n" in app, line
    assert "\n      - candidate:/candidate:ro\n" in app
    assert "\n    tmpfs:\n      - /tmp:rw,noexec,nosuid,size=16m\n" in app
    assert "cap_add" not in app and "environment" not in app
    # Only the network namespace is shared with the verifier.
    assert not re.search(r"^\s+(pid|ipc|uts|userns_mode|privileged|devices):", app, re.M)
    main = compose[compose.index("\n  main:\n") : compose.index("\n  app:\n")]
    assert '\n    network_mode: "none"\n' in main
    assert '\n    user: "999:999"\n' in main
    assert "\n      - candidate:/candidate\n" in main


def requirements(path):
    pins = {}
    for block in re.split(r"\n(?=[a-z])", path.read_text()):
        match = re.match(r"([a-z0-9_.-]+)==(\S+)", block)
        if match:
            assert "--hash=sha256:" in block, match.group(1)
            pins[match.group(1)] = match.group(2)
    return pins


def test_requirements_are_hash_pinned_to_the_lockfile():
    lock = {
        p["name"]: p["version"] for p in tomllib.loads((ROOT / "uv.lock").read_text())["package"]
    }
    tests = task("invoice-read") / "tests"
    app = requirements(tests / "app-requirements.txt")
    verifier = requirements(tests / "verifier-requirements.txt")
    assert {"fastapi", "uvicorn", "psycopg", "psycopg-binary", "psycopg-pool"} <= set(app)
    assert {"httpx", "psycopg", "psycopg-binary"} <= set(verifier)
    for pins in (app, verifier):
        assert pins and all(lock[name] == version for name, version in pins.items())


@pytest.fixture
def verifier(monkeypatch):
    """The task's trusted orchestrator, loaded as its own module."""
    import importlib.util

    pytest.importorskip("psycopg")
    tests = task("invoice-read") / "tests"
    # Importing must not leave bytecode inside the reviewed task directory.
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    monkeypatch.syspath_prepend(str(tests))
    spec = importlib.util.spec_from_file_location("ds_app_verifier", tests / "run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield module
    # run.py imports its reviewed neighbours as top-level modules.
    for name in ("fixture", "verify"):
        sys.modules.pop(name, None)


@pytest.fixture
def apps():
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        yield runpy.run_path(str(ROOT / "scripts/harbor_apps.py"), run_name="apps")
    finally:
        sys.path.remove(str(ROOT / "scripts"))


NONCE = "e" * 64


def evidence(output):
    return json.loads((output / "app-evidence.json").read_text())


def test_orchestrator_without_nonce_emits_no_reward(verifier, tmp_path):
    output = tmp_path / "verifier"
    output.mkdir()
    (output / "reward.json").write_text('{"reward": 1}')
    (output / "reward.txt").symlink_to(tmp_path / "outside")
    with pytest.raises(SystemExit):
        verifier.main(output=output, environ={})
    assert list(output.iterdir()) == []
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("submission", ["missing", "symlink", "directory", "oversize", "binary"])
def test_invalid_submission_gets_a_bound_zero(verifier, apps, tmp_path, submission):
    candidate = tmp_path / "app.py"
    if submission == "symlink":
        # Harbor may resolve a link on the host first (a documented limit);
        # this covers the verifier's own second line of checks.
        (tmp_path / "real.py").write_text("x = 1\n")
        candidate.symlink_to(tmp_path / "real.py")
    elif submission == "directory":
        candidate.mkdir()
    elif submission == "oversize":
        candidate.write_bytes(b"#" * (verifier.MAX_BYTES + 1))
    elif submission == "binary":
        candidate.write_bytes(b"\xff\xfe")
    output = tmp_path / "verifier"
    output.mkdir()
    verifier.main(output=output, environ={"DS_NONCE": NONCE}, candidate=candidate)
    record = evidence(output)
    assert (output / "reward.txt").read_text() == "0"
    assert record["outcome"] == "invalid_submission" and record["reward"] == 0
    assert record["mac"] == apps["harbor_spike"].evidence_mac(NONCE, record)


def test_handoff_publishes_exact_bytes_read_only(verifier, tmp_path):
    handoff = tmp_path / ".run"
    verifier.hand_off(b"app bytes", "host=127.0.0.1 password=x", handoff)
    assert (handoff / "app.py").read_bytes() == b"app bytes"
    assert (handoff / "runtime-dsn").read_text() == "host=127.0.0.1 password=x"
    for name in ("app.py", "runtime-dsn", "ready"):
        assert (handoff / name).stat().st_mode & 0o777 == 0o444
    with pytest.raises(FileExistsError):
        verifier.hand_off(b"other", "x", handoff)


def trial_with(verifier, tmp_path, monkeypatch, *, started, result=None):
    trial = tmp_path / "job" / "invoice-read__x"
    (trial / "verifier").mkdir(parents=True)
    (trial / "artifacts").mkdir()
    app = REFERENCE.read_bytes()
    (trial / "artifacts/app.py").write_bytes(app)
    (trial / "artifacts/manifest.json").write_text(
        json.dumps(
            [
                {
                    "source": "/logs/artifacts",
                    "destination": "artifacts/agent-artifacts",
                    "type": "directory",
                    "status": "failed",
                    "service": None,
                }
            ]
        )
    )
    candidate = tmp_path / "candidate.py"
    candidate.write_bytes(app)
    monkeypatch.setattr(verifier, "provision", lambda *args: None)
    monkeypatch.setattr(verifier, "wait_until_ready", lambda client: started)
    monkeypatch.setattr(verifier, "verify", lambda client, dsn: result)
    verifier.main(
        output=trial / "verifier",
        environ={"DS_NONCE": NONCE},
        candidate=candidate,
        handoff=tmp_path / ".run",
        admin_dsn="host=/nonexistent",
        url="http://127.0.0.1:9",
    )
    record = evidence(trial / "verifier")
    rewards = {"reward": record["reward"]}
    (trial / "result.json").write_text(
        json.dumps(
            {
                "exception_info": None,
                "verifier_environment_mode": "separate",
                "agent_info": {"name": "oracle"},
                "finished_at": "2026-10-15",
                "verifier_result": {"rewards": rewards},
            }
        )
    )
    return trial.parent, record


def test_orchestrator_evidence_is_accepted_by_the_host(verifier, apps, tmp_path, monkeypatch):
    from democratize_security.verification.reference import REQUIRED, Check, summarize

    passing = summarize([Check(name, "pass") for name in sorted(REQUIRED)])
    job, record = trial_with(verifier, tmp_path, monkeypatch, started=True, result=passing)
    assert record["reward"] == 1 and record["outcome"] == "pass"
    expected = apps["expected_outcomes"]("invoice-read", "oracle")
    accepted = apps["accept_app"](job, "oracle", expected, NONCE)
    assert accepted["reward"] == 1 and (job / "app.bundle.json").is_file()
    # The same evidence cannot satisfy a different expectation or nonce.
    (job / "app.bundle.json").unlink()
    with pytest.raises(ValueError):
        apps["accept_app"](job, "oracle", expected, "f" * 64)
    with pytest.raises(ValueError):
        apps["accept_app"](job, "oracle", apps["expected_outcomes"]("invoice-read", "nop"), NONCE)


@pytest.mark.parametrize("how", ["simulated", "mode_000"])
def test_unreadable_submission_is_a_distinct_bound_zero(verifier, apps, tmp_path, monkeypatch, how):
    # Harbor keeps the agent's mode bits and the verifier is another user.
    candidate = tmp_path / "app.py"
    candidate.write_bytes(REFERENCE.read_bytes())
    if how == "simulated":

        def unreadable(path):
            raise PermissionError(13, "Permission denied", str(path))

        monkeypatch.setattr(verifier, "read_candidate", unreadable)
    elif os.geteuid() == 0:
        pytest.skip("root reads files regardless of mode")
    else:
        candidate.chmod(0)
    output = tmp_path / "verifier"
    output.mkdir()
    verifier.main(output=output, environ={"DS_NONCE": NONCE}, candidate=candidate)
    record = evidence(output)
    assert record["outcome"] == "unreadable_submission" and record["reward"] == 0
    assert record["artifact_sha256"] is None
    assert record["mac"] == apps["harbor_spike"].evidence_mac(NONCE, record)


def test_host_requires_exact_checks_not_just_the_reward(verifier, apps, tmp_path, monkeypatch):
    from democratize_security.verification.reference import Check, summarize

    unsafe = CONTROLS["invoice-read"]["unsafe"]
    result = summarize([Check(name, outcome) for name, outcome in sorted(unsafe.items())])
    job, record = trial_with(verifier, tmp_path, monkeypatch, started=True, result=result)
    assert record["reward"] == 0 and record["outcome"] == "fail"
    # Same reward and outcome as the nop control, different checks: rejected.
    nop = apps["expected_outcomes"]("invoice-read", "nop")
    with pytest.raises(ValueError, match="reviewed expectation"):
        apps["accept_app"](job, "oracle", nop, NONCE)
    accepted = apps["accept_app"](job, "oracle", unsafe, NONCE)
    assert accepted["checks"] == unsafe


def test_app_that_never_starts_gets_zero(verifier, apps, tmp_path, monkeypatch):
    job, record = trial_with(verifier, tmp_path, monkeypatch, started=False)
    assert record["outcome"] == "app_not_started" and record["reward"] == 0
    assert set(record["checks"].values()) == {"not_evaluated"}
    # Never an acceptable control outcome: controls require a started app.
    with pytest.raises(ValueError):
        apps["accept_app"](job, "oracle", apps["expected_outcomes"]("invoice-read", "nop"), NONCE)


def test_launcher_imports_candidates_like_uvicorn(tmp_path, monkeypatch):
    # dataclasses (and pydantic forward references) look the defining module
    # up in sys.modules while it executes; a correct app must not crash.
    import importlib.util

    pytest.importorskip("uvicorn")
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    path = task("invoice-read") / "tests/launch.py"
    spec = importlib.util.spec_from_file_location("ds_app_launcher", path)
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)
    candidate = tmp_path / "app.py"
    candidate.write_text(
        "from __future__ import annotations\n"
        "from dataclasses import dataclass\n\n\n"
        "@dataclass\nclass Invoice:\n    id: int\n\n\n"
        "def create_app():\n    return Invoice(1)\n"
    )
    monkeypatch.delitem(sys.modules, "app", raising=False)
    try:
        assert launcher.load(candidate).create_app().id == 1
    finally:
        sys.modules.pop("app", None)


def rejected_trial(verifier, tmp_path, secret):
    """A trial whose collector rejected the artifact: nothing collected."""
    trial = tmp_path / "job" / "task-symlink__x"
    (trial / "verifier").mkdir(parents=True)
    (trial / "artifacts").mkdir()
    verifier.main(
        output=trial / "verifier",
        environ={"DS_NONCE": NONCE},
        candidate=tmp_path / "not-collected.py",
    )
    manifest = [
        {
            "source": "/logs/artifacts",
            "destination": "artifacts/agent-artifacts",
            "type": "directory",
            "status": "failed",
            "service": None,
        },
        {"source": "/candidate/app.py", "status": "failed", "service": "collector"},
    ]
    (trial / "artifacts/manifest.json").write_text(json.dumps(manifest))
    (trial / "agent").mkdir()
    (trial / "agent/oracle.txt").write_text("extraction control in place\n")
    (trial / "result.json").write_text(
        json.dumps(
            {
                "exception_info": None,
                "verifier_environment_mode": "separate",
                "agent_info": {"name": "oracle"},
                "finished_at": "2026-10-15",
                "verifier_result": {"rewards": {"reward": 0}},
            }
        )
    )
    return trial


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "collected",
        "manifest_ok",
        "canary",
        "wrong_nonce",
        "reward_json",
        "script_failed",
        "no_marker",
    ],
)
def test_rejected_artifact_acceptance(verifier, apps, tmp_path, mutation):
    secret = b"canary-0123456789abcdef"
    trial = rejected_trial(verifier, tmp_path, secret)
    nonce = NONCE
    if mutation == "collected":
        (trial / "artifacts/app.py").symlink_to(tmp_path)
    elif mutation == "manifest_ok":
        manifest = json.loads((trial / "artifacts/manifest.json").read_text())
        manifest[1]["status"] = "ok"
        (trial / "artifacts/manifest.json").write_text(json.dumps(manifest))
    elif mutation == "canary":
        (trial / "verifier/copied.txt").write_bytes(b"host data: " + secret)
    elif mutation == "wrong_nonce":
        nonce = "f" * 64
    elif mutation == "reward_json":
        (trial / "verifier/reward.json").write_text('{"reward": 1}')
    elif mutation == "script_failed":
        # A hostile script that failed early proves nothing about collection.
        (trial / "agent/exit-code.txt").write_text("1")
    elif mutation == "no_marker":
        (trial / "agent/oracle.txt").write_text("rm: cannot remove\n")
    if mutation is None:
        accepted = apps["accept_rejected"](trial.parent, nonce, secret)
        assert accepted == {"outcome": "invalid_submission", "reward": 0, "collected": False}
    else:
        with pytest.raises(ValueError):
            apps["accept_rejected"](trial.parent, nonce, secret)


def test_extraction_controls_are_reviewed_scripts(apps, tmp_path):
    assert set(apps["EXTRACTION"]) == {"symlink", "sparse", "fifo"}
    # Every script checks its own hostile object before the marker.
    assert "test -L" in apps["EXTRACTION"]["symlink"] and "test -p" in apps["EXTRACTION"]["fifo"]
    hostile = tmp_path / "task"
    apps["prepare_extraction"](task("invoice-read"), hostile, apps["PRIVATE"])
    solve = hostile / "solution/solve.sh"
    assert solve.stat().st_mode & 0o005 == 0o005
    assert "install -m 600 /solution/app.py /candidate/app.py" in solve.read_text()
    assert solve.read_text().rstrip().endswith(f"echo '{apps['MARKER']}'")
    assert (hostile / "solution/app.py").read_bytes() == REFERENCE.read_bytes()


def test_logs_controls_require_nothing_staged(apps, tmp_path):
    trial = tmp_path / "job" / "task-logs__x"
    (trial / "artifacts").mkdir(parents=True)
    (trial / "result.json").write_text("{}")
    (trial / "artifacts/manifest.json").write_text(
        json.dumps(
            [
                {
                    "source": "/logs/artifacts",
                    "destination": "artifacts/agent-artifacts",
                    "type": "directory",
                    "status": "failed",
                    "service": None,
                }
            ]
        )
    )
    assert apps["accept_logs"](trial.parent) == "nothing staged"
    # The fallback control passes only if the copy really happened and was caught.
    with pytest.raises(ValueError, match="did not force"):
        apps["detect_fallback"](trial.parent)
    (trial / "artifacts/agent-artifacts").mkdir()
    (trial / "artifacts/agent-artifacts/fallback.txt").write_text("staged by fallback\n")
    with pytest.raises(ValueError):
        apps["accept_logs"](trial.parent)
    assert apps["detect_fallback"](trial.parent) == "fallback staged and rejected"
    for line in ("truncate -s 1G", "ln -s {canary}", "mkfifo", "install -m 000"):
        assert line in apps["LOGS"]
    assert apps["FALLBACK"].rstrip().endswith("kill -TERM 1")


def test_fill_control_is_a_reviewed_script(apps, tmp_path):
    script = apps["FILL"].format(marker=apps["MARKER"])
    for surface in ("/candidate/fill", "/tmp/fill", "/dev/shm/fill"):
        assert f"$(fill {surface})" in script
    # 128 MiB requested per surface, far past every bound, and 8 MiB of log.
    assert "bs=65536 count=2048" in script
    assert "head -c 8388608 /dev/zero | tr '\\0' a > /proc/1/fd/1" in script
    hostile = tmp_path / "task"
    apps["prepare_extraction"](task("invoice-read"), hostile, script, marker=False)
    solve = (hostile / "solution/solve.sh").read_text()
    report = f'echo "{apps["MARKER"]} candidate=$candidate tmp=$tmp shm=$shm"'
    assert solve.rstrip().endswith(report)
    assert "cp /solution/app.py /candidate/app.py" in solve
    # The bounds acceptance holds the writes to are the compose file's.
    compose = (task("invoice-read") / "environment/docker-compose.yaml").read_text()
    assert '      o: "size=16m,nr_inodes=4096,mode=0755,uid=10001,gid=10001' in compose
    assert "      - /tmp:rw,noexec,nosuid,size=16m\n" in compose
    assert apps["FILL_BOUNDS"] == {
        "candidate": 16 * 1024 * 1024,
        "tmp": 16 * 1024 * 1024,
        "shm": 64 * 1024 * 1024,
    }


@pytest.mark.parametrize(
    "mutation",
    [None, "no_report", "candidate_over", "tmp_short", "shm_over", "log_over", "log_unobserved"],
)
def test_fill_acceptance(apps, tmp_path, mutation):
    from democratize_security.adapters.runners.harbor_audit import compose_project

    trial = tmp_path / "fill" / "task-fill__AbC"
    (trial / "agent").mkdir(parents=True)
    (trial / "result.json").write_text("{}")
    mib = 1024 * 1024
    written = {"candidate": 16 * mib - 8192, "tmp": 16 * mib - 4096, "shm": 64 * mib}
    if mutation == "candidate_over":
        written["candidate"] = 16 * mib + 65536
    elif mutation == "tmp_short":
        # Stopped long before the bound: an error, not the bound, ended it.
        written["tmp"] = 65536
    elif mutation == "shm_over":
        written["shm"] = 128 * mib
    line = f"{apps['MARKER']} " + " ".join(f"{k}={v}" for k, v in written.items())
    (trial / "agent/oracle.txt").write_text("" if mutation == "no_report" else f"{line}\n")
    logs = {compose_project("task-fill__AbC__env"): 900_000}
    if mutation == "log_over":
        logs[compose_project("task-fill__AbC__env")] = 4 * mib
    elif mutation == "log_unobserved":
        logs = {}
    if mutation is None:
        assert apps["accept_fill"](trial.parent, logs) == {
            "candidate_bytes": written["candidate"],
            "tmp_bytes": written["tmp"],
            "shm_bytes": written["shm"],
            "agent_log_bytes": 900_000,
        }
    else:
        with pytest.raises(ValueError):
            apps["accept_fill"](trial.parent, logs)
