"""The disposable relay runner must clean up failed container starts too."""
import importlib.util
from pathlib import Path

import pytest


def test_failed_start_removes_only_the_created_container(monkeypatch):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("local_safety_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    calls = []

    def docker(*args):
        calls.append(args)
        if args[0] in ("run", "start"):
            raise RuntimeError("test container startup failed")
        return ""

    monkeypatch.setattr(runner, "docker", docker)
    # The binary probe added on 24.09 is its own docker run; these tests fake docker and
    # describe container lifecycles, so the probe is covered in scripts/tests instead.
    monkeypatch.setattr(runner, "require_source_relay_binary", lambda: None)
    with pytest.raises(RuntimeError, match="startup failed"):
        runner.main()
    created_name = calls[0][calls[0].index("--name") + 1]
    assert calls[-1] == ("rm", "-f", created_name)


def test_release_image_path_checks_health_and_skips_notary(monkeypatch):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("release_image_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    calls = []

    def docker(*args):
        calls.append(args)
        if args[0] == "port":
            return "127.0.0.1:34567"
        if args[0] == "inspect":
            return "healthy"
        return ""

    def run(coroutine):
        coroutine.close()

    monkeypatch.setattr(runner, "docker", docker)
    # The binary probe added on 24.09 is its own docker run; these tests fake docker and
    # describe container lifecycles, so the probe is covered in scripts/tests instead.
    monkeypatch.setattr(runner, "require_source_relay_binary", lambda: None)
    monkeypatch.setattr(runner, "wait_ready", lambda base: None)
    monkeypatch.setattr(runner, "get", lambda base, path: (b"{}", {}))
    monkeypatch.setattr(runner.asyncio, "run", run)
    runner.main(["--image", "a4a-relay:ci", "--relay-only"])

    create = next(call for call in calls if call[0] == "create")
    assert create[0] == "create"
    assert "a4a-relay:ci" in create
    assert "--entrypoint" not in create
    assert "a4a-relay-target:/build:ro" not in create
    assert any(value.endswith(":/usr/src/app/config.toml:ro") for value in create)
    assert any(value.endswith(":/usr/src/app/db") for value in create)
    assert any(value.endswith(":/usr/src/app/backup") for value in create)
    assert sum(call[0] == "inspect" for call in calls) == 2
    created_name = create[create.index("--name") + 1]
    database_volume = calls[0][-1]
    backup_volume = calls[1][-1]
    assert calls[0] == ("volume", "create", database_volume)
    assert calls[1] == ("volume", "create", backup_volume)
    initialize = calls[2]
    assert initialize[:5] == ("run", "--rm", "--pull", "never", "--network")
    assert "none" in initialize
    assert ("--user", "root") == initialize[
        initialize.index("--user"):initialize.index("--user") + 2]
    assert ("--cap-drop", "ALL") == initialize[
        initialize.index("--cap-drop"):initialize.index("--cap-drop") + 2]
    assert ("--cap-add", "CHOWN") == initialize[
        initialize.index("--cap-add"):initialize.index("--cap-add") + 2]
    assert f"{backup_volume}:/backup" in initialize
    assert initialize[-4:] == ("chown", "a4a-relay:ci", "appuser:appuser", "/backup")
    assert calls[-3] == ("rm", "-f", created_name)
    assert calls[-2] == ("volume", "rm", database_volume)
    assert calls[-1] == ("volume", "rm", backup_volume)


def test_failed_release_image_create_removes_owned_volume(monkeypatch):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("failed_release_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    calls = []

    def docker(*args):
        calls.append(args)
        if args[0] == "create":
            raise RuntimeError("release container create failed")
        return ""

    monkeypatch.setattr(runner, "docker", docker)
    # The binary probe added on 24.09 is its own docker run; these tests fake docker and
    # describe container lifecycles, so the probe is covered in scripts/tests instead.
    monkeypatch.setattr(runner, "require_source_relay_binary", lambda: None)
    with pytest.raises(RuntimeError, match="create failed"):
        runner.main(["--image", "a4a-relay:ci", "--relay-only"])
    database_volume = calls[0][-1]
    backup_volume = calls[1][-1]
    assert calls[0] == ("volume", "create", database_volume)
    assert calls[1] == ("volume", "create", backup_volume)
    assert all(call[0] != "rm" for call in calls)
    assert calls[-2] == ("volume", "rm", database_volume)
    assert calls[-1] == ("volume", "rm", backup_volume)


def test_failed_backup_volume_initialization_removes_both_owned_volumes(monkeypatch):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("failed_backup_init_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    calls = []

    def docker(*args):
        calls.append(args)
        if args[0] == "run":
            raise RuntimeError("backup initialization failed")
        return ""

    monkeypatch.setattr(runner, "docker", docker)
    # The binary probe added on 24.09 is its own docker run; these tests fake docker and
    # describe container lifecycles, so the probe is covered in scripts/tests instead.
    monkeypatch.setattr(runner, "require_source_relay_binary", lambda: None)
    with pytest.raises(RuntimeError, match="backup initialization failed"):
        runner.main(["--image", "a4a-relay:ci", "--relay-only"])
    database_volume = calls[0][-1]
    backup_volume = calls[1][-1]
    assert calls[-2] == ("volume", "rm", database_volume)
    assert calls[-1] == ("volume", "rm", backup_volume)


def test_failed_failover_container_create_removes_its_owned_volume(monkeypatch):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("failed_failover_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    calls = []

    def docker(*args):
        calls.append(args)
        if args[0] == "create":
            raise RuntimeError("failover container create failed")
        return ""

    monkeypatch.setattr(runner, "docker", docker)
    # The binary probe added on 24.09 is its own docker run; these tests fake docker and
    # describe container lifecycles, so the probe is covered in scripts/tests instead.
    monkeypatch.setattr(runner, "require_source_relay_binary", lambda: None)
    with pytest.raises(RuntimeError, match="failover container create failed"):
        runner.asyncio.run(runner.verify_multi_relay_failover(
            image="a4a-relay:ci", primary_container="owned-primary",
            primary_url="ws://127.0.0.1:30001", owner=runner.Keys(),
        ))
    volume = calls[0][-1]
    assert calls[0] == ("volume", "create", volume)
    assert calls[-1] == ("volume", "rm", volume)


def test_sqlite_integrity_check_requires_exact_ok(monkeypatch):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("integrity_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    calls = []

    def docker(*args):
        calls.append(args)
        return "ok"

    monkeypatch.setattr(runner, "docker", docker)
    # The binary probe added on 24.09 is its own docker run; these tests fake docker and
    # describe container lifecycles, so the probe is covered in scripts/tests instead.
    monkeypatch.setattr(runner, "require_source_relay_binary", lambda: None)
    runner.verify_sqlite_integrity("owned-container", "/data/nostr.db")
    assert calls == [("exec", "owned-container", "sqlite3", "/data/nostr.db",
                      "PRAGMA integrity_check;")]

    monkeypatch.setattr(runner, "docker", lambda *args: "*** corruption ***")
    with pytest.raises(RuntimeError, match="integrity check failed"):
        runner.verify_sqlite_integrity("owned-container", "/data/nostr.db")


def test_health_wait_allows_expected_recovery_after_unpause(monkeypatch):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("recovering_health_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    statuses = iter(["unhealthy", "healthy"])
    monkeypatch.setattr(runner, "docker", lambda *args: next(statuses))
    monkeypatch.setattr(runner.time, "sleep", lambda _: None)

    runner.wait_container_healthy("owned-container", allow_recovery=True)


def test_health_wait_rejects_unhealthy_initial_start(monkeypatch):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("failed_health_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    monkeypatch.setattr(runner, "docker", lambda *args: "unhealthy")

    with pytest.raises(RuntimeError, match="status=unhealthy"):
        runner.wait_container_healthy("owned-container")


@pytest.mark.parametrize("image", ["-danger", "bad image", "x" * 256])
def test_unsafe_release_image_reference_is_rejected_before_docker(monkeypatch, image):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("unsafe_image_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    monkeypatch.setattr(runner, "docker", lambda *args: pytest.fail("Docker must not be called"))
    with pytest.raises(SystemExit):
        runner.main(["--image", image, "--relay-only"])


@pytest.mark.parametrize("fail", [False, True])
def test_private_pilot_uses_only_the_owned_relay_and_cleans_up(monkeypatch, fail):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("private_pilot_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    calls, runs = [], []

    def docker(*args):
        calls.append(args)
        return "127.0.0.1:34567" if args[0] == "port" else ""

    def run(command, **kwargs):
        runs.append((command, kwargs))
        if fail:
            raise RuntimeError("private pilot failed")
        report = next((a.split("=", 1)[1] for a in command if a.startswith("--junitxml=")), None)
        if report:
            Path(report).write_text(
                '<testsuites><testsuite><testcase name="test_private_pilot_on_disposable_relay"/>'
                '</testsuite></testsuites>', encoding="utf-8")

    monkeypatch.setattr(runner, "docker", docker)
    # The binary probe added on 24.09 is its own docker run; these tests fake docker and
    # describe container lifecycles, so the probe is covered in scripts/tests instead.
    monkeypatch.setattr(runner, "require_source_relay_binary", lambda: None)
    monkeypatch.setattr(runner, "wait_ready", lambda base: None)
    monkeypatch.setattr(runner, "get", lambda base, path: (b"{}", {}))
    monkeypatch.setattr(runner.subprocess, "run", run)
    if fail:
        with pytest.raises(RuntimeError, match="private pilot failed"):
            runner.main(["--private-pilot-python", "test-python"])
    else:
        runner.main(["--private-pilot-python", "test-python"])
    assert len(runs) == 1
    command, kwargs = runs[0]
    assert command[0] == "test-python"
    assert "tests/test_private_pilot.py::test_private_pilot_on_disposable_relay" in command
    assert kwargs["env"]["A4A_LOCAL_PRIVATE_PILOT_RELAY"] == "ws://127.0.0.1:34567"
    assert kwargs["check"] is True
    created_name = calls[0][calls[0].index("--name") + 1]
    assert calls[-1] == ("rm", "-f", created_name)
    assert all(c[0] != "run" for c in calls), "private pilot must not launch a notary"


@pytest.mark.parametrize("source", ["host", "context"])
@pytest.mark.parametrize("endpoint", ["ssh://review-sentinel.invalid", "tcp://127.0.0.1:2375",
                                      "npipe:////remote-host/pipe/docker_engine"])
def test_remote_docker_is_rejected_before_create(monkeypatch, source, endpoint):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("remote_docker_check", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setenv("DOCKER_HOST" if source == "host" else "DOCKER_CONTEXT",
                       endpoint if source == "host" else "review-remote")
    calls = []

    def output(command, **kwargs):
        calls.append(command)
        return runner.json.dumps(endpoint)

    monkeypatch.setattr(runner.subprocess, "check_output", output)
    with pytest.raises(RuntimeError, match="local Docker"):
        runner.docker("create", "sentinel-image")
    assert all("create" not in command for command in calls)


@pytest.mark.parametrize("endpoint", ["npipe:////./pipe/dockerDesktopLinuxEngine", "unix:///var/run/docker.sock"])
def test_local_docker_endpoint_is_pinned_for_cleanup(monkeypatch, endpoint):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("pinned_docker_check", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.setenv("DOCKER_CONTEXT", "review-local")
    calls = []

    def output(command, **kwargs):
        calls.append((command, kwargs))
        return runner.json.dumps(endpoint) if "inspect" in command else "created"

    monkeypatch.setattr(runner.subprocess, "check_output", output)
    runner.docker("create", "sentinel-image")
    monkeypatch.setenv("DOCKER_CONTEXT", "review-remote")
    monkeypatch.setenv("DOCKER_HOST", "ssh://review-sentinel.invalid")
    runner.docker("rm", "sentinel-container")
    assert len(calls) == 3, "context must be resolved once per invocation"
    for command, options in calls[1:]:
        assert command[:3] == ["docker", "--host", endpoint]
        assert not ({"DOCKER_HOST", "DOCKER_CONTEXT"} & options["env"].keys())


@pytest.mark.parametrize("report", [
    None,
    '<testsuites><testsuite tests="0"/></testsuites>',
    '<testsuites><testsuite><testcase name="test_private_pilot_on_disposable_relay">'
    '<skipped/></testcase></testsuite></testsuites>',
    '<testsuites><testsuite><testcase name="test_private_pilot_on_disposable_relay">'
    '<failure/></testcase></testsuite></testsuites>',
    '<testsuites><testsuite><testcase name="unrelated_test"/></testsuite></testsuites>',
])
def test_collection_or_skip_cannot_pass_the_private_pilot(monkeypatch, report):
    path = Path(__file__).resolve().parents[2] / "scripts" / "local-relay-safety-check.py"
    spec = importlib.util.spec_from_file_location("collection_check", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    calls = []
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("PYTEST_PLUGINS", "unexpected_plugin")

    def docker(*args):
        calls.append(args)
        return "127.0.0.1:34567" if args[0] == "port" else ""

    def run(command, **kwargs):
        if report is not None:
            target = next((a.split("=", 1)[1] for a in command if a.startswith("--junitxml=")), None)
            if target:
                Path(target).write_text(report, encoding="utf-8")
        assert "PYTEST_ADDOPTS" not in kwargs["env"]
        assert "PYTEST_PLUGINS" not in kwargs["env"]
        assert kwargs["env"]["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"

    monkeypatch.setattr(runner, "docker", docker)
    # The binary probe added on 24.09 is its own docker run; these tests fake docker and
    # describe container lifecycles, so the probe is covered in scripts/tests instead.
    monkeypatch.setattr(runner, "require_source_relay_binary", lambda: None)
    monkeypatch.setattr(runner, "wait_ready", lambda base: None)
    monkeypatch.setattr(runner, "get", lambda base, path: (b"{}", {}))
    monkeypatch.setattr(runner.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="one executed passing test"):
        runner.main(["--private-pilot-python", "test-python"])
    created_name = calls[0][calls[0].index("--name") + 1]
    assert calls[-1] == ("rm", "-f", created_name)
