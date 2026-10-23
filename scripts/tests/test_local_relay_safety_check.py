"""Source-volume safety check must refuse to start when the relay binary is absent.

Docker is not used. The docker() helper is replaced, and the missing binary is
the probe's exit code 1. Without the guard, main() reaches docker create and
this test fails.
"""
from __future__ import annotations

import importlib.util
import asyncio
import json
import subprocess
import sys
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "local-relay-safety-check.py"
SPEC = importlib.util.spec_from_file_location("local_relay_safety_check", SCRIPT)
assert SPEC and SPEC.loader
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)

MISSING_BINARY = (
    "relay binary is missing from the a4a-relay-target volume; "
    "build it from this checkout with `bash relay/dev.sh build`."
)
BINARY = "/build/debug/nostr-rs-relay"


def test_missing_source_binary_stops_before_container_create(monkeypatch):
    calls: list[tuple[str, ...]] = []

    def fake_docker(*args: str) -> str:
        calls.append(args)
        if args[0] == "run" and BINARY in args:
            raise subprocess.CalledProcessError(1, args)
        if args[0] == "create":
            raise AssertionError("container create must not run when the relay binary is missing")
        raise AssertionError(f"unexpected docker invocation: {args!r}")

    monkeypatch.setattr(check, "docker", fake_docker)

    with pytest.raises(SystemExit) as raised:
        check.main([])

    assert raised.value.code == MISSING_BINARY
    assert "relay/dev.sh build" in str(raised.value.code)
    assert calls and calls[0][0] == "run"
    assert "a4a-relay-target:/build:ro" in calls[0]
    assert all(args[0] != "create" for args in calls)


def test_present_source_binary_reaches_container_create(monkeypatch):
    calls: list[tuple[str, ...]] = []

    def fake_docker(*args: str) -> str:
        calls.append(args)
        if args[0] == "create":
            raise SystemExit("stop-after-create")
        return ""

    monkeypatch.setattr(check, "docker", fake_docker)

    with pytest.raises(SystemExit) as raised:
        check.main([])

    assert raised.value.code == "stop-after-create"
    assert calls[0][0] == "run" and BINARY in calls[0]
    assert calls[-1][0] == "create"
    assert "a4a-relay-builder" in calls[-1]


def test_image_mode_does_not_probe_the_source_volume(monkeypatch):
    calls: list[tuple[str, ...]] = []

    def fake_docker(*args: str) -> str:
        calls.append(args)
        raise SystemExit("stop-image")

    monkeypatch.setattr(check, "docker", fake_docker)

    with pytest.raises(SystemExit) as raised:
        check.main(["--image", "a4a-relay:test"])

    assert raised.value.code == "stop-image"
    flat = " ".join(" ".join(args) for args in calls)
    assert "a4a-relay-target" not in flat
    assert BINARY not in flat


def test_other_docker_failure_is_not_reported_as_a_missing_binary(monkeypatch):
    def fake_docker(*args: str) -> str:
        raise subprocess.CalledProcessError(125, args)

    monkeypatch.setattr(check, "docker", fake_docker)

    with pytest.raises(subprocess.CalledProcessError) as raised:
        check.require_source_relay_binary()

    assert raised.value.returncode == 125


def test_external_sqlite_receives_only_owned_fixture_volumes(monkeypatch):
    calls = []
    prefix = "a4a-safety-check-fixture"
    mounts = [{"Destination": "/usr/src/app/db", "Name": prefix + "-db", "Type": "volume"},
              {"Destination": "/usr/src/app/backup", "Name": prefix + "-backup", "Type": "volume"},
              {"Destination": "/usr/src/app/config.toml", "Source": "/private/config", "Type": "bind"}]

    def fake(*args):
        calls.append(args)
        if args[:2] == ("image", "inspect"):
            return "sha256:" + "a" * 64
        if args[0] == "inspect":
            return json.dumps([{"Mounts": mounts}])
        return "ok"

    monkeypatch.setattr(check, "docker", fake)
    tools = check.FixtureDiagnostics("local-tools:test", prefix)
    assert tools.sqlite(prefix, "/usr/src/app/db/nostr.db", "PRAGMA integrity_check;") == "ok"
    run = calls[-1]
    assert prefix + "-db:/usr/src/app/db:ro" in run
    assert prefix + "-backup:/usr/src/app/backup:ro" in run
    assert "/private/config" not in " ".join(run)
    assert "--read-only" in run and "-readonly" in run
    assert not any("immutable=" in argument for argument in run)
    assert run[run.index("--network") + 1] == "none"
    tools.sqlite(prefix, "/usr/src/app/db/nostr.db", ".backup '/usr/src/app/backup/recovery-backup.db'", backup=True)
    assert prefix + "-backup:/usr/src/app/backup" in calls[-1]
    assert prefix + "-db:/usr/src/app/db:ro" in calls[-1]
    tools.sqlite(prefix, "/usr/src/app/backup/recovery-backup.db", "PRAGMA integrity_check;")
    assert "file:/usr/src/app/backup/recovery-backup.db?immutable=1&mode=ro" in calls[-1]
    assert prefix + "-backup:/usr/src/app/backup:ro" in calls[-1]
    mounts[0]["Name"] = "production-db"
    count = len([call for call in calls if call[0] == "run"])
    with pytest.raises(RuntimeError, match="outside this run"):
        tools.sqlite(prefix, "/usr/src/app/db/nostr.db", "PRAGMA integrity_check;")
    assert len([call for call in calls if call[0] == "run"]) == count


def test_external_diagnostic_cannot_inspect_an_unowned_container(monkeypatch):
    calls = []
    def fake(*args):
        calls.append(args)
        return "sha256:" + "a" * 64
    monkeypatch.setattr(check, "docker", fake)
    tools = check.FixtureDiagnostics("local-tools:test", "a4a-safety-check-fixture")
    with pytest.raises(RuntimeError, match="outside this run"):
        tools.sqlite("production-relay", "/usr/src/app/db/nostr.db", "PRAGMA integrity_check;")
    assert len(calls) == 1


def test_diagnostic_image_requires_target_image_before_any_docker_operation(monkeypatch):
    monkeypatch.setattr(check, "docker", lambda *args: pytest.fail("unexpected daemon access"))
    with pytest.raises(SystemExit) as error:
        check.main(["--diagnostic-image", "local-tools:test"])
    assert error.value.code == 2


_NOTARY_TEST = "test_real_history_pages_reach_notary_store_across_restart"


def _notary_report(cases):
    return "<testsuites><testsuite>" + cases + "</testsuite></testsuites>"


def test_notary_report_requires_one_executed_pass(tmp_path):
    report = tmp_path / "result.xml"
    report.write_text(_notary_report(f'<testcase name="{_NOTARY_TEST}"/>'), encoding="utf-8")
    check.check_notary_report(report)


@pytest.mark.parametrize("xml", [
    "", "not xml", _notary_report(""),
    _notary_report('<testcase name="another_test"/>'),
    _notary_report(f'<testcase name="{_NOTARY_TEST}"/>' * 2),
    *[_notary_report(f'<testcase name="{_NOTARY_TEST}"><{tag}/></testcase>')
      for tag in ("skipped", "failure", "error")],
])
def test_notary_report_rejects_skip_failure_and_missing_coverage(tmp_path, xml):
    report = tmp_path / "result.xml"
    report.write_text(xml, encoding="utf-8")
    with pytest.raises(RuntimeError, match="one executed passing test"):
        check.check_notary_report(report)


def test_notary_report_rejects_missing_file(tmp_path):
    with pytest.raises(RuntimeError, match="one executed passing test"):
        check.check_notary_report(tmp_path / "absent.xml")


def test_notary_helper_retains_log_and_requires_real_pass(tmp_path, monkeypatch):
    packages = tmp_path / "packages"
    packages.mkdir()
    calls = []
    results = tmp_path / "results"
    results.mkdir()
    monkeypatch.setattr(check.tempfile, "mkdtemp", lambda **kwargs: str(results))

    def fake_docker(*args):
        calls.append(args)
        return json.dumps({"exit_code": 0, "log": "one test executed",
                           "junit": _notary_report(f'<testcase name="{_NOTARY_TEST}"/>')})

    monkeypatch.setattr(check, "docker", fake_docker)
    assert check.run_notary_history_check("owned-relay", image="notary:new", packages=packages) == results
    run = calls[0]
    assert run[run.index("--network") + 1] == "container:owned-relay"
    assert "notary:new" in run and f"{packages}:/host-packages:ro" in run
    assert "--local-history-check" in run[-1]
    assert "--local-history-relay" in run[-1]
    assert "A4A_LOCAL_HISTORY_CHECK=1" not in run
    assert (results / "pytest.log").read_text(encoding="utf-8") == "one test executed"
    assert (results / "result.xml").is_file()


@pytest.mark.parametrize("exit_code", [0, 1])
def test_notary_helper_rejects_skipped_and_failed_container_result(tmp_path, monkeypatch, exit_code):
    results = tmp_path / "results"
    results.mkdir()
    monkeypatch.setattr(check.tempfile, "mkdtemp", lambda **kwargs: str(results))
    monkeypatch.setattr(check, "docker", lambda *args: json.dumps({
        "exit_code": exit_code, "log": "retained diagnostic",
        "junit": _notary_report(f'<testcase name="{_NOTARY_TEST}"><skipped/></testcase>')}))
    with pytest.raises(RuntimeError):
        check.run_notary_history_check("owned-relay", image="notary:new", packages=tmp_path)
    assert (results / "pytest.log").read_text(encoding="utf-8") == "retained diagnostic"


@pytest.mark.parametrize("value", ["bad image", "x" * 256])
def test_notary_image_is_validated_before_docker(monkeypatch, value):
    monkeypatch.setattr(check, "docker", lambda *args: pytest.fail("unexpected daemon access"))
    with pytest.raises(SystemExit) as error:
        check.main(["--notary-image", value])
    assert error.value.code == 2


def test_notary_tooling_must_exist_before_docker(tmp_path, monkeypatch):
    monkeypatch.setattr(check, "docker", lambda *args: pytest.fail("unexpected daemon access"))
    with pytest.raises(SystemExit) as error:
        check.main(["--notary-test-packages", str(tmp_path / "missing")])
    assert error.value.code == 2


def test_notary_check_sees_seed_before_any_crash_write(monkeypatch):
    events = {}
    revoked = False

    class StopAfterNotary(Exception):
        pass

    class Relay:
        def __init__(self, url):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def publish(self, event):
            nonlocal revoked
            if event.kind == 31002 and revoked:
                raise check.RelayError("revoked")
            if event.kind == 31007:
                revoked = True
                for event_id, old in list(events.items()):
                    if old.kind == 31007:
                        del events[event_id]
            events[event.id] = event

    def get(base, path):
        event = events.get(path.rsplit("/", 1)[-1])
        if event is None:
            raise urllib.error.HTTPError(path, 404, "not found", {}, None)
        return b"", event.model_dump()

    async def history(base):
        return {event.id for event in events.values() if event.kind != 31002}, [100, 100]

    def notary_check():
        historical = [event for event in events.values() if event.kind != 31002]
        assert len(historical) == 26
        assert not any((event.tag_value("d") or "").startswith("crash") for event in historical)
        raise StopAfterNotary

    monkeypatch.setattr(check, "RelayClient", Relay)
    monkeypatch.setattr(check, "docker", lambda *args: "127.0.0.1:12345")
    monkeypatch.setattr(check, "wait_ready", lambda *args: None)
    monkeypatch.setattr(check, "get", get)
    monkeypatch.setattr(check, "history_ids", history)
    monkeypatch.setattr(check.asyncio, "sleep", AsyncMock())
    with pytest.raises(StopAfterNotary):
        asyncio.run(check.check("ws://127.0.0.1:12345", "http://127.0.0.1:12345",
                                "owned-relay", "/tmp/nostr.db", notary_check=notary_check))


@pytest.mark.parametrize("relay_only", [False, True])
def test_main_enables_notary_only_for_the_full_check(tmp_path, monkeypatch, relay_only):
    called = []
    async def fake_check(*args, **kwargs):
        if kwargs["notary_check"] is not None:
            kwargs["notary_check"]()
    monkeypatch.setattr(check, "check", fake_check)
    monkeypatch.setattr(check, "run_notary_history_check", lambda *args, **kwargs: called.append((args, kwargs)))
    monkeypatch.setattr(check, "docker", lambda *args: "127.0.0.1:12345" if args[0] == "port" else "")
    monkeypatch.setattr(check, "wait_ready", lambda *args: None)
    monkeypatch.setattr(check, "get", lambda *args: (b"", {"healthy": True}))
    args = ["--notary-image", "notary:new", "--notary-test-packages", str(tmp_path)]
    check.main(args + (["--relay-only"] if relay_only else []))
    assert len(called) == (0 if relay_only else 1)
    if called:
        assert called[0][1] == {"image": "notary:new", "packages": tmp_path.resolve()}


@pytest.mark.parametrize("enabled", [False, True])
def test_notary_endpoint_registration_requires_explicit_flag(monkeypatch, enabled):
    registrations = []
    fake_guard = SimpleNamespace(install=lambda: None, unreachable=lambda *args: None,
        allow=lambda *args: registrations.append(("allow", args)),
        forget=lambda *args: registrations.append(("forget", args)))
    monkeypatch.setitem(sys.modules, "ambient", SimpleNamespace(sanitize=lambda: {}))
    monkeypatch.setitem(sys.modules, "network_guard", fake_guard)
    monkeypatch.setitem(sys.modules, "guarded_child", SimpleNamespace())
    monkeypatch.setattr(sys, "path", list(sys.path))
    spec = importlib.util.spec_from_file_location("notary_fixture_contract", ROOT / "notary/tests/conftest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    options = {}
    module.pytest_addoption(SimpleNamespace(addoption=lambda name, **kwargs: options.update({name: kwargs})))
    assert options["--local-history-check"]["default"] is False
    assert options["--local-history-relay"]["choices"] == ["ws://127.0.0.1:8080"]
    request = SimpleNamespace(config=SimpleNamespace(getoption=lambda name:
        enabled if name == "--local-history-check" else "ws://127.0.0.1:8080"))
    fixture = module.local_history_relay.__wrapped__(request)
    if not enabled:
        with pytest.raises(pytest.skip.Exception):
            next(fixture)
        assert not registrations
    else:
        assert next(fixture) == "ws://127.0.0.1:8080"
        assert registrations == [("allow", ("127.0.0.1", 8080))]
        fixture.close()
        assert registrations[-1] == ("forget", ("127.0.0.1", 8080))
