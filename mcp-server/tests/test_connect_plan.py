"""Safe connection preparation is not installation or host-wake evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib

import pytest


def planner():
    from a4a_mcp.onboarding import connection_plan
    return connection_plan


def plan(tmp_path, **changes):
    values = dict(client="claude-code", home=str(tmp_path / "profiles/mail"),
                  project=str(tmp_path / "project"), relay="ws://127.0.0.1:17404",
                  consumer="mail-agent", executable=sys.executable,
                  host_executable=str(tmp_path / "Claude/claude.exe"))
    if changes.get("client", "claude-code") != "claude-code":
        values["host_executable"] = None
    return planner()(**{**values, **changes})


def test_plan_is_explicit_safe_and_does_not_install(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    monkeypatch.setenv("A4A_MCP_CHANNEL", "claude")
    result = plan(tmp_path)
    assert result["state"] == "plan_only" and result["ready"] is False
    entry = result["mcp_server"]
    assert entry["command"] == sys.executable
    assert entry["args"] == ["-I", "-m", "a4a_mcp"]
    assert entry["env"]["A4A_HOME"] == str(tmp_path / "profiles/mail")
    for name, value in {"A4A_MANDATE_AUTO": "0", "A4A_MANDATE_DAYS": "1",
                        "A4A_PUBLIC_TEXT": "deny", "A4A_MCP_TRANSPORT": "stdio",
                        "A4A_MCP_CHANNEL": ""}.items():
        assert entry["env"][name] == value
    assert result["inbox"]["allowed_peers"] == []
    assert result["inbox"]["consumer"] == "mail-agent"
    assert result["permissions"]["open_inbound_port"] is False
    assert result["permissions"]["remote_tool_approval"] is False
    assert result["permissions"]["publish_profile"] is False
    assert not list(tmp_path.iterdir())
    assert "dangerously" not in json.dumps(result)


def test_claude_registration_uses_local_scope_and_argv_not_shell(tmp_path):
    result = plan(tmp_path, executable=str(tmp_path / "Python space/python.exe"))
    registration = result["registration"]
    args = registration["argv"]
    assert registration["cwd"] == str(tmp_path / "project")
    assert args[:5] == [str(tmp_path / "Claude/claude.exe"), "mcp", "add", "--scope", "local"]
    end = args.index("--")
    assert args[end - 3:end] == ["--transport", "stdio", "a4a"]
    assert args[end + 1:] == [str(tmp_path / "Python space/python.exe"), "-I", "-m", "a4a_mcp"]
    assert "Do not replace" in result["existing_configuration"]


def test_claude_registration_needs_an_explicit_host_executable(tmp_path):
    assert plan(tmp_path, host_executable=None)["registration"] is None
    with pytest.raises(ValueError, match="absolute local path"):
        plan(tmp_path, host_executable="claude")


def test_host_executable_is_not_guessed_for_other_clients(tmp_path):
    with pytest.raises(ValueError, match="only for claude-code"):
        plan(tmp_path, client="generic", host_executable=sys.executable)


@pytest.mark.parametrize("client", ["codex", "cursor", "generic"])
def test_other_clients_do_not_get_an_invented_global_registration_command(tmp_path, client):
    result = plan(tmp_path, client=client)
    assert result["registration"] is None
    assert result["ready"] is False
    assert result["automatic_delivery"] == "requires_host_acceptance"


@pytest.mark.parametrize("client", ["codex", "cursor"])
def test_host_config_roundtrips_paths_without_shell_interpolation(tmp_path, client):
    # Even shell-sensitive characters remain plain config data, never shell code.
    root = tmp_path / "space & dollar$ `tick` apostrophe' unicode-\u0430\u0433\u0435\u043d\u0442-🤖"
    result = plan(tmp_path, client=client, home=str(root / "profile"),
                  executable=str(root / "python.exe"))
    config = result["host_configuration"]
    assert config["scope"] == "project"
    assert config["operation"] == "merge_missing_a4a_only"
    if client == "codex":
        parsed = tomllib.loads(config["content"])["mcp_servers"]["a4a"]
        assert config["path"] == str(tmp_path / "project/.codex/config.toml")
        assert config["requires_project_trust"] is True
    else:
        parsed = json.loads(config["content"])["mcpServers"]["a4a"]
        assert parsed.pop("type") == "stdio"
        assert config["path"] == str(tmp_path / "project/.cursor/mcp.json")
    assert parsed == result["mcp_server"]
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("client", ["codex", "cursor"])
def test_merge_preserves_existing_servers_and_settings_and_is_idempotent(tmp_path, client):
    from a4a_mcp.onboarding import merge_host_config
    result = plan(tmp_path, client=client)
    original = ('# Keep this comment\nmodel = "test-model"\n\n[mcp_servers.other]\n'
                'command = "other-tool"\nargs = ["--flag"]\n' if client == "codex" else
                '{"setting":{"nested":true},"mcpServers":{"other":{"command":"other-tool"}}}')
    output = merge_host_config(result, original)
    parse = tomllib.loads if client == "codex" else json.loads
    before, after = parse(original), parse(output)
    section = "mcp_servers" if client == "codex" else "mcpServers"
    assert after[section].pop("a4a")
    assert after == before
    if client == "codex":
        assert output.startswith(original)  # Comments and formatting survive append.
    assert merge_host_config(result, output) == output
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("client", ["codex", "cursor"])
def test_merge_refuses_to_replace_a_different_existing_identity(tmp_path, client):
    from a4a_mcp.onboarding import merge_host_config
    result = plan(tmp_path, client=client)
    old_plan = plan(tmp_path, client=client, home=str(tmp_path / "someone-elses-profile"))
    original = old_plan["host_configuration"]["content"]
    with pytest.raises(ValueError, match="existing A4A entry differs"):
        merge_host_config(result, original)
    assert old_plan["host_configuration"]["content"] == original
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("client,original", [
    ("cursor", '{"mcpServers":{},"mcpServers":{}}'),
    ("cursor", '{"mcpServers":null}'), ("cursor", '[]'),
    ("cursor", '{"other":NaN}'), ("cursor", '{/* comments need a preserving editor */}'),
    ("codex", '[mcp_servers\n'), ("codex", 'mcp_servers = []'),
    ("codex", 'mcp_servers = { other = { command = "tool" } }'),
])
def test_ambiguous_or_unmergeable_configuration_fails_without_changes(tmp_path, client, original):
    from a4a_mcp.onboarding import merge_host_config
    with pytest.raises(ValueError):
        merge_host_config(plan(tmp_path, client=client), original)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("token", ["1e999", "-1e999", "1e-999", "-1e-999",
                                   "0.12345678901234567890123456789", "9007199254740993.0"])
def test_cursor_merge_rejects_numeric_overflow_underflow_and_precision_loss(tmp_path, token):
    from a4a_mcp.onboarding import merge_host_config
    original = '{"mcpServers":{},"unrelated":{"number":' + token + '}}'
    with pytest.raises(ValueError, match="number cannot be preserved exactly"):
        merge_host_config(plan(tmp_path, client="cursor"), original)
    assert not list(tmp_path.iterdir())


def test_cursor_merge_retains_ordinary_exact_decimal_value(tmp_path):
    from a4a_mcp.onboarding import merge_host_config
    original = '{"mcpServers":{},"unrelated":{"number":1.25}}'
    output = merge_host_config(plan(tmp_path, client="cursor"), original)
    assert json.loads(output)["unrelated"]["number"] == 1.25


@pytest.mark.parametrize("relay", ["ws://example.invalid", "ws://localhost:1234", "ws://192.0.2.1",
    "https://example.invalid", "wss://u:p@example.invalid", "wss://example.invalid?key=x",
    "wss://example.invalid#x", "wss://example.invalid:0", "wss://example.invalid:65536",
    "wss://example.invalid:", "wss://bad host", "wss://example.invalid\n", "wss://",
    "wss://example.invalid\\other", "wss://example.invalid/${TOKEN}"])
def test_unsafe_relay_is_rejected_without_echoing_input(tmp_path, relay):
    with pytest.raises(ValueError) as exc:
        plan(tmp_path, relay=relay)
    assert relay not in str(exc.value)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("relay", ["wss://relay.example.invalid", "wss://relay.example.invalid:443/path",
    "ws://127.0.0.1:17404", "ws://[::1]:17404"])
def test_explicit_tls_or_numeric_loopback_relay_needs_no_dns(tmp_path, relay, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: pytest.fail("unexpected DNS"))
    assert plan(tmp_path, relay=relay)["mcp_server"]["env"]["A4A_RELAY"] == relay


@pytest.mark.parametrize("field,value", [("client", "unknown"), ("consumer", "*"),
    ("consumer", "name\ncommand"), ("consumer", ""), ("consumer", "x" * 97),
    ("home", "relative"), ("home", "//server/share"), ("home", "\\\\server\\share"),
    ("home", "${HOME}/mail"), ("executable", "python"), ("project", ".")])
def test_invalid_plan_inputs_fail_before_any_action(tmp_path, field, value):
    with pytest.raises(ValueError):
        plan(tmp_path, **{field: value})
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("value", [None, 1, "x" * 4097, "C:/mail\x00box"])
def test_path_inputs_must_be_plain_bounded_strings(tmp_path, value):
    with pytest.raises(ValueError, match="absolute local path"):
        plan(tmp_path, home=value)
    assert not list(tmp_path.iterdir())


def test_identity_must_not_be_put_in_the_project_tree(tmp_path):
    for home in (tmp_path / "project", tmp_path / "project/private/mail"):
        with pytest.raises(ValueError, match="outside"):
            plan(tmp_path, home=str(home))


@pytest.mark.parametrize("field", ["home", "project", "executable"])
@pytest.mark.parametrize("value", [r"/\server.example.invalid/share/mail",
    r"\/server.example.invalid/share/mail", r"/\?\C:\mail", r"\/.\pipe\mail"])
def test_mixed_network_and_device_paths_are_not_local(tmp_path, field, value):
    with pytest.raises(ValueError, match="absolute local path"):
        plan(tmp_path, **{field: value})


def test_generated_startup_ignores_project_module_and_pythonpath(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "a4a_mcp.py").write_text("raise RuntimeError('unverified project module')\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("A4A_")}
    env.update(PYTHONPATH=str(project), PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    result = plan(tmp_path)
    entry = result["mcp_server"]
    invocation = [entry["command"], *entry["args"], "connect-plan", "--client", "generic",
                  "--home", str(tmp_path / "mail"), "--consumer", "mail-agent",
                  "--relay", "wss://relay.example.invalid"]
    run = subprocess.run(invocation, cwd=project, env=env, capture_output=True,
                         text=True, encoding="utf-8", timeout=15)
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["state"] == "plan_only"
    assert not (tmp_path / "mail").exists()


def test_cli_plan_is_json_only_with_no_profile_or_runtime_actions(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("A4A_")}
    env.update(A4A_HOME=str(tmp_path / "existing"), PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    code = """
import sys
def guard(event, args):
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system'):
        raise AssertionError('plan must not start a receiver, host or network call')
sys.addaudithook(guard)
from a4a_mcp.__main__ import cli_main
cli_main()
"""
    result = subprocess.run([sys.executable, "-B", "-c", code, "connect-plan",
        "--client", "generic", "--home", str(tmp_path / "mail"),
        "--consumer", "mail-agent", "--relay", "wss://relay.example.invalid"],
        cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True, text=True,
        encoding="utf-8", timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["state"] == "plan_only"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("client", ["codex", "cursor"])
def test_cli_config_is_parseable_utf8_and_never_changes_existing_files(tmp_path, client):
    project = tmp_path / "target project"
    project.mkdir()
    config_path = project / (".codex/config.toml" if client == "codex" else ".cursor/mcp.json")
    config_path.parent.mkdir()
    existing = b"owner configuration sentinel; do not overwrite"
    config_path.write_bytes(existing)
    private_home = tmp_path / "private 'owner' $state \u0430\u0433\u0435\u043d\u0442 🤖"
    env = {k: v for k, v in os.environ.items() if not k.startswith("A4A_")}
    result = subprocess.run([sys.executable, "-I", "-m", "a4a_mcp", "connect-plan",
        "--client", client, "--home", str(private_home), "--consumer", "test-client",
        "--relay", "ws://127.0.0.1:17404", "--format", "config"],
        cwd=project, env=env, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    content = result.stdout.decode("utf-8")
    data = tomllib.loads(content) if client == "codex" else json.loads(content)
    entry = data["mcp_servers" if client == "codex" else "mcpServers"]["a4a"]
    assert entry["env"]["A4A_HOME"] == str(private_home)
    assert config_path.read_bytes() == existing
    assert not private_home.exists()


def test_readiness_cannot_be_inferred_from_receiver_or_host_hint():
    from a4a_mcp.onboarding import readiness
    status = {"state": "configured", "receiver": {"state": "ready", "stale": False},
              "notifications": {"state": "listening", "host_wake": "verified"},
              "host_signal": {"state": "retained", "stale": False, "host_wake": "verified"}}
    result = readiness(status, allowed_peer_count=1)
    assert result["ready"] is False
    assert result["host_acceptance"] == "unverified"
    assert "host_acceptance_required" in result["blockers"]
    assert result["contact_policy"] == "configured"


@pytest.mark.parametrize("status", [{}, {"state": "unconfigured"}, {"receiver": None}])
def test_incomplete_status_fails_closed(status):
    from a4a_mcp.onboarding import readiness
    result = readiness(status, allowed_peer_count=0)
    assert result["ready"] is False
    assert "inbox_not_configured" in result["blockers"]
    assert "receiver_not_running" in result["blockers"]


def test_runtime_status_exposes_setup_blockers_without_creating_identity(tmp_path, monkeypatch):
    from a4a_mcp import identity, inbox_runtime
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / "mail")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / "mail/identity.json")
    result = inbox_runtime.status()
    assert result["readiness"]["ready"] is False
    assert "inbox_not_configured" in result["readiness"]["blockers"]
    assert not list(tmp_path.iterdir())


def test_every_blocker_says_whether_it_is_expected_or_an_alarm():
    """Representative, 26.09: host_acceptance_required stands in every status of this version
    and read as an alarm. Each blocker now carries a note that says which it is, and the real
    alarms say so."""
    from a4a_mcp.onboarding import readiness
    status = {"state": "configured", "receiver": {"state": "failed", "stale": True},
              "notifications": {"state": "disabled"}, "host_signal": {"state": "unconfigured"}}
    result = readiness(status, allowed_peer_count=1)
    notes = result["notes"]
    assert set(notes) == set(result["blockers"])
    assert notes["host_acceptance_required"].startswith("expected in this version, not an alarm")
    assert notes["receiver_not_running"].startswith("ALARM")
    assert notes["notification_path_not_observed"].startswith("expected")
