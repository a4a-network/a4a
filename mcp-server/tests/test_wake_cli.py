"""Wake CLI fails closed, never prints credentials or installs a service."""
import json
import os
import subprocess
import sys

import guarded_child


def run_cli(home, *args):
    """Run the wake CLI behind the installed suite boundary.

    This previously launched bare: patches remain in parent memory, leaving the child
    interpreter free to access the network without any boundary.
    """
    argv, env, ready = guarded_child.module_command(
        ["-m", "a4a_mcp", *args], home=str(home), relay="ws://127.0.0.1:1/never",
        env={"A4A_MANDATE_AUTO": "0", "A4A_MCP_CHANNEL": ""})
    result = subprocess.run(argv, env=env, text=True, encoding="utf-8", input="",  # unguarded-launch: argv comes from module_command
                            capture_output=True, timeout=20,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    ready.note_exit(result.returncode)
    ready.check()
    return result


def test_wake_help_describes_explicit_lifetime_and_no_secret_argv(tmp_path):
    result = run_cli(tmp_path / "empty", "wake-run", "--help")
    assert result.returncode == 0
    for flag in ("--project-id", "--target-session-id", "--token-file", "--once", "--forever", "--resume-rejected"):
        assert flag in result.stdout
    assert not (tmp_path / "empty").exists()


def test_unknown_option_with_accidental_credential_is_redacted(tmp_path):
    secret = "SYNTHETIC-SECRET-NOT-TO-PRINT"
    result = run_cli(tmp_path / "empty", "wake-run", "--token", secret)
    assert result.returncode != 0
    assert secret not in result.stdout + result.stderr
    assert not (tmp_path / "empty").exists()


def test_missing_credential_fails_without_creating_identity(tmp_path):
    result = run_cli(tmp_path / "empty", "wake-run", "--project-id", "test",
                     "--target-session-id", "test-session", "--token-file", str(tmp_path / "missing"), "--once")
    assert result.returncode != 0
    assert "credential" in result.stderr
    assert not (tmp_path / "empty").exists()


def test_status_distinguishes_host_signal_from_current_mcp_channel(tmp_path):
    result = run_cli(tmp_path / "empty", "inbox-status")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["host_signal"] == {"state": "unconfigured", "host_wake": "unverified"}
    assert data["notifications"]["state"] == "disabled"
