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
    assert data["delivery_capabilities"] == {
        "reception": "manual",
        "wake": "none",
        "verification": "unverified",
    }


def test_wake_capabilities_cli_help_and_missing_credential(tmp_path):
    help_res = run_cli(tmp_path / "empty", "wake-capabilities", "--help")
    assert help_res.returncode == 0
    assert "--token-file" in help_res.stdout
    assert "--endpoint" in help_res.stdout

    missing_res = run_cli(
        tmp_path / "empty",
        "wake-capabilities",
        "--token-file",
        str(tmp_path / "missing-token"),
    )
    assert missing_res.returncode != 0
    assert "credential" in missing_res.stderr
    assert not (tmp_path / "empty").exists()


def test_bb_wake_signal_formatting_and_cli_adapter(tmp_path, monkeypatch):
    import asyncio
    from types import SimpleNamespace
    import pytest
    from a4a_mcp.host_signal import SignalError
    from a4a_mcp.wake_runtime import (
        format_bb_wake_message,
        send_bb_cli_signal,
        query_bb_cli_signal,
    )

    sig = SimpleNamespace(
        signal_id="sig_001",
        project_id="proj-a4a",
        target_session_id="thread-abc-123",
        consumer="bb-agent",
        mode="inbox",
        pending=2,
        seq_hint=42,
    )
    msg = format_bb_wake_message(sig)
    assert "[A4A Wake v1]" in msg
    assert "signal_id=sig_001" in msg
    assert "session=thread-abc-123" in msg
    assert "pending=2 seq_hint=42" in msg

    # Reject unsafe/injected characters in metadata fields
    bad_sig = SimpleNamespace(
        signal_id="sig_001; rm -rf /",
        project_id="proj-a4a",
        target_session_id="thread-abc-123",
        consumer="bb-agent",
        mode="inbox",
        pending=1,
        seq_hint=1,
    )
    with pytest.raises(SignalError):
        format_bb_wake_message(bad_sig)

    fake_bb = tmp_path / ("bb.cmd" if os.name == "nt" else "bb")
    fake_bb.write_text("inert", encoding="utf-8")

    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[1:3] == ["thread", "send"]:
            return SimpleNamespace(returncode=0, stdout="Sent to thread-abc-123\n", stderr="")
        if argv[1:4] == ["thread", "queue", "list"]:
            return SimpleNamespace(returncode=0, stdout="1. [A4A Wake v1] signal_id=sig_001\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unknown command")

    monkeypatch.setattr("subprocess.run", fake_run)
    out_send = asyncio.run(send_bb_cli_signal(sig, bb_executable=fake_bb))
    assert out_send.status == "accepted"
    assert out_send.reason == "bb_cli_queued"

    out_query = asyncio.run(query_bb_cli_signal(sig, bb_executable=fake_bb))
    assert out_query.status == "retained"
    assert out_query.reason == "bb_queue_retained"

    # Busy thread -> deferred (queued behind active turn)
    monkeypatch.setattr(
        "subprocess.run",
        lambda argv, **kw: SimpleNamespace(
            returncode=0, stdout="thread-busy: queued for delivery after active turn\n", stderr=""
        ),
    )
    out_busy = asyncio.run(send_bb_cli_signal(sig, bb_executable=fake_bb))
    assert out_busy.status == "deferred"
    assert out_busy.reason == "bb_thread_busy"
