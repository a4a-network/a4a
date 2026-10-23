"""Owner CLI never falls through to serving MCP after a misspelled command."""
import json
import os
import subprocess
import sys
from pathlib import Path

import guarded_child
import pytest

from a4a import Keys, giftwrap, types
from a4a.event import Event
from a4a_mcp import identity, inbox_runtime


def run(home, *args, env_extra=None):
    """Run the real owner CLI behind the installed suite boundary.

    This previously used bare `subprocess.run`: patches live only in parent memory, so  # unguarded-launch: mention, not a launch
    the child interpreter accessed the network without a boundary and inherited the
    developer's contaminated environment in full.
    """
    repository = Path(__file__).resolve().parents[2]
    argv, env, ready = guarded_child.module_command(
        ["-m", "a4a_mcp", *args], home=str(home),
        relay="ws://127.0.0.1:1",
        source_roots=(repository / "mcp-server", repository / "sdk-python"),
        env={"A4A_MANDATE_AUTO": "0", "A4A_MCP_TRANSPORT": "stdio",
             "A4A_MCP_CHANNEL": "", **(env_extra or {})})
    result = subprocess.run(argv, env=env, input="", capture_output=True,  # unguarded-launch: argv comes from module_command
                            text=True, encoding="utf-8", timeout=20)
    ready.note_exit(result.returncode)
    ready.check()
    return result


def test_cli_status_does_not_create_identity(tmp_path):
    result = run(tmp_path / "home", "inbox-status")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["state"] == "unconfigured"
    assert not (tmp_path / "home").exists()


def test_configure_requires_verified_existing_identity(tmp_path):
    result = run(tmp_path / "home", "inbox-configure", "--consumer", "test")
    assert result.returncode != 0
    assert "identity" in result.stderr
    assert not (tmp_path / "home").exists()


def test_cli_owner_configuration_and_local_status(tmp_path):
    home = tmp_path / "home"
    assert run(home, "address").returncode == 0
    peer_keys = Keys()
    result = run(home, "inbox-configure", "--consumer", "test", "--allow-peer", peer_keys.npub)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["consumer"] == "test"
    assert json.loads(result.stdout)["allowed_peers"] == [peer_keys.pubkey_hex]
    result = run(home, "inbox-status")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["receiver"]["state"] == "not_started"
    assert run(home, "inbox-configure", "--consumer", "test").returncode != 0
    result = run(home, "inbox-next")
    assert json.loads(result.stdout)["state"] == "receiver_unavailable"
    result = run(home, "inbox-watch", "--once")
    assert result.returncode != 0
    assert not result.stdout, "failed receiver must not emit a success notification"


def test_cli_reconciliation_requires_an_existing_exact_unknown_message(tmp_path):
    home = tmp_path / "home"
    assert run(home, "address").returncode == 0
    assert run(home, "inbox-configure", "--consumer", "test",
               "--allow-peer", "a" * 64).returncode == 0
    result = run(home, "inbox-reconcile", "--seq", "1", "--inner-id", "b" * 64,
                 "--resolution", "retry")
    assert result.returncode != 0
    assert "reconciliation" in result.stderr
    assert not result.stdout


def test_cli_discovers_only_unknown_bindings_and_reconciles_without_claim_output(
        tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setattr(identity, "IDENTITY_DIR", home)
    monkeypatch.setattr(identity, "IDENTITY_FILE", home / "identity.json")
    monkeypatch.setenv("A4A_HOME", str(home))
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1")
    me, peer = identity.load_or_create_identity(), Keys()
    policy = inbox_runtime.configure("test", [peer.pubkey_hex], start_after=0)

    with inbox_runtime.open_runtime() as (_, agent, store):
        def add(delivery, created, now):
            inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                          tags=[["p", me.pubkey_hex], ["d", delivery]],
                          content="must not appear in listing",
                          created_at=created).sign(peer)
            outer = giftwrap.wrap(inner, me.pubkey_hex, peer, now=now)
            assert store.accept(agent, outer, policy.allowed_peers, now=now) == "stored"
            return inner

        unknown_one = add("cli-unknown-one", 1, 2)
        assert store.claim(agent, policy.consumer, policy.allowed_peers,
                           now=3, lease_seconds=1) is not None
        store.status(now=4)
        unknown_two = add("cli-unknown-two", 5, 6)
        assert store.claim(agent, policy.consumer, policy.allowed_peers,
                           now=7, lease_seconds=1) is not None
        store.status(now=8)

        add("cli-processed", 9, 10)
        processed = store.claim(agent, policy.consumer, policy.allowed_peers, now=11)
        store.finish(processed["seq"], processed["lease_token"], policy.consumer,
                     "processed", now=12)
        add("cli-failed", 13, 14)
        failed = store.claim(agent, policy.consumer, policy.allowed_peers, now=15)
        store.finish(failed["seq"], failed["lease_token"], policy.consumer,
                     "failed", now=16)
        add("cli-blocked", 17, 18)
        assert store.claim(agent, policy.consumer, set(), now=19) is None
        add("cli-pending", 20, 21)

    limited = run(home, "inbox-unknown", "--limit", "1")
    assert limited.returncode == 0, limited.stderr
    assert json.loads(limited.stdout)["truncated"] is True

    listed = run(home, "inbox-unknown", "--limit", "100")
    assert listed.returncode == 0, listed.stderr
    payload = json.loads(listed.stdout)
    assert set(payload) == {"unknown", "truncated", "limit"}
    assert payload["truncated"] is False
    assert {item["inner_id"] for item in payload["unknown"]} == {
        unknown_one.id, unknown_two.id}
    assert len(payload["unknown"]) == 2
    assert all(set(item) == {"seq", "inner_id"} for item in payload["unknown"])
    assert "must not appear in listing" not in listed.stdout

    discovered = payload["unknown"][0]
    resolved = run(home, "inbox-reconcile", "--seq", str(discovered["seq"]),
                   "--inner-id", discovered["inner_id"], "--resolution", "processed")
    assert resolved.returncode == 0, resolved.stderr
    assert json.loads(resolved.stdout)["state"] == "processed"
    remaining = json.loads(run(home, "inbox-unknown").stdout)["unknown"]
    assert remaining == [payload["unknown"][1]]


def test_cli_reconciliation_help_names_retry_safety_boundaries(tmp_path):
    result = run(tmp_path / "home", "inbox-reconcile", "--help")
    assert result.returncode == 0, result.stderr
    for text in ("unexpired", "authorized sender", "ACK", "seq", "inner_id"):
        assert text in result.stdout

    listing = run(tmp_path / "home", "inbox-unknown", "--help")
    assert listing.returncode == 0, listing.stderr
    for text in ("seq", "inner_id", "text", "envelope", "keys"):
        assert text in listing.stdout


@pytest.mark.parametrize("args,extra", [(["inbox-typo"], {}), ([], {"A4A_MCP_CHANNEL": "typo"}),
    ([], {"A4A_MCP_CHANNEL": "claude", "A4A_MCP_TRANSPORT": "http"})])
def test_invalid_cli_and_channel_combinations_fail_loudly(tmp_path, args, extra):
    result = run(tmp_path / "home", *args, env_extra=extra)
    assert result.returncode != 0
    assert result.stderr


def test_unconfigured_claude_channel_fails_before_handshake(tmp_path):
    result = run(tmp_path / "home", env_extra={"A4A_MCP_CHANNEL": "claude"})
    assert result.returncode != 0
    assert not result.stdout
    assert not (tmp_path / "home").exists()
