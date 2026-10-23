"""Readiness evidence is local, payload-free, and never inferred from an address."""
import json

import pytest

from a4a_mcp import identity, inbox_runtime, server


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / "home")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / "home" / "identity.json")
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1")
    monkeypatch.setenv("A4A_MANDATE_AUTO", "0")
    monkeypatch.delenv("A4A_MCP_CHANNEL", raising=False)


def test_unconfigured_status_reports_notifications_without_creating_identity():
    result = inbox_runtime.status()
    assert result["state"] == "unconfigured"
    assert result.get("notifications") == {
        "adapter": "none", "state": "disabled",
        "scope": "current_process", "host_wake": "unverified",
    }
    assert not identity.IDENTITY_DIR.exists()


@pytest.mark.parametrize("receiver_state", ["ready", "stopped", "failed"])
async def test_receiver_health_is_not_host_wake_evidence(receiver_state):
    keys = identity.load_or_create_identity()
    inbox_runtime.configure("test-status", [])
    with inbox_runtime.open_runtime() as (_, _, store):
        store.set_health(receiver_state)
    result = await server.a4a_inbox_status()
    assert result["receiver"]["state"] == receiver_state
    assert result.get("notifications", {}).get("state") == "disabled"
    assert result["notifications"]["host_wake"] == "unverified"
    assert keys.privkey_hex not in json.dumps(result)


async def test_address_points_to_diagnostics_without_claiming_a_connection():
    result = await server.a4a_my_address()
    assert "a4a_inbox_status" in result
    assert "does not confirm" in result
    assert "connected" not in server.a4a_my_address.__doc__


def test_another_receivers_health_cannot_start_this_process_adapter(monkeypatch):
    identity.load_or_create_identity()
    inbox_runtime.configure("test-status", [])
    with inbox_runtime.open_runtime() as (_, _, store):
        store.set_health("ready")
    monkeypatch.setenv("A4A_MCP_CHANNEL", "claude")
    result = inbox_runtime.status()
    assert result["receiver"]["state"] == "ready"
    assert result["notifications"]["state"] == "not_started"
    assert result["notifications"]["host_wake"] == "unverified"


def test_model_instructions_require_host_acceptance_not_address_success():
    assert "host_wake" in server.mcp.instructions
    assert "unverified" in server.mcp.instructions
    assert "empty model polling" in server.mcp.instructions


def test_stale_receiver_health_is_shown_as_unknown_not_as_a_plausible_state():
    """26.09.2026: a project agent read a 2-minute-old "failed" while its receiver was storing letters.
    A stale value must not look actionable: shown as unknown, the old word kept aside."""
    import time
    identity.load_or_create_identity()
    inbox_runtime.configure("test-status", [])
    with inbox_runtime.open_runtime() as (_, _, store):
        store.set_health("failed", now=time.time() - 120)
    result = inbox_runtime.status()
    assert result["receiver"]["state"] == "unknown"
    assert result["receiver"]["last_reported"] == "failed"
    assert result["receiver"]["stale"] is True
    assert result["counts"]["reliable"] is False


def test_fresh_receiver_health_is_shown_as_reported():
    identity.load_or_create_identity()
    inbox_runtime.configure("test-status", [])
    with inbox_runtime.open_runtime() as (_, _, store):
        store.set_health("failed")
    assert inbox_runtime.status()["receiver"]["state"] == "failed"


def test_every_count_in_the_status_carries_the_moment_it_was_taken():
    """Network rule 1 (26.09.2026): a count without the time it was taken misleads - 50 vs 55.
    The rule is enforced here, not only written down."""
    import time
    identity.load_or_create_identity()
    inbox_runtime.configure("test-status", [])
    result = inbox_runtime.status()
    assert abs(result["counts"]["as_of"] - time.time()) < 60
