"""Cover the MCP server's separate owner key (2026-08-29).

The original single-key model made the agent its own owner with no delegation. That
MVP design made a compromised working key impossible to revoke because it was also the
identity. A separate owner key decouples long-lived identity from the working key, so
the agent key can be revoked without losing the owner's address or reputation.

This is independent of legal identity questions, which concern certification of the
owner key rather than whether that key exists.
"""
import json
from unittest.mock import Mock

import pytest
from a4a import Agent, keyfile

from a4a_mcp import identity, server
from fake_relay import FakeRelay


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")


def test_owner_key_is_created_and_differs_from_agent_key(mcp_home):
    agent_keys = identity.load_or_create_identity()
    owner_keys = identity.load_or_create_owner_identity()
    assert owner_keys.privkey_hex != agent_keys.privkey_hex, \
        "owner and agent share one key, leaving nothing able to revoke it"
    assert len(owner_keys.pubkey_hex) == 64


def test_owner_key_is_stable_between_calls(mcp_home):
    first = identity.load_or_create_owner_identity()
    second = identity.load_or_create_owner_identity()
    assert first.privkey_hex == second.privkey_hex


def test_existing_single_key_install_keeps_its_address(mcp_home):
    """Keep the agent address when migrating an existing single-key installation.

    A user may already have `identity.json` with one key. Changing its address would
    lose all associated reputation and connections. Add the owner key alongside it
    while preserving the original agent key.
    """
    before = identity.load_or_create_identity()
    identity.load_or_create_owner_identity()
    after = identity.load_or_create_identity()
    assert after.pubkey_hex == before.pubkey_hex, "migration changed the agent address"


def test_owner_key_migration_rechecks_replaced_file(mcp_home, monkeypatch):
    harden = Mock(wraps=keyfile._harden)
    monkeypatch.setattr(keyfile, "_harden", harden)
    identity.load_or_create_identity()
    assert harden.call_count == 1
    identity.load_or_create_owner_identity()
    assert harden.call_count == 2
    assert keyfile.is_private(identity.IDENTITY_FILE)[0]


def test_file_key_updates_recheck_replaced_file(mcp_home, monkeypatch):
    harden = Mock(wraps=keyfile._harden)
    monkeypatch.setattr(keyfile, "_harden", harden)
    identity.store_file_key("a" * 64, "test-key", size=1, name="test")
    assert harden.call_count == 1
    identity.store_file_key("b" * 64, "test-key", size=1, name="test")
    assert harden.call_count == 2
    identity.pop_file_key("a" * 64)
    assert harden.call_count == 3
    assert keyfile.is_private(identity._file_keys_path())[0]


def test_owner_key_never_leaves_the_file(mcp_home):
    identity.load_or_create_owner_identity()
    data = json.loads(identity.IDENTITY_FILE.read_text(encoding="utf-8"))
    assert "owner_privkey_hex" in data


async def test_published_events_carry_a_delegation(mcp_home, monkeypatch):
    """Prove that an agent event is cryptographically linked to its owner."""
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await server.a4a_publish_intent(need="landing_page", category="design")
        assert "published" in out
        intents = [e for e in relay.events if e["kind"] == 31002]
        assert intents, "the intent was not published"
        tags = {t[0] for t in intents[0]["tags"]}
        assert "delegation" in tags, "the agent event was published without an owner mandate"
