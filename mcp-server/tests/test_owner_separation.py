"""An ordinary MCP publication must not load or create the owner secret."""
import json

import pytest

from a4a import Agent, Keys
from a4a_mcp import identity, server
from fake_relay import FakeRelay


@pytest.fixture
def profile(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / "agent")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / "agent" / "identity.json")
    monkeypatch.setenv("A4A_MANDATE_AUTO", "0")
    return identity.load_or_create_identity()


def forbid_owner_load():
    raise AssertionError("MCP must not load the owner secret")


async def test_manual_missing_mandate_does_not_create_owner(profile, monkeypatch):
    before = identity.IDENTITY_FILE.read_bytes()
    monkeypatch.setattr(server, "load_or_create_owner_identity", forbid_owner_load)
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await server.a4a_publish_profile(["test"], "development")
        assert "issue-mandate" in out
        assert relay.events == []
    assert identity.IDENTITY_FILE.read_bytes() == before


async def test_manual_publication_needs_only_public_owner_binding(profile, monkeypatch):
    owner = Keys()
    data = json.loads(identity.IDENTITY_FILE.read_text(encoding="utf-8"))
    data["owner_pubkey_hex"] = owner.pubkey_hex
    identity.IDENTITY_FILE.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(server, "load_or_create_owner_identity", forbid_owner_load)
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url], keys=profile) as agent:
            mandate = await agent.ensure_registered(owner, "owner provisioned", days=30)
        before = identity.IDENTITY_FILE.read_bytes()
        out = await server.a4a_publish_profile(["test"], "development")
        assert "published" in out
        profiles = [ev for ev in relay.events if ev["kind"] == 31001]
        assert len(profiles) == 1
        assert [t[1] for t in profiles[0]["tags"] if t[0] == "delegation"] == [mandate]
        assert identity.IDENTITY_FILE.read_bytes() == before


def test_public_binding_prevents_silent_replacement_owner(profile):
    data = json.loads(identity.IDENTITY_FILE.read_text(encoding="utf-8"))
    data["owner_pubkey_hex"] = Keys().pubkey_hex
    identity.IDENTITY_FILE.write_text(json.dumps(data), encoding="utf-8")
    before = identity.IDENTITY_FILE.read_bytes()
    with pytest.raises(ValueError, match="owner"):
        identity.load_or_create_owner_identity()
    assert identity.IDENTITY_FILE.read_bytes() == before
