"""Test MCP tools against FakeRelay without mocking the thin `Agent` layer.

The key contract here is reputation mode. A 2026-08-17 change made
`a4a_get_reputation` safe by default by counting only reviews attached to confirmed
agreements, but it lacked coverage. Code presence is not proof of behavior.
"""
import pytest
from a4a import Agent

from a4a_mcp import identity, server
from fake_relay import FakeRelay


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")


async def test_my_address_never_exposes_private_key(mcp_home, monkeypatch):
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1/never-connected")
    keys = identity.load_or_create_identity()
    out = await server.a4a_my_address()
    assert keys.pubkey_hex in out and keys.npub in out
    assert keys.privkey_hex not in out


async def test_reputation_default_mode_ignores_reviews_without_agreement(mcp_home,
                                                                        monkeypatch):
    """Ignore reviews without the rated key's signed agreement by default.

    `verified_only=False` includes them. This verifies linkage to a signed agreement,
    not resistance to self-dealing or collusion, and not independence of the parties.
    """
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as stranger, Agent([relay.url]) as target:
            await stranger.publish_review("nonexistent-agreement", target.pubkey, 5)

            safe = await server.a4a_get_reputation(target.pubkey)
            assert "0 review records" in safe
            assert "two-signature agreements" in safe

            loose = await server.a4a_get_reputation(target.pubkey, verified_only=False)
            assert "1 review records" in loose
            assert "WITHOUT agreement checks" in loose


async def test_reputation_of_unknown_key_is_zero(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await server.a4a_get_reputation("f" * 64)
        assert "0 review records" in out
