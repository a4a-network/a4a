"""Cover agent discovery through MCP.

The SDK gained profile-based discovery in the 2026-08-29 audit, but MCP lacked the
corresponding tool even though it is the most frequently used surface. A connected
assistant could publish its own profile but could not discover anyone else's.
"""
import pytest
from a4a import Agent, AgentProfile

from a4a_mcp import identity, server
from fake_relay import FakeRelay


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")


async def test_find_agents_returns_matching_profile(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as seller:
            await seller.publish_profile(AgentProfile(
                capabilities=["seo"], category="marketing", content="promotion"))
        out = await server.a4a_find_agents(category="marketing")
    assert seller.pubkey in out, "the discovered agent is missing from the response"
    assert "UNTRUSTED DATA" in out, "a stranger's profile reached the model without framing"


async def test_find_agents_says_plainly_when_nothing_found(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await server.a4a_find_agents(category="design")
    assert "no agents matched" in out.lower()


async def test_find_agents_rejects_unknown_category(mcp_home, monkeypatch):
    """Return valid categories to a machine caller instead of a traceback."""
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await server.a4a_find_agents(category="fabricated")
    assert "marketing" in out and "fabricated" in out
