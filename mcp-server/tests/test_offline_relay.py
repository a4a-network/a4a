"""Define what a model sees, and what a user pays, when a relay is unreachable.

A long-running check found this on 2026-09-05: without network access the service
returned only "Error executing tool", with no address, cause, or warning that retrying
was useless. Only publishing tools wrapped the failure as text; read tools leaked the
exception to the caller.

This is not cosmetic. On the host platform every model turn is a paid call charged to
the user. An opaque error after a delay reads as "try again", turning an unreachable
relay into an expense counter the user cannot see. A measured address that silently
dropped packets, matching a closed cluster network policy, cost ten seconds on every
call.
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk-python"))

from a4a import Keys, types                                   # noqa: E402
from a4a.relay import RelayError, RelayUnreachable            # noqa: E402
from a4a_mcp import identity, inbox_runtime, server           # noqa: E402
from tests.fake_relay import FakeRelay                        # noqa: E402

#: Every relay-backed tool and its minimal arguments. The list is intentionally
#: exhaustive because wrappers were omitted tool by tool; sampling is insufficient.
CALLS = {
    "a4a_search_intents": dict(category="development"),
    "a4a_find_agents": dict(category="development"),
    "a4a_get_offers": dict(intent_id="a" * 64),
    "a4a_get_agreements": {},
    "a4a_get_tasks": {},
    "a4a_get_task_results": dict(agreement_id="a" * 64),
    "a4a_get_connection_requests": {},
    "a4a_read_private": {},
    "a4a_get_reputation": dict(pubkey="b" * 64),
    "a4a_check_authority": dict(event_id="c" * 64),
    "a4a_publish_intent": dict(category="development", need="landing_page"),
    "a4a_publish_offer": dict(intent_id="a" * 64, price=1),
    "a4a_request_connection": dict(peer_pubkey="b" * 64),
    "a4a_send_private": dict(to_pubkey="b" * 64, text="hello"),
    "a4a_deliver": dict(to_pubkey="b" * 64, text="hello", new_letter=True),
}


@pytest.fixture(autouse=True)
def _clean_memory():
    server._forget_unreachable()
    yield
    server._forget_unreachable()


@pytest.fixture
def offline(monkeypatch, tmp_path):
    """Model an unreachable relay without live networking and count attempts."""
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    monkeypatch.setattr(identity, "OWNER_FILE", tmp_path / ".a4a" / "owner.json",
                        raising=False)
    monkeypatch.setattr(server, "_relay_url", lambda: "ws://10.255.255.1:8080")
    identity.load_or_create_identity()
    inbox_runtime.configure("offline-errors", ["b" * 64], start_after=0)
    attempts = []

    class _Dead:
        async def __aenter__(self):
            attempts.append(1)
            raise RelayUnreachable("could not connect to relay: TimeoutError")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(server, "_make_agent", lambda: _Dead())
    monkeypatch.setattr(server, "_mandated", lambda: _Dead())
    return attempts


async def test_every_relay_tool_answers_with_text_not_an_exception(offline):
    """Every tool must return text instead of exposing an exception to the model."""
    for name, kwargs in CALLS.items():
        server._forget_unreachable()          # Check every tool independently.
        out = await getattr(server, name)(**kwargs)
        assert isinstance(out, str), f"{name} did not return text"
        assert "unreachable" in out, f"{name}: {out[:80]}"
        assert "10.255.255.1" in out, f"{name} omitted the relay address: {out[:80]}"
        assert "WILL NOT HELP" in out, f"{name} did not say that retrying is useless: {out[:80]}"


async def test_second_call_does_not_touch_the_network(offline):
    """Serve repeated calls from memory so every turn does not pay for a timeout.

    This checks behavior rather than wording by counting connection attempts.
    """
    await server.a4a_search_intents(category="development")
    assert len(offline) == 1
    for _ in range(5):
        out = await server.a4a_search_intents(category="development")
    assert len(offline) == 1, f"connection attempts: {len(offline)} instead of one"
    assert "did not access the network" in out, out[:120]


async def test_memory_expires(offline, monkeypatch):
    """Expire the cache so a recovered relay is not considered dead forever."""
    monkeypatch.setattr(server, "UNREACHABLE_TTL", 0)
    await server.a4a_search_intents(category="development")
    await server.a4a_search_intents(category="development")
    assert len(offline) == 2, "an expired cache entry did not allow another attempt"


async def test_memory_is_bound_to_the_address(offline, monkeypatch):
    """Bind cached failures to an address so another relay is still attempted."""
    await server.a4a_search_intents(category="development")
    monkeypatch.setattr(server, "_relay_url", lambda: "ws://10.255.255.2:8080")
    await server.a4a_search_intents(category="development")
    assert len(offline) == 2, "a failure for one address blocked another relay"


async def test_live_relay_works_again_once_the_memory_is_stale(monkeypatch, tmp_path):
    """Detect recovery no later than the TTL, the strongest honest guarantee.

    The first version claimed that a successful call cleared the cache. That condition
    was impossible: while the cache is fresh, no call reaches the relay and success
    cannot occur. Removing the cleanup still left the mutation test green. The real
    property is that once the cache expires, a live relay responds normally and that
    success then clears the cached failure.
    """
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    monkeypatch.setattr(identity, "OWNER_FILE", tmp_path / ".a4a" / "owner.json",
                        raising=False)
    async with FakeRelay() as relay:
        monkeypatch.setattr(server, "_relay_url", lambda: relay.url)
        monkeypatch.setattr(server, "load_or_create_identity", lambda: Keys())
        server._remember_unreachable(relay.url, "stale failure")
        assert server._recent_unreachable() is not None, "the cache was not primed"

        monkeypatch.setattr(server, "UNREACHABLE_TTL", 0)     # Expire the cache.
        out = await server.a4a_search_intents(category="development")
    assert "unreachable" not in out and "stale failure" not in out, out[:100]
    assert server._last_unreachable is None, "success did not clear the cached failure"


async def test_relay_refusal_is_not_confused_with_unreachability(monkeypatch, tmp_path):
    """Distinguish a semantic relay refusal from network unreachability.

    A refusal is addressed by changing the event, so retrying can make sense; retrying
    cannot repair unreachability. When both errors shared a type, publishing tools
    described a network failure as "relay rejected publication", blaming the relay for
    a decision it never made.
    """
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    monkeypatch.setattr(identity, "OWNER_FILE", tmp_path / ".a4a" / "owner.json",
                        raising=False)
    monkeypatch.setattr(server, "_relay_url", lambda: "ws://relay")

    class _Refusing:
        async def __aenter__(self):
            raise RelayError("relay rejected event: blocked: mandate required",
                             reason="blocked: mandate required")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(server, "_mandated", lambda: _Refusing())
    out = await server.a4a_publish_intent(category="development", need="landing_page")
    assert "WILL NOT HELP" not in out, "a relay refusal was presented as unreachability"
    assert "unreachable" not in out
    assert server._recent_unreachable() is None, "a relay refusal entered the failure cache"
