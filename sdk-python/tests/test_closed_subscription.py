"""When a relay closes a subscription (`CLOSED`, NIP-01), surface its reason promptly.

Finding 111 (2026-09-05): after filter parsing was hardened, the relay rejected malformed
`REQ` messages, but the SDK client only handled `OK`, `EVENT`, and `EOSE`. It ignored
`CLOSED`, leaving the caller stuck until its 10-second timeout and returning a useless
"no EOSE" error instead of the relay's reason. These tests require `query` and
`subscribe` to fail immediately, preserve the relay text verbatim, and add a hint for
the reason class.
"""
import asyncio
import time

import pytest

from a4a import Agent, Keys
from a4a.relay import RelayClient, RelayError
from tests.fake_relay import FakeRelay

PARSE_FAIL = "invalid: could not parse REQ filter"


async def test_query_wakes_up_with_the_relay_reason_not_a_timeout():
    async with FakeRelay(closed_reason=PARSE_FAIL) as relay:
        async with RelayClient(relay.url, timeout=10) as rc:
            started = time.monotonic()
            with pytest.raises(RelayError) as info:
                await rc.query({"kinds": ["a"]})
            elapsed = time.monotonic() - started
    assert PARSE_FAIL in str(info.value), "the relay reason must be preserved verbatim"
    assert info.value.reason == PARSE_FAIL
    assert "no EOSE" not in str(info.value)
    assert elapsed < 2, f"waited {elapsed:.1f}s; the client is hanging until timeout again"


async def test_reason_carries_a_hint_matching_its_class():
    cases = {
        PARSE_FAIL: "check the types",
        "rate-limited: too many concurrent REQs": "rate-limiting",
        "blocked: not on the allow list": "rejected the subscription",
        "": None,
    }
    for reason, hint in cases.items():
        async with FakeRelay(closed_reason=reason) as relay:
            async with RelayClient(relay.url, timeout=5) as rc:
                with pytest.raises(RelayError) as info:
                    await rc.query({"kinds": [1]})
        text = str(info.value)
        assert "closed the subscription" in text and reason in text
        if hint:
            assert hint in text, (reason, text)


async def test_subscribe_ends_with_the_same_reason():
    """`subscribe` has no timeout and waits forever unless it handles CLOSED.

    Bound the wait externally: the test must fail within seconds with the relay's
    reason rather than hang, as it did when mutated to ignore CLOSED.
    """
    async def consume():
        async with FakeRelay(closed_reason=PARSE_FAIL) as relay:
            async with RelayClient(relay.url, timeout=10) as rc:
                async for _ in rc.subscribe({"kinds": ["a"]}):
                    pass
    started = time.monotonic()
    with pytest.raises(RelayError, match="could not parse"):
        await asyncio.wait_for(consume(), timeout=5)
    assert time.monotonic() - started < 5


async def test_agent_level_calls_surface_the_reason():
    """Agent callers also receive the reason instead of an apparent silent relay."""
    async with FakeRelay(closed_reason=PARSE_FAIL) as relay:
        async with Agent([relay.url], Keys()) as agent:
            with pytest.raises(RelayError, match="could not parse"):
                await agent.search_intents(category="development")


async def test_normal_subscriptions_are_untouched():
    """Positive control: subscriptions without CLOSED continue to work."""
    async with FakeRelay() as relay:
        async with Agent([relay.url], Keys()) as agent:
            await agent.ensure_registered(Keys(), "bot")
            assert await agent.search_intents(category="development") == []
