"""A hung relay must not delay EVERY read by its full per-relay timeout.

PREVIOUSLY, fan-out queried relays concurrently but waited for ALL of them. Each relay
had a 10-second timeout, so every read cost as much as the slowest response. One hung
relay in a list of five added ten seconds to every read, and removing it manually was
the only way to restore performance.

WHY NOT A QUORUM, despite the obvious appeal. A4A relays DO NOT synchronize with one
another; an event may exist on exactly one relay. "A majority answered, ignore the
rest" would silently lose messages stored on a lagging relay, indistinguishable from
"there are no messages." This exact failure class struck three times in one day.

THEREFORE, impose one deadline on the ENTIRE fan-out and NAME incompleteness. Relays
that miss the deadline do not count as responders, so callers see reduced coverage.
Completeness is not guaranteed; explicit disclosure of its absence is.
"""
import time

import pytest

from a4a import Agent, Keys
from a4a.relay import FanOutRelayClient
from tests.fake_relay import FakeRelay


async def test_hung_node_does_not_cost_a_full_timeout_on_every_read():
    """A read with a hung relay must complete within the fan-out deadline."""
    async with FakeRelay() as good, FakeRelay(respond_eose=False) as hung:
        async with Agent([good.url, hung.url]) as agent:
            agent.relay.read_deadline = 1.0
            started = time.monotonic()
            await agent.relay.query({"kinds": [1]}, max_events=10)
            spent = time.monotonic() - started
    assert spent < 4.0, (
        f"read took {spent:.1f}s; the hung relay still consumed its full timeout")


async def test_partial_coverage_is_reported_not_hidden():
    """NAME incomplete coverage: one of two relays responded, not two."""
    async with FakeRelay() as good, FakeRelay(respond_eose=False) as hung:
        async with Agent([good.url, hung.url]) as agent:
            agent.relay.read_deadline = 1.0
            result = await agent.relay.query_bounded({"kinds": [1]}, max_events=10)
    assert result.relays_responded == 1, (
        "a relay that missed the deadline counted as responding, overstating coverage")


async def test_two_healthy_nodes_are_both_counted():
    """POSITIVE control: "always one" must not look like "correctly one."""
    async with FakeRelay() as r1, FakeRelay() as r2:
        async with Agent([r1.url, r2.url]) as agent:
            agent.relay.read_deadline = 1.0
            result = await agent.relay.query_bounded({"kinds": [1]}, max_events=10)
    assert result.relays_responded == 2, "both healthy relays must count"


async def test_all_nodes_silent_still_raises():
    """When NO relay answers, report failure rather than empty success.

    An empty list from all-silent relays is indistinguishable from "nothing found."
    The previous behavior was correct here and must not be weakened.
    """
    async with FakeRelay(respond_eose=False) as h1, FakeRelay(respond_eose=False) as h2:
        async with Agent([h1.url, h2.url]) as agent:
            agent.relay.read_deadline = 1.0
            with pytest.raises(Exception):
                await agent.relay.query({"kinds": [1]}, max_events=10)
