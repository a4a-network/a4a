"""Read budget measures WORK rather than address count.

WHY THIS WAS NEEDED. The "at most five relays" cap protected against work, not relay
count: signature verification for every raw event is expensive, and `max_events`
bounded it for ONE relay. Without a relay-count ceiling, aggregate work grew linearly
with list length, so adding addresses bypassed the protection.

But five addresses are a crude work estimate and block legitimate behavior. Network
self-healing needs to read the UNION of announced relays and a recently derived one:
five plus one is six, rejected by the old rule (review finding HEAL-006). Silently
raising the cap would dissolve the safeguard.

SOLUTION. Apply one budget to the ENTIRE query and divide it across relays. Aggregate
verification stays bounded by the same number whether the list has two relays or ten.
The tradeoff is explicit: wider fanout gives each relay a smaller window, and a flag
reports truncation rather than hiding it.
"""
import pytest

from a4a import Agent
from a4a.relay import FanOutRelayClient
from tests.fake_relay import FakeRelay


async def test_total_inspection_does_not_grow_with_the_number_of_nodes():
    """Core property: aggregate work does NOT grow with relay count.

    THE FIRST VERSION OF THIS TEST WAS VACUOUS, found by a reviewer rather than me.
    It seeded no events, so relays returned nothing and "zero is at most sixty" passed
    long before the implementation changed. The green result proved nothing.

    Relays are now SATURATED: each holds more events than the entire budget. Only
    saturation exposes budget division; below it, division and no division look alike.
    """
    async def saturated(count):
        relays = [FakeRelay() for _ in range(count)]
        for r in relays:
            await r.__aenter__()
        try:
            for r in relays:
                for i in range(70):
                    r.events.append({"id": f"{i:064x}", "pubkey": "0" * 64, "kind": 1,
                                     "created_at": 1, "tags": [], "content": "x", "sig": "0" * 128})
            async with Agent([r.url for r in relays], keys=None) as agent:
                agent.relay.read_budget = 60
                return await agent.relay.query_bounded({"kinds": [1]}, max_events=60)
        finally:
            for r in relays:
                await r.__aexit__(None, None, None)

    one = await saturated(1)
    three = await saturated(3)
    assert one.inspected_events <= 60, \
        f"one relay inspected {one.inspected_events} events under a budget of 60"
    assert three.inspected_events <= 60, (
        f"three saturated relays inspected {three.inspected_events} events under a budget of 60; "
        "work grows with list length and address additions bypass the safeguard")
    assert three.truncated, "saturated relays must report truncation"


async def test_more_nodes_than_the_old_cap_are_allowed():
    """Six relays can be announced-plus-derived union and must remain usable."""
    async with FakeRelay() as a, FakeRelay() as b, FakeRelay() as c, \
               FakeRelay() as d, FakeRelay() as e, FakeRelay() as f:
        urls = [x.url for x in (a, b, c, d, e, f)]
        async with Agent(urls, keys=None) as agent:
            assert len(agent.relay.clients) == 6
            result = await agent.relay.query_bounded({"kinds": [1]}, max_events=60)
    assert result.relays_responded == 6


async def test_absurd_fan_out_is_still_refused():
    """NEGATIVE control: the limit moved; it did not disappear.

    Without this case, "budget instead of cap" is indistinguishable from removing all
    protection. A list containing more relays than budgeted events cannot allocate
    even one event per relay; such fanout is meaningless and must be rejected.
    """
    async with FakeRelay() as r:
        client = FanOutRelayClient([r.url])
        client.read_budget = 3
        with pytest.raises(ValueError):
            client._per_relay_ceiling(10)


async def test_share_is_divided_and_never_zero():
    """Per-relay share divides the budget but never falls below one event."""
    client = FanOutRelayClient.__new__(FanOutRelayClient)
    client.read_budget = 100
    assert client._per_relay_ceiling(1) == 100
    assert client._per_relay_ceiling(4) == 25
    assert client._per_relay_ceiling(3) == 33
