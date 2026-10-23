"""Publishing must report HOW MANY relays accepted an event, not merely "success".

External reviewer finding HEAL-004. The fanout considers publication successful
when at least one relay accepts the event. An event stored on ONE relay therefore
looks exactly like an event stored on three:

    A accepted, B and C rejected  ->  call succeeds
    A is lost                      ->  zero copies

We counted configured relays and called that redundancy. Redundancy is determined
by the number of ACCEPTED copies, which was not exposed anywhere.

A4A relays do not exchange data with each other, so accepted-copy count is the
actual durability: n accepted copies survive the loss of n-1 relays, not n; and
acceptance is weaker than STORAGE. A list of three provides nothing if only one
relay accepted the event.
"""
import logging

import pytest

from a4a import Agent, InsufficientCopies
from a4a.relay import RelayError
from a4a.event import Event
from tests.fake_relay import FakeRelay

REJECT = "blocked: relay does not accept events"


def _probe(agent) -> Event:
    return Event(kind=1, content="copy-count probe").sign(agent.keys)


async def test_publish_reports_how_many_nodes_accepted():
    """The caller sees the accepted count instead of a generic "success"."""
    async with FakeRelay() as good, FakeRelay(reject_reason=REJECT) as bad:
        async with Agent([good.url, bad.url]) as agent:
            accepted = await agent.relay.publish(_probe(agent), replay_on_reconnect=False)
    assert accepted == 1, f"one of two relays accepted, but publish reported {accepted}"


async def test_all_healthy_nodes_are_counted():
    """Positive control: distinguish "always one" from "correctly one"."""
    async with FakeRelay() as r1, FakeRelay() as r2:
        async with Agent([r1.url, r2.url]) as agent:
            accepted = await agent.relay.publish(_probe(agent), replay_on_reconnect=False)
    assert accepted == 2, "both healthy relays must be counted"


async def test_caller_can_require_a_minimum_number_of_copies():
    """Callers needing redundancy must be able to REQUIRE it, not hope for it."""
    async with FakeRelay() as good, FakeRelay(reject_reason=REJECT) as bad:
        async with Agent([good.url, bad.url]) as agent:
            # Require InsufficientCopies specifically, not any exception. The first
            # version caught Exception and passed BEFORE the fix because it caught a
            # TypeError for an unknown argument. A pre-implementation green test
            # verifies nothing.
            with pytest.raises(InsufficientCopies) as refusal:
                await agent.relay.publish(_probe(agent), min_accepted=2,
                                          replay_on_reconnect=False)
    assert refusal.value.accepted == 1 and refusal.value.required == 2


async def test_minimum_that_is_met_does_not_raise():
    """Negative control: a satisfied minimum must pass without raising."""
    async with FakeRelay() as r1, FakeRelay() as r2:
        async with Agent([r1.url, r2.url]) as agent:
            accepted = await agent.relay.publish(_probe(agent), min_accepted=2,
                                                 replay_on_reconnect=False)
    assert accepted == 2


async def test_partial_redundancy_is_named_in_the_log(caplog):
    """Partial redundancy must be STATED, not inferred by subtraction."""
    async with FakeRelay() as good, FakeRelay(reject_reason=REJECT) as bad:
        with caplog.at_level(logging.WARNING, logger="a4a"):
            async with Agent([good.url, bad.url]) as agent:
                await agent.relay.publish(_probe(agent), replay_on_reconnect=False)
    assert any("1 of 2" in r.getMessage()
               for r in caplog.records), \
        "the accepted count is missing from logs, making partial redundancy look complete"


async def test_nobody_accepted_still_raises():
    """Preserve prior behavior: zero acceptances are failure, not degradation."""
    async with FakeRelay(reject_reason=REJECT) as b1, FakeRelay(reject_reason=REJECT) as b2:
        async with Agent([b1.url, b2.url]) as agent:
            # Require a relay refusal specifically, not any exception: a broad
            # `Exception` would also pass on an argument error or network break.
            # Check the TEXT reason as well as the class: an empty RelayError would
            # pass for an invented disconnect and fail to establish the actual cause.
            with pytest.raises(RelayError) as refusal:
                await agent.relay.publish(_probe(agent), replay_on_reconnect=False)
    assert "does not accept" in str(refusal.value), \
        f"refusal does not preserve the relay's actual reason: {refusal.value}"


async def test_same_node_configured_twice_is_not_two_copies():
    """One relay configured twice is ONE copy, not two.

    An external reviewer measured that `min_accepted=2` could be satisfied by one
    store. Losing that relay left zero copies despite the requirement appearing met.
    """
    async with FakeRelay() as r:
        async with Agent([r.url, r.url]) as agent:
            assert len(agent.relay.clients) == 1, "duplicate addresses must collapse"
            accepted = await agent.relay.publish(_probe(agent), replay_on_reconnect=False)
    assert accepted == 1


async def test_two_distinct_nodes_still_count_as_two_positive_control():
    """Positive control for deduplication: distinct relays do not collapse."""
    async with FakeRelay() as r1, FakeRelay() as r2:
        async with Agent([r1.url, r2.url]) as agent:
            assert len(agent.relay.clients) == 2
            accepted = await agent.relay.publish(_probe(agent), replay_on_reconnect=False)
    assert accepted == 2


async def test_impossible_minimum_is_refused_before_writing_anything():
    """An impossible minimum is rejected BEFORE anything is written.

    The previous version published the event before refusing, leaving a network
    copy that the caller believed did not exist.
    """
    async with FakeRelay() as r:
        async with Agent([r.url]) as agent:
            event = _probe(agent)
            with pytest.raises(ValueError):
                await agent.relay.publish(event, min_accepted=2, replay_on_reconnect=False)
        assert event.id not in {e["id"] for e in r.events}, \
            "event was written despite a provably impossible requirement"


async def test_trailing_slash_is_not_a_second_node():
    """`wss://x/` and `wss://x` are one relay; a slash cannot bypass the minimum.

    The reviewer's third pass on HEAL-004 found that deduplication compared raw
    strings, so a trailing slash produced two "copies" backed by one store.
    """
    async with FakeRelay() as r:
        async with Agent([r.url, r.url + "/"]) as agent:
            assert len(agent.relay.clients) == 1, "a trailing slash created a second relay"
            with pytest.raises(ValueError):
                await agent.relay.publish(_probe(agent), min_accepted=2,
                                          replay_on_reconnect=False)


def test_same_address_written_two_ways_is_one_node():
    """`[::1]` and `[0:0:0:0:0:0:0:1]` are two spellings of one host.

    On the fourth HEAL-004 pass, the bypass became narrower: string comparison
    treated two spellings of one numeric address as distinct relays, satisfying
    a two-copy requirement with ONE store.
    """
    from a4a.relay import _canonical_relay_key as key
    assert key("ws://[::1]:9") == key("ws://[0:0:0:0:0:0:0:1]:9")
    assert key("ws://127.0.0.1:9") != key("ws://127.0.0.2:9")


def test_canonical_key_does_not_merge_different_paths():
    """Negative control: different paths must NOT merge.

    Without this case, "collapse everything similar" is indistinguishable from
    "collapse identical endpoints", and two real relays behind one host would
    count as one.
    """
    from a4a.relay import _canonical_relay_key as key
    assert key("wss://x/") == key("wss://x") == key("WSS://X:443")
    assert key("wss://x/a") != key("wss://x/b")
    assert key("wss://x") != key("wss://y")
    # Collapse ONLY an empty path with the root. My previous fix stripped trailing
    # slashes from every path and merged `/a` with `/a/`: distinct resources that
    # a relay may route to different stores. Fixing one bypass created another.
    assert key("wss://x/a") != key("wss://x/a/")
