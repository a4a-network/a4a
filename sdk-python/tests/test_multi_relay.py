"""Publish to every configured relay rather than only the first.

Before 2026-09-04, `Agent([r1, r2])` wrote only to r1 under the original MVP rule,
while NIP-65 and the specification advertised relay lists and only reviews used them.
A counterparty listening to r2 from our own announcement saw no intents, agreements,
or mandate. Reads originally remained first-relay-only; later tests below document
and protect the intentional removal of that limitation.
"""
import contextlib
import logging

from a4a import Agent, Intent, Keys
from a4a.delegation import create_delegation
from tests.fake_relay import FakeRelay

DEAD = "ws://127.0.0.1:1/never"


def _intent() -> Intent:
    return Intent(intent_type="service_request", category="development", need="x",
                  budget_min=1, budget_max=2, deadline=10 ** 9, content="multi-relay")


async def test_publish_register_and_revoke_reach_every_own_relay():
    owner = Keys()
    async with FakeRelay() as r1, FakeRelay() as r2:
        async with Agent([r1.url, r2.url]) as agent:
            deleg_id = await agent.ensure_registered(owner, "bot")
            intent_id = await agent.publish_intent(_intent())
            deleg = next(e for e in await agent.relay.query({"ids": [deleg_id]}))
            rev_id = await agent.revoke_delegation(owner, deleg)
        for relay in (r1, r2):
            ids = {e["id"] for e in relay.events}
            assert {deleg_id, intent_id, rev_id} <= ids, "second relay must receive every event"


async def test_dead_secondary_relay_is_reported_not_fatal(caplog):
    # Preserve the guarantee that an unavailable relay is named in logs rather than
    # swallowed. Transport (`a4a.relay`) now emits the record because fan-out moved
    # there, eliminating the second `_broadcast` pass that republished the event.
    async with FakeRelay() as r1:
        with caplog.at_level(logging.WARNING, logger="a4a"):
            async with Agent([r1.url, DEAD]) as agent:
                intent_id = await agent.publish_intent(_intent())
        assert intent_id in {e["id"] for e in r1.events}, "live relay accepted the event"
    assert any(DEAD in r.getMessage() for r in caplog.records), \
        "unreachable relay was not named in logs"


async def test_dead_relay_is_survived_while_another_lives():
    """Survive a dead relay even when it is listed first.

    Before 2026-09-08, failure of the FIRST relay was fatal because reads used only
    that endpoint. Reads now fan out and the first relay has no privilege. Redundancy
    that depends on WHICH node dies is not redundancy; address order must not decide
    whether the agent survives.
    """
    async with FakeRelay() as r2:
        async with Agent([DEAD, r2.url]) as agent:
            await agent.ensure_registered(Keys(), "bot")
            published = await agent.publish_intent(_intent())
        async with Agent([r2.url]) as reader:
            found = await reader.search_intents(category="development")
    assert any(i.source.id == published for i in found), "live relay accepted the event"


async def test_all_relays_dead_is_still_fatal():
    """The converse remains true: failure of ALL relays is a loud error."""
    import pytest
    from a4a.relay import RelayError
    with pytest.raises(RelayError):
        async with Agent([DEAD, "ws://127.0.0.1:2/never"]) as agent:
            await agent.publish_intent(_intent())


async def test_reads_merge_across_all_relays():
    """Readers must see an event stored ONLY on the second relay.

    The former limitation read from the first relay without merging. Redundancy was
    written but never used: a sender stored an envelope on several advertised relays,
    while the recipient watched one and lost undelivered messages if it failed.
    """
    async with FakeRelay() as r1, FakeRelay() as r2:
        async with Agent([r2.url]) as writer:
            await writer.ensure_registered(Keys(), "bot")
            only_on_r2 = await writer.publish_intent(_intent())
        async with Agent([r1.url, r2.url]) as reader:
            found = await reader.search_intents(category="development")
    assert any(i.source.id == only_on_r2 for i in found)


async def test_refused_subscription_is_raised_not_reported_as_end_of_stream():
    """Surface subscription refusal instead of presenting it as end-of-stream.

    Review finding FAN-003: fan-in caught a subscription exception and simply ended
    the stream. Readers saw zero events when a relay answered `CLOSED: blocked: ...`.
    This failure is indistinguishable from an empty inbox and lets an agent calmly
    report that no mail exists.
    """
    import pytest
    from a4a.relay import RelayError
    reason = "blocked: synthetic control"
    async with FakeRelay(closed_reason=reason) as r1, FakeRelay(closed_reason=reason) as r2:
        for urls in ([r1.url], [r1.url, r2.url]):        # Single relay and fan-out.
            async with Agent(urls) as agent:
                with pytest.raises(RelayError) as info:
                    async for _ in agent.relay.subscribe({"kinds": [1]}):
                        break
            assert info.value.reason == reason, "relay reason was not preserved verbatim"


async def test_relay_list_is_bounded():
    """Bound relay count because aggregate parsing budget grows with the list.

    Review finding FAN-007: `max_events` bounds raw-event processing PER relay. Without
    a relay-count ceiling, an attacker bypasses that defense by extending the list.
    """
    import pytest
    from a4a.relay import FanOutRelayClient
    too_many = [f"ws://127.0.0.1:{9000 + i}" for i in range(FanOutRelayClient.MAX_RELAYS + 1)]
    with pytest.raises(ValueError, match="at most .* nodes"):
        FanOutRelayClient(too_many)


async def test_merge_buffer_is_bounded_like_a_single_client():
    """Bound the merge buffer exactly like a single client.

    Review finding FAN-002: the merge queue was unbounded, allowing a slow consumer
    to accumulate events indefinitely. Of 25,001 produced, one was delivered and the
    rest remained in memory. A single client evicts the oldest under the same load.
    """
    import asyncio
    from a4a import relay as relay_module
    from a4a.relay import RelayClient

    built = []
    original = asyncio.Queue

    class Watched(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            built.append(self.maxsize)

    async with FakeRelay() as r1, FakeRelay() as r2:
        relay_module.asyncio.Queue = Watched
        try:
            async with Agent([r1.url, r2.url]) as agent:
                stream = agent.relay.subscribe({"kinds": [1]})
                # Advance until the queue exists but before events arrive. There is
                # no first message to wait for here.
                with contextlib.suppress(asyncio.TimeoutError):
                    async with asyncio.timeout(0.5):
                        await anext(stream)
                await stream.aclose()
        finally:
            relay_module.asyncio.Queue = original

    # Define failure precisely. Merely finding a queue with the expected limit is
    # useless because the single client already creates bounded queues, so that test
    # would pass with an unbounded merge. ZERO must fail: maxsize=0 means unbounded,
    # and no other transport queue uses it.
    assert built, "observer saw no queues, so the test proved nothing"
    assert 0 not in built, f"unbounded queue was created; sizes: {built}"
    assert RelayClient.MAX_QUEUED_EVENTS in built, "client queue limit is no longer active"


def test_finished_marker_survives_a_flood_and_never_waits_for_room():
    """Completion sentinels survive floods and never wait for queue space.

    Two review findings both caused permanent hangs:

    FAN-008: indiscriminate oldest-item eviction removed the completion sentinel for
    a finished source. Both sources ended while the consumer waited for a second
    sentinel that no longer existed.

    FAN-009: waiting for sentinel space blocked on a full queue that nobody consumed,
    leaving stream closure hanging until timeout.

    Failure is defined before execution: a sentinel disappears from the queue or the
    call fails to return.
    """
    import asyncio
    from a4a.relay import _offer_keeping_sentinel

    done = object()
    queue: asyncio.Queue = asyncio.Queue(maxsize=4)
    _offer_keeping_sentinel(queue, done, done)          # Source A finishes first.
    for n in range(200):                                # Source B floods the queue.
        _offer_keeping_sentinel(queue, f"event-{n}", done)
    _offer_keeping_sentinel(queue, done, done)          # Source B finishes while full.

    drained = []
    while not queue.empty():
        drained.append(queue.get_nowait())
    assert drained.count(done) == 2, \
        f"completion sentinels were lost during flood: {drained}"
    assert len(drained) == 4, "queue limit was exceeded"
    assert any(isinstance(x, str) for x in drained), "events, not sentinels, should be evicted"


async def test_reused_mandate_reaches_newly_added_node_without_reissuing():
    """Joining a discovery node must preserve existing owner authorization.

    A real-node experiment found that the merged lookup reused the home-node
    mandate while the newly added node rejected profiles and public requests
    because it had never received that mandate.
    """
    owner, keys = Keys(), Keys()
    async with FakeRelay() as home, FakeRelay() as discovery:
        async with Agent([home.url], keys=keys) as agent:
            original_id = await agent.ensure_registered(owner, "bot")
        original = next(e for e in home.events if e["id"] == original_id)
        assert not discovery.events

        async with Agent([home.url, discovery.url], keys=keys) as agent:
            reused_id = await agent.ensure_registered(owner, "bot")
            intent_id = await agent.publish_intent(_intent())

        assert reused_id == original_id
        for node in (home, discovery):
            mandates = [e for e in node.events if e["kind"] == 31000]
            assert mandates and all(e == original for e in mandates)
            assert intent_id in {e["id"] for e in node.events}


