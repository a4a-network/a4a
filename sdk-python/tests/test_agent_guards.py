"""`agent.py` validation and client-side filtering previously unproven by tests.

A 2026-08-29 mutation pass disabled each defensive branch and each relay-result
filter individually, then ran the complete suite. Eight mutants survived, meaning
eight defenses existed only on trust.

Half share one principle: **the relay is untrusted**. It may return more than requested,
either accidentally because it cannot filter multi-character tags or deliberately.
An honest test relay filters correctly and never exercises client-side filtering, so
the tests require a relay that behaves badly.
"""
import pytest
from a4a import types
from a4a.agent import Agent, _BoundedSeen
from a4a.keys import Keys
from a4a.relay import RelayError

from tests.fake_relay import FakeRelay


def test_bounded_seen_duplicate_replay_does_not_consume_capacity():
    """Repeated replay of one ID must not evict another ID from bounded deduplication."""
    seen = _BoundedSeen(cap=2)
    seen.add("legitimate-event")
    seen.add("replayed-event")

    for _ in range(10):
        seen.add("replayed-event")

    assert "legitimate-event" in seen, "replays prematurely evicted a unique ID"
    assert "replayed-event" in seen


def test_bounded_seen_evicts_oldest_distinct_id_on_overflow():
    """Positive control: a distinct ID beyond capacity evicts the oldest."""
    seen = _BoundedSeen(cap=2)
    seen.add("oldest-event")
    seen.add("middle-event")
    seen.add("newest-event")

    assert "oldest-event" not in seen
    assert "middle-event" in seen
    assert "newest-event" in seen


class _SloppyRelayView:
    """Return everything after discarding every tag filter."""

    def __init__(self, inner):
        self.inner = inner

    async def query(self, filters):
        stripped = {k: v for k, v in filters.items() if not k.startswith("#")}
        return await self.inner.query(stripped)

    def __getattr__(self, name):
        return getattr(self.inner, name)


class _MaliciousRelayView:
    """Honor only `kinds`; invent authors and tags freely.

    This is not test paranoia. A relay can physically return anything; the signature
    is the only fact known about an event. Validate results against signed fields,
    not against what the query requested.
    """

    def __init__(self, inner):
        self.inner = inner

    async def query(self, filters):
        return await self.inner.query({"kinds": filters.get("kinds", [])})

    def __getattr__(self, name):
        return getattr(self.inner, name)


class _RejectingRelayView:
    """Reject every query like strfry rejects an unindexed tag."""

    def __init__(self, inner):
        self.inner = inner
        self.calls = 0

    async def query(self, filters):
        self.calls += 1
        raise RelayError("unindexed tag filter")

    def __getattr__(self, name):
        return getattr(self.inner, name)


# --- Untrusted relay list --------------------------------------------------

async def test_resolve_relays_rejects_public_host_with_non_websocket_scheme():
    """A public host alone does not make a URL a relay.

    The recipient signs its relay list, but each address remains untrusted. Without
    explicit scheme validation, an external `https://` URL passed perimeter checks
    and entered the future outbound-connection list.
    """
    hostile = "https://relay.attacker.example/inbox"
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as owner, Agent([relay.url]) as reader:
            await owner.publish_relay_list([hostile])
            assert await reader.resolve_relays(owner.pubkey) == []


async def test_resolve_relays_accepts_public_websocket_scheme():
    """Positive control: preserve the same public address when it uses `wss`."""
    expected = "wss://relay.example/inbox"
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as owner, Agent([relay.url]) as reader:
            await owner.publish_relay_list([expected])
            assert await reader.resolve_relays(owner.pubkey) == [expected]


# --- Relay refusal with no safe fallback ----------------------------------

async def test_query_tolerant_reraises_when_nothing_to_strip():
    """Reraise when tolerant-query fallback has no multi-character tags to remove.

    Retrying the same query is pointless and returns the same refusal. Returning an
    empty result silently would look like an empty network when the network actually
    failed to answer.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as agent:
            view = _RejectingRelayView(agent.relay)
            agent.relay = view
            with pytest.raises(RelayError):
                await agent._query_tolerant({"kinds": [types.KIND_INTENT]})
            assert view.calls == 1, "identical refused query was retried unnecessarily"


# --- Client-side relay-result filtering -----------------------------------

async def test_search_intents_refilters_category_client_side():
    """Refilter categories when a relay cannot process our multi-character tag.

    Otherwise it returns intents from every category and offers the owner work they
    never requested.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as author, Agent([relay.url]) as reader:
            for cat, need in (("design", "landing page"), ("hardware", "soldering iron")):
                await author.publish_intent(types.Intent(
                    intent_type="service_request", category=cat, need=need,
                    budget_min=0, budget_max=10, deadline=0))
            reader.relay = _SloppyRelayView(reader.relay)
            found = await reader.search_intents(category="design")
            assert [i.need for i in found] == ["landing page"]


async def test_search_intents_filters_by_budget_ceiling():
    """Apply the budget ceiling client-side because relays know nothing about money."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as author, Agent([relay.url]) as reader:
            for lo, need in ((5, "affordable"), (100_000, "too expensive")):
                await author.publish_intent(types.Intent(
                    intent_type="service_request", category="design", need=need,
                    budget_min=lo, budget_max=lo + 10, deadline=0))
            found = await reader.search_intents(category="design", budget_max=10_000)
            assert [i.need for i in found] == ["affordable"]


async def test_get_offers_refilters_even_when_relay_ignores_e_tag():
    """Refilter offers even when a relay ignores the indexed `#e` tag.

    A stock relay supports this single-character tag and therefore cannot exercise
    the client defense. A relay may still return extra results, which must never reach
    the owner.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as seller, Agent([relay.url]) as buyer:
            await seller.publish_offer(types.Offer(intent_id="a" * 64, price=111, eta=1))
            await seller.publish_offer(types.Offer(intent_id="b" * 64, price=222, eta=1))
            buyer.relay = _SloppyRelayView(buyer.relay)
            offers = await buyer.get_offers("a" * 64)
            assert [o.price for o in offers] == [111]


async def test_disconnect_deletes_only_our_own_requests():
    """A disconnect deletion event (NIP-09) must target ONLY OUR requests to this peer.

    Exercise both filters: the relay returns another author's request and our request
    to another recipient. Signing deletion of someone else's event leaves misleading
    data under our name; deleting our request to a different recipient silently breaks
    the wrong connection.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as me, Agent([relay.url]) as stranger,                 Agent([relay.url]) as observer:
            peer, other_peer = Keys().pubkey_hex, Keys().pubkey_hex
            await me.request_connection(peer, "business matter")
            await me.request_connection(other_peer, "another matter")
            await stranger.request_connection(peer, "their matter")

            mine = await observer.relay.query(
                {"kinds": [types.KIND_CONNECTION_REQUEST], "authors": [me.pubkey],
                 "#p": [peer]})
            assert len(mine) == 1

            me.relay = _MaliciousRelayView(me.relay)
            assert await me.disconnect(peer) is not None

            deletions = await observer.relay.query({"kinds": [5], "authors": [me.pubkey]})
            targets = sorted({t[1] for e in deletions for t in e.tags if t[0] == "e"})
            assert targets == [mine[0].id], "deletion included an unrelated event"


# --- Arguments that must not be accepted silently -------------------------

async def test_send_private_message_rejects_empty_delivery_id():
    """`None` means generate an ID; an empty string is a caller error.

    Accepting it creates a message with an empty delivery ID that cannot be linked to
    an ACK or distinguished from a retry.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as agent:
            with pytest.raises(ValueError, match="delivery_id"):
                await agent.send_private_message(Keys().pubkey_hex, "text",
                                                 delivery_id="")


async def test_acknowledge_refuses_message_without_delivery_id():
    """Refuse acknowledgement when a message has no `d` delivery ID."""
    from a4a.event import Event
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as agent:
            ev = Event(kind=types.KIND_PRIVATE_MESSAGE, tags=[], content="")
            ev.sign(Keys())
            with pytest.raises(ValueError, match="no d tag"):
                await agent.acknowledge(ev)


async def test_deliver_with_ack_rejects_negative_retries():
    """Negative retries are invalid, not equivalent to zero retries.

    Silently making one attempt would return "not delivered" when the caller asked
    for persistence.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as agent:
            with pytest.raises(ValueError, match="retries"):
                await agent.deliver_with_ack(Keys().pubkey_hex, "text", retries=-1)
