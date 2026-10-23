"""A large gift-wrap inbox is read whole, page by page (27.09.2026).

The representative's outbox recheck across two nodes stopped at 2500 events per node (the
5000 budget split in two) and returned the newest part only: acknowledgements, whose
envelopes are backdated up to two days, fell out, and 55 letters looked unacknowledged."""
from a4a import relay as relay_mod
from a4a.agent import Agent
from tests.fake_relay import FakeRelay


async def test_unwrap_inbox_reads_past_the_per_query_budget(monkeypatch):
    monkeypatch.setattr(relay_mod, "MAX_EVENTS_PER_QUERY", 5)
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            for i in range(12):
                await alice.send_private_message(bob.pubkey, f"letter {i}", wrap=True)
            inners = await bob._unwrap_inbox(since=0)
    assert sorted(e.content for e in inners if e.pubkey == alice.pubkey) != []
    assert len({e.id for e in inners}) == 12


async def test_a_node_that_caps_limit_below_the_budget_is_still_read_whole(monkeypatch):
    """A node may answer fewer events than `limit` asked and send EOSE: a short page is not
    proof that nothing older exists, so reading stops only on a page with nothing new."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            for i in range(9):
                await alice.send_private_message(bob.pubkey, f"letter {i}", wrap=True)
            real = relay._matching
            def capped(filters):
                return real([dict(f, limit=min(f.get("limit", 4), 4)) for f in filters])
            monkeypatch.setattr(relay, "_matching", capped)
            inners = await bob._unwrap_inbox(since=0)
    assert len({e.id for e in inners}) == 9
