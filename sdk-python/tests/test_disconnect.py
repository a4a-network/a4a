"""Connections could not be revoked (internal audit, 2026-08-29).

Reciprocal requests (A→B and B→A) mean "connected," which project-agent policy treats
as UNCONDITIONAL access to the owner, stronger than attestations or reputation. Yet
there was no way to withdraw consent: no method existed, and the only technical route
(deleting one's own request with a NIP-09 event) was neither exposed nor documented.

A counterparty later found to be malicious therefore remained trusted forever.
"""
from a4a.agent import Agent
from tests.fake_relay import FakeRelay


async def test_disconnect_breaks_a_mutual_connection():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            await a.request_connection(b.pubkey, "let's work together")
            await b.accept_connection(a.pubkey)
            assert await a.is_connected(b.pubkey) is True

            await a.disconnect(b.pubkey)
            assert await a.is_connected(b.pubkey) is False, "connection survived revocation"


async def test_disconnect_does_not_touch_other_connections():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b, \
                Agent([relay.url]) as c:
            for peer in (b, c):
                await a.request_connection(peer.pubkey)
                await peer.accept_connection(a.pubkey)
            await a.disconnect(b.pubkey)
            assert await a.is_connected(b.pubkey) is False
            assert await a.is_connected(c.pubkey) is True, "an unrelated connection was removed"


async def test_reconnecting_after_disconnect_works():
    """Disconnect is not a lifetime ban; either party may reconsider."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            await a.request_connection(b.pubkey)
            await b.accept_connection(a.pubkey)
            await a.disconnect(b.pubkey)
            await a.request_connection(b.pubkey, "reconsidered")
            assert await a.is_connected(b.pubkey) is True


async def test_fake_relay_does_not_let_a_stranger_delete_someone_elses_event():
    """Pin the fake relay's behavior rather than the SDK's.

    FakeRelay implements NIP-09 deletion for these tests. If it allowed a stranger to
    hide ANOTHER AUTHOR'S events, future deletion tests would pass for the wrong reason
    while the divergence from a real relay remained undetected.
    """
    from a4a.event import Event
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as victim, Agent([relay.url]) as attacker:
            request_id = await victim.request_connection(attacker.pubkey, "hello")
            deletion = Event(kind=5, tags=[["e", request_id]], content="delete peer event")
            deletion.sign(attacker.keys)
            await attacker.relay.publish(deletion)
            still = await attacker.relay.query({"ids": [request_id]})
            assert still, "the fake allowed a stranger to hide another author's event"
