"""Agreement events (31004) lacked the regular `delegation` tag.

This surfaced only when delegation became mandatory. Agreement events contain
`delegation_a` and `delegation_b`, the mandates of both parties, while the relay
requires a `delegation` tag for the event AUTHOR. The most important kind for
traceability therefore could not satisfy relay enforcement at all.

The second half of the finding was that `delegation_a` and `delegation_b` were assigned
positionally by PUBLISHER rather than by party. If agent_b published the agreement,
its mandate landed in `delegation_a`, so a reader validating a party's mandate would
validate the wrong one.
"""
import pytest

from a4a import crypto, types
from a4a.agent import Agent
from a4a.keys import Keys
from tests.fake_relay import FakeRelay


def _agreement(a: str, b: str, ka: Keys, kb: Keys) -> types.Agreement:
    digest = types.agreement_digest("i" * 64, "o" * 64, 100, "USD", 0, a, b)
    return types.Agreement(intent_id="i" * 64, offer_id="o" * 64, price=100,
                           currency="USD", deadline=0, agent_a=a, agent_b=b,
                           sig_a=crypto.sign(digest, ka.privkey_hex),
                           sig_b=crypto.sign(digest, kb.privkey_hex))


async def test_agreement_carries_the_publishers_delegation():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            await a.ensure_registered(Keys(), "A")
            await b.ensure_registered(Keys(), "B")
            ag = _agreement(a.pubkey, b.pubkey, a.keys, b.keys)
            ev_id = await a.publish_agreement(ag, delegation_b=b.delegation_id)
            [ev] = await a.relay.query({"ids": [ev_id]})
    assert ev.tag_value("delegation") == a.delegation_id, \
        "agreement lacks the author's mandate and an enforcing relay will reject it"


async def test_party_delegations_follow_the_party_not_the_publisher():
    """When B publishes instead of A, its mandate must remain in delegation_b."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            await a.ensure_registered(Keys(), "A")
            await b.ensure_registered(Keys(), "B")
            ag = _agreement(a.pubkey, b.pubkey, a.keys, b.keys)
            ev_id = await b.publish_agreement(ag, delegation_b=a.delegation_id)
            [ev] = await b.relay.query({"ids": [ev_id]})
    assert ev.tag_value("delegation_b") == b.delegation_id, \
        "the publisher's mandate was assigned to the wrong party"
    assert ev.tag_value("delegation_a") == a.delegation_id
    assert ev.tag_value("delegation") == b.delegation_id
