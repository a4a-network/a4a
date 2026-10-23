"""Agreement co-signing: what must not be signed and why.

An agreement is valid only with MUTUAL signatures. The `agent_a`/`agent_b` tags are
trivial to forge, but digest signatures are not. The second party therefore needs a
“sign the proposal” step that rejects every case where our signature would attest to
the wrong thing.
"""
import pytest
from a4a import types
from a4a.agent import Agent
from a4a.keys import Keys
from a4a.types import Agreement, agreement_digest

from tests.fake_relay import FakeRelay


def _proposed(proposer_keys, other_pubkey, price: int = 1000,
              sign: bool = True) -> Agreement:
    digest = agreement_digest("i" * 64, "o" * 64, price, "USD", 0,
                              proposer_keys.pubkey_hex, other_pubkey)
    sig = "" if not sign else __import__("a4a").crypto.sign(digest,
                                                            proposer_keys.privkey_hex)
    proposal = Agreement(intent_id="i" * 64, offer_id="o" * 64, price=price,
                     currency="USD", deadline=0,
                     agent_a=proposer_keys.pubkey_hex, agent_b=other_pubkey,
                     sig_a=sig, sig_b="")
    proposal.source = proposal.to_event("a" * 64, publisher=proposer_keys.pubkey_hex).sign(proposer_keys)
    return proposal


async def _publish_proposal(relay_client, proposer_keys, proposal) -> str:
    """Publish a proposal TO THE RELAY on behalf of the proposer.

    Without this, duplicate tests prove nothing: if the proposal is absent from the
    network, there is nothing to sign twice and every implementation appears correct.
    """
    ev = proposal.to_event()
    ev.sign(proposer_keys)
    await relay_client.publish(ev)
    return ev.id


async def test_cosign_completes_a_proposed_agreement():
    """After co-signing, the agreement validates both parties' signatures."""
    async with FakeRelay() as relay:
        proposer = Keys()
        async with Agent([relay.url]) as me:
            me.delegation_id = "b" * 64
            new_id = await me.co_sign_agreement(_proposed(proposer, me.pubkey))
            events = await me.relay.query({"ids": [new_id]})
            signed = types.Agreement.from_event(events[0])
            assert signed.verify_signatures()


async def test_cosign_refuses_agreement_we_are_not_party_to():
    """Signing a foreign agreement would attest to an irrelevant obligation."""
    async with FakeRelay() as relay:
        proposer, third = Keys(), Keys()
        async with Agent([relay.url]) as me:
            with pytest.raises(ValueError, match="does not include us"):
                await me.co_sign_agreement(_proposed(proposer, third.pubkey_hex))


async def test_cosign_refuses_when_our_signature_is_already_there():
    """Repeated signing would create another completed version of one agreement."""
    async with FakeRelay() as relay:
        proposer = Keys()
        async with Agent([relay.url]) as me:
            proposal = _proposed(proposer, me.pubkey)
            both = proposal.model_copy(update={"sig_b": me.sign_agreement(proposal)})
            with pytest.raises(ValueError, match="already present"):
                await me.co_sign_agreement(both)


async def test_cosign_refuses_when_the_other_side_has_not_signed():
    """There is nothing to co-sign when the other party has not signed the terms."""
    async with FakeRelay() as relay:
        proposer = Keys()
        async with Agent([relay.url]) as me:
            with pytest.raises(ValueError, match="no counterparty signature"):
                await me.co_sign_agreement(_proposed(proposer, me.pubkey, sign=False))


async def test_cosign_refuses_signature_that_does_not_match_the_terms():
    """Reject a counterparty signature copied from DIFFERENT terms.

    Signing it would attest to terms the counterparty never signed and produce an
    “agreement” whose second signature validates against nothing.
    """
    async with FakeRelay() as relay:
        proposer = Keys()
        async with Agent([relay.url]) as me:
            honest = _proposed(proposer, me.pubkey, price=1000)
            swapped = honest.model_copy(update={"price": 999_999})
            with pytest.raises(ValueError, match="does not match the agreement terms"):
                await me.co_sign_agreement(swapped)


async def test_cosign_is_idempotent_and_does_not_duplicate_the_deal():
    """A proposal cannot be co-signed twice.

    The original one-signature event remains on the relay. A repeated call could sign
    it again and create a SECOND completed agreement with the same digest, leaving
    parties with two IDs for one arrangement, tasks attached to one and reviews to
    the other. A retry must return the completed agreement instead of creating one.
    """
    async with FakeRelay() as relay:
        proposer = Keys()
        async with Agent([relay.url]) as me:
            me.delegation_id = "b" * 64
            proposal = _proposed(proposer, me.pubkey)
            await _publish_proposal(me.relay, proposer, proposal)

            first = await me.co_sign_agreement(proposal)
            second = await me.co_sign_agreement(proposal)
            assert first == second, "repeated co-signing created a second agreement"

            events = await me.relay.query({"kinds": [types.KIND_AGREEMENT]})
            signed = [e for e in events
                      if types.Agreement.from_event(e).verify_signatures()]
            assert len(signed) == 1, "the network contains multiple completed agreements"


async def test_get_agreements_shows_one_entry_per_deal():
    """One arrangement produces one result row.

    After co-signing, the network contains TWO events: a one-signature proposal and a
    two-signature agreement. Returning both asks the owner which is real and invites
    another co-sign attempt. Agreement identity is the terms digest, not the event ID.
    """
    async with FakeRelay() as relay:
        proposer = Keys()
        async with Agent([relay.url]) as me:
            me.delegation_id = "b" * 64
            proposal = _proposed(proposer, me.pubkey)
            await _publish_proposal(me.relay, proposer, proposal)
            await me.co_sign_agreement(proposal)

            raw = await me.relay.query({"kinds": [types.KIND_AGREEMENT]})
            assert len(raw) == 2, "both events must remain on the network"

            deals = await me.get_agreements()
            assert len(deals) == 1, "one agreement was returned twice"
            assert deals[0].verify_signatures(), "the unsigned version was returned"
