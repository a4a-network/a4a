"""Cross-reader regressions discovered during the final protocol audit."""
from unittest.mock import AsyncMock

import pytest

from a4a import crypto, delegation, types
from a4a.agent import Agent
from a4a.event import Event
from a4a.keys import Keys


@pytest.mark.parametrize("expirations", [
    ["2000", "900"], ["900", "2000"], ["2000", "+2000"], ["2000", ""],
])
def test_every_mandate_expiration_constrains_authority(expirations):
    owner, sender = Keys(), Keys()
    mandate = delegation.create_delegation(owner, sender.pubkey_hex, "fixture", 2000, created_at=100)
    mandate.tags = [tag for tag in mandate.tags if tag[0] != "expiration"]
    mandate.tags += [["expiration", value] for value in expirations]
    mandate.sign(owner)
    assert not delegation.validate_sender_mandate(sender.pubkey_hex, mandate, now=1000)


def test_multiple_valid_future_expirations_remain_accepted():
    owner, sender = Keys(), Keys()
    mandate = delegation.create_delegation(owner, sender.pubkey_hex, "fixture", 2000, created_at=100)
    mandate.tags.append(["expiration", "3000"])
    mandate.sign(owner)
    assert delegation.validate_sender_mandate(sender.pubkey_hex, mandate, now=1000)


@pytest.mark.parametrize("coordinate", ["omitted", "correct", "hint", "uppercase", "bare", "wrong-kind", "conflicting"])
def test_optional_revocation_coordinates_must_agree(coordinate):
    owner, sender = Keys(), Keys()
    mandate = delegation.create_delegation(owner, sender.pubkey_hex, "fixture", 2000, created_at=100)
    correct = f"31000:{owner.pubkey_hex}:{sender.pubkey_hex}"
    wrong = f"31001:{owner.pubkey_hex}:{sender.pubkey_hex}"
    tags = [["d", sender.pubkey_hex]]
    if coordinate != "omitted":
        tags.append(["a", wrong if coordinate == "wrong-kind" else correct])
    if coordinate == "conflicting":
        tags.append(["a", wrong])
    if coordinate == "hint":
        tags[-1].append("wss://relay.example.com")
    if coordinate == "uppercase":
        tags[-1][1] = correct.upper()
    if coordinate == "bare":
        tags[-1] = ["a"]
    revocation = Event(kind=types.KIND_DELEGATION_REVOCATION, tags=tags, created_at=200).sign(owner)
    assert delegation.is_revocation_valid(revocation, mandate) == (coordinate in {"omitted", "correct", "hint", "uppercase"})


@pytest.mark.parametrize("receiver_is_a", [False, True])
async def test_default_cosign_preserves_counterparty_mandate(receiver_is_a):
    proposer, receiver = Keys(), Keys()
    me = Agent(["wss://unused.example.com"], keys=receiver)
    me.delegation_id = "b" * 64
    proposal = types.Agreement(
        intent_id="1" * 64, offer_id="2" * 64, price=1, deadline=2000,
        agent_a=receiver.pubkey_hex if receiver_is_a else proposer.pubkey_hex,
        agent_b=proposer.pubkey_hex if receiver_is_a else receiver.pubkey_hex,
        sig_a="", sig_b="")
    setattr(proposal, "sig_b" if receiver_is_a else "sig_a", crypto.sign(proposal.digest(), proposer.privkey_hex))
    source = proposal.to_event("a" * 64, "b" * 64, publisher=proposer.pubkey_hex).sign(proposer)
    me._agreements_of = AsyncMock(return_value=[])
    me._broadcast = AsyncMock()
    await me.co_sign_agreement(types.Agreement.from_event(source))
    published = me._broadcast.await_args.args[0]
    assert published.tag_value("delegation_a") == ("b" if receiver_is_a else "a") * 64
    assert published.tag_value("delegation_b") == ("a" if receiver_is_a else "b") * 64
    assert types.Agreement.from_event(published).verify_signatures()


async def test_registration_renews_the_earliest_mandate_expiration(monkeypatch):
    owner, sender = Keys(), Keys()
    mandate = delegation.create_delegation(owner, sender.pubkey_hex, "fixture", 200000, created_at=100)
    mandate.tags.append(["expiration", "900"])
    mandate.sign(owner)
    me = Agent(["wss://unused.example.com"], keys=sender)
    me.relay.query = AsyncMock(side_effect=[[mandate], []])
    me.register = AsyncMock(return_value="fresh-mandate")
    monkeypatch.setattr("a4a.agent.time.time", lambda: 1000)
    assert await me.ensure_registered(owner, name="fixture", renew_before_days=0) == "fresh-mandate"


async def test_cosign_does_not_infer_authority_from_altered_source():
    proposer, receiver = Keys(), Keys()
    proposal = types.Agreement(intent_id="1" * 64, offer_id="2" * 64, price=1,
        deadline=2000, agent_a=proposer.pubkey_hex, agent_b=receiver.pubkey_hex,
        sig_a="", sig_b="")
    proposal.sig_a = crypto.sign(proposal.digest(), proposer.privkey_hex)
    source = proposal.to_event("a" * 64, publisher=proposer.pubkey_hex).sign(proposer)
    source.tags.append(["delegation_a", "c" * 64])
    assert not source.verify()
    me = Agent(["wss://unused.example.com"], keys=receiver)
    me.delegation_id = "b" * 64
    me._agreements_of = AsyncMock(return_value=[])
    me._broadcast = AsyncMock()
    with pytest.raises(ValueError, match="counterparty delegation is required"):
        await me.co_sign_agreement(types.Agreement.from_event(source))
    me._broadcast.assert_not_awaited()


@pytest.mark.parametrize("missing", ["publisher", "counterparty"])
async def test_cosign_requires_both_party_mandates(missing):
    proposer, receiver = Keys(), Keys()
    me = Agent(["wss://unused.example.com"], keys=receiver)
    me.delegation_id = None if missing == "publisher" else "b" * 64
    proposal = types.Agreement(intent_id="1" * 64, offer_id="2" * 64, price=1,
        deadline=2000, agent_a=proposer.pubkey_hex, agent_b=receiver.pubkey_hex,
        sig_a="", sig_b="")
    proposal.sig_a = crypto.sign(proposal.digest(), proposer.privkey_hex)
    me._agreements_of = AsyncMock(return_value=[])
    me._broadcast = AsyncMock()
    with pytest.raises(ValueError, match=missing + " delegation is required"):
        await me.co_sign_agreement(proposal, None if missing == "counterparty" else "a" * 64)
    me._broadcast.assert_not_awaited()


def test_identity_readers_use_the_same_earliest_expiration():
    from a4a.identity import verify_identity_attestation
    issuer, subject = Keys(), Keys()
    event = types.IdentityAttestation(subject=subject.pubkey_hex, level="person:bank", expiration=2000).to_event()
    event.tags.append(["expiration", "900"])
    event.sign(issuer)
    assert types.IdentityAttestation.from_event(event).expiration == 900
    assert not verify_identity_attestation(event, subject.pubkey_hex, now=1000)
