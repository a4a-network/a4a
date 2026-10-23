"""A signed event is invalid if any numeric tag has noncanonical syntax."""
import pytest

from a4a import crypto, types
from a4a.agent import _safe_from_event
from a4a.delegation import create_delegation, validate_sender_mandate
from a4a.event import Event, parse_decimal
from a4a.keys import Keys
from a4a.relay import RelayClient
from a4a.agent import Agent
from a4a.identity import verify_identity_attestation
from a4a.inbox import InboxStore
from a4a import nip44
from a4a.reputation import build_trust_graph, compute_reputation


def intent():
    return types.Intent(intent_type="service_request", category="other", need="fixture",
                        budget_min=0, budget_max=10, deadline=2000000000).to_event()


@pytest.mark.parametrize("name", ["price", "deadline", "budget_min", "budget_max", "eta",
                                  "rating", "weight", "progress", "amount", "since", "expiration"])
@pytest.mark.parametrize("raw", ["+10", "01", " 10", "1e1"])
def test_all_numeric_values_invalidate_signed_native_event(name, raw):
    event = intent()
    event.tags.extend([[name, "10"], [name, raw]])
    event.sign(Keys())
    assert event.verify()  # Cryptographic validity does not establish protocol validity.
    assert RelayClient._parse_event(event.model_dump()) is None
    assert _safe_from_event(types.Intent, event) is None


@pytest.mark.parametrize("name", ["price", "deadline"])
def test_agreement_party_signatures_do_not_hide_invalid_second_tag(name):
    a, b = Keys(), Keys()
    agreement = types.Agreement(intent_id="a" * 64, offer_id="b" * 64, price=10,
        currency="USD", deadline=2000000000, agent_a=a.pubkey_hex, agent_b=b.pubkey_hex,
        sig_a="", sig_b="")
    agreement.sig_a = crypto.sign(agreement.digest(), a.privkey_hex)
    agreement.sig_b = crypto.sign(agreement.digest(), b.privkey_hex)
    event = agreement.to_event(publisher=b.pubkey_hex)
    event.tags.append([name, "+10"])
    event.sign(b)
    assert event.verify()
    assert _safe_from_event(types.Agreement, event) is None


def test_canonical_duplicate_values_and_decimal_weight_remain_accepted():
    event = intent()
    event.tags.extend([["deadline", "2000000001"], ["weight", "0.5"], [], ["e"]])
    event.sign(Keys())
    assert RelayClient._parse_event(event.model_dump()) is not None
    assert _safe_from_event(types.Intent, event) is not None


def test_unrelated_nostr_tags_are_not_reinterpreted_as_a4a_numbers():
    event = Event(kind=1, tags=[["rating", "excellent"], ["expiration"]]).sign(Keys())
    assert RelayClient._parse_event(event.model_dump()) is not None
    event.tags.append(["expiration", "+10"])
    event.sign(Keys())
    assert RelayClient._parse_event(event.model_dump()) is None


def test_direct_mandate_reader_rejects_noncanonical_unused_numeric_tag():
    owner, agent = Keys(), Keys()
    mandate = create_delegation(owner, agent.pubkey_hex, "fixture", 2000000000)
    assert validate_sender_mandate(agent.pubkey_hex, mandate, now=1000)
    mandate.tags.append(["price", "+10"])
    mandate.sign(owner)
    assert not validate_sender_mandate(agent.pubkey_hex, mandate, now=1000)


def test_direct_identity_reader_rejects_invalid_unused_numeric_tag():
    issuer, subject = Keys(), Keys()
    event = Event(kind=types.KIND_IDENTITY_ATTESTATION,
                  tags=[["p", subject.pubkey_hex], ["level", "account:email"]]).sign(issuer)
    assert verify_identity_attestation(event, subject.pubkey_hex)
    event.tags.append(["amount", "+10"])
    event.sign(issuer)
    assert not verify_identity_attestation(event, subject.pubkey_hex)


def test_pure_reputation_readers_validate_all_numeric_occurrences():
    issuer, subject = Keys(), Keys()
    review = Event(kind=types.KIND_REVIEW, tags=[["p", subject.pubkey_hex],
                   ["agreement", "a" * 64], ["rating", "5"]]).sign(issuer)
    assertion = Event(kind=types.KIND_TRUST_ASSERTION,
                      tags=[["trust", subject.pubkey_hex], ["weight", "0.5"]]).sign(issuer)
    assert compute_reputation([review]).total_reviews == 1
    assert build_trust_graph([assertion])
    for event in (review, assertion):
        event.tags.append(["amount", "+10"])
        event.sign(issuer)
    assert compute_reputation([review]).total_reviews == 0
    assert build_trust_graph([assertion]) == {}


def test_private_decoder_and_durable_page_reject_numeric_poison(tmp_path):
    sender, recipient = Keys(), Keys()
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    event = Event(kind=types.KIND_PRIVATE_MESSAGE, created_at=200000,
                  tags=[["p", recipient.pubkey_hex], ["d", "numeric-poison"]],
                  content=nip44.encrypt("fixture", sender.privkey_hex, recipient.pubkey_hex)).sign(sender)
    assert agent._decode_incoming(event) is not None
    event.tags.append(["amount", "+10"])
    event.sign(sender)
    assert event.verify()
    assert agent._decode_incoming(event) is None
    with InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "fixture") as store:
        store.bind_relay(agent.relay.url, 0)
        assert store.accept_page(agent, agent.relay.url, (0, ""), [(200000, event)],
                                 {sender.pubkey_hex}, now=200001) == ["ignored"]
        assert store.cursor(agent.relay.url) == (200000, event.id)
        assert store.status(now=200001)["pending"] == 0


def test_normative_decimal_grammar_accepts_long_canonical_fraction():
    raw = "0.5" + "0" * 25
    assert parse_decimal(raw) == 0.5
    event = intent()
    event.tags.append(["weight", raw])
    event.sign(Keys())
    assert event.verify_protocol()
    assert RelayClient._parse_event(event.model_dump()) is not None
    assert _safe_from_event(types.Intent, event) is not None


def test_protocol_verification_returns_false_on_mutated_tag_type():
    event = intent().sign(Keys())
    event.tags = [["amount", 10]]
    assert event.verify_protocol() is False


@pytest.mark.asyncio
async def test_historical_authority_refuses_numeric_poison_before_lookup(monkeypatch):
    owner, agent_keys = Keys(), Keys()
    mandate = create_delegation(owner, agent_keys.pubkey_hex, "fixture", 2000000000)
    event = Event(kind=types.KIND_AGREEMENT, tags=[["delegation", mandate.id],
                  ["amount", "+10"]]).sign(agent_keys)
    agent = Agent(["ws://127.0.0.1:1"], keys=agent_keys)
    async def forbidden(*args, **kwargs):
        raise AssertionError("invalid event must not initiate timestamp lookup")
    monkeypatch.setattr(agent, "get_stamp", forbidden)
    result = await agent.authority_at(event)
    assert result["state"] == "unauthorized"
    assert result["evidence"]["event_signature_valid"] is True


def test_evidence_readers_reject_signed_numeric_poison():
    from a4a import evidence, identity_evidence
    event = Event(kind=types.KIND_REVIEW, created_at=100,
                  tags=[["rating", "5"], ["amount", "+10"]]).sign(Keys())
    assert event.verify()
    assert evidence._verified(event, event.kind) is False
    assert identity_evidence._verified(event, now=101) is False
