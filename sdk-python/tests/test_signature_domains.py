"""Agreement and event signatures use separate domains.

This addresses internal audit finding 6, fixed in v0.4 on 2026-09-04 without v1
compatibility. Two properties matter: (1) the agreement digest is a tagged hash using
`a4a/agreement/v2`, not a bare SHA-256 of the terms, and never equals an event ID;
(2) `Agent.sign_agreement` only signs a digest that it computes from the model and
never accepts "ready-made 32 bytes" supplied by a counterparty.
"""
import hashlib
import time

import pytest

from a4a import Agent, Keys, crypto, types
from a4a.event import Event
from a4a.types import AGREEMENT_DOMAIN, agreement_canonical, agreement_digest, tagged_hash

TERMS = dict(intent_id="i" * 64, offer_id="o" * 64, price=45000, currency="USD",
             deadline=1_800_000_000, agent_a="a" * 64, agent_b="b" * 64)


def test_digest_is_a_tagged_hash_not_plain_sha256():
    canon = agreement_canonical(**TERMS)
    digest = agreement_digest(**TERMS)
    assert digest == tagged_hash(AGREEMENT_DOMAIN, canon).hex()
    assert digest != hashlib.sha256(canon).hexdigest(), "bare SHA-256 is the v1 format"
    tag = hashlib.sha256(AGREEMENT_DOMAIN.encode()).digest()
    assert digest == hashlib.sha256(tag + tag + canon).hexdigest(), "BIP-340 tagged hash"


def test_deal_signature_does_not_verify_over_the_v1_digest_or_an_event_id():
    keys = Keys()
    agent = Agent(["ws://127.0.0.1:1/never"], keys)
    model = types.Agreement(sig_a="", sig_b="", **TERMS)
    sig = agent.sign_agreement(model)
    assert crypto.verify(model.digest(), sig, keys.pubkey_hex)
    v1 = hashlib.sha256(agreement_canonical(**TERMS)).hexdigest()
    assert not crypto.verify(v1, sig, keys.pubkey_hex), "a v2 signature is invalid as v1"
    # Even an event whose serialized content is the canonical agreement has a different
    # ID domain (SHA-256 of "[0,..."), so the agreement signature does not verify it.
    ev = Event(kind=1, tags=[], content=agreement_canonical(**TERMS).decode()).sign(keys)
    assert ev.id != model.digest()
    assert not crypto.verify(ev.id, sig, keys.pubkey_hex)


def test_sign_agreement_refuses_ready_made_bytes():
    agent = Agent(["ws://127.0.0.1:1/never"], Keys())
    with pytest.raises(TypeError, match="Agreement"):
        agent.sign_agreement("ab" * 32)          # "digest" supplied by a counterparty
    with pytest.raises(TypeError):
        agent.sign_agreement(Event(kind=1).sign(Keys()).id)


def test_both_parties_signing_the_model_yields_a_verifiable_deal():
    a, b = Keys(), Keys()
    terms = types.Agreement(sig_a="", sig_b="", **{**TERMS, "agent_a": a.pubkey_hex,
                                                    "agent_b": b.pubkey_hex})
    signed = terms.model_copy(update={
        "sig_a": Agent(["ws://127.0.0.1:1/never"], a).sign_agreement(terms),
        "sig_b": Agent(["ws://127.0.0.1:1/never"], b).sign_agreement(terms)})
    assert signed.verify_signatures()
    tampered = signed.model_copy(update={"price": 45001})
    assert not tampered.verify_signatures()


def test_domain_tag_is_the_documented_one():
    assert AGREEMENT_DOMAIN == "a4a/agreement/v2"
    assert hashlib.sha256(AGREEMENT_DOMAIN.encode()).hexdigest() == \
        "cfc45a3eeef537b1771e30c288716fa4250a0aa66f3472717059c7df77c90d3b"
