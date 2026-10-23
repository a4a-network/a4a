"""Delegation revocation (31007) is history: it neither carries nor obeys expiry.

Finding 79 (2026-09-04): a live production check applied NIP-40 `expiration` to every
event, including revocations. One hour later the revocation would disappear under
NIP-40 and the revoked delegation would "resurrect". Since then, relay ingress rejects
kind 31007 containing `expiration`. This file covers the other half: the SDK does not
emit such revocations, and treats an expiring revocation from a foreign relay as
invalid. Client and relay must share the same grammar, or a client could trust a
revocation the relay itself would reject.

This also guards the class: historical kinds (delegation, revocation, profile,
agreement, review, and trust) receive no default `expiration`. Reputation must not
vanish from a foreign relay after 30 days.
"""
import time

import pytest

from a4a import types
from a4a.agent import Agent
from a4a.delegation import (create_delegation, create_revocation, is_revocation_valid,
                            validate_delegation)
from a4a.event import Event
from a4a.keys import Keys
from tests.fake_relay import FakeRelay

NOW = int(time.time())


def _chain():
    owner, agent = Keys(), Keys()
    deleg = create_delegation(owner, agent.pubkey_hex, "bot", NOW + 3600)
    ev = Event(kind=types.KIND_INTENT, tags=[["delegation", deleg.id]]).sign(agent)
    return owner, agent, deleg, ev


# --- 1. SDK never emits an expiring revocation ---------------------------------

def test_create_revocation_carries_no_expiration():
    owner, _, deleg, _ = _chain()
    rev = create_revocation(owner, deleg, reason="compromise")
    assert rev.tag_value("expiration") is None
    assert [t[0] for t in rev.tags] == ["d", "a", "e", "delegate", "reason"]


async def test_revoke_delegation_publishes_revocation_without_expiration():
    owner, agent, deleg, _ = _chain()
    async with FakeRelay() as relay:
        async with Agent([relay.url], agent) as a:
            await a.revoke_delegation(owner, deleg)
        published = [e for e in relay.events if e["kind"] == types.KIND_DELEGATION_REVOCATION]
    assert len(published) == 1
    assert not any(t[0] == "expiration" for t in published[0]["tags"])


# --- 2. Expiring revocation is inert; permanent revocation works ---------------

def test_revocation_with_expiration_is_not_valid_and_does_not_revoke():
    owner, _, deleg, ev = _chain()
    good = create_revocation(owner, deleg)
    assert is_revocation_valid(good, deleg)
    assert not validate_delegation(ev, deleg, revocation=good), \
        "control: a permanent revocation must revoke"

    with_ttl = create_revocation(owner, deleg)
    with_ttl.tags.append(["expiration", str(NOW + 3600)])
    with_ttl.sign(owner)                       # signature is valid; only tag differs
    assert with_ttl.verify()
    assert not is_revocation_valid(with_ttl, deleg)
    assert validate_delegation(ev, deleg, revocation=with_ttl), \
        "an expiring revocation must be inert"


async def test_validate_delegation_ignores_expiring_revocation_from_relay():
    """A foreign relay may serve an expiring revocation; the client must reject it."""
    owner, agent, deleg, ev = _chain()
    with_ttl = create_revocation(owner, deleg)
    with_ttl.tags.append(["expiration", str(NOW + 3600)])
    with_ttl.sign(owner)
    async with FakeRelay() as relay:
        async with Agent([relay.url], Keys()) as reader:
            await reader.relay.publish(deleg)
            await reader.relay.publish(with_ttl)
            assert await reader.validate_delegation(ev), "expiring revocation must be inert"
            await reader.relay.publish(create_revocation(owner, deleg))
            assert not await reader.validate_delegation(ev), \
                "control: a genuine permanent revocation must apply"


# --- 3. Class guard: history receives no default expiry ------------------------

def _history_events():
    owner, agent = Keys(), Keys()
    deleg = create_delegation(owner, agent.pubkey_hex, "bot", NOW + 3600)
    yield "31007 delegation revocation", create_revocation(owner, deleg)
    yield "31001 profile", types.AgentProfile(capabilities=["x"], category="development").to_event()
    yield "31004 agreement", types.Agreement(
        intent_id="a" * 64, offer_id="b" * 64, price=1, deadline=NOW, agent_a="c" * 64,
        agent_b="d" * 64, sig_a="", sig_b="").to_event()
    yield "31005 agreement review", types.Review(agreement_id="a" * 64, target="c" * 64,
                                                rating=5).to_event()
    yield "31020 trust", types.TrustAssertion(trusted="c" * 64, weight=0.5).to_event()


@pytest.mark.parametrize("label, ev", list(_history_events()),
                         ids=[label for label, _ in _history_events()])
def test_history_kinds_carry_no_default_expiration(label, ev):
    assert ev.tag_value("expiration") is None, label


def test_delegation_expiration_is_its_own_term_not_a_ttl():
    """For kind 31000, `expiration` is a mandate term and must occur exactly once."""
    owner, agent = Keys(), Keys()
    deleg = create_delegation(owner, agent.pubkey_hex, "bot", NOW + 3600)
    assert deleg.tag_values("expiration") == [str(NOW + 3600)]
