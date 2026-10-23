"""Delegation revocation (kind 31007): creation, validation, and P4 enforcement."""
import time

from a4a import types
from a4a.agent import Agent
from a4a.delegation import (create_delegation, create_revocation,
                            is_revocation_valid, validate_delegation)
from a4a.event import Event
from a4a.keys import Keys
from tests.fake_relay import FakeRelay

NOW = int(time.time())


def _deleg(user, agent):
    return create_delegation(user, agent.pubkey_hex, "agent", NOW + 86400)


def _agent_event(agent, deleg):
    return Event(kind=types.KIND_INTENT,
                 tags=[["delegation", deleg.id], ["d", "x"]],
                 content="c").sign(agent)


# --- revocation structure and validity -----------------------------------------

def test_create_revocation_structure():
    user, agent = Keys(), Keys()
    deleg = _deleg(user, agent)
    rev = create_revocation(user, deleg, reason="key compromised")
    assert rev.kind == types.KIND_DELEGATION_REVOCATION
    assert rev.pubkey == user.pubkey_hex           # signed by the owner
    # The addressable coordinate is the AGENT, not one delegation copy. Reissuance
    # changes the event ID, so an ID-bound revocation did not cover the old signed
    # copy (internal audit F6, 2026-08-29).
    assert rev.tag_value("d") == agent.pubkey_hex
    assert rev.tag_value("a") == f"{types.KIND_DELEGATION}:{user.pubkey_hex}:{agent.pubkey_hex}"
    assert rev.tag_value("e") == deleg.id          # informational; not used for validation
    assert rev.tag_value("delegate") == agent.pubkey_hex
    assert rev.tag_value("reason") == "key compromised"
    assert is_revocation_valid(rev, deleg)


def test_revocation_by_non_owner_is_invalid():
    user, agent, stranger = Keys(), Keys(), Keys()
    deleg = _deleg(user, agent)
    # An outsider attempts to revoke another owner's delegation.
    rev = create_revocation(stranger, deleg)
    assert not is_revocation_valid(rev, deleg)


def test_revocation_for_other_delegation_is_invalid():
    user, agent = Keys(), Keys()
    deleg = _deleg(user, agent)
    other = create_delegation(user, Keys().pubkey_hex, "other", NOW + 86400)
    rev = create_revocation(user, other)           # revokes a DIFFERENT delegation
    assert not is_revocation_valid(rev, deleg)


# --- validate_delegation with revocation ---------------------------------------

def test_valid_delegation_becomes_invalid_when_revoked():
    user, agent = Keys(), Keys()
    deleg = _deleg(user, agent)
    ev = _agent_event(agent, deleg)
    assert validate_delegation(ev, deleg) is True                 # valid without revocation
    rev = create_revocation(user, deleg)
    assert validate_delegation(ev, deleg, revocation=rev) is False  # revoked


def test_bogus_revocation_does_not_invalidate():
    user, agent, stranger = Keys(), Keys(), Keys()
    deleg = _deleg(user, agent)
    ev = _agent_event(agent, deleg)
    fake_rev = create_revocation(stranger, deleg)                 # not signed by owner
    assert validate_delegation(ev, deleg, revocation=fake_rev) is True


# --- integration: revoke_delegation + validate_delegation over relay -----------

async def test_revoke_delegation_enforced_over_relay():
    user, agent_keys = Keys(), Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys=agent_keys) as agent, \
                Agent([relay.url]) as validator:
            deleg = _deleg(user, agent_keys)
            await agent.relay.publish(deleg)
            ev = _agent_event(agent_keys, deleg)
            await agent.relay.publish(ev)

            assert await validator.validate_delegation(ev) is True

            await agent.revoke_delegation(user, deleg, reason="rotation")
            assert await validator.validate_delegation(ev) is False


class _MaliciousRelayView:
    """Relay that does NOT filter revocations and puts a decoy first.

    This models the exact finding: server-side filtering is untrusted, while an
    honest FakeRelay would discard the decoy itself and make the test vacuous.
    """

    def __init__(self, inner, decoy_first: list):
        self.inner = inner
        self._decoy = decoy_first

    async def query(self, filters):
        found = await self.inner.query(filters)
        if types.KIND_DELEGATION_REVOCATION in filters.get("kinds", []):
            return self._decoy + found
        return found

    def __getattr__(self, name):
        return getattr(self.inner, name)


async def test_decoy_revocation_does_not_hide_the_real_one():
    """F5: an untrusted relay may put an unrelated owner revocation first.

    Previously the client selected the first item before verifying its link to the
    delegation. The real revocation was never considered, and the revoked agent
    could continue publishing.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as agent:
            owner = Keys()
            deleg_id = await agent.register(owner, name="agent", days=30)
            [deleg] = await agent.relay.query({"ids": [deleg_id]})
            other_deleg = create_delegation(owner, "ab" * 32, "other",
                                            int(time.time()) + 30 * 86400)
            decoy = create_revocation(owner, other_deleg)   # revokes another delegation
            await agent.relay.publish(create_revocation(owner, deleg))  # genuine revocation

            agent.relay = _MaliciousRelayView(agent.relay, [decoy])
            ev = types.Intent(intent_type="service_request", category="design",
                              need="x", budget_min=0, budget_max=1,
                              deadline=0).to_event(agent.delegation_id)
            ev.sign(agent.keys)
            assert await agent.validate_delegation(ev) is False, \
                "revoked delegation was treated as active"


async def test_three_element_delegation_tag_is_not_a_delegation():
    """Parser mismatch: relay accepts ONLY a two-element `["delegation", id]` tag.

    The SDK used to read tag[1] from any delegation tag of length >= 2. For an event
    containing `["delegation", id, "garbage"]`, the relay saw no delegation and did
    no validation, while the client saw one and checked its chain. The two sides
    disagreed about what was enforced, so the relay verdict no longer described what
    clients observed.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as agent:
            owner = Keys()
            deleg_id = await agent.register(owner, name="agent", days=30)
            ev = types.Intent(intent_type="service_request", category="design",
                              need="x", budget_min=0, budget_max=1,
                              deadline=0).to_event(deleg_id)
            ev.tags = [t for t in ev.tags if t[0] != "delegation"]
            ev.tags.append(["delegation", deleg_id, "garbage"])
            ev.sign(agent.keys)
            assert await agent.validate_delegation(ev) is False, \
                "three-element tag was accepted as delegation although relay ignores it"
