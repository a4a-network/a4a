"""F6: revocation used to target a delegation COPY rather than an agent.

Kind 31000 is addressable by `d`=<delegate pubkey>: when an owner reissues it, the new
delegation replaces the previous one and CHANGES the event ID. Revocation, however,
targeted one specific ID. An agent could retain the owner's signed OLD copy (it is
public), publish it to a relay that had not seen the new one, and reference its ID.
A revocation issued for the new delegation did not cover the old copy, so the chain
remained valid. Expiration did not help because the old copy had its own deadline.
"""
import time

from a4a import types
from a4a.delegation import (create_delegation, create_revocation,
                            is_revocation_valid, validate_delegation)
from a4a.keys import Keys


def _at(ev, ts, keys):
    """Re-sign an event at a given time because revocation ordering matters."""
    ev.created_at = ts
    return ev.sign(keys)


def _chain():
    """The owner issues a mandate, reissues it with a new ID, then revokes it."""
    owner, agent = Keys(), Keys()
    t0 = int(time.time())
    exp = t0 + 30 * 86400
    old = _at(create_delegation(owner, agent.pubkey_hex, "agent", exp), t0, owner)
    new = _at(create_delegation(owner, agent.pubkey_hex, "agent", exp), t0 + 1, owner)
    return owner, agent, old, new


def _agent_event(agent, deleg_id):
    ev = types.Intent(intent_type="service_request", category="design", need="x",
                      budget_min=0, budget_max=1, deadline=0).to_event(deleg_id)
    return ev.sign(agent)


def test_revocation_covers_every_copy_of_the_delegation():
    owner, agent, old, new = _chain()
    rev = _at(create_revocation(owner, new), new.created_at + 1, owner)
    ev = _agent_event(agent, old.id)
    assert validate_delegation(ev, old, revocation=rev) is False, \
        "the old signed copy survived revocation"
    assert validate_delegation(ev, new, revocation=rev) is False


def test_revocation_does_not_kill_a_later_delegation_to_the_same_agent():
    """A later mandate must work after an owner revokes and rehires the same agent.

    Otherwise revocation would become a lifetime ban.
    """
    owner, agent, old, _ = _chain()
    rev = _at(create_revocation(owner, old), old.created_at + 1, owner)
    later = _at(create_delegation(owner, agent.pubkey_hex, "agent rehired",
                                 int(time.time()) + 30 * 86400),
                rev.created_at + 1, owner)
    ev = _agent_event(agent, later.id)
    assert validate_delegation(ev, later, revocation=rev) is True


def test_revocation_of_another_agent_does_not_apply():
    owner, agent, old, _ = _chain()
    other = Keys()
    other_deleg = create_delegation(owner, other.pubkey_hex, "another agent",
                                    int(time.time()) + 30 * 86400)
    rev = _at(create_revocation(owner, other_deleg), old.created_at + 1, owner)
    assert is_revocation_valid(rev, old) is False
    ev = _agent_event(agent, old.id)
    assert validate_delegation(ev, old, revocation=rev) is True


def test_revocation_by_a_stranger_does_not_apply():
    _, agent, old, _ = _chain()
    stranger = Keys()
    rev = _at(create_revocation(stranger, old), old.created_at + 1, stranger)
    assert is_revocation_valid(rev, old) is False
