"""Separate owner key and an agent mandate that survives restarts.

`register()` used to issue a delegation on every call, producing a new kind-31000
event and `delegation_id` at every agent start. Addressable replacement kept this
working superficially, but prevented deliberate expiry checks and renewal; the only
option was reissuance. Mandatory relay delegation could not be enabled under that
model because an agent started without the owner key would stop publishing entirely.
"""
import time

from a4a import types, delegation
from a4a.agent import Agent
from a4a.keys import Keys
from tests.fake_relay import FakeRelay


def _delegations(relay) -> list:
    return [e for e in relay.events if e["kind"] == types.KIND_DELEGATION]


async def test_delegation_survives_restart_and_is_not_reissued(monkeypatch):
    """Reuse exact signed bytes without invoking owner authorization again.

    Two `register` calls within one second produce byte-identical events with the
    same ID, so ID comparison alone cannot rule out reissuance. Refuse any call to
    the signing factory on restart; replaying the existing signature is allowed.
    """
    async with FakeRelay() as relay:
        owner, agent_keys = Keys(), Keys()
        async with Agent([relay.url], keys=agent_keys) as a:
            first = await a.ensure_registered(owner, name="agent")
        original = _delegations(relay)[0]
        def unexpected_issuance(*args, **kwargs):
            raise AssertionError("restart attempted to issue another owner mandate")
        monkeypatch.setattr(delegation, "create_delegation", unexpected_issuance)
        async with Agent([relay.url], keys=agent_keys) as a:
            second = await a.ensure_registered(owner, name="agent")
        assert first == second
        assert _delegations(relay) == [original], \
            "an existing exact mandate must be reused without redundant copying or re-signing"


async def test_expiring_delegation_is_renewed():
    """Mandates are intentionally short-lived as a second boundary after revocation.

    Renew them in advance or the agent will eventually stop publishing without warning.
    """
    async with FakeRelay() as relay:
        owner, agent_keys = Keys(), Keys()
        async with Agent([relay.url], keys=agent_keys) as a:
            await a.ensure_registered(owner, name="agent", days=10)
            assert len(_delegations(relay)) == 1
            await a.ensure_registered(owner, name="agent", days=400,
                                      renew_before_days=30)
        assert len(_delegations(relay)) == 2, "expiring mandate was not renewed"


async def test_expired_delegation_is_replaced():
    async with FakeRelay() as relay:
        owner, agent_keys = Keys(), Keys()
        async with Agent([relay.url], keys=agent_keys) as a:
            stale = types.Event if False else None  # noqa: F841 (readability)
            from a4a.delegation import create_delegation
            expired = create_delegation(owner, a.pubkey, "agent",
                                        int(time.time()) - 3600)
            await a.relay.publish(expired)
            fresh = await a.ensure_registered(owner, name="agent")
        assert fresh != expired.id, "expired mandate was treated as active"


async def test_delegation_of_another_owner_is_not_reused():
    """Lookup uses the coordinate from this owner to this agent.

    Another owner's mandate for the same agent cannot authorize us.
    """
    async with FakeRelay() as relay:
        owner, other, agent_keys = Keys(), Keys(), Keys()
        async with Agent([relay.url], keys=agent_keys) as a:
            from a4a.delegation import create_delegation
            foreign = create_delegation(other, a.pubkey, "foreign",
                                        int(time.time()) + 86400 * 365)
            await a.relay.publish(foreign)
            mine = await a.ensure_registered(owner, name="agent")
        assert mine != foreign.id, "another owner's mandate was reused"
