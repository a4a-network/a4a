"""Delegation revocation must follow an agent everywhere it has published.

A 2026-08-30 measurement across two relays showed immediate refusal on the first after
revocation, while the stolen key could publish INDEFINITELY on the second because the
revocation reached only the home relay. The README promises immediate revocation after
compromise, and NIP-65 explicitly assumes an agent may use several relays.

An open network cannot guarantee that every relay learns about a revocation. We must,
however, send it to every relay the agent itself advertised.
"""
import asyncio

from a4a import types
from a4a.agent import Agent
from a4a.event import Event
from a4a.keys import Keys

from tests.fake_relay import FakeRelay


async def test_revocation_reaches_the_agents_own_declared_relays():
    """Send revocation to a second relay advertised by the agent."""
    async with FakeRelay() as home, FakeRelay() as other:
        owner, agent_keys = Keys(), Keys()
        async with Agent([home.url], keys=agent_keys,
                         allow_internal_relays=True) as agent:
            await agent.ensure_registered(owner, "agent with two relays", days=1)
            # The agent advertises both relays through NIP-65.
            await agent.publish_relay_list([home.url, other.url])
            deleg = (await agent.relay.query(
                {"kinds": [types.KIND_DELEGATION],
                 "authors": [owner.pubkey_hex]}))[0]

            await agent.revoke_delegation(owner, deleg)

        async with Agent([other.url], allow_internal_relays=True) as observer:
            on_other = await observer.relay.query(
                {"kinds": [types.KIND_DELEGATION_REVOCATION],
                 "authors": [owner.pubkey_hex]})
    assert on_other, "revocation missed the second relay, leaving the key active there"


async def test_revocation_reaches_relays_named_by_the_owner():
    """Reach an owner-known relay absent from the agent list through `extra_relays`."""
    async with FakeRelay() as home, FakeRelay() as elsewhere:
        owner, agent_keys = Keys(), Keys()
        async with Agent([home.url], keys=agent_keys,
                         allow_internal_relays=True) as agent:
            await agent.ensure_registered(owner, "agent", days=1)
            deleg = (await agent.relay.query(
                {"kinds": [types.KIND_DELEGATION],
                 "authors": [owner.pubkey_hex]}))[0]
            await agent.revoke_delegation(owner, deleg,
                                          extra_relays=[elsewhere.url])

        async with Agent([elsewhere.url], allow_internal_relays=True) as observer:
            got = await observer.relay.query(
                {"kinds": [types.KIND_DELEGATION_REVOCATION],
                 "authors": [owner.pubkey_hex]})
    assert got, "revocation did not reach the owner-specified relay"


async def test_unreachable_relay_does_not_cancel_the_revocation():
    """An unreachable remote relay must not prevent revocation on the home relay.

    Otherwise the owner cannot revoke at all while one agent relay is down, precisely
    when revocation may be most urgent.
    """
    async with FakeRelay() as home:
        owner, agent_keys = Keys(), Keys()
        async with Agent([home.url], keys=agent_keys,
                         allow_internal_relays=True) as agent:
            await agent.ensure_registered(owner, "agent", days=1)
            deleg = (await agent.relay.query(
                {"kinds": [types.KIND_DELEGATION],
                 "authors": [owner.pubkey_hex]}))[0]

            rev_id = await agent.revoke_delegation(
                owner, deleg, extra_relays=["ws://127.0.0.1:9/unreachable"])
            on_home = await agent.relay.query({"ids": [rev_id]})
    assert on_home, "an unreachable remote relay prevented home-relay revocation"
