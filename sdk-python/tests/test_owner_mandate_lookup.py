"""An inbox trusts an owner's current mandate, not an arbitrary agent claim."""

import time
from types import SimpleNamespace

import pytest

from a4a import Agent, Keys, types
from a4a.delegation import create_delegation, create_revocation, signed_agent_name
from a4a.relay import RelayError
from a4a.relay import RelayClient
from tests.fake_relay import FakeRelay


async def test_owner_mandate_lookup_requires_selected_owner_and_current_mandate():
    owner, other_owner, delegate = Keys(), Keys(), Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys=delegate) as agent:
            mandate = create_delegation(owner, delegate.pubkey_hex, "Sales", int(time.time()) + 3600)
            await agent.relay.publish(mandate)

            assert await agent.active_owner_mandate(delegate.pubkey_hex, {other_owner.pubkey_hex}) is None
            found = await agent.active_owner_mandate(delegate.pubkey_hex, {owner.pubkey_hex})
            assert found is not None and found.id == mandate.id

            await agent.relay.publish(create_revocation(owner, mandate))
            assert await agent.active_owner_mandate(delegate.pubkey_hex, {owner.pubkey_hex}) is None


async def test_owner_mandate_lookup_rejects_expired_and_unmandated_keys():
    owner, delegate, stranger = Keys(), Keys(), Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys=delegate) as agent:
            await agent.relay.publish(create_delegation(
                owner, delegate.pubkey_hex, "Agent", int(time.time()) - 1))
            assert await agent.active_owner_mandate(delegate.pubkey_hex, {owner.pubkey_hex}) is None
            assert await agent.active_owner_mandate(stranger.pubkey_hex, {owner.pubkey_hex}) is None


def test_agent_name_is_owner_signed_and_rejects_control_text():
    owner, delegate = Keys(), Keys()
    good = create_delegation(owner, delegate.pubkey_hex, "Sales", int(time.time()) + 3600)
    assert signed_agent_name(good) == "Sales"
    unsafe = create_delegation(owner, delegate.pubkey_hex, "Sales\u202e", int(time.time()) + 3600)
    assert signed_agent_name(unsafe) is None
    duplicate = create_delegation(owner, delegate.pubkey_hex, "Sales", int(time.time()) + 3600)
    duplicate.tags.append(["name", "Admin"])
    duplicate.sign(owner)
    assert signed_agent_name(duplicate) is None


async def test_many_senders_share_bounded_queries_and_truncation_splits(monkeypatch):
    owner, senders = Keys(), [Keys(), Keys(), Keys()]
    mandates = {sender.pubkey_hex: create_delegation(
        owner, sender.pubkey_hex, "Agent", int(time.time()) + 3600)
        for sender in senders}
    agent = Agent(["ws://127.0.0.1:9"])
    queries = []

    async def query(filters, *, max_events):
        queries.append((filters["kinds"][0], filters["#d"], max_events))
        if filters["kinds"] == [types.KIND_DELEGATION] and len(filters["#d"]) > 1:
            return SimpleNamespace(events=[], truncated=True)
        events = ([mandates[key] for key in filters["#d"]]
                  if filters["kinds"] == [types.KIND_DELEGATION] else [])
        return SimpleNamespace(events=events, truncated=False)

    monkeypatch.setattr(agent.relay, "query_bounded", query)
    found = await agent.active_owner_mandates(set(mandates), {owner.pubkey_hex})
    assert set(found) == set(mandates)
    assert any(len(keys) > 1 for _, keys, _ in queries)
    assert all(limit == 256 for _, _, limit in queries)


async def test_single_sender_truncation_fails_closed(monkeypatch):
    agent = Agent(["ws://127.0.0.1:9"])

    async def truncated(_filters, *, max_events):
        return SimpleNamespace(events=[], truncated=True)

    monkeypatch.setattr(agent.relay, "query_bounded", truncated)
    with pytest.raises(RelayError, match="truncated"):
        await agent.active_owner_mandate(Keys().pubkey_hex, {Keys().pubkey_hex})


async def test_revocation_on_second_relay_blocks_owner_trust():
    owner, sender = Keys(), Keys()
    async with FakeRelay() as first, FakeRelay() as second:
        async with Agent([first.url, second.url], keys=sender) as agent:
            mandate = create_delegation(owner, sender.pubkey_hex, "Agent", int(time.time()) + 3600)
            await agent.relay.publish(mandate)
            assert await agent.active_owner_mandate(sender.pubkey_hex, {owner.pubkey_hex}) is not None
            async with RelayClient(second.url) as node:
                await node.publish(create_revocation(owner, mandate))
            assert await agent.active_owner_mandate(sender.pubkey_hex, {owner.pubkey_hex}) is None
