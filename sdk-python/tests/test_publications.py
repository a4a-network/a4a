"""Public-copy repair: persistence, exact signatures and negative controls."""
import json
import time

import pytest
from a4a import Agent, AgentProfile, Event, Intent, Keys
from a4a.publications import PublicationError, PublicationStore
from a4a.delegation import create_delegation
from tests.fake_relay import FakeRelay


def profile(text="First profile"):
    return AgentProfile(category="development", capabilities=["writing"], content=text)


async def pending(home, missing, directory, keys=None):
    owner = Keys()
    agent = Agent([home.url, missing.url], keys=keys, public_journal_dir=directory)
    await agent.__aenter__()
    mandate_id = await agent.ensure_registered(owner, "repair fixture")
    event_id = await agent.publish_profile(profile())
    return agent, owner, mandate_id, event_id


async def test_restart_repairs_only_missing_copy_with_exact_mandate_and_event(tmp_path):
    directory = tmp_path / "publications"
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: test outage") as missing:
        agent, owner, mandate_id, event_id = await pending(home, missing, directory)
        keys = agent.keys
        original = next(e for e in home.events if e["id"] == event_id)
        mandate = next(e for e in home.events if e["id"] == mandate_id)
        assert agent.last_publication == {"event_id": event_id, "accepted": 1, "configured": 2, "pending": 1}
        await agent.__aexit__()
        missing.reject_reason = None
        async with Agent([home.url, missing.url], keys=keys, public_journal_dir=directory) as restarted:
            report = await restarted.repair_publications(now=time.time()+61)
        assert report["restored"] == 1
        assert [e for e in missing.events if e["kind"] == 31000] == [mandate]
        assert [e for e in missing.events if e["kind"] == 31001] == [original]
        assert len([e for e in home.events if e["id"] == event_id]) == 1
        with PublicationStore(directory, keys.pubkey_hex) as store:
            assert store.status() == {}


async def test_new_profile_supersedes_pending_old_profile(tmp_path):
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: outage") as missing:
        agent, _, _, old_id = await pending(home, missing, tmp_path)
        try:
            new_id = await agent.publish_profile(profile("Updated profile"))
            missing.reject_reason = None
            await agent.repair_publications(now=time.time()+61)
            assert new_id in {e["id"] for e in missing.events}
            assert old_id not in {e["id"] for e in missing.events}
        finally:
            await agent.__aexit__()


async def test_fresher_publication_from_another_process_blocks_old_repair(tmp_path):
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: outage") as missing:
        agent, _, _, old_id = await pending(home, missing, tmp_path)
        try:
            async with Agent([home.url], keys=agent.keys) as other:
                other.delegation_id = agent.delegation_id
                other._last_addressable = dict(agent._last_addressable)
                new_id = await other.publish_profile(profile("Other process update"))
            missing.reject_reason = None
            assert (await agent.repair_publications(now=time.time()+61))["held"] == 1
            assert old_id not in {e["id"] for e in missing.events}
            assert new_id in {e["id"] for e in home.events}
            with PublicationStore(tmp_path, agent.pubkey) as store:
                assert store.status() == {"superseded": 1}
        finally:
            await agent.__aexit__()


async def test_short_owner_authorization_expires_before_queue_age_limit(tmp_path):
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: outage") as missing:
        async with Agent([home.url, missing.url], public_journal_dir=tmp_path) as agent:
            mandate = create_delegation(Keys(), agent.pubkey, "Short mandate", int(time.time())+30)
            await agent.relay.publish(mandate)
            agent.delegation_id = mandate.id
            iid = await agent.publish_profile(profile())
            missing.reject_reason = None
            assert (await agent.repair_publications(now=time.time()+61))["held"] == 1
            assert iid not in {e["id"] for e in missing.events}
            with PublicationStore(tmp_path, agent.pubkey) as store:
                assert store.status() == {"authorization_expired": 1}


async def test_all_nodes_reject_still_leaves_durable_repair_record(tmp_path):
    async with FakeRelay() as node:
        async with Agent([node.url], public_journal_dir=tmp_path) as agent:
            await agent.ensure_registered(Keys(), "fixture")
            node.reject_reason = "blocked: write outage"
            from a4a.relay import RelayError
            with pytest.raises(RelayError, match="queued for repair") as rejected:
                await agent.publish_profile(profile())
            assert rejected.value.reason == "blocked: write outage"
            with PublicationStore(tmp_path, agent.pubkey) as store:
                original = store.due(time.time()+61, 5)[0]
            node.reject_reason = None
            assert (await agent.repair_publications(now=time.time()+61))["restored"] == 1
            assert original["event_id"] in {e["id"] for e in node.events}


async def test_new_owner_mandate_stops_old_authorization_replay(tmp_path):
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: outage") as missing:
        agent, owner, mid, iid = await pending(home, missing, tmp_path)
        try:
            original = (await agent.relay.query({"ids": [mid]}))[0]
            replacement = create_delegation(owner, agent.pubkey, "New terms", int(time.time())+3600,
                                            created_at=original.created_at+1)
            await agent.relay.publish(replacement)
            missing.reject_reason = None
            assert (await agent.repair_publications(now=time.time()+61))["held"] == 1
            assert not missing.events
            with PublicationStore(tmp_path, agent.pubkey) as store:
                assert store.status() == {"authorization_superseded": 1}
        finally:
            await agent.__aexit__()


@pytest.mark.parametrize("incomplete", ["truncated", "connection_dropped_events", "discarded_invalid_events"])
async def test_incomplete_security_evidence_is_not_treated_as_permission(tmp_path, monkeypatch, incomplete):
    from a4a.relay import QueryResult
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: outage") as missing:
        agent, _, _, _ = await pending(home, missing, tmp_path)
        try:
            missing.reject_reason = None
            async def incomplete_query(*args, **kwargs):
                return QueryResult(events=[], inspected_events=0, discarded_invalid_events=int(incomplete == "discarded_invalid_events"),
                    truncated=incomplete == "truncated", connection_dropped_events=int(incomplete == "connection_dropped_events"))
            monkeypatch.setattr(agent.relay.clients[0], "query_bounded", incomplete_query)
            assert (await agent.repair_publications(now=time.time()+61))["deferred"] == 1
            assert not missing.events
        finally:
            await agent.__aexit__()


@pytest.mark.parametrize("block", ["revoked", "withdrawn", "authorization_expired"])
async def test_repair_never_republishes_blocked_authorization_or_withdrawal(tmp_path, block):
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: outage") as missing:
        agent, owner, mandate_id, event_id = await pending(home, missing, tmp_path)
        try:
            mandate = (await agent.relay.query({"ids": [mandate_id]}))[0]
            if block == "revoked":
                await agent.revoke_delegation(owner, mandate)
                now = time.time()+61
            elif block == "withdrawn":
                await agent.relay.publish(Event(kind=5, tags=[["e", event_id]]).sign(agent.keys))
                now = time.time()+61
            else:
                now = int(mandate.tag_value("expiration"))+1
            missing.reject_reason = None
            result = await agent.repair_publications(now=now)
            assert result["held"] == 1
            assert event_id not in {e["id"] for e in missing.events}
            with PublicationStore(tmp_path, agent.pubkey) as store:
                # The 48-hour repair ceiling also stops old authorizations.
                assert store.status() in ({block: 1}, {"expired": 1})
        finally:
            await agent.__aexit__()


async def test_expired_request_is_not_restored(tmp_path):
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: outage") as missing:
        async with Agent([home.url, missing.url], public_journal_dir=tmp_path) as agent:
            await agent.ensure_registered(Keys(), "fixture")
            iid = await agent.publish_intent(Intent(intent_type="service_request", category="development", need="test", budget_min=0, budget_max=0, deadline=int(time.time())+10))
            missing.reject_reason = None
            assert (await agent.repair_publications(now=time.time()+61))["held"] == 1
            assert iid not in {e["id"] for e in missing.events}


async def test_removed_destination_is_not_contacted_or_replaced_by_new_node(tmp_path):
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: outage") as missing, FakeRelay() as new:
        agent, _, _, iid = await pending(home, missing, tmp_path)
        keys = agent.keys
        await agent.__aexit__()
        async with Agent([home.url, new.url], keys=keys, public_journal_dir=tmp_path) as changed:
            assert (await changed.repair_publications(now=time.time()+61))["held"] == 1
        assert not new.events
        assert not missing.events
        with PublicationStore(tmp_path, keys.pubkey_hex) as store:
            assert store.status() == {"configuration_changed": 1}


async def test_incomplete_verification_defers_without_republishing(tmp_path):
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: outage") as missing:
        agent, _, _, iid = await pending(home, missing, tmp_path)
        try:
            missing.reject_reason = None
            missing.closed_reason = "blocked: verification unavailable"
            result = await agent.repair_publications(now=time.time()+61)
            assert result["deferred"] == 1
            assert not missing.events
            with PublicationStore(tmp_path, agent.pubkey) as store:
                assert not store.due(time.time()+62, 5), "failure must apply backoff"
        finally:
            await agent.__aexit__()


async def test_private_messages_never_create_public_queue(tmp_path):
    directory = tmp_path / "not-created"
    async with FakeRelay() as relay:
        async with Agent([relay.url], public_journal_dir=directory) as agent:
            await agent.send_private_message(Keys().pubkey_hex, "private control")
        assert not directory.exists()


def test_store_rejects_private_foreign_and_unsigned_events(tmp_path):
    keys = Keys()
    with PublicationStore(tmp_path, keys.pubkey_hex) as store:
        for event in (Event(kind=31033).sign(keys), Event(kind=10002).sign(Keys()), Event(kind=10002)):
            with pytest.raises(PublicationError):
                store.stage(event, None, ["ws://fixture.invalid"])
        assert store.status() == {}


def test_wrong_identity_does_not_poison_database(tmp_path):
    keys = Keys()
    with PublicationStore(tmp_path, keys.pubkey_hex):
        pass
    with pytest.raises(PublicationError):
        PublicationStore(tmp_path, Keys().pubkey_hex)
    with PublicationStore(tmp_path, keys.pubkey_hex) as store:
        assert store.status() == {}


def test_stage_is_durable_before_any_network_attempt_and_due_is_bounded(tmp_path):
    keys = Keys()
    event = Event(kind=10002, tags=[["r", "ws://fixture.invalid"]]).sign(keys)
    now = time.time()
    with PublicationStore(tmp_path, keys.pubkey_hex) as store:
        store.stage(event, None, ["ws://fixture.invalid"], now=now)
        assert not store.due(now+59, 5)
        with pytest.raises(ValueError):
            store.due(now+61, 21)
    with PublicationStore(tmp_path, keys.pubkey_hex) as restarted:
        row = restarted.due(now+61, 5)[0]
        assert Event.model_validate_json(row["event"]) == event
        assert json.loads(row["targets"]) == ["ws://fixture.invalid"]
