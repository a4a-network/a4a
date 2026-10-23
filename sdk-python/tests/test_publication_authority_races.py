"""Initial mandate-copy authorization and cross-process cancellation boundaries."""
import asyncio
import time

import pytest
from a4a import Agent, AgentProfile, Event, Keys
from a4a.delegation import create_delegation, create_revocation, validate_sender_mandate
from a4a.publications import PublicationError, PublicationStore
from a4a.relay import QueryResult
from tests.fake_relay import FakeRelay
from tests.test_publications import pending, profile


@pytest.mark.parametrize("negative", ["revoked", "superseded"])
async def test_initial_publication_never_copies_known_invalid_authority(tmp_path, negative):
    owner, keys = Keys(), Keys()
    now = int(time.time())
    mandate = create_delegation(owner, keys.pubkey_hex, "Synthetic", now+86400, created_at=now-10)
    newer = (create_revocation(owner, mandate) if negative == "revoked" else
             create_delegation(owner, keys.pubkey_hex, "Replacement", now+86400, created_at=now-5))
    async with FakeRelay() as home, FakeRelay() as fresh:
        home.events.extend([mandate.model_dump(), newer.model_dump()])
        async with Agent([home.url, fresh.url], keys=keys, public_journal_dir=tmp_path) as agent:
            agent.delegation_id = mandate.id
            before = list(home.events)
            with pytest.raises(PublicationError, match=negative):
                await agent.publish_profile(profile())
            assert home.events == before
            assert not fresh.events


@pytest.mark.parametrize("flag", ["truncated", "discarded_invalid_events", "connection_dropped_events"])
@pytest.mark.parametrize("negative", ["revoked", "superseded"])
async def test_known_negative_evidence_blocks_even_an_incomplete_answer(tmp_path, monkeypatch, flag, negative):
    owner, keys = Keys(), Keys()
    now = int(time.time())
    mandate = create_delegation(owner, keys.pubkey_hex, "Synthetic", now+86400, created_at=now-10)
    newer = (create_revocation(owner, mandate) if negative == "revoked" else
             create_delegation(owner, keys.pubkey_hex, "Replacement", now+86400, created_at=now-5))
    async with FakeRelay() as home, FakeRelay() as fresh:
        home.events.append(mandate.model_dump())
        async with Agent([home.url, fresh.url], keys=keys, public_journal_dir=tmp_path) as agent:
            agent.delegation_id = mandate.id
            async def incomplete(*args, **kwargs):
                return QueryResult(events=[mandate, newer], inspected_events=2,
                    discarded_invalid_events=int(flag == "discarded_invalid_events"),
                    truncated=flag == "truncated", connection_dropped_events=int(flag == "connection_dropped_events"))
            monkeypatch.setattr(agent.relay.clients[0], "query_bounded", incomplete)
            with pytest.raises(PublicationError, match=negative):
                await agent.publish_profile(profile())
            assert [e["id"] for e in home.events] == [mandate.id]
            assert not fresh.events


async def test_owner_reuse_never_broadcasts_old_mandate_when_fanout_hides_revocation(tmp_path, monkeypatch):
    owner, keys = Keys(), Keys()
    now = int(time.time())
    old = create_delegation(owner, keys.pubkey_hex, "Old", now+30*86400, created_at=now-10)
    revoked = create_revocation(owner, old)
    async with FakeRelay() as home, FakeRelay() as fresh:
        home.events.extend([old.model_dump(), revoked.model_dump()])
        async with Agent([home.url, fresh.url], keys=keys) as agent:
            original = agent.relay.query
            async def incomplete_fanout(filters, *args, **kwargs):
                if filters.get("kinds") == [31007]:
                    return []  # The ordinary fan-out view hid an unavailable responder.
                return await original(filters, *args, **kwargs)
            monkeypatch.setattr(agent.relay, "query", incomplete_fanout)
            reused = await agent.ensure_registered(owner, "Explicit owner renewal")
            assert reused != old.id, "known revocation must not be reused or copied"
            assert old.id not in {e["id"] for e in fresh.events}
            assert reused in {e["id"] for e in fresh.events}, "the owner may sign a new mandate explicitly"
            renewed = Event.model_validate(next(e for e in fresh.events if e["id"] == reused))
            assert renewed.created_at > revoked.created_at
            # A one-second future start is intentional after same-second revocation.
            assert validate_sender_mandate(agent.pubkey, renewed, now=renewed.created_at,
                                           revocation=revoked, require_started=True)


@pytest.mark.parametrize("missing", ["unavailable", "truncated", "discarded_invalid_events", "connection_dropped_events"])
async def test_incomplete_evidence_preserves_existing_copy_but_never_authorizes_new_copy(tmp_path, monkeypatch, missing):
    owner, keys = Keys(), Keys()
    mandate = create_delegation(owner, keys.pubkey_hex, "Synthetic", int(time.time())+86400)
    async with FakeRelay() as home, FakeRelay() as fresh:
        home.events.append(mandate.model_dump())
        async with Agent([home.url, fresh.url], keys=keys, public_journal_dir=tmp_path) as agent:
            agent.delegation_id = mandate.id
            async def incomplete(*args, **kwargs):
                if missing == "unavailable":
                    raise OSError("synthetic unavailable evidence")
                return QueryResult(events=[], inspected_events=0,
                    discarded_invalid_events=int(missing == "discarded_invalid_events"),
                    truncated=missing == "truncated", connection_dropped_events=int(missing == "connection_dropped_events"))
            monkeypatch.setattr(agent.relay.clients[1], "query_bounded", incomplete)
            iid = await agent.publish_profile(profile())
            assert agent.last_publication == {"event_id": iid, "accepted": 1, "configured": 2, "pending": 1}
            assert [e["id"] for e in home.events] == [mandate.id, iid]
            assert not fresh.events, "uncertain evidence must not copy even a valid signed mandate"


@pytest.mark.parametrize("mutation", ["discard", "replace"])
async def test_mutation_during_evidence_fences_stale_retry(tmp_path, monkeypatch, mutation):
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: outage") as missing:
        agent, _, mandate_id, event_id = await pending(home, missing, tmp_path)
        try:
            missing.reject_reason = None
            checking, release = asyncio.Event(), asyncio.Event()
            original = agent.relay.clients[0].query_bounded
            async def paused(*args, **kwargs):
                checking.set()
                await release.wait()
                return await original(*args, **kwargs)
            monkeypatch.setattr(agent.relay.clients[0], "query_bounded", paused)
            retry = asyncio.create_task(agent.repair_publications(now=time.time()+61))
            try:
                await asyncio.wait_for(checking.wait(), 5)
                with PublicationStore(tmp_path, agent.pubkey) as other_process:
                    if mutation == "discard":
                        assert other_process.discard(event_id)
                    else:
                        row = other_process.due(time.time()+61, 5)[0]
                        from a4a import Event
                        mandate = Event.model_validate_json(row["mandate"])
                        newer = profile("New local version").to_event(mandate_id)
                        newer.created_at = int(time.time())+1
                        newer.sign(agent.keys)
                        other_process.stage(newer, mandate, [home.url, missing.url])
                assert not missing.events
                release.set()
                assert (await retry)["restored"] == 0
                assert not missing.events, "neither stale mandate nor cancelled event may reach the wire"
            finally:
                release.set()
                if not retry.done():
                    retry.cancel()
                    await asyncio.gather(retry, return_exceptions=True)
        finally:
            await agent.__aexit__()


async def test_inflight_send_refuses_discard_and_releases_lock_on_cancellation(tmp_path, monkeypatch):
    async with FakeRelay() as home, FakeRelay(reject_reason="blocked: outage") as missing:
        agent, _, _, event_id = await pending(home, missing, tmp_path)
        try:
            missing.reject_reason = None
            sending, release = asyncio.Event(), asyncio.Event()
            original = agent.relay.clients[1].publish
            async def paused(*args, **kwargs):
                sending.set()
                await release.wait()
                return await original(*args, **kwargs)
            monkeypatch.setattr(agent.relay.clients[1], "publish", paused)
            retry = asyncio.create_task(agent.repair_publications(now=time.time()+61))
            try:
                await asyncio.wait_for(sending.wait(), 5)
                with PublicationStore(tmp_path, agent.pubkey) as other_process:
                    with pytest.raises(PublicationError, match="in flight"):
                        other_process.discard(event_id)
                    assert other_process.entries()[0]["event_id"] == event_id
                retry.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await retry
                with PublicationStore(tmp_path, agent.pubkey) as other_process:
                    assert other_process.discard(event_id), "cancellation must release OS ownership"
                assert not missing.events
            finally:
                release.set()
                if not retry.done():
                    retry.cancel()
                    await asyncio.gather(retry, return_exceptions=True)
        finally:
            await agent.__aexit__()


def test_process_death_releases_publication_mutation_lock(tmp_path):
    from tests.test_inbox_lock import _holder
    keys = Keys()
    with PublicationStore(tmp_path, keys.pubkey_hex) as store:
        with _holder(store.lock_directory):
            with pytest.raises(PublicationError, match="in flight"):
                with store.mutation_guard():
                    pytest.fail("the process-held publication lock was bypassed")
        with store.mutation_guard():
            pass
