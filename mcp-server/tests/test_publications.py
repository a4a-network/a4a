"""Model-facing public repair and receiver integration, without owner-key use."""
import json
import time

import pytest
from a4a import Agent, Keys
from a4a.publications import PublicationStore
from a4a_mcp import identity, inbox_runtime, outbox_runtime, server
from fake_relay import FakeRelay
from tool_call import call_text


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    monkeypatch.setenv("A4A_MANDATE_AUTO", "0")


async def test_partial_publication_notice_and_local_status_then_exact_repair(home, monkeypatch):
    keys = identity.load_or_create_identity()
    owner = identity.load_or_create_owner_identity()
    async with FakeRelay() as good, FakeRelay(reject_reason="blocked: outage") as missing:
        monkeypatch.setenv("A4A_RELAY", good.url+","+missing.url)
        async with Agent([good.url], keys=keys) as issuer:
            mid = await issuer.ensure_registered(owner, "Issued beforehand")
        def forbidden():
            raise AssertionError("public repair must not open the owner's private key")
        monkeypatch.setattr(server, "load_or_create_owner_identity", forbidden)
        text = await call_text(server.mcp, "a4a_publish_profile", {"capabilities": ["writing"], "category": "development"})
        assert "Profile published" in text and "1 of 2" in text and "queued" in text
        signed = next(e for e in good.events if e["kind"] == 31001)
        directory = server._make_agent().public_journal_dir
        with PublicationStore(directory, keys.pubkey_hex) as store:
            # Advance the durable schedule, not the tool's clock, for deterministic testing.
            store.db.execute("UPDATE pending SET next_attempt=0")
        def no_connections(*args, **kwargs):
            raise AssertionError("status must not connect to a node")
        with monkeypatch.context() as local:
            local.setattr(server.Agent, "__aenter__", no_connections)
            local.setattr(server, "_recent_unreachable", lambda: "Cached node outage")
            status = json.loads(await call_text(server.mcp, "a4a_publication_status", {}))
            assert status["states"] == {"pending": 1}
            assert status["records"][0]["event_id"] == signed["id"]
            assert not {"event", "mandate", "content"} & status["records"][0].keys()
        missing.reject_reason = None
        report = json.loads(await call_text(server.mcp, "a4a_repair_publications", {}))
        assert report == {"checked": 1, "restored": 1, "held": 0, "deferred": 0}
        assert [e for e in missing.events if e["kind"] == 31001] == [signed]
        assert {e["id"] for e in missing.events if e["kind"] == 31000} == {mid}
        assert json.loads(await call_text(server.mcp, "a4a_publication_status", {})) == {"states": {}, "records": []}


async def test_discard_cancels_only_exact_local_retry_without_withdrawing_network_copy(home, monkeypatch):
    keys = identity.load_or_create_identity()
    owner = identity.load_or_create_owner_identity()
    async with FakeRelay() as good, FakeRelay(reject_reason="blocked: outage") as missing:
        monkeypatch.setenv("A4A_RELAY", good.url+","+missing.url)
        async with Agent([good.url], keys=keys) as issuer:
            await issuer.ensure_registered(owner, "Issued beforehand")
        await call_text(server.mcp, "a4a_publish_profile", {"capabilities": ["writing"], "category": "development"})
        status = json.loads(await call_text(server.mcp, "a4a_publication_status", {}))
        event_id = status["records"][0]["event_id"]
        with monkeypatch.context() as local:
            local.setattr(server, "_recent_unreachable", lambda: "Cached outage")
            assert json.loads(await call_text(server.mcp, "a4a_discard_publication", {"event_id": event_id})) == {"discarded": True}
            assert json.loads(await call_text(server.mcp, "a4a_discard_publication", {"event_id": event_id})) == {"discarded": False}
        assert event_id in {e["id"] for e in good.events}
        assert not any(e["kind"] == 5 for e in good.events)
        missing.reject_reason = None
        assert json.loads(await call_text(server.mcp, "a4a_repair_publications", {}))["checked"] == 0
        assert not missing.events


async def test_receiver_tick_repairs_publications_once_per_interval(monkeypatch):
    calls = []
    class Receiver:
        async def repair_publications(self, *, now):
            calls.append(("public", now))
            return {"restored": 1}
    async def private(agent, *, now):
        calls.append(("private", now))
        return {}
    monkeypatch.setattr(inbox_runtime, "_last_outbox_recheck", 0)
    monkeypatch.setattr(outbox_runtime, "recheck_due_on", private)
    agent = Receiver()
    await inbox_runtime._recheck_sent_deliveries(agent)
    await inbox_runtime._recheck_sent_deliveries(agent)
    assert [kind for kind, _ in calls] == ["public", "private"]


async def test_public_repair_failure_does_not_stop_private_receiver_maintenance(monkeypatch):
    calls = []
    class Receiver:
        async def repair_publications(self, **kwargs):
            raise OSError("synthetic unavailable public journal")
    async def private(agent, **kwargs):
        calls.append("private")
        return {}
    monkeypatch.setattr(inbox_runtime, "_last_outbox_recheck", 0)
    monkeypatch.setattr(outbox_runtime, "recheck_due_on", private)
    await inbox_runtime._recheck_sent_deliveries(Receiver())
    assert calls == ["private"]
