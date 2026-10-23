"""Durable dialogue tests: synthetic identities, no external network."""
import asyncio
import importlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from pathlib import Path

import guarded_child
import network_guard
import pytest

from a4a import Agent, Keys, giftwrap, types
from a4a.event import Event
from a4a.inbox import InboxConflict, InboxError, InboxFull, InboxStore


@pytest.fixture(autouse=True)
def local_only():
    """Allow connections only to addresses started by the test itself.

    The old rule required a loopback address, and only on synchronous sockets.
    That is weaker than it sounds: an unrelated service may listen on 127.0.0.1,
    while asynchronous connections bypassed the check entirely. The shared test
    boundary requires ownership rather than loopback; this fixture attributes any
    violation to THIS test.
    """
    mark = len(network_guard.unexpected())
    yield
    new = network_guard.unexpected()[mark:]
    assert not new, f"test contacted addresses it did not start: {sorted(set(new))}"


@pytest.fixture
def setup(tmp_path):
    assert importlib.util.find_spec("a4a.dialogue") is not None, "durable dialogue runtime is missing"
    api = importlib.import_module("a4a.dialogue")
    a, b = Keys(), Keys()
    agent = Agent(["ws://127.0.0.1:1/never"], keys=a)
    path = tmp_path / "inbox"
    with api.DialogueStore(path, a.pubkey_hex, "general") as store:
        store.activate()
    return api, path, agent, b


def letter(sender, recipient, text="private incoming", delivery="one"):
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, tags=[["p", recipient], ["d", delivery]], content=text).sign(sender)
    return giftwrap.wrap(inner, recipient, sender)


def open_store(setup, **kwargs):
    api, path, agent, _ = setup
    return api.DialogueStore(path, agent.pubkey, "general", **kwargs)


def make_outbox_legacy(store, agent, operation_id, relay_url):
    """Rewrite a fresh test row into the authenticated pre-relay-set format."""
    row = store.db.execute(
        "SELECT * FROM dialogue_outbox WHERE operation_id=?", (operation_id,),
    ).fetchone()
    body = store._unseal(agent, row["local_body"])
    body["relay"] = relay_url
    with store._transaction():
        store.db.execute(
            "UPDATE dialogue_outbox SET relay=?,local_body=? WHERE seq=?",
            (relay_url, store._seal(agent, body), row["seq"]),
        )


@pytest.mark.parametrize("value", [None, "", "contains space", "x" * 129])
def test_local_dialogue_identifiers_are_bounded_ascii(setup, value):
    api, _, _, _ = setup
    with pytest.raises(InboxError, match="identifier"):
        api._name(value)


def test_dialogue_text_rejects_non_strings_and_oversize_utf8(setup):
    api, _, _, _ = setup
    with pytest.raises(InboxError, match="string"):
        api._text(None, 8)
    with pytest.raises(InboxError, match="size limit"):
        api._text("é" * 5, 8)


def test_dialogue_schema_version_is_enforced_on_reopen(setup):
    _, _, _, _ = setup
    with open_store(setup) as store:
        with store._transaction():
            store.db.execute("UPDATE metadata SET value='2' WHERE key='dialogue_schema'")
    with pytest.raises(InboxConflict, match="schema"):
        with open_store(setup):
            pass


def test_activation_refuses_an_active_legacy_claim(setup):
    api, path, agent, peer = setup
    other = path.parent / "legacy-processing"
    allowed = {peer.pubkey_hex}
    with api.DialogueStore(other, agent.pubkey, "general") as store:
        store.accept(agent, letter(peer, agent.pubkey), allowed, now=1)
        assert store.claim(agent, "general", allowed, now=2) is not None
        with pytest.raises(InboxConflict, match="legacy inbox claims"):
            store.activate()


def test_dialogue_operations_require_explicit_activation(setup):
    api, path, agent, peer = setup
    other = path.parent / "inactive"
    with api.DialogueStore(other, agent.pubkey, "general") as store:
        with pytest.raises(InboxError, match="not enabled"):
            store.acquire(peer.pubkey_hex, "worker", {peer.pubkey_hex}, now=1)


def test_dialogue_rejects_an_agent_bound_to_another_identity(setup):
    _, _, _, peer = setup
    wrong = Agent(["ws://127.0.0.1:1/never"], keys=Keys())
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        with pytest.raises(InboxConflict, match="identity mismatch"):
            store.checkpoint(wrong, lease["token"], "worker", allowed, "text", now=2)


@pytest.mark.parametrize("lease_seconds", [True, 0, 3601])
def test_acquire_rejects_invalid_lease_duration(setup, lease_seconds):
    _, _, _, peer = setup
    with open_store(setup) as store:
        with pytest.raises(InboxError, match="1..3600"):
            store.acquire(peer.pubkey_hex, "worker", {peer.pubkey_hex}, now=1,
                          lease_seconds=lease_seconds)


@pytest.mark.parametrize("lease_seconds", [True, 0, 3601])
def test_renew_rejects_invalid_lease_duration(setup, lease_seconds):
    _, _, _, peer = setup
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        with pytest.raises(InboxError, match="1..3600"):
            store.renew(lease["token"], "worker", allowed, now=2,
                        lease_seconds=lease_seconds)


def test_dialogue_count_limit_blocks_a_new_peer(setup):
    _, _, _, peer = setup
    with open_store(setup) as store:
        with store._transaction():
            for index in range(100):
                store.db.execute(
                    "INSERT INTO dialogues(peer,conversation_id) VALUES (?,?)",
                    (f"{index:064x}", f"conversation-{index}"),
                )
        with pytest.raises(InboxFull, match="dialogue count limit"):
            store.acquire(peer.pubkey_hex, "worker", {peer.pubkey_hex}, now=1)


def test_work_rejects_an_unbounded_peer_policy(setup):
    peers = {Keys().pubkey_hex for _ in range(101)}
    with open_store(setup) as store:
        with pytest.raises(InboxError, match="policy exceeds"):
            store.work(peers, now=1)


@pytest.mark.parametrize(("before", "limit"), [
    (True, 20), (-1, 20), (0, True), (0, 0), (0, 101),
])
def test_history_rejects_invalid_page_bounds(setup, before, limit):
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        with pytest.raises(InboxError, match="history page"):
            store.history(agent, lease["token"], "worker", allowed, now=2,
                          before=before, limit=limit)


def test_history_rejects_a_checkpoint_from_another_conversation(setup):
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        forged = store._seal(agent, {"conversation_id": "not-this-conversation",
                                     "text": "forged"})
        with store._transaction():
            store.db.execute("UPDATE dialogues SET checkpoint=? WHERE peer=?",
                             (forged, peer.pubkey_hex))
        with pytest.raises(InboxConflict, match="checkpoint conversation"):
            store.history(agent, lease["token"], "worker", allowed, now=2)


def test_history_rejects_an_incoming_envelope_from_another_sender(setup):
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}
    intruder = Keys()
    with open_store(setup) as store:
        store.accept(agent, letter(peer, agent.pubkey), allowed, now=1)
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=2)
        substitute = letter(intruder, agent.pubkey, "forged", "other").model_dump_json()
        with store._transaction():
            store.db.execute("UPDATE messages SET envelope=? WHERE seq=1", (substitute,))
        with pytest.raises(InboxConflict, match="incoming history"):
            store.history(agent, lease["token"], "worker", allowed, now=3)


@pytest.mark.parametrize(("seq", "status", "reconciled"), [
    (True, "processed", False), (0, "processed", False),
    (1, "unknown", False), (1, "processed", 1),
])
def test_finish_incoming_rejects_invalid_arguments(setup, seq, status, reconciled):
    _, _, _, peer = setup
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        with pytest.raises(InboxError, match="invalid dialogue completion"):
            store.finish_incoming(lease["token"], "worker", allowed, seq, status,
                                  reconciled=reconciled, now=2)


def test_finish_incoming_rejects_a_missing_message(setup):
    _, _, _, peer = setup
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        with pytest.raises(InboxConflict, match="not unfinished"):
            store.finish_incoming(lease["token"], "worker", allowed, 1,
                                  "processed", now=2)


def test_abandon_rejects_a_missing_operation(setup):
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        with pytest.raises(InboxConflict, match="operation is missing"):
            store.abandon(agent, lease["token"], "worker", allowed, "missing", now=2)


async def test_dispatch_rejects_a_substituted_outer_envelope(setup, monkeypatch):
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}

    async def must_not_publish(*args, **kwargs):
        raise AssertionError("a substituted envelope reached the network")

    monkeypatch.setattr(agent.relay, "publish", must_not_publish)
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        store.prepare_send(agent, lease["token"], "worker", allowed, "one", "first", now=2)
        store.prepare_send(agent, lease["token"], "worker", allowed, "two", "second", now=2)
        other = store.db.execute(
            "SELECT envelope FROM dialogue_outbox WHERE operation_id='two'").fetchone()[0]
        with store._transaction():
            store.db.execute(
                "UPDATE dialogue_outbox SET envelope=? WHERE operation_id='one'", (other,))
        with pytest.raises(InboxConflict, match="envelope failed verification"):
            await store.dispatch(agent, lease["token"], "worker", allowed, "one", now=3)


async def test_dispatch_blocks_a_second_operation_while_one_is_uncertain(setup, monkeypatch):
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}

    async def must_not_publish(*args, **kwargs):
        raise AssertionError("a second operation reached the network")

    monkeypatch.setattr(agent.relay, "publish", must_not_publish)
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        store.prepare_send(agent, lease["token"], "worker", allowed, "one", "first", now=2)
        store.prepare_send(agent, lease["token"], "worker", allowed, "two", "second", now=2)
        with store._transaction():
            store.db.execute(
                "UPDATE dialogue_outbox SET state='unknown' WHERE operation_id='one'")
        with pytest.raises(InboxConflict, match="another outgoing operation"):
            await store.dispatch(agent, lease["token"], "worker", allowed, "two", now=3)


async def test_reconcile_does_not_query_a_stable_operation(setup, monkeypatch):
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}

    async def must_not_query(*args, **kwargs):
        raise AssertionError("a stable operation triggered relay reconciliation")

    monkeypatch.setattr(agent.relay, "query_bounded", must_not_query)
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        store.prepare_send(agent, lease["token"], "worker", allowed, "one", "first", now=2)
        result = await store.reconcile(agent, lease["token"], "worker", allowed,
                                       "one", now=3)
        assert result["state"] == "prepared"


def test_restart_retains_address_history_checkpoint_and_unfinished_work(setup):
    _, path, agent, peer = setup
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        store.accept(agent, letter(peer, agent.pubkey), allowed, now=10)
        lease = store.acquire(peer.pubkey_hex, "worker-a", allowed, now=11, lease_seconds=10)
        store.checkpoint(agent, lease["token"], "worker-a", allowed, "secret checkpoint", now=12)
    with open_store(setup) as store:
        resumed = store.acquire(peer.pubkey_hex, "worker-b", allowed, now=22)
        assert resumed["conversation_id"] == lease["conversation_id"]
        assert resumed["epoch"] > lease["epoch"]
        history = store.history(agent, resumed["token"], "worker-b", allowed, now=23)
        assert history["checkpoint"] == "secret checkpoint"
        assert history["items"][0]["content"] == "private incoming"
        assert history["items"][0]["state"] == "unknown"
        with pytest.raises(InboxConflict):
            store.checkpoint(agent, lease["token"], "worker-a", allowed, "stale", now=23)
    for file in path.iterdir():
        if file.is_file():
            assert b"private incoming" not in file.read_bytes()
            assert b"secret checkpoint" not in file.read_bytes()


def test_two_workers_have_only_one_conversation_lease(setup):
    _, _, _, peer = setup
    barrier = Barrier(2)
    def acquire(worker):
        with open_store(setup) as store:
            barrier.wait()
            try:
                return store.acquire(peer.pubkey_hex, worker, {peer.pubkey_hex}, now=10)
            except InboxConflict:
                return None
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(acquire, ("one", "two")))
    assert sum(item is not None for item in results) == 1


def test_legacy_claim_is_closed_after_activation(setup):
    _, path, agent, peer = setup
    with InboxStore(path, agent.pubkey, "general") as store:
        store.accept(agent, letter(peer, agent.pubkey), {peer.pubkey_hex})
        with pytest.raises(InboxConflict, match="dialogue"):
            store.claim(agent, "general", {peer.pubkey_hex})


def test_legacy_completion_cannot_bypass_dialogue_worker_fencing(setup):
    _, _, agent, peer = setup
    with open_store(setup) as store:
        store.accept(agent, letter(peer, agent.pubkey), {peer.pubkey_hex}, now=1)
        lease = store.acquire(peer.pubkey_hex, "one", {peer.pubkey_hex}, now=2)
        with pytest.raises(InboxConflict, match="dialogue"):
            store.finish(1, lease["token"], "general", "processed", now=3)


def test_incoming_during_active_dialogue_does_not_generate_another_wakeup(setup):
    _, _, agent, peer = setup
    with open_store(setup) as store:
        store.acquire(peer.pubkey_hex, "one", {peer.pubkey_hex}, now=2, lease_seconds=10)
        store.accept(agent, letter(peer, agent.pubkey), {peer.pubkey_hex}, now=3)
        assert store.notice({peer.pubkey_hex}, now=3) is None
        assert store.notice({peer.pubkey_hex}, now=13)["pending"] == 1


def test_late_incoming_exposed_in_history_requires_reconciliation_after_restart(setup):
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "old", allowed, now=1, lease_seconds=5)
        store.accept(agent, letter(peer, agent.pubkey), allowed, now=2)
        page = store.history(agent, lease["token"], "old", allowed, now=3)
        assert page["items"][0]["state"] == "processing"
    with open_store(setup) as store:
        new = store.acquire(peer.pubkey_hex, "new", allowed, now=7)
        page = store.history(agent, new["token"], "new", allowed, now=8)
        assert page["items"][0]["state"] == "unknown"
        with pytest.raises(InboxConflict, match="reconciliation"):
            store.finish_incoming(new["token"], "new", allowed, 1, "processed", now=8)


async def test_managed_dispatch_never_replays_on_transport_reconnect(setup):
    _, _, agent, peer = setup
    sent = []
    class Socket:
        async def send(self, data):
            sent.append(json.loads(data))
    agent.relay.clients[0]._ws = Socket()
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "old", {peer.pubkey_hex}, now=1, lease_seconds=5)
        store.prepare_send(agent, lease["token"], "old", {peer.pubkey_hex}, "op", "once", now=2)
        task = asyncio.create_task(store.dispatch(agent, lease["token"], "old", {peer.pubkey_hex}, "op", now=3))
        try:
            for _ in range(100):
                if sent:
                    break
                await asyncio.sleep(0)
            assert len(sent) == 1
            store.acquire(peer.pubkey_hex, "new", {peer.pubkey_hex}, now=7)
            await agent.relay.clients[0]._resend_pending()
            assert len(sent) == 1
            assert store.db.execute("SELECT state FROM dialogue_outbox").fetchone()[0] == "unknown"
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


async def test_outgoing_envelope_substitution_is_rejected_before_send(setup, monkeypatch):
    _, _, agent, peer = setup
    calls = []
    async def publish(event, **kwargs):
        calls.append(event)
    monkeypatch.setattr(agent.relay, "publish", publish)
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex}, now=1)
        for op, text in (("one", "approved text one"), ("two", "different text two")):
            store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, op, text, now=2)
        other = store.db.execute("SELECT envelope,outer_id FROM dialogue_outbox WHERE operation_id='two'").fetchone()
        store.db.execute("UPDATE dialogue_outbox SET envelope=?,outer_id=? WHERE operation_id='one'", tuple(other))
        with pytest.raises(InboxConflict, match="binding"):
            await store.dispatch(agent, lease["token"], "w", {peer.pubkey_hex}, "one", now=3)
        assert calls == []


@pytest.mark.parametrize("managed", [False, True])
async def test_transport_replay_default_and_pending_id_ownership(setup, managed):
    from a4a.relay import RelayError
    _, _, agent, peer = setup
    _, outer, _ = agent.prepare_private_message(peer.pubkey_hex, "transport test")
    sent = []
    class Socket:
        async def send(self, data):
            sent.append(json.loads(data))
    agent.relay.clients[0]._ws = Socket()
    options = {"replay_on_reconnect": False} if managed else {}
    task = asyncio.create_task(agent.relay.publish(outer, **options))
    try:
        for _ in range(100):
            if sent:
                break
            await asyncio.sleep(0)
        assert len(sent) == 1
        with pytest.raises(RelayError, match="already pending"):
            await agent.relay.publish(outer)
        await agent.relay.clients[0]._resend_pending()
        assert len(sent) == (1 if managed else 2)
        agent.relay.clients[0]._dispatch(["OK", outer.id, True, ""])
        await task
        assert not agent.relay.clients[0]._pending_ok and not agent.relay.clients[0]._pending_events
    finally:
        if not task.done():
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


def test_expired_worker_causes_reconciliation_hint_not_silent_loss(setup):
    _, _, agent, peer = setup
    with open_store(setup) as store:
        store.accept(agent, letter(peer, agent.pubkey), {peer.pubkey_hex}, now=1)
        store.acquire(peer.pubkey_hex, "old", {peer.pubkey_hex}, now=2, lease_seconds=1)
        hint = store.notice({peer.pubkey_hex}, now=4)
        assert hint is not None
        assert hint["pending"] == 0
        assert hint["needs_reconciliation"] == 1


def test_revocation_suppresses_access_without_erasing_incoming_uncertainty(setup):
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        store.accept(agent, letter(peer, agent.pubkey), allowed, now=1)
        store.acquire(peer.pubkey_hex, "old", allowed, now=2, lease_seconds=1)
        assert store.notice(set(), now=4) is None
        assert store.work(set(), now=4) == []
        assert store.db.execute("SELECT state FROM messages").fetchone()[0] == "unknown"
        assert store.work(allowed, now=5)[0]["unknown"] == 1
        assert store.notice(allowed, now=5)["needs_reconciliation"] == 1
        lease = store.acquire(peer.pubkey_hex, "new", allowed, now=6)
        assert store.history(agent, lease["token"], "new", allowed, now=6)["items"][0]["state"] == "unknown"
        with pytest.raises(InboxConflict, match="reconciliation"):
            store.finish_incoming(lease["token"], "new", allowed, 1, "processed", now=6)
        assert store.finish_incoming(lease["token"], "new", allowed, 1, "processed", reconciled=True, now=6)["state"] == "processed"


async def test_actual_relay_reconciliation_after_lost_receipt_does_not_resend(setup, monkeypatch):
    from tests.fake_relay import FakeRelay
    _, path, agent, peer = setup
    allowed = {peer.pubkey_hex}
    async with FakeRelay() as relay:
        agent = Agent([relay.url], keys=agent.keys)
        async with agent:
            with open_store(setup) as store:
                lease = store.acquire(peer.pubkey_hex, "old", allowed, now=1, lease_seconds=5)
                prepared = store.prepare_send(agent, lease["token"], "old", allowed, "out-1", "confidential reply", now=2)
                original = agent.relay.publish
                async def lost_receipt(event, **kwargs):
                    await original(event, **kwargs)
                    raise ConnectionError("lost after relay accepted")
                monkeypatch.setattr(agent.relay, "publish", lost_receipt)
                with pytest.raises(ConnectionError):
                    await store.dispatch(agent, lease["token"], "old", allowed, "out-1", now=3)
            assert len(relay.events) == 1
            with open_store(setup) as store:
                new = store.acquire(peer.pubkey_hex, "new", allowed, now=7)
                receipt = await store.reconcile(agent, new["token"], "new", allowed, "out-1", now=8)
                assert receipt["state"] == "relay_observed"
                assert receipt["outer_id"] == prepared["outer_id"]
                again = await store.dispatch(agent, new["token"], "new", allowed, "out-1", now=8)
                assert again["state"] == "relay_observed"
                assert len(relay.events) == 1
                assert store.history(agent, new["token"], "new", allowed, now=8)["items"][0]["content"] == "confidential reply"
        recipient = Agent([relay.url], keys=peer)
        outer = Event.model_validate(relay.events[0])
        with InboxStore(path.parent / "recipient", peer.pubkey_hex, "peer") as inbox:
            assert inbox.accept(recipient, outer, {agent.pubkey}) == "stored"
            assert inbox.accept(recipient, outer, {agent.pubkey}) == "duplicate"
            assert inbox.status()["pending"] == 1


async def test_absent_relay_event_keeps_unknown_and_blocks_next_send(setup, monkeypatch):
    from a4a.relay import QueryResult
    _, _, agent, peer = setup
    async def fail(event, **kwargs):
        raise ConnectionError("uncertain")
    async def empty(*args, **kwargs):
        return QueryResult([], 0, 0, False)
    monkeypatch.setattr(agent.relay, "publish", fail)
    monkeypatch.setattr(agent.relay, "query_bounded", empty)
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex}, now=1)
        store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "op", "x", now=1)
        with pytest.raises(ConnectionError):
            await store.dispatch(agent, lease["token"], "w", {peer.pubkey_hex}, "op", now=1)
        result = await store.reconcile(agent, lease["token"], "w", {peer.pubkey_hex}, "op", now=2)
        assert result["state"] == "unknown"


def test_history_pages_are_bounded_and_survive_reopen(setup):
    _, _, agent, peer = setup
    with open_store(setup) as store:
        for i in range(4):
            store.accept(agent, letter(peer, agent.pubkey, "x" * 30000, str(i)), {peer.pubkey_hex}, now=i + 1)
        lease = store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex}, now=5)
        page = store.history(agent, lease["token"], "w", {peer.pubkey_hex}, now=6)
        assert len(page["items"]) == 2
        assert page["more"] is True
        next_page = store.history(agent, lease["token"], "w", {peer.pubkey_hex}, now=6, before=page["next_before"])
        assert len(next_page["items"]) == 2
        assert next_page["more"] is False


def test_work_discovery_survives_restart_without_a_remembered_peer(setup):
    _, _, agent, peer = setup
    with open_store(setup) as store:
        store.accept(agent, letter(peer, agent.pubkey), {peer.pubkey_hex}, now=1)
    with open_store(setup) as store:
        [work] = store.work({peer.pubkey_hex}, now=2)
        assert work["peer"] == peer.pubkey_hex
        assert work["pending"] == 1
        assert work["lease_active"] is False
        assert store.work(set(), now=2) == []


async def test_cancellation_leaves_durable_unknown(setup, monkeypatch):
    _, _, agent, peer = setup
    started = asyncio.Event()
    async def hang(event, **kwargs):
        started.set()
        await asyncio.Event().wait()
    monkeypatch.setattr(agent.relay, "publish", hang)
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex})
        store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "cancelled", "secret")
        task = asyncio.create_task(store.dispatch(agent, lease["token"], "w", {peer.pubkey_hex}, "cancelled"))
        await asyncio.wait_for(started.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    with open_store(setup) as store:
        existing = store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "cancelled", "secret")
        assert existing["state"] == "unknown"


async def test_late_sender_cannot_mark_success_after_takeover(setup, monkeypatch):
    api, _, agent, peer = setup
    clock = [10]
    monkeypatch.setattr(api.time, "time", lambda: clock[0])
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        old = store.acquire(peer.pubkey_hex, "old", allowed, lease_seconds=1)
        store.prepare_send(agent, old["token"], "old", allowed, "late", "hello")
        async def takeover(event, **kwargs):
            clock[0] = 12
            with open_store(setup) as second:
                new = second.acquire(peer.pubkey_hex, "new", allowed)
                with pytest.raises(InboxConflict):
                    second.prepare_send(agent, new["token"], "new", allowed, "another", "hello")
        monkeypatch.setattr(agent.relay, "publish", takeover)
        with pytest.raises(InboxConflict, match="stale"):
            await store.dispatch(agent, old["token"], "old", allowed, "late")
        assert store.db.execute("SELECT state FROM dialogue_outbox").fetchone()[0] == "unknown"


def test_outbox_capacity_failure_retains_existing_work(setup):
    _, _, agent, peer = setup
    with open_store(setup, max_items=1) as store:
        lease = store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex}, now=1)
        first = store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "one", "saved", now=2)
        with pytest.raises(InboxError, match="capacity"):
            store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "two", "unsaved", now=2)
        assert store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "one", "saved", now=2) == first


def test_database_full_rolls_back_before_any_possible_send(setup):
    _, _, agent, peer = setup
    with open_store(setup, max_bytes=65536) as store:
        lease = store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex}, now=1)
        with pytest.raises(InboxError, match="database"):
            store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "one", "z" * 32768, now=2)
        assert store.db.execute("SELECT COUNT(*) FROM dialogue_outbox").fetchone()[0] == 0
        assert store.db.execute("SELECT COUNT(*) FROM dialogue_history").fetchone()[0] == 0


def test_ciphertext_is_bound_to_conversation_and_operation(setup):
    _, path, agent, peer = setup
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex}, now=1)
        store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "one", "OUTGOING-SECRET-946", now=2)
        store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "two", "different", now=2)
        rows = store.db.execute("SELECT seq,local_body FROM dialogue_outbox ORDER BY seq").fetchall()
        store.db.execute("UPDATE dialogue_outbox SET local_body=? WHERE seq=?", (rows[1]["local_body"], rows[0]["seq"]))
        with pytest.raises(InboxConflict, match="binding"):
            store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "one", "OUTGOING-SECRET-946", now=2)
    for path in path.iterdir():
        if path.is_file():
            assert b"OUTGOING-SECRET-946" not in path.read_bytes()


@pytest.mark.parametrize("now", [True, float("nan"), float("inf"), -1, 10**1000])
def test_invalid_clock_fails_closed(setup, now):
    _, _, _, peer = setup
    with open_store(setup) as store:
        with pytest.raises(InboxError):
            store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex}, now=now)


def test_abrupt_process_exit_preserves_uncertain_send(setup):
    _, path, agent, peer = setup
    code = r'''
import os, socket, ipaddress
for method in ("connect", "connect_ex"):
    original = getattr(socket.socket, method)
    def local_only(self, address, _original=original):
        if not isinstance(address, tuple) or not ipaddress.ip_address(address[0]).is_loopback:
            raise AssertionError("crash probe prohibits external network")
        return _original(self, address)
    setattr(socket.socket, method, local_only)
from a4a import Agent, Keys
from a4a.dialogue import DialogueStore
import asyncio
agent = Agent(["ws://127.0.0.1:1/never"], keys=Keys(os.environ["SYNTHETIC_KEY"]))
peer = os.environ["SYNTHETIC_PEER"]
async def die_after_dispatch(event, **kwargs):
    os._exit(23)
agent.relay.publish = die_after_dispatch
with DialogueStore(os.environ["SYNTHETIC_STORE"], agent.pubkey, "general") as store:
    lease = store.acquire(peer, "dead-worker", {peer}, now=1, lease_seconds=2)
    store.prepare_send(agent, lease["token"], "dead-worker", {peer}, "crash-op", "survives termination", now=1)
    asyncio.run(store.dispatch(agent, lease["token"], "dead-worker", {peer}, "crash-op", now=1))
'''
    env = {**os.environ, "SYNTHETIC_KEY": agent.keys.privkey_hex,
           "SYNTHETIC_PEER": peer.pubkey_hex, "SYNTHETIC_STORE": str(path)}
    # Start the child with the boundary already installed. This used to be a bare
    # invocation, allowing the interpreter to access the network unchecked. It
    # needs no network here because publication is stubbed, and that claim is now
    # verified instead of assumed.
    result = guarded_child.run_guarded(code, env={k: v for k, v in env.items()
                                                  if k.startswith("SYNTHETIC_")}, timeout=20)
    assert result.returncode == 23, result.stderr.decode("utf-8", errors="replace")
    with open_store(setup) as store:
        assert store.db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        lease = store.acquire(peer.pubkey_hex, "replacement", {peer.pubkey_hex}, now=4)
        history = store.history(agent, lease["token"], "replacement", {peer.pubkey_hex}, now=4)
        assert history["items"][0]["state"] == "unknown"
        assert history["items"][0]["content"] == "survives termination"
        with pytest.raises(InboxConflict):
            store.prepare_send(agent, lease["token"], "replacement", {peer.pubkey_hex}, "next-op", "do not resend", now=4)


def test_peer_policy_and_worker_are_checked_on_each_operation(setup):
    _, _, agent, peer = setup
    with open_store(setup) as store:
        with pytest.raises(InboxError):
            store.acquire(peer.pubkey_hex, "worker", set(), now=1)
        lease = store.acquire(peer.pubkey_hex, "worker", {peer.pubkey_hex}, now=1)
        with pytest.raises(InboxError):
            store.history(agent, lease["token"], "intruder", {peer.pubkey_hex}, now=2)
        with pytest.raises(InboxError):
            store.history(agent, lease["token"], "worker", set(), now=2)


async def test_outgoing_prepared_before_network_and_never_resent_blindly(setup, monkeypatch):
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}
    calls = []
    async def failed(event, **kwargs):
        calls.append(event.id)
        raise OSError("simulated lost response")
    monkeypatch.setattr(agent.relay, "publish", failed)
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "one", allowed, now=1)
        prepared = store.prepare_send(agent, lease["token"], "one", allowed, "operation-1", "secret outgoing", now=2)
        assert calls == []
        with pytest.raises(OSError):
            await store.dispatch(agent, lease["token"], "one", allowed, "operation-1", now=3)
        assert len(calls) == 1
        again = store.prepare_send(agent, lease["token"], "one", allowed, "operation-1", "secret outgoing", now=4)
        assert again["state"] == "unknown"
        assert again["outer_id"] == prepared["outer_id"]
        await store.dispatch(agent, lease["token"], "one", allowed, "operation-1", now=4)
        assert len(calls) == 1
        with pytest.raises(InboxConflict):
            store.prepare_send(agent, lease["token"], "one", allowed, "operation-1", "different", now=5)
        with pytest.raises(InboxConflict):
            store.prepare_send(agent, lease["token"], "one", allowed, "operation-2", "another", now=5)


def test_unknown_incoming_requires_explicit_reconciliation(setup):
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        store.accept(agent, letter(peer, agent.pubkey), allowed, now=1)
        store.acquire(peer.pubkey_hex, "old", allowed, now=2, lease_seconds=1)
        lease = store.acquire(peer.pubkey_hex, "new", allowed, now=4)
        seq = store.history(agent, lease["token"], "new", allowed, now=4)["items"][0]["inbox_seq"]
        with pytest.raises(InboxConflict):
            store.finish_incoming(lease["token"], "new", allowed, seq, "processed", now=4)
        store.finish_incoming(lease["token"], "new", allowed, seq, "processed", reconciled=True, now=4)
        assert store.status(now=4)["processed"] == 1


async def test_reordering_the_relay_list_does_not_strand_prepared_letters(setup, monkeypatch):
    """Reordering relays preserves the same set in a different order.

    The journal stores the relay address under which a letter was prepared and
    compares it with the current one before sending. That was exact while clients
    used one relay. With fanout transport, `relay.url` is the FIRST relay in the
    set, so the check began answering a different question: not "is this the same
    set?" but "is the first list entry unchanged?"

    The owner-visible consequence: reordering relays in settings stranded prepared
    letters behind a manual review even though recipient, envelope, and relay set
    were unchanged.
    """
    api, path, agent, peer = setup
    urls = ["ws://127.0.0.1:1/never", "ws://127.0.0.1:2/never"]
    agent.relay = Agent(urls, keys=agent.keys).relay
    published = []

    async def publish(event, **kwargs):
        published.append(event)

    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex}, now=1)
        store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "op", "text", now=2)

        reordered = Agent(list(reversed(urls)), keys=agent.keys)
        monkeypatch.setattr(reordered.relay, "publish", publish)
        await store.dispatch(reordered, lease["token"], "w", {peer.pubkey_hex}, "op", now=3)

    assert len(published) == 1, "letter was stranded after relay-list reordering"


async def test_a_relay_set_without_the_preparing_node_is_still_refused(setup, monkeypatch):
    """Control for the prior case: relax ordering only, nothing else.

    Without this control, fixing reordering would be indistinguishable from removing
    the check entirely: both approaches make the preceding test pass.
    """
    api, path, agent, peer = setup
    agent.relay = Agent(["ws://127.0.0.1:1/never", "ws://127.0.0.1:2/never"],
                        keys=agent.keys).relay

    async def publish(event, **kwargs):
        raise AssertionError("letter was sent through a set missing its preparation relay")

    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex}, now=1)
        store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "op", "text", now=2)

        elsewhere = Agent(["ws://127.0.0.1:9/never"], keys=agent.keys)
        monkeypatch.setattr(elsewhere.relay, "publish", publish)
        with pytest.raises(InboxConflict, match="different relay"):
            await store.dispatch(elsewhere, lease["token"], "w", {peer.pubkey_hex}, "op", now=3)


async def test_adding_a_relay_after_preparation_is_refused(setup, monkeypatch):
    """An added relay is another operator seeing the envelope, not the same set.

    The check first compared the first relay, then membership. Membership catches a
    removed relay but permits additions: a letter prepared for one operator set
    would be sent through another without telling the owner. Content is encrypted,
    but who communicates with whom and when is not.
    """
    api, path, agent, peer = setup
    urls = ["ws://127.0.0.1:1/never", "ws://127.0.0.1:2/never"]
    agent.relay = Agent(urls, keys=agent.keys).relay

    async def publish(event, **kwargs):
        raise AssertionError("letter was sent to an operator absent during preparation")

    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex}, now=1)
        store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "op", "text", now=2)

        wider = Agent([*urls, "ws://127.0.0.1:9/never"], keys=agent.keys)
        monkeypatch.setattr(wider.relay, "publish", publish)
        with pytest.raises(InboxConflict, match="different relay"):
            await store.dispatch(wider, lease["token"], "w", {peer.pubkey_hex}, "op", now=3)


def test_legacy_row_is_accepted_only_for_the_very_same_single_relay(setup):
    """A legacy row stores one address, not a set, so reject expansion.

    The first version treated such a record as membership: a legacy row for relay A
    was considered valid for {A, B}. This allowed adding an operator when the
    original set was unknown. Unknown is not permission: prepare the letter again
    for the current set so the owner sees that the composition changed.
    """
    api, path, agent, peer = setup
    single = Agent(["ws://127.0.0.1:1/never"], keys=agent.keys)
    assert api._same_relay_set("ws://127.0.0.1:1/never", single)
    assert not api._same_relay_set("ws://127.0.0.1:5/never", single)

    pair = Agent(["ws://127.0.0.1:1/never", "ws://127.0.0.1:2/never"], keys=agent.keys)
    assert not api._same_relay_set("ws://127.0.0.1:1/never", pair), (
        "legacy row allowed a set it contains no information about")


async def test_legacy_prepared_row_names_safe_abandon_and_reprepare_path(
    setup, monkeypatch,
):
    """A legacy refusal must tell an operator how to resolve prepared work."""
    _, _, original, peer = setup
    allowed = {peer.pubkey_hex}
    legacy_url = original.relay.clients[0].url
    expanded = Agent([legacy_url, "ws://127.0.0.1:2/never"], keys=original.keys)
    calls = []

    async def publish(event, **kwargs):
        calls.append((event.id, kwargs))
        return 2

    monkeypatch.setattr(expanded.relay, "publish", publish)
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        prepared = store.prepare_send(
            original, lease["token"], "worker", allowed,
            "legacy-prepared", "prepared with legacy relay metadata", now=2,
        )
        make_outbox_legacy(store, original, "legacy-prepared", legacy_url)
        with pytest.raises(
            InboxConflict,
            match="legacy single-relay operation.*different relay set.*abandon",
        ):
            await store.dispatch(
                expanded, lease["token"], "worker", allowed,
                "legacy-prepared", now=3,
            )
        assert calls == []
        abandoned = store.abandon(
            expanded, lease["token"], "worker", allowed,
            "legacy-prepared", now=3,
        )
        assert abandoned == {**prepared, "state": "abandoned"}
        replacement = store.prepare_send(
            expanded, lease["token"], "worker", allowed,
            "current-set", "prepared explicitly for current relay set", now=4,
        )
        sent = await store.dispatch(
            expanded, lease["token"], "worker", allowed,
            "current-set", now=5,
        )
        assert sent == {**replacement, "state": "relay_accepted"}
        assert calls == [(
            replacement["outer_id"], {"replay_on_reconnect": False},
        )]
        assert [item["state"] for item in store.history(
            expanded, lease["token"], "worker", allowed, now=6,
        )["items"]] == ["relay_accepted", "abandoned"]


async def test_legacy_unknown_row_names_restore_and_reconcile_path(
    setup, monkeypatch,
):
    """Legacy uncertainty cannot be abandoned or inspected through a new set."""
    from a4a.relay import QueryResult

    _, _, original, peer = setup
    allowed = {peer.pubkey_hex}
    legacy_url = original.relay.clients[0].url
    expanded = Agent([legacy_url, "ws://127.0.0.1:2/never"], keys=original.keys)
    accepted = []

    async def accepted_but_lost(event, **kwargs):
        accepted.append(event)
        raise ConnectionError("lost legacy result")

    monkeypatch.setattr(original.relay, "publish", accepted_but_lost)
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        prepared = store.prepare_send(
            original, lease["token"], "worker", allowed,
            "legacy-unknown", "uncertain legacy message", now=2,
        )
        make_outbox_legacy(store, original, "legacy-unknown", legacy_url)
        with pytest.raises(ConnectionError, match="lost legacy result"):
            await store.dispatch(
                original, lease["token"], "worker", allowed,
                "legacy-unknown", now=3,
            )
        async def no_changed_query(*args, **kwargs):
            raise AssertionError("legacy uncertainty queried the changed set")
        monkeypatch.setattr(expanded.relay, "query_bounded", no_changed_query)
        with pytest.raises(
            InboxConflict,
            match="uncertain legacy single-relay operation.*restore.*cannot be abandoned",
        ):
            await store.reconcile(
                expanded, lease["token"], "worker", allowed,
                "legacy-unknown", now=4,
            )
        with pytest.raises(InboxConflict, match="only a prepared operation"):
            store.abandon(
                expanded, lease["token"], "worker", allowed,
                "legacy-unknown", now=4,
            )

        async def observed(*args, **kwargs):
            return QueryResult(accepted, 1, 0, False)
        monkeypatch.setattr(original.relay, "query_bounded", observed)
        receipt = await store.reconcile(
            original, lease["token"], "worker", allowed,
            "legacy-unknown", now=5,
        )
        assert receipt == {**prepared, "state": "relay_observed"}


async def test_missing_outbox_operation_has_unambiguous_diagnostic(setup):
    """Missing and relay-mismatched operations require different remedies."""
    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}
    with open_store(setup) as store:
        lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1)
        with pytest.raises(InboxConflict, match=r"^outgoing operation is missing$"):
            await store.dispatch(
                agent, lease["token"], "worker", allowed, "missing", now=2)
        with pytest.raises(InboxConflict, match=r"^outgoing operation is missing$"):
            await store.reconcile(
                agent, lease["token"], "worker", allowed, "missing", now=2)


def test_a_fresh_single_relay_record_is_not_mistaken_for_a_legacy_row(setup):
    """A fresh ONE-relay record must not be mistaken for a legacy row.

    Delimiter-based encoding failed here: a one-address set has no delimiter, so
    its record looked legacy and was checked by membership. A letter prepared for
    relay A could then be sent through {A, B}, silently adding an operator absent
    during preparation. The most common case reintroduced the gap.
    """
    api, path, agent, peer = setup
    one = Agent(["ws://127.0.0.1:1/never"], keys=agent.keys)
    fresh = api._relay_fingerprint(one)
    assert fresh != "ws://127.0.0.1:1/never", "fingerprint is indistinguishable from a legacy row"

    wider = Agent(["ws://127.0.0.1:1/never", "ws://127.0.0.1:2/never"], keys=agent.keys)
    assert not api._same_relay_set(fresh, wider), (
        "fresh one-relay record accepted a two-relay set and added an operator")


@pytest.mark.parametrize("prepared, current, same", [
    (["ws://a"], ["ws://a"], True),
    (["ws://a"], ["ws://a", "ws://b"], False),                 # addition
    (["ws://a", "ws://b"], ["ws://a", "ws://b", "ws://c"], False),
    (["ws://a", "ws://b"], ["ws://a"], False),                 # removal
    (["ws://a", "ws://b"], ["ws://b", "ws://a"], True),        # reordering
], ids=["same", "1->2", "2->3", "removal", "reordering"])
def test_relay_set_equality_covers_addition_removal_and_order(setup, prepared, current, same):
    """Set equality ignores order but preserves composition in both directions."""
    api, path, agent, _peer = setup
    recorded = api._relay_fingerprint(Agent(prepared, keys=agent.keys))
    assert api._same_relay_set(recorded, Agent(current, keys=agent.keys)) is same


@pytest.mark.parametrize(("prepared_urls", "changed_urls"), [
    (["ws://a", "ws://b"], ["ws://a"]),
    (["ws://a"], ["ws://a", "ws://b"]),
], ids=["removal", "addition"])
async def test_unknown_send_requires_original_relay_set_before_reprepare(
    setup, monkeypatch, prepared_urls, changed_urls,
):
    """A configuration change must not reinterpret an uncertain network result.

    Reconciliation queries reveal communication metadata too. Querying an added node
    is therefore not safer than publishing to it, while querying only retained nodes
    silently narrows the investigation and cannot inspect copies on removed siblings.
    Restore the recorded set, reconcile there, and only then use the new set.
    """
    from a4a.relay import QueryResult

    _, _, agent, peer = setup
    allowed = {peer.pubkey_hex}
    prepared_agent = Agent(prepared_urls, keys=agent.keys)
    changed_agent = Agent(changed_urls, keys=agent.keys)
    accepted = []

    async def accepted_but_result_lost(event, **kwargs):
        accepted.append(event)
        raise ConnectionError("relay accepted before response was lost")

    monkeypatch.setattr(prepared_agent.relay, "publish", accepted_but_result_lost)
    with open_store(setup) as store:
        old = store.acquire(peer.pubkey_hex, "old", allowed, now=1, lease_seconds=10)
        prepared = store.prepare_send(
            prepared_agent, old["token"], "old", allowed,
            "uncertain-before-change", "uncertain across relay-set change", now=2,
        )
        with pytest.raises(ConnectionError, match="response was lost"):
            await store.dispatch(
                prepared_agent, old["token"], "old", allowed,
                "uncertain-before-change", now=3,
            )
        assert len(accepted) == 1 and accepted[0].id == prepared["outer_id"]
        assert store.release(old["token"], "old", allowed, now=4) == {
            "state": "released",
        }

        replacement = store.acquire(peer.pubkey_hex, "new", allowed, now=5)
        changed_network = []

        async def changed_publish(*args, **kwargs):
            changed_network.append("publish")
            raise AssertionError("changed relay set published uncertain work")

        async def changed_query(*args, **kwargs):
            changed_network.append("query")
            raise AssertionError("changed relay set queried uncertain work")

        monkeypatch.setattr(changed_agent.relay, "publish", changed_publish)
        monkeypatch.setattr(changed_agent.relay, "query_bounded", changed_query)
        with pytest.raises(InboxConflict, match="different relay"):
            await store.dispatch(
                changed_agent, replacement["token"], "new", allowed,
                "uncertain-before-change", now=6,
            )
        with pytest.raises(InboxConflict, match="different relay"):
            await store.reconcile(
                changed_agent, replacement["token"], "new", allowed,
                "uncertain-before-change", now=6,
            )
        assert changed_network == []
        with pytest.raises(InboxConflict, match="only a prepared operation"):
            store.abandon(
                changed_agent, replacement["token"], "new", allowed,
                "uncertain-before-change", now=6,
            )
        with pytest.raises(InboxConflict, match="requires reconciliation"):
            store.prepare_send(
                changed_agent, replacement["token"], "new", allowed,
                "must-wait", "must not overtake uncertain work", now=6,
            )

        async def observed_on_original_set(*args, **kwargs):
            return QueryResult([accepted[0]], 1, 0, False,
                               relays_responded=len(prepared_urls))

        monkeypatch.setattr(
            prepared_agent.relay, "query_bounded", observed_on_original_set)
        reconciled = await store.reconcile(
            prepared_agent, replacement["token"], "new", allowed,
            "uncertain-before-change", now=7,
        )
        assert reconciled == {**prepared, "state": "relay_observed"}

        sent = []

        async def publish_new(event, **kwargs):
            sent.append((event, kwargs))
            return len(changed_urls)

        monkeypatch.setattr(changed_agent.relay, "publish", publish_new)
        next_operation = store.prepare_send(
            changed_agent, replacement["token"], "new", allowed,
            "after-reconcile", "new work uses the changed relay set", now=8,
        )
        result = await store.dispatch(
            changed_agent, replacement["token"], "new", allowed,
            "after-reconcile", now=9,
        )
        assert result == {**next_operation, "state": "relay_accepted"}
        assert [(event.id, kwargs) for event, kwargs in sent] == [(
            next_operation["outer_id"], {"replay_on_reconnect": False},
        )]
