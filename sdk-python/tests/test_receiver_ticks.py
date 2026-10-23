"""Offline receiver ticks share ownership, recovery, and joined stream cleanup."""
import asyncio
import contextlib

import network_guard
import pytest
import pytest_asyncio

from a4a import Agent, Keys, giftwrap, types
from a4a.event import Event
from a4a.inbox import InboxError, InboxPolicyChanged, InboxStore
from a4a.inbox_lock import receiver_lock
from a4a.inbox_receiver import InboxReceiver
from a4a import inbox_receiver


@pytest_asyncio.fixture(autouse=True)
async def no_network():
    """These tests must remain fully offline, and the complete boundary is enforced.

    A local `socket.connect` stub previously guarded only one of four paths: async
    connections, datagrams, and name resolution bypassed the assertion. One boundary
    now protects the entire run.
    """
    with network_guard.no_network("receiver tick tests prohibit network"):
        yield


@pytest.fixture
def mailbox(tmp_path):
    agent = Agent(["ws://127.0.0.1:1/never"], keys=Keys())
    peer = Keys()
    with InboxStore(tmp_path / "inbox", agent.pubkey, "test") as store:
        yield store, agent, peer, {peer.pubkey_hex}


def envelope(mailbox):
    _, agent, peer, _ = mailbox
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, tags=[["p", agent.pubkey]],
                  content="local retained secret").sign(peer)
    return giftwrap.wrap(inner, agent.pubkey, peer)


class EmptyHistory:
    async def page(self, cursor):
        return []


def receiver(mailbox, history=None, **kwargs):
    store, agent, _, allowed = mailbox
    watcher = InboxReceiver(agent, store, lambda: allowed, start_after=0,
                            history=history or EmptyHistory(), **kwargs)
    started, closed = asyncio.Event(), asyncio.Event()

    async def stream():
        try:
            started.set()
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            closed.set()

    watcher._stream_hints = stream
    return watcher, started, closed


async def cancel(task):
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.parametrize("has_work", [False, True])
async def test_every_hint_and_timer_ticks_even_when_notice_is_suppressed(mailbox, has_work):
    store, agent, _, allowed = mailbox
    if has_work:
        assert store.accept(agent, envelope(mailbox), allowed) == "stored"
        assert store.notice(allowed, per_hour=1)
    budget_before = [tuple(row) for row in store.db.execute("SELECT * FROM wakeups")]
    watcher, started, closed = receiver(mailbox)
    # Shorten only this test instance's timer; public validation stays unchanged.
    watcher.poll_seconds = .01
    observations = []
    done = asyncio.Event()

    async def callback():
        await started.wait()
        observations.append(store.work_snapshot(allowed))
        if len(observations) == 1:
            watcher.hint.set()
        if len(observations) == 3:
            done.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(watcher.run_ticks(callback))
    try:
        await asyncio.wait_for(done.wait(), 1)
        assert len(observations) == 3
        assert all(value["notice"]["pending"] == int(has_work) for value in observations)
        assert [tuple(row) for row in store.db.execute("SELECT * FROM wakeups")] == budget_before
    finally:
        await cancel(task)
    assert closed.is_set()
    assert store.health()["state"] == "stopped"


async def test_relay_errors_still_tick_local_work_and_retain_failed_health(mailbox):
    store, agent, _, allowed = mailbox
    assert store.accept(agent, envelope(mailbox), allowed) == "stored"
    calls = []

    class Outage:
        async def page(self, cursor):
            calls.append(cursor)
            raise InboxError("synthetic relay outage")

    watcher, started, closed = receiver(mailbox, Outage())
    done = asyncio.Event()
    snapshots = []

    async def callback():
        await started.wait()
        snapshots.append(store.work_snapshot(allowed))
        if len(snapshots) == 2:
            done.set()
            await asyncio.Event().wait()
        watcher.hint.set()

    task = asyncio.create_task(watcher.run_ticks(callback))
    try:
        await asyncio.wait_for(done.wait(), 1)
        assert calls == [(0, ""), (0, "")]
        assert len(snapshots) == 2 and snapshots[0] == snapshots[1]
        assert snapshots[0]["notice"]["pending"] == 1
        assert store.db.execute("SELECT count(*) FROM wakeups").fetchone()[0] == 0
    finally:
        await cancel(task)
    assert closed.is_set()
    assert store.health()["state"] == "failed"


async def test_reception_history_is_bounded_per_tick_and_callback_sees_commits(mailbox):
    store, agent, _, allowed = mailbox
    event = envelope(mailbox)
    calls = []

    class History:
        async def page(self, cursor):
            calls.append(cursor)
            return [(cursor[0] + 1, event)]

    watcher, started, _ = receiver(mailbox, History(), max_pages=2)
    done = asyncio.Event()

    async def callback():
        await started.wait()
        assert len(calls) == 2
        assert store.cursor(agent.relay.url) == (2, event.id)
        assert not store.db.in_transaction
        assert store.work_snapshot(allowed)["notice"]["pending"] == 1
        assert store.health()["state"] == "backlog"
        done.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(watcher.run_ticks(callback))
    try:
        await asyncio.wait_for(done.wait(), 1)
    finally:
        await cancel(task)


@pytest.mark.parametrize("competitor", ["ticks", "notices", "sync", "once"])
async def test_tick_owner_excludes_every_receiver_entry_point(mailbox, competitor):
    store, _, _, _ = mailbox
    watcher, started, _ = receiver(mailbox)
    other, _, _ = receiver(mailbox)
    entered = asyncio.Event()

    async def callback():
        await started.wait()
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(watcher.run_ticks(callback))
    try:
        await asyncio.wait_for(entered.wait(), 1)
        health = store.health()
        with pytest.raises(InboxError, match="receiver"):
            if competitor == "ticks":
                await watcher.run_ticks(callback)
            elif competitor == "notices":
                async with contextlib.aclosing(other.notices()) as source:
                    await anext(source)
            elif competitor == "sync":
                await other.sync_once()
            else:
                await other.notice_once()
        assert store.health() == health
    finally:
        await cancel(task)
    assert await other.sync_once() == 0


@pytest.mark.parametrize("once", [False, True])
@pytest.mark.parametrize("error", [InboxError, InboxPolicyChanged, ValueError])
async def test_callback_errors_propagate_and_preserve_failed_health(mailbox, error, once):
    store, _, _, _ = mailbox
    watcher, started, closed = receiver(mailbox)

    async def callback():
        await started.wait()
        raise error("synthetic callback failure")

    with pytest.raises(error, match="synthetic callback failure"):
        await asyncio.wait_for(watcher.run_ticks(callback, once=once), 1)
    assert closed.is_set()
    assert store.health()["state"] == "failed"
    with receiver_lock(store.path.parent):
        pass


@pytest.mark.parametrize("error", [InboxError, InboxPolicyChanged, ValueError])
@pytest.mark.parametrize("rows", [False, True])
async def test_policy_errors_are_fatal_with_or_without_history_rows(mailbox, error, rows):
    store, _, _, _ = mailbox
    event = envelope(mailbox)

    class History:
        async def page(self, cursor):
            await started.wait()
            return [(1, event)] if rows else []

    watcher, started, closed = receiver(mailbox, History())
    callbacks = []

    def policy():
        raise error("synthetic policy failure")

    async def callback():
        callbacks.append(True)

    watcher.allowed_senders = policy
    with pytest.raises(error):
        await asyncio.wait_for(watcher.run_ticks(callback), 1)
    assert not callbacks
    assert closed.is_set()
    assert store.cursor(watcher.url) == (0, "")
    assert store.health()["state"] == "failed"


@pytest.mark.parametrize("phase", ["history", "callback", "idle"])
async def test_cancellation_joins_stream_before_releasing_lock(mailbox, phase):
    store, _, _, _ = mailbox
    entered, cleaning, release_cleanup, closed = [asyncio.Event() for _ in range(4)]

    class History:
        async def page(self, cursor):
            await started.wait()
            if phase == "history":
                entered.set()
                await asyncio.Event().wait()
            return []

    watcher, started, _ = receiver(mailbox, History())

    async def stream():
        try:
            started.set()
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release_cleanup.wait()
            closed.set()

    async def callback():
        entered.set()
        if phase == "callback":
            await asyncio.Event().wait()

    watcher._stream_hints = stream
    task = asyncio.create_task(watcher.run_ticks(callback))
    try:
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        await asyncio.wait_for(cleaning.wait(), 1)
        assert not task.done()
        with pytest.raises(InboxError, match="receiver"):
            with receiver_lock(store.path.parent):
                pass
    finally:
        release_cleanup.set()
        if not task.cancelling():
            task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert closed.is_set()
    assert store.health()["state"] == "stopped"
    with receiver_lock(store.path.parent):
        pass


async def test_tick_stream_uses_bounded_ws_hints_and_closes_subscription(mailbox, monkeypatch):
    store, agent, _, _ = mailbox
    delivered, closed = asyncio.Event(), asyncio.Event()
    event = envelope(mailbox)
    filters_seen, relays = [], []

    class Relay:
        def __init__(self, url):
            assert url == agent.relay.url
            relays.append(self)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            closed.set()

        async def subscribe(self, filters):
            filters_seen.append(filters)
            yield event
            delivered.set()
            await asyncio.Event().wait()

    monkeypatch.setattr(inbox_receiver, "RelayClient", Relay)
    watcher = InboxReceiver(agent, store, lambda: set(), start_after=0, history=EmptyHistory())
    callbacks = []
    done = asyncio.Event()

    async def callback():
        callbacks.append(True)
        if len(callbacks) == 2:
            done.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(watcher.run_ticks(callback))
    try:
        await asyncio.wait_for(done.wait(), 3)
        assert delivered.is_set()
        assert len(relays) == 1 and relays[0].MAX_QUEUED_EVENTS == 8
        assert filters_seen == [{"kinds": [1059, 31033], "#p": [agent.pubkey], "limit": 0}]
    finally:
        await cancel(task)
    assert closed.is_set()
    assert watcher.stream_connected is False


@pytest.mark.parametrize("outage", [False, True])
async def test_once_holds_lock_through_sync_callback_and_health_cleanup(mailbox, monkeypatch, outage):
    store, _, _, allowed = mailbox
    phases = []

    def assert_owned():
        with pytest.raises(InboxError, match="receiver"):
            with receiver_lock(store.path.parent):
                pass

    class History:
        async def page(self, cursor):
            assert_owned()
            phases.append("sync")
            if outage:
                raise InboxError("synthetic outage")
            return []

    watcher, started, closed = receiver(mailbox, History())
    set_health = store.set_health

    def health(state, **kwargs):
        assert_owned()
        if state == "stopped":
            assert closed.is_set()
            phases.append("cleanup")
        return set_health(state, **kwargs)

    async def callback():
        await started.wait()
        assert_owned()
        phases.append("callback")
        with store._transaction():
            assert store._work_snapshot(allowed, 10)["fingerprint"] is None
        watcher.hint.set()

    monkeypatch.setattr(store, "set_health", health)
    assert await asyncio.wait_for(watcher.run_ticks(callback, once=True), 1) is None
    assert phases == (["sync", "callback"] if outage else ["sync", "callback", "cleanup"])
    assert closed.is_set()
    assert store.health()["state"] == ("failed" if outage else "stopped")
    with receiver_lock(store.path.parent):
        pass


@pytest.mark.parametrize("once", [False, True])
async def test_cancellation_during_shutdown_still_joins_stream(mailbox, once):
    store, _, _, _ = mailbox
    watcher, started, _ = receiver(mailbox)
    called, cleaning, release_cleanup, closed = [asyncio.Event() for _ in range(4)]

    async def stream():
        try:
            started.set()
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release_cleanup.wait()
            closed.set()

    async def callback():
        await started.wait()
        called.set()

    watcher._stream_hints = stream
    task = asyncio.create_task(watcher.run_ticks(callback, once=once))
    try:
        await asyncio.wait_for(called.wait(), 1)
        if not once:
            task.cancel()
        await asyncio.wait_for(cleaning.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(task), .02)
        with pytest.raises(InboxError, match="receiver"):
            with receiver_lock(store.path.parent):
                pass
    finally:
        release_cleanup.set()
        await asyncio.gather(task, return_exceptions=True)
    assert closed.is_set()
    assert task.cancelled()
    assert store.health()["state"] == "stopped"
