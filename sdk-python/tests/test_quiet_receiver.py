"""Receiver attachment lifecycle with synthetic local work and blocked sockets."""
import asyncio
import contextlib

import network_guard
import pytest
import pytest_asyncio

from a4a import Agent, Keys, giftwrap, types
from a4a.event import Event
from a4a import inbox
from a4a.inbox_receiver import InboxReceiver


@pytest_asyncio.fixture(autouse=True)
async def no_network():
    """These tests must remain fully offline, and the complete boundary is enforced.

    A local `socket.connect` stub previously guarded only one of four paths: async
    connections, datagrams, and name resolution bypassed the assertion. One boundary
    now protects the entire run.
    """
    with network_guard.no_network("quiet receiver tests prohibit network"):
        yield


@pytest.fixture
def setup(tmp_path, monkeypatch):
    agent = Agent(["ws://127.0.0.1:1/never"], keys=Keys())
    peer = Keys()
    tick = [100]
    monkeypatch.setattr(inbox, "_now", lambda value: tick[0] if value is None else value)
    with inbox.InboxStore(tmp_path / "inbox", agent.pubkey, "test") as store:
        def add(delivery):
            inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                          tags=[["p", agent.pubkey], ["d", delivery]], content="secret").sign(peer)
            store.accept(agent, giftwrap.wrap(inner, agent.pubkey, peer), {peer.pubkey_hex})
        yield store, agent, {peer.pubkey_hex}, add, tick


def receiver(setup, history):
    store, agent, allowed, _, _ = setup
    result = InboxReceiver(agent, store, lambda: allowed, start_after=0, history=history)
    async def stream():
        await asyncio.Event().wait()
    result._stream_hints = stream
    return result


@pytest.mark.parametrize("mode", ["once", "stream"])
async def test_tick_callback_runs_before_notice(setup, mode):
    _, _, _, add, _ = setup
    add("one")

    class History:
        async def page(self, cursor):
            return []

    watcher = receiver(setup, History())
    calls = []

    async def on_tick():
        calls.append("tick")

    if mode == "once":
        notice = await watcher.notice_once(on_tick=on_tick)
    else:
        async with contextlib.aclosing(watcher.notices(on_tick=on_tick)) as source:
            notice = await anext(source)
    assert notice["pending"] == 1
    assert calls == ["tick"]


async def test_one_attachment_signals_changes_not_every_recovery(setup):
    store, _, _, add, tick = setup
    add("one")
    calls = []
    class History:
        async def page(self, cursor):
            calls.append(cursor)
            tick[0] += 60
            if len(calls) == 4:
                add("two")
            watcher.hint.set()
            return []
    watcher = receiver(setup, History())
    async with contextlib.aclosing(watcher.notices()) as source:
        assert (await anext(source))["pending"] == 1
        assert (await asyncio.wait_for(anext(source), 2))["pending"] == 2
        assert len(calls) == 4
    assert store.health()["state"] == "stopped"


@pytest.mark.parametrize("competitor", ["sync", "iterator", "same_object", "once"])
async def test_competitor_fails_before_network_or_health_change(setup, competitor):
    store, _, _, add, _ = setup
    add("one")
    calls = []
    class History:
        async def page(self, cursor):
            calls.append(cursor)
            return []
    first = receiver(setup, History())
    second = first if competitor == "same_object" else receiver(setup, History())
    async with contextlib.aclosing(first.notices()) as source:
        assert await anext(source)
        health = store.health()
        with pytest.raises(inbox.InboxError, match="receiver"):
            if competitor == "iterator":
                async with contextlib.aclosing(second.notices()) as other:
                    await asyncio.wait_for(anext(other), .5)
            elif competitor == "once":
                await second.notice_once()
            else:
                await second.sync_once()
        assert len(calls) == 1
        assert store.health() == health
    assert await second.sync_once() == 0


async def test_cancel_idle_receiver_releases_ownership(setup):
    entered = asyncio.Event()
    class History:
        async def page(self, cursor):
            entered.set()
            return []
    watcher = receiver(setup, History())
    source = watcher.notices()
    pending = asyncio.create_task(anext(source))
    try:
        await asyncio.wait_for(entered.wait(), 1)
    finally:
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        await source.aclose()
    assert await watcher.sync_once() == 0


async def test_reconnect_can_reannounce_retained_work(setup):
    _, _, _, add, tick = setup
    add("one")
    class History:
        async def page(self, cursor):
            return []
    watcher = receiver(setup, History())
    async with contextlib.aclosing(watcher.notices()) as source:
        first = await anext(source)
    tick[0] += 60
    async with contextlib.aclosing(watcher.notices()) as source:
        assert await anext(source) == first


async def test_local_work_is_not_hidden_by_history_outage(setup):
    store, _, _, add, _ = setup
    add("one")
    class History:
        async def page(self, cursor):
            raise inbox.InboxError("synthetic history outage")
    watcher = receiver(setup, History())
    async with contextlib.aclosing(watcher.notices()) as source:
        assert (await asyncio.wait_for(anext(source), .5))["pending"] == 1
    assert store.health()["state"] == "failed"


async def test_repeated_outages_and_unchanged_mail_emit_no_second_hint(setup):
    store, _, _, add, tick = setup
    add("one")
    attempts = 0
    observed = asyncio.Event()
    class History:
        async def page(self, cursor):
            nonlocal attempts
            attempts += 1
            tick[0] += 60
            if attempts == 4:
                observed.set()
                await asyncio.Event().wait()
            watcher.hint.set()
            raise inbox.InboxError("synthetic repeated outage")
    watcher = receiver(setup, History())
    async with contextlib.aclosing(watcher.notices()) as source:
        assert (await anext(source))["pending"] == 1
        pending = asyncio.create_task(anext(source))
        try:
            await asyncio.wait_for(observed.wait(), 1)
            assert not pending.done()
            assert store.db.execute("SELECT count FROM wakeups").fetchone()[0] == 1
        finally:
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending


async def test_unexpected_source_failure_releases_lock(setup):
    class History:
        async def page(self, cursor):
            raise ValueError("synthetic programming failure")
    watcher = receiver(setup, History())
    async with contextlib.aclosing(watcher.notices()) as source:
        with pytest.raises(ValueError, match="synthetic"):
            await anext(source)
    # The next failure is the history error, not ownership contention.
    with pytest.raises(ValueError, match="synthetic"):
        await watcher.sync_once()
