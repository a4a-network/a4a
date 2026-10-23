"""Failed publishing-context entry owns cleanup, including cancellation."""
import asyncio

import pytest

from a4a_mcp import server


class _ConnectionFixture:
    def __init__(self):
        self.entered = 0
        self.closed = 0

    async def __aenter__(self):
        self.entered += 1
        return self

    async def __aexit__(self, *exc):
        self.closed += 1


def _bind(monkeypatch, connection, lookup):
    monkeypatch.setattr(server, "_make_agent", lambda: connection)
    monkeypatch.setattr(server, "_mandate_auto", lambda: False)
    monkeypatch.setattr(server, "_mandate_days", lambda: 30)
    monkeypatch.setattr(server, "_find_existing_mandate", lookup)


async def test_cancel_during_mandate_lookup_closes_entered_agent(monkeypatch):
    connection = _ConnectionFixture()
    started = asyncio.Event()

    async def lookup(_agent, *, republish=False):
        assert republish is True
        started.set()
        await asyncio.Future()

    _bind(monkeypatch, connection, lookup)
    body_entered = False

    async def caller():
        nonlocal body_entered
        async with server._mandated():
            body_entered = True

    task = asyncio.create_task(caller())
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    assert not body_entered
    assert connection.entered == 1
    assert connection.closed == 1


async def test_lookup_failure_closes_agent_and_preserves_error(monkeypatch):
    connection = _ConnectionFixture()
    original = RuntimeError("lookup failed")

    async def lookup(_agent, *, republish=False):
        assert republish is True
        raise original

    _bind(monkeypatch, connection, lookup)
    with pytest.raises(RuntimeError) as caught:
        async with server._mandated():
            pytest.fail("failed lookup must not enter the tool body")
    assert caught.value is original
    assert connection.entered == 1
    assert connection.closed == 1


async def test_successful_entry_closes_only_after_tool_body(monkeypatch):
    connection = _ConnectionFixture()

    async def lookup(_agent, *, republish=False):
        assert republish is True
        return "a" * 64

    _bind(monkeypatch, connection, lookup)
    async with server._mandated() as entered:
        assert entered is connection
        assert entered.delegation_id == "a" * 64
        assert connection.closed == 0
    assert connection.entered == 1
    assert connection.closed == 1
