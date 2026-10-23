"""Recover from actual SDK transport failure without hiding local state faults."""
import asyncio
import logging

import pytest
from a4a.keys import Keys
from a4a.relay import RelayError, RelayUnreachable
from a4a_notary import __main__ as entrypoint


@pytest.fixture
def config(tmp_path, monkeypatch):
    # Keep the disposable signing key in memory, never in retained test files.
    monkeypatch.setattr(entrypoint, "load_or_create_keys", lambda path: Keys())
    return {"relay_url": "ws://127.0.0.1:1", "public_url": "ws://127.0.0.1:1",
            "key_file": tmp_path / "unused.key", "db": tmp_path / "notary.db",
            "interval": 1, "calendars": []}


async def test_once_handles_actual_unreachable_sdk_connection(config, caplog):
    # Real RelayClient wraps ConnectionRefusedError in RelayUnreachable. A fake
    # raising ConnectionError would miss the entrypoint defect this reproduces.
    with caplog.at_level(logging.WARNING, logger="a4a.notary"):
        assert await entrypoint.main_loop(config, once=True) == 0
    assert "pass failed:" in caplog.text
    assert "could not connect to relay" in caplog.text
    assert not config["key_file"].exists()


async def test_daemon_retries_after_sdk_transport_failure(config, monkeypatch, caplog):
    calls = []
    sleeps = []

    async def one_pass(cfg, keys, store):
        calls.append(cfg)
        if len(calls) == 1:
            raise RelayUnreachable("fixture connection lost")
        return {"processed": 0}

    async def sleep(delay):
        sleeps.append(delay)
        if len(sleeps) == 2:
            raise asyncio.CancelledError()

    monkeypatch.setattr(entrypoint, "one_pass", one_pass)
    monkeypatch.setattr(entrypoint.asyncio, "sleep", sleep)
    with caplog.at_level(logging.WARNING, logger="a4a.notary"):
        with pytest.raises(asyncio.CancelledError):
            await entrypoint.main_loop(config, once=False)
    assert len(calls) == 2 and len(sleeps) == 2
    assert all(delay >= 1 for delay in sleeps)
    assert caplog.text.count("pass failed:") == 1


async def test_semantic_relay_rejection_remains_fatal(config, monkeypatch):
    failure = RelayError("fixture event rejected", reason="invalid: mandate")

    async def one_pass(*args):
        raise failure

    monkeypatch.setattr(entrypoint, "one_pass", one_pass)
    with pytest.raises(RelayError) as raised:
        await entrypoint.main_loop(config, once=True)
    assert raised.value is failure


async def test_local_state_failure_remains_fatal(config, monkeypatch):
    failure = OSError("fixture state cannot be opened")

    def open_store(path):
        raise failure

    monkeypatch.setattr(entrypoint, "Store", open_store)
    with pytest.raises(OSError) as raised:
        await entrypoint.main_loop(config, once=True)
    assert raised.value is failure
