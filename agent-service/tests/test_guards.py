"""Project-agent guards previously missed by the suite (mutation pass, 2026-08-29).

The pass disabled each ``if ...: raise`` branch and each filter one at a time,
then ran the full suite. Three mutations survived, meaning no test would have
noticed if those guards were absent.
"""
import asyncio
import json

import pytest
from a4a.agent import Agent

from a4a_agent import config, service
from a4a_agent.config import Config
from a4a_agent.policy import Policy
from a4a_agent.service import ProjectAgent
from tests.fake_relay import FakeRelay


@pytest.fixture(autouse=True)
def agent_home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_AGENT_HOME", str(tmp_path / "home"))


def test_negative_number_in_config_is_refused(monkeypatch):
    """A negative threshold or interval is a typo, not zero or disabled.

    Accepting one silently gives the agent behavior nobody intended: a negative
    sleep interval creates a loop without pauses, while a negative window keeps
    inbound messages from being read at all. Settings are read from the
    environment at startup, which is the only point where this error can be
    reported clearly.
    """
    monkeypatch.setenv("A4A_TEST_NUMBER", "-5")
    with pytest.raises(ValueError, match="negative"):
        config._num("A4A_TEST_NUMBER", 10, int)


def test_seen_journal_ignores_non_string_entries(tmp_path):
    """The processed-event journal lives on disk and survives restarts.

    The file may be corrupt or replaced, and its list may contain arbitrary
    values. A non-string entry later compared with an event ID can never match,
    so an already processed message would be handled again: the owner would get
    a duplicate notification and the sender a duplicate response.
    """
    path = tmp_path / "seen.json"
    path.write_text(json.dumps(["ok-id", None, 42, {"a": 1}, "other-id"]),
                    encoding="utf-8")
    journal = service.ProcessedLog(path)
    assert "ok-id" in journal and "other-id" in journal
    assert 42 not in journal._ids and None not in journal._ids


async def test_serve_stops_loudly_when_a_background_loop_dies(monkeypatch):
    """A failed background loop must stop the service loudly.

    The inbound-message and connection-request loops are the agent's core work.
    If one dies while the service remains alive, everything looks healthy from
    outside: the process exists and the address is published, but nobody reads
    network requests. That silence is worse than a crash because the owner learns
    about it from a peer who received no answer.

    Trigger the failure through disconnect logging: the subscription fails,
    ``keep_alive`` enters its recovery branch, and logging raises there. Verify
    that ``serve`` does not swallow the exception.
    """
    class _Boom(Exception):
        pass

    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project:
            svc = ProjectAgent(project, Config(policy=Policy()), lambda text: True)

            async def broken(*a, **kw):
                raise RuntimeError("subscription disconnected")
                yield  # pragma: no cover - make this an async generator

            monkeypatch.setattr(project, "subscribe_private_messages", broken)
            monkeypatch.setattr(project, "subscribe_connection_requests", broken)

            def explode(*a, **kw):
                raise _Boom("logging failed")

            monkeypatch.setattr(service.log, "warning", explode)

            with pytest.raises(_Boom):
                await svc.serve(stop=asyncio.Event())
