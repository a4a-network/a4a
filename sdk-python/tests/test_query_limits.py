"""Bound query results so the client neither requests nor accepts everything.

A 2026-08-30 measurement on a relay with 14,164 events showed that a query without
`limit` returned ALL 14,164 in 1.3 seconds, while `search_intents` returned 1,512
intents at once. In a network where publishing is free, a single spammer can occupy
the entire result set while the owner pays for it in tokens: every intent that reaches
the agent costs money.

There are two distinct safeguards:

* `limit` in the filter is a REQUEST that a well-behaved relay will honor;
* the client-side ceiling protects against a malicious relay, which may send any
  number of events and can only be stopped by the reader.
"""
import pytest
from a4a import relay as relay_mod
from a4a import types
from a4a.agent import Agent
from a4a.event import Event
from a4a.keys import Keys

from tests.fake_relay import FakeRelay


class _RecordingRelayView:
    """Record the filters passed to the relay."""

    def __init__(self, inner):
        self.inner = inner
        self.filters = []

    async def query(self, filters):
        self.filters.append(filters)
        return await self.inner.query(filters)

    def __getattr__(self, name):
        return getattr(self.inner, name)


async def test_intent_search_asks_the_relay_for_a_bounded_page():
    """Without `limit`, a query asks for every event in the selected facet."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as reader:
            view = _RecordingRelayView(reader.relay)
            reader.relay = view
            await reader.search_intents(category="design", limit=7)
            assert view.filters, "query was not sent"
            assert view.filters[-1].get("limit") == 7, view.filters[-1]


async def test_offers_and_connection_requests_are_bounded_too():
    """Bound offers and connection requests because they come from strangers."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as reader:
            view = _RecordingRelayView(reader.relay)
            reader.relay = view
            await reader.get_offers("a" * 64, limit=5)
            assert view.filters[-1].get("limit") == 5
            await reader.get_connection_requests(limit=3)
            assert view.filters[-1].get("limit") == 3


async def test_client_stops_reading_when_the_relay_ignores_the_limit(monkeypatch, caplog):
    """Stop reading when the relay sends more events than requested.

    The `limit` request guarantees nothing because the relay is untrusted. If it sends
    a stream, only the reader can stop it. Truncation must also be LOUD: a silently
    truncated result looks like there are no more events on the network and causes the
    caller to draw conclusions from incomplete data.
    """
    monkeypatch.setattr(relay_mod, "MAX_EVENTS_PER_QUERY", 5)
    author = Keys()

    # honour_limit=False makes the fake behave like a relay that ignores the `limit`
    # request. It previously ignored the limit ALWAYS, so this test passed by default
    # while also hiding that nobody tested result truncation (2026-09-05).
    async with FakeRelay(honour_limit=False) as relay:
        async with Agent([relay.url]) as writer, Agent([relay.url]) as reader:
            for i in range(12):
                ev = Event(kind=types.KIND_INTENT, tags=[["d", str(i)]],
                           content=f"intent {i}")
                ev.sign(author)
                await writer.relay.publish(ev)

            with caplog.at_level("WARNING"):
                got = await reader.relay.query({"kinds": [types.KIND_INTENT],
                                                "limit": 1})
    assert len(got) == 5, f"accepted {len(got)} events instead of the ceiling"
    assert any("INCOMPLETE" in r.message
               for r in caplog.records), "truncation was silent"
