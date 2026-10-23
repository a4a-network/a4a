"""Negative controls for relay guards that must fail before network access."""
import asyncio

import pytest

from a4a.event import Event
from a4a.keys import Keys
from a4a.relay import (
    MAX_EVENTS_PER_QUERY,
    FanOutRelayClient,
    QueryResult,
    RelayClient,
    RelayError,
    _EOSE,
)


def _event(text="event"):
    return Event(kind=1, content=text).sign(Keys())


async def test_truncated_ok_is_ignored_without_indexing_missing_fields():
    client = RelayClient("ws://example.invalid")
    event = _event()
    future = asyncio.get_running_loop().create_future()
    client._pending_ok[event.id] = future

    client._dispatch(["OK", event.id])

    assert not future.done()
    assert client._pending_ok[event.id] is future


@pytest.mark.parametrize("value", [None, 0, 1, "yes"])
async def test_publish_replay_flag_must_be_an_exact_boolean(value):
    client = RelayClient("ws://example.invalid")
    with pytest.raises(ValueError, match="boolean"):
        await client.publish(_event(), replay_on_reconnect=value)


async def test_same_event_cannot_replace_an_inflight_publication():
    client = RelayClient("ws://example.invalid", timeout=0.01)
    event = _event()
    original = asyncio.get_running_loop().create_future()
    client._pending_ok[event.id] = original
    try:
        with pytest.raises(RelayError, match="already pending"):
            await client.publish(event)
        assert client._pending_ok[event.id] is original
    finally:
        client._pending_ok.pop(event.id, None)
        original.cancel()


@pytest.mark.parametrize("value", [True, 0, MAX_EVENTS_PER_QUERY + 1])
async def test_single_relay_bounded_query_rejects_invalid_limits_before_io(value):
    client = RelayClient("ws://example.invalid")
    with pytest.raises(ValueError, match="max_events"):
        await client.query_bounded({}, max_events=value)


@pytest.mark.parametrize("value", [True, 0, MAX_EVENTS_PER_QUERY + 1])
async def test_single_relay_legacy_query_rejects_invalid_limits_before_io(value):
    client = RelayClient("ws://example.invalid")
    with pytest.raises(ValueError, match="max_events"):
        await client.query({}, max_events=value)


async def test_subscription_eose_is_control_flow_not_event_input(monkeypatch):
    client = RelayClient("ws://example.invalid")
    event = _event()
    queue = asyncio.Queue()
    queue.put_nowait(_EOSE)
    queue.put_nowait(event.model_dump())

    monkeypatch.setattr(client, "_new_queue", lambda: queue)

    async def sent(_payload):
        return None

    class Socket:
        async def send(self, _payload):
            return None

    client._ws = Socket()
    monkeypatch.setattr(client, "_safe_send", sent)
    original = client._parse_event

    def parse(item):
        assert item is not _EOSE, "EOSE reached event parsing"
        return original(item)

    monkeypatch.setattr(client, "_parse_event", parse)
    stream = client.subscribe({"kinds": [1]})
    try:
        assert await anext(stream) == event
    finally:
        await stream.aclose()


def test_fanout_requires_at_least_one_relay():
    with pytest.raises(ValueError, match="at least one"):
        FanOutRelayClient([])


@pytest.mark.parametrize("value", [True, 0, -1])
async def test_fanout_publish_rejects_invalid_minimum_before_io(value):
    client = FanOutRelayClient(["ws://example.invalid"])
    with pytest.raises(ValueError, match="min_accepted"):
        await client.publish(_event(), min_accepted=value)


def test_merge_deduplicates_events_across_and_within_batches():
    event = _event()
    merged, truncated = FanOutRelayClient._merge(
        [[event, event], [event]], MAX_EVENTS_PER_QUERY)
    assert merged == [event]
    assert truncated is False


def test_merge_stops_at_the_callers_ceiling():
    first, second = _event("first"), _event("second")
    merged, truncated = FanOutRelayClient._merge([[first, second]], 1)
    assert merged == [first]
    assert truncated is True


async def test_single_relay_query_preserves_the_client_batch_object(monkeypatch):
    client = FanOutRelayClient(["ws://example.invalid"])
    event = _event()
    batch = [event, event]

    async def gathered(_call):
        return [batch]

    monkeypatch.setattr(client, "_gather", gathered)
    result = await client.query({"kinds": [1]})
    assert result is batch
    assert result == [event, event]


@pytest.mark.parametrize("value", [True, 0, MAX_EVENTS_PER_QUERY + 1])
async def test_fanout_legacy_query_rejects_invalid_limits_before_io(value):
    client = FanOutRelayClient(["ws://example.invalid"])
    with pytest.raises(ValueError, match="max_events"):
        await client.query({}, max_events=value)


@pytest.mark.parametrize("value", [True, 0, MAX_EVENTS_PER_QUERY + 1])
async def test_fanout_bounded_query_rejects_invalid_limits_before_io(value):
    client = FanOutRelayClient(["ws://example.invalid"])
    with pytest.raises(ValueError, match="max_events"):
        await client.query_bounded({}, max_events=value)


async def test_single_relay_bounded_query_preserves_the_client_result(monkeypatch):
    client = FanOutRelayClient(["ws://example.invalid"])
    result = QueryResult([_event()], 7, 3, True, 2, relays_responded=1)

    async def gathered(_call):
        return [result]

    monkeypatch.setattr(client, "_gather", gathered)
    observed = await client.query_bounded({"kinds": [1]}, max_events=10)
    assert observed is result


async def test_fanout_subscription_deduplicates_across_relays():
    event = _event()

    class Source:
        def __init__(self, url):
            self.url = url

        async def subscribe(self, _filters):
            yield event

    client = object.__new__(FanOutRelayClient)
    client.clients = [Source("ws://one.invalid"), Source("ws://two.invalid")]
    received = []
    async for item in client.subscribe({"kinds": [1]}):
        received.append(item)
    assert received == [event]
