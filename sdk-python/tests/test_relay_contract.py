"""F9/F12: relay response contract and subscription-queue boundaries.

A relay is an untrusted party. Its response used to be interpreted by truthiness
rather than type, while its event stream had no backpressure bound.
"""
import asyncio

import pytest

from a4a.event import Event
from a4a.keys import Keys
from a4a.relay import RelayClient, RelayError


def _client() -> RelayClient:
    return RelayClient("ws://example.invalid")


async def test_string_false_is_not_an_accepted_publish():
    """The OK field was interpreted by truthiness without checking its type.

    JSON string "false" is truthy in Python, so a relay replying
    `["OK", id, "false", "blocked: spam"]` looked as if it accepted the event:
    `publish()` returned normally, callers assumed delivery, and no retry followed.
    This caused silent data loss and let a relay quietly swallow unwanted events.
    """
    rc = _client()
    ev = Event(kind=1, content="x").sign(Keys())
    fut: asyncio.Future = asyncio.get_running_loop().create_future()
    rc._pending_ok[ev.id] = fut
    rc._dispatch(["OK", ev.id, "false", "blocked: spam"])
    accepted, reason = await fut
    assert accepted is False, f"string 'false' was treated as success (reason={reason!r})"


async def test_only_json_true_counts_as_accepted():
    rc = _client()
    ev = Event(kind=1, content="x").sign(Keys())
    fut: asyncio.Future = asyncio.get_running_loop().create_future()
    rc._pending_ok[ev.id] = fut
    rc._dispatch(["OK", ev.id, True, ""])
    accepted, _ = await fut
    assert accepted is True


def test_subscription_queue_is_bounded():
    """Signature validation occurs only AFTER events leave the queue.

    Filtering therefore cannot constrain ingress: a relay or relay-backed spammer
    can fill the queue faster than the consumer drains it, causing a long-lived
    subscribed agent to consume memory until OOM.
    """
    rc = _client()
    q = rc._new_queue()
    for i in range(rc.MAX_QUEUED_EVENTS + 500):
        rc._offer(q, {"n": i})
    assert q.qsize() <= rc.MAX_QUEUED_EVENTS, \
        f"queue grew to {q.qsize()} with a limit of {rc.MAX_QUEUED_EVENTS}"


async def test_query_subscription_is_restored_after_reconnect():
    """F11: `query()` registered in `_subs` but NOT in `_sub_filters`.

    Reconnect resends only `_sub_filters`. After an ordinary network interruption,
    a pending query waited for an EOSE that could never arrive and timed out, which
    callers could not distinguish from a silent relay.
    """
    rc = _client()
    sid = "abc123"
    rc._register_subscription(sid, [{"kinds": [1]}], rc._new_queue())
    assert sid in rc._sub_filters, "one-shot query will not be restored after reconnect"
    rc._forget_subscription(sid)
    assert sid not in rc._sub_filters and sid not in rc._subs


async def test_pending_publish_is_resent_after_reconnect():
    """Pending `publish()` calls received neither failure nor retransmission.

    They simply waited for an OK that could never arrive. Nostr events are idempotent
    by ID, so retransmission is safe and the relay can answer `duplicate`.
    """
    rc = _client()
    ev = Event(kind=1, content="x").sign(Keys())
    sent: list = []

    class _FakeWs:
        async def send(self, payload):
            sent.append(payload)

    rc._ws = _FakeWs()
    rc._pending_ok[ev.id] = asyncio.get_running_loop().create_future()
    rc._pending_events[ev.id] = ev
    await rc._resend_pending()
    assert any(ev.id in p for p in sent), "event was not resent after reconnect"


def test_closed_reason_is_cleared_on_successful_reconnect():
    """Otherwise the next failure reports the stale reason from a previous break."""
    rc = _client()
    rc._closed_reason = "connection lost"
    rc._on_reconnected()
    assert rc._closed_reason is None


async def test_rejection_for_clock_skew_points_at_the_clock():
    """A time-based rejection must identify the CLOCK, not merely a "range".

    Clock skew is one of the most common causes of "nothing works" for a new user.
    A relay message about an acceptable range does not say what to fix, sending the
    user toward keys, network, and installation instead. A wrong direction is costly,
    so the hint names both the offset and a corrective command.
    """
    import time as _time

    from a4a.event import Event
    from a4a.keys import Keys
    from a4a.relay import RelayClient, RelayError

    class _RefusingRelay(RelayClient):
        async def _safe_send(self, msg):
            ev_id = msg[1]["id"]
            fut = self._pending_ok.get(ev_id)
            if fut is not None and not fut.done():
                fut.set_result((False, "invalid: The event created_at field is out of "
                                       "the acceptable range (+900sec) for this relay."))

    client = _RefusingRelay("ws://irrelevant")
    ev = Event(kind=1, tags=[], content="x")
    ev.created_at = int(_time.time()) + 4000
    ev.sign(Keys())

    with pytest.raises(RelayError) as e:
        await client.publish(ev)
    text = str(e.value)
    assert "clock" in text.lower(), text
    assert "w32tm" in text or "timedatectl" in text, "the hint does not say how to fix it"


async def test_clock_hint_is_truthful_when_the_local_clock_is_the_broken_one():
    """Primary case: the LOCAL machine's clock is wrong.

    The event then carries that same local time and the local delta is near zero, so
    saying "dated 0 seconds ahead" is useless. The hint must report the difference
    from relay time rather than an empty local measurement.
    """
    import time as _time

    from a4a.event import Event
    from a4a.keys import Keys
    from a4a.relay import RelayClient, RelayError

    class _RefusingRelay(RelayClient):
        async def _safe_send(self, msg):
            fut = self._pending_ok.get(msg[1]["id"])
            if fut is not None and not fut.done():
                fut.set_result((False, "invalid: The event created_at field is out of "
                                       "the acceptable range (+900sec) for this relay."))

    client = _RefusingRelay("ws://irrelevant")
    ev = Event(kind=1, tags=[], content="x")
    ev.created_at = int(_time.time())      # locally "correct" from the machine's view
    ev.sign(Keys())

    with pytest.raises(RelayError) as e:
        await client.publish(ev)
    text = str(e.value)
    assert "differs from the relay's clock" in text, text
    assert "0s ahead" not in text, "the hint displayed a meaningless zero skew"
