import asyncio

import pytest

from a4a.event import Event
from a4a.keys import Keys
from a4a.relay import RelayClient, RelayError
from tests.fake_relay import FakeRelay


async def test_publish_and_query():
    async with FakeRelay() as relay:
        async with RelayClient(relay.url, timeout=5) as client:
            ev = Event(kind=31002, tags=[["category", "development"]], content="order").sign(Keys())
            await client.publish(ev)
            found = await client.query({"kinds": [31002], "#category": ["development"]})
            assert [e.id for e in found] == [ev.id]


async def test_query_drops_invalid_signature():
    async with FakeRelay() as relay:
        async with RelayClient(relay.url, timeout=5) as client:
            good = Event(kind=31002, content="ok").sign(Keys())
            bad = Event(kind=31002, content="ok").sign(Keys())
            bad.content = "tampered after signing"  # fake relay accepts it; client must discard it
            await client.publish(good)
            await client.publish(bad)
            found = await client.query({"kinds": [31002]})
            assert [e.id for e in found] == [good.id]


async def test_subscribe_receives_live_events():
    async with FakeRelay() as relay:
        async with RelayClient(relay.url, timeout=5) as sub_client, \
                   RelayClient(relay.url, timeout=5) as pub_client:
            received = asyncio.Queue()

            async def listen():
                async for ev in sub_client.subscribe({"kinds": [31002]}):
                    await received.put(ev)

            task = asyncio.create_task(listen())
            await asyncio.sleep(0.2)  # allow the subscription to become active
            ev = Event(kind=31002, content="live event").sign(Keys())
            await pub_client.publish(ev)
            got = await asyncio.wait_for(received.get(), timeout=5)
            assert got.id == ev.id
            task.cancel()


async def test_reconnect_restores_subscription():
    async with FakeRelay() as relay:
        async with RelayClient(relay.url, timeout=5) as sub_client, \
                   RelayClient(relay.url, timeout=5) as pub_client:
            received = asyncio.Queue()

            async def listen():
                async for ev in sub_client.subscribe({"kinds": [31002]}):
                    await received.put(ev)

            task = asyncio.create_task(listen())
            await asyncio.sleep(0.2)  # allow the subscription to become active
            await relay.drop_connections()  # connection loss
            await asyncio.sleep(2.0)  # first reconnect after 1s, plus margin for pub_client
            ev = Event(kind=31002, content="after reconnect").sign(Keys())
            await pub_client.publish(ev)
            got = await asyncio.wait_for(received.get(), timeout=5)
            assert got.id == ev.id
            task.cancel()


async def test_publish_timeout_raises():
    async with FakeRelay(respond_ok=False) as relay:  # silent relay: no OK arrives
        async with RelayClient(relay.url, timeout=0.3) as client:
            ev = Event(kind=31002, content="x").sign(Keys())
            with pytest.raises(RelayError):
                await client.publish(ev)


async def test_reader_survives_garbage_messages():
    async with FakeRelay() as relay:
        async with RelayClient(relay.url, timeout=5) as client:
            await relay.send_raw("this is not json")
            await relay.send_raw('{"also": "not a list"}')
            await relay.send_raw("[]")
            await asyncio.sleep(0.1)
            ev = Event(kind=31002, content="after garbage").sign(Keys())
            await client.publish(ev)  # reader remains alive and receives OK
            found = await client.query({"kinds": [31002]})
            assert [e.id for e in found] == [ev.id]


async def test_query_skips_event_with_broken_structure():
    async with FakeRelay() as relay:
        relay.events.append({"id": "x", "pubkey": "y", "created_at": "not a number",
                             "kind": 31002, "tags": [], "content": "", "sig": ""})
        async with RelayClient(relay.url, timeout=5) as client:
            good = Event(kind=31002, content="ok").sign(Keys())
            await client.publish(good)
            found = await client.query({"kinds": [31002]})
            assert [e.id for e in found] == [good.id]


async def test_query_timeout_raises_relay_error():
    async with FakeRelay(respond_eose=False) as relay:
        async with RelayClient(relay.url, timeout=0.3) as client:
            with pytest.raises(RelayError):
                await client.query({"kinds": [31002]})


async def test_publish_before_connect_raises():
    client = RelayClient("ws://127.0.0.1:1")
    ev = Event(kind=31002, content="x").sign(Keys())
    with pytest.raises(RelayError):
        await client.publish(ev)


async def test_fail_pending_rejects_waiters():
    client = RelayClient("ws://127.0.0.1:1")
    fut = asyncio.get_running_loop().create_future()
    client._pending_ok["abc"] = fut
    client._fail_pending("test")
    with pytest.raises(RelayError):
        fut.result()


async def test_reconnect_survives_handshake_rejection():
    """A relay's 503 handshake refusal must not break subscription recovery.

    WHAT THIS ALMOST FAILED TO TEST. The fake relay returned refusal using an older
    library's API, so the installed client received a MALFORMED handshake rather
    than a genuine 503. The test stayed green because it proved recovery after a
    disconnect, but never exercised the scenario named by the test. An external
    reviewer found this as TEST-HS-001 by measuring bytes sent over the socket.

    The refusal is now a real 503, observed by the client as InvalidStatus.
    """
    async with FakeRelay() as relay:
        async with RelayClient(relay.url, timeout=5) as sub, \
                   RelayClient(relay.url, timeout=5) as pub:
            received = asyncio.Queue()

            async def listen():
                async for ev in sub.subscribe({"kinds": [31002]}):
                    await received.put(ev)

            task = asyncio.create_task(listen())
            await asyncio.sleep(0.2)
            relay.reject_next_handshakes(1)   # reject the first reconnect attempt
            await relay.drop_connections()
            await asyncio.sleep(3.5)           # first retry refused; second succeeds after 2s
            ev = Event(kind=31002, content="after handshake refusal").sign(Keys())
            await pub.publish(ev)
            got = await asyncio.wait_for(received.get(), timeout=5)
            assert got.id == ev.id
            task.cancel()


async def test_publish_after_aclose_raises_relay_error():
    async with FakeRelay() as relay:
        client = RelayClient(relay.url, timeout=5)
        await client.connect()
        await client.aclose()
        ev = Event(kind=31002, content="x").sign(Keys())
        with pytest.raises(RelayError):
            await client.publish(ev)


async def test_fail_pending_wakes_subscriber_on_terminal_loss():
    async with FakeRelay() as relay:
        async with RelayClient(relay.url, timeout=5) as client:
            queue = asyncio.Queue()

            async def listen():
                try:
                    async for ev in client.subscribe({"kinds": [31002]}):
                        await queue.put(("ev", ev))
                except RelayError:
                    await queue.put(("closed", None))

            task = asyncio.create_task(listen())
            await asyncio.sleep(0.2)
            client._fail_pending("terminal-loss test")
            client._wake_subscribers("terminal-loss test")
            kind, _ = await asyncio.wait_for(queue.get(), timeout=5)
            assert kind == "closed"
            task.cancel()


async def test_truncated_ok_for_inflight_publish_is_ignored():
    async with FakeRelay(respond_ok=False) as relay:
        async with RelayClient(relay.url, timeout=5) as client:
            ev = Event(kind=31002, content="in-flight").sign(Keys())
            pub = asyncio.create_task(client.publish(ev))
            await asyncio.sleep(0.1)
            await relay.send_raw(f'["OK","{ev.id}"]')      # truncated OK for the real event
            await asyncio.sleep(0.2)
            assert not pub.done()                           # truncated frame ignored; future lives
            await relay.send_raw(f'["OK","{ev.id}",true,""]')  # complete OK
            await asyncio.wait_for(pub, timeout=5)          # publish completes normally


async def test_query_fast_fails_on_terminal_loss():
    async with FakeRelay(respond_eose=False) as relay:  # no EOSE: query remains pending
        async with RelayClient(relay.url, timeout=30) as client:
            async def do_query():
                return await client.query({"kinds": [31002]})
            task = asyncio.create_task(do_query())
            await asyncio.sleep(0.2)
            client._wake_subscribers("connection-loss test")
            with pytest.raises(RelayError):
                await asyncio.wait_for(task, timeout=5)   # fast-fail instead of waiting 30s


async def test_connection_failure_is_a_separate_error_type():
    """Relay unavailability has its own error type rather than generic RelayError.

    Callers need the distinction: a semantic refusal ("mandate expired") can be
    fixed by changing the event and retrying, while unavailability is not fixed by
    repetition. For an MCP-server wrapper this also affects the user's COST because
    every model turn is metered, so "try again" against a dead relay burns budget.
    Message-text matching is insufficient because it couples wrappers to wording.
    """
    from a4a.relay import RelayUnreachable

    with pytest.raises(RelayUnreachable) as got:
        async with RelayClient("ws://127.0.0.1:1/never", timeout=3):
            pass
    assert isinstance(got.value, RelayError), "type must remain a RelayError subtype"
    assert "127.0.0.1:1" in str(got.value), "error omits the unreachable address"


async def test_rejected_event_is_absent_from_store_query_and_live_delivery():
    """A refused EVENT is not stored mail.

    The fake relay used to append the event, apply deletions, and stream it to
    live subscribers before answering ["OK", id, false, reason]. ACK and
    partial-fan-out tests then treated a refused write as a stored copy.
    """
    reason = "blocked: refused by test"
    async with FakeRelay(reject_reason=reason) as relay:
        async with RelayClient(relay.url, timeout=5) as subscriber, \
                   RelayClient(relay.url, timeout=5) as publisher:
            received = asyncio.Queue()

            async def listen():
                async for ev in subscriber.subscribe({"kinds": [31002]}):
                    await received.put(ev)

            task = asyncio.create_task(listen())
            await asyncio.sleep(0.2)
            assert relay._subs, "subscription never became active"
            refused = Event(kind=31002, content="refused").sign(Keys())
            with pytest.raises(RelayError, match=reason):
                await publisher.publish(refused)
            assert refused.id not in {e["id"] for e in relay.events}
            found = await publisher.query({"kinds": [31002]})
            assert refused.id not in {e.id for e in found}
            assert not task.done(), "subscriber died before the refusal could be observed"
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(received.get(), timeout=0.4)
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, RelayError):
                pass


async def test_rejected_deletion_leaves_previously_accepted_event_intact():
    """A refused kind-5 deletion must not erase an event the relay already accepted."""
    keys = Keys()
    async with FakeRelay() as relay:
        async with RelayClient(relay.url, timeout=5) as client:
            kept = Event(kind=31002, content="kept").sign(keys)
            await client.publish(kept)
            found = await client.query({"ids": [kept.id]})
            assert [e.id for e in found] == [kept.id]
            relay.reject_reason = "blocked: deletion refused"
            deletion = Event(kind=5, tags=[["e", kept.id]], content="delete").sign(keys)
            with pytest.raises(RelayError, match="deletion refused"):
                await client.publish(deletion)
            assert any(e["id"] == kept.id for e in relay.events)
            assert deletion.id not in {e["id"] for e in relay.events}
            found = await client.query({"ids": [kept.id]})
            assert [e.id for e in found] == [kept.id]
