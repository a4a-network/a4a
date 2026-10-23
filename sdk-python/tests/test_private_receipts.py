"""Private receipts and inbox identity, with real crypto and loopback FakeRelay."""
import asyncio
import contextlib
import json
import time

import pytest

from a4a import files, giftwrap, nip44, types
from a4a.agent import PRIVATE_TTL_SECONDS, Agent
from a4a.event import Event
from a4a.keys import Keys
from a4a.relay import RelayError
from tests.fake_relay import FakeRelay


def _inner(sender, recipient, *, tags=None, wrapped=True, content="payload"):
    if tags is None:
        tags = [["p", recipient.pubkey_hex], ["d", "delivery"]]
    if not wrapped:
        content = nip44.encrypt(content, sender.privkey_hex, recipient.pubkey_hex)
    return Event(kind=types.KIND_PRIVATE_RUMOR if wrapped else types.KIND_PRIVATE_MESSAGE,
                 tags=tags, content=content).sign(sender)


def _envelope(inner, sender, recipient, *, tags=None):
    # Assemble a decryptable envelope even when its signed routing tags are false.
    seal = Event(kind=giftwrap.KIND_SEAL, content=nip44.encrypt(
        json.dumps(inner.model_dump()), sender.privkey_hex, recipient.pubkey_hex))
    seal.sign(sender)
    ephemeral = Keys()
    return Event(kind=giftwrap.KIND_GIFT_WRAP,
                 tags=[["p", recipient.pubkey_hex]] if tags is None else tags,
                 content=nip44.encrypt(json.dumps(seal.model_dump()),
                                       ephemeral.privkey_hex, recipient.pubkey_hex)
                 ).sign(ephemeral)


def _bad_addresses(case, recipient, other):
    me, stranger = recipient.pubkey_hex, other.pubkey_hex
    return {
        "missing": [],
        "foreign": [["p", stranger]],
        "duplicate": [["p", me], ["p", me]],
        "self_first": [["p", me], ["p", stranger]],
        "self_last": [["p", stranger], ["p", me]],
        "empty": [["p", ""]],
        "short": [["p"]],
        "short_extra": [["p", me], ["p"]],
        "prefix": [["p", me[:16]]],
    }[case]


async def _receive(agent, mode, count=1, since=None):
    if mode == "read":
        return await agent.read_private_messages(since=since)
    async with contextlib.aclosing(agent.subscribe_private_messages(since=since)) as stream:
        return [await asyncio.wait_for(anext(stream), timeout=2) for _ in range(count)]


@pytest.mark.parametrize("wrap", [True, False])
@pytest.mark.parametrize("delivery_id", [None, "explicit-delivery"])
@pytest.mark.parametrize("expires_in", [None, 0, 60])
async def test_receipt_identifies_the_single_published_event(wrap, delivery_id, expires_in):
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender:
            recipient = Keys()
            sender.delegation_id = "d" * 64
            before = int(time.time())
            receipt = await sender.send_private_message_receipt(
                recipient.pubkey_hex, "private payload", delivery_id=delivery_id,
                wrap=wrap, expires_in=expires_in)
            after = int(time.time())
            assert len(relay.events) == 1
            outer = Event(**relay.events[0])
            inner = giftwrap.unwrap(outer, recipient) if wrap else outer
            assert receipt == {"inner_id": inner.id, "outer_id": outer.id,
                               "delivery_id": inner.tag_value("d"),
                               "status": "relay_accepted"}
            assert receipt["delivery_id"]
            if delivery_id is not None:
                assert receipt["delivery_id"] == delivery_id
            assert inner.verify() and outer.verify()
            assert (inner.id != outer.id) is wrap
            assert inner.delegation_ref() == sender.delegation_id
            assert inner.tag_values("p") == outer.tag_values("p") == [recipient.pubkey_hex]
            assert "private payload" not in outer.content
            if wrap:
                assert inner.content == "private payload"
                assert inner.kind == types.KIND_PRIVATE_RUMOR
                assert outer.kind == giftwrap.KIND_GIFT_WRAP
                assert outer.pubkey != sender.pubkey
                assert outer.tag_value("d") is None
                assert outer.delegation_ref() is None
                assert inner.tag_value("expiration") is None
            else:
                assert outer.kind == types.KIND_PRIVATE_MESSAGE
                assert nip44.decrypt(outer.content, recipient.privkey_hex,
                                     sender.pubkey) == "private payload"
            if expires_in == 0:
                assert outer.tag_value("expiration") is None
            else:
                ttl = PRIVATE_TTL_SECONDS if expires_in is None else expires_in
                assert before + ttl <= int(outer.tag_value("expiration")) <= after + ttl


async def test_receipt_defaults_to_wrapped_and_generates_distinct_delivery_ids():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender:
            recipient = Keys()
            receipts = [await sender.send_private_message_receipt(
                recipient.pubkey_hex, "same text") for _ in range(2)]
            assert len(relay.events) == 2
            assert all(ev["kind"] == giftwrap.KIND_GIFT_WRAP for ev in relay.events)
            assert len({r["delivery_id"] for r in receipts}) == 2
            assert len({r["inner_id"] for r in receipts}) == 2


@pytest.mark.parametrize("wrap", [True, False])
async def test_receipt_does_not_report_success_when_relay_rejects(wrap):
    async with FakeRelay(reject_reason="blocked: test rejection") as relay:
        async with Agent([relay.url]) as sender:
            with pytest.raises(RelayError, match="test rejection"):
                await sender.send_private_message_receipt(Keys().pubkey_hex, "payload", wrap=wrap)
            assert relay.events == [], "a refused receipt must not remain stored"


@pytest.mark.parametrize("wrap", [True, False])
@pytest.mark.parametrize("invalid", ["recipient", "delivery_id", "expires_in"])
async def test_receipt_preserves_validation_before_publish(wrap, invalid):
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender:
            kwargs = {"to_pubkey": Keys().pubkey_hex, "content": "payload", "wrap": wrap}
            kwargs.update({"recipient": {"to_pubkey": "not-a-pubkey"},
                           "delivery_id": {"delivery_id": ""},
                           "expires_in": {"expires_in": -1}}[invalid])
            with pytest.raises(ValueError):
                await sender.send_private_message_receipt(**kwargs)
            assert relay.events == []


@pytest.mark.parametrize("wrap", [True, False])
@pytest.mark.parametrize("method", ["message", "file"])
async def test_legacy_senders_still_return_inner_string_id(wrap, method):
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender:
            recipient = Keys()
            if method == "message":
                result = await sender.send_private_message(
                    recipient.pubkey_hex, "payload", "delivery", wrap, 0)
            else:
                result = await sender.send_file(recipient.pubkey_hex, url="ipfs://test",
                                                sha256="a" * 64, key="b" * 64,
                                                delivery_id="delivery", wrap=wrap)
            assert isinstance(result, str)
            assert len(relay.events) == 1
            outer = Event(**relay.events[0])
            inner = giftwrap.unwrap(outer, recipient) if wrap else outer
            assert result == inner.id
            if method == "file":
                content = inner.content if wrap else nip44.decrypt(
                    inner.content, recipient.privkey_hex, sender.pubkey)
                assert files.parse_file_reference(content)["url"] == "ipfs://test"


@pytest.mark.parametrize("wrap", [True, False])
@pytest.mark.parametrize("mode", ["read", "subscribe"])
async def test_incoming_messages_preserve_inner_and_outer_identity(wrap, mode):
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender, Agent([relay.url]) as recipient:
            inner_id = await sender.send_private_message(
                recipient.pubkey, "payload", delivery_id="delivery", wrap=wrap)
            [message] = await _receive(recipient, mode)
            assert message["event"].id == message["inner_id"] == inner_id
            assert message["outer_id"] == relay.events[0]["id"]
            assert isinstance(message["outer_event"], Event)
            assert message["outer_event"].model_dump() == relay.events[0]
            assert message["delivery_id"] == "delivery"
            assert message["from_pubkey"] == sender.pubkey
            assert message["content"] == "payload"
            assert message["wrapped"] is wrap
            assert message["event"].verify() and message["outer_event"].verify()
            if not wrap:
                assert message["outer_event"] is message["event"]


@pytest.mark.parametrize("layer", ["plain", "outer", "inner"])
@pytest.mark.parametrize("case", ["missing", "foreign", "duplicate", "self_first",
                                  "self_last", "empty", "short", "short_extra", "prefix"])
def test_decode_rejects_false_or_ambiguous_recipient(layer, case):
    sender, recipient, other = Keys(), Keys(), Keys()
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    tags = _bad_addresses(case, recipient, other) + [["d", "delivery"]]
    inner = _inner(sender, recipient, wrapped=layer != "plain",
                   tags=tags if layer != "outer" else None)
    outer = inner if layer == "plain" else _envelope(
        inner, sender, recipient, tags=tags if layer == "outer" else None)
    assert inner.verify() and outer.verify()
    if layer == "plain":
        assert nip44.decrypt(outer.content, recipient.privkey_hex, sender.pubkey_hex) == "payload"
    elif layer == "inner":
        assert giftwrap.unwrap(outer, recipient) == inner
    assert agent._decode_incoming(outer) is None


@pytest.mark.parametrize("layer", ["plain", "outer", "inner"])
@pytest.mark.parametrize("tamper", ["signature", "id"])
def test_decode_verifies_signatures_without_relay_parser(layer, tamper):
    sender, recipient = Keys(), Keys()
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    inner = _inner(sender, recipient, wrapped=layer != "plain")
    outer = inner if layer == "plain" else _envelope(inner, sender, recipient)
    target = inner if layer == "inner" else outer
    if tamper == "signature":
        target.sig = "0" * 128
    else:
        target.id = "0" * 64
    if layer == "inner":
        outer = _envelope(inner, sender, recipient)
    assert not target.verify()
    assert agent._decode_incoming(outer) is None


@pytest.mark.parametrize("wrap", [True, False])
def test_decode_keeps_messages_without_delivery_tag_compatible(wrap):
    sender, recipient = Keys(), Keys()
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    inner = _inner(sender, recipient, tags=[["p", recipient.pubkey_hex]], wrapped=wrap)
    outer = giftwrap.wrap(inner, recipient.pubkey_hex, sender) if wrap else inner
    message = agent._decode_incoming(outer)
    assert message["inner_id"] == inner.id
    assert message["outer_id"] == outer.id
    assert message["delivery_id"] is None
    assert message["outer_event"] is outer


@pytest.mark.parametrize("mode", ["read", "subscribe"])
async def test_incoming_does_not_trust_relay_filters(mode, monkeypatch):
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender, Agent([relay.url]) as recipient:
            other = Keys()
            bad = []
            for case in ("missing", "foreign", "duplicate", "self_first", "short_extra"):
                tags = _bad_addresses(case, recipient.keys, other)
                bad.append(_inner(sender.keys, recipient.keys, tags=tags, wrapped=False))
                inner = _inner(sender.keys, recipient.keys, tags=tags)
                bad.append(_envelope(inner, sender.keys, recipient.keys))
                inner = _inner(sender.keys, recipient.keys)
                bad.append(_envelope(inner, sender.keys, recipient.keys, tags=tags))
            good = _inner(sender.keys, recipient.keys, wrapped=False, content="valid sentinel")
            relay.events.extend(ev.model_dump() for ev in [*bad, good])
            monkeypatch.setattr(relay, "_matching", lambda filters: list(relay.events))
            [message] = await _receive(recipient, mode)
            assert message["event"].id == good.id


@pytest.mark.parametrize("mode", ["read", "subscribe"])
async def test_rewrapping_deduplicates_by_inner_id_and_keeps_matching_outer(mode, monkeypatch):
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender, Agent([relay.url]) as recipient:
            inner = _inner(sender.keys, recipient.keys)
            first = giftwrap.wrap(inner, recipient.pubkey, sender.keys)
            second = giftwrap.wrap(inner, recipient.pubkey, sender.keys)
            next_inner = _inner(sender.keys, recipient.keys, content="next")
            last = giftwrap.wrap(next_inner, recipient.pubkey, sender.keys)
            relay.events.extend(ev.model_dump() for ev in [first, second, last])
            monkeypatch.setattr(relay, "_matching", lambda filters: list(relay.events))
            messages = await _receive(recipient, mode, count=2)
            assert [m["inner_id"] for m in messages] == [inner.id, next_inner.id]
            assert [m["outer_id"] for m in messages] == [first.id, last.id]
            assert [m["outer_event"].id for m in messages] == [first.id, last.id]


@pytest.mark.parametrize("wrap", [True, False])
async def test_ack_remains_separate_and_unwrap_inbox_keeps_event_contract(wrap):
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender, Agent([relay.url]) as recipient:
            receipt = await sender.send_private_message_receipt(
                recipient.pubkey, "payload", delivery_id="delivery", wrap=wrap)
            [message] = await recipient.read_private_messages()
            await recipient.acknowledge(message, status="processed")
            [ack] = await sender.get_acks("delivery", from_pubkey=recipient.pubkey)
            assert ack["acked_event_id"] == receipt["inner_id"]
            assert ack["status"] == "processed"
            assert receipt["status"] == "relay_accepted"
            assert await sender.read_private_messages() == []
            ack_outer = Event(**relay.events[-1])
            assert sender._decode_incoming(ack_outer) is None
            unwrapped = await sender._unwrap_inbox()
            assert unwrapped == ([ack["event"]] if wrap else [])
            assert all(isinstance(ev, Event) for ev in unwrapped)
            await recipient.send_private_message(sender.pubkey, "ordinary message")
            [ordinary] = await _receive(sender, "subscribe")
            assert ordinary["content"] == "ordinary message"


@pytest.mark.parametrize("private", [True, False])
async def test_deliver_with_ack_preserves_inner_event_id(private):
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender, Agent([relay.url]) as recipient:
            async def acknowledge_one():
                [message] = await _receive(recipient, "subscribe")
                await recipient.acknowledge(message, status="processed")
                return message

            receiver = asyncio.create_task(acknowledge_one())
            try:
                result = await sender.deliver_with_ack(
                    recipient.pubkey, "payload", private=private, retries=0,
                    ack_timeout=2, poll_interval=0.01, resolve_recipient_relays=False)
                message = await asyncio.wait_for(receiver, timeout=2)
            finally:
                if not receiver.done():
                    receiver.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await receiver
            assert result["status"] == "acknowledged"
            assert result["event_id"] == message["inner_id"] == message["event"].id
            assert result["delivery_id"] == message["delivery_id"]
            assert result["ack_status"] == "processed"
            assert result["attempts"] == 1
            assert len(relay.events) == 2


async def test_partial_fanout_ack_is_visible_only_on_the_accepting_relay():
    """Partial fan-out acceptance is a different fact from the sender's relay set.

    The recipient is configured with relays A and B and publishes one wrapped
    acknowledgement to both. A refuses that envelope after having accepted the
    letter; B accepts it. `acknowledge()` uses the default minimum of one
    acceptance, so the call succeeds and a caller may record the receipt as
    sent. The sender configured with only A then reads no acknowledgement:
    these relays do not copy stored events to each other. The same sender key,
    pointed at B, finds the processed acknowledgement for this exact delivery.
    The id returned by `acknowledge()`, and the id inside `get_acks()`, is the
    signed inner event. The id indexed on B is the outer gift wrap.

    Synthetic two-FakeRelay contract only. It does not describe a live relay.
    """
    async with FakeRelay() as relay_a, FakeRelay() as relay_b:
        async with Agent([relay_a.url]) as sender, Agent(
                [relay_a.url, relay_b.url]) as recipient:
            receipt = await sender.send_private_message_receipt(
                recipient.pubkey, "payload", delivery_id="delivery", wrap=True)
            [message] = await recipient.read_private_messages()
            assert message["wrapped"] is True
            assert message["delivery_id"] == receipt["delivery_id"] == "delivery"
            assert [event["id"] for event in relay_a.events] == [receipt["outer_id"]]
            assert relay_b.events == []

            # Refuse only the acknowledgement. The letter already stored on A stays.
            relay_a.reject_reason = "blocked: ack refused on this relay"
            ack_id = await recipient.acknowledge(message, status="processed")

            assert [event["id"] for event in relay_a.events] == [receipt["outer_id"]]
            [stored] = relay_b.events
            outer = Event(**stored)
            assert outer.kind == giftwrap.KIND_GIFT_WRAP
            assert outer.verify()
            inner = giftwrap.unwrap(outer, sender.keys)
            assert inner.verify()
            assert inner.kind == types.KIND_ACK_RECEIPT
            assert inner.pubkey == recipient.pubkey
            assert inner.id == ack_id
            assert outer.id != ack_id
            assert inner.tag_value("status") == "processed"
            assert inner.tag_value("d") == "delivery"
            assert inner.tag_value("e") == receipt["inner_id"] == message["event"].id

            assert await sender.get_acks(
                "delivery", from_pubkey=recipient.pubkey) == []
            async with Agent([relay_b.url], keys=sender.keys) as sender_on_b:
                [ack] = await sender_on_b.get_acks(
                    "delivery", from_pubkey=recipient.pubkey)
            assert ack["status"] == "processed"
            assert ack["delivery_id"] == "delivery"
            assert ack["acker_pubkey"] == recipient.pubkey
            assert ack["acked_event_id"] == receipt["inner_id"]
            assert ack["event"].id == ack_id
            assert ack["event"].id != outer.id
            assert ack["event"].verify()
