"""Offline private-message preparation with real keys, signatures and encryption."""
import asyncio
import inspect
import socket
import time
import uuid

import pytest

from a4a import giftwrap, nip44, types
from a4a.agent import PRIVATE_TTL_SECONDS, Agent
from a4a.event import Event
from a4a.keys import Keys
from a4a.relay import RelayError


@pytest.fixture(autouse=True)
async def no_network(monkeypatch):
    # Install after asyncio's Windows control socket exists, before any test runs.
    def blocked(*args, **kwargs):
        raise AssertionError("network disabled in private preparation tests")

    for name in ("__init__", "connect", "connect_ex", "bind", "sendto"):
        monkeypatch.setattr(socket.socket, name, blocked)
    for name in ("create_connection", "getaddrinfo", "gethostbyname",
                 "gethostbyname_ex", "gethostbyaddr", "getnameinfo"):
        monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setattr(asyncio.get_running_loop(), "create_connection", blocked)
    yield


@pytest.fixture
def sender():
    return Agent(["ws://relay.invalid:1"], keys=Keys())


async def test_socket_and_dns_guards_are_active():
    with pytest.raises(AssertionError, match="network disabled"):
        socket.socket()
    with pytest.raises(AssertionError, match="network disabled"):
        socket.getaddrinfo("relay.invalid", 443)
    with pytest.raises(AssertionError, match="network disabled"):
        await asyncio.get_running_loop().create_connection(lambda: None, "127.0.0.1", 1)


@pytest.mark.parametrize("wrap", [True, False])
@pytest.mark.parametrize("delivery_id", [None, "explicit-delivery"])
@pytest.mark.parametrize("expires_in", [None, 0, 60])
@pytest.mark.parametrize("delegation_id", [None, "d" * 64])
def test_prepare_returns_signed_decryptable_events_offline(
        sender, wrap, delivery_id, expires_in, delegation_id):
    recipient = Keys()
    sender.delegation_id = delegation_id
    content = "private payload: \u043f\u0440\u0438\u0432\u0435\u0442"
    assert not inspect.iscoroutinefunction(sender.prepare_private_message)
    before = int(time.time())
    prepared = sender.prepare_private_message(
        recipient.pubkey_hex, content, delivery_id, wrap, expires_in)
    after = int(time.time())

    assert isinstance(prepared, tuple) and len(prepared) == 3
    inner, outer, actual_delivery_id = prepared
    assert isinstance(inner, Event) and isinstance(outer, Event)
    assert inner.verify() and outer.verify()
    assert inner.pubkey == sender.pubkey
    assert inner.tag_values("p") == outer.tag_values("p") == [recipient.pubkey_hex]
    assert inner.tag_values("d") == [actual_delivery_id]
    assert inner.delegation_ref() == delegation_id
    assert isinstance(actual_delivery_id, str) and actual_delivery_id
    if delivery_id is not None:
        assert actual_delivery_id == delivery_id
    else:
        assert uuid.UUID(hex=actual_delivery_id).version == 4
    assert content not in outer.content
    if wrap:
        assert inner.kind == types.KIND_PRIVATE_RUMOR
        assert outer.kind == giftwrap.KIND_GIFT_WRAP
        assert outer.pubkey != sender.pubkey
        assert inner.id != outer.id
        assert inner.content == content
        assert giftwrap.unwrap(outer, recipient).model_dump() == inner.model_dump()
        expected_tags = [["p", recipient.pubkey_hex], ["d", actual_delivery_id]]
        if delegation_id:
            expected_tags.append(["delegation", delegation_id])
        assert inner.tags == expected_tags
        assert outer.tag_value("d") is None
        assert outer.delegation_ref() is None
        assert inner.tag_value("expiration") is None
    else:
        assert inner is outer
        assert outer.kind == types.KIND_PRIVATE_MESSAGE
        assert nip44.decrypt(outer.content, recipient.privkey_hex, sender.pubkey) == content
    if expires_in == 0:
        assert outer.tag_value("expiration") is None
    else:
        ttl = PRIVATE_TTL_SECONDS if expires_in is None else expires_in
        assert before + ttl <= int(outer.tag_value("expiration")) <= after + ttl


def test_prepare_defaults_to_wrapping_and_fresh_delivery_ids(sender):
    recipient = Keys()
    prepared = [sender.prepare_private_message(recipient.pubkey_hex, "same text")
                for _ in range(2)]
    assert all(outer.kind == giftwrap.KIND_GIFT_WRAP for _, outer, _ in prepared)
    assert len({delivery_id for _, _, delivery_id in prepared}) == 2
    assert len({inner.id for inner, _, _ in prepared}) == 2
    assert len({outer.id for _, outer, _ in prepared}) == 2


@pytest.mark.parametrize("previous_offset", [None, 10])
def test_unwrapped_preparation_reserves_monotonic_time_before_signing(
        sender, monkeypatch, previous_offset):
    now = 1_800_000_000
    monkeypatch.setattr(time, "time", lambda: now)
    coordinate = f"{types.KIND_PRIVATE_MESSAGE}:delivery"
    if previous_offset is not None:
        sender._last_addressable[coordinate] = now + previous_offset
    recipient = Keys()
    first, _, _ = sender.prepare_private_message(
        recipient.pubkey_hex, "first", "delivery", False, 60)
    snapshot = first.model_dump()
    second, _, _ = sender.prepare_private_message(
        recipient.pubkey_hex, "second", "delivery", False, 60)
    other, _, _ = sender.prepare_private_message(
        recipient.pubkey_hex, "other", "other-delivery", False, 60)

    expected = now if previous_offset is None else now + previous_offset + 1
    assert first.created_at == expected
    assert second.created_at == expected + 1
    assert other.created_at == now
    assert sender._last_addressable[coordinate] == second.created_at
    assert first.model_dump() == snapshot
    assert first.id != second.id
    assert first.verify() and second.verify() and other.verify()
    assert first.tag_value("expiration") == second.tag_value("expiration") == str(now + 60)


@pytest.mark.parametrize("wrap", [True, False])
async def test_receipt_broadcasts_exact_prepared_event_without_resigning(sender, monkeypatch, wrap):
    recipient = Keys()
    prepare = sender.prepare_private_message
    prepared = []
    published = []

    def forbid_resigning(*args, **kwargs):
        raise AssertionError("prepared events must not be signed again")

    def capture_preparation(*args, **kwargs):
        inner, outer, delivery_id = prepare(*args, **kwargs)
        prepared.append((inner, outer, delivery_id, inner.model_dump(), outer.model_dump()))
        monkeypatch.setattr(Event, "sign", forbid_resigning)
        return inner, outer, delivery_id

    async def broadcast(event):
        assert len(prepared) == 1
        inner, outer, _, inner_snapshot, outer_snapshot = prepared[0]
        assert event is outer
        assert inner.model_dump() == inner_snapshot
        assert event.model_dump() == outer_snapshot
        assert event.verify()
        published.append(event)

    monkeypatch.setattr(sender, "prepare_private_message", capture_preparation)
    monkeypatch.setattr(sender, "_broadcast", broadcast)
    receipt = await sender.send_private_message_receipt(
        recipient.pubkey_hex, "payload", "delivery", wrap, 0)

    assert len(prepared) == len(published) == 1
    inner, outer, delivery_id, inner_snapshot, outer_snapshot = prepared[0]
    assert receipt == {"inner_id": inner_snapshot["id"], "outer_id": outer_snapshot["id"],
                       "delivery_id": delivery_id, "status": "relay_accepted"}
    assert inner.model_dump() == inner_snapshot
    assert outer.model_dump() == outer_snapshot


@pytest.mark.parametrize("wrap", [True, False])
async def test_receipt_propagates_broadcast_failure_without_retry(sender, monkeypatch, wrap):
    published = []
    failure = RelayError("synthetic rejection")

    async def broadcast(event):
        assert event.verify()
        published.append(event)
        raise failure

    monkeypatch.setattr(sender, "_broadcast", broadcast)
    with pytest.raises(RelayError) as caught:
        await sender.send_private_message_receipt(Keys().pubkey_hex, "payload", wrap=wrap)
    assert caught.value is failure
    assert len(published) == 1


@pytest.mark.parametrize("wrap", [True, False])
@pytest.mark.parametrize("method", ["prepare_private_message", "send_private_message_receipt"])
@pytest.mark.parametrize("invalid, error, match", [
    ({"to_pubkey": "not-a-pubkey"}, ValueError, "pubkey"),
    ({"to_pubkey": "A" * 64}, ValueError, "pubkey"),
    ({"delivery_id": ""}, ValueError, "delivery_id"),
    ({"expires_in": -1}, ValueError, "expires_in"),
    ({"content": "x" * 65536}, nip44.Nip44Error, None),
], ids=["recipient", "uppercase-recipient", "empty-delivery", "negative-expiry", "oversize"])
async def test_invalid_input_fails_before_network(sender, monkeypatch, wrap, method, invalid, error, match):
    published = []

    async def broadcast(event):
        published.append(event)

    if method == "send_private_message_receipt":
        monkeypatch.setattr(sender, "_broadcast", broadcast)
    kwargs = {"to_pubkey": Keys().pubkey_hex, "content": "payload", "wrap": wrap}
    kwargs.update(invalid)
    with pytest.raises(error, match=match):
        result = getattr(sender, method)(**kwargs)
        if method == "send_private_message_receipt":
            await result
    assert published == []
    assert sender._last_addressable == {}


def test_preparation_preserves_format_specific_empty_content_behavior(sender):
    recipient = Keys()
    with pytest.raises(nip44.Nip44Error):
        sender.prepare_private_message(recipient.pubkey_hex, "", wrap=False)
    inner, outer, _ = sender.prepare_private_message(recipient.pubkey_hex, "")
    assert inner.content == ""
    assert giftwrap.unwrap(outer, recipient) == inner
