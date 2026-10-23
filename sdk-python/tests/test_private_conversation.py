"""Conversation routing metadata stays signed and inside the private envelope."""

import asyncio

import pytest

from a4a import Agent, Keys, giftwrap, nip44, types
from a4a.event import Event
from a4a.inbox import InboxConflict, InboxStore
from fake_relay import FakeRelay


CID = "a" * 64


def _agents():
    sender = Agent(["ws://relay.invalid:1"], keys=Keys())
    recipient = Agent(["ws://relay.invalid:1"], keys=Keys())
    return sender, recipient


def test_wrapped_conversation_reaches_inbox_without_public_metadata(tmp_path):
    sender, recipient = _agents()
    inner, outer, _ = sender.prepare_private_message(
        recipient.pubkey, "status request", conversation_id=CID)

    assert inner.tag_values("a4a_conversation") == [CID]
    assert outer.tag_values("a4a_conversation") == []
    assert CID not in outer.model_dump_json()
    assert giftwrap.unwrap(outer, recipient.keys) == inner
    assert recipient._decode_incoming(outer)["conversation_id"] == CID

    with InboxStore(tmp_path / "inbox", recipient.pubkey, "consumer") as store:
        assert store.accept(recipient, outer, {sender.pubkey}) == "stored"
        leased = store.claim(recipient, "consumer", {sender.pubkey})
    assert leased["conversation_id"] == CID
    assert leased["content"] == "status request"


def test_old_letters_without_conversation_remain_readable():
    sender, recipient = _agents()
    for wrap in (True, False):
        _, outer, _ = sender.prepare_private_message(
            recipient.pubkey, "legacy message", wrap=wrap)
        decoded = recipient._decode_incoming(outer)
        assert decoded["conversation_id"] is None
        assert decoded["content"] == "legacy message"


def test_delivery_id_cannot_be_reused_in_another_conversation(tmp_path):
    sender, recipient = _agents()
    _, first, _ = sender.prepare_private_message(
        recipient.pubkey, "same text", delivery_id="fixed", conversation_id=CID)
    _, moved, _ = sender.prepare_private_message(
        recipient.pubkey, "same text", delivery_id="fixed", conversation_id="b" * 64)
    with InboxStore(tmp_path / "inbox", recipient.pubkey, "consumer") as store:
        assert store.accept(recipient, first, {sender.pubkey}) == "stored"
        with pytest.raises(InboxConflict, match="reused"):
            store.accept(recipient, moved, {sender.pubkey})


@pytest.mark.parametrize("reported", [None, "b" * 64])
def test_inbox_rechecks_decoder_conversation_against_signed_inner(
        tmp_path, monkeypatch, reported):
    sender, recipient = _agents()
    _, outer, _ = sender.prepare_private_message(
        recipient.pubkey, "text", conversation_id=CID)
    decoded = recipient._decode_incoming(outer)
    monkeypatch.setattr(recipient, "_decode_incoming",
                        lambda _outer: {**decoded, "conversation_id": reported})
    with InboxStore(tmp_path / "inbox", recipient.pubkey, "consumer") as store:
        assert store.accept(recipient, outer, {sender.pubkey}) == "ignored"
        assert store.status()["total"] == 0


@pytest.mark.parametrize("cid", ["", "a" * 63, "A" * 64, "g" * 64, 17])
def test_invalid_conversation_rejected_before_event_or_network(cid):
    sender, recipient = _agents()
    with pytest.raises(ValueError, match="conversation_id"):
        sender.prepare_private_message(recipient.pubkey, "text", conversation_id=cid)
    assert sender._last_addressable == {}


def test_unwrapped_conversation_refused_to_prevent_public_correlation():
    sender, recipient = _agents()
    with pytest.raises(ValueError, match="gift wrapping"):
        sender.prepare_private_message(
            recipient.pubkey, "text", wrap=False, conversation_id=CID)
    assert sender._last_addressable == {}


@pytest.mark.parametrize("tags", [
    [["a4a_conversation", CID], ["a4a_conversation", CID]],
    [["a4a_conversation"]],
    [["a4a_conversation", CID, "ambiguous"]],
    [["a4a_conversation", "A" * 64]],
])
def test_invalid_signed_inner_conversation_is_not_routed(tags):
    sender, recipient = _agents()
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, content="text",
                  tags=[["p", recipient.pubkey], *tags])
    inner.sign(sender.keys)
    outer = giftwrap.wrap(inner, recipient.pubkey, sender.keys)
    assert recipient._decode_incoming(outer) is None


def test_plain_event_with_conversation_tag_is_not_routed():
    sender, recipient = _agents()
    plain = Event(kind=types.KIND_PRIVATE_MESSAGE,
                  tags=[["p", recipient.pubkey], ["d", "delivery"],
                        ["a4a_conversation", CID]],
                  content=nip44.encrypt("text", sender.keys.privkey_hex,
                                        recipient.pubkey))
    plain.sign(sender.keys)
    assert recipient._decode_incoming(plain) is None


@pytest.mark.parametrize("tag", ["a4a_owner", "a4a_descriptor", "a4a_request"])
def test_personal_decoder_rejects_organization_only_inner_tags(tag):
    sender, recipient = _agents()
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, content="organization letter",
                  tags=[["p", recipient.pubkey], ["d", "delivery"],
                        [tag, "a" * 64]])
    inner.sign(sender.keys)
    outer = giftwrap.wrap(inner, recipient.pubkey, sender.keys)
    assert recipient._decode_incoming(outer) is None


@pytest.mark.parametrize("wrap", [False, True])
def test_personal_decoder_rejects_public_organization_route_metadata(wrap):
    sender, recipient = _agents()
    if wrap:
        _, outer, _ = sender.prepare_private_message(recipient.pubkey, "text")
        outer.tags.append(["a4a_owner", "a" * 64])
        outer.sign(sender.keys)
    else:
        outer = Event(kind=types.KIND_PRIVATE_MESSAGE,
                      tags=[["p", recipient.pubkey], ["d", "delivery"],
                            ["a4a_owner", "a" * 64]],
                      content=nip44.encrypt("text", sender.keys.privkey_hex,
                                            recipient.pubkey))
        outer.sign(sender.keys)
    assert recipient._decode_incoming(outer) is None


def test_personal_inbox_rechecks_organization_tag_after_decoder(tmp_path, monkeypatch):
    sender, recipient = _agents()
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, content="organization letter",
                  tags=[["p", recipient.pubkey], ["d", "delivery"],
                        ["a4a_owner", "a" * 64]])
    inner.sign(sender.keys)
    outer = giftwrap.wrap(inner, recipient.pubkey, sender.keys)
    monkeypatch.setattr(recipient, "_decode_incoming", lambda _outer: {
        "from_pubkey": sender.pubkey, "content": inner.content,
        "event": inner, "wrapped": True, "inner_id": inner.id,
        "outer_id": outer.id, "delivery_id": "delivery",
        "outer_event": outer, "conversation_id": None})
    with InboxStore(tmp_path / "inbox", recipient.pubkey, "consumer") as store:
        assert store.accept(recipient, outer, {sender.pubkey}) == "ignored"
        assert store.status()["total"] == 0


async def test_receipt_preserves_conversation_in_signed_inner(monkeypatch):
    sender, recipient = _agents()
    published = []

    async def broadcast(event):
        published.append(event)

    monkeypatch.setattr(sender, "_broadcast", broadcast)
    receipt = await sender.send_private_message_receipt(
        recipient.pubkey, "text", conversation_id=CID)
    assert receipt["inner_id"] == giftwrap.unwrap(published[0], recipient.keys).id
    assert recipient._decode_incoming(published[0])["conversation_id"] == CID


async def test_reliable_delivery_keeps_conversation_across_ack():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender, Agent([relay.url]) as recipient:
            async def receive_and_ack():
                for _ in range(40):
                    messages = await recipient.read_private_messages()
                    if messages:
                        assert messages[0]["conversation_id"] == CID
                        await recipient.acknowledge(messages[0], status="processed")
                        return
                    await asyncio.sleep(0.05)
                pytest.fail("recipient did not get the conversation letter")

            receiver = asyncio.create_task(receive_and_ack())
            result = await sender.deliver_with_ack(
                recipient.pubkey, "status request", private=True,
                conversation_id=CID, retries=1, ack_timeout=2,
                poll_interval=0.05)
            await receiver
            assert result["status"] == "acknowledged"
            assert result["ack_status"] == "processed"


async def test_reliable_delivery_rejects_public_conversation_before_network(monkeypatch):
    sender, recipient = _agents()

    async def forbidden(*_args, **_kwargs):
        pytest.fail("invalid conversation must not start relay discovery")

    monkeypatch.setattr(sender, "resolve_relays", forbidden)
    with pytest.raises(ValueError, match="private gift-wrapped"):
        await sender.deliver_with_ack(
            recipient.pubkey, "text", conversation_id=CID,
            resolve_recipient_relays=True)
