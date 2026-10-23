"""A reply names the letter it answers inside the signed, wrapped rumor.

26.09.2026, owner's representative: "an agreement without enforcement does not work".
Quoting the delivery-id by hand depended on each agent's discipline, so the reference
now travels as a signed tag and the recipient sees it as `reply_to`.
"""

import asyncio

import pytest

from a4a import Agent, Keys, giftwrap, nip44, types
from a4a.event import Event
from a4a.inbox import InboxStore
from fake_relay import FakeRelay


DELIVERY = "5f0c2d1e9a8b4c3d2e1f0a9b8c7d6e5f"
INNER = "e" * 64
REPLY = (DELIVERY, INNER)


def _agents():
    sender = Agent(["ws://relay.invalid:1"], keys=Keys())
    recipient = Agent(["ws://relay.invalid:1"], keys=Keys())
    return sender, recipient


def _wrapped(sender, recipient, extra_tags):
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, content="text",
                  tags=[["p", recipient.pubkey], ["d", "delivery"], *extra_tags])
    inner.sign(sender.keys)
    return giftwrap.wrap(inner, recipient.pubkey, sender.keys)


def test_reply_reference_is_signed_inside_the_wrap_and_decoded(tmp_path):
    sender, recipient = _agents()
    inner, outer, _ = sender.prepare_private_message(
        recipient.pubkey, "answer", reply_to=REPLY)

    assert ["a4a_reply", DELIVERY, INNER] in inner.tags
    assert DELIVERY not in outer.model_dump_json() and INNER not in outer.model_dump_json()
    assert recipient._decode_incoming(outer)["reply_to"] == {
        "delivery_id": DELIVERY, "inner_id": INNER}

    with InboxStore(tmp_path / "inbox", recipient.pubkey, "consumer") as store:
        assert store.accept(recipient, outer, {sender.pubkey}) == "stored"
        leased = store.claim(recipient, "consumer", {sender.pubkey})
    assert leased["reply_to"] == {"delivery_id": DELIVERY, "inner_id": INNER}


def test_letter_without_reference_decodes_to_none(tmp_path):
    sender, recipient = _agents()
    for wrap in (True, False):
        _, outer, _ = sender.prepare_private_message(recipient.pubkey, "new", wrap=wrap)
        assert recipient._decode_incoming(outer)["reply_to"] is None
    _, outer, _ = sender.prepare_private_message(recipient.pubkey, "new")
    with InboxStore(tmp_path / "inbox", recipient.pubkey, "consumer") as store:
        assert store.accept(recipient, outer, {sender.pubkey}) == "stored"
        assert store.claim(recipient, "consumer", {sender.pubkey})["reply_to"] is None


@pytest.mark.parametrize("tags", [
    [["a4a_reply"]],
    [["a4a_reply", DELIVERY]],
    [["a4a_reply", DELIVERY, INNER, "extra"]],
    [["a4a_reply", DELIVERY, "E" * 64]],
    [["a4a_reply", "bad id with spaces", INNER]],
    [["a4a_reply", DELIVERY, INNER], ["a4a_reply", DELIVERY, INNER]],
])
def test_malformed_reference_never_breaks_decoding(tags):
    """A reference is a hint for the reader, not a routing key: a broken one is dropped."""
    sender, recipient = _agents()
    decoded = recipient._decode_incoming(_wrapped(sender, recipient, tags))
    assert decoded is not None and decoded["content"] == "text"
    assert decoded["reply_to"] is None


def test_plain_event_never_reports_a_reference():
    sender, recipient = _agents()
    plain = Event(kind=types.KIND_PRIVATE_MESSAGE,
                  tags=[["p", recipient.pubkey], ["d", "delivery"],
                        ["a4a_reply", DELIVERY, INNER]],
                  content=nip44.encrypt("text", sender.keys.privkey_hex,
                                        recipient.pubkey))
    plain.sign(sender.keys)
    assert recipient._decode_incoming(plain)["reply_to"] is None


@pytest.mark.parametrize("reply_to", [
    ("", INNER),
    ("x" * 129, INNER),
    ("has space", INNER),
    (DELIVERY, "E" * 64),
    (DELIVERY, "e" * 63),
    (DELIVERY,),
    DELIVERY,
    (DELIVERY, 17),
])
def test_invalid_reference_rejected_before_signing(reply_to):
    sender, recipient = _agents()
    with pytest.raises(ValueError, match="reply_to"):
        sender.prepare_private_message(recipient.pubkey, "text", reply_to=reply_to)
    assert sender._last_addressable == {}


def test_unwrapped_reply_refused_to_keep_the_thread_private():
    sender, recipient = _agents()
    with pytest.raises(ValueError, match="reply_to.*gift wrapping"):
        sender.prepare_private_message(
            recipient.pubkey, "text", wrap=False, reply_to=REPLY)
    assert sender._last_addressable == {}


async def test_receipt_keeps_reference_in_signed_inner(monkeypatch):
    sender, recipient = _agents()
    published = []

    async def broadcast(event):
        published.append(event)

    monkeypatch.setattr(sender, "_broadcast", broadcast)
    await sender.send_private_message_receipt(recipient.pubkey, "text", reply_to=REPLY)
    assert recipient._decode_incoming(published[0])["reply_to"] == {
        "delivery_id": DELIVERY, "inner_id": INNER}


async def test_reliable_delivery_carries_reference_to_recipient():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender, Agent([relay.url]) as recipient:
            async def receive_and_ack():
                for _ in range(40):
                    messages = await recipient.read_private_messages()
                    if messages:
                        assert messages[0]["reply_to"] == {
                            "delivery_id": DELIVERY, "inner_id": INNER}
                        await recipient.acknowledge(messages[0], status="processed")
                        return
                    await asyncio.sleep(0.05)
                pytest.fail("recipient did not get the reply")

            receiver = asyncio.create_task(receive_and_ack())
            result = await sender.deliver_with_ack(
                recipient.pubkey, "answer", private=True, reply_to=REPLY,
                retries=1, ack_timeout=2, poll_interval=0.05)
            await receiver
            assert result["status"] == "acknowledged"


async def test_reliable_delivery_rejects_public_reply_before_network(monkeypatch):
    sender, recipient = _agents()

    async def forbidden(*_args, **_kwargs):
        pytest.fail("invalid reply must not start relay discovery")

    monkeypatch.setattr(sender, "resolve_relays", forbidden)
    with pytest.raises(ValueError, match="reply_to"):
        await sender.deliver_with_ack(recipient.pubkey, "text", reply_to=REPLY,
                                      resolve_recipient_relays=True)
    with pytest.raises(ValueError, match="reply_to"):
        await sender.deliver_with_ack(recipient.pubkey, "text", private=True,
                                      reply_to=(DELIVERY, "bad"),
                                      resolve_recipient_relays=True)


VIA_INNER = "f" * 64


def _via():
    return _agents()[0].pubkey


def test_routed_reply_names_the_forwarder_inside_the_wrap():
    """Representative, 26.09: an answer addressed from a forward line says so, and whose."""
    sender, recipient = _agents()
    VIA = _via()
    inner, outer, _ = sender.prepare_private_message(
        recipient.pubkey, "answer", reply_to=(DELIVERY, INNER, VIA, VIA_INNER))
    assert ["a4a_routed_via", VIA, VIA_INNER] in inner.tags
    assert VIA not in outer.model_dump_json()
    assert recipient._decode_incoming(outer)["reply_to"] == {
        "delivery_id": DELIVERY, "inner_id": INNER,
        "routed_via": {"pubkey": VIA, "inner_id": VIA_INNER}}


def test_malformed_routed_via_is_dropped_not_fatal():
    from a4a.agent import _reply_reference
    from a4a.event import Event
    rumor = Event(kind=14, tags=[["a4a_reply", DELIVERY, INNER], ["a4a_routed_via", "bad", "x"]],
                  content="answer")
    assert _reply_reference(rumor) == {"delivery_id": DELIVERY, "inner_id": INNER}


def test_invalid_routed_via_is_refused_before_signing():
    sender, recipient = _agents()
    with pytest.raises(ValueError, match="routed_via"):
        sender.prepare_private_message(recipient.pubkey, "answer",
                                       reply_to=(DELIVERY, INNER, "bad", VIA_INNER))


def test_the_signed_send_time_reaches_the_reader(tmp_path):
    """Representative, 26.09: a count has two moments - taken and sent. The sent moment is
    set by the tool (the signed inner event), not typed by an agent; the envelope's own
    time is deliberately jittered and must not be shown as the send time."""
    import time
    sender, recipient = _agents()
    before = int(time.time())
    inner, outer, _ = sender.prepare_private_message(recipient.pubkey, '55 \u043f\u0438\u0441\u0435\u043c')
    decoded = recipient._decode_incoming(outer)
    assert decoded["signed_at"] == inner.created_at
    assert before - 1 <= decoded["signed_at"] <= int(time.time()) + 1
    with InboxStore(tmp_path / "inbox", recipient.pubkey, "consumer") as store:
        assert store.accept(recipient, outer, {sender.pubkey}) == "stored"
        leased = store.claim(recipient, "consumer", {sender.pubkey})
    assert leased["signed_at"] == inner.created_at


def test_the_reader_gets_its_own_receive_and_read_times(tmp_path):
    """Representative, 26.09: a letter read a day after it was signed looks as fresh as one read
    in a minute. The receiving side gives its own two moments - when its inbox stored the letter
    and when it was taken for reading - so the reader measures the age of the numbers itself."""
    sender, recipient = _agents()
    inner, outer, _ = sender.prepare_private_message(recipient.pubkey, '55 \u043f\u0438\u0441\u0435\u043c')
    with InboxStore(tmp_path / "inbox", recipient.pubkey, "consumer") as store:
        assert store.accept(recipient, outer, {sender.pubkey}, now=1000) == "stored"
        leased = store.claim(recipient, "consumer", {sender.pubkey}, now=1000 + 7 * 3600)
    assert leased["received_at"] == 1000
    assert leased["read_at"] == 1000 + 7 * 3600
