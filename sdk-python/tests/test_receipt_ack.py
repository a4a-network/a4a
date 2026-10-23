"""An opt-in 'received' ACK when a letter lands in the mailbox.

On 23.09.2026 two letters from a pilot partner's agent reached the A4A pilot mailbox within
seconds and then sat there for an hour: the receiver stored them, but an ACK was sent
only when someone completed the work, and nobody was looking. The sender saw silence,
retried, and concluded the other side was down. `received` and `processed` already
exist as ACK statuses; this sends the first one on storage, honestly: delivered to the
mailbox, not yet processed.
"""
import time

from a4a import Agent, Keys, giftwrap
from a4a.inbox import InboxStore
from a4a.inbox_receiver import InboxReceiver
from tests.fake_relay import FakeRelay


async def _letter(relay_url, sender_keys, recipient_keys, delivery_id):
    async with Agent([relay_url], sender_keys) as sender:
        _inner, outer, _ = sender.prepare_private_message(
            recipient_keys.pubkey_hex, "hello", delivery_id=delivery_id, wrap=True)
    return outer


class _History:
    def __init__(self, event):
        self.event = event

    async def page(self, cursor):
        return [(200, self.event)] if cursor[0] < 200 else []


async def _receipts(relay_url, sender_keys, recipient_keys, delivery_id):
    async with Agent([relay_url], sender_keys) as sender:
        return await sender._get_wrapped_acks(
            delivery_id, from_pubkey=recipient_keys.pubkey_hex,
            since=int(time.time()) - giftwrap._JITTER_SECONDS - 60)


async def _run(tmp_path, *, ack_on_receipt, allowed):
    recipient, sender = Keys(), Keys()
    async with FakeRelay() as relay:
        outer = await _letter(relay.url, sender, recipient, "d-receipt")
        agent = Agent([relay.url], keys=recipient)
        allowed_keys = {sender.pubkey_hex} if allowed else {Keys().pubkey_hex}
        with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
            receiver = InboxReceiver(agent, store, lambda: allowed_keys, start_after=150,
                                     history=_History(outer), ack_on_receipt=ack_on_receipt)
            stored = await receiver.sync_once()
            pending = store.status()["pending"]
        return stored, pending, await _receipts(relay.url, sender, recipient, "d-receipt")


async def test_received_ack_is_sent_when_the_letter_is_stored(tmp_path):
    stored, pending, acks = await _run(tmp_path, ack_on_receipt=True, allowed=True)
    assert stored == 1 and pending == 1, "the letter must still await processing"
    assert [a["status"] for a in acks] == ["received"], \
        "the sender learns nothing until someone completes the work"


async def test_no_receipt_ack_unless_the_mailbox_opts_in(tmp_path):
    stored, _, acks = await _run(tmp_path, ack_on_receipt=False, allowed=True)
    assert stored == 1 and acks == []


async def test_a_stranger_never_gets_a_receipt(tmp_path):
    """A receipt tells the sender the mailbox exists and is watched; strangers get nothing."""
    stored, _, acks = await _run(tmp_path, ack_on_receipt=True, allowed=False)
    assert stored == 0 and acks == []


async def test_a_failed_receipt_does_not_lose_the_letter(tmp_path):
    """The relay refuses the receipt: the letter is still stored and still pending."""
    recipient, sender = Keys(), Keys()
    async with FakeRelay() as source:
        outer = await _letter(source.url, sender, recipient, "d-refused")
    async with FakeRelay(reject_reason="blocked: receipts refused") as relay:
        agent = Agent([relay.url], keys=recipient)
        with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
            receiver = InboxReceiver(agent, store, lambda: {sender.pubkey_hex}, start_after=150,
                                     history=_History(outer), ack_on_receipt=True)
            assert await receiver.sync_once() == 1
            assert store.status()["pending"] == 1
            assert store.health()["state"] == "ready", "a refused receipt is not a relay outage"
