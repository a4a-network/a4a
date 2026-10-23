"""Reliable delivery: AckReceipt and acknowledge/get_acks/deliver_with_ack (P1)."""
import asyncio

import pytest
from pydantic import ValidationError

from a4a import types
from a4a.agent import Agent
from a4a.keys import Keys
from tests.fake_relay import FakeRelay


# --- AckReceipt model ----------------------------------------------------------

def test_ack_receipt_roundtrip():
    ack = types.AckReceipt(delivery_id="deliv1", acked_event_id="ev1",
                           to_pubkey="a" * 64, status="processed", content="ok")
    ev = ack.to_event(delegation_id="delg1")
    assert ev.kind == types.KIND_ACK_RECEIPT
    assert ev.tag_value("d") == "deliv1"          # addressable by delivery_id
    assert ev.tag_value("e") == "ev1"
    assert ev.tag_value("p") == "a" * 64
    assert ev.tag_value("status") == "processed"
    assert ev.tag_value("delegation") == "delg1"
    back = types.AckReceipt.from_event(ev)
    assert (back.delivery_id, back.acked_event_id, back.to_pubkey, back.status) == \
           ("deliv1", "ev1", "a" * 64, "processed")


def test_ack_receipt_rejects_unknown_status():
    with pytest.raises(ValidationError):
        types.AckReceipt(delivery_id="d", acked_event_id="e",
                         to_pubkey="a" * 64, status="totally_bogus")


# --- acknowledge + get_acks ----------------------------------------------------

async def test_acknowledge_and_get_acks():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            did = "delivery-xyz"
            await alice.send_private_message(bob.pubkey, "hello", delivery_id=did)
            inbox = await bob.read_private_messages()
            assert len(inbox) == 1

            ack_id = await bob.acknowledge(inbox[0], status="received")
            assert ack_id

            acks = await alice.get_acks(did, from_pubkey=bob.pubkey)
            assert len(acks) == 1
            assert acks[0]["acker_pubkey"] == bob.pubkey
            assert acks[0]["status"] == "received"
            assert acks[0]["delivery_id"] == did


async def test_get_acks_ignores_ack_addressed_to_another_sender():
    # delivery_id (tag d) is visible as plaintext. Mallory reuses another sender's
    # delivery_id for a message to Bob, and Bob acknowledges THAT message. The receipt
    # (p=mallory) must not count for Alice's delivery, or deliver_with_ack could return
    # a false "acknowledged" result.
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob, \
                Agent([relay.url]) as mallory:
            did = "shared-delivery-id"
            await alice.send_private_message(bob.pubkey, "from Alice", delivery_id=did)
            await mallory.send_private_message(bob.pubkey, "from Mallory", delivery_id=did)

            inbox = await bob.read_private_messages()
            mallory_msg = next(m for m in inbox if m["from_pubkey"] == mallory.pubkey)
            await bob.acknowledge(mallory_msg, status="processed")  # p = mallory

            # Alice does NOT see this as confirmation of her delivery.
            assert await alice.get_acks(did, from_pubkey=bob.pubkey) == []
            # Mallory, the actual ACK recipient, does see it.
            mallory_acks = await mallory.get_acks(did, from_pubkey=bob.pubkey)
            assert len(mallory_acks) == 1
            assert mallory_acks[0]["to_pubkey"] == mallory.pubkey


async def test_get_acks_filters_by_acker():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            did = "delivery-filter"
            await alice.send_private_message(bob.pubkey, "x", delivery_id=did)
            inbox = await bob.read_private_messages()
            await bob.acknowledge(inbox[0])
            # Filtering by an unrelated pubkey returns nothing.
            assert await alice.get_acks(did, from_pubkey="f" * 64) == []


async def test_acknowledge_requires_delivery_id():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as bob:
            from a4a.event import Event
            bogus = Event(kind=types.KIND_PRIVATE_MESSAGE, tags=[["p", bob.pubkey]],
                          content="no-d-tag").sign(bob.keys)
            with pytest.raises(ValueError):
                await bob.acknowledge(bogus)


# --- deliver_with_ack ----------------------------------------------------------

async def test_deliver_with_ack_acknowledged():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            async def recv_and_ack():
                for _ in range(40):
                    inbox = await bob.read_private_messages()
                    if inbox:
                        await bob.acknowledge(inbox[0], status="processed")
                        return
                    await asyncio.sleep(0.05)

            task = asyncio.create_task(recv_and_ack())
            result = await alice.deliver_with_ack(
                bob.pubkey, "confidential meeting note", retries=5,
                ack_timeout=2.0, poll_interval=0.05)
            await task

            assert result["status"] == "acknowledged"
            assert result["ack_status"] == "processed"
            assert result["delivery_id"]


async def test_deliver_with_ack_dead_letter_when_no_ack():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice:
            unreachable = Keys().pubkey_hex  # nobody will acknowledge this address
            result = await alice.deliver_with_ack(
                unreachable, "into the void", retries=1,
                ack_timeout=0.2, poll_interval=0.05)
            assert result["status"] == "dead_letter"
            assert result["ack_status"] is None
            assert result["attempts"] == 2  # initial attempt plus one retry
