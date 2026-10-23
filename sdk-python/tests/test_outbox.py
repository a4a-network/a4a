"""Sender-side delivery journal: what the sender still knows after `dead_letter`.

Before 2026-09-23 `deliver_with_ack` returned `dead_letter` and forgot it. Three facts
were lost: that a message went unacknowledged (the session ends, nobody remembers), that
the recipient acknowledged it LATER (a receiver that was down for an hour catches up and
ACKs, but the sender never looks again), and whether any relay accepted the message at
all ("no relay accepted it" and "the recipient is silent" are different facts).
"""
import asyncio

import pytest

from a4a.agent import Agent
from a4a.keys import Keys
from a4a.outbox import OutboxStore
from a4a.relay import RelayError
from tests.fake_relay import FakeRelay

SECRET = "OUTBOX-PLAINTEXT-MARKER-must-never-reach-disk"


async def _ack_later(bob, delay):
    """Acknowledge the first private message after `delay` seconds."""
    await asyncio.sleep(delay)
    for _ in range(40):
        inbox = await bob.read_private_messages()
        if inbox:
            await bob.acknowledge(inbox[0], status="processed")
            return
        await asyncio.sleep(0.05)


async def test_dead_letter_survives_a_restart(tmp_path):
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice:
            silent = Keys().pubkey_hex
            result = await alice.deliver_with_ack(
                silent, "into the void", retries=0, ack_timeout=0.2,
                poll_interval=0.05, private=True, outbox=OutboxStore(tmp_path / "outbox"))
    assert result["status"] == "dead_letter"
    # A new store over the same directory stands in for a new process.
    record = OutboxStore(tmp_path / "outbox").get(result["delivery_id"])
    assert record is not None, "the dead letter was not recorded: it is lost on restart"
    assert record["state"] == "dead_letter"
    assert record["recipient"] == silent
    assert record["attempts"] == 1


async def test_late_ack_is_found_by_recheck(tmp_path):
    store = OutboxStore(tmp_path / "outbox")
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            result = await alice.deliver_with_ack(
                bob.pubkey, "late", retries=0, ack_timeout=0.2,
                poll_interval=0.05, private=True, outbox=store)
            assert result["status"] == "dead_letter"
            await _ack_later(bob, 0)  # the recipient's receiver comes back
            record = await alice.recheck_delivery(store, result["delivery_id"])
    assert record["state"] == "acknowledged", "a late ACK stayed invisible to the sender"
    assert record["ack_status"] == "processed"
    assert record["late"] is True


async def test_republish_sends_the_same_envelope(tmp_path):
    store = OutboxStore(tmp_path / "outbox")
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice:
            silent = Keys().pubkey_hex
            result = await alice.deliver_with_ack(
                silent, "again", retries=0, ack_timeout=0.2,
                poll_interval=0.05, private=True, outbox=store)
            stored_id = store.get(result["delivery_id"])["envelope_ids"][-1]
            before = len(relay.events)
            republished = await alice.republish_delivery(store, result["delivery_id"])
            sent = relay.events[before:]
    assert republished == stored_id, "republish built a new message instead of resending"
    assert [e["id"] for e in sent] == [stored_id]
    assert store.get(result["delivery_id"])["republished"] == 1


async def test_no_relay_accepted_is_not_dead_letter(tmp_path):
    store = OutboxStore(tmp_path / "outbox")
    async with FakeRelay(reject_reason="blocked: test") as relay:
        async with Agent([relay.url]) as alice:
            with pytest.raises(RelayError):
                await alice.deliver_with_ack(
                    Keys().pubkey_hex, "nowhere", retries=0, ack_timeout=0.2,
                    poll_interval=0.05, private=True, outbox=store)
    records = store.list()
    assert len(records) == 1
    assert records[0]["state"] == "publish_failed", \
        "a message no relay accepted was recorded as if it had been sent"
    assert records[0]["envelope_ids"] == []


async def test_journal_holds_no_plaintext(tmp_path):
    store = OutboxStore(tmp_path / "outbox")
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice:
            await alice.deliver_with_ack(
                Keys().pubkey_hex, SECRET, retries=0, ack_timeout=0.2,
                poll_interval=0.05, private=True, outbox=store)
    store.close()
    files = [p for p in (tmp_path / "outbox").iterdir() if p.is_file()]
    assert files, "the journal wrote nothing, so this check would pass vacuously"
    for path in files:
        assert SECRET.encode() not in path.read_bytes(), f"plaintext leaked into {path.name}"


async def test_recheck_upgrades_received_to_processed(tmp_path):
    """A `received` receipt is not the end: recheck must see the later `processed` ACK."""
    store = OutboxStore(tmp_path / "outbox")
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            async def receipt_then_work():
                for _ in range(40):
                    inbox = await bob.read_private_messages()
                    if inbox:
                        await bob.acknowledge(inbox[0], status="received")
                        return inbox[0]
                    await asyncio.sleep(0.05)

            task = asyncio.create_task(receipt_then_work())
            result = await alice.deliver_with_ack(
                bob.pubkey, "two stage", retries=1, ack_timeout=1.0,
                poll_interval=0.05, private=True, outbox=store)
            message = await task
            assert result["ack_status"] == "received"
            await bob.acknowledge(message, status="processed")
            record = await alice.recheck_delivery(store, result["delivery_id"])
    assert record["state"] == "acknowledged"
    assert record["ack_status"] == "processed", "the journal froze at 'received'"
    assert record["late"] is False, "the delivery was acknowledged in time, only upgraded later"


async def test_journal_keeps_when_the_recipient_signed_the_ack(tmp_path):
    """Two different moments: the recipient signed the ACK, and we found it.

    A pilot partner noticed on 23.09.2026 that a journal said 17:18 for ACKs signed at
    16:09 - it stored only the moment of the recheck. In a dispute both matter.
    """
    store = OutboxStore(tmp_path / "outbox")
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            result = await alice.deliver_with_ack(
                bob.pubkey, "sign time", retries=0, ack_timeout=0.2,
                poll_interval=0.05, private=True, outbox=store)
            await _ack_later(bob, 0)
            await asyncio.sleep(2.2)
            record = await alice.recheck_delivery(store, result["delivery_id"])
    assert record["state"] == "acknowledged"
    assert isinstance(record["ack_signed_at"], int), "the signed time was not kept"
    assert record["ack_at"] - record["ack_signed_at"] >= 1.5, \
        "the journal still shows only when we found the ACK"


def test_journal_from_before_the_signed_time_column_still_opens(tmp_path):
    """Journals written earlier the same day (the live pilot has them) must keep working."""
    import sqlite3
    directory = tmp_path / "outbox"
    OutboxStore(directory).close()
    db = sqlite3.connect(directory / "outbox.sqlite3")
    db.execute("ALTER TABLE deliveries DROP COLUMN ack_signed_at")
    db.execute("INSERT INTO deliveries (delivery_id, recipient, private, created, since, "
               "updated, state) VALUES ('d-old', ?, 1, 1, 1, 1, 'dead_letter')", ("a" * 64,))
    db.commit()
    db.close()
    store = OutboxStore(directory)
    record = store.get("d-old")
    assert record["state"] == "dead_letter" and record["ack_signed_at"] is None


def test_recheck_schedule_backs_off_and_gives_up(tmp_path):
    """Undelivered records come due with growing gaps and stop after 48 hours.

    The owner's rule (23.09.2026): if an agent has to remember a manual command after
    every failure, the logic belongs in the protocol client, not in the agent.
    """
    store = OutboxStore(tmp_path / "outbox")
    store.start("d1", "a" * 64, private=True, since=0)
    store.finish("d1", "dead_letter", attempts=4)
    created = store.get("d1")["created"]
    assert store.due_for_recheck(created + 30) == [], "rechecked before the first gap"
    assert store.due_for_recheck(created + 61) == ["d1"]
    store.mark_rechecked("d1", created + 61)
    assert store.due_for_recheck(created + 62) == [], "rechecked again without waiting"
    assert store.due_for_recheck(created + 61 + 301) == ["d1"], "second gap is five minutes"
    assert store.due_for_recheck(created + 48 * 3600 + 1) == [], "gave up after 48 hours"


def test_final_and_unsent_records_are_never_due(tmp_path):
    store = OutboxStore(tmp_path / "outbox")
    for did, state, status in (("ok", "acknowledged", "processed"),
                               ("rx", "acknowledged", "received"),
                               ("nf", "publish_failed", None)):
        store.start(did, "a" * 64, private=True, since=0)
        store.finish(did, state, ack_status=status)
    created = store.get("ok")["created"]
    assert store.due_for_recheck(created + 120) == ["rx"], \
        "only a 'received' receipt still waits for its final word"


async def test_recheck_due_heals_a_dead_letter_without_the_agent(tmp_path):
    """The always-on loop finds the late ACK; nobody has to remember a command."""
    store = OutboxStore(tmp_path / "outbox")
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            result = await alice.deliver_with_ack(
                bob.pubkey, "heal me", retries=0, ack_timeout=0.2,
                poll_interval=0.05, private=True, outbox=store)
            await _ack_later(bob, 0)
            created = store.get(result["delivery_id"])["created"]
            too_early = await alice.recheck_due(store, now=created + 10)
            healed = await alice.recheck_due(store, now=created + 61)
    assert too_early == {"checked": 0, "acknowledged": 0}
    assert healed == {"checked": 1, "acknowledged": 1}
    record = store.get(result["delivery_id"])
    assert record["state"] == "acknowledged" and record["late"] is True
