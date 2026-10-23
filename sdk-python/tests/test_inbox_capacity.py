"""Inbox growth must be a visible number rather than a surprise (2026-09-08).

The store has a hard ceiling of 10,000 letters or 64 MiB. Once reached, it stops
accepting new mail; `InboxFull` visibly moves receiver health to `failed`. But there
was NO way to see that the limit was approaching: `status()` counted letters by
state without reporting occupied space.

Measurements on live profiles on 2026-09-08 showed 275 and 496 KiB per day, reaching
the ceiling in January and May 2027. A predictable date must be observable in advance.
A report without the number reveals the problem only after mail is already rejected.

Processed letters are retained as protocol evidence and must not be deleted
automatically. The honest safeguard is therefore to expose consumption.
"""
import importlib
import importlib.util
import sys

import pytest

from a4a import Agent, Keys, giftwrap, types
from a4a.event import Event


@pytest.fixture
def api():
    assert importlib.util.find_spec("a4a.inbox") is not None
    return importlib.import_module("a4a.inbox")


@pytest.fixture
def people():
    return Keys(), Keys()


def letter(sender, recipient, delivery, text="payload"):
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, content=text,
                  tags=[["p", recipient.pubkey_hex], ["d", delivery]], created_at=100)
    inner.sign(sender)
    return giftwrap.wrap(inner, recipient.pubkey_hex, sender, now=200000)


def test_status_reports_used_space_and_the_ceiling(api, tmp_path, people):
    """Report usage, units, and ceiling so operators can see the limit approach."""
    sender, recipient = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    with api.InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "session-a") as store:
        empty = store.status(now=200000)
        assert empty["bytes"] == 0, "an empty inbox must report zero, not omit the field"
        assert empty["capacity_bytes"] == store.max_bytes
        assert empty["capacity_items"] == store.max_items

        store.accept(agent, letter(sender, recipient, "one"), {sender.pubkey_hex}, now=200000)
        filled = store.status(now=200000)
        assert filled["bytes"] > empty["bytes"], "used space did not grow after a letter"
        assert filled["bytes"] < filled["capacity_bytes"]


def test_used_space_counts_processed_letters_too(api, tmp_path, people):
    """HISTORY consumes space, not merely the queue; processed mail remains stored.

    Counting only pending mail would show almost zero precisely when the inbox is
    full of processed correspondence, which is the normal case here.
    """
    sender, recipient = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with api.InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "session-a") as store:
        store.accept(agent, letter(sender, recipient, "one"), allowed, now=200000)
        job = store.claim(agent, "session-a", allowed, now=200001)
        store.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200002)
        after = store.status(now=200002)
        assert after["processed"] == 1
        assert after["bytes"] > 0, "processed letter disappeared from space accounting"


def test_capacity_is_configurable_without_touching_the_default(api, tmp_path, people):
    """A parameter may raise the ceiling while leaving the default unchanged.

    Negative control for the third step: callers may raise their own limit, but the
    default must not silently change for everyone.
    """
    _, recipient = people
    with api.InboxStore(tmp_path / "a", recipient.pubkey_hex, "session-a") as default:
        assert default.max_bytes == 64 * 1024 * 1024
    with api.InboxStore(tmp_path / "b", recipient.pubkey_hex, "session-a",
                        max_bytes=512 * 1024 * 1024) as roomy:
        assert roomy.status(now=200000)["capacity_bytes"] == 512 * 1024 * 1024


def test_compacted_rows_are_reported_separately(api, tmp_path, people, monkeypatch):
    """Compaction reclaims BYTES but not SLOTS in the letter count.

    The two counters behave differently and must be exposed separately; neither can
    be derived from the other, and they are easy to confuse. Tombstones are never
    evicted automatically, or capacity checks would pass by forgetting identities.
    """
    sender, recipient = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with api.InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "session-a") as store:
        store.accept(agent, letter(sender, recipient, "one"), allowed, now=200000)
        job = store.claim(agent, "session-a", allowed, now=200001)
        store.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200002)
        before = store.status(now=200003)
        assert before["compacted"] == 0
        assert before["bytes"] > 0

        # Open compaction explicitly. Production refuses it until export durability
        # has a defined boundary, but the behavior still needs coverage or it will
        # silently decay.
        monkeypatch.setattr(api.InboxStore, "DURABLE_ARCHIVE_PLATFORMS", (sys.platform,))
        store.prune(before=200_100, archive=tmp_path / "a.json", compact=True, now=200004)

        after = store.status(now=200005)
        assert after["compacted"] == 1, "compacted row was not reported separately"
        assert after["bytes"] == 0, "envelope bytes were not reclaimed"
        assert after["total"] == before["total"], "letter slot was freed and tombstone lost"
