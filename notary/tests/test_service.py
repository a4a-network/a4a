"""Exercise the complete notary cycle with an in-memory relay and fake calendar."""
import base64
import os

import pytest
from a4a import timestamp as a4a_ts
from a4a.event import Event
from a4a.keys import Keys

from a4a_notary import service as svc
from a4a_notary.store import Store
from tests.test_calendar import FakeCalendar


class FakeRelay:
    def __init__(self):
        self.events: list[Event] = []
        self.published: list[Event] = []
        self.fail_publish_after: int | None = None
        # Number of accepted kind-1040 events the relay silently loses through author
        # pruning (finding 85): publication returns OK, but REQ cannot retrieve them.
        self.silently_drop: int = 0

    async def history(self, after: int, limit: int, after_id: str = "") -> list[tuple[int, Event]]:
        """Model node REST `/v1/history` ordering by receipt time, not `created_at`.

        The fake derives `first_seen` from publication order on the relay.
        """
        rows = [(1_800_000_000 + i, e) for i, e in enumerate(self.events)
                if e.kind in (31000, 31007, 31004, 31005, 31020, 31021)]
        return [(fs, e) for fs, e in rows if (fs, e.id) > (after, after_id)][:limit]

    async def query(self, flt: dict) -> list[Event]:
        kinds = set(flt.get("kinds", []))
        since = flt.get("since", 0)
        authors = set(flt.get("authors", []))
        targets = set(flt.get("#e", []))
        pool = self.events + self.published[: len(self.published) - self.silently_drop]
        return [e for e in pool if e.kind in kinds and e.created_at >= since
                and (not authors or e.pubkey in authors)
                and (not targets or e.tag_value("e") in targets)]

    async def publish(self, ev: Event) -> None:
        if self.fail_publish_after is not None and len(self.published) >= self.fail_publish_after:
            raise ConnectionError("relay went away")
        self.published.append(ev)


def _history(n: int, kind: int = 31004, t0: int = 1_700_000_000) -> list[Event]:
    owner = Keys()
    out = []
    for i in range(n):
        ev = Event(kind=kind, tags=[["d", os.urandom(8).hex()]], content="history %d" % i)
        ev.created_at = t0 + i
        out.append(ev.sign(owner))
    return out


@pytest.fixture
def world(tmp_path):
    relay = FakeRelay()
    calendar = FakeCalendar("https://fake")
    store = Store(tmp_path / "n.db")
    notary = svc.NotaryService(relay, store, Keys(), "wss://relay.test",
                               calendars=["https://fake"], factory=lambda url: calendar)
    return relay, calendar, store, notary


async def test_first_pass_batches_and_submits_but_publishes_nothing(world):
    relay, calendar, store, notary = world
    relay.events = _history(5)
    r = await notary.run_once(now=1_700_000_100)
    assert r == {"collected": 5, "finalized": 0, "published": 0, "missing": 0}
    assert len(calendar.submits) == 1, "the batch must use one root, not one per event"
    assert relay.published == []
    assert store.stats() == {"batches": 1, "pending": 1, "leaves": 5, "published": 0}


async def test_same_second_byte_limited_pages_resume_after_restart(world):
    relay, calendar, store, notary = world
    events = sorted(_history(7), key=lambda e: e.id)

    async def history(after, limit, after_id=""):
        # Deliberately return fewer than the requested count, like the byte cap.
        return [(100, e) for e in events if (100, e.id) > (after, after_id)][:2]

    relay.history = history
    total = await notary.collect()
    # Recreate the service: continuation must not be only an in-memory offset.
    notary = svc.NotaryService(relay, store, Keys(), "ws://relay.test",
                               calendars=["https://fake"], factory=lambda _: calendar)
    for _ in range(5):
        total += await notary.collect()
    assert total == 7
    assert all(store.known(e.id) for e in events)
    assert len(calendar.submits) == 4


async def test_after_the_block_every_leaf_gets_a_verifiable_1040(world):
    relay, calendar, store, notary = world
    relay.events = _history(4)
    await notary.run_once(now=1_700_000_100)
    calendar.height = 900_000
    r = await notary.run_once(now=1_700_003_700)
    assert r == {"collected": 0, "finalized": 1, "published": 4, "missing": 0}
    assert len(relay.published) == 4
    ids = {e.id for e in relay.events}
    for att in relay.published:
        assert att.kind == 1040 and att.pubkey == notary.pubkey
        assert att.verify(), "the notary key does not verify the kind-1040 signature"
        target = att.tag_value("e")
        assert target in ids
        assert ["k", "31004"] in att.tags
        assert not att.tag_value("expiration"), "kind 1040 is history and must not expire"
        # Verify with the SDK reader and a fake block header: state must be confirmed.
        proof = a4a_ts.parse_ots(base64.b64decode(att.content, validate=True))
        assert proof.digest.hex() == target
        # The reader compares block merkle roots in display byte order (reversed hex,
        # as shown by explorers and Esplora); the attestation stores its message in
        # internal byte order.
        merkle_root_display = proof.attestations[0].msg[::-1].hex()
        verdict = a4a_ts.verify_stamp(att, target, a4a_ts.StaticHeaders(
            {900_000: (merkle_root_display, 1_700_003_000)}))
        assert verdict.state == "confirmed", verdict
        assert verdict.block_height == 900_000
    # The third pass is quiet: nothing new and nothing duplicated.
    r = await notary.run_once(now=1_700_007_300)
    assert r == {"collected": 0, "finalized": 0, "published": 0, "missing": 0}
    assert len(relay.published) == 4


async def test_publish_is_resumable_after_a_relay_failure(world):
    relay, calendar, store, notary = world
    relay.events = _history(3)
    await notary.run_once()
    calendar.height = 1
    relay.fail_publish_after = 2  # Fail the third publication.
    with pytest.raises(ConnectionError):
        await notary.run_once()
    assert len(relay.published) == 2
    assert store.stats()["published"] == 2
    relay.fail_publish_after = None
    r = await notary.run_once()
    assert r["published"] == 1, "publish only the missing leaf, not all three again"
    assert len(relay.published) == 3
    assert len({e.tag_value("e") for e in relay.published}) == 3


async def test_only_history_kinds_are_collected(world):
    relay, calendar, store, notary = world
    relay.events = _history(2, kind=31002) + _history(1, kind=31007) + _history(1, kind=1040)
    r = await notary.run_once()
    assert r["collected"] == 1, "stamp only history, excluding intents and foreign 1040s"


async def test_new_events_form_a_new_batch_old_ones_are_not_restamped(world):
    relay, calendar, store, notary = world
    relay.events = _history(2, t0=1_700_000_000)
    await notary.run_once()
    relay.events += _history(3, t0=1_700_000_500)
    r = await notary.run_once()
    assert r["collected"] == 3 and store.stats()["batches"] == 2
    assert len(calendar.submits) == 2


async def test_after_publishing_the_notary_rereads_its_stamps_and_warns_about_losses(world, caplog):
    """Detect accepted stamps that the relay later loses (finding 85).

    Author pruning removed kind-1040 events after an OK response, while the notary
    considered the work complete. It now rereads its stamps by batch event ID after
    publication and logs numeric WARNING details if the relay returns fewer than were
    published.
    """
    relay, calendar, store, notary = world
    relay.events = _history(4)
    await notary.run_once(now=1_700_000_100)
    calendar.height = 900_000
    relay.silently_drop = 3  # Accept all four but return only one through REQ.
    with caplog.at_level("WARNING", logger="a4a.notary"):
        r = await notary.run_once(now=1_700_003_700)
    assert r["published"] == 4
    lost = [m for m in caplog.messages if "1040" in m and "4" in m and "1" in m]
    assert lost, "notary missed that the relay returns 1 of 4 stamps: %r" % caplog.messages
    assert r["missing"] == 3


async def test_self_check_is_silent_when_the_relay_keeps_every_stamp(world, caplog):
    relay, calendar, store, notary = world
    relay.events = _history(2)
    await notary.run_once(now=1_700_000_100)
    calendar.height = 900_000
    with caplog.at_level("WARNING", logger="a4a.notary"):
        r = await notary.run_once(now=1_700_003_700)
    assert r["published"] == 2 and r["missing"] == 0
    assert not [m for m in caplog.messages if "1040" in m], caplog.messages


async def test_backdated_history_event_is_stamped_in_the_next_batch(world):
    """Stamp a backdated history event in the next batch (finding 86).

    A peer reproduced this against local node 0.3.13: the node accepted a delegation
    whose `created_at` was two days old, but the notary skipped it because collection
    used a 24-hour `created_at` window. The proof must follow receipt time because that
    establishes the "no later than T" bound.
    """
    relay, calendar, store, notary = world
    relay.events = _history(2, t0=1_700_000_000)
    await notary.run_once(now=1_700_000_100)
    late = _history(1, t0=1_700_000_100 - 2 * 86400)  # Received now, dated two days ago.
    relay.events += late
    r = await notary.run_once(now=1_700_003_700)
    assert r["collected"] == 1, "a backdated event outside 24 hours was never stamped"
    assert store.known(late[0].id)


async def test_collect_never_uses_created_at_filters(world):
    """Guard the collection shape: use history(after, limit), not REQ since/until."""
    relay, calendar, store, notary = world
    calls: list[dict] = []
    original = relay.query

    async def spy(flt):
        calls.append(flt)
        return await original(flt)

    relay.query = spy
    relay.events = _history(3)
    await notary.run_once()
    assert not [c for c in calls if "since" in c or "until" in c], calls


async def test_unsigned_or_tampered_history_is_never_stamped(world, caplog):
    """Reject the documented NIP-03 attack: timestamping an unsigned event ID.

    The notary verifies signatures itself even if the node's REST transport returned
    the event as accepted.
    """
    relay, calendar, store, notary = world
    good = _history(1)
    bad = _history(1)[0].model_copy(update={"content": "tampered after signing"})
    relay.events = good + [bad]
    with caplog.at_level("WARNING", logger="a4a.notary"):
        r = await notary.run_once()
    assert r["collected"] == 1
    assert store.known(good[0].id) and not store.known(bad.id)
    assert [m for m in caplog.messages if "signature" in m], caplog.messages


async def test_cursor_does_not_advance_when_the_store_refuses_the_batch(world, monkeypatch):
    """Advance the cursor only after the batch is stored (finding 110).

    During restamping after a key change, identical event IDs produced the same root.
    The store rejected it through a UNIQUE constraint after the cursor had already
    advanced, losing the events.
    """
    relay, calendar, store, notary = world
    relay.events = _history(2)
    before = store.cursor()

    def refuse(*a, **k):
        raise RuntimeError("store rejected the batch")

    monkeypatch.setattr(store, "add_batch", refuse)
    with pytest.raises(RuntimeError):
        await notary.run_once()
    assert store.cursor() == before, "cursor advanced without a batch and lost events"
    monkeypatch.undo()
    r = await notary.run_once()
    assert r["collected"] == 2, "events were not collected after the store recovered"


async def test_self_check_chunks_fit_the_relay_tag_filter_limit(world):
    """Fit self-check chunks within the relay tag-filter limit (finding 121).

    The self-check sent 200 values in a tag filter while the node accepts 100. The
    entire filter was rejected, so nothing was checked. Before relay 0.3.16 added a
    CLOSED response, this looked like silence and produced a plausible `missing: 0`.
    Every chunk must fit `MAX_TAG_VALUES_PER_FILTER = 100`.
    """
    from a4a_notary import service as svc

    assert svc.SELF_CHECK_CHUNK <= 100, "self-check chunk exceeds the relay tag-filter limit"

    relay, calendar, store, notary = world
    seen: list[int] = []
    original = relay.query

    async def spy(flt):
        if "#e" in flt:
            seen.append(len(flt["#e"]))
        return await original(flt)

    relay.query = spy
    relay.events = _history(250)
    await notary.run_once(now=1_700_000_100)
    calendar.height = 900_000
    r = await notary.run_once(now=1_700_003_700)
    assert r["published"] == 250 and r["missing"] == 0
    assert seen, "self-check made no queries"
    assert max(seen) <= 100, f"chunk size {max(seen)} exceeds the relay limit"
