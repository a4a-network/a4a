"""Cleanup after live checks (`scripts/live_cleanup.py`) deletes real data.

The 2026-09-05 internal audit found 92 mandates and 26 delegation revocations from 83
disposable keys in production, all residue from our live checks. Mandates and revocations
do not expire from history, so a newcomer querying `kinds=[31000]` would see a hundred
test agents instead of real ones. Checks must clean up after themselves.

These tests prove deletion occurs, uses ONLY the publisher's own keys, and never turns a
cleanup failure into a primary-check failure.
"""
import asyncio
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

from live_cleanup import Cleanup, sweep                          # noqa: E402

from a4a import Agent, Keys, types                               # noqa: E402
from a4a.event import Event                                      # noqa: E402
from tests.fake_relay import FakeRelay                           # noqa: E402


def _intent(keys: Keys, mark: str) -> Event:
    return Event(kind=types.KIND_INTENT, tags=[["d", mark]], content=mark).sign(keys)


async def test_sweep_removes_everything_the_keys_published():
    mine, theirs = Keys(), Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], mine) as a:
            for i in range(3):
                await a.relay.publish(_intent(mine, f"mine {i}"))
            await a.relay.publish(_intent(theirs, "theirs"))
            removed = await sweep(relay.url, [mine], verbose=False)
            left = await a.relay.query({"authors": [mine.pubkey_hex, theirs.pubkey_hex]})
    assert removed == 3
    mine_left = [e for e in left if e.pubkey == mine.pubkey_hex]
    # Exactly one deletion remains from our key; deletions cannot themselves be deleted.
    assert [e.kind for e in mine_left] == [5]
    assert any(e.pubkey == theirs.pubkey_hex for e in left), "must not touch another author"


async def test_sweep_covers_mandates_and_revocations():
    """Mandates and revocations are history and therefore require explicit deletion."""
    from a4a.delegation import create_delegation, create_revocation

    owner, agent_keys = Keys(), Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], agent_keys) as a:
            deleg = create_delegation(owner, agent_keys.pubkey_hex, "probe", 2 ** 31)
            await a.relay.publish(deleg)
            await a.relay.publish(create_revocation(owner, deleg))
            await a.relay.publish(_intent(agent_keys, "intent"))
            kinds_before = {e.kind for e in await a.relay.query(
                {"authors": [owner.pubkey_hex, agent_keys.pubkey_hex]})}
            removed = await sweep(relay.url, [owner, agent_keys], verbose=False)
            left = [e for e in await a.relay.query(
                {"authors": [owner.pubkey_hex, agent_keys.pubkey_hex]}) if e.kind != 5]
    assert {types.KIND_DELEGATION, types.KIND_DELEGATION_REVOCATION} <= kinds_before
    assert removed == 3 and left == [], "mandate and revocation must be deleted too"


async def test_deletions_are_batched_per_key_and_capped():
    """Use kind 5 per key without exceeding the target cap or the tail silently fails."""
    keys = Keys()
    ids = [f"{i:064x}" for i in range(Cleanup.MAX_TARGETS + 5)]
    async with FakeRelay() as relay:
        cleanup = Cleanup(relay.url, verbose=False)
        cleanup.track(keys, *ids)
        removed = await cleanup.run()
        deletions = [e for e in relay.events if e["kind"] == 5]
    assert removed == len(ids)
    assert len(deletions) == 2, "targets must be chunked at the per-event cap"
    assert all(len([t for t in d["tags"] if t[0] == "e"]) <= Cleanup.MAX_TARGETS
               for d in deletions)


async def test_cleanup_failure_does_not_raise():
    """Cleanup is non-critical: log its failure without failing the primary check."""
    assert await sweep("ws://127.0.0.1:1/never", [Keys()], verbose=False) == 0
    cleanup = Cleanup("ws://127.0.0.1:1/never", verbose=False)
    cleanup.track(Keys(), "a" * 64)
    assert await cleanup.run() == 0


async def test_sweep_without_keys_is_a_no_op():
    assert await sweep("ws://127.0.0.1:1/never", [], verbose=False) == 0

async def test_second_sweep_leaves_the_deletion_alone():
    """A second cleanup must not delete its own deletion event.

    Without skipping kind 5, the second run treats the deletion as its own event and
    publishes a deletion of a deletion, creating infinite history residue. Mutation
    showed that the first test version missed this.
    """
    keys = Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys) as a:
            await a.relay.publish(_intent(keys, "one intent"))
            assert await sweep(relay.url, [keys], verbose=False) == 1
            assert await sweep(relay.url, [keys], verbose=False) == 0, \
                "second pass must delete nothing"
            deletions = [e for e in relay.events if e["kind"] == 5]
    assert len(deletions) == 1, "second deletion must not be published"


# --- query boundaries: both fail silently -----------------------------------------
#
# The node rejects a filter containing more than 256 authors and returns only the newest
# `limit` events. Both limits look successful: the first finds nothing and the second
# reports a truncated deletion count. A collaborator found both while auditing arbitrary-
# length inputs on 2026-09-05.

async def test_sweep_collects_everything_past_one_page():
    """Cleanup must fetch beyond one page rather than silently truncating events.

    Timestamps deliberately arrive in GROUPS of three events per second. A page boundary
    likely splits a group, proving that `until` must not skip other events from the same
    second. With unique timestamps, mutation showed this test stayed green even when the
    cursor subtracted one second.
    """
    from live_cleanup import PAGE

    keys = Keys()
    total = PAGE + 7
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys) as a:
            base = int(time.time()) - total
            for i in range(total):
                ev = _intent(keys, f"event {i}")
                ev.created_at = base + i // 3     # Three events per second.
                ev.sign(keys)
                await a.relay.publish(ev)

            # The fake MUST truncate results; otherwise "cleanup fetched the tail" proves
            # nothing because one query returned everything. Mutation exposed this.
            page = await a.relay.query({"authors": [keys.pubkey_hex], "limit": PAGE})
            assert len(page) == PAGE, f"query was not capped: {len(page)}"

            removed = await sweep(relay.url, [keys], verbose=False)
            left = [e for e in await a.relay.query({"authors": [keys.pubkey_hex],
                                                    "limit": 5000}) if e.kind != 5]
    assert removed == total, f"deleted {removed} of {total}; tail was lost"
    assert left == [], f"{len(left)} events remain"


async def test_saturated_page_is_reported_incomplete_not_complete(capsys):
    """When one timestamp exceeds a page, cleanup must REPORT incomplete enumeration.

    Pagination advances by time. If more than one page shares the same `created_at`, the
    cursor cannot move and the next query returns the same page, stopping before the tail.

    The old code simply exited and reported "deleted 500 of 500" while seven remained
    without warning. External review found TEST-CLEAN-001 on a real node. The neighboring
    test cannot expose this because three-event groups let its cursor advance.
    """
    from live_cleanup import PAGE

    keys = Keys()
    total = PAGE + 7
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys) as a:
            stamp = int(time.time()) - 10
            for i in range(total):
                ev = _intent(keys, f"simultaneous {i}")
                ev.created_at = stamp          # All in one second; cursor cannot advance.
                ev.sign(keys)
                await a.relay.publish(ev)

            removed = await sweep(relay.url, [keys], verbose=True)
            left = [e for e in await a.relay.query({"authors": [keys.pubkey_hex],
                                                    "limit": 5000}) if e.kind != 5]

    said = capsys.readouterr().out
    if left:
        assert "COULD NOT BE CONFIRMED" in said, (
            f"{len(left)} events remain but cleanup gave no incompleteness warning; "
            f"deleted {removed}")
    else:
        # A warning is allowed even after collecting everything because the conservative
        # signal also fires at exactly PAGE simultaneous events. It must not CLAIM residue
        # definitely remains when none does (TEST-CLEAN-002/P3).
        assert removed == total
        assert "Some events WILL remain" not in said, (
            "cleanup claims residue remains although the node is empty")


async def test_sweep_splits_authors_across_filters():
    """Split authors across filters when their count exceeds the node cap.

    The node rejects an oversized filter ENTIRELY, so cleanup finds nothing and reports
    zero deleted, indistinguishable from there being nothing to remove.
    """
    from live_cleanup import AUTHORS_PER_FILTER, _all_own_events

    asked: list[int] = []

    class _Rec:
        async def query(self, flt):
            asked.append(len(flt["authors"]))
            assert len(flt["authors"]) <= AUTHORS_PER_FILTER, "filter exceeds node cap"
            return []

    pubkeys = [f"{i:064x}" for i in range(AUTHORS_PER_FILTER * 2 + 5)]
    got, complete = await _all_own_events(_Rec(), pubkeys)
    assert got == []
    # Empty results mean exhaustion, not inaccessibility; the enumerator must distinguish.
    assert complete, "empty node response treated as incomplete enumeration"
    assert len(asked) == 3 and sum(asked) == len(pubkeys), f"queries: {asked}"


async def test_sweep_stops_when_events_share_one_second():
    """Events sharing one `created_at` value must not loop the cursor forever.

    `until` is inclusive, so advancing to the minimum timestamp returns the same events.
    Stop when no NEW events appear or cleanup loops indefinitely.
    """
    keys = Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys) as a:
            stamp = int(time.time())
            for i in range(5):
                ev = _intent(keys, f"simultaneous {i}")
                ev.created_at = stamp
                ev.sign(keys)
                await a.relay.publish(ev)
            removed = await asyncio.wait_for(sweep(relay.url, [keys], verbose=False), 10)
    assert removed == 5
