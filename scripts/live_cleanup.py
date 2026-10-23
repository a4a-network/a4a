"""Clean up after a live check by deleting everything it published to the relay.

WHY. Live checks publish real events with real keys or they verify nothing. Mandates
(31000) and revocations (31007) are historical records, however, so the relay does not
expire them. After a week of checks, production can appear to contain a hundred throwaway
agents and no real ones. A 2026-09-05 production measurement found 294 events, including
92 mandates and 26 delegation revocations from 83 disposable keys, all test residue.

HOW. At the end, every key that signed an event publishes one deletion event (kind 5)
referencing its own events. Deleting another author's data is neither possible nor
necessary: the relay accepts kind 5 only from the deleted event's author.

Deletion events themselves remain permanently, one per key. They cannot be deleted, but
they are visible as cleanup records rather than network agents.

USAGE:

    from live_cleanup import Cleanup
    cleanup = Cleanup(RELAY)
    cleanup.track(keys, event_id)          # after each successful publication
    ...
    await cleanup.run()                    # at the end, even when the check fails
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk-python"))

from a4a.event import Event                                   # noqa: E402
from a4a.keys import Keys                                     # noqa: E402
from a4a.relay import RelayClient, RelayError                 # noqa: E402


class Cleanup:
    """Collect published IDs by key and delete them with one kind 5 per key."""

    #: NIP-09 does not limit `e` tags, but this relay accepts at most 64 targets per event
    #: after filtering junk and duplicates. Chunk explicitly or the tail silently fails.
    MAX_TARGETS = 64

    def __init__(self, relay_url: str, verbose: bool = True):
        self.relay_url = relay_url
        self.verbose = verbose
        self._by_key: dict[str, tuple[Keys, list[str]]] = {}

    def track(self, keys: Keys, *event_ids: str) -> None:
        """Record events published by this key."""
        entry = self._by_key.setdefault(keys.pubkey_hex, (keys, []))
        entry[1].extend(i for i in event_ids if i)

    def track_event(self, keys: Keys, event: Event) -> None:
        self.track(keys, event.id)

    @property
    def tracked(self) -> int:
        return sum(len(ids) for _, ids in self._by_key.values())

    async def run(self) -> int:
        """Publish deletions and return the number of deleted events.

        Cleanup errors do not fail the primary check. They remain visible in the log and
        are useful findings themselves because the relay rejected kind 5.
        """
        if not self._by_key:
            return 0
        removed = 0
        try:
            async with RelayClient(self.relay_url, timeout=15) as rc:
                for keys, ids in self._by_key.values():
                    unique = list(dict.fromkeys(ids))
                    for start in range(0, len(unique), self.MAX_TARGETS):
                        chunk = unique[start:start + self.MAX_TARGETS]
                        ev = Event(kind=5, tags=[["e", i] for i in chunk],
                                   content="A4A live-check cleanup").sign(keys)
                        try:
                            await rc.publish(ev)
                            removed += len(chunk)
                        except RelayError as e:
                            self._say(f"  cleanup: relay rejected deletion from "
                                      f"{keys.pubkey_hex[:12]}…: {e}")
        except Exception as e:                    # noqa: BLE001 - cleanup is non-critical
            self._say(f"  cleanup failed ({type(e).__name__}: {e}); events remain on "
                      f"the relay and must be deleted manually with the same keys")
            return removed
        self._say(f"  cleanup: deleted {removed} of {self.tracked} events "
                  f"({len(self._by_key)} keys, one kind 5 per key)")
        return removed

    def _say(self, text: str) -> None:
        if self.verbose:
            print(text, flush=True)


async def cleanup_after(relay_url: str, pairs) -> int:
    """One-shot cleanup; `pairs` is a sequence of (Keys, [id, ...])."""
    c = Cleanup(relay_url)
    for keys, ids in pairs:
        c.track(keys, *ids)
    return await c.run()


#: Maximum authors accepted in one filter (`MAX_IDS_OR_AUTHORS_PER_FILTER`). A longer
#: filter is rejected ENTIRELY: not "some missing," but "nothing found."
AUTHORS_PER_FILTER = 256

#: Query page size. The node returns the newest `limit` events, so "everything at once"
#: works only until more events exist.
PAGE = 500


async def _all_own_events(rc, pubkeys: list[str]) -> tuple[list, bool]:
    """Fetch all events for these keys, 256 authors per filter and paged by `until`.

    One `{"authors": [...], "limit": 1000}` query looked exhaustive while there were few
    keys and hundreds of events. Both boundaries fail silently: more than 256 authors
    makes the node reject the whole filter, while more than one page truncates the tail.
    Both can resemble success, so this implementation avoids both.

    RETURNS a pair: found events and a COMPLETENESS flag. Without completeness, cleanup
    can report "deleted 500 of 500" while seven events remain unnoticed.

    The flag is conservative, not exact. False means completeness could not be confirmed,
    including cases where nothing actually remains. Do not read it as proof of residue.
    """
    seen: dict[str, object] = {}
    complete = True
    for start in range(0, len(pubkeys), AUTHORS_PER_FILTER):
        chunk = pubkeys[start:start + AUTHORS_PER_FILTER]
        until = None
        while True:
            flt = {"authors": chunk, "limit": PAGE}
            if until is not None:
                flt["until"] = until
            page = await rc.query(flt)
            fresh = [e for e in page if e.id not in seen]
            for ev in page:
                seen[ev.id] = ev
            if len(page) < PAGE:
                break                 # A short page proves there is nothing more.
            if not fresh:
                # A FULL page with no new events means "cannot advance," not "no more."
                # This occurs when one `created_at` bucket exceeds a page: `until` cannot
                # move, so the next query returns the same events.
                #
                # The old code simply stopped. Cleanup of 507 simultaneous events then
                # reported "deleted 500 of 500" while seven remained without warning.
                # External review reproduced TEST-CLEAN-001 on a real node; a few events
                # cannot expose it because the timestamp bucket must overflow the page.
                #
                # Moving `until` back one second would lose all other events written in
                # that second. The only honest outcome is to mark enumeration incomplete.
                #
                # Exactly `PAGE` simultaneous events produce the same signal even though
                # zero remain: a full final page with no new events is indistinguishable
                # from an unreachable tail. Report uncertainty ("may remain"), never the
                # stronger claim that residue definitely exists (TEST-CLEAN-002/P3).
                complete = False
                break
            # `until` is inclusive. Re-fetch same-timestamp events and deduplicate by ID;
            # subtracting one second would silently lose events from that second.
            until = min(e.created_at for e in page)
    return list(seen.values()), complete


async def sweep(relay_url: str, keys_list, verbose: bool = True) -> int:
    """Find and delete EVERYTHING these keys published to the relay.

    This is safer than tracking IDs during the check. Some SDK methods return something
    else (`send_task` returns task_id; `submit_task_result` returns nothing), so manual
    tracking inevitably misses data. The relay is the source of truth.

    This includes mandates (31000) and revocations (31007), which do not expire. One
    deletion event (kind 5) remains per key because deletions cannot themselves be deleted.
    """
    keys_by_pubkey = {k.pubkey_hex: k for k in keys_list if k is not None}
    if not keys_by_pubkey:
        return 0
    cleanup = Cleanup(relay_url, verbose=verbose)
    try:
        async with RelayClient(relay_url, timeout=15) as rc:
            found, complete = await _all_own_events(rc, list(keys_by_pubkey))
            if not complete:
                print("  WARNING: enumeration completeness COULD NOT BE CONFIRMED; one "
                      "timestamp contains at least a full page. Some events MAY remain "
                      "on the node, so the count below is not exhaustive.")
    except Exception as e:                        # noqa: BLE001 - cleanup is non-critical
        if verbose:
            print(f"  cleanup: could not read own events ({type(e).__name__}: {e})")
        return 0
    for ev in found:
        if ev.kind == 5:
            continue                              # Deletions cannot and need not be deleted.
        cleanup.track(keys_by_pubkey[ev.pubkey], ev.id)
    return await cleanup.run()
