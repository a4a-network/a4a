"""Notary cycle: collect history, submit a root, await a block, publish kind 1040.

The steps are independent and idempotent. Each reads persistent storage rather than
process memory, so a crash between steps neither loses data nor publishes it twice.

Here a relay implements ``await history(after, limit, after_id="")``, ``await
query(filter)``, and ``await publish(event)``. Production uses ``RelayWithHistory``
from ``history.py`` (WebSocket REQ plus the node's REST ``/v1/history`` endpoint),
while tests use a fake. See ``calendar.py`` for the calendar interface.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Iterable

from a4a.event import Event
from a4a.keys import Keys

from . import calendar as cal
from . import tree
from .store import Store

log = logging.getLogger("a4a.notary")

# Notarize the same historical kinds the relay retains indefinitely (PROTECTED_KINDS).
# Requests, offers, and tasks are excluded: their volume is unbounded and their exact
# time is not evidence the protocol needs.
NOTARISED_KINDS: tuple[int, ...] = (31000, 31007, 31004, 31005, 31020, 31021)

# Select history by node RECEIPT time (first_seen), not created_at, or a two-day
# backdated event would never be notarized (finding 86). The cursor is exclusively the
# (first_seen, id) pair; store.known() removes repeats when migrating an old database.

# The self-check reads kind 1040 events in chunks. A node accepts at most 100 TAG FILTER
# VALUES (MAX_TAG_VALUES_PER_FILTER), so each chunk must fit. At 200 the node rejected
# the entire filter: the check verified nothing yet logged a plausible ``missing: 0``.
# Before CLOSED arrived in relay 0.3.16 this looked like silence. An overnight run found
# it on 2026-09-05 (finding 121). Sixty-four leaves headroom for stricter peer nodes.
SELF_CHECK_CHUNK = 64


class NotaryService:
    def __init__(self, relay, store: Store, keys: Keys, relay_url: str,
                 calendars: Iterable[str] = cal.DEFAULT_CALENDARS,
                 factory: cal.CalendarFactory = cal.remote_calendar,
                 kinds: Iterable[int] = NOTARISED_KINDS,
                 max_batch: int = 5000):
        self.relay, self.store, self.keys, self.relay_url = relay, store, keys, relay_url
        self.calendars, self.factory = list(calendars), factory
        self.kinds, self.max_batch = list(kinds), max_batch

    @property
    def pubkey(self) -> str:
        return self.keys.pubkey_hex

    # --- Step 1: create a new batch ---------------------------------------------------
    async def collect(self, now: int | None = None) -> int:
        """Collect unnotarized history into a batch and submit its root.

        Return the number of leaves in the new batch, or zero when there is nothing to
        notarize.
        """
        now = int(now if now is not None else time.time())
        rows = await self.relay.history(self.store.cursor(), self.max_batch,
                                        after_id=self.store.cursor_id())
        # Notarize only a SIGNED event verified again here, never merely an ID returned
        # by a query. The published NIP-03 attack (alexgleason, 2026-06-05) timestamps an
        # unsigned event attributed to someone else's pubkey, then uses it after a key
        # leak to "prove" it predates revocation. The node accepts only signed events,
        # but the notary does not trust its transport and verifies independently.
        events = []
        for _, e in rows:
            if e.kind not in self.kinds:
                continue
            if not e.verify():
                log.warning("relay event %s... failed signature verification; not notarizing", e.id[:12])
                continue
            events.append(e)
        fresh = [(e.id, e.kind) for e in events if not self.store.known(e.id)]
        # Deduplicate events repeated within one relay response (filters or replicas).
        seen: set[str] = set()
        fresh = [(i, k) for i, k in fresh if not (i in seen or seen.add(i))]
        if not fresh:
            if rows:
                self.store.set_cursor(*max((fs, e.id) for fs, e in rows))
            return 0
        batch = tree.build_batch([i for i, _ in fresh])
        answered = cal.submit_root(batch.root, self.calendars, factory=self.factory)
        self.store.add_batch(batch.root, fresh, answered, now=now)
        # Advance the cursor only AFTER writing the batch. Otherwise a storage failure
        # (for example the same root after a key rotation) skips events permanently
        # (internal audit finding 110, reproduced live).
        self.store.set_cursor(*max((fs, e.id) for fs, e in rows))
        log.info("batch: %d leaves, root %s..., calendars %s", len(fresh),
                 batch.root_digest.hex()[:12], answered)
        return len(fresh)

    # --- Step 2: await block inclusion ------------------------------------------------
    async def upgrade(self) -> int:
        """Query calendars for pending batches and return those finalized now."""
        done = 0
        for batch_id, root, _created in self.store.pending_batches():
            finalized = cal.upgrade_root(root, factory=self.factory)
            self.store.save_root(batch_id, root, finalized=finalized)
            done += int(finalized)
        return done

    # --- Step 3: publish kind 1040 -----------------------------------------------------
    async def publish(self) -> list[str]:
        """Publish kind 1040 for every unpublished leaf in finalized batches.

        Return the IDs of source events whose attestations were published this pass.
        """
        done: list[str] = []
        for batch_id, root, leaves in self.store.finalized_unpublished():
            batch = tree.Batch(root=root)
            # Rebuild leaves from their IDs. A leaf path is its position in the tree,
            # which build_batch makes deterministic by sorting IDs.
            rebuilt = tree.build_batch([eid for eid, _ in self._all_leaves(batch_id)])
            if rebuilt.root_digest != root.msg:
                log.error("batch %d: rebuilt leaf tree does not match root; not publishing", batch_id)
                continue
            rebuilt.root.merge(root)
            for event_id, kind in leaves:
                unsigned = tree.attestation_event(rebuilt, event_id, kind, self.relay_url)
                ev = Event(kind=unsigned["kind"], tags=unsigned["tags"],
                           content=unsigned["content"]).sign(self.keys)
                await self.relay.publish(ev)
                self.store.mark_published(event_id, ev.id)
                done.append(event_id)
        return done

    # --- Step 4: verify that the relay actually returns our attestations --------------
    async def check_published(self, event_ids: list[str]) -> int:
        """Read back own kind 1040 events and return how many the relay omits.

        Finding 85: the per-author event ceiling silently discarded attestations. The
        relay returned OK for every publication, but REQ found only 5 of 56. Our relay
        now protects kind 1040, but the notary also uses peer nodes and must detect loss
        itself rather than trust an OK response.
        """
        if not event_ids:
            return 0
        seen: set[str] = set()
        for i in range(0, len(event_ids), SELF_CHECK_CHUNK):
            chunk = event_ids[i:i + SELF_CHECK_CHUNK]
            got = await self.relay.query({"kinds": [1040], "authors": [self.pubkey],
                                          "#e": chunk, "limit": len(chunk)})
            seen.update(e.tag_value("e") for e in got)
        missing = [i for i in event_ids if i not in seen]
        if missing:
            log.warning("self-check: published kind 1040=%d, relay returns=%d, missing=%d "
                        "(first %s...); relay may not protect kind 1040 or may cap authors",
                        len(event_ids), len(event_ids) - len(missing), len(missing), missing[0][:12])
        return len(missing)

    def _all_leaves(self, batch_id: int) -> list[tuple[str, int]]:
        rows = self.store._conn.execute(  # noqa: SLF001 - store and service share a package
            "SELECT event_id, kind FROM leaves WHERE batch_id=? ORDER BY event_id", (batch_id,)
        ).fetchall()
        return [(e, int(k)) for e, k in rows]

    async def run_once(self, now: int | None = None) -> dict:
        collected = await self.collect(now)
        finalized = await self.upgrade()
        published = await self.publish()
        missing = await self.check_published(published)
        return {"collected": collected, "finalized": finalized, "published": len(published),
                "missing": missing}
