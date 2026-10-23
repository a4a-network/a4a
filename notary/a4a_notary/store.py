"""Notary state: batches, leaves, and cursor in one SQLite file, one row per fact.

Dedicated storage is necessary because hours pass between root submission and block
inclusion, and the process may crash between block discovery and kind 1040 publication.
Everything required to resume lives here: the serialized root with pending attestations
for calendar queries, the leaves for proof construction, and a publication marker for
each leaf to prevent duplicates or loss.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import Timestamp

_SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    id           INTEGER PRIMARY KEY,
    root_hex     TEXT NOT NULL UNIQUE,
    root_ts      BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    finalized_at INTEGER,
    calendars    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leaves (
    event_id     TEXT PRIMARY KEY,
    kind         INTEGER NOT NULL,
    batch_id     INTEGER NOT NULL REFERENCES batches(id),
    published_id TEXT,
    published_at INTEGER
);
CREATE TABLE IF NOT EXISTS cursor (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
"""


def serialize_timestamp(ts: Timestamp) -> bytes:
    ctx = BytesSerializationContext()
    ts.serialize(ctx)
    return ctx.getbytes()


def deserialize_timestamp(data: bytes, msg: bytes) -> Timestamp:
    return Timestamp.deserialize(BytesDeserializationContext(data), msg)


class Store:
    def __init__(self, path: str | Path):
        self._conn = sqlite3.connect(str(path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # --- Cursor: latest node RECEIPT time (first_seen) scanned -------------------------
    # The first_seen key supersedes the old since key, which stored created_at (finding
    # 86). On migration the notary rereads history from zero once; known() removes repeats.
    def cursor(self) -> int:
        row = self._conn.execute("SELECT value FROM cursor WHERE key='first_seen'").fetchone()
        return int(row[0]) if row else 0

    def cursor_id(self) -> str:
        row = self._conn.execute("SELECT value FROM cursor WHERE key='first_seen_id'").fetchone()
        return str(row[0]).removeprefix("id:") if row else ""

    def set_cursor(self, value: int, event_id: str = "") -> None:
        # Keep both cursor fields atomic. The prefix prevents SQLite's INTEGER
        # affinity from rounding a digit-only hex id into a floating-point value.
        with self._conn:
            self._conn.executemany(
                "INSERT INTO cursor(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [("first_seen", int(value)), ("first_seen_id", "id:" + event_id)])

    # --- Leaves -----------------------------------------------------------------------
    def known(self, event_id: str) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM leaves WHERE event_id=?", (event_id,)).fetchone() is not None

    def add_batch(self, root: Timestamp, leaves: list[tuple[str, int]],
                  calendars: list[str], now: int | None = None) -> int:
        """Write a complete batch in one transaction: pending root and all leaves."""
        now = int(now if now is not None else time.time())
        # A root without attestations was not submitted to a calendar. It cannot be
        # serialized by the library and should not be saved: without a calendar response
        # there is nobody to query for block inclusion. Raise here with an actionable
        # cause instead of exposing a serializer-internal ValueError.
        if not any(True for _ in root.all_attestations()):
            raise ValueError("root has no attestations: batch was not submitted to a calendar")
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO batches(root_hex, root_ts, created_at, calendars) VALUES(?,?,?,?)",
            (root.msg.hex(), serialize_timestamp(root), now, ",".join(calendars)))
        batch_id = int(cur.lastrowid)
        cur.executemany(
            "INSERT INTO leaves(event_id, kind, batch_id) VALUES(?,?,?)",
            [(eid, int(kind), batch_id) for eid, kind in leaves])
        self._conn.commit()
        return batch_id

    def pending_batches(self) -> list[tuple[int, Timestamp, int]]:
        """Return batches without Bitcoin attestations as ``(id, pending root, time)``."""
        rows = self._conn.execute(
            "SELECT id, root_hex, root_ts, created_at FROM batches "
            "WHERE finalized_at IS NULL ORDER BY id").fetchall()
        return [(int(i), deserialize_timestamp(blob, bytes.fromhex(h)), int(c))
                for i, h, blob, c in rows]

    def save_root(self, batch_id: int, root: Timestamp, finalized: bool,
                  now: int | None = None) -> None:
        now = int(now if now is not None else time.time())
        self._conn.execute(
            "UPDATE batches SET root_ts=?, finalized_at=COALESCE(finalized_at, ?) WHERE id=?",
            (serialize_timestamp(root), now if finalized else None, batch_id))
        self._conn.commit()

    def finalized_unpublished(self) -> list[tuple[int, Timestamp, list[tuple[str, int]]]]:
        """Return block-finalized batches that still have unpublished leaves."""
        rows = self._conn.execute(
            "SELECT DISTINCT b.id, b.root_hex, b.root_ts FROM batches b "
            "JOIN leaves l ON l.batch_id=b.id "
            "WHERE b.finalized_at IS NOT NULL AND l.published_id IS NULL ORDER BY b.id").fetchall()
        out = []
        for i, h, blob in rows:
            leaves = self._conn.execute(
                "SELECT event_id, kind FROM leaves WHERE batch_id=? AND published_id IS NULL "
                "ORDER BY event_id", (i,)).fetchall()
            out.append((int(i), deserialize_timestamp(blob, bytes.fromhex(h)),
                        [(e, int(k)) for e, k in leaves]))
        return out

    def mark_published(self, event_id: str, attestation_id: str, now: int | None = None) -> None:
        now = int(now if now is not None else time.time())
        self._conn.execute(
            "UPDATE leaves SET published_id=?, published_at=? WHERE event_id=?",
            (attestation_id, now, event_id))
        self._conn.commit()

    def stats(self) -> dict:
        (batches,) = self._conn.execute("SELECT count(*) FROM batches").fetchone()
        (pending,) = self._conn.execute(
            "SELECT count(*) FROM batches WHERE finalized_at IS NULL").fetchone()
        (leaves,) = self._conn.execute("SELECT count(*) FROM leaves").fetchone()
        (published,) = self._conn.execute(
            "SELECT count(*) FROM leaves WHERE published_id IS NOT NULL").fetchone()
        return {"batches": batches, "pending": pending, "leaves": leaves, "published": published}
