"""Sender-side delivery journal for `Agent.deliver_with_ack`.

The sender used to learn a delivery's outcome once, as a return value, and keep nothing.
A `dead_letter` vanished with the session; a recipient whose receiver came back an hour
later and acknowledged was never noticed; "no relay accepted the message" and "the
recipient stayed silent" were not told apart in any record. This journal keeps exactly
what is needed to answer those questions later.

It stores the PUBLISHED envelopes, never the plaintext: a gift wrap (or a NIP-44 kind
31033 event) is already encrypted to the recipient, so the journal adds no readable copy
of the message, and republishing the stored envelope resends the identical event instead
of composing a second message.

States:
  sending         written before the first publication; left behind only if the process
                  died mid-delivery, which is itself the "could not find out" outcome
  acknowledged    the recipient's ACK was verified (possibly late, see `late`)
  dead_letter     at least one relay accepted the message, no ACK arrived in time
  publish_failed  no relay accepted any attempt; nothing was sent
  interrupted     something was published, then the delivery stopped on an error
"""
from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from . import keyfile
from .event import Event, is_canonical_pubkey
from .inbox import _private_directory

STATES = ("sending", "acknowledged", "dead_letter", "publish_failed", "interrupted")

#: Categorized outbound registry classes (2026-10-30 Trust Levels specification).
OUTBOUND_CATEGORIES = (
    "fact",
    "money",
    "promise",
    "user_data",
    "internal_metrics",
    "routine_dev",
)
#: Outbound categories that ALWAYS require explicit owner approval regardless of trust level.
RESTRICTED_OUTBOUND_CATEGORIES = frozenset({
    "money",
    "promise",
    "user_data",
    "internal_metrics",
})

#: Gaps between automatic rechecks, then every six hours, until RECHECK_GIVE_UP. A
#: delivery that stays unacknowledged for two days is left for a person to look at.
RECHECK_GAPS = (60, 300, 900, 3600, 10800)
RECHECK_LAST_GAP = 21600
RECHECK_GIVE_UP = 48 * 3600
#: Columns added after the first journals were written; created on open when missing.
_LATER_COLUMNS = (
    ("ack_signed_at", "INTEGER"),
    ("checks", "INTEGER NOT NULL DEFAULT 0"),
    ("last_check", "REAL"),
    ("category", "TEXT"),
    ("trust_level", "INTEGER"),
    ("topic", "TEXT"),
    ("content_sha256", "TEXT"),
    ("owner_approved", "INTEGER NOT NULL DEFAULT 0"),
    ("commitment_note", "TEXT"),
)


class OutboxError(RuntimeError):
    """The journal could not record an outcome; callers must not report success."""


class OutboxStore:
    def __init__(self, directory):
        directory = Path(directory)
        _private_directory(directory)
        self.path = directory / "outbox.sqlite3"
        if self.path.is_symlink():
            raise OutboxError("outbox database must not be a symlink")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        ok, _ = keyfile.harden_and_check(self.path, force=True)
        if not ok:
            raise OutboxError("cannot protect outbox database")
        self.db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            # DELETE, not WAL: a WAL file would be a second place where envelopes live
            # after close, outside the protected database file.
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            with self._transaction():
                self.db.execute("""CREATE TABLE IF NOT EXISTS deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    recipient TEXT NOT NULL, private INTEGER NOT NULL,
                    created REAL NOT NULL, since INTEGER NOT NULL, updated REAL NOT NULL,
                    state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                    ack_status TEXT, ack_at REAL, late INTEGER NOT NULL DEFAULT 0,
                    republished INTEGER NOT NULL DEFAULT 0)""")
                # Journals created before 23.09.2026 evening lack the column. ack_at is
                # when WE found the ACK; ack_signed_at is when the RECIPIENT signed it -
                # an hour apart in the pilot where a late ACK was found by recheck.
                columns = {row[1] for row in self.db.execute("PRAGMA table_info(deliveries)")}
                for name, kind in _LATER_COLUMNS:
                    if name not in columns:
                        self.db.execute(f"ALTER TABLE deliveries ADD COLUMN {name} {kind}")
                self.db.execute("""CREATE TABLE IF NOT EXISTS envelopes (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    delivery_id TEXT NOT NULL REFERENCES deliveries(delivery_id),
                    event_id TEXT NOT NULL, envelope TEXT NOT NULL, published REAL NOT NULL,
                    UNIQUE(delivery_id, event_id))""")
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @contextmanager
    def _transaction(self):
        try:
            self.db.execute("BEGIN IMMEDIATE")
            yield
            self.db.execute("COMMIT")
        except BaseException as exc:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise OutboxError("outbox database operation failed") from exc
            raise

    def set_context(self, *, category: str | None = None, trust_level: int | None = None,
                    topic: str | None = None, content_sha256: str | None = None,
                    owner_approved: bool = False, commitment_note: str | None = None):
        """Bind outbound registry metadata for the next delivery started on this store."""
        self._context = {
            "category": category,
            "trust_level": trust_level,
            "topic": topic,
            "content_sha256": content_sha256,
            "owner_approved": owner_approved,
            "commitment_note": commitment_note,
        }

    def start(self, delivery_id: str, recipient: str, *, private: bool, since: int,
              category: str | None = None, trust_level: int | None = None,
              topic: str | None = None, content_sha256: str | None = None,
              owner_approved: bool = False, commitment_note: str | None = None):
        if not is_canonical_pubkey(recipient):
            raise OutboxError("invalid recipient")
        ctx = getattr(self, "_context", None) or {}
        eff_cat = category if category is not None else ctx.get("category")
        eff_level = trust_level if trust_level is not None else ctx.get("trust_level")
        eff_topic = topic if topic is not None else ctx.get("topic")
        eff_sha = content_sha256 if content_sha256 is not None else ctx.get("content_sha256")
        eff_approved = bool(owner_approved or ctx.get("owner_approved", False))
        eff_note = commitment_note if commitment_note is not None else ctx.get("commitment_note")
        if eff_cat is not None and eff_cat not in OUTBOUND_CATEGORIES:
            raise OutboxError(f"invalid outbound category {eff_cat!r}")
        now = time.time()
        with self._transaction():
            self.db.execute(
                "INSERT INTO deliveries (delivery_id, recipient, private, created, since, "
                "updated, state, category, trust_level, topic, content_sha256, "
                "owner_approved, commitment_note) VALUES (?, ?, ?, ?, ?, ?, 'sending', "
                "?, ?, ?, ?, ?, ?)",
                (delivery_id, recipient, int(bool(private)), now, int(since), now,
                 eff_cat, eff_level, eff_topic, eff_sha, int(eff_approved),
                 eff_note))

    def annotate(self, delivery_id: str, *, category: str | None = None,
                 trust_level: int | None = None, topic: str | None = None,
                 content_sha256: str | None = None, owner_approved: bool | None = None,
                 commitment_note: str | None = None):
        if category is not None and category not in OUTBOUND_CATEGORIES:
            raise OutboxError(f"invalid outbound category {category!r}")
        approved_int = None if owner_approved is None else int(bool(owner_approved))
        with self._transaction():
            cur = self.db.execute(
                "UPDATE deliveries SET "
                "category=COALESCE(?, category), "
                "trust_level=COALESCE(?, trust_level), "
                "topic=COALESCE(?, topic), "
                "content_sha256=COALESCE(?, content_sha256), "
                "owner_approved=COALESCE(?, owner_approved), "
                "commitment_note=COALESCE(?, commitment_note) "
                "WHERE delivery_id=?",
                (category, trust_level, topic, content_sha256, approved_int,
                 commitment_note, delivery_id))
            if cur.rowcount != 1:
                raise OutboxError("unknown delivery")

    def add_envelope(self, delivery_id: str, event: Event):
        with self._transaction():
            self.db.execute(
                "INSERT OR IGNORE INTO envelopes (delivery_id, event_id, envelope, published) "
                "VALUES (?, ?, ?, ?)",
                (delivery_id, event.id, event.model_dump_json(), time.time()))

    def finish(self, delivery_id: str, state: str, *, attempts: int | None = None,
               ack_status: str | None = None, late: bool = False,
               ack_signed_at: int | None = None):
        if state not in STATES or state == "sending":
            raise OutboxError(f"invalid final state {state!r}")
        now = time.time()
        with self._transaction():
            cur = self.db.execute(
                "UPDATE deliveries SET state=?, updated=?, "
                "attempts=COALESCE(?, attempts), ack_status=COALESCE(?, ack_status), "
                "ack_at=CASE WHEN ?='acknowledged' THEN ? ELSE ack_at END, "
                "late=MAX(late, ?), ack_signed_at=COALESCE(?, ack_signed_at) "
                "WHERE delivery_id=?",
                (state, now, attempts, ack_status, state, now, int(late), ack_signed_at,
                 delivery_id))
            if cur.rowcount != 1:
                raise OutboxError("unknown delivery")

    def mark_republished(self, delivery_id: str):
        with self._transaction():
            self.db.execute(
                "UPDATE deliveries SET republished=republished+1, updated=? WHERE delivery_id=?",
                (time.time(), delivery_id))

    def due_for_recheck(self, now: float, limit: int = 50) -> list[str]:
        """Deliveries whose outcome may still change and whose next recheck is due.

        dead_letter and interrupted may still be acknowledged late; `received` still
        awaits its final processed/failed; `sending` older than five minutes means the
        process died mid-delivery and the ACK may exist anyway.
        """
        rows = self.db.execute(
            "SELECT delivery_id, created, checks, last_check FROM deliveries "
            "WHERE state IN ('dead_letter', 'interrupted') "
            "OR (state = 'acknowledged' AND ack_status = 'received') "
            "OR (state = 'sending' AND created < ?) ORDER BY created", (now - 300,))
        due = []
        for row in rows.fetchall():
            if now - row["created"] > RECHECK_GIVE_UP:
                continue
            gap = (RECHECK_GAPS[row["checks"]] if row["checks"] < len(RECHECK_GAPS)
                   else RECHECK_LAST_GAP)
            if now >= (row["last_check"] or row["created"]) + gap:
                due.append(row["delivery_id"])
            if len(due) >= limit:
                break
        return due

    def mark_rechecked(self, delivery_id: str, now: float):
        with self._transaction():
            self.db.execute(
                "UPDATE deliveries SET checks = checks + 1, last_check = ? WHERE delivery_id=?",
                (now, delivery_id))

    def latest_envelope(self, delivery_id: str) -> Event | None:
        row = self.db.execute(
            "SELECT envelope FROM envelopes WHERE delivery_id=? ORDER BY seq DESC LIMIT 1",
            (delivery_id,)).fetchone()
        return Event.model_validate_json(row["envelope"]) if row else None

    def _record(self, row) -> dict:
        record = dict(row)
        record["private"] = bool(record["private"])
        record["late"] = bool(record["late"])
        record["owner_approved"] = bool(record.get("owner_approved"))
        record["envelope_ids"] = [r["event_id"] for r in self.db.execute(
            "SELECT event_id FROM envelopes WHERE delivery_id=? ORDER BY seq",
            (record["delivery_id"],))]
        return record

    def get(self, delivery_id: str) -> dict | None:
        row = self.db.execute(
            "SELECT * FROM deliveries WHERE delivery_id=?", (delivery_id,)).fetchone()
        return self._record(row) if row else None

    def list(self, states=None, limit: int = 100, *, category: str | None = None,
             recipient: str | None = None, commitments_only: bool = False) -> list[dict]:
        clauses: list[str] = []
        params: list[object] = []
        if states:
            marks = ",".join("?" * len(states))
            clauses.append(f"state IN ({marks})")
            params.extend(states)
        if category is not None:
            if category not in OUTBOUND_CATEGORIES:
                raise OutboxError(f"invalid outbound category {category!r}")
            clauses.append("COALESCE(category, 'routine_dev') = ?")
            params.append(category)
        if recipient is not None:
            if not is_canonical_pubkey(recipient):
                raise OutboxError("invalid recipient filter")
            clauses.append("recipient = ?")
            params.append(recipient)
        if commitments_only:
            marks = ",".join("?" * len(RESTRICTED_OUTBOUND_CATEGORIES))
            clauses.append(f"category IN ({marks})")
            params.extend(sorted(RESTRICTED_OUTBOUND_CATEGORIES))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.db.execute(
            f"SELECT * FROM deliveries{where} ORDER BY created DESC LIMIT ?",
            (*params, limit))
        return [self._record(r) for r in rows.fetchall()]
