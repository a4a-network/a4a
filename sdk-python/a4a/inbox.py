"""Bounded encrypted inbox and local processing leases. No model or auto-replies."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

from . import giftwrap, keyfile, types
from .event import Event, is_canonical_pubkey


_log = logging.getLogger("a4a.inbox")


class InboxError(RuntimeError):
    """The inbox did not complete an operation; callers must not report success."""


class InboxFull(InboxError):
    pass


class InboxStorageError(InboxError):
    """Local storage failed; another relay cannot repair the operation."""


class InboxConflict(InboxError):
    pass


class InboxPolicyChanged(InboxError):
    """A running consumer must stop instead of using a stale authorization."""


class InboxAuthorizationUnavailable(InboxError):
    """Owner trust could not be verified; no cursor or lease may advance."""


class NoticeTracker:
    """Last signalled work on one attachment, never a delivery acknowledgement."""

    def __init__(self):
        self._fingerprint = None


def _now(value):
    return time.time() if value is None else value


def _validate_wake_budget(interval, per_hour):
    if type(interval) is not int or not 10 <= interval <= 3600:
        raise InboxError("notification interval must be 10..3600 seconds")
    if type(per_hour) is not int or not 1 <= per_hour <= 60:
        raise InboxError("notification budget must be 1..60 per hour")


def _private_directory(path: Path):
    if path.is_symlink():
        raise InboxError("inbox directory must not be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "nt":
        ok, _ = keyfile.harden_and_check(path, force=True)
        if ok:
            # Without inheritable owner rights, new files use the token's default
            # DACL, which may include unrelated logon-session principals.
            user_sid = keyfile._windows_current_sid()
            result = subprocess.run(
                ["icacls", str(path), "/grant:r", f"*{user_sid}:(OI)(CI)F"],
                capture_output=True, text=True, errors="replace", timeout=15)
            ok = result.returncode == 0 and keyfile.is_private(path)[0]
    else:
        os.chmod(path, 0o700)
        ok, _ = keyfile.is_private(path)
    if not ok:
        raise InboxError("cannot protect inbox directory")


class InboxStore:
    """One recipient and one owner-selected consumer, shared safely by processes.

    The database keeps encrypted transport events, not decrypted messages. Metadata
    is private local state. Finished rows are deduplication tombstones: no automatic
    deletion or retry of uncertain work. Reaching a bound is an explicit failure.
    """

    def __init__(self, directory, recipient: str, consumer: str, *,
                 max_items=10_000, max_bytes=64 * 1024 * 1024):
        if not is_canonical_pubkey(recipient):
            raise InboxError("invalid inbox recipient")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", consumer):
            raise InboxError("a fixed local inbox consumer is required")
        if type(max_items) is not int or not 1 <= max_items <= 100_000:
            raise InboxError("invalid inbox item limit")
        if type(max_bytes) is not int or not 65536 <= max_bytes <= 1024**3:
            raise InboxError("invalid inbox byte limit")
        directory = Path(directory)
        _private_directory(directory)
        self.path = directory / "inbox.sqlite3"
        if self.path.is_symlink():
            raise InboxError("inbox database must not be a symlink")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        ok, _ = keyfile.harden_and_check(self.path, force=True)
        if not ok:
            raise InboxError("cannot protect inbox database")
        self.recipient, self.consumer = recipient, consumer
        self.max_items, self.max_bytes = max_items, max_bytes
        self.db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
            self.db.execute(f"PRAGMA max_page_count={max_bytes // page_size}")
            with self._transaction():
                self.db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                for key, value in (("schema", "1"), ("recipient", recipient), ("consumer", consumer)):
                    self.db.execute("INSERT OR IGNORE INTO metadata VALUES (?, ?)", (key, value))
                    if self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()[0] != value:
                        raise InboxConflict("inbox belongs to another identity, consumer or schema")
                self.db.execute("""CREATE TABLE IF NOT EXISTS messages (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL, dedup TEXT NOT NULL, digest TEXT NOT NULL,
                    inner_id TEXT NOT NULL, outer_id TEXT NOT NULL,
                    delivery_id TEXT NOT NULL, envelope TEXT NOT NULL,
                    received REAL NOT NULL, expires REAL,
                    state TEXT NOT NULL DEFAULT 'pending',
                    lease_token TEXT, lease_until REAL,
                    UNIQUE(sender, dedup))""")
                # Durable network-ACK outbox for MCP lease completion.  It is a
                # separate table so existing schema-1 inboxes remain compatible and
                # older readers safely ignore it.  The completion token is stored only
                # as a digest: it fences idempotent retries without retaining the
                # bearer token itself after the processing lease ends.
                self.db.execute("""CREATE TABLE IF NOT EXISTS completion_acks (
                    seq INTEGER PRIMARY KEY,
                    token_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending',
                    event_id TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY(seq) REFERENCES messages(seq))""")
                self.db.execute("CREATE INDEX IF NOT EXISTS inbox_pending ON messages(state, seq)")
                self.db.execute("CREATE TABLE IF NOT EXISTS cursors (relay TEXT PRIMARY KEY, stamp INTEGER NOT NULL, event_id TEXT NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS wakeups (singleton INTEGER PRIMARY KEY CHECK(singleton=1), last REAL NOT NULL, window REAL NOT NULL, count INTEGER NOT NULL)")
                self.db.execute("""CREATE TABLE IF NOT EXISTS quarantine_requests (
                    req_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL UNIQUE,
                    dedup TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    inner_id TEXT NOT NULL,
                    outer_id TEXT NOT NULL,
                    delivery_id TEXT NOT NULL,
                    envelope TEXT NOT NULL,
                    preview TEXT NOT NULL DEFAULT '',
                    received REAL NOT NULL,
                    expires REAL,
                    state TEXT NOT NULL DEFAULT 'pending',
                    decided_at REAL)""")
        except BaseException:
            self.db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.db.close()

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
                raise InboxStorageError("inbox database operation failed; no success receipt") from exc
            raise

    def _prepare(self, agent, outer, allowed, now, *, intake_mode="closed", blocked_senders=frozenset()):
        if agent.pubkey != self.recipient:
            raise InboxConflict("decoder identity does not match inbox")
        if not isinstance(outer, Event) or not outer.verify_protocol():
            return "ignored", None
        if [t[1] for t in outer.tags if len(t) >= 2 and t[0] == "p"] != [self.recipient]:
            return "ignored", None
        if any(tag and tag[0] in types.ORGANIZATION_ONLY_PRIVATE_TAGS
               for tag in outer.tags):
            return "ignored", None
        expiry = [t[1] for t in outer.tags if len(t) >= 2 and t[0] == "expiration"]
        if len(expiry) > 1 or (expiry and not re.fullmatch(r"[0-9]{1,12}", expiry[0])):
            return "ignored", None
        expires = int(expiry[0]) if expiry else None
        if expires is not None and expires <= now:
            return "ignored", None
        envelope = outer.model_dump_json()
        try:
            envelope_bytes = envelope.encode("utf-8")
        except UnicodeEncodeError:
            return "rejected-content", None
        if len(envelope_bytes) > 256 * 1024:
            return "rejected-size", None
        message = agent._decode_incoming(outer)
        if message is None:
            return "ignored", None
        inner = message["event"]
        if [t[1] for t in inner.tags if len(t) >= 2 and t[0] == "p"] != [self.recipient]:
            return "ignored", None
        if any(tag and tag[0] in types.ORGANIZATION_ONLY_PRIVATE_TAGS
               for tag in inner.tags):
            return "ignored", None
        is_allowed = inner.pubkey in allowed
        if not is_allowed and (inner.pubkey in blocked_senders or intake_mode != "reception"):
            return "blocked", None
        inner_expiry = [t[1] for t in inner.tags if len(t) >= 2 and t[0] == "expiration"]
        if len(inner_expiry) > 1 or (inner_expiry and not re.fullmatch(r"[0-9]{1,12}", inner_expiry[0])):
            return "ignored", None
        if inner_expiry:
            expires = min(expires, int(inner_expiry[0])) if expires is not None else int(inner_expiry[0])
            if expires <= now:
                return "ignored", None
        try:
            content = message["content"].encode("utf-8")
        except UnicodeEncodeError:
            # JSON accepts escaped lone surrogates and the signed/encrypted envelope
            # can therefore be entirely valid on the wire.  Such text is not UTF-8:
            # classify it as a rejected row so accept_page can still atomically move
            # its cursor past the poison envelope and retain later valid messages.
            return "rejected-content", None
        max_content_bytes = 32 * 1024 if is_allowed else 4 * 1024
        if len(content) > max_content_bytes:
            return "rejected-size", None
        deliveries = [t[1] for t in inner.tags if len(t) >= 2 and t[0] == "d"]
        if len(deliveries) > 1 or (deliveries and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", deliveries[0])):
            return "ignored", None
        delivery = deliveries[0] if deliveries else ""
        conversation_tags = [tag for tag in inner.tags
                             if tag and tag[0] == "a4a_conversation"]
        if conversation_tags and (len(conversation_tags) != 1
                                  or len(conversation_tags[0]) != 2
                                  or re.fullmatch(r"[0-9a-f]{64}", conversation_tags[0][1]) is None
                                  or not message.get("wrapped")
                                  or inner.kind != types.KIND_PRIVATE_RUMOR
                                  or outer.kind != giftwrap.KIND_GIFT_WRAP):
            return "ignored", None
        conversation_id = conversation_tags[0][1] if conversation_tags else None
        if conversation_id != message.get("conversation_id"):
            return "ignored", None
        # A retry may rewrap the same message, but must not move one delivery ID
        # into another conversation while keeping identical text. Legacy messages
        # retain their original content-only digest for existing inbox databases.
        digest_input = (b"a4a-conversation-v1\0" + conversation_id.encode("ascii")
                        + b"\0" + content) if conversation_id is not None else content
        row = (inner.pubkey, "d:" + delivery if delivery else "e:" + inner.id,
               hashlib.sha256(digest_input).hexdigest(), inner.id, outer.id,
               delivery, envelope, now, expires)
        if not is_allowed:
            preview = " ".join(message["content"].split())[:200]
            return "quarantine", (*row[:7], preview, now, expires)
        return "ready", row

    def _insert(self, prepared):
        kind, row = prepared
        if row is None:
            return kind
        if kind == "quarantine":
            existing_q = self.db.execute(
                "SELECT state FROM quarantine_requests WHERE sender=?",
                (row[0],),
            ).fetchone()
            if existing_q is not None:
                return "quarantine-duplicate"
            q_count = self.db.execute(
                "SELECT COUNT(*) FROM quarantine_requests WHERE state='pending'"
            ).fetchone()[0]
            if q_count >= 200:
                return "quarantine-full"
            self.db.execute(
                """INSERT INTO quarantine_requests
                (sender,dedup,digest,inner_id,outer_id,delivery_id,envelope,preview,received,expires,state)
                VALUES (?,?,?,?,?,?,?,?,?,?,'pending')""",
                row,
            )
            return "quarantined"
        existing = self.db.execute("SELECT digest FROM messages WHERE sender=? AND dedup=?", row[:2]).fetchone()
        if existing:
            if existing[0] != row[2]:
                raise InboxConflict("delivery id reused with different content")
            return "duplicate"
        count, size = self.db.execute("SELECT COUNT(*), COALESCE(SUM(length(CAST(envelope AS BLOB))), 0) FROM messages").fetchone()
        if count >= self.max_items or size + len(row[6].encode("utf-8")) > self.max_bytes:
            raise InboxFull("inbox capacity reached; existing work was retained")
        self.db.execute("""INSERT INTO messages
            (sender,dedup,digest,inner_id,outer_id,delivery_id,envelope,received,expires)
            VALUES (?,?,?,?,?,?,?,?,?)""", row)
        return "stored"

    def accept(self, agent, outer, allowed_senders, *, now=None, intake_mode="closed", blocked_senders=frozenset()):
        prepared = self._prepare(
            agent, outer, allowed_senders, _now(now),
            intake_mode=intake_mode, blocked_senders=blocked_senders,
        )
        with self._transaction():
            return self._insert(prepared)

    def cursor(self, relay):
        row = self.db.execute("SELECT stamp,event_id FROM cursors WHERE relay=?", (relay,)).fetchone()
        return tuple(row) if row else (0, "")

    def pending_sender_keys(self):
        """Return bounded distinct senders awaiting a lease, without private text."""
        return {row[0] for row in self.db.execute(
            "SELECT DISTINCT sender FROM messages WHERE state='pending'")}

    def sender_for_seq(self, seq):
        row = self.db.execute("SELECT sender FROM messages WHERE seq=?", (seq,)).fetchone()
        return row[0] if row else None

    def bind_relay(self, relay, start_after):
        if type(start_after) is not int or start_after < 0:
            raise InboxError("invalid inbox starting point")
        with self._transaction():
            self.db.execute("INSERT OR IGNORE INTO cursors VALUES (?,?,?)", (relay, start_after, ""))
        return self.cursor(relay)

    def accept_page(self, agent, relay, previous, rows, allowed_senders, *, now=None, intake_mode="closed", blocked_senders=frozenset()):
        if len(rows) > 500:
            raise InboxError("history page exceeds inbox batch limit")
        position = previous
        prepared = []
        for stamp, event in rows:
            if type(stamp) is not int or stamp < 0 or (stamp, event.id) <= position:
                raise InboxError("history page is not strictly ordered")
            position = (stamp, event.id)
            prepared.append(self._prepare(
                agent, event, allowed_senders, _now(now),
                intake_mode=intake_mode, blocked_senders=blocked_senders,
            ))
        with self._transaction():
            if self.cursor(relay) != previous:
                raise InboxConflict("history cursor changed concurrently")
            results = [self._insert(item) for item in prepared]
            if rows:
                self.db.execute("INSERT INTO cursors VALUES (?,?,?) ON CONFLICT(relay) DO UPDATE SET stamp=excluded.stamp,event_id=excluded.event_id", (relay, *position))
            return results

    def _expire(self, now):
        self.db.execute("UPDATE messages SET state='unknown',lease_token=NULL WHERE state='processing' AND lease_until<=?", (now,))
        self.db.execute("UPDATE messages SET state='expired' WHERE state='pending' AND expires<=?", (now,))

    def _expire_dialogues(self, now):
        self._expire(now)
        self.db.execute("""UPDATE dialogue_outbox SET state='unknown' WHERE state='dispatching'
            AND peer IN (SELECT peer FROM dialogues WHERE lease_until<=?)""", (now,))

    def claim(self, agent, consumer, allowed_senders, *, now=None, lease_seconds=300):
        if consumer != self.consumer or agent.pubkey != self.recipient:
            raise InboxConflict("wrong inbox consumer or decoder identity")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise InboxError("lease must be 1..3600 seconds")
        now = _now(now)
        with self._transaction():
            if self.dialogue_enabled():
                raise InboxConflict("dialogue mode requires a conversation lease, not legacy inbox claim")
            self._expire(now)
            rows = self.db.execute("SELECT * FROM messages WHERE state='pending' ORDER BY seq")
            for row in rows:
                if row["sender"] not in allowed_senders:
                    self.db.execute("UPDATE messages SET state='blocked' WHERE seq=?", (row["seq"],))
                    continue
                outer = Event.model_validate_json(row["envelope"])
                prepared = self._prepare(agent, outer, allowed_senders, now)
                if prepared[1] is None or prepared[1][2] != row["digest"] or prepared[1][3] != row["inner_id"]:
                    raise InboxConflict("stored message verification failed")
                decoded = agent._decode_incoming(outer)
                token = secrets.token_hex(24)
                self.db.execute("UPDATE messages SET state='processing',lease_token=?,lease_until=? WHERE seq=?",
                                (token, now + lease_seconds, row["seq"]))
                return {"seq": row["seq"], "inner_id": row["inner_id"], "outer_id": row["outer_id"],
                        "delivery_id": row["delivery_id"], "from_pubkey": row["sender"],
                        "content": decoded["content"], "wrapped": decoded["wrapped"],
                        "conversation_id": decoded["conversation_id"],
                        "reply_to": decoded["reply_to"], "signed_at": decoded["signed_at"],
                        # The receiving side's own moments (representative, 26.09): stored by
                        # this inbox, and taken for reading - so the age of the numbers shows.
                        "received_at": row["received"], "read_at": now,
                        "lease_token": token, "lease_until": now + lease_seconds}
        return None

    def dialogue_enabled(self):
        row = self.db.execute("SELECT value FROM metadata WHERE key='dialogue_mode'").fetchone()
        return row is not None and row[0] == "1"

    @staticmethod
    def _completion_token_digest(token) -> str:
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{48}", token):
            raise InboxError("invalid inbox completion token")
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def release(self, seq, token, consumer, *, now=None):
        """Return a live lease to pending: the consumer certainly did not act on it.

        Only the lease holder may do this, only while the lease is live, and no ACK is
        sent. After expiry the outcome is unknown and belongs to reconcile_unknown.
        """
        if consumer != self.consumer:
            raise InboxError("invalid inbox release")
        now = _now(now)
        with self._transaction():
            if self.dialogue_enabled():
                raise InboxConflict("dialogue mode requires fenced dialogue completion")
            changed = self.db.execute("""UPDATE messages
                SET state='pending',lease_token=NULL,lease_until=NULL
                WHERE seq=? AND state='processing' AND lease_token=? AND lease_until>?""",
                (seq, token, now)).rowcount
            if changed != 1:
                raise InboxConflict("release rejected: stale, expired or unknown lease")
        return {"seq": seq, "state": "pending"}

    def finish(self, seq, token, consumer, status, *, now=None,
               network_ack=False):
        if consumer != self.consumer or status not in ("processed", "failed"):
            raise InboxError("invalid inbox completion")
        if type(network_ack) is not bool:
            raise InboxError("network_ack must be a boolean")
        now = _now(now)
        token_digest = self._completion_token_digest(token) if network_ack else ""
        with self._transaction():
            if self.dialogue_enabled():
                raise InboxConflict("dialogue mode requires fenced dialogue completion")
            if network_ack:
                previous = self.db.execute("""SELECT a.status,a.state,a.event_id,
                    m.state AS message_state,m.envelope,m.inner_id,m.delivery_id
                    FROM completion_acks a
                    JOIN messages m ON m.seq=a.seq WHERE a.seq=? AND a.token_digest=?""",
                    (seq, token_digest)).fetchone()
                if previous is not None:
                    if previous["status"] != status:
                        raise InboxConflict(
                            "completion retry changed status for the same lease")
                    if previous["message_state"] != status:
                        raise InboxConflict(
                            "completion ACK outbox disagrees with inbox state")
                    return {"seq": seq, "status": status,
                            "ack_state": previous["state"],
                            "ack_event_id": previous["event_id"],
                            "envelope": previous["envelope"],
                            "inner_id": previous["inner_id"],
                            "delivery_id": previous["delivery_id"]}
            changed = self.db.execute("""UPDATE messages SET state=?,lease_token=NULL
                WHERE seq=? AND state='processing' AND lease_token=? AND lease_until>?""",
                (status, seq, token, now)).rowcount
            if changed != 1:
                raise InboxConflict("completion rejected: stale or unknown lease")
            if not network_ack:
                return None
            row = self.db.execute(
                "SELECT envelope,inner_id,delivery_id FROM messages WHERE seq=?",
                (seq,)).fetchone()
            # Messages without a delivery ID predate reliable delivery semantics and
            # cannot be acknowledged.  Their local completion is still valid.
            if not row["delivery_id"]:
                return {"seq": seq, "status": status, "ack_state": "not_applicable",
                        "ack_event_id": "", "envelope": row["envelope"],
                        "inner_id": row["inner_id"], "delivery_id": ""}
            self.db.execute("""INSERT INTO completion_acks
                (seq,token_digest,status,state,event_id) VALUES (?,?,?,'pending','')""",
                (seq, token_digest, status))
            return {"seq": seq, "status": status, "ack_state": "pending",
                    "ack_event_id": "", "envelope": row["envelope"],
                    "inner_id": row["inner_id"],
                    "delivery_id": row["delivery_id"]}

    def mark_completion_ack_sent(self, seq, token, consumer, event_id):
        """Mark one durable completion ACK sent, fenced by the original lease token."""
        if consumer != self.consumer or not isinstance(event_id, str) \
                or not re.fullmatch(r"[0-9a-f]{64}", event_id):
            raise InboxError("invalid completion ACK marker")
        token_digest = self._completion_token_digest(token)
        with self._transaction():
            row = self.db.execute("""SELECT state,event_id FROM completion_acks
                WHERE seq=? AND token_digest=?""", (seq, token_digest)).fetchone()
            if row is None:
                raise InboxConflict("completion ACK marker has no matching outbox item")
            if row["state"] == "sent":
                return row["event_id"]
            if row["state"] != "pending":
                raise InboxConflict("completion ACK outbox is not pending")
            self.db.execute("""UPDATE completion_acks SET state='sent',event_id=?
                WHERE seq=? AND token_digest=? AND state='pending'""",
                (event_id, seq, token_digest))
            return event_id

    def pending_completion_acks(self, consumer, *, limit=100):
        """Return a bounded trusted-runtime worklist for crash-safe ACK recovery.

        The original lease token is deliberately unavailable here.  Once the inbox
        row is terminal, replaying its signed ACK cannot re-run the leased action; the
        consumer binding and joined terminal state fence this recovery path instead.
        """
        if consumer != self.consumer or type(limit) is not int or not 1 <= limit <= 100:
            raise InboxError("invalid completion ACK worklist request")
        with self._transaction():
            rows = self.db.execute("""SELECT a.seq,a.status,
                m.state AS message_state,m.envelope,m.inner_id,m.delivery_id
                FROM completion_acks a JOIN messages m ON m.seq=a.seq
                WHERE a.state='pending' ORDER BY a.seq LIMIT ?""", (limit,)).fetchall()
            output = []
            for row in rows:
                if (row["status"] not in ("processed", "failed")
                        or row["message_state"] != row["status"]
                        or not row["envelope"]
                        or not re.fullmatch(r"[0-9a-f]{64}", row["inner_id"])
                        or not row["delivery_id"]):
                    raise InboxConflict("completion ACK outbox is inconsistent")
                output.append({key: row[key] for key in (
                    "seq", "status", "envelope", "inner_id", "delivery_id")})
            return output

    def mark_completion_ack_sent_by_seq(self, seq, consumer, event_id):
        """Finish a pending ACK after trusted-runtime recovery, without its old token."""
        if (consumer != self.consumer or type(seq) is not int or seq < 1
                or not isinstance(event_id, str)
                or not re.fullmatch(r"[0-9a-f]{64}", event_id)):
            raise InboxError("invalid recovered completion ACK marker")
        with self._transaction():
            row = self.db.execute("""SELECT a.state,a.event_id,a.status,
                m.state AS message_state FROM completion_acks a
                JOIN messages m ON m.seq=a.seq WHERE a.seq=?""", (seq,)).fetchone()
            if row is None:
                raise InboxConflict("completion ACK marker has no matching outbox item")
            if row["status"] != row["message_state"]:
                raise InboxConflict("completion ACK outbox disagrees with inbox state")
            if row["state"] == "sent":
                return row["event_id"]
            if row["state"] != "pending":
                raise InboxConflict("completion ACK outbox is not pending")
            self.db.execute("""UPDATE completion_acks SET state='sent',event_id=?
                WHERE seq=? AND state='pending'""", (event_id, seq))
            return event_id

    def _reconcile_refusal(self, seq, inner_id):
        """Name what the row actually is; "state changed" alone sends operators guessing."""
        row = self.db.execute("SELECT state,lease_until FROM messages WHERE seq=? AND inner_id=?",
                              (seq, inner_id)).fetchone()
        if row is None:
            return ("unknown message reconciliation rejected: no message with this seq "
                    "and inner_id")
        text = (f"unknown message reconciliation rejected: the message is {row['state']}, "
                "not unknown")
        if row["state"] == "processing":
            text += (f"; its lease is still active until {int(row['lease_until'])}: finish "
                     "it with the lease token or reconcile after the lease expires")
        return text

    def reconcile_unknown(self, seq, inner_id, consumer, resolution, *,
                          allowed_senders=None, now=None):
        """Resolve one expired legacy claim without guessing whether work ran.

        `retry` is deliberately explicit and only requeues unexpired work from a
        sender allowed by the current policy: an expired worker may have completed an
        external effect before losing its lease, so automatic re-execution is unsafe.
        Expired or no-longer-allowed messages require a terminal `processed` or
        `failed` decision.
        Binding the decision to both the local sequence and signed inner event id keeps
        a stale note about one message from resolving another row that reused its seq in
        a different database.  Dialogue mode has its own fenced reconciliation path.
        """
        valid = (consumer == self.consumer and type(seq) is int
                 and 0 < seq <= 2**63 - 1
                 and isinstance(inner_id, str)
                 and re.fullmatch(r"[0-9a-f]{64}", inner_id)
                 and resolution in ("retry", "processed", "failed")
                 and (resolution != "retry" or allowed_senders is not None))
        if not valid:
            raise InboxError("invalid inbox reconciliation binding or resolution")
        state = "pending" if resolution == "retry" else resolution
        retry_refusal = None
        with self._transaction():
            if self.dialogue_enabled():
                raise InboxConflict(
                    "dialogue mode requires fenced dialogue reconciliation")
            now = _now(now)
            self._expire(now)
            if resolution == "retry":
                row = self.db.execute("""SELECT sender,expires FROM messages
                    WHERE seq=? AND inner_id=? AND state='unknown'""",
                    (seq, inner_id)).fetchone()
                if (row is not None and row["expires"] is not None
                        and row["expires"] <= now):
                    retry_refusal = "message expired"
                elif row is not None and row["sender"] not in allowed_senders:
                    retry_refusal = "sender is not allowed by current policy"
            if retry_refusal is None:
                changed = self.db.execute("""UPDATE messages
                    SET state=?,lease_token=NULL,lease_until=NULL
                    WHERE seq=? AND inner_id=? AND state='unknown'""",
                    (state, seq, inner_id)).rowcount
                if changed != 1:
                    raise InboxConflict(self._reconcile_refusal(seq, inner_id))
        if retry_refusal is not None:
            raise InboxConflict(
                f"unknown message retry rejected: {retry_refusal}; "
                "choose processed or failed")
        return {"state": state, "resolution": resolution, "seq": seq,
                "inner_id": inner_id, "network_ack_sent": False}

    def unknown_bindings(self, consumer, *, now=None, limit=100):
        """List bounded identifiers needed for explicit legacy reconciliation.

        This deliberately returns no sender, envelope, content, key, or lease data.
        It is an owner-CLI building block, not a model-facing inbox operation.
        """
        valid = (consumer == self.consumer and type(limit) is int
                 and 1 <= limit <= 100)
        if not valid:
            raise InboxError("invalid unknown inbox listing binding or limit")
        with self._transaction():
            if self.dialogue_enabled():
                raise InboxConflict(
                    "dialogue mode requires fenced dialogue reconciliation")
            self._expire(_now(now))
            rows = self.db.execute("""SELECT seq,inner_id FROM messages
                WHERE state='unknown' ORDER BY seq LIMIT ?""", (limit + 1,)).fetchall()
        return {"unknown": [{"seq": row["seq"], "inner_id": row["inner_id"]}
                            for row in rows[:limit]],
                "truncated": len(rows) > limit, "limit": limit}

    #: States from which work will NOT return. `blocked` is deliberately excluded: a
    #: message was rejected because its sender was not allowed, but the owner may allow
    #: that sender later and need the retained correspondence. `pending`, `processing`,
    #: and `unknown` are excluded even more obviously because they are unresolved work.
    FINISHED = ("processed", "failed", "expired")

    #: Platforms for which the archive durability boundary has been ESTABLISHED and
    #: verified: not only writing and `fsync`-ing the file, but also directory durability
    #: and access-control behavior across failures. The tuple is currently empty by
    #: design: the file is `fsync`-ed, the directory is not, and the Windows procedure
    #: has not been verified.
    #:
    #: While the tuple is empty, `compact=True` is refused EVERYWHERE. A destructive
    #: operation must not ship under an unverified promise (reviewer's answer to a
    #: direct question on 2026-09-09). Establishing the boundary means adding a platform
    #: here together with tests, not removing this tuple.
    DURABLE_ARCHIVE_PLATFORMS: tuple = ()

    def prune(self, *, before, archive, compact=False, now=None):
        """Export TERMINAL messages older than `before` to a file.

        The product does not and will not automatically delete by age: these are signed
        messages that may be presented in a dispute. This is a manual owner operation.

        By default the operation **only exports**: messages remain in place. This is not
        caution for its own sake. Destructive compaction promises that the export will
        survive a failure, but that promise has not been verified on any platform: the
        file is `fsync`-ed, the directory is not, and Windows behavior has not been
        measured. Until that promise is established, `compact=True` is refused. A
        useful non-destructive operation is better than destruction under an unverified
        guarantee.

        Compaction ordering is mandatory: write the file first, then clear the envelope.
        The export is written INSIDE the transaction so a write failure rolls everything
        back. Reversing the order loses data precisely when the disk is full, which is
        the very reason an owner would run cleanup.

        `archive` is mandatory. This is a refusal, not a warning, because warnings are
        often read only after the operation has completed.
        """
        if archive is None:
            raise InboxError("inbox prune requires an archive path: nothing is removed without it")
        # OPS-009: truthiness was evaluated twice, once at the gate and once in the
        # destructive branch. An object whose `__bool__` returned false first and true
        # second passed the gate and compacted data (a reviewer counted six truthiness
        # checks in one run). Validate the type once before any side effects, then use
        # that verified value rather than the original object.
        if type(compact) is not bool:
            raise InboxError(
                f"prune compact must be a bool, got {type(compact).__name__}: a value "
                "whose truth can change between checks is not a permission")
        if compact and sys.platform not in self.DURABLE_ARCHIVE_PLATFORMS:
            raise InboxError(
                "destructive compaction is refused: the durable archive boundary is not "
                f"established for {sys.platform!r}. Export-only pruning is available and "
                "leaves every message in place.")
        now = _now(now)
        archive = Path(archive)
        placeholders = ",".join("?" for _ in self.FINISHED)
        with self._transaction():
            # OPS-006: dialogue history refers to rows in this table. Removing an
            # envelope breaks ordinary history reads, not merely an "archive view."
            # Until archived history is designed, refuse rather than silently skipping
            # missing rows: incomplete history presented as complete is worse than failure.
            #
            # This check belongs INSIDE the transaction, and that is not a formality.
            # When it ran outside, a reviewer reproduced a race with two real
            # connections: the check saw the mode disabled, the second connection
            # enabled it, and cleanup erased the envelope of a row already referenced
            # by history. `BEGIN IMMEDIATE` makes "check, then clear" indivisible.
            # OPS-006: destruction is refused in dialogue mode because history refers
            # to these rows. Export is still ALLOWED because it moves nothing; banning
            # it would ban a harmless operation (the reviewer correctly found that my
            # proposed prohibition was too broad).
            if compact and self.dialogue_enabled():
                raise InboxError("inbox prune is refused while dialogue mode is enabled: "
                                 "dialogue history references these rows")
            # OPS-008: `_expire` is NO LONGER CALLED here. Export promises a copy, while
            # the previous version changed `processing` to `unknown`, cleared its lease
            # token, and changed `pending` to `expired` on the way, then exported rows
            # that had only just become terminal. Expiring leases belongs to ordinary
            # inbox operations, not copying.
            # `envelope != ''` prevents exporting already-compacted rows again: only
            # tombstones remain and they contain no envelope bytes.
            rows = self.db.execute(
                f"SELECT * FROM messages WHERE state IN ({placeholders}) "
                f"AND received < ? AND envelope != '' AND seq NOT IN "
                f"(SELECT seq FROM completion_acks WHERE state='pending')",
                (*self.FINISHED, before)).fetchall()
            payload = {"recipient": self.recipient, "consumer": self.consumer,
                       "written": now, "before": before,
                       "messages": [{key: row[key] for key in row.keys()} for row in rows]}
            freed = sum(len(row["envelope"].encode("utf-8")) for row in rows)
            # Always write a file, even for an empty export. The file proves the
            # operation ran and records exactly what it selected; an absent file proves
            # nothing. OPS-004: creation is EXCLUSIVE. The previous version opened for
            # writing and truncated an existing file, destroying prior evidence on a
            # SUCCESSFUL rerun rather than only on failure. An existing export after a
            # database rollback is orphaned evidence, not permission to overwrite it.
            try:
                fd = os.open(archive, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                raise InboxError(
                    f"inbox prune archive already exists and is never overwritten: {archive}"
                ) from None
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            if rows and compact:
                # OPS-005: the row is NOT deleted. A terminal record represents both
                # envelope bytes and the fact that "this work is done." Reclaim the
                # former while retaining the latter: `sender`, `dedup`, `digest`,
                # `inner_id`, and state stay in place while the envelope is cleared.
                # The tombstone deliberately lives in the SAME table. A separate table
                # would create a compatibility gap: an old receiver with an already-open
                # connection would not know about it and would accept the message again.
                #
                # The cost is explicit: `max_items` counts tombstones, so cleanup
                # reclaims bytes but does not free slots in the message count.
                self.db.execute(
                    f"UPDATE messages SET envelope='' WHERE state IN ({placeholders}) "
                    f"AND received < ? AND envelope != '' AND seq NOT IN "
                    f"(SELECT seq FROM completion_acks WHERE state='pending')",
                    (*self.FINISHED, before))
        # VACUUM runs outside the transaction. Without it, freed pages remain in the
        # file and an owner who ran cleanup to reclaim disk space sees no benefit.
        # Export-only mode has nothing to compact.
        reclaimed = False
        if compact:
            reclaimed = True
            try:
                self.db.execute("VACUUM")
            except sqlite3.Error:
                reclaimed = False
        # `exported` is the number exported; `compacted` is the number cleared. The
        # latter is visibly zero in export-only mode rather than being implicit. Using
        # one name for two counts invites "I thought it deleted them" misunderstandings.
        return {"exported": len(rows), "compacted": len(rows) if compact else 0,
                "bytes": freed if compact else 0, "archive": str(archive),
                "reclaimed": reclaimed, "mode": "compact" if compact else "export-only"}

    def status(self, *, now=None):
        with self._transaction():
            self._expire(_now(now))
            result = {state: 0 for state in ("pending", "processing", "processed", "failed", "unknown", "blocked", "expired")}
            result.update(dict(self.db.execute("SELECT state,COUNT(*) FROM messages GROUP BY state")))
            result["total"] = sum(result.values())
            result["ack_pending"] = self.db.execute(
                "SELECT COUNT(*) FROM completion_acks WHERE state='pending'"
            ).fetchone()[0]
            result["ack_sent"] = self.db.execute(
                "SELECT COUNT(*) FROM completion_acks WHERE state='sent'"
            ).fetchone()[0]
            result["consumer"] = self.consumer
            # Add space use and capacity AFTER computing total; otherwise those values
            # enter the state sum and "total messages" becomes a byte count.
            #
            # Use exactly the same expression as `_insert`. Two ways to measure one
            # resource silently diverge, making the report show spare capacity where
            # acceptance already fails. HISTORY consumes the space: processed messages
            # are never deleted and eventually push the inbox against its ceiling
            # (production-profile measurements on 2026-09-08: 275 and 496 KiB/day).
            result["bytes"] = self.db.execute(
                "SELECT COALESCE(SUM(length(CAST(envelope AS BLOB))), 0) FROM messages").fetchone()[0]
            result["capacity_bytes"] = self.max_bytes
            result["capacity_items"] = self.max_items
            # Compacted rows are envelope-free tombstones retained after cleanup. Show
            # them SEPARATELY because they affect the two limits differently: they use
            # no envelope bytes but still occupy message-count slots. Cleanup reclaims
            # bytes and does NOT reclaim slots; reports should state that explicitly.
            result["compacted"] = self.db.execute(
                "SELECT COUNT(*) FROM messages WHERE envelope=''").fetchone()[0]
            return result

    def work_snapshot(self, allowed_senders, *, now=None):
        """Return current eligible metadata without reserving a wake budget."""
        with self._transaction():
            return self._work_snapshot(allowed_senders, _now(now))

    def _work_snapshot(self, allowed_senders, now):
        """Observe/expire eligible work inside the caller's existing transaction.

        The fingerprint is lowercase SHA256 hex, or None for no eligible work.
        The notice always has the existing closed metadata shape, including zeros.
        """
        dialogue = self.dialogue_enabled()
        outgoing = []
        if dialogue:
            self._expire_dialogues(now)
            rows = self.db.execute("""SELECT seq,sender,state FROM messages
                WHERE state IN ('pending','unknown') AND sender NOT IN
                (SELECT peer FROM dialogues WHERE lease_until>?) ORDER BY seq""", (now,)).fetchall()
            outgoing = [row for row in self.db.execute("""SELECT seq,peer,state FROM dialogue_outbox
                WHERE state IN ('prepared','unknown') AND peer NOT IN
                (SELECT peer FROM dialogues WHERE lease_until>?) ORDER BY seq""", (now,))
                if row["peer"] in allowed_senders]
        else:
            self._expire(now)
            rows = self.db.execute("SELECT seq,sender,state FROM messages WHERE state='pending' ORDER BY seq").fetchall()
        ready = []
        uncertain = 0
        for row in rows:
            if row["sender"] in allowed_senders:
                ready.append(row)
                uncertain += row["state"] == "unknown"
            # Revocation suppresses access, not evidence of unfinished effects.
            elif row["state"] != "unknown":
                self.db.execute("UPDATE messages SET state='blocked' WHERE seq=?", (row["seq"],))
        fingerprint = hashlib.sha256(json.dumps([
            self.recipient, self.consumer, dialogue,
            [(r["seq"], r["state"]) for r in ready],
            [(r["seq"], r["state"]) for r in outgoing],
        ], separators=(",", ":")).encode()).hexdigest() if ready or outgoing else None
        notice = {"consumer": self.consumer, "pending": len(ready) - uncertain,
                  "seq_hint": ready[0]["seq"] if ready else 0}
        if dialogue:
            notice["needs_reconciliation"] = uncertain + sum(r["state"] == "unknown" for r in outgoing)
            notice["outgoing_prepared"] = sum(r["state"] == "prepared" for r in outgoing)
        return {"fingerprint": fingerprint, "notice": notice}

    def _reserve_wake(self, now, interval, per_hour):
        """Validate and reserve the existing budget in the caller's transaction."""
        _validate_wake_budget(interval, per_hour)
        prior = self.db.execute("SELECT last,window,count FROM wakeups WHERE singleton=1").fetchone()
        window, count = (prior["window"], prior["count"]) if prior and now - prior["window"] < 3600 else (now, 0)
        if (not prior or now - prior["last"] >= interval) and count < per_hour:
            self.db.execute("INSERT INTO wakeups VALUES (1,?,?,?) ON CONFLICT(singleton) DO UPDATE SET last=excluded.last,window=excluded.window,count=excluded.count", (now, window, count + 1))
            return True
        return False

    def notice(self, allowed_senders, *, now=None, interval=60, per_hour=12,
               tracker: NoticeTracker | None = None):
        """Reserve a bounded wake hint, not a read/processing acknowledgement."""
        _validate_wake_budget(interval, per_hour)
        now = _now(now)
        hint = None
        with self._transaction():
            snapshot = self._work_snapshot(allowed_senders, now)
            has_work = snapshot["fingerprint"] is not None
            fingerprint = bytes.fromhex(snapshot["fingerprint"]) if has_work else None
            if has_work and (tracker is None or tracker._fingerprint != fingerprint):
                if self._reserve_wake(now, interval, per_hour):
                    hint = snapshot["notice"]
        # Only committed observations count. Throttled new work remains eligible.
        if tracker is not None and (hint is not None or not has_work):
            tracker._fingerprint = fingerprint
        return hint

    def set_health(self, state, *, now=None):
        if state not in ("starting", "ready", "disconnected", "backlog", "stopped", "failed"):
            raise InboxError("invalid receiver state")
        # 26.09.2026: a live receiver showed "failed" and no one could say which code wrote
        # it. A change of state (not a repeat) names the old state and the calling function.
        before = self.health(now=now).get("state")
        if before != state:
            caller = sys._getframe(1).f_code
            _log.info("receiver health %s -> %s (from %s, line %d)", before, state,
                      caller.co_name, sys._getframe(1).f_lineno)
        with self._transaction():
            self.db.execute("INSERT INTO metadata VALUES ('receiver',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                            (json.dumps({"state": state, "checked_at": _now(now)}),))

    def health(self, *, now=None):
        row = self.db.execute("SELECT value FROM metadata WHERE key='receiver'").fetchone()
        if not row:
            return {"state": "not_started", "stale": True}
        value = json.loads(row[0])
        value["stale"] = _now(now) - value["checked_at"] > 90
        return value

    def quarantine_counts(self) -> dict[str, int]:
        """Return counts of reception quarantine requests by state."""
        counts = {"pending": 0, "accepted": 0, "rejected": 0, "blocked": 0}
        for state, cnt in self.db.execute(
            "SELECT state, COUNT(*) FROM quarantine_requests GROUP BY state"
        ):
            if state in counts:
                counts[state] = int(cnt)
        counts["total"] = sum(counts.values())
        return counts

    def quarantine_list(self, *, state: str | None = "pending", limit: int = 50) -> list[dict]:
        """Return bounded quarantine request summaries for owner digest review."""
        if type(limit) is not int or not 1 <= limit <= 200:
            raise InboxError("quarantine list limit must be 1..200")
        if state is not None and state not in ("pending", "accepted", "rejected", "blocked"):
            raise InboxError(f"invalid quarantine state filter: {state!r}")
        if state is None:
            rows = self.db.execute(
                """SELECT req_id, sender, delivery_id, inner_id, preview, received, expires, state, decided_at
                   FROM quarantine_requests ORDER BY req_id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        else:
            rows = self.db.execute(
                """SELECT req_id, sender, delivery_id, inner_id, preview, received, expires, state, decided_at
                   FROM quarantine_requests WHERE state=? ORDER BY req_id ASC LIMIT ?""",
                (state, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def quarantine_decide(self, req_id: int, decision: str, *, now=None) -> dict:
        """Apply an owner decision ('accept', 'reject', or 'block') to a quarantine request."""
        if type(req_id) is not int or req_id < 1:
            raise InboxError("req_id must be a positive integer")
        if decision not in ("accept", "reject", "block"):
            raise InboxError("decision must be 'accept', 'reject', or 'block'")
        ts = _now(now)
        with self._transaction():
            row = self.db.execute(
                "SELECT * FROM quarantine_requests WHERE req_id=?",
                (req_id,),
            ).fetchone()
            if row is None:
                raise InboxError(f"no quarantine request with req_id={req_id}")
            if row["state"] != "pending":
                raise InboxConflict(
                    f"quarantine request {req_id} is already {row['state']}"
                )
            new_state = {
                "accept": "accepted",
                "reject": "rejected",
                "block": "blocked",
            }[decision]
            seq = None
            if decision == "accept":
                existing = self.db.execute(
                    "SELECT seq FROM messages WHERE sender=? AND dedup=?",
                    (row["sender"], row["dedup"]),
                ).fetchone()
                if existing is not None:
                    seq = int(existing[0])
                else:
                    cur = self.db.execute(
                        """INSERT INTO messages
                        (sender,dedup,digest,inner_id,outer_id,delivery_id,envelope,received,expires)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                        (
                            row["sender"],
                            row["dedup"],
                            row["digest"],
                            row["inner_id"],
                            row["outer_id"],
                            row["delivery_id"],
                            row["envelope"],
                            row["received"],
                            row["expires"],
                        ),
                    )
                    seq = int(cur.lastrowid)
            self.db.execute(
                "UPDATE quarantine_requests SET state=?, decided_at=? WHERE req_id=?",
                (new_state, ts, req_id),
            )
            return {
                "req_id": req_id,
                "sender": row["sender"],
                "decision": decision,
                "state": new_state,
                "delivery_id": row["delivery_id"],
                "inner_id": row["inner_id"],
                "promoted_seq": seq,
                "decided_at": ts,
            }

