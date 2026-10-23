"""Bounded durable repair of already authorized public announcements.

Only profiles, requests and relay lists belong here. Private messages and keys
are never stored. Records retain exact signed events and original destinations;
repair can use only destinations still configured by the caller. Fully accepted
records leave this operational queue; it is not a public-history backup.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
import json
import os
from pathlib import Path
import sqlite3
import time

from . import delegation, keyfile
from .event import Event, is_canonical_pubkey, parse_uint
from .inbox import InboxError, _private_directory
from .inbox_lock import receiver_lock
from .relay import RelayError

KINDS = frozenset((10002, 31001, 31002))
MAX_RECORDS = 256
MAX_EVENT_BYTES = 131072
MAX_AGE = 48 * 3600
RETRY_GAPS = (60, 300, 900, 3600, 10800, 21600)


class PublicationError(RuntimeError):
    """The public repair queue cannot safely record or restore a publication."""


def _mutating(method):
    @wraps(method)
    def protected(self, *args, **kwargs):
        with self.mutation_guard():
            return method(self, *args, **kwargs)
    return protected


def coordinate(event):
    ds = event.tag_values("d")
    if event.kind not in KINDS or not event.verify_protocol():
        raise PublicationError("only signed public announcements may enter the repair queue")
    if event.kind != 10002 and (len(ds) != 1 or not ds[0]):
        raise PublicationError("public announcement needs one exact coordinate")
    return f"{event.kind}:{event.pubkey}:{ds[0] if event.kind != 10002 else ''}"


class PublicationStore:
    def __init__(self, directory, pubkey):
        if not is_canonical_pubkey(pubkey):
            raise PublicationError("publication identity must be an exact public key")
        directory = Path(directory)
        _private_directory(directory)
        self.lock_directory = directory / ".publication-mutations"
        _private_directory(self.lock_directory)
        self.path = directory / "publications.sqlite3"
        if self.path.is_symlink():
            raise PublicationError("publication database must not be a symlink")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        if not keyfile.harden_and_check(self.path, force=True)[0]:
            raise PublicationError("cannot protect publication database")
        self.pubkey = pubkey
        self.db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("CREATE TABLE IF NOT EXISTS identity (pubkey TEXT PRIMARY KEY)")
            self.db.execute("BEGIN IMMEDIATE")
            if not self.db.execute("SELECT pubkey FROM identity").fetchone():
                self.db.execute("INSERT OR IGNORE INTO identity VALUES (?)", (pubkey,))
            if [r[0] for r in self.db.execute("SELECT pubkey FROM identity")] != [pubkey]:
                raise PublicationError("publication database belongs to another identity")
            self.db.execute("COMMIT")
            self.db.execute("""CREATE TABLE IF NOT EXISTS pending (
                coordinate TEXT PRIMARY KEY, event_id TEXT NOT NULL,
                event TEXT NOT NULL, mandate TEXT, targets TEXT NOT NULL,
                accepted TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt REAL NOT NULL, state TEXT NOT NULL DEFAULT 'pending')""")
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    @contextmanager
    def mutation_guard(self):
        """Serialize cancellation/replacement with wire sends; death releases the lock."""
        try:
            with receiver_lock(self.lock_directory):
                yield
        except InboxError as exc:
            raise PublicationError(
                "publication mutation or send is already in flight, or its lock is unsafe; "
                "the requested local change was not performed") from exc

    @_mutating
    def stage(self, event, mandate, targets, *, now=None):
        now = time.time() if now is None else now
        key = coordinate(event)
        raw = event.model_dump_json()
        if event.pubkey != self.pubkey or len(raw.encode()) > MAX_EVENT_BYTES:
            raise PublicationError("publication author or size is invalid")
        if mandate is not None and len(mandate.model_dump_json().encode()) > MAX_EVENT_BYTES:
            raise PublicationError("publication mandate exceeds the size bound")
        if event.kind == 10002 and mandate is not None:
            raise PublicationError("relay-list repair must not carry a mandate")
        if event.kind != 10002:
            if (mandate is None or event.tag_values("delegation") != [mandate.id]
                    or not delegation.validate_sender_mandate(self.pubkey, mandate, now=int(now), require_started=True)):
                raise PublicationError("public announcement needs its current signed owner mandate")
        targets = list(dict.fromkeys(targets))
        if not targets or len(targets) > 32 or any(not isinstance(t, str) or len(t) > 2048 for t in targets):
            raise PublicationError("publication destinations must be a bounded configured set")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            old = self.db.execute("SELECT * FROM pending WHERE coordinate=?", (key,)).fetchone()
            if old and old["event_id"] == event.id:
                if json.loads(old["targets"]) != targets:
                    raise PublicationError("an existing signed event cannot acquire new repair destinations")
                self.db.execute("COMMIT")
                return
            if old and old["event_id"] != event.id:
                previous = Event.model_validate_json(old["event"])
                if (-previous.created_at, previous.id) <= (-event.created_at, event.id):
                    raise PublicationError("a newer announcement already occupies this coordinate")
            if old is None and self.db.execute("SELECT count(*) FROM pending").fetchone()[0] >= MAX_RECORDS:
                raise PublicationError("public repair queue is full; review pending publications")
            self.db.execute("""INSERT OR REPLACE INTO pending
                (coordinate,event_id,event,mandate,targets,accepted,next_attempt)
                VALUES (?,?,?,?,?,?,?)""", (key,event.id,raw,mandate.model_dump_json() if mandate else None,
                    json.dumps(targets),json.dumps([]),now+RETRY_GAPS[0]))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    @_mutating
    def record(self, event_id, accepted, *, now=None):
        self._record_locked(event_id, accepted, now=now)

    def _record_locked(self, event_id, accepted, *, now=None):
        """Update receipts while the caller owns mutation_guard."""
        now = time.time() if now is None else now
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT * FROM pending WHERE event_id=?", (event_id,)).fetchone()
            if row:
                done = set(json.loads(row["accepted"])) | set(accepted)
                targets = set(json.loads(row["targets"]))
                if done >= targets:
                    self.db.execute("DELETE FROM pending WHERE event_id=?", (event_id,))
                else:
                    attempts = row["attempts"] + 1
                    delay = RETRY_GAPS[min(attempts-1, len(RETRY_GAPS)-1)]
                    self.db.execute("UPDATE pending SET accepted=?,attempts=?,next_attempt=? WHERE event_id=?",
                                    (json.dumps(sorted(done & targets)),attempts,now+delay,event_id))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    @_mutating
    def hold(self, event_id, reason):
        self.db.execute("UPDATE pending SET state=? WHERE event_id=?", (reason,event_id))

    def due(self, now, limit):
        if type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError("repair limit must be 1..20")
        return [dict(r) for r in self.db.execute("SELECT * FROM pending WHERE state='pending' AND next_attempt<=? ORDER BY next_attempt LIMIT ?", (now,limit))]

    def status(self):
        return {r["state"]: r["n"] for r in self.db.execute("SELECT state,count(*) AS n FROM pending GROUP BY state")}

    def entries(self):
        """Bounded operational metadata, without public bodies or signed mandates."""
        return [dict(r) for r in self.db.execute(
            "SELECT event_id,coordinate,state,attempts,next_attempt FROM pending ORDER BY next_attempt LIMIT ?", (MAX_RECORDS,))]

    @_mutating
    def discard(self, event_id):
        """Cancel a local retry unless a send has begun; never withdraw network copies."""
        if not is_canonical_pubkey(event_id):
            raise PublicationError("an exact event ID is required to discard a retry")
        return bool(self.db.execute("DELETE FROM pending WHERE event_id=?", (event_id,)).rowcount)


@dataclass
class _NodeMandateEvidence:
    events: list[Event]
    complete: bool


async def mandate_evidence(agent, mandate, *, timeout=2):
    """Keep each node's complete answer; missing negative evidence is never empty."""
    filters = [{"kinds": [31000, 31007], "authors": [mandate.pubkey],
                "#d": [agent.pubkey]}]
    async def one(client):
        async with asyncio.timeout(timeout):
            if client._ws is None:
                await client.connect()
            result = await client.query_bounded(filters, max_events=256)
            complete = not (result.truncated or result.connection_dropped_events or result.discarded_invalid_events)
            # A partial answer can still prove revocation. Never lose such positive
            # negative-authority evidence while refusing to infer absence from it.
            return _NodeMandateEvidence(result.events, complete)
    batches = await asyncio.gather(*(one(c) for c in agent.relay.clients), return_exceptions=True)
    return dict(zip((c.url for c in agent.relay.clients),
                    (batch if not isinstance(batch, BaseException) else _NodeMandateEvidence([], False)
                     for batch in batches)))


def _mandate_blocked(agent, mandate, batches):
    for batch in batches.values():
        for ev in batch.events:
            if ev.kind == 31007 and delegation.is_revocation_valid(ev, mandate):
                return "revoked"
            if (ev.kind == 31000 and ev.pubkey == mandate.pubkey and ev.verify()
                    and delegation.delegation_target(ev) == agent.pubkey
                    and (-ev.created_at, ev.id) < (-mandate.created_at, mandate.id)):
                return "authorization_superseded"
    return None


def _has_exact_mandate(batch, mandate):
    return any(
        ev.id == mandate.id and ev.model_dump() == mandate.model_dump() and ev.verify()
        for ev in batch.events)


@dataclass
class _MandateCopyResult:
    usable: bool
    revocations: list[Event]


async def check_and_copy_existing_mandate(agent, mandate):
    """Copy only with complete negative evidence; never create owner authorization."""
    if not delegation.validate_sender_mandate(agent.pubkey, mandate, require_started=True):
        return _MandateCopyResult(False, [])
    batches = await mandate_evidence(agent, mandate)
    revocations = [ev for batch in batches.values() for ev in batch.events
                   if delegation.is_revocation_valid(ev, mandate)]
    if _mandate_blocked(agent, mandate, batches):
        return _MandateCopyResult(False, revocations)
    if not all(batch.complete for batch in batches.values()):
        return _MandateCopyResult(True, revocations)  # No new node receives a mandate.
    async def one(client):
        if not _has_exact_mandate(batches[client.url], mandate):
            await client.publish(mandate, replay_on_reconnect=False)
    outcomes = await asyncio.gather(*(one(c) for c in agent.relay.clients), return_exceptions=True)
    if any(isinstance(outcome, asyncio.CancelledError) for outcome in outcomes):
        raise asyncio.CancelledError
    return _MandateCopyResult(True, revocations)


async def copy_existing_mandate(agent, mandate):
    """Boolean reuse verdict for callers that never issue replacement authority."""
    return (await check_and_copy_existing_mandate(agent, mandate)).usable


async def send_record(agent, event, mandate, store, *, targets=None, now=None, timeout=10, require_acceptance=False):
    """Send exact signatures through owned clients; return actual node receipts."""
    clients = [c for c in agent.relay.clients if targets is None or c.url in targets]
    batches = await mandate_evidence(agent, mandate) if mandate is not None else {}
    blocked = _mandate_blocked(agent, mandate, batches) if mandate is not None else None
    if blocked:
        store.hold(event.id, blocked)
        raise PublicationError("the existing owner mandate is " + blocked + "; publication was not performed")
    copy_allowed = all(batch.complete for batch in batches.values())
    async def one(client):
        try:
            async with asyncio.timeout(timeout):
                if client._ws is None:
                    await client.connect()
                if mandate is not None:
                    if not _has_exact_mandate(batches[client.url], mandate):
                        if not copy_allowed:
                            raise PublicationError("cannot copy a mandate without complete node evidence")
                        await client.publish(mandate, replay_on_reconnect=False)
                await client.publish(event, replay_on_reconnect=False)
            return client.url, None
        except (RelayError, OSError, TimeoutError, PublicationError) as exc:
            return None, exc
    # Evidence awaits above must not let a discarded or superseded snapshot send.
    # Mutations use the same nonblocking OS lock and refuse cancellation in flight.
    # No SQLite transaction spans network work; process death releases ownership.
    with store.mutation_guard():
        row = store.db.execute("SELECT * FROM pending WHERE coordinate=?", (coordinate(event),)).fetchone()
        if (row is None or row["event_id"] != event.id or row["state"] != "pending"
                or row["event"] != event.model_dump_json()
                or row["mandate"] != (mandate.model_dump_json() if mandate is not None else None)
                or any(c.url not in json.loads(row["targets"]) for c in clients)):
            if require_acceptance:
                raise PublicationError("publication was cancelled or superseded before sending")
            return {"event_id": event.id, "accepted": 0, "configured": len(clients),
                    "pending": len(clients), "cancelled": True}
        outcomes = await asyncio.gather(*(one(c) for c in clients))
        accepted = [url for url, _ in outcomes if url is not None]
        store._record_locked(event.id, accepted, now=now)
    if require_acceptance and not accepted:
        reason = next((e.reason for _, e in outcomes if isinstance(e, RelayError) and e.reason), "")
        raise RelayError("no configured node accepted the public announcement; its signed event is queued for repair"
                         + (f"; relay refusal: {reason}" if reason else ""), reason=reason)
    return {"event_id": event.id, "accepted": len(accepted), "configured": len(clients),
            "pending": len(clients)-len(accepted)}


async def repair(agent, store, *, now=None, limit=5):
    now = time.time() if now is None else now
    report = {"checked": 0, "restored": 0, "held": 0, "deferred": 0}
    configured = {c.url for c in agent.relay.clients}
    for row in store.due(now, limit):
        try:
            if any(len(row[k].encode()) > MAX_EVENT_BYTES for k in ("event", "mandate") if row[k]):
                raise ValueError("event size")
            event = Event.model_validate_json(row["event"])
            mandate = Event.model_validate_json(row["mandate"]) if row["mandate"] else None
            targets, accepted = json.loads(row["targets"]), json.loads(row["accepted"])
            if (not isinstance(targets, list) or not 1 <= len(targets) <= 32
                    or any(not isinstance(t, str) or len(t) > 2048 for t in targets)
                    or not isinstance(accepted, list) or any(t not in targets for t in accepted)
                    or (event.kind == 10002 and mandate is not None)):
                raise ValueError("destinations or mandate")
            coordinate(event)
        except (ValueError, TypeError, PublicationError) as exc:
            raise PublicationError("publication queue record is malformed") from exc
        if event.pubkey != agent.pubkey or coordinate(event) != row["coordinate"] or event.id != row["event_id"]:
            raise PublicationError("publication queue record identity is invalid")
        report["checked"] += 1
        expiry = parse_uint(event.tag_value("expiration"))
        deadline = parse_uint(event.tag_value("deadline")) if event.kind == 31002 else None
        if now > event.created_at+MAX_AGE or (expiry is not None and now >= expiry) or (deadline is not None and now >= deadline):
            store.hold(event.id, "expired")
            report["held"] += 1
            continue
        if event.kind != 10002:
            if (mandate is None or event.tag_values("delegation") != [mandate.id]
                    or not delegation.validate_sender_mandate(agent.pubkey, mandate, now=int(now), require_started=True)):
                store.hold(event.id, "authorization_expired")
                report["held"] += 1
                continue
        filters = [{"kinds":[5],"authors":[agent.pubkey],"#e":[event.id]},
                   {"kinds":[5],"authors":[agent.pubkey],"#a":[row["coordinate"]]}]
        current_filter = {"kinds": [event.kind], "authors": [agent.pubkey]}
        if event.kind != 10002:
            current_filter["#d"] = event.tag_values("d")
        filters.append(current_filter)
        if mandate is not None:
            filters.append({"kinds":[31007],"authors":[mandate.pubkey],"#d":[agent.pubkey]})
            filters.append({"kinds":[31000],"authors":[mandate.pubkey],"#d":[agent.pubkey]})
        async def verify_node(client):
            async with asyncio.timeout(2):
                if client._ws is None:
                    await client.connect()
                result = await client.query_bounded(filters, max_events=256)
                if result.truncated or result.connection_dropped_events or result.discarded_invalid_events:
                    raise PublicationError("publication authority/deletion check was truncated")
                return result.events
        # Never interpret an unavailable node as proof that no revocation or
        # withdrawal exists. Verify every currently configured node before repair.
        batches = await asyncio.gather(*(verify_node(c) for c in agent.relay.clients), return_exceptions=True)
        if any(isinstance(batch, BaseException) for batch in batches):
            store.record(event.id, [], now=now)
            report["deferred"] += 1
            continue
        evidence = [e for batch in batches for e in batch]
        if mandate is not None and any(e.kind == 31000 and e.pubkey == mandate.pubkey
                and delegation.delegation_target(e) == agent.pubkey and e.verify()
                and (-e.created_at, e.id) < (-mandate.created_at, mandate.id) for e in evidence):
            store.hold(event.id, "authorization_superseded")
            report["held"] += 1
            continue
        if any(e.kind == event.kind and e.pubkey == agent.pubkey and e.verify()
               and (event.kind == 10002 or e.tag_values("d") == event.tag_values("d"))
               and (-e.created_at, e.id) < (-event.created_at, event.id) for e in evidence):
            store.hold(event.id, "superseded")
            report["held"] += 1
            continue
        if mandate is not None and any(delegation.is_revocation_valid(r, mandate) for r in evidence if r.kind == 31007):
            store.hold(event.id, "revoked")
            report["held"] += 1
            continue
        if any(e.verify() and e.pubkey == agent.pubkey and e.kind == 5 and
               (event.id in e.tag_values("e") or (row["coordinate"] in e.tag_values("a") and e.created_at >= event.created_at)) for e in evidence):
            store.hold(event.id, "withdrawn")
            report["held"] += 1
            continue
        pending = set(targets) - set(accepted)
        allowed = pending & configured
        if not allowed:
            store.hold(event.id, "configuration_changed")
            report["held"] += 1
            continue
        result = await send_record(agent, event, mandate, store, targets=allowed, now=now, timeout=2)
        if result["pending"] == 0 and pending <= configured:
            report["restored"] += 1
    return report
