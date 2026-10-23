"""Offline verification of the proposed owner-signed organization inbox route.

This module does not fetch or publish descriptors, encrypt messages, or change
a live mailbox. Its optional local checkpoint store records verified route
high-water marks, but is not wired to any sender. Kind 31008 is a v0.5
*candidate* pending wire-format and relay review; callers must not treat this
module as a live organization-mail transport.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from . import keyfile
from .event import Event, is_canonical_pubkey, parse_uint
from .inbox import _private_directory


_CANDIDATE_KIND = 31008
_TAG_NAMES = frozenset({"d", "p", "generation", "not_before", "expiration"})
_MAX_ACTIVE_GENERATIONS = 2
_MAX_TAG_UINT = 10**19 - 1


class DescriptorError(ValueError):
    """No safe physical inbox can be selected from the given route proof."""


@dataclass(frozen=True)
class InboxDescriptor:
    owner_pubkey: str
    ingress_pubkey: str
    generation: int
    not_before: int
    expiration: int
    event_id: str


@dataclass(frozen=True)
class DescriptorCheckpoint:
    """Exact high-water mark of an established sender's last verified route."""

    owner_pubkey: str
    event_id: str
    generation: int
    ingress_pubkey: str

    def __post_init__(self):
        if (not isinstance(self.owner_pubkey, str)
                or not is_canonical_pubkey(self.owner_pubkey)
                or not isinstance(self.event_id, str)
                or not is_canonical_pubkey(self.event_id)
                or not isinstance(self.ingress_pubkey, str)
                or not is_canonical_pubkey(self.ingress_pubkey)
                or type(self.generation) is not int
                or not 1 <= self.generation <= _MAX_TAG_UINT):
            raise DescriptorError("invalid descriptor checkpoint")


@dataclass(frozen=True)
class FirstContactCheckpoint:
    """Stable QR/address bundle: owner key and minimum acceptable generation."""

    owner_pubkey: str
    generation_floor: int

    def __post_init__(self):
        if (not isinstance(self.owner_pubkey, str)
                or not is_canonical_pubkey(self.owner_pubkey)
                or type(self.generation_floor) is not int
                or not 1 <= self.generation_floor <= _MAX_TAG_UINT):
            raise DescriptorError("invalid first-contact checkpoint")


def _inputs(owner_pubkey: str, now: int, max_validity_seconds: int):
    if not isinstance(owner_pubkey, str) or not is_canonical_pubkey(owner_pubkey):
        raise DescriptorError("invalid organization owner key")
    if type(now) is not int or now < 0:
        raise DescriptorError("invalid verification time")
    if type(max_validity_seconds) is not int or max_validity_seconds < 1:
        raise DescriptorError("invalid maximum descriptor validity")


def _parse(event: Event, owner_pubkey: str, max_validity_seconds: int) -> InboxDescriptor:
    if not isinstance(event, Event):
        raise DescriptorError("descriptor must be a signed event")
    if event.kind != _CANDIDATE_KIND:
        raise DescriptorError("wrong descriptor kind")
    if event.pubkey != owner_pubkey:
        raise DescriptorError("descriptor signer is not the organization owner")
    if not event.verify():
        raise DescriptorError("invalid descriptor signature")
    if event.content != "":
        raise DescriptorError("descriptor content must be empty")
    if len(event.tags) != len(_TAG_NAMES):
        raise DescriptorError("descriptor tags are missing or duplicated")
    tags = {}
    for tag in event.tags:
        if len(tag) != 2 or tag[0] not in _TAG_NAMES or tag[0] in tags:
            raise DescriptorError("descriptor has an ambiguous or unknown tag")
        tags[tag[0]] = tag[1]
    if tags.keys() != _TAG_NAMES:
        raise DescriptorError("descriptor tags are incomplete")
    ingress = tags["p"]
    if not is_canonical_pubkey(ingress):
        raise DescriptorError("invalid physical ingress key")
    if ingress == owner_pubkey:
        raise DescriptorError("owner and online ingress keys must be distinct")
    generation = parse_uint(tags["generation"])
    not_before = parse_uint(tags["not_before"])
    expiration = parse_uint(tags["expiration"])
    if generation is None or generation < 1:
        raise DescriptorError("generation must be a positive canonical integer")
    if tags["d"] != f"inbox:{generation}":
        raise DescriptorError("descriptor address does not match generation")
    if (not_before is None or expiration is None or expiration <= not_before
            or expiration - not_before > max_validity_seconds):
        raise DescriptorError("invalid descriptor validity interval")
    return InboxDescriptor(owner_pubkey, ingress, generation,
                           not_before, expiration, event.id)


def _active(proof: InboxDescriptor, now: int):
    if not proof.not_before <= now < proof.expiration:
        raise DescriptorError("descriptor is not active at verification time")


def verify_descriptor(event: Event, owner_pubkey: str, *, now: int,
                      max_validity_seconds: int) -> InboxDescriptor:
    """Verify one candidate route proof, including signature and active time."""
    _inputs(owner_pubkey, now, max_validity_seconds)
    proof = _parse(event, owner_pubkey, max_validity_seconds)
    _active(proof, now)
    return proof


def select_descriptor(events: Iterable[Event], owner_pubkey: str, *, now: int,
                      max_validity_seconds: int, lookup_complete: bool,
                      first_contact: FirstContactCheckpoint | None = None,
                      previous: DescriptorCheckpoint | None = None) -> InboxDescriptor:
    """Fail-closed offline selection from a caller-supplied complete relay result.

    `lookup_complete` is an assertion by the future network caller, not a claim
    this offline function can independently prove. A first-contact QR pins a
    generation floor while an established sender remembers an exact event.
    """
    _inputs(owner_pubkey, now, max_validity_seconds)
    if lookup_complete is not True:
        raise DescriptorError("incomplete descriptor relay lookup")
    if (first_contact is None) == (previous is None):
        raise DescriptorError("choose one first-contact or previous checkpoint")
    if (first_contact is not None and not isinstance(first_contact, FirstContactCheckpoint)
            or previous is not None and not isinstance(previous, DescriptorCheckpoint)):
        raise DescriptorError("wrong descriptor checkpoint type")
    checkpoint = first_contact if first_contact is not None else previous
    if checkpoint.owner_pubkey != owner_pubkey:
        raise DescriptorError("checkpoint owner mismatch")
    candidates = []
    for event in events:
        if len(candidates) >= 100:
            raise DescriptorError("descriptor relay result exceeds limit")
        candidates.append(_parse(event, owner_pubkey, max_validity_seconds))
    if not candidates:
        raise DescriptorError("no descriptor found")
    active_generations = {proof.generation for proof in candidates
                          if proof.not_before <= now < proof.expiration}
    if len(active_generations) > _MAX_ACTIVE_GENERATIONS:
        raise DescriptorError("too many simultaneously active descriptor generations")
    effective = [proof for proof in candidates if proof.not_before <= now]
    if not effective:
        raise DescriptorError("no effective descriptor yet")
    highest = max(proof.generation for proof in effective)
    newest = {proof.event_id: proof for proof in effective
              if proof.generation == highest}
    if len(newest) != 1:
        raise DescriptorError("conflicting descriptors at the same generation")
    proof = next(iter(newest.values()))
    if first_contact is not None:
        if proof.generation < first_contact.generation_floor:
            raise DescriptorError("checkpoint_outdated: descriptor below QR generation floor")
    else:
        if proof.generation < previous.generation:
            raise DescriptorError("descriptor generation rollback")
        if proof.generation == previous.generation:
            if (proof.event_id != previous.event_id
                    or proof.ingress_pubkey != previous.ingress_pubkey):
                raise DescriptorError("descriptor conflicts with stored checkpoint")
    _active(proof, now)
    return proof


@dataclass(frozen=True)
class RecordedDescriptorCheckpoint:
    checkpoint: DescriptorCheckpoint
    checked_at: int


class DescriptorCheckpointStore:
    """Durably retain the exact verified route, never a private key or letter.

    Every update takes a caller-supplied *complete* relay result through
    `select_descriptor` while holding a SQLite write transaction. This makes
    concurrent local clients compare against the latest committed high-water
    mark. It does not prove that a relay disclosed every published descriptor;
    `lookup_complete` remains a network caller assertion.
    """

    def __init__(self, directory, *, max_owners: int = 10_000):
        if type(max_owners) is not int or not 1 <= max_owners <= 100_000:
            raise DescriptorError("invalid route checkpoint capacity")
        self.max_owners = max_owners
        directory = Path(directory)
        _private_directory(directory)
        self.path = directory / "organization-routes.sqlite3"
        if self.path.is_symlink():
            raise DescriptorError("route checkpoint database must not be a symlink")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        if not keyfile.harden_and_check(self.path, force=True)[0]:
            raise DescriptorError("cannot protect route checkpoint database")
        self.db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('schema', '1')")
            if self.db.execute("SELECT value FROM metadata WHERE key='schema'").fetchone()[0] != "1":
                raise DescriptorError("unsupported route checkpoint schema")
            self.db.execute("""CREATE TABLE IF NOT EXISTS routes (
                owner TEXT PRIMARY KEY, generation TEXT NOT NULL,
                event_id TEXT NOT NULL, ingress TEXT NOT NULL,
                checked_at TEXT NOT NULL)""")
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            self.db.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.db.close()

    def _record(self, owner_pubkey: str) -> RecordedDescriptorCheckpoint | None:
        row = self.db.execute("SELECT * FROM routes WHERE owner=?", (owner_pubkey,)).fetchone()
        if row is None:
            return None
        try:
            generation = parse_uint(row["generation"])
            checked_at = parse_uint(row["checked_at"])
            if generation is None or generation < 1 or checked_at is None:
                raise ValueError
            checkpoint = DescriptorCheckpoint(
                row["owner"], row["event_id"], generation, row["ingress"])
        except (ValueError, TypeError) as exc:
            raise DescriptorError("invalid stored route checkpoint") from exc
        return RecordedDescriptorCheckpoint(checkpoint, checked_at)

    def get(self, owner_pubkey: str) -> RecordedDescriptorCheckpoint | None:
        if not is_canonical_pubkey(owner_pubkey):
            raise DescriptorError("invalid organization owner key")
        return self._record(owner_pubkey)

    def select_and_record(self, events: Iterable[Event], owner_pubkey: str, *,
                          now: int, max_validity_seconds: int,
                          lookup_complete: bool,
                          first_contact: FirstContactCheckpoint | None = None) -> InboxDescriptor:
        """Verify a fresh lookup and atomically advance the per-owner checkpoint.

        The first lookup needs an owner-authenticated QR floor. Later lookups
        use the exact stored event ID; a new QR floor may raise that minimum.
        This API intentionally has no cached-route send or network fallback.
        """
        _inputs(owner_pubkey, now, max_validity_seconds)
        if first_contact is not None and (
                not isinstance(first_contact, FirstContactCheckpoint)
                or first_contact.owner_pubkey != owner_pubkey):
            raise DescriptorError("first-contact checkpoint owner mismatch")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            previous = self._record(owner_pubkey)
            if previous is not None and now < previous.checked_at:
                raise DescriptorError(
                    "verification clock moved behind route checkpoint; wait for clock correction")
            if previous is None and first_contact is None:
                raise DescriptorError(
                    "no stored route checkpoint; authenticated QR checkpoint required "
                    "(first contact or lost local state)")
            proof = select_descriptor(
                events, owner_pubkey, now=now,
                max_validity_seconds=max_validity_seconds,
                lookup_complete=lookup_complete,
                first_contact=first_contact if previous is None else None,
                previous=previous.checkpoint if previous is not None else None)
            if first_contact is not None and proof.generation < first_contact.generation_floor:
                raise DescriptorError("checkpoint_outdated: descriptor below QR generation floor")
            if (previous is None and self.db.execute("SELECT COUNT(*) FROM routes").fetchone()[0]
                    >= self.max_owners):
                raise DescriptorError("route checkpoint capacity reached")
            self.db.execute("""INSERT INTO routes VALUES (?,?,?,?,?)
                ON CONFLICT(owner) DO UPDATE SET
                    generation=excluded.generation, event_id=excluded.event_id,
                    ingress=excluded.ingress, checked_at=excluded.checked_at""",
                (owner_pubkey, str(proof.generation), proof.event_id,
                 proof.ingress_pubkey, str(now)))
            self.db.execute("COMMIT")
            return proof
        except BaseException as exc:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise DescriptorError("route checkpoint database operation failed") from exc
            raise
