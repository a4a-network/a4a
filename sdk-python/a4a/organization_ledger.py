"""Offline durable identity fence for candidate organization requests.

This is NOT an ingress receiver or dispatcher. Its full-envelope path retains
encrypted transport and signed route proof and can reverify the original
against its stored request offline. It cannot issue a `received` ACK, select
a worker, or prove current authority to execute. Its metadata-only path does
not retain an envelope and must never be acknowledged as durable mail.
"""

from __future__ import annotations

import os
import json
import re
import sqlite3
from dataclasses import dataclass
from itertools import islice
from pathlib import Path

from . import giftwrap, keyfile, types
from .event import Event, is_canonical_pubkey
from .inbox import _private_directory
from .keys import Keys
from .organization_mail import OrganizationLetterError, verify_organization_letter
from .organization_assignment import (
    VerifiedAssignment,
    inspect_stored_assignment_decision,
    select_dispatch_policy,
    verify_assignment_decision,
    verify_worker_claim,
    verify_worker_completion,
)


_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class OrganizationLedgerError(RuntimeError):
    """The request identity fence did not durably complete its operation."""


class OrganizationLedgerConflict(OrganizationLedgerError):
    """An existing logical request or delivery ID has different signed data."""


def _check_outer_envelope(outer: Event, ingress_pubkey: str, now: int) -> None:
    """Validate only the encrypted transport route at a specific time."""
    if type(now) is not int or now < 0:
        raise OrganizationLedgerError("invalid envelope verification time")
    if not isinstance(outer, Event) or outer.kind != giftwrap.KIND_GIFT_WRAP or not outer.verify():
        raise OrganizationLedgerError("organization envelope is not a signed gift wrap")
    recipients = [tag for tag in outer.tags if tag and tag[0] == "p"]
    if (len(recipients) != 1 or len(recipients[0]) != 2
            or recipients[0][1] != ingress_pubkey):
        raise OrganizationLedgerError("organization envelope recipient is ambiguous")
    expirations = [tag for tag in outer.tags if tag and tag[0] == "expiration"]
    if (len(expirations) > 1
            or any(len(tag) != 2 or not isinstance(tag[1], str)
                   or re.fullmatch(r"[0-9]{1,12}", tag[1]) is None
                   for tag in expirations)
            or expirations and int(expirations[0][1]) <= now):
        raise OrganizationLedgerError("organization envelope has invalid expiration")
    if any(not tag or tag[0] not in {"p", "expiration"} for tag in outer.tags):
        raise OrganizationLedgerError("organization route metadata must not be on outer envelope")


@dataclass(frozen=True)
class LedgerResult:
    status: str  # stored or duplicate; neither means a worker executed
    seq: int
    inner_event_id: str
    envelope_retained: bool


@dataclass(frozen=True)
class AssignmentResult:
    status: str  # committed, renewed, or duplicate; never a worker delivery
    seq: int
    epoch: int
    worker_pubkey: str


@dataclass(frozen=True)
class AttemptResult:
    status: str  # acquired, duplicate, or uncertain; only acquired permits work
    seq: int
    epoch: int
    claim_event_id: str
    lease_until: int


@dataclass(frozen=True)
class CompletionResult:
    status: str  # committed, duplicate, or uncertain; never a processed ACK
    seq: int
    epoch: int


@dataclass(frozen=True, repr=False)
class RetainedOrganizationOriginal:
    """Sensitive plaintext; historical proof, not worker authority or an ACK."""
    inner: Event
    outer: Event
    descriptor: Event
    first_seen: int


@dataclass(frozen=True, repr=False)
class CurrentAssignmentEvidence:
    """Sensitive offline evidence, not a worker ticket or execution permission."""
    original: RetainedOrganizationOriginal
    policy_event: Event
    decision_event: Event
    assignment: VerifiedAssignment


class OrganizationRequestLedger:
    """One owner-scoped local SQLite fence shared by all its ingress generations.

    Distinct ingress keys on different hosts cannot share this *local* database;
    that deployment needs one transactional store before cross-key retries are
    safe. A changed signed inner event under the same request ID is a conflict,
    even if its text is identical. Never silently promote it to new work.
    """

    def __init__(self, directory, owner_pubkey: str, *, max_items: int = 10_000,
                 max_envelope_bytes: int = 64 * 1024 * 1024):
        if not is_canonical_pubkey(owner_pubkey):
            raise OrganizationLedgerError("invalid organization owner key")
        if type(max_items) is not int or not 1 <= max_items <= 100_000:
            raise OrganizationLedgerError("invalid request ledger capacity")
        if (type(max_envelope_bytes) is not int
                or not 1024 * 1024 <= max_envelope_bytes <= 1024**3):
            raise OrganizationLedgerError("invalid envelope retention capacity")
        directory = Path(directory)
        _private_directory(directory)
        self.path = directory / "organization-requests.sqlite3"
        if self.path.is_symlink():
            raise OrganizationLedgerError("request ledger database must not be a symlink")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        if not keyfile.harden_and_check(self.path, force=True)[0]:
            raise OrganizationLedgerError("cannot protect request ledger database")
        self.owner_pubkey, self.max_items = owner_pubkey, max_items
        self.max_envelope_bytes = max_envelope_bytes
        self.db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            for key, value in (("schema", "1"), ("owner", owner_pubkey)):
                self.db.execute("INSERT OR IGNORE INTO metadata VALUES (?,?)", (key, value))
                if self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()[0] != value:
                    raise OrganizationLedgerConflict("request ledger belongs to another owner or schema")
            self.db.execute("""CREATE TABLE IF NOT EXISTS requests (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL, ingress TEXT NOT NULL, sender TEXT NOT NULL,
                conversation TEXT NOT NULL, request TEXT NOT NULL,
                descriptor_id TEXT NOT NULL, inner_id TEXT NOT NULL,
                delivery_id TEXT NOT NULL, content_sha256 TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                UNIQUE(owner,sender,conversation,request),
                UNIQUE(ingress,sender,delivery_id))""")
            # Additive table: older metadata-only records remain present but
            # cannot be mistaken for durably retained original envelopes.
            self.db.execute("""CREATE TABLE IF NOT EXISTS request_envelopes (
                seq INTEGER PRIMARY KEY, outer_id TEXT NOT NULL,
                envelope TEXT NOT NULL, descriptor TEXT NOT NULL,
                FOREIGN KEY(seq) REFERENCES requests(seq))""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS dispatch_policy_checkpoint (
                owner TEXT PRIMARY KEY, generation INTEGER NOT NULL,
                event_id TEXT NOT NULL)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS dispatch_clock (
                owner TEXT PRIMARY KEY, checked_at INTEGER NOT NULL)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS conversation_assignments (
                owner TEXT NOT NULL, sender TEXT NOT NULL,
                conversation TEXT NOT NULL, epoch INTEGER NOT NULL,
                worker TEXT NOT NULL, department TEXT NOT NULL,
                policy_id TEXT NOT NULL, decision_id TEXT NOT NULL,
                PRIMARY KEY(owner,sender,conversation))""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS assignment_operations (
                operation_id TEXT PRIMARY KEY, decision_id TEXT NOT NULL,
                request_seq INTEGER NOT NULL UNIQUE,
                policy_event TEXT NOT NULL, decision_event TEXT NOT NULL,
                FOREIGN KEY(request_seq) REFERENCES requests(seq))""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS assignment_operation_history (
                operation_id TEXT PRIMARY KEY, decision_id TEXT NOT NULL,
                request_seq INTEGER NOT NULL,
                policy_event TEXT NOT NULL, decision_event TEXT NOT NULL,
                superseded_by TEXT NOT NULL, superseded_at INTEGER NOT NULL,
                FOREIGN KEY(request_seq) REFERENCES requests(seq))""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS request_execution (
                seq INTEGER PRIMARY KEY, state TEXT NOT NULL,
                epoch INTEGER NOT NULL, worker TEXT NOT NULL,
                operation_id TEXT NOT NULL, claim_event_id TEXT,
                claim_event TEXT, lease_until INTEGER,
                completion_event_id TEXT, completion_event TEXT,
                result_sha256 TEXT,
                FOREIGN KEY(seq) REFERENCES requests(seq))""")
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

    def get(self, sender_pubkey: str, conversation_id: str,
            request_id: str) -> dict | None:
        if (not is_canonical_pubkey(sender_pubkey)
                or not isinstance(conversation_id, str)
                or _HEX64.fullmatch(conversation_id) is None
                or not isinstance(request_id, str)
                or _HEX32.fullmatch(request_id) is None):
            raise OrganizationLedgerError("invalid request lookup key")
        row = self.db.execute("""SELECT r.*,
            EXISTS(SELECT 1 FROM request_envelopes e WHERE e.seq=r.seq)
                AS envelope_retained
            FROM requests r WHERE
            owner=? AND sender=? AND conversation=? AND request=?""",
            (self.owner_pubkey, sender_pubkey, conversation_id, request_id)).fetchone()
        return dict(row) if row else None

    def get_assignment(self, sender_pubkey: str, conversation_id: str) -> dict | None:
        if (not is_canonical_pubkey(sender_pubkey)
                or not is_canonical_pubkey(conversation_id)):
            raise OrganizationLedgerError("invalid conversation lookup key")
        row = self.db.execute("""SELECT * FROM conversation_assignments WHERE
            owner=? AND sender=? AND conversation=?""",
            (self.owner_pubkey, sender_pubkey, conversation_id)).fetchone()
        return dict(row) if row else None

    def get_execution(self, seq: int) -> dict | None:
        if type(seq) is not int or seq < 1:
            raise OrganizationLedgerError("invalid request sequence")
        row = self.db.execute("SELECT * FROM request_execution WHERE seq=?", (seq,)).fetchone()
        return dict(row) if row else None

    def _check_dispatch_clock(self, now: int):
        if type(now) is not int or now < 0:
            raise OrganizationLedgerError("invalid assignment verification time")
        row = self.db.execute("SELECT checked_at FROM dispatch_clock WHERE owner=?",
                              (self.owner_pubkey,)).fetchone()
        if row is not None and now < row["checked_at"]:
            raise OrganizationLedgerError(
                "verification clock moved behind dispatch checkpoint")

    def _advance_dispatch_clock(self, now: int):
        self.db.execute("""INSERT INTO dispatch_clock VALUES (?,?)
            ON CONFLICT(owner) DO UPDATE SET checked_at=excluded.checked_at""",
            (self.owner_pubkey, now))

    def claim_signed_attempt(
        self, claim: Event, policy_events, worker_mandate: Event, *, now: int,
        lease_seconds: int, max_policy_validity_seconds: int,
        policy_lookup_complete: bool, revocation_lookup_complete: bool,
        worker_revocation: Event | None = None,
    ) -> AttemptResult:
        """Fence one worker-signed attempt; an expired attempt becomes uncertain.

        This is not an envelope delivery API. Only `acquired` permits a first
        execution attempt. A `duplicate` after a crash is NOT permission to
        retry side effects: the earlier attempt's outcome may be unknown. A
        different claim cannot steal an expired lease; reconciliation is separate.
        """
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
            raise OrganizationLedgerError("invalid organization attempt lease")
        events = tuple(islice(policy_events, 101))
        verified = verify_worker_claim(
            claim, events, worker_mandate, self.owner_pubkey, now=now,
            max_policy_validity_seconds=max_policy_validity_seconds,
            policy_lookup_complete=policy_lookup_complete,
            revocation_lookup_complete=revocation_lookup_complete,
            worker_revocation=worker_revocation)
        if now + lease_seconds > verified.expiration:
            raise OrganizationLedgerError("attempt lease outlives signed worker claim")
        policy = select_dispatch_policy(
            events, self.owner_pubkey, now=now,
            max_validity_seconds=max_policy_validity_seconds,
            lookup_complete=policy_lookup_complete)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            self._check_dispatch_clock(now)
            request = self.db.execute("""SELECT r.*, x.state, x.epoch,
                x.worker, x.claim_event_id, x.lease_until,
                c.epoch AS conversation_epoch, c.worker AS conversation_worker,
                c.department, c.decision_id
                FROM requests r JOIN request_execution x ON x.seq=r.seq
                JOIN conversation_assignments c ON c.owner=r.owner
                    AND c.sender=r.sender AND c.conversation=r.conversation
                WHERE r.owner=? AND r.sender=? AND r.conversation=?
                    AND r.request=?""",
                (self.owner_pubkey, verified.sender_pubkey,
                 verified.conversation_id, verified.request_id)).fetchone()
            if (request is None or request["descriptor_id"] != verified.descriptor_id
                    or request["epoch"] != verified.epoch
                    or request["conversation_epoch"] != verified.epoch
                    or request["worker"] != verified.worker_pubkey
                    or request["conversation_worker"] != verified.worker_pubkey
                    or request["decision_id"] != verified.decision_id
                    or policy.admin_pubkey == request["ingress"]
                    or verified.worker_pubkey == request["ingress"]
                    or (request["department"], verified.worker_pubkey)
                    not in policy.workers):
                raise OrganizationLedgerConflict("worker claim does not match current assignment")
            checkpoint = self.db.execute(
                "SELECT * FROM dispatch_policy_checkpoint WHERE owner=?",
                (self.owner_pubkey,)).fetchone()
            if checkpoint is not None and (
                    policy.generation < checkpoint["generation"]
                    or policy.generation == checkpoint["generation"]
                    and policy.event_id != checkpoint["event_id"]):
                raise OrganizationLedgerConflict("dispatch policy rollback or equivocation")
            state = request["state"]
            if state == "leased" and now >= request["lease_until"]:
                self.db.execute("""UPDATE request_execution SET state='uncertain'
                    WHERE seq=?""", (request["seq"],))
                state = "uncertain"
            if state == "uncertain":
                self._advance_dispatch_clock(now)
                self.db.execute("COMMIT")
                return AttemptResult("uncertain", request["seq"], verified.epoch,
                                     request["claim_event_id"],
                                     request["lease_until"])
            if state == "leased":
                if request["claim_event_id"] != verified.event_id:
                    raise OrganizationLedgerConflict("another worker attempt already holds lease")
                self._advance_dispatch_clock(now)
                self.db.execute("COMMIT")
                return AttemptResult("duplicate", request["seq"], verified.epoch,
                                     verified.event_id, request["lease_until"])
            if state != "assigned":
                raise OrganizationLedgerConflict("request is not available for an attempt")
            if self.load_envelope(request["seq"]) is None:
                raise OrganizationLedgerError(
                    "worker claim requires retained envelope")
            self.db.execute("""UPDATE request_execution SET state='leased',
                claim_event_id=?, claim_event=?, lease_until=? WHERE seq=?""",
                (verified.event_id, claim.model_dump_json(),
                 now + lease_seconds, request["seq"]))
            self.db.execute("""INSERT INTO dispatch_policy_checkpoint VALUES (?,?,?)
                ON CONFLICT(owner) DO UPDATE SET generation=excluded.generation,
                    event_id=excluded.event_id""",
                (self.owner_pubkey, policy.generation, policy.event_id))
            self._advance_dispatch_clock(now)
            self.db.execute("COMMIT")
            return AttemptResult("acquired", request["seq"], verified.epoch,
                                 verified.event_id, now + lease_seconds)
        except BaseException as exc:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise OrganizationLedgerError("attempt database operation failed") from exc
            raise

    def expire_attempt(self, seq: int, *, now: int) -> bool:
        """Mark a timed-out attempt uncertain; never reopen it automatically."""
        if type(seq) is not int or seq < 1 or type(now) is not int or now < 0:
            raise OrganizationLedgerError("invalid attempt expiry arguments")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            self._check_dispatch_clock(now)
            exists = self.db.execute(
                "SELECT 1 FROM request_execution WHERE seq=?", (seq,)).fetchone()
            cursor = self.db.execute("""UPDATE request_execution SET state='uncertain'
                WHERE seq=? AND state='leased' AND lease_until<=?""", (seq, now))
            if exists is not None:
                self._advance_dispatch_clock(now)
            self.db.execute("COMMIT")
            return cursor.rowcount == 1
        except BaseException as exc:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise OrganizationLedgerError("attempt expiry database operation failed") from exc
            raise

    def record_signed_completion(
        self, completion: Event, policy_events, worker_mandate: Event, *,
        now: int, max_policy_validity_seconds: int,
        policy_lookup_complete: bool, revocation_lookup_complete: bool,
        worker_revocation: Event | None = None,
    ) -> CompletionResult:
        """Commit a worker's signed completion, not delivery or a processed ACK.

        The result hash is an attestation reference, NOT proof that the
        external sender received a result. An expired or uncertain attempt
        requires supervised reconciliation and cannot complete here.
        """
        events = tuple(islice(policy_events, 101))
        proof = verify_worker_completion(
            completion, worker_mandate, self.owner_pubkey, now=now,
            revocation_lookup_complete=revocation_lookup_complete,
            worker_revocation=worker_revocation)
        policy = select_dispatch_policy(
            events, self.owner_pubkey, now=now,
            max_validity_seconds=max_policy_validity_seconds,
            lookup_complete=policy_lookup_complete)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            self._check_dispatch_clock(now)
            row = self.db.execute("""SELECT r.seq, r.ingress, r.descriptor_id,
                x.*, c.epoch AS conversation_epoch,
                c.worker AS conversation_worker, c.department,
                c.decision_id FROM requests r
                JOIN request_execution x ON x.seq=r.seq
                JOIN conversation_assignments c ON c.owner=r.owner
                    AND c.sender=r.sender AND c.conversation=r.conversation
                WHERE r.owner=? AND r.sender=? AND r.conversation=?
                    AND r.request=?""",
                (self.owner_pubkey, proof.sender_pubkey,
                 proof.conversation_id, proof.request_id)).fetchone()
            if (row is None or row["descriptor_id"] != policy.descriptor_id
                    or row["epoch"] != proof.epoch
                    or row["conversation_epoch"] != proof.epoch
                    or row["worker"] != proof.worker_pubkey
                    or row["conversation_worker"] != proof.worker_pubkey
                    or row["decision_id"] != proof.decision_id
                    or row["claim_event_id"] != proof.claim_event_id
                    or policy.admin_pubkey == row["ingress"]
                    or proof.worker_pubkey == row["ingress"]
                    or (row["department"], proof.worker_pubkey)
                    not in policy.workers):
                raise OrganizationLedgerConflict(
                    "worker completion does not match current assignment")
            checkpoint = self.db.execute(
                "SELECT * FROM dispatch_policy_checkpoint WHERE owner=?",
                (self.owner_pubkey,)).fetchone()
            if checkpoint is not None and (
                    policy.generation < checkpoint["generation"]
                    or policy.generation == checkpoint["generation"]
                    and policy.event_id != checkpoint["event_id"]):
                raise OrganizationLedgerConflict("dispatch policy rollback or equivocation")
            if row["state"] == "completed":
                if row["completion_event_id"] != proof.event_id:
                    raise OrganizationLedgerConflict("different completion for terminal request")
                self._advance_dispatch_clock(now)
                self.db.execute("COMMIT")
                return CompletionResult("duplicate", row["seq"], proof.epoch)
            if row["state"] == "leased" and now >= row["lease_until"]:
                self.db.execute("""UPDATE request_execution SET state='uncertain'
                    WHERE seq=?""", (row["seq"],))
                self._advance_dispatch_clock(now)
                self.db.execute("COMMIT")
                return CompletionResult("uncertain", row["seq"], proof.epoch)
            if row["state"] == "uncertain":
                self._advance_dispatch_clock(now)
                self.db.execute("COMMIT")
                return CompletionResult("uncertain", row["seq"], proof.epoch)
            if row["state"] != "leased":
                raise OrganizationLedgerConflict("request has no active worker attempt")
            self.db.execute("""UPDATE request_execution SET state='completed',
                completion_event_id=?, completion_event=?, result_sha256=?
                WHERE seq=?""", (proof.event_id, completion.model_dump_json(),
                                  proof.result_sha256, row["seq"]))
            self.db.execute("""INSERT INTO dispatch_policy_checkpoint VALUES (?,?,?)
                ON CONFLICT(owner) DO UPDATE SET generation=excluded.generation,
                    event_id=excluded.event_id""",
                (self.owner_pubkey, policy.generation, policy.event_id))
            self._advance_dispatch_clock(now)
            self.db.execute("COMMIT")
            return CompletionResult("committed", row["seq"], proof.epoch)
        except BaseException as exc:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise OrganizationLedgerError("completion database operation failed") from exc
            raise

    def mark_attempt_uncertain(self, seq: int, claim_event_id: str) -> bool:
        """Tighten an active attempt immediately when side effects are unknown."""
        if (type(seq) is not int or seq < 1
                or not is_canonical_pubkey(claim_event_id)):
            raise OrganizationLedgerError("invalid uncertain attempt reference")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            cursor = self.db.execute("""UPDATE request_execution SET state='uncertain'
                WHERE seq=? AND state='leased' AND claim_event_id=?""",
                (seq, claim_event_id))
            self.db.execute("COMMIT")
            return cursor.rowcount == 1
        except BaseException as exc:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise OrganizationLedgerError("attempt state database operation failed") from exc
            raise

    def apply_signed_assignment(
        self, decision: Event, policy_events, descriptor_event: Event,
        worker_mandate: Event, ingress_pubkey: str, *, now: int,
        max_descriptor_validity_seconds: int, max_policy_validity_seconds: int,
        policy_lookup_complete: bool, revocation_lookup_complete: bool,
        worker_revocation: Event | None = None,
    ) -> AssignmentResult:
        """Atomically fence a signed decision against the retained original.

        This is an offline candidate. It does not deliver work, issue an ACK,
        or prove that a relay lookup was complete. For this conservative pilot,
        each request needs a fresh decision and all older work in its
        conversation must be terminal before the next epoch can commit.
        """
        events = tuple(islice(policy_events, 101))
        authority = verify_assignment_decision(
            decision, events, descriptor_event, worker_mandate,
            self.owner_pubkey, ingress_pubkey, now=now,
            max_descriptor_validity_seconds=max_descriptor_validity_seconds,
            max_policy_validity_seconds=max_policy_validity_seconds,
            policy_lookup_complete=policy_lookup_complete,
            revocation_lookup_complete=revocation_lookup_complete,
            worker_revocation=worker_revocation)
        policy = select_dispatch_policy(
            events, self.owner_pubkey, now=now,
            max_validity_seconds=max_policy_validity_seconds,
            lookup_complete=policy_lookup_complete)
        policy_event = next(event for event in events if event.id == policy.event_id)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            self._check_dispatch_clock(now)
            row = self.db.execute("""SELECT r.*,
                EXISTS(SELECT 1 FROM request_envelopes e WHERE e.seq=r.seq)
                    AS envelope_retained
                FROM requests r WHERE owner=? AND sender=? AND conversation=?
                    AND request=?""", (self.owner_pubkey, authority.sender_pubkey,
                                      authority.conversation_id,
                                      authority.request_id)).fetchone()
            if (row is None or not row["envelope_retained"]
                    or row["ingress"] != ingress_pubkey
                    or row["descriptor_id"] != authority.descriptor_id):
                raise OrganizationLedgerError(
                    "assignment requires the exact retained signed envelope")
            if self.db.execute(
                    "SELECT 1 FROM assignment_operation_history WHERE operation_id=?",
                    (authority.operation_id,)).fetchone() is not None:
                raise OrganizationLedgerConflict(
                    "assignment operation was superseded")
            existing_op = self.db.execute(
                "SELECT * FROM assignment_operations WHERE operation_id=?",
                (authority.operation_id,)).fetchone()
            if existing_op is not None:
                if (existing_op["decision_id"] != authority.decision_id
                        or existing_op["request_seq"] != row["seq"]):
                    raise OrganizationLedgerConflict(
                        "assignment operation ID reused with a different decision")
                self._advance_dispatch_clock(now)
                self.db.execute("COMMIT")
                return AssignmentResult("duplicate", row["seq"],
                                        authority.next_epoch, authority.worker_pubkey)
            checkpoint = self.db.execute(
                "SELECT * FROM dispatch_policy_checkpoint WHERE owner=?",
                (self.owner_pubkey,)).fetchone()
            if checkpoint is not None and (
                    policy.generation < checkpoint["generation"]
                    or policy.generation == checkpoint["generation"]
                    and policy.event_id != checkpoint["event_id"]):
                raise OrganizationLedgerConflict("dispatch policy rollback or equivocation")
            current = self.db.execute("""SELECT * FROM conversation_assignments
                WHERE owner=? AND sender=? AND conversation=?""",
                (self.owner_pubkey, authority.sender_pubkey,
                 authority.conversation_id)).fetchone()
            actual_epoch = current["epoch"] if current is not None else 0
            if authority.expected_epoch != actual_epoch:
                raise OrganizationLedgerConflict("stale assignment epoch")
            if current is not None and current["department"] != authority.department:
                raise OrganizationLedgerConflict(
                    "cross-department reassignment is not permitted in offline pilot")
            pending = self.db.execute("""SELECT x.seq FROM request_execution x
                JOIN requests r ON r.seq=x.seq WHERE r.owner=? AND r.sender=?
                    AND r.conversation=? AND x.state NOT IN ('completed','failed')
                LIMIT 1""", (self.owner_pubkey, authority.sender_pubkey,
                              authority.conversation_id)).fetchone()
            if pending is not None:
                raise OrganizationLedgerConflict(
                    "conversation has unfinished or uncertain work")
            if self.db.execute("SELECT 1 FROM request_execution WHERE seq=?",
                               (row["seq"],)).fetchone() is not None:
                raise OrganizationLedgerConflict("request was already assigned")
            self.db.execute("""INSERT INTO dispatch_policy_checkpoint
                VALUES (?,?,?) ON CONFLICT(owner) DO UPDATE SET
                generation=excluded.generation, event_id=excluded.event_id""",
                (self.owner_pubkey, policy.generation, policy.event_id))
            self.db.execute("""INSERT INTO conversation_assignments
                VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(owner,sender,conversation)
                DO UPDATE SET epoch=excluded.epoch, worker=excluded.worker,
                department=excluded.department, policy_id=excluded.policy_id,
                decision_id=excluded.decision_id""",
                (self.owner_pubkey, authority.sender_pubkey,
                 authority.conversation_id, authority.next_epoch,
                 authority.worker_pubkey, authority.department,
                 authority.policy_id, authority.decision_id))
            self.db.execute("INSERT INTO assignment_operations VALUES (?,?,?,?,?)",
                            (authority.operation_id, authority.decision_id,
                             row["seq"], policy_event.model_dump_json(),
                             decision.model_dump_json()))
            self.db.execute("""INSERT INTO request_execution
                (seq,state,epoch,worker,operation_id) VALUES (?,?,?,?,?)""",
                            (row["seq"], "assigned", authority.next_epoch,
                             authority.worker_pubkey, authority.operation_id))
            self._advance_dispatch_clock(now)
            self.db.execute("COMMIT")
            return AssignmentResult("committed", row["seq"],
                                    authority.next_epoch, authority.worker_pubkey)
        except BaseException as exc:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise OrganizationLedgerError("assignment database operation failed") from exc
            raise

    def renew_signed_assignment(
        self, decision: Event, policy_events, descriptor_event: Event,
        worker_mandate: Event, ingress_keys: Keys, *, now: int,
        max_descriptor_validity_seconds: int,
        max_policy_validity_seconds: int, policy_lookup_complete: bool,
        revocation_lookup_complete: bool,
        worker_revocation: Event | None = None,
    ) -> AssignmentResult:
        """Replace an expired or expiring decision before any worker claim.

        Only the same request, department, worker, and epoch may be renewed.
        The prior signed operation remains in an append-only audit table. A
        newer signed decision is mandatory; neither work nor ACK is delivered.
        """
        if not isinstance(ingress_keys, Keys):
            raise OrganizationLedgerError("renewal requires physical ingress key")
        events = tuple(islice(policy_events, 101))
        authority = verify_assignment_decision(
            decision, events, descriptor_event, worker_mandate,
            self.owner_pubkey, ingress_keys.pubkey_hex, now=now,
            max_descriptor_validity_seconds=max_descriptor_validity_seconds,
            max_policy_validity_seconds=max_policy_validity_seconds,
            policy_lookup_complete=policy_lookup_complete,
            revocation_lookup_complete=revocation_lookup_complete,
            worker_revocation=worker_revocation)
        policy = select_dispatch_policy(
            events, self.owner_pubkey, now=now,
            max_validity_seconds=max_policy_validity_seconds,
            lookup_complete=policy_lookup_complete)
        policy_event = next(event for event in events if event.id == policy.event_id)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            self._check_dispatch_clock(now)
            request = self.db.execute("""SELECT * FROM requests WHERE
                owner=? AND sender=? AND conversation=? AND request=?""",
                (self.owner_pubkey, authority.sender_pubkey,
                 authority.conversation_id, authority.request_id)).fetchone()
            if request is None:
                raise OrganizationLedgerConflict("renewal lacks assigned request")
            original = self.load_verified_original(
                request["seq"], ingress_keys,
                max_validity_seconds=max_descriptor_validity_seconds)
            if original is None or original.descriptor.id != authority.descriptor_id:
                raise OrganizationLedgerError("renewal requires exact retained original")
            execution = self.db.execute(
                "SELECT * FROM request_execution WHERE seq=?",
                (request["seq"],)).fetchone()
            conversation = self.db.execute("""SELECT * FROM conversation_assignments
                WHERE owner=? AND sender=? AND conversation=?""",
                (request["owner"], request["sender"],
                 request["conversation"])).fetchone()
            if (execution is None or conversation is None
                    or execution["state"] != "assigned"
                    or any(execution[column] is not None for column in (
                        "claim_event_id", "claim_event", "lease_until",
                        "completion_event_id", "completion_event",
                        "result_sha256"))):
                raise OrganizationLedgerConflict(
                    "renewal requires an unclaimed current assignment")
            operation = self.db.execute(
                "SELECT * FROM assignment_operations WHERE operation_id=?",
                (execution["operation_id"],)).fetchone()
            checkpoint = self.db.execute(
                "SELECT * FROM dispatch_policy_checkpoint WHERE owner=?",
                (self.owner_pubkey,)).fetchone()
            if operation is None or checkpoint is None:
                raise OrganizationLedgerError("renewal lacks stored assignment evidence")
            try:
                old_policy = Event(**json.loads(operation["policy_event"]))
                old_decision = Event(**json.loads(operation["decision_event"]))
            except (ValueError, TypeError, KeyError) as exc:
                raise OrganizationLedgerError(
                    "renewal has malformed stored assignment evidence") from exc
            prior = inspect_stored_assignment_decision(
                old_decision, old_policy, original.descriptor,
                self.owner_pubkey, ingress_keys.pubkey_hex, now=now,
                max_descriptor_validity_seconds=max_descriptor_validity_seconds,
                max_policy_validity_seconds=max_policy_validity_seconds)
            if (operation["request_seq"] != request["seq"]
                    or operation["decision_id"] != prior.decision_id
                    or operation["operation_id"] != prior.operation_id
                    or (request["owner"], request["ingress"], request["sender"],
                        request["conversation"], request["request"],
                        request["descriptor_id"]) != (
                        prior.owner_pubkey, prior.ingress_pubkey,
                        prior.sender_pubkey, prior.conversation_id,
                        prior.request_id, prior.descriptor_id)
                    or (execution["epoch"], execution["worker"],
                        execution["operation_id"]) != (
                        prior.next_epoch, prior.worker_pubkey,
                        prior.operation_id)
                    or (conversation["epoch"], conversation["worker"],
                        conversation["department"], conversation["policy_id"],
                        conversation["decision_id"]) != (
                        prior.next_epoch, prior.worker_pubkey,
                        prior.department, prior.policy_id, prior.decision_id)):
                raise OrganizationLedgerError(
                    "renewal stored assignment does not match ledger")
            if (authority.owner_pubkey, authority.ingress_pubkey,
                    authority.descriptor_id, authority.sender_pubkey,
                    authority.conversation_id, authority.request_id,
                    authority.department, authority.worker_pubkey,
                    authority.expected_epoch, authority.next_epoch) != (
                    prior.owner_pubkey, prior.ingress_pubkey,
                    prior.descriptor_id, prior.sender_pubkey,
                    prior.conversation_id, prior.request_id,
                    prior.department, prior.worker_pubkey,
                    prior.expected_epoch, prior.next_epoch):
                raise OrganizationLedgerConflict("renewal changes assignment scope")
            if (policy.generation < checkpoint["generation"]
                    or policy.generation == checkpoint["generation"]
                    and policy.event_id != checkpoint["event_id"]):
                raise OrganizationLedgerConflict(
                    "renewal dispatch policy rollback or equivocation")
            if authority.operation_id == prior.operation_id:
                if authority.decision_id != prior.decision_id:
                    raise OrganizationLedgerConflict(
                        "renewal reuses assignment operation ID")
                self._advance_dispatch_clock(now)
                self.db.execute("COMMIT")
                return AssignmentResult("duplicate", request["seq"],
                                        prior.next_epoch, prior.worker_pubkey)
            if decision.created_at <= old_decision.created_at:
                raise OrganizationLedgerConflict(
                    "renewal requires a newer signed decision")
            if self.db.execute("""SELECT 1 FROM assignment_operation_history
                WHERE operation_id=?""", (authority.operation_id,)).fetchone() is not None:
                raise OrganizationLedgerConflict(
                    "renewal reuses superseded operation ID")
            if self.db.execute("""SELECT 1 FROM assignment_operations
                WHERE operation_id=?""", (authority.operation_id,)).fetchone() is not None:
                raise OrganizationLedgerConflict(
                    "renewal operation ID belongs to another request")
            self.db.execute("""INSERT INTO assignment_operation_history
                VALUES (?,?,?,?,?,?,?)""",
                (prior.operation_id, prior.decision_id, request["seq"],
                 operation["policy_event"], operation["decision_event"],
                 authority.operation_id, now))
            self.db.execute("""UPDATE assignment_operations SET
                operation_id=?, decision_id=?, policy_event=?, decision_event=?
                WHERE operation_id=? AND request_seq=?""",
                (authority.operation_id, authority.decision_id,
                 policy_event.model_dump_json(), decision.model_dump_json(),
                 prior.operation_id, request["seq"]))
            self.db.execute("UPDATE request_execution SET operation_id=? WHERE seq=?",
                            (authority.operation_id, request["seq"]))
            self.db.execute("""UPDATE conversation_assignments SET
                policy_id=?, decision_id=? WHERE owner=? AND sender=?
                AND conversation=?""",
                (authority.policy_id, authority.decision_id,
                 request["owner"], request["sender"],
                 request["conversation"]))
            self.db.execute("""INSERT INTO dispatch_policy_checkpoint VALUES (?,?,?)
                ON CONFLICT(owner) DO UPDATE SET generation=excluded.generation,
                    event_id=excluded.event_id""",
                (self.owner_pubkey, policy.generation, policy.event_id))
            self._advance_dispatch_clock(now)
            self.db.execute("COMMIT")
            return AssignmentResult("renewed", request["seq"],
                                    authority.next_epoch, authority.worker_pubkey)
        except BaseException as exc:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise OrganizationLedgerError("renewal database operation failed") from exc
            raise

    def _retained_row(self, seq: int):
        if type(seq) is not int or seq < 1:
            raise OrganizationLedgerError("invalid request sequence")
        return self.db.execute("""SELECT r.*, e.outer_id, e.envelope, e.descriptor
            FROM requests r LEFT JOIN request_envelopes e ON e.seq=r.seq
            WHERE r.seq=? AND r.owner=?""", (seq, self.owner_pubkey)).fetchone()

    def _decode_retained_row(self, row) -> tuple[Event, Event]:
        try:
            outer = Event(**json.loads(row["envelope"]))
            descriptor = Event(**json.loads(row["descriptor"]))
        except (ValueError, TypeError, KeyError) as exc:
            raise OrganizationLedgerError("retained envelope is malformed") from exc
        if (outer.kind != giftwrap.KIND_GIFT_WRAP or not outer.verify()
                or outer.id != row["outer_id"]
                or not descriptor.verify()
                or descriptor.pubkey != self.owner_pubkey
                or descriptor.id != row["descriptor_id"]):
            raise OrganizationLedgerError("retained envelope or route proof failed verification")
        return outer, descriptor

    def load_envelope(self, seq: int) -> tuple[Event, Event] | None:
        """Recover encrypted original and signed route proof, never plaintext.

        This is not an ACK or worker-delivery API. Its caller must hold the
        correct ingress key and revalidate the proof at use time.
        """
        row = self._retained_row(seq)
        return (self._decode_retained_row(row)
                if row is not None and row["envelope"] is not None else None)

    def load_verified_original(self, seq: int, ingress_keys: Keys, *,
                               max_validity_seconds: int) -> RetainedOrganizationOriginal | None:
        """Reopen and bind the original to its stored request at admission time.

        This historical check does not establish a current worker mandate,
        assignment ticket, admission permission, or any ACK. Descriptor expiry
        after the original admission does not erase previously retained work.
        The returned inner event contains plaintext and must not be logged.
        """
        row = self._retained_row(seq)
        if row is None or row["envelope"] is None:
            return None
        if not isinstance(ingress_keys, Keys) or ingress_keys.pubkey_hex != row["ingress"]:
            raise OrganizationLedgerError("retained original requires matching ingress key")
        if (not isinstance(row["first_seen"], str)
                or re.fullmatch(r"(0|[1-9][0-9]*)", row["first_seen"]) is None):
            raise OrganizationLedgerError("invalid retained admission time")
        first_seen = int(row["first_seen"])
        outer, descriptor = self._decode_retained_row(row)
        _check_outer_envelope(outer, ingress_keys.pubkey_hex, first_seen)
        try:
            inner = giftwrap.unwrap(outer, ingress_keys)
        except giftwrap.GiftWrapError as exc:
            raise OrganizationLedgerError("retained original could not be decrypted") from exc
        try:
            letter = verify_organization_letter(
                inner, descriptor, self.owner_pubkey, ingress_keys.pubkey_hex,
                now=first_seen, max_validity_seconds=max_validity_seconds)
        except OrganizationLetterError as exc:
            raise OrganizationLedgerError("invalid historical route proof") from exc
        if (letter.owner_pubkey, letter.ingress_pubkey, letter.sender_pubkey,
                letter.conversation_id, letter.request_id, letter.descriptor_id,
                letter.inner_event_id, letter.delivery_id, letter.content_sha256) != (
                row["owner"], row["ingress"], row["sender"], row["conversation"],
                row["request"], row["descriptor_id"], row["inner_id"],
                row["delivery_id"], row["content_sha256"]):
            raise OrganizationLedgerError("retained original does not match stored request")
        return RetainedOrganizationOriginal(inner, outer, descriptor, first_seen)

    def load_current_assignment_evidence(
        self, seq: int, ingress_keys: Keys, policy_events,
        worker_mandate: Event, *, now: int,
        max_descriptor_validity_seconds: int,
        max_policy_validity_seconds: int, policy_lookup_complete: bool,
        revocation_lookup_complete: bool,
        worker_revocation: Event | None = None,
    ) -> CurrentAssignmentEvidence | None:
        """Recheck one unclaimed assignment and its signed original atomically.

        This read-only local snapshot is not a delivery, ACK, ticket, or lease.
        A later worker claim must recheck current authority and fence its own
        epoch. Expired decisions or mandates fail closed even for retained mail.
        The returned original contains plaintext and must not be logged.
        """
        events = tuple(islice(policy_events, 101))
        try:
            self.db.execute("BEGIN")
            self._check_dispatch_clock(now)
            request = self._retained_row(seq)
            if request is None:
                self.db.execute("COMMIT")
                return None
            execution = self.db.execute(
                "SELECT * FROM request_execution WHERE seq=?", (seq,)).fetchone()
            if execution is None:
                self.db.execute("COMMIT")
                return None
            if (execution["state"] != "assigned"
                    or execution["claim_event_id"] is not None
                    or execution["claim_event"] is not None
                    or execution["lease_until"] is not None
                    or execution["completion_event_id"] is not None
                    or execution["completion_event"] is not None
                    or execution["result_sha256"] is not None):
                raise OrganizationLedgerError(
                    "assignment evidence requires an unclaimed request")
            original = self.load_verified_original(
                seq, ingress_keys,
                max_validity_seconds=max_descriptor_validity_seconds)
            if original is None:
                raise OrganizationLedgerError("assignment evidence lacks signed original")
            operation = self.db.execute(
                "SELECT * FROM assignment_operations WHERE operation_id=?",
                (execution["operation_id"],)).fetchone()
            conversation = self.db.execute("""SELECT * FROM conversation_assignments
                WHERE owner=? AND sender=? AND conversation=?""",
                (request["owner"], request["sender"],
                 request["conversation"])).fetchone()
            checkpoint = self.db.execute(
                "SELECT * FROM dispatch_policy_checkpoint WHERE owner=?",
                (self.owner_pubkey,)).fetchone()
            if operation is None or conversation is None or checkpoint is None:
                raise OrganizationLedgerError("assignment evidence is incomplete")
            try:
                policy_event = Event(**json.loads(operation["policy_event"]))
                decision_event = Event(**json.loads(operation["decision_event"]))
            except (ValueError, TypeError, KeyError) as exc:
                raise OrganizationLedgerError(
                    "assignment evidence contains malformed signed events") from exc
            if not policy_event.verify():
                raise OrganizationLedgerError("assignment evidence has invalid signed policy")
            assignment = verify_assignment_decision(
                decision_event, events, original.descriptor, worker_mandate,
                self.owner_pubkey, ingress_keys.pubkey_hex, now=now,
                max_descriptor_validity_seconds=max_descriptor_validity_seconds,
                max_policy_validity_seconds=max_policy_validity_seconds,
                policy_lookup_complete=policy_lookup_complete,
                revocation_lookup_complete=revocation_lookup_complete,
                worker_revocation=worker_revocation)
            if (operation["request_seq"] != seq
                    or operation["decision_id"] != assignment.decision_id
                    or operation["operation_id"] != assignment.operation_id
                    or policy_event.id != assignment.policy_id
                    or (request["owner"], request["ingress"], request["sender"],
                        request["conversation"], request["request"],
                        request["descriptor_id"]) != (
                        assignment.owner_pubkey, assignment.ingress_pubkey,
                        assignment.sender_pubkey, assignment.conversation_id,
                        assignment.request_id, assignment.descriptor_id)
                    or (execution["epoch"], execution["worker"],
                        execution["operation_id"]) != (
                        assignment.next_epoch, assignment.worker_pubkey,
                        assignment.operation_id)
                    or (conversation["epoch"], conversation["worker"],
                        conversation["department"], conversation["policy_id"],
                        conversation["decision_id"]) != (
                        assignment.next_epoch, assignment.worker_pubkey,
                        assignment.department, assignment.policy_id,
                        assignment.decision_id)
                    or (checkpoint["generation"], checkpoint["event_id"]) != (
                        assignment.policy_generation, assignment.policy_id)):
                raise OrganizationLedgerError("assignment evidence does not match ledger")
            evidence = CurrentAssignmentEvidence(
                original, policy_event, decision_event, assignment)
            self.db.execute("COMMIT")
            return evidence
        except BaseException as exc:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise OrganizationLedgerError(
                    "assignment evidence database operation failed") from exc
            raise

    def admit_inner(self, inner: Event, descriptor_event: Event,
                    ingress_pubkey: str, *, now: int,
                    max_validity_seconds: int) -> LedgerResult:
        """Fence one signed inner request; does not authenticate its outer wrap.

        Rewrapping the *same* signed inner event is idempotent. A newly signed
        letter with the same logical request ID is ambiguous—even across
        ingress rotation—and must be reconciled, not executed automatically.
        """
        letter = verify_organization_letter(
            inner, descriptor_event, self.owner_pubkey, ingress_pubkey,
            now=now, max_validity_seconds=max_validity_seconds)
        return self._admit_verified(letter, now, envelope_data=None)

    def admit_envelope(self, outer: Event, descriptor_event: Event,
                       ingress_keys: Keys, *, now: int,
                       max_validity_seconds: int) -> LedgerResult:
        """Verify and retain one encrypted gift wrap and route proof atomically.

        This path still does not authorize a network ACK: admission policy,
        current mandates, assignment authority, and a crash-safe ACK outbox
        belong to later gates. The metadata-only path remains non-ACKable.
        """
        if not isinstance(ingress_keys, Keys):
            raise OrganizationLedgerError("actual ingress keys are required")
        _check_outer_envelope(outer, ingress_keys.pubkey_hex, now)
        try:
            envelope_json = outer.model_dump_json()
            if len(envelope_json.encode("utf-8")) > 256 * 1024:
                raise OrganizationLedgerError("organization envelope exceeds size limit")
            inner = giftwrap.unwrap(outer, ingress_keys)
        except (UnicodeError, giftwrap.GiftWrapError) as exc:
            raise OrganizationLedgerError("organization envelope could not be opened") from exc
        letter = verify_organization_letter(
            inner, descriptor_event, self.owner_pubkey, ingress_keys.pubkey_hex,
            now=now, max_validity_seconds=max_validity_seconds)
        descriptor_json = descriptor_event.model_dump_json()
        if len(descriptor_json.encode("utf-8")) > 16 * 1024:
            raise OrganizationLedgerError("organization route proof exceeds size limit")
        return self._admit_verified(
            letter, now, envelope_data=(outer.id, envelope_json, descriptor_json))

    def _retain(self, seq: int, envelope_data: tuple[str, str, str]):
        outer_id, envelope_json, descriptor_json = envelope_data
        used = self.db.execute("""SELECT COALESCE(SUM(
            length(CAST(envelope AS BLOB)) + length(CAST(descriptor AS BLOB))), 0)
            FROM request_envelopes""").fetchone()[0]
        added = len(envelope_json.encode("utf-8")) + len(descriptor_json.encode("utf-8"))
        if used + added > self.max_envelope_bytes:
            raise OrganizationLedgerError("encrypted envelope retention capacity reached")
        self.db.execute("INSERT INTO request_envelopes VALUES (?,?,?,?)",
                        (seq, outer_id, envelope_json, descriptor_json))

    def _admit_verified(self, letter, now: int,
                        envelope_data: tuple[str, str, str] | None) -> LedgerResult:
        key = (self.owner_pubkey, letter.sender_pubkey,
               letter.conversation_id, letter.request_id)
        immutable = (letter.ingress_pubkey, letter.descriptor_id,
                     letter.inner_event_id, letter.delivery_id,
                     letter.content_sha256)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("""SELECT * FROM requests WHERE
                owner=? AND sender=? AND conversation=? AND request=?""", key).fetchone()
            if row is not None:
                existing = (row["ingress"], row["descriptor_id"], row["inner_id"],
                            row["delivery_id"], row["content_sha256"])
                if existing != immutable:
                    raise OrganizationLedgerConflict(
                        "logical request ID reused with different signed letter")
                retained = self.db.execute(
                    "SELECT 1 FROM request_envelopes WHERE seq=?", (row["seq"],)).fetchone()
                status = "duplicate"
                if retained is None and envelope_data is not None:
                    self._retain(row["seq"], envelope_data)
                    status = "envelope_added"
                    retained = True
                self.db.execute("COMMIT")
                return LedgerResult(status, row["seq"], row["inner_id"], bool(retained))
            reused = self.db.execute("""SELECT 1 FROM requests WHERE
                ingress=? AND sender=? AND delivery_id=?""",
                (letter.ingress_pubkey, letter.sender_pubkey,
                 letter.delivery_id)).fetchone()
            if reused:
                raise OrganizationLedgerConflict("delivery ID reused for another request")
            if self.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0] >= self.max_items:
                raise OrganizationLedgerError("request ledger capacity reached")
            cursor = self.db.execute("""INSERT INTO requests (
                owner,ingress,sender,conversation,request,descriptor_id,
                inner_id,delivery_id,content_sha256,first_seen)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (*key[:1], letter.ingress_pubkey, *key[1:],
                 letter.descriptor_id, letter.inner_event_id,
                 letter.delivery_id, letter.content_sha256, str(now)))
            if envelope_data is not None:
                self._retain(cursor.lastrowid, envelope_data)
            self.db.execute("COMMIT")
            return LedgerResult("stored", cursor.lastrowid, letter.inner_event_id,
                                envelope_data is not None)
        except BaseException as exc:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(exc, sqlite3.Error):
                raise OrganizationLedgerError("request ledger database operation failed") from exc
            raise
