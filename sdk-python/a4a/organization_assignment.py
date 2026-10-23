"""Offline verifier for provisional organization dispatch authority.

Kind 31009 and these tags are NOT allocated wire protocol. No relay lookup,
publication, worker handoff, or ACK path calls this module yet. A future
network caller must establish complete policy/mandate/revocation lookups; the
boolean assertions here cannot prove that a relay was honest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .delegation import is_revocation_valid, validate_sender_mandate
from .event import Event, is_canonical_pubkey, parse_uint
from .organization_inbox import DescriptorError, verify_descriptor


_POLICY_KIND = 31009
_POLICY_SINGLE = frozenset({"d", "a4a_descriptor", "generation", "not_before",
                            "expiration", "admin", "triage"})
_DECISION_TAGS = frozenset({
    "p", "a4a_owner", "a4a_descriptor", "a4a_policy", "a4a_sender",
    "a4a_conversation", "a4a_request", "a4a_department", "a4a_worker",
    "a4a_expected_epoch", "a4a_next_epoch", "a4a_operation", "expiration",
})
_DEPARTMENT = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_MAX_POLICY_EVENTS = 100
_MAX_WORKERS = 32
_MAX_DECISION_SECONDS = 600
_MAX_SQLITE_INT = 2**63 - 1
_CLAIM_TAGS = frozenset({
    "a4a_owner", "a4a_sender", "a4a_conversation", "a4a_request",
    "a4a_decision", "a4a_epoch", "a4a_claim", "expiration",
})
_COMPLETION_TAGS = frozenset({
    "a4a_owner", "a4a_sender", "a4a_conversation", "a4a_request",
    "a4a_decision", "a4a_epoch", "a4a_claim_event",
    "a4a_result_sha256", "expiration",
})


class AssignmentAuthorityError(ValueError):
    """A proposed assignment lacks an unambiguous current signed authority."""


@dataclass(frozen=True)
class DispatchPolicy:
    owner_pubkey: str
    descriptor_id: str
    event_id: str
    generation: int
    not_before: int
    expiration: int
    admin_pubkey: str
    triage_department: str
    workers: frozenset[tuple[str, str]]  # (department, worker pubkey)


@dataclass(frozen=True)
class VerifiedAssignment:
    owner_pubkey: str
    ingress_pubkey: str
    descriptor_id: str
    policy_id: str
    policy_generation: int
    decision_id: str
    operation_id: str
    sender_pubkey: str
    conversation_id: str
    request_id: str
    department: str
    worker_pubkey: str
    expected_epoch: int
    next_epoch: int


@dataclass(frozen=True)
class VerifiedClaim:
    event_id: str
    owner_pubkey: str
    sender_pubkey: str
    conversation_id: str
    request_id: str
    decision_id: str
    epoch: int
    worker_pubkey: str
    policy_id: str
    policy_generation: int
    descriptor_id: str
    expiration: int


@dataclass(frozen=True)
class VerifiedCompletion:
    event_id: str
    owner_pubkey: str
    sender_pubkey: str
    conversation_id: str
    request_id: str
    decision_id: str
    epoch: int
    worker_pubkey: str
    claim_event_id: str
    result_sha256: str
    expiration: int


def _tag_map(event: Event, allowed: frozenset[str]) -> dict[str, str]:
    tags = {}
    for tag in event.tags:
        if (len(tag) != 2 or tag[0] not in allowed or tag[0] in tags
                or not isinstance(tag[1], str)):
            raise AssignmentAuthorityError("ambiguous or unknown dispatch tag")
        tags[tag[0]] = tag[1]
    if tags.keys() != allowed:
        raise AssignmentAuthorityError("incomplete dispatch tags")
    return tags


def _parse_policy(event: Event, owner_pubkey: str, *,
                  max_validity_seconds: int) -> DispatchPolicy:
    if (not isinstance(event, Event) or event.kind != _POLICY_KIND
            or event.pubkey != owner_pubkey or not event.verify()
            or event.content != "" or event.created_at < 0):
        raise AssignmentAuthorityError("invalid owner-signed dispatch policy")
    singles: dict[str, str] = {}
    workers: set[tuple[str, str]] = set()
    for tag in event.tags:
        if len(tag) == 3 and tag[0] == "worker":
            department, worker = tag[1:]
            if (not isinstance(department, str) or _DEPARTMENT.fullmatch(department) is None
                    or not isinstance(worker, str) or not is_canonical_pubkey(worker)
                    or (department, worker) in workers):
                raise AssignmentAuthorityError("invalid or duplicate dispatch worker")
            workers.add((department, worker))
            if len(workers) > _MAX_WORKERS:
                raise AssignmentAuthorityError("dispatch worker allowlist exceeds limit")
        elif (len(tag) == 2 and tag[0] in _POLICY_SINGLE
              and tag[0] not in singles and isinstance(tag[1], str)):
            singles[tag[0]] = tag[1]
        else:
            raise AssignmentAuthorityError("ambiguous or unknown dispatch policy tag")
    if singles.keys() != _POLICY_SINGLE or not workers:
        raise AssignmentAuthorityError("incomplete dispatch policy")
    generation = parse_uint(singles["generation"])
    not_before = parse_uint(singles["not_before"])
    expiration = parse_uint(singles["expiration"])
    if (generation is None or not 1 <= generation <= _MAX_SQLITE_INT
            or singles["d"] != f"dispatch:{generation}"
            or not_before is None or expiration is None
            or not event.created_at <= not_before < expiration
            or expiration - not_before > max_validity_seconds):
        raise AssignmentAuthorityError("invalid dispatch policy generation or validity")
    descriptor_id = singles["a4a_descriptor"]
    admin = singles["admin"]
    triage = singles["triage"]
    if (not is_canonical_pubkey(descriptor_id)
            or not is_canonical_pubkey(admin) or admin == owner_pubkey
            or _DEPARTMENT.fullmatch(triage) is None
            or not any(department == triage for department, _ in workers)
            or any(worker in (owner_pubkey, admin) for _, worker in workers)):
        raise AssignmentAuthorityError("invalid dispatch policy scope")
    return DispatchPolicy(owner_pubkey, descriptor_id, event.id, generation,
                          not_before, expiration, admin, triage, frozenset(workers))


def select_dispatch_policy(events: Iterable[Event], owner_pubkey: str, *,
                           now: int, max_validity_seconds: int,
                           lookup_complete: bool) -> DispatchPolicy:
    """Select the highest effective generation; equivocation fails closed."""
    if (not is_canonical_pubkey(owner_pubkey) or type(now) is not int
            or not 0 <= now <= _MAX_SQLITE_INT - _MAX_DECISION_SECONDS
            or type(max_validity_seconds) is not int or max_validity_seconds < 1
            or lookup_complete is not True):
        raise AssignmentAuthorityError("invalid or incomplete policy lookup")
    parsed = []
    for event in events:
        if len(parsed) >= _MAX_POLICY_EVENTS:
            raise AssignmentAuthorityError("policy lookup exceeds limit")
        parsed.append(_parse_policy(event, owner_pubkey,
                                    max_validity_seconds=max_validity_seconds))
    effective = [policy for policy in parsed if policy.not_before <= now]
    if not effective:
        raise AssignmentAuthorityError("no effective dispatch policy")
    highest = max(policy.generation for policy in effective)
    newest = {policy.event_id: policy for policy in effective
              if policy.generation == highest}
    if len(newest) != 1:
        raise AssignmentAuthorityError("conflicting dispatch policies at one generation")
    policy = next(iter(newest.values()))
    if now >= policy.expiration:
        raise AssignmentAuthorityError("current dispatch policy expired")
    return policy


def _parse_assignment_decision(decision: Event, policy: DispatchPolicy,
                               descriptor, ingress_pubkey: str, *,
                               now: int | None) -> VerifiedAssignment:
    """Verify signed decision grammar; `now=None` omits only live expiry."""
    if (not isinstance(decision, Event) or decision.kind != 14
            or decision.pubkey != policy.admin_pubkey or not decision.verify()
            or decision.content != "" or type(decision.created_at) is not int
            or decision.created_at < 0
            or now is not None and decision.created_at > now):
        raise AssignmentAuthorityError("invalid administrator-signed decision")
    tags = _tag_map(decision, _DECISION_TAGS)
    expiration = parse_uint(tags["expiration"])
    if (expiration is None or expiration <= decision.created_at
            or now is not None and not now < expiration
            or expiration - decision.created_at > _MAX_DECISION_SECONDS):
        raise AssignmentAuthorityError("assignment decision expired or too long-lived")
    if (tags["p"] != ingress_pubkey or tags["a4a_owner"] != policy.owner_pubkey
            or tags["a4a_descriptor"] != descriptor.event_id
            or tags["a4a_policy"] != policy.event_id):
        raise AssignmentAuthorityError("assignment decision route binding mismatch")
    sender, conversation, request = (tags["a4a_sender"],
                                     tags["a4a_conversation"], tags["a4a_request"])
    if (not is_canonical_pubkey(sender) or not is_canonical_pubkey(conversation)
            or _HEX32.fullmatch(request) is None
            or _HEX32.fullmatch(tags["a4a_operation"]) is None):
        raise AssignmentAuthorityError("noncanonical assignment identity")
    department, worker = tags["a4a_department"], tags["a4a_worker"]
    if (department, worker) not in policy.workers:
        raise AssignmentAuthorityError("worker is outside the signed department scope")
    expected = parse_uint(tags["a4a_expected_epoch"])
    next_epoch = parse_uint(tags["a4a_next_epoch"])
    if (expected is None or next_epoch is None
            or next_epoch > _MAX_SQLITE_INT or next_epoch != expected + 1):
        raise AssignmentAuthorityError("assignment epoch is not monotonic")
    return VerifiedAssignment(
        policy.owner_pubkey, ingress_pubkey, descriptor.event_id, policy.event_id,
        policy.generation, decision.id, tags["a4a_operation"], sender,
        conversation, request, department, worker, expected, next_epoch)


def inspect_stored_assignment_decision(
    decision: Event, policy_event: Event, descriptor_event: Event,
    owner_pubkey: str, ingress_pubkey: str, *, now: int,
    max_descriptor_validity_seconds: int,
    max_policy_validity_seconds: int,
) -> VerifiedAssignment:
    """Check old signed scope and grammar, not historic relay or mandate state.

    Used only to authenticate a stored decision before replacing an unclaimed
    assignment. Its expired decision is not authority for new execution.
    """
    try:
        descriptor = verify_descriptor(
            descriptor_event, owner_pubkey, now=now,
            max_validity_seconds=max_descriptor_validity_seconds)
    except DescriptorError as exc:
        raise AssignmentAuthorityError("invalid assignment route proof") from exc
    if descriptor.ingress_pubkey != ingress_pubkey:
        raise AssignmentAuthorityError("assignment ingress does not match route proof")
    policy = _parse_policy(
        policy_event, owner_pubkey,
        max_validity_seconds=max_policy_validity_seconds)
    if (policy.descriptor_id != descriptor.event_id
            or policy.admin_pubkey == ingress_pubkey
            or any(worker == ingress_pubkey for _, worker in policy.workers)):
        raise AssignmentAuthorityError("dispatch policy is not separate from ingress")
    return _parse_assignment_decision(
        decision, policy, descriptor, ingress_pubkey, now=None)


def verify_assignment_decision(
    decision: Event, policy_events: Iterable[Event], descriptor_event: Event,
    worker_mandate: Event, owner_pubkey: str, ingress_pubkey: str, *,
    now: int, max_descriptor_validity_seconds: int,
    max_policy_validity_seconds: int, policy_lookup_complete: bool,
    revocation_lookup_complete: bool, worker_revocation: Event | None = None,
) -> VerifiedAssignment:
    """Check one provisional private admin decision against current owner scope.

    Lookup-completeness flags are obligations of the eventual network caller,
    not proof generated here. Do not use this offline verdict for live routing.
    """
    if revocation_lookup_complete is not True:
        raise AssignmentAuthorityError("incomplete worker revocation lookup")
    try:
        descriptor = verify_descriptor(
            descriptor_event, owner_pubkey, now=now,
            max_validity_seconds=max_descriptor_validity_seconds)
    except DescriptorError as exc:
        raise AssignmentAuthorityError("invalid assignment route proof") from exc
    if descriptor.ingress_pubkey != ingress_pubkey:
        raise AssignmentAuthorityError("assignment ingress does not match route proof")
    policy = select_dispatch_policy(
        policy_events, owner_pubkey, now=now,
        max_validity_seconds=max_policy_validity_seconds,
        lookup_complete=policy_lookup_complete)
    if (policy.descriptor_id != descriptor.event_id
            or policy.admin_pubkey == ingress_pubkey
            or any(worker == ingress_pubkey for _, worker in policy.workers)):
        raise AssignmentAuthorityError("dispatch policy is not separate from ingress")
    assignment = _parse_assignment_decision(
        decision, policy, descriptor, ingress_pubkey, now=now)
    if (not isinstance(worker_mandate, Event)
            or worker_mandate.pubkey != owner_pubkey
            or worker_revocation is not None and not is_revocation_valid(
                worker_revocation, worker_mandate)
            or not validate_sender_mandate(
                assignment.worker_pubkey, worker_mandate, now=now,
                revocation=worker_revocation,
                require_started=True)):
        raise AssignmentAuthorityError("worker lacks a current owner mandate")
    return assignment


def verify_worker_claim(
    claim: Event, policy_events: Iterable[Event], worker_mandate: Event,
    owner_pubkey: str, *, now: int, max_policy_validity_seconds: int,
    policy_lookup_complete: bool, revocation_lookup_complete: bool,
    worker_revocation: Event | None = None,
) -> VerifiedClaim:
    """Verify a worker-signed attempt claim; the ledger still fences its epoch.

    The claim alone grants no envelope access. Its current department scope and
    exact decision binding are checked against the ledger transactionally.
    """
    if revocation_lookup_complete is not True:
        raise AssignmentAuthorityError("incomplete worker revocation lookup")
    policy = select_dispatch_policy(
        policy_events, owner_pubkey, now=now,
        max_validity_seconds=max_policy_validity_seconds,
        lookup_complete=policy_lookup_complete)
    if (not isinstance(claim, Event) or claim.kind != 14 or not claim.verify()
            or claim.content != "" or claim.created_at > now):
        raise AssignmentAuthorityError("invalid signed worker claim")
    tags = _tag_map(claim, _CLAIM_TAGS)
    expiration = parse_uint(tags["expiration"])
    epoch = parse_uint(tags["a4a_epoch"])
    if (expiration is None or not now < expiration
            or expiration - claim.created_at > _MAX_DECISION_SECONDS
            or epoch is None or not 1 <= epoch <= _MAX_SQLITE_INT):
        raise AssignmentAuthorityError("worker claim has invalid epoch or validity")
    if (tags["a4a_owner"] != owner_pubkey
            or not is_canonical_pubkey(tags["a4a_sender"])
            or not is_canonical_pubkey(tags["a4a_conversation"])
            or _HEX32.fullmatch(tags["a4a_request"]) is None
            or not is_canonical_pubkey(tags["a4a_decision"])
            or _HEX32.fullmatch(tags["a4a_claim"]) is None):
        raise AssignmentAuthorityError("worker claim identity is malformed")
    if (not isinstance(worker_mandate, Event)
            or worker_mandate.pubkey != owner_pubkey
            or worker_revocation is not None and not is_revocation_valid(
                worker_revocation, worker_mandate)
            or not validate_sender_mandate(
                claim.pubkey, worker_mandate, now=now,
                revocation=worker_revocation, require_started=True)):
        raise AssignmentAuthorityError("claiming worker lacks a current owner mandate")
    return VerifiedClaim(
        claim.id, owner_pubkey, tags["a4a_sender"],
        tags["a4a_conversation"], tags["a4a_request"],
        tags["a4a_decision"], epoch, claim.pubkey,
        policy.event_id, policy.generation, policy.descriptor_id, expiration)


def verify_worker_completion(completion: Event, worker_mandate: Event,
                             owner_pubkey: str, *, now: int,
                             revocation_lookup_complete: bool,
                             worker_revocation: Event | None = None,
                             ) -> VerifiedCompletion:
    """Verify a signed local completion declaration, not result delivery."""
    if revocation_lookup_complete is not True:
        raise AssignmentAuthorityError("incomplete worker revocation lookup")
    if (not isinstance(completion, Event) or completion.kind != 14
            or not completion.verify() or completion.content != ""
            or completion.created_at > now):
        raise AssignmentAuthorityError("invalid signed worker completion")
    tags = _tag_map(completion, _COMPLETION_TAGS)
    expiration = parse_uint(tags["expiration"])
    epoch = parse_uint(tags["a4a_epoch"])
    if (expiration is None or not now < expiration
            or expiration - completion.created_at > _MAX_DECISION_SECONDS
            or epoch is None or not 1 <= epoch <= _MAX_SQLITE_INT):
        raise AssignmentAuthorityError("worker completion has invalid epoch or validity")
    if (tags["a4a_owner"] != owner_pubkey
            or not is_canonical_pubkey(tags["a4a_sender"])
            or not is_canonical_pubkey(tags["a4a_conversation"])
            or _HEX32.fullmatch(tags["a4a_request"]) is None
            or not is_canonical_pubkey(tags["a4a_decision"])
            or not is_canonical_pubkey(tags["a4a_claim_event"])
            or not is_canonical_pubkey(tags["a4a_result_sha256"])):
        raise AssignmentAuthorityError("worker completion identity is malformed")
    if (not isinstance(worker_mandate, Event)
            or worker_mandate.pubkey != owner_pubkey
            or worker_revocation is not None and not is_revocation_valid(
                worker_revocation, worker_mandate)
            or not validate_sender_mandate(
                completion.pubkey, worker_mandate, now=now,
                revocation=worker_revocation, require_started=True)):
        raise AssignmentAuthorityError("completing worker lacks a current owner mandate")
    return VerifiedCompletion(
        completion.id, owner_pubkey, tags["a4a_sender"],
        tags["a4a_conversation"], tags["a4a_request"],
        tags["a4a_decision"], epoch, completion.pubkey,
        tags["a4a_claim_event"], tags["a4a_result_sha256"], expiration)
