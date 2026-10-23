"""Offline verifier for candidate organization-addressed private letters.

This does not unwrap gift wraps, fetch descriptors, send mail, store requests,
issue ACKs, or route to a worker. It verifies one signed inner kind-14 event
against one owner-signed active descriptor before a future ingress may consider
durably admitting it. The candidate wire grammar is not allocated for live use.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from . import types
from .event import Event, is_canonical_pubkey
from .organization_inbox import DescriptorError, verify_descriptor


_REQUIRED = frozenset({
    "p", "d", "a4a_owner", "a4a_descriptor", "a4a_request",
    "a4a_conversation",
})
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _matches(pattern: re.Pattern[str], value) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


class OrganizationLetterError(ValueError):
    """A signed letter cannot be admitted to the candidate organization route."""


@dataclass(frozen=True)
class OrganizationLetter:
    owner_pubkey: str
    ingress_pubkey: str
    sender_pubkey: str
    descriptor_id: str
    inner_event_id: str
    delivery_id: str
    request_id: str
    conversation_id: str
    content_sha256: str


def verify_organization_letter(inner: Event, descriptor_event: Event,
                               owner_pubkey: str, ingress_pubkey: str, *,
                               now: int, max_validity_seconds: int) -> OrganizationLetter:
    """Verify exact signed route bindings, not permission to execute content.

    `ingress_pubkey` is the physical mailbox key the caller already controls;
    passing a sender-supplied key here would defeat recipient binding. The
    caller must separately verify outer gift-wrap recipient, admission policy,
    replay ledger, current worker authority, and sender's mandate if required.
    """
    try:
        descriptor = verify_descriptor(descriptor_event, owner_pubkey, now=now,
                                       max_validity_seconds=max_validity_seconds)
    except DescriptorError as exc:
        raise OrganizationLetterError("invalid organization route proof") from exc
    if not is_canonical_pubkey(ingress_pubkey) or ingress_pubkey != descriptor.ingress_pubkey:
        raise OrganizationLetterError("physical ingress does not match descriptor")
    if not isinstance(inner, Event) or inner.kind != types.KIND_PRIVATE_RUMOR:
        raise OrganizationLetterError("organization letter must be a signed inner kind-14 event")
    if not inner.verify():
        raise OrganizationLetterError("invalid organization letter signature")
    tags: dict[str, str] = {}
    delegation_seen = False
    for tag in inner.tags:
        if len(tag) < 2 or not isinstance(tag[0], str):
            raise OrganizationLetterError("malformed organization letter tag")
        name = tag[0]
        if name in _REQUIRED:
            if len(tag) != 2 or name in tags:
                raise OrganizationLetterError("ambiguous organization route tag")
            tags[name] = tag[1]
        elif name == "delegation":
            if len(tag) != 2 or delegation_seen or not _matches(_HEX64, tag[1]):
                raise OrganizationLetterError("invalid delegation reference")
            delegation_seen = True
        elif name.startswith("a4a_"):
            raise OrganizationLetterError("unknown organization route tag")
    if tags.keys() != _REQUIRED:
        raise OrganizationLetterError("incomplete organization route tags")
    if tags["p"] != ingress_pubkey or tags["a4a_owner"] != owner_pubkey:
        raise OrganizationLetterError("organization letter recipient or owner mismatch")
    if tags["a4a_descriptor"] != descriptor.event_id:
        raise OrganizationLetterError("organization descriptor event ID mismatch")
    if (not _matches(_HEX32, tags["d"])
            or not _matches(_HEX32, tags["a4a_request"])
            or not _matches(_HEX64, tags["a4a_conversation"])):
        raise OrganizationLetterError("noncanonical organization letter identifier")
    try:
        content = inner.content.encode("utf-8")
    except UnicodeError as exc:
        raise OrganizationLetterError("invalid organization letter encoding") from exc
    if len(content) > 32 * 1024:
        raise OrganizationLetterError("organization letter exceeds content limit")
    return OrganizationLetter(
        owner_pubkey=owner_pubkey, ingress_pubkey=ingress_pubkey,
        sender_pubkey=inner.pubkey, descriptor_id=descriptor.event_id,
        inner_event_id=inner.id, delivery_id=tags["d"],
        request_id=tags["a4a_request"],
        conversation_id=tags["a4a_conversation"],
        content_sha256=hashlib.sha256(content).hexdigest())
