"""Candidate organization inner-letter verifier; no relay or live routing."""

import hashlib

import pytest

from a4a.event import Event
from a4a.keys import Keys
from a4a.organization_mail import (
    OrganizationLetterError,
    verify_organization_letter,
)


NOW = 1_800_000_000
WEEK = 7 * 24 * 3600
REQUEST = "a" * 32
DELIVERY = "b" * 32
CONVERSATION = "c" * 64


def _descriptor(owner, ingress):
    return Event(kind=31008, content="", tags=[
        ["d", "inbox:1"], ["p", ingress.pubkey_hex],
        ["generation", "1"], ["not_before", str(NOW - 60)],
        ["expiration", str(NOW + 60)],
    ]).sign(owner)


def _inner(sender, owner, ingress, descriptor, *, tags=None, content="status"):
    if tags is None:
        tags = [
            ["p", ingress.pubkey_hex], ["d", DELIVERY],
            ["a4a_owner", owner.pubkey_hex],
            ["a4a_descriptor", descriptor.id],
            ["a4a_request", REQUEST],
            ["a4a_conversation", CONVERSATION],
        ]
    return Event(kind=14, content=content, tags=tags).sign(sender)


def _verify(inner, descriptor, owner, ingress):
    return verify_organization_letter(
        inner, descriptor, owner.pubkey_hex, ingress.pubkey_hex,
        now=NOW, max_validity_seconds=WEEK)


def test_owner_signed_route_and_signed_inner_bind_the_physical_inbox():
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    result = _verify(inner, descriptor, owner, ingress)
    assert result.owner_pubkey == owner.pubkey_hex
    assert result.ingress_pubkey == ingress.pubkey_hex
    assert result.sender_pubkey == sender.pubkey_hex
    assert result.descriptor_id == descriptor.id
    assert result.inner_event_id == inner.id
    assert result.request_id == REQUEST
    assert result.delivery_id == DELIVERY
    assert result.conversation_id == CONVERSATION
    assert result.content_sha256 == hashlib.sha256(b"status").hexdigest()


def test_witnessed_physical_recipient_is_not_taken_from_untrusted_letter():
    owner, ingress, other, sender = Keys(), Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    with pytest.raises(OrganizationLetterError, match="physical ingress"):
        _verify(inner, descriptor, owner, other)
    inner = _inner(sender, owner, ingress, descriptor,
                   tags=[["p", other.pubkey_hex], ["d", DELIVERY],
                         ["a4a_owner", owner.pubkey_hex],
                         ["a4a_descriptor", descriptor.id],
                         ["a4a_request", REQUEST],
                         ["a4a_conversation", CONVERSATION]])
    with pytest.raises(OrganizationLetterError, match="recipient or owner"):
        _verify(inner, descriptor, owner, ingress)


def test_wrong_owner_or_route_proof_fails_before_admission():
    owner, other_owner, ingress, sender = Keys(), Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    with pytest.raises(OrganizationLetterError, match="route proof"):
        _verify(inner, descriptor, other_owner, ingress)
    swapped = _descriptor(owner, Keys())
    with pytest.raises(OrganizationLetterError, match="physical ingress"):
        _verify(inner, swapped, owner, ingress)


@pytest.mark.parametrize("mutation", [
    lambda tags: tags + [["a4a_owner", tags[2][1]]],
    lambda tags: tags + [["p", tags[0][1]]],
    lambda tags: tags + [["a4a_future", "value"]],
    lambda tags: tags[:-1],
    lambda tags: tags[:4] + [["a4a_request", "A" * 32]] + tags[5:],
    lambda tags: tags[:1] + [["d", "not-a-hex-delivery"]] + tags[2:],
    lambda tags: tags + [["delegation", "a" * 64], ["delegation", "b" * 64]],
])
def test_ambiguous_or_noncanonical_routing_fails_closed(mutation):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    tags = _inner(sender, owner, ingress, descriptor).tags
    with pytest.raises(OrganizationLetterError):
        _verify(_inner(sender, owner, ingress, descriptor,
                       tags=mutation(tags)), descriptor, owner, ingress)


def test_wrong_descriptor_id_and_invalid_inner_signature_fail():
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    tags = _inner(sender, owner, ingress, descriptor).tags
    tags[3][1] = "d" * 64
    with pytest.raises(OrganizationLetterError, match="descriptor event ID"):
        _verify(_inner(sender, owner, ingress, descriptor, tags=tags),
                descriptor, owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    inner.content = "tampered"
    with pytest.raises(OrganizationLetterError, match="signature"):
        _verify(inner, descriptor, owner, ingress)


def test_plain_event_and_oversized_content_are_not_organization_letters():
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    inner.kind = 31033
    inner.sign(sender)
    with pytest.raises(OrganizationLetterError, match="inner kind-14"):
        _verify(inner, descriptor, owner, ingress)
    large = _inner(sender, owner, ingress, descriptor, content="x" * (32 * 1024 + 1))
    with pytest.raises(OrganizationLetterError, match="content limit"):
        _verify(large, descriptor, owner, ingress)


def test_optional_single_delegation_reference_does_not_grant_authority():
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    tags = _inner(sender, owner, ingress, descriptor).tags
    tags.append(["delegation", "d" * 64])
    assert _verify(_inner(sender, owner, ingress, descriptor, tags=tags),
                   descriptor, owner, ingress).sender_pubkey == sender.pubkey_hex
