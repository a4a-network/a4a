"""F7: one key used to admit infinitely many valid identity strings.

`bytes.fromhex` silently ignores whitespace, so "e4bc...", "e4 bc...", and
"e4\tbc..." are one key for signature verification but DIFFERENT strings for
comparisons and mapping keys. An event with a whitespace-formatted pubkey passed
verify() completely because its ID covered the same string and its signature was
valid. This bypassed both reputation's "one author, one vote" deduplication and the
rejection of self-issued attestations.
"""
import time

import pytest
from pydantic import ValidationError

from a4a import crypto
from a4a.event import Event
from a4a.identity import is_self_issued, verify_identity_attestation
from a4a.keys import Keys
from a4a.reputation import compute_reputation
from a4a.types import KIND_IDENTITY_ATTESTATION, KIND_REVIEW


def _spaced(hexstr: str) -> str:
    return hexstr[:2] + " " + hexstr[2:]


def _sign_with_pubkey(keys: Keys, pubkey: str, kind: int, tags, content="") -> Event:
    """Create a genuinely signed event with an ARBITRARY pubkey string spelling."""
    ev = Event(kind=kind, tags=tags, content=content, created_at=1000)
    object.__setattr__(ev, "pubkey", pubkey)
    ev.id = crypto.compute_event_id(pubkey, ev.created_at, ev.kind, ev.tags, ev.content)
    ev.sig = crypto.sign(ev.id, keys.privkey_hex)
    return ev


def test_non_canonical_pubkey_is_rejected_at_parse():
    k = Keys()
    with pytest.raises(ValidationError):
        Event(kind=1, pubkey=_spaced(k.pubkey_hex), id="a" * 64, sig="b" * 128)


def test_uppercase_hex_is_not_a_second_identity():
    """Uppercase hex compares differently while representing the same cryptographic key."""
    k = Keys()
    with pytest.raises(ValidationError):
        Event(kind=1, pubkey=k.pubkey_hex.upper(), id="a" * 64, sig="b" * 128)


def test_unsigned_event_still_constructs():
    """Empty identity fields are normal before an event is signed."""
    ev = Event(kind=1)
    assert ev.pubkey == "" and ev.id == "" and ev.sig == ""
    ev.sign(Keys())
    assert len(ev.pubkey) == 64


def test_whitespace_pubkey_cannot_multiply_reviews():
    """Five spellings of one author key must produce at most one reputation vote."""
    author = Keys()
    subject = Keys().pubkey_hex
    canon = author.pubkey_hex
    variants = [canon, _spaced(canon), canon[:4] + "\t" + canon[4:],
                canon[:6] + "\n" + canon[6:], canon[:8] + "  " + canon[8:]]
    reviews = []
    for i, v in enumerate(variants):
        ev = _sign_with_pubkey(author, v, KIND_REVIEW,
                               [["p", subject], ["rating", "5"], ["d", f"r{i}"]])
        if ev.verify():          # formerly accepted variants must now fail
            reviews.append(ev)
    rep = compute_reputation(reviews, subject=subject)
    assert rep.total_reviews <= 1, f"one author produced {rep.total_reviews} votes"


def test_self_issued_attestation_cannot_hide_behind_whitespace():
    """Reject a self-issued attestation hidden behind whitespace spelling.

    The issuer and subject are the same key, but tag p uses a spaced variant.
    is_self_issued used to compare strings and miss the self-signature, while
    verify_identity_attestation accepted it as a THIRD-PARTY attestation.
    """
    issuer = Keys()
    alias = _spaced(issuer.pubkey_hex)
    att = Event(kind=KIND_IDENTITY_ATTESTATION,
                tags=[["p", alias], ["level", "account:telegram"],
                      ["expiration", str(int(time.time()) + 3600)]])
    att.sign(issuer)
    assert is_self_issued(att) is True, "self-issued attestation was not recognized"
    assert verify_identity_attestation(att, alias) is False, \
        "self-assertion passed as a third-party attestation"
