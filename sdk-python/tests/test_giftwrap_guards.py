"""`unwrap` guards missed by the original suite (2026-08-29 mutation pass).

The pass disabled each `giftwrap.py` guard in turn and ran the full suite. Recipient
and seal checks initially survived mutation; a second full pass found that the outer
envelope check was also unproven:

* the outer envelope must be kind 1059 with a valid signature;
* its `p` tag must address us;
* the encrypted inner envelope must be a signed seal.

All checks concern forgery and are therefore proven with real signed events, not mocks.
"""
import json

import pytest
from a4a import giftwrap, nip44
from a4a.event import Event
from a4a.giftwrap import KIND_GIFT_WRAP, KIND_SEAL, GiftWrapError
from a4a.keys import Keys


def _inner(sender: Keys, text: str = "text") -> Event:
    ev = Event(kind=14, tags=[], content=text)
    ev.sign(sender)
    return ev


def _envelope(content: str, p_tag: str) -> Event:
    """Build an envelope from a one-time key with arbitrary content and recipient."""
    eph = Keys()
    gw = Event(kind=KIND_GIFT_WRAP, tags=[["p", p_tag]], content=content)
    gw.sign(eph)
    return gw, eph


def test_unwrap_rejects_outer_envelope_of_wrong_kind():
    """A correctly signed event of another kind is still not gift wrap."""
    sender, me = Keys(), Keys()
    seal_json = json.dumps(_seal(sender, me).model_dump(), separators=(",", ":"))
    eph = Keys()
    content = nip44.encrypt(seal_json, eph.privkey_hex, me.pubkey_hex)
    wrong_kind = Event(kind=1, tags=[["p", me.pubkey_hex]], content=content)
    wrong_kind.sign(eph)

    with pytest.raises(GiftWrapError, match="not a signed gift wrap"):
        giftwrap.unwrap(wrong_kind, me)


def test_unwrap_rejects_outer_envelope_with_broken_signature():
    """Kind 1059 does not replace verification of the envelope's one-time key."""
    sender, me = Keys(), Keys()
    tampered = giftwrap.wrap(_inner(sender), me.pubkey_hex, sender)
    tampered.created_at += 1

    with pytest.raises(GiftWrapError, match="not a signed gift wrap"):
        giftwrap.unwrap(tampered, me)


def test_unwrap_rejects_envelope_addressed_to_someone_else():
    """The envelope is encrypted TO US, but its signed `p` tag names someone else.

    This mismatch is route substitution: the content reached us while the sender (or
    envelope rebuilder) claims it targeted somebody else. Accepting it would mean
    processing and replying to someone else's conversation.
    """
    sender, me, stranger = Keys(), Keys(), Keys()
    seal_json = json.dumps(_seal(sender, me).model_dump(), separators=(",", ":"))
    eph = Keys()
    content = nip44.encrypt(seal_json, eph.privkey_hex, me.pubkey_hex)
    gw = Event(kind=KIND_GIFT_WRAP, tags=[["p", stranger.pubkey_hex]], content=content)
    gw.sign(eph)

    with pytest.raises(GiftWrapError, match="another recipient"):
        giftwrap.unwrap(gw, me)


def _seal(sender: Keys, recipient: Keys, kind: int = KIND_SEAL,
          break_signature: bool = False) -> Event:
    inner = _inner(sender)
    content = nip44.encrypt(
        json.dumps(inner.model_dump(), separators=(",", ":"), ensure_ascii=False),
        sender.privkey_hex, recipient.pubkey_hex)
    seal = Event(kind=kind, tags=[], content=content)
    seal.sign(sender)
    if break_signature:
        # Signature remains syntactically valid but does not cover this content.
        seal.content = nip44.encrypt("substituted", sender.privkey_hex,
                                     recipient.pubkey_hex)
    return seal


def test_unwrap_rejects_seal_of_wrong_kind():
    """The inner envelope must be a seal; otherwise this is not our NIP-59 structure."""
    sender, me = Keys(), Keys()
    fake = _seal(sender, me, kind=1)
    eph = Keys()
    content = nip44.encrypt(json.dumps(fake.model_dump(), separators=(",", ":")),
                            eph.privkey_hex, me.pubkey_hex)
    gw = Event(kind=KIND_GIFT_WRAP, tags=[["p", me.pubkey_hex]], content=content)
    gw.sign(eph)

    with pytest.raises(GiftWrapError, match="seal is invalid"):
        giftwrap.unwrap(gw, me)


def test_unwrap_rejects_seal_with_broken_signature():
    """Only the seal signature links an envelope to its sender.

    The outer envelope is signed by a one-time key and says nothing about authorship;
    accepting an unchecked seal would mean accepting a letter from anybody.
    """
    sender, me = Keys(), Keys()
    tampered = _seal(sender, me, break_signature=True)
    eph = Keys()
    content = nip44.encrypt(json.dumps(tampered.model_dump(), separators=(",", ":")),
                            eph.privkey_hex, me.pubkey_hex)
    gw = Event(kind=KIND_GIFT_WRAP, tags=[["p", me.pubkey_hex]], content=content)
    gw.sign(eph)

    with pytest.raises(GiftWrapError, match="seal is invalid"):
        giftwrap.unwrap(gw, me)


def test_unsigned_rumor_is_refused_with_an_explanation():
    """An unsigned rumor is canonical NIP-59 and may come from another implementation.

    A4A requires a signature because revealing unsigned conversation text proves
    nothing in a dispute. The error must name this incompatibility instead of merely
    saying "invalid," or the other operator will search for a nonexistent local bug.
    """
    sender, me = Keys(), Keys()
    unsigned = Event(kind=14, tags=[], content="as in NIP-59")   # Intentionally unsigned.
    content = nip44.encrypt(
        json.dumps(unsigned.model_dump(), separators=(",", ":"), ensure_ascii=False),
        sender.privkey_hex, me.pubkey_hex)
    seal = Event(kind=KIND_SEAL, tags=[], content=content)
    seal.sign(sender)
    eph = Keys()
    gw = Event(kind=KIND_GIFT_WRAP, tags=[["p", me.pubkey_hex]],
               content=nip44.encrypt(json.dumps(seal.model_dump(), separators=(",", ":")),
                                     eph.privkey_hex, me.pubkey_hex))
    gw.sign(eph)

    with pytest.raises(GiftWrapError, match="NIP-59"):
        giftwrap.unwrap(gw, me)
