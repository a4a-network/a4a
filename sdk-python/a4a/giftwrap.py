"""A4A Sealed Envelope (kind 1059) for metadata privacy.

A private message—a SIGNED inner event—is encrypted into a seal (kind 13, signed by
the sender) from sender to recipient, then wrapped as kind 1059 by a ONE-TIME ephemeral
key with a fuzzed `created_at`. The relay sees only an envelope from a random key to
recipient `p`: sender and precise time are hidden, while content and delivery_id remain
inside and unavailable to the relay.

Unlike unsigned rumor schemes, the inner A4A event is SIGNED by the sender.
This permits self-verifying disclosure in a dispute—the sender signed
this exact text, and disclosure does not reveal keys. The tradeoff is less deniability,
which is desirable for verifiable agreements.
"""
import json
import secrets

from . import nip44
from .event import Event
from .keys import Keys

KIND_SEAL = 13
KIND_GIFT_WRAP = 1059
# Move created_at randomly up to two days into the past (NIP-59) so observers cannot
# correlate messages precisely by time.
_JITTER_SECONDS = 2 * 24 * 3600


class GiftWrapError(Exception):
    """Gift wrap could not be opened or verified (malformed, misrouted, or forged)."""


def _dump(ev: Event) -> str:
    return json.dumps(ev.model_dump(), separators=(",", ":"), ensure_ascii=False)


def _jitter(now: int) -> int:
    if type(now) is not int or not 0 <= now < (1 << 64):
        raise ValueError("gift-wrap time must be an unsigned 64-bit integer")
    # Near the Unix epoch, the privacy window cannot extend below zero.
    return now - secrets.randbelow(min(_JITTER_SECONDS, now + 1))


def wrap(inner: Event, recipient_pubkey: str, sender_keys: Keys,
         now: int | None = None, extra_tags: list[list[str]] | None = None) -> Event:
    """Wrap a SIGNED `inner` event for `recipient_pubkey`.

    Return kind 1059 signed by an ephemeral key; publish that event to the relay.
    The sender must have already signed `inner`.
    """
    import time
    now = now if now is not None else int(time.time())
    # Seal: encrypt inner from sender to recipient and sign the event as the sender.
    seal_content = nip44.encrypt(_dump(inner), sender_keys.privkey_hex, recipient_pubkey)
    seal = Event(kind=KIND_SEAL, tags=[], content=seal_content, created_at=_jitter(now))
    seal.sign(sender_keys)
    # Gift wrap: encrypt the seal to the recipient with a ONE-TIME ephemeral key.
    eph = Keys()
    gw_content = nip44.encrypt(_dump(seal), eph.privkey_hex, recipient_pubkey)
    # Add extra_tags BEFORE signing (for example, NIP-40 expiry). Appending tags after
    # signing would invalidate the id and signature.
    gw = Event(kind=KIND_GIFT_WRAP,
               tags=[["p", recipient_pubkey], *(extra_tags or [])],
               content=gw_content, created_at=_jitter(now))
    gw.sign(eph)
    return gw


def unwrap(giftwrap: Event, recipient_keys: Keys) -> Event:
    """Open gift wrap into the sender's SIGNED inner event.

    Verify that the seal is valid and signed, and that the SAME key signed the inner
    event; otherwise somebody substituted another seal. Raise `GiftWrapError` on failure.
    """
    # Verify the outer envelope too. Previously only the seal and inner event were
    # checked—not the kind, outer signature, or whether `p` named us. The normal SDK
    # path receives events through relay._parse_event with verified signatures, but
    # unwrap is a public API (2026-08-29 internal audit, F15).
    if giftwrap.kind != KIND_GIFT_WRAP or not giftwrap.verify_protocol():
        raise GiftWrapError("envelope is not a signed gift wrap")
    addressed_to = giftwrap.tag_value("p")
    if addressed_to is not None and addressed_to != recipient_keys.pubkey_hex:
        raise GiftWrapError("envelope is addressed to another recipient")
    try:
        seal_json = nip44.decrypt(giftwrap.content, recipient_keys.privkey_hex,
                                  giftwrap.pubkey)
        seal = Event(**json.loads(seal_json))
    except (nip44.Nip44Error, ValueError, TypeError, KeyError) as e:
        raise GiftWrapError(f"failed to open gift-wrap envelope: {e}") from e
    if seal.kind != KIND_SEAL or not seal.verify_protocol():
        raise GiftWrapError("seal is invalid or unsigned")
    try:
        inner_json = nip44.decrypt(seal.content, recipient_keys.privkey_hex, seal.pubkey)
        inner = Event(**json.loads(inner_json))
    except (nip44.Nip44Error, ValueError, TypeError, KeyError) as e:
        raise GiftWrapError(f"failed to decrypt seal contents: {e}") from e
    # Anti-substitution: the inner author equals the seal author and its signature verifies.
    if inner.pubkey != seal.pubkey or not inner.verify_protocol():
        # This may be another implementation rather than an attack: canonical NIP-59
        # leaves the inner rumor UNSIGNED. Explain the incompatibility so its operator
        # does not waste time searching for a local bug.
        raise GiftWrapError(
            "inner event is not signed by the seal author. A4A requires a SIGNED rumor, "
            "unlike canonical NIP-59: without that signature, revealing a conversation "
            "proves nothing in a dispute")
    return inner
