"""Signed/encrypted wire cases that the normal sender API intentionally cannot emit."""
import json

from a4a import Keys, crypto, giftwrap, nip44, types
from a4a.event import Event


def wrapped_with_escaped_content(sender: Keys, recipient: Keys, content: str, *,
                                 delivery: str = "escaped-content",
                                 now: int = 200000) -> tuple[Event, Event]:
    """Build a valid gift-wrap whose inner JSON uses ASCII escapes.

    `giftwrap.wrap` serializes with `ensure_ascii=False`, so invalid Unicode scalar
    values are rejected by the sender-side UTF-8 encoder.  A peer can nevertheless
    put the same value on the wire as an ASCII JSON escape and sign a malformed
    inner event using the low-level hash helper. Event.sign intentionally rejects
    those strings: this is not a valid protocol event despite its real signature.
    Receiver regressions need its encrypted shape instead of injecting a dictionary.
    """
    def event_json(event: Event) -> str:
        return json.dumps(
            event.model_dump(), separators=(",", ":"), ensure_ascii=True)

    inner = Event(
        kind=types.KIND_PRIVATE_RUMOR,
        tags=[["p", recipient.pubkey_hex], ["d", delivery]],
        content=content,
        created_at=now,
    )
    inner.pubkey = sender.pubkey_hex
    inner.id = crypto.compute_event_id(inner.pubkey, inner.created_at, inner.kind,
                                       inner.tags, inner.content)
    inner.sig = crypto.sign(inner.id, sender.privkey_hex)

    seal = Event(
        kind=giftwrap.KIND_SEAL,
        tags=[],
        content=nip44.encrypt(
            event_json(inner), sender.privkey_hex, recipient.pubkey_hex),
        created_at=now,
    )
    seal.sign(sender)

    ephemeral = Keys()
    outer = Event(
        kind=giftwrap.KIND_GIFT_WRAP,
        tags=[["p", recipient.pubkey_hex]],
        content=nip44.encrypt(
            event_json(seal), ephemeral.privkey_hex, recipient.pubkey_hex),
        created_at=now,
    )
    outer.sign(ephemeral)
    return outer, inner
