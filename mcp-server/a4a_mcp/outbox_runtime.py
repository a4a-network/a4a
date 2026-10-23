"""Owner and MCP access to the sender-side delivery journal (`a4a.outbox`).

The journal lives next to the identity it belongs to, like the inbox. Everything that
leaves this module is metadata: ids, states, counts. Stored envelopes are encrypted,
but they are still not shown: nobody reading a status needs them, and a listing that
never carries them cannot leak them.
"""
from __future__ import annotations

import logging
import time

from a4a.outbox import RECHECK_GIVE_UP, OutboxStore
from a4a.relay import RelayError

from . import identity

_FIELDS = ("delivery_id", "recipient", "private", "state", "attempts", "ack_status",
           "late", "republished", "created", "updated", "ack_at", "ack_signed_at")

#: States whose outcome can still change while rechecks run.
_UNCONFIRMED = ("dead_letter", "interrupted", "sending")

#: What a person should read beside each state. 26.09.2026, owner's representative:
#: "dead_letter" reads as "the letter is lost" while it means "no acknowledgement yet".
_MEANING = {
    "acknowledged": "the recipient acknowledged the letter (see ack_status)",
    "dead_letter": ("no acknowledgement yet - the letter is not lost and may already be "
                    "stored by the recipient; rechecks continue until rechecks_until"),
    "interrupted": ("sending was interrupted - the letter may have left; rechecks continue "
                    "until rechecks_until"),
    "sending": "sending is in progress or its process died; rechecks continue",
    "publish_failed": "not delivered: no relay accepted the letter",
}


log = logging.getLogger(__name__)


def open_store() -> OutboxStore:
    return OutboxStore(identity.IDENTITY_DIR / "outbox")


def _journal_exists() -> bool:
    return (identity.IDENTITY_DIR / "outbox" / "outbox.sqlite3").is_file()


async def recheck_due_on(agent, *, now: float | None = None) -> dict:
    """Heal journaled deliveries whose automatic recheck is due; used on receiver ticks.

    Cheap when there is nothing to do: no journal, or nothing due, means no relay
    connection at all. A mailbox that never sent anything never grows a journal here.
    """
    idle = {"checked": 0, "acknowledged": 0}
    if not _journal_exists():
        return idle
    moment = time.time() if now is None else now
    with open_store() as store:
        if not store.due_for_recheck(moment, limit=1):
            return idle
        try:
            await agent.relay.connect()
            return await agent.recheck_due(store, now=moment, resolve_recipient_relays=True)
        except RelayError as error:
            log.warning("automatic delivery recheck could not reach relays: %s", error)
            return {**idle, "error": str(error)}
        finally:
            await agent.relay.aclose()


def _public(record: dict, now: float | None = None) -> dict:
    shown = {key: record[key] for key in _FIELDS}
    shown["envelopes"] = len(record["envelope_ids"])
    moment = time.time() if now is None else now
    shown["rechecks_until"] = record["created"] + RECHECK_GIVE_UP
    unconfirmed = record["state"] in _UNCONFIRMED
    # Representative, 26.09: "received" only says the recipient's MAILBOX stored the
    # letter; rechecks keep waiting for its agent's "processed". It must not hide from final.
    stored_only = record["state"] == "acknowledged" and record["ack_status"] == "received"
    expired = moment > shown["rechecks_until"]
    # Final: automatic rechecks have ended without the acknowledgement they wait for.
    shown["final"] = (unconfirmed or stored_only) and expired
    meaning = _MEANING.get(record["state"], "unknown state")
    if record["state"] == "acknowledged":
        # "processed" = read and taken into work, not an answer (representative, 27.09).
        meaning = ("the recipient's agent processed the letter: read and taken into work - "
                   "not a reply; a reply arrives as its own letter bound by a4a_reply"
                   if record["ack_status"] == "processed" else
                   "the recipient's agent reported the letter failed"
                   if record["ack_status"] == "failed" else
                   "stored by the recipient's mailbox, not processed yet by its agent; "
                   "rechecks continue until rechecks_until")
    if shown["final"] and stored_only:
        meaning = ("stored by the recipient's mailbox but not processed within the recheck "
                   "period - the recipient's agent may not be reading its mail; do not resend")
    elif shown["final"]:
        meaning = ("no acknowledgement within the recheck period; automatic rechecks have "
                   "ended - republish by hand (outbox-republish) or treat as unconfirmed")
    shown["meaning"] = meaning
    return shown


def summary(now: float | None = None) -> dict:
    """Counts with the moment they were taken: a count without a time misleads (26.09)."""
    moment = time.time() if now is None else now
    if not _journal_exists():
        return {"as_of": moment, "total": 0, "processed": 0, "stored_not_processed": 0,
                "stored_not_processed_final": 0, "unconfirmed": 0, "unconfirmed_final": 0,
                "not_delivered": 0}
    with open_store() as store:
        records = [_public(r, moment) for r in store.list(None, 100_000)]
    unconfirmed = [r for r in records if r["state"] in _UNCONFIRMED]
    # Two levels of acknowledgement, never summed into one "delivered" (representative, 26.09).
    stored = [r for r in records if r["state"] == "acknowledged" and r["ack_status"] == "received"]
    return {"as_of": moment, "total": len(records),
            "processed": sum(r["state"] == "acknowledged" and r["ack_status"] == "processed"
                             for r in records),
            "stored_not_processed": len(stored),
            "stored_not_processed_final": sum(r["final"] for r in stored),
            "unconfirmed": len(unconfirmed),
            "unconfirmed_final": sum(r["final"] for r in unconfirmed),
            "not_delivered": sum(r["state"] == "publish_failed" for r in records)}


def get(delivery_id: str) -> dict | None:
    with open_store() as store:
        record = store.get(delivery_id)
    return _public(record) if record else None


def list_records(states=None, limit: int = 100) -> list[dict]:
    with open_store() as store:
        return [_public(r) for r in store.list(states, limit)]


async def recheck(delivery_id: str) -> dict | None:
    from .server import _make_agent
    if not _journal_exists():
        return None  # never create an empty journal just to look into it
    with open_store() as store:
        if store.get(delivery_id) is None:
            return None
        async with _make_agent() as agent:
            record = await agent.recheck_delivery(
                store, delivery_id, resolve_recipient_relays=True)
        return _public(record)


async def republish(delivery_id: str) -> dict:
    """Resend the stored envelope. Gift wraps need no mandate, so none is loaded."""
    from .server import _make_agent
    with open_store() as store:
        async with _make_agent() as agent:
            event_id = await agent.republish_delivery(
                store, delivery_id, resolve_recipient_relays=True)
        return {"republished_event_id": event_id, **_public(store.get(delivery_id))}
