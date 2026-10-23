"""OpenTimestamps calendars: submit a root and await a Bitcoin attestation.

Protocol, verified against python-opentimestamps source on 2026-09-04: ``POST
<calendar>/digest`` with raw digest bytes and ``Accept:
application/vnd.opentimestamps.v1`` returns a serialized ``Timestamp`` over that digest
with ``PendingAttestation(uri)``. Later, ``GET <calendar>/timestamp/<hex commitment>``
returns 404 until block inclusion, then a ``Timestamp`` over the commitment with
``BitcoinBlockHeaderAttestation(height)``. The commitment is NOT the root; it is the
``msg`` of the node carrying the pending attestation after the calendar appends its ops.

A calendar here is any object implementing ``submit(digest)`` and
``get_timestamp(commitment)``. The latter raises ``CommitmentNotFoundError`` until block
inclusion. Production uses ``opentimestamps.calendar.RemoteCalendar``; tests use fakes.
No code outside this module accesses calendar networking.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable

import logging

from opentimestamps.calendar import CommitmentNotFoundError, RemoteCalendar
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.timestamp import Timestamp

# Public OpenTimestamps calendars; all four returned HTTP 200 from the live node on
# 2026-09-04.
DEFAULT_CALENDARS = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
)

CalendarFactory = Callable[[str], object]

log = logging.getLogger("a4a.notary.calendar")


def remote_calendar(url: str) -> RemoteCalendar:
    # RemoteCalendar has no timeout parameter. The first live run on 2026-09-04 failed
    # in its constructor, while a broad except misreported it as no calendar response.
    # The entry point therefore sets a socket-level timeout with setdefaulttimeout().
    return RemoteCalendar(url, user_agent="a4a-notary/0.1 (+https://a4a.network)")


class NoCalendarAnswered(RuntimeError):
    """No calendar accepted the root; leave the batch unsubmitted and retry later."""


def submit_root(root: Timestamp, urls: Iterable[str] = DEFAULT_CALENDARS,
                factory: CalendarFactory = remote_calendar) -> list[str]:
    """Submit the root to every calendar and return the responding URLs.

    One response is sufficient because NIP-03 recommends one attestation. Additional
    calendars provide redundancy if the first never reaches a block.
    """
    answered: list[str] = []
    for url in urls:
        try:
            reply = factory(url).submit(root.msg)
        except Exception as e:  # noqa: BLE001 - unavailable calendar; try the next one
            # Always log the cause. The first live run "did not respond" in 84 ms because
            # the constructor raised, not because of the network, and a broad except hid it.
            log.warning("calendar %s rejected the root: %s: %s", url, type(e).__name__, e)
            continue
        if reply.msg != root.msg:
            log.warning("calendar %s replied for a different digest; ignoring it", url)
            continue  # The reply is not for our digest; do not trust this calendar.
        root.merge(reply)
        answered.append(url)
    if not answered:
        raise NoCalendarAnswered("no calendar responded for the root")
    return answered


def _pending_nodes(ts: Timestamp) -> list[tuple[Timestamp, PendingAttestation]]:
    out: list[tuple[Timestamp, PendingAttestation]] = []
    for att in ts.attestations:
        if isinstance(att, PendingAttestation):
            out.append((ts, att))
    for child in ts.ops.values():
        out.extend(_pending_nodes(child))
    return out


def has_bitcoin_attestation(ts: Timestamp) -> bool:
    return any(isinstance(a, BitcoinBlockHeaderAttestation) for _, a in ts.all_attestations())


def upgrade_root(root: Timestamp, factory: CalendarFactory = remote_calendar) -> bool:
    """Query calendars for every pending node and report Bitcoin finalization.

    Pending attestations are removed after a successful response. NIP-03 excludes them
    from the published proof, and there is no reason to retain them afterward.
    """
    if has_bitcoin_attestation(root):
        return True
    for node, pending in _pending_nodes(root):
        try:
            reply = factory(pending.uri).get_timestamp(node.msg)
        except CommitmentNotFoundError:
            continue  # Not in a block yet; this is expected.
        except Exception as e:  # noqa: BLE001 - network failure; retry next pass
            log.warning("calendar %s did not answer for commitment: %s: %s",
                        pending.uri, type(e).__name__, e)
            continue
        if reply.msg != node.msg:
            continue
        node.merge(reply)
        if has_bitcoin_attestation(reply):
            node.attestations.discard(pending)
    return has_bitcoin_attestation(root)
