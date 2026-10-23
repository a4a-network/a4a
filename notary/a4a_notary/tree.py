"""Merkle tree over event IDs and NIP-03 leaf attestations.

One calendar request per hour covers all historical events. Leaves are the raw 32-byte
IDs (NIP-03 says the proof must use the referenced ``e`` event ID as its digest, as does
``nostr-ots``). Internal nodes use standard OpenTimestamps append, prepend, and SHA-256
operations, so any ``ots verify`` can read a leaf path without this library.

Publish ONLY after a Bitcoin attestation. NIP-03 recommends one and excludes pending
attestations. A calendar's ``POST /digest`` initially returns pending; building kind
1040 from it would give readers a timestamp that proves nothing yet but looks like proof.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.core.op import OpSHA256
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp, make_merkle_tree

# Canonical event IDs match keys and the SDK: 64 lowercase hexadecimal characters.
_EVENT_ID = re.compile(r"[0-9a-f]{64}")

KIND_OTS_ATTESTATION = 1040


class NotFinalized(RuntimeError):
    """The batch root has no Bitcoin attestation yet, so nothing can be published."""


@dataclass
class Batch:
    root: Timestamp
    leaves: dict[str, Timestamp] = field(default_factory=dict)

    @property
    def root_digest(self) -> bytes:
        return self.root.msg


def build_batch(event_ids: list[str]) -> Batch:
    """Build a tree over IDs; OpenTimestamps makes a single leaf its own root."""
    if not event_ids:
        raise ValueError("empty batch: nothing to notarize")
    leaves: dict[str, Timestamp] = {}
    for event_id in event_ids:
        if not _EVENT_ID.fullmatch(event_id):
            raise ValueError("non-canonical event ID (expected 64 lowercase hex): %r" % event_id)
        if event_id in leaves:
            continue
        leaves[event_id] = Timestamp(bytes.fromhex(event_id))
    # Sort leaves by ID so the same set always produces the same root.
    ordered = [leaves[i] for i in sorted(leaves)]
    root = make_merkle_tree(ordered)
    return Batch(root=root, leaves=leaves)


def _tips(ts: Timestamp) -> set[bytes]:
    if not ts.ops:
        return {ts.msg}
    out: set[bytes] = set()
    for child in ts.ops.values():
        out |= _tips(child)
    return out


def leaf_tips(batch: Batch, event_id: str) -> set[bytes]:
    """Return every leaf-path tip; a valid tree has exactly ``{root}``."""
    return _tips(batch.leaves[event_id])


def attach_calendar_reply(batch: Batch, reply: Timestamp) -> None:
    """Attach a calendar reply for this root to the batch root.

    Reject replies for a different digest, or another tree's proof could be attached to
    our leaves.
    """
    if reply.msg != batch.root_digest:
        raise ValueError("calendar reply is for another digest, not this batch root")
    batch.root.merge(reply)


def _bitcoin_attestations(ts: Timestamp) -> list[BitcoinBlockHeaderAttestation]:
    return [a for _, a in ts.all_attestations() if isinstance(a, BitcoinBlockHeaderAttestation)]


def is_finalized(batch: Batch) -> bool:
    return bool(_bitcoin_attestations(batch.root))


def _earliest_height(ts: Timestamp) -> int | None:
    heights = [a.height for _, a in ts.all_attestations() if isinstance(a, BitcoinBlockHeaderAttestation)]
    return min(heights) if heights else None


def _prune_to_one(ts: Timestamp, height: int) -> Timestamp | None:
    """Copy a timestamp with EXACTLY ONE path to the first attestation at ``height``.

    NIP-03 recommends one attestation; the others add bytes without evidentiary value.
    Two calendars returned two blocks each for the first live batch. Readers choose the
    earliest, so writers must retain only that path.
    """
    for att in ts.attestations:
        if isinstance(att, BitcoinBlockHeaderAttestation) and att.height == height:
            out = Timestamp(ts.msg)
            out.attestations.add(att)
            return out
    for op, child in ts.ops.items():
        pruned = _prune_to_one(child, height)
        if pruned is not None:
            out = Timestamp(ts.msg)
            out.ops[op] = pruned
            return out
    return None


def _prune_to_bitcoin(ts: Timestamp) -> Timestamp:
    """Return one path to the earliest Bitcoin attestation."""
    height = _earliest_height(ts)
    if height is None:
        raise NotFinalized("batch root has no Bitcoin attestation")
    pruned = _prune_to_one(ts, height)
    assert pruned is not None, "path to the discovered attestation was lost"
    return pruned


def leaf_ots(batch: Batch, event_id: str) -> bytes:
    """Build a leaf ``.ots``: event-ID digest, root path, and Bitcoin attestation."""
    if not is_finalized(batch):
        raise NotFinalized("batch root has no Bitcoin attestation")
    pruned = _prune_to_bitcoin(batch.leaves[event_id])
    detached = DetachedTimestampFile(OpSHA256(), pruned)
    ctx = BytesSerializationContext()
    detached.serialize(ctx)
    return ctx.getbytes()


def attestation_event(batch: Batch, event_id: str, target_kind: int, relay_url: str) -> dict:
    """Build an unsigned NIP-03 kind 1040 event for the notary to sign.

    Kind 1040 has no expiry because it attests history and lives as long as that history.
    """
    blob = leaf_ots(batch, event_id)
    return {
        "kind": KIND_OTS_ATTESTATION,
        "tags": [["e", event_id, relay_url], ["k", str(int(target_kind))]],
        "content": base64.b64encode(blob).decode("ascii"),
    }
