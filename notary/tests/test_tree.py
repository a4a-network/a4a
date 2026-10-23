"""Test the notary core: event-ID Merkle tree to root stamp to per-leaf `.ots`.

The design in `docs/design/2026-09-04-ots-notary-design.md` batches all history events
into one calendar request per hour rather than one request per event. Every leaf path
uses standard OpenTimestamps operations (append, prepend, sha256), allowing an external
`ots verify` to read the proof without our library. The proof digest is the raw 32-byte
event ID, following NIP-03 and `nostr-ots`.

The calendar attestation is fake because tests do not access the network. It uses a
`BitcoinBlockHeaderAttestation(height)` object serialized by the reference library in
the same form as a real one. The SDK reader verifies through Esplora whether that block
actually existed.
"""
import base64
import os

import pytest
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.serialize import BytesDeserializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

from a4a_notary import tree

EVENT_IDS = [os.urandom(32).hex() for _ in range(7)]


def _fake_calendar_reply(root_digest: bytes, height: int = 358391) -> Timestamp:
    """Return a calendar-style Timestamp over the same message with an attestation."""
    ts = Timestamp(root_digest)
    ts.attestations.add(BitcoinBlockHeaderAttestation(height))
    return ts


def test_batch_has_one_root_for_all_leaves():
    batch = tree.build_batch(EVENT_IDS)
    assert len(batch.root_digest) == 32
    assert set(batch.leaves) == set(EVENT_IDS)
    # Every leaf must lead exactly to the batch root or the root stamp proves nothing.
    for event_id in EVENT_IDS:
        assert tree.leaf_tips(batch, event_id) == {batch.root_digest}


def test_batch_of_one_is_allowed_and_root_is_the_leaf_itself():
    batch = tree.build_batch([EVENT_IDS[0]])
    assert batch.root_digest == bytes.fromhex(EVENT_IDS[0])


def test_batch_rejects_non_canonical_ids():
    for bad in ["", "abc", EVENT_IDS[0].upper(), "+" + EVENT_IDS[0][1:], "g" * 64]:
        with pytest.raises(ValueError):
            tree.build_batch([bad])


def test_leaf_proof_carries_the_root_attestation_and_the_leaf_digest():
    batch = tree.build_batch(EVENT_IDS)
    tree.attach_calendar_reply(batch, _fake_calendar_reply(batch.root_digest, 900_000))
    for event_id in EVENT_IDS:
        blob = tree.leaf_ots(batch, event_id)
        # Read with the reference library, independently from our writer.
        detached = DetachedTimestampFile.deserialize(BytesDeserializationContext(blob))
        assert detached.file_digest == bytes.fromhex(event_id), "proof digest is not the event ID"
        attestations = [a for _, a in detached.timestamp.all_attestations()]
        assert attestations, "the leaf has no attestation; the root stamp did not reach it"
        assert all(isinstance(a, BitcoinBlockHeaderAttestation) for a in attestations)
        assert {a.height for a in attestations} == {900_000}


def test_pending_attestation_is_not_enough_to_finalize():
    """Require a Bitcoin attestation before finalizing under NIP-03.

    A calendar POST initially returns pending, which is insufficient for publishing a
    kind-1040 event.
    """
    batch = tree.build_batch(EVENT_IDS)
    pending = Timestamp(batch.root_digest)
    pending.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
    tree.attach_calendar_reply(batch, pending)
    assert not tree.is_finalized(batch)
    with pytest.raises(tree.NotFinalized):
        tree.leaf_ots(batch, EVENT_IDS[0])


def test_calendar_reply_for_a_different_digest_is_refused():
    batch = tree.build_batch(EVENT_IDS)
    with pytest.raises(ValueError):
        tree.attach_calendar_reply(batch, _fake_calendar_reply(os.urandom(32)))


def test_event_1040_is_well_formed():
    batch = tree.build_batch(EVENT_IDS)
    tree.attach_calendar_reply(batch, _fake_calendar_reply(batch.root_digest))
    ev = tree.attestation_event(batch, EVENT_IDS[0], target_kind=31004,
                                relay_url="wss://eu1.a4a.network")
    assert ev["kind"] == 1040
    assert ["e", EVENT_IDS[0], "wss://eu1.a4a.network"] in ev["tags"]
    assert ["k", "31004"] in ev["tags"]
    blob = base64.b64decode(ev["content"], validate=True)
    detached = DetachedTimestampFile.deserialize(BytesDeserializationContext(blob))
    assert detached.file_digest == bytes.fromhex(EVENT_IDS[0])
    # Kind 1040 has no expiration because it is history, as is the event it attests.
    assert all(t[0] != "expiration" for t in ev["tags"])
