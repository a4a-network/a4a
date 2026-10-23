"""Cross-check our `.ots` writer against the independent SDK reader.

The format was fixed on 2026-09-04: the digest is the raw 32-byte event ID, with one
Bitcoin attestation and no pending attestation. The writer (`a4a_notary.tree`) uses the
reference OpenTimestamps library, while a collaborator implemented the reader
(`a4a.timestamp.parse_ots`) without it. If they diverge, this test fails before an
external client encounters an unreadable stamp.
"""
import base64
import os

import pytest
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.core.timestamp import Timestamp

from a4a_notary import tree

a4a_timestamp = pytest.importorskip("a4a.timestamp", reason="SDK is not installed with the notary")


def _finalized_batch(n: int = 6, height: int = 358391) -> tuple[tree.Batch, list[str]]:
    ids = [os.urandom(32).hex() for _ in range(n)]
    batch = tree.build_batch(ids)
    reply = Timestamp(batch.root_digest)
    reply.attestations.add(BitcoinBlockHeaderAttestation(height))
    tree.attach_calendar_reply(batch, reply)
    return batch, ids


def test_sdk_reader_parses_our_leaf_proof():
    batch, ids = _finalized_batch()
    for event_id in ids:
        proof = a4a_timestamp.parse_ots(tree.leaf_ots(batch, event_id))
        assert proof.digest.hex() == event_id, "reader and writer disagree on the digest"
        assert proof.digest_op == "sha256"
        kinds = {a.kind for a in proof.attestations}
        assert kinds == {"bitcoin"}, "published stamp must not contain pending: %s" % kinds
        assert {a.height for a in proof.attestations} == {358391}
        # The attestation message is the tree root, proving the leaf path reached it.
        assert all(a.msg == batch.root_digest for a in proof.attestations)


def test_sdk_reader_accepts_the_event_content_as_standard_base64():
    """Require STANDARD base64 for event content through an end-to-end check.

    The reader decodes `content` strictly with `validate=True` and rejects URL-safe
    encoding, so the writer must use the standard alphabet.
    """
    batch, ids = _finalized_batch(3)
    ev = tree.attestation_event(batch, ids[0], target_kind=31005, relay_url="wss://x")
    raw = base64.b64decode(ev["content"], validate=True)
    proof = a4a_timestamp.parse_ots(raw)
    assert proof.digest.hex() == ids[0]
    assert ["k", "31005"] in ev["tags"]
