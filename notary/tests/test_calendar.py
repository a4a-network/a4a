"""Exercise the calendar layer with fakes, without touching the network."""
import os

import pytest
from opentimestamps.calendar import CommitmentNotFoundError
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
from opentimestamps.core.op import OpAppend, OpSHA256
from opentimestamps.core.timestamp import Timestamp

from a4a_notary import calendar as cal
from a4a_notary import tree


class FakeCalendar:
    """Behave like a real calendar.

    Submission returns pending over a digest with the calendar's own operations, so
    commitment differs from root. Retrieval returns 404 before confirmation and then a
    Bitcoin attestation over the commitment.
    """

    def __init__(self, url: str, confirmed_height: int | None = None, down: bool = False):
        self.url, self.height, self.down = url, confirmed_height, down
        self.submits: list[bytes] = []
        self.commitments: dict[bytes, bytes] = {}  # commitment -> digest

    def submit(self, digest: bytes) -> Timestamp:
        if self.down:
            raise ConnectionError("calendar down")
        self.submits.append(digest)
        ts = Timestamp(digest)
        nonce = os.urandom(16)
        node = ts.ops.add(OpAppend(nonce))
        node = node.ops.add(OpSHA256())
        node.attestations.add(PendingAttestation(self.url))
        self.commitments[node.msg] = digest
        return ts

    def get_timestamp(self, commitment: bytes) -> Timestamp:
        if self.down:
            raise ConnectionError("calendar down")
        if commitment not in self.commitments:
            raise CommitmentNotFoundError("unknown commitment")
        if self.height is None:
            raise CommitmentNotFoundError("Pending confirmation in Bitcoin blockchain")
        ts = Timestamp(commitment)
        node = ts.ops.add(OpSHA256())
        node.attestations.add(BitcoinBlockHeaderAttestation(self.height))
        return ts


def test_remote_calendar_factory_constructs_without_network():
    """Positive-control factory construction without network access.

    A constructor performs no I/O and should not fail. The first live run on 2026-09-04
    reported unresponsive calendars but was actually a constructor TypeError.
    """
    c = cal.remote_calendar("https://a.pool.opentimestamps.org")
    assert hasattr(c, "submit") and hasattr(c, "get_timestamp")


def _factory(cals: dict[str, FakeCalendar]):
    return lambda url: cals[url]


def _root() -> Timestamp:
    return tree.build_batch([os.urandom(32).hex() for _ in range(4)]).root


def test_submit_merges_pending_from_every_answering_calendar():
    cals = {"a": FakeCalendar("a"), "b": FakeCalendar("b", down=True), "c": FakeCalendar("c")}
    root = _root()
    answered = cal.submit_root(root, ["a", "b", "c"], factory=_factory(cals))
    assert answered == ["a", "c"]
    uris = {a.uri for _, a in root.all_attestations() if isinstance(a, PendingAttestation)}
    assert uris == {"a", "c"}
    assert not cal.has_bitcoin_attestation(root)


def test_submit_with_all_calendars_down_raises():
    cals = {"a": FakeCalendar("a", down=True)}
    with pytest.raises(cal.NoCalendarAnswered):
        cal.submit_root(_root(), ["a"], factory=_factory(cals))


def test_submit_ignores_a_reply_about_a_different_digest():
    class Liar(FakeCalendar):
        def submit(self, digest):
            return super().submit(os.urandom(32))
    cals = {"a": Liar("a")}
    with pytest.raises(cal.NoCalendarAnswered):
        cal.submit_root(_root(), ["a"], factory=_factory(cals))


def test_upgrade_is_false_while_pending_and_true_after_the_block():
    c = FakeCalendar("a")
    cals = {"a": c}
    root = _root()
    cal.submit_root(root, ["a"], factory=_factory(cals))
    assert cal.upgrade_root(root, factory=_factory(cals)) is False, "no block exists yet"
    c.height = 900_000
    assert cal.upgrade_root(root, factory=_factory(cals)) is True
    # The attestation hangs from the commitment node, connected to the root by an
    # operation path, just as in a real .ots proof.
    heights = {a.height for _, a in root.all_attestations() if isinstance(a, BitcoinBlockHeaderAttestation)}
    assert heights == {900_000}
    # Remove pending from the calendar that returned a block so it cannot enter the proof.
    assert not [a for _, a in root.all_attestations() if isinstance(a, PendingAttestation)]


def test_upgrade_asks_the_calendar_for_the_commitment_not_the_root():
    """Query `/timestamp/<commitment>` rather than a root unknown to the calendar."""
    c = FakeCalendar("a", confirmed_height=1)
    root = _root()
    cal.submit_root(root, ["a"], factory=_factory({"a": c}))
    assert cal.upgrade_root(root, factory=_factory({"a": c})) is True
    assert root.msg not in c.commitments, "test setup requires root and commitment to differ"


def test_published_proof_keeps_exactly_one_earliest_bitcoin_attestation():
    """Keep one earliest Bitcoin attestation in the published proof.

    NIP-03 and section 2.9 require one Bitcoin attestation. Two calendars can report two
    blocks (the first live batch on 2026-09-04 returned 965428 and 965435, twice each).
    The reader uses the earliest, making the rest excess bytes rather than evidence.
    """
    from opentimestamps.core.serialize import BytesDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile
    early, late = FakeCalendar("early", confirmed_height=100), FakeCalendar("late", confirmed_height=107)
    cals = {"early": early, "late": late}
    ids = [os.urandom(32).hex() for _ in range(3)]
    batch = tree.build_batch(ids)
    cal.submit_root(batch.root, ["late", "early"], factory=_factory(cals))
    assert cal.upgrade_root(batch.root, factory=_factory(cals))
    for event_id in ids:
        d = DetachedTimestampFile.deserialize(BytesDeserializationContext(tree.leaf_ots(batch, event_id)))
        atts = [a for _, a in d.timestamp.all_attestations()]
        assert len(atts) == 1, "the proof contains more than one attestation: %r" % atts
        assert atts[0].height == 100, "the earliest attestation was not retained"


def test_leaf_proof_after_upgrade_is_readable_by_the_reference_library():
    from opentimestamps.core.serialize import BytesDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile
    c = FakeCalendar("a", confirmed_height=777)
    ids = [os.urandom(32).hex() for _ in range(5)]
    batch = tree.build_batch(ids)
    cal.submit_root(batch.root, ["a"], factory=_factory({"a": c}))
    assert cal.upgrade_root(batch.root, factory=_factory({"a": c}))
    for event_id in ids:
        d = DetachedTimestampFile.deserialize(BytesDeserializationContext(tree.leaf_ots(batch, event_id)))
        assert d.file_digest == bytes.fromhex(event_id)
        assert {a.height for _, a in d.timestamp.all_attestations()} == {777}
