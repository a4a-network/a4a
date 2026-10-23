"""Ensure notary batches survive restart and each leaf is published exactly once."""
import os

from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation

from a4a_notary import tree
from a4a_notary.store import Store


def _ids(n=4):
    return [os.urandom(32).hex() for _ in range(n)]


def test_batch_round_trips_through_sqlite(tmp_path):
    ids = _ids()
    batch = tree.build_batch(ids)
    batch.root.attestations.add(PendingAttestation("https://a"))
    store = Store(tmp_path / "n.db")
    bid = store.add_batch(batch.root, [(i, 31004) for i in ids], ["https://a"], now=1000)
    assert all(store.known(i) for i in ids)
    assert not store.known("f" * 64)

    # Simulate restart: a new connection reads the same batch, root, and pending state.
    store.close()
    store2 = Store(tmp_path / "n.db")
    pending = store2.pending_batches()
    assert [(b, c) for b, _, c in pending] == [(bid, 1000)]
    root = pending[0][1]
    assert root.msg == batch.root_digest
    assert {a.uri for _, a in root.all_attestations() if isinstance(a, PendingAttestation)} == {"https://a"}
    assert store2.finalized_unpublished() == []


def test_finalized_batch_lists_only_unpublished_leaves(tmp_path):
    ids = sorted(_ids(3))
    batch = tree.build_batch(ids)
    batch.root.attestations.add(PendingAttestation("https://a"))  # State after submission.
    store = Store(tmp_path / "n.db")
    bid = store.add_batch(batch.root, [(i, 31000) for i in ids], ["https://a"])
    batch.root.attestations.add(BitcoinBlockHeaderAttestation(1))
    store.save_root(bid, batch.root, finalized=True, now=2000)
    assert store.pending_batches() == []

    todo = store.finalized_unpublished()
    assert len(todo) == 1 and [e for e, _ in todo[0][2]] == ids
    store.mark_published(ids[0], "1" * 64)
    todo = store.finalized_unpublished()
    assert [e for e, _ in todo[0][2]] == ids[1:]
    store.mark_published(ids[1], "2" * 64)
    store.mark_published(ids[2], "3" * 64)
    assert store.finalized_unpublished() == [], "all leaves are published; nothing remains"
    assert store.stats() == {"batches": 1, "pending": 0, "leaves": 3, "published": 3}


def test_save_root_does_not_unfinalize(tmp_path):
    ids = _ids(2)
    batch = tree.build_batch(ids)
    batch.root.attestations.add(PendingAttestation("https://a"))
    store = Store(tmp_path / "n.db")
    bid = store.add_batch(batch.root, [(i, 31005) for i in ids], ["https://a"])
    store.save_root(bid, batch.root, finalized=True, now=10)
    store.save_root(bid, batch.root, finalized=False)  # Repeated save without a block.
    assert store.pending_batches() == [], "a repeated save reset finalized_at"


def test_unsubmitted_root_is_refused_with_a_reason(tmp_path):
    """A batch no calendar accepted has nobody to query later and must not be saved."""
    import pytest
    batch = tree.build_batch(_ids(2))
    with pytest.raises(ValueError, match="not submitted"):
        Store(tmp_path / "n.db").add_batch(batch.root, [], [])


def test_cursor_defaults_to_zero_and_persists(tmp_path):
    store = Store(tmp_path / "n.db")
    assert store.cursor() == 0
    store.set_cursor(1_700_000_000)
    store.close()
    assert Store(tmp_path / "n.db").cursor() == 1_700_000_000


def test_cursor_id_preserves_digit_only_hex_and_resets_with_legacy_cursor(tmp_path):
    store = Store(tmp_path / "n.db")
    assert store.cursor_id() == ""
    store.set_cursor(100, "9" * 64)
    store.close()
    store = Store(tmp_path / "n.db")
    assert (store.cursor(), store.cursor_id()) == (100, "9" * 64)
    store.set_cursor(0)
    assert (store.cursor(), store.cursor_id()) == (0, "")
