"""Metadata-only wake snapshots; synthetic identities and no network."""
from contextlib import contextmanager

import network_guard
import pytest

from a4a import Agent, Keys, giftwrap, types
from a4a.event import Event
from a4a import inbox
from a4a.dialogue import DialogueStore


@pytest.fixture(autouse=True)
def no_network():
    """These tests must remain fully offline, and the complete boundary is enforced.

    A local `socket.connect` stub previously guarded only one of four paths: async
    connections, datagrams, and name resolution bypassed the assertion. The suite once
    had eight such copies; one boundary now protects the entire run.
    """
    with network_guard.no_network("quiet notice tests prohibit network"):
        yield


@pytest.fixture
def mailbox(tmp_path):
    peer = Keys()
    agent = Agent(["ws://127.0.0.1:1/never"], keys=Keys())
    with DialogueStore(tmp_path / "inbox", agent.pubkey, "test") as store:
        yield store, agent, peer, {peer.pubkey_hex}


def add(mailbox, delivery="one"):
    store, agent, peer, allowed = mailbox
    inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                  tags=[["p", agent.pubkey], ["d", delivery]],
                  content="private body never enters wake hint").sign(peer)
    assert store.accept(agent, giftwrap.wrap(inner, agent.pubkey, peer), allowed, now=1) == "stored"


def tracker():
    assert hasattr(inbox, "NoticeTracker"), "per-attachment tracker is missing"
    return inbox.NoticeTracker()


def test_unchanged_work_is_quiet_and_does_not_spend_quota(mailbox):
    store, _, _, allowed = mailbox
    add(mailbox)
    seen = tracker()
    assert store.notice(allowed, now=10, tracker=seen) == {"consumer": "test", "pending": 1, "seq_hint": 1}
    assert store.notice(allowed, now=70, tracker=seen) is None
    assert store.notice(allowed, now=3700, tracker=seen) is None
    assert store.db.execute("SELECT last,count FROM wakeups").fetchone()[:] == (10, 1)


def test_new_partial_and_reconnected_work_can_signal(mailbox):
    store, agent, _, allowed = mailbox
    seen = tracker()
    add(mailbox)
    assert store.notice(allowed, now=10, tracker=seen)
    add(mailbox, "two")
    assert store.notice(allowed, now=20, tracker=seen) is None
    assert store.notice(allowed, now=70, tracker=seen)["pending"] == 2
    claimed = store.claim(agent, "test", allowed, now=71)
    store.finish(claimed["seq"], claimed["lease_token"], "test", "processed", now=72)
    assert store.notice(allowed, now=130, tracker=seen)["pending"] == 1
    assert store.notice(allowed, now=190, tracker=seen) is None
    assert store.notice(allowed, now=190, tracker=tracker())["pending"] == 1


def test_commit_failure_does_not_consume_snapshot(mailbox, monkeypatch):
    store, _, _, allowed = mailbox
    add(mailbox)
    seen = tracker()
    transaction = store._transaction
    @contextmanager
    def fail_commit():
        with transaction():
            yield
            raise inbox.InboxError("synthetic commit failure")
    with monkeypatch.context() as patch:
        patch.setattr(store, "_transaction", fail_commit)
        with pytest.raises(inbox.InboxError, match="synthetic"):
            store.notice(allowed, now=10, tracker=seen)
    assert store.db.execute("SELECT count(*) FROM wakeups").fetchone()[0] == 0
    assert store.notice(allowed, now=10, tracker=seen)


def test_same_count_with_different_rows_is_new_work(mailbox):
    store, agent, _, allowed = mailbox
    seen = tracker()
    add(mailbox)
    assert store.notice(allowed, now=10, tracker=seen)["seq_hint"] == 1
    claimed = store.claim(agent, "test", allowed, now=11)
    store.finish(claimed["seq"], claimed["lease_token"], "test", "processed", now=12)
    add(mailbox, "two")
    assert store.notice(allowed, now=70, tracker=seen) == {"consumer": "test", "pending": 1, "seq_hint": 2}


def test_dialogue_mode_and_unknown_transition_change_snapshot(mailbox):
    store, _, peer, allowed = mailbox
    seen = tracker()
    add(mailbox)
    assert store.notice(allowed, now=10, tracker=seen)
    store.activate()
    hint = store.notice(allowed, now=70, tracker=seen)
    assert hint == {"consumer": "test", "pending": 1, "seq_hint": 1,
                    "needs_reconciliation": 0, "outgoing_prepared": 0}
    store.acquire(peer.pubkey_hex, "worker", allowed, now=71, lease_seconds=10)
    assert store.notice(allowed, now=130, tracker=seen) == {
        "consumer": "test", "pending": 0, "seq_hint": 1,
        "needs_reconciliation": 1, "outgoing_prepared": 0}


@pytest.mark.parametrize("state", ["prepared", "dispatching", "unknown"])
def test_outbox_only_work_survives_lease_expiry_and_policy_revocation(mailbox, state):
    store, agent, peer, allowed = mailbox
    store.activate()
    lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1, lease_seconds=10)
    store.prepare_send(agent, lease["token"], "worker", allowed, "op", "outgoing secret", now=2)
    store.db.execute("UPDATE dialogue_outbox SET state=?", (state,))
    seen = tracker()
    assert store.notice(allowed, now=3, tracker=seen) is None
    # Receiver opens InboxStore, not DialogueStore: expiry must work there too.
    with inbox.InboxStore(store.path.parent, agent.pubkey, "test") as observer:
        hint = observer.notice(allowed, now=12, tracker=seen)
        assert hint == {"consumer": "test", "pending": 0, "seq_hint": 0,
                        "needs_reconciliation": int(state != "prepared"),
                        "outgoing_prepared": int(state == "prepared")}
        assert observer.notice(allowed, now=72, tracker=seen) is None
        assert observer.notice(set(), now=73, tracker=seen) is None
        assert observer.db.execute("SELECT state FROM dialogue_outbox").fetchone()[0] == (
            "prepared" if state == "prepared" else "unknown")
        assert observer.notice(allowed, now=74, tracker=seen) == hint


def test_lease_gap_reannounces_remaining_prepared_work(mailbox):
    store, agent, peer, allowed = mailbox
    store.activate()
    lease = store.acquire(peer.pubkey_hex, "one", allowed, now=1, lease_seconds=5)
    store.prepare_send(agent, lease["token"], "one", allowed, "op", "retained", now=2)
    seen = tracker()
    assert store.notice(allowed, now=10, tracker=seen)["outgoing_prepared"] == 1
    store.acquire(peer.pubkey_hex, "two", allowed, now=11, lease_seconds=100)
    assert store.notice(allowed, now=70, tracker=seen) is None
    assert store.notice(allowed, now=112, tracker=seen)["outgoing_prepared"] == 1
