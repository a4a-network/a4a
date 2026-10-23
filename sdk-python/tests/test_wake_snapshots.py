"""Transactional wake metadata and budgets, using synthetic identities offline."""
from contextlib import contextmanager
import hashlib
import json
import re

import network_guard
import pytest

from a4a import Agent, Keys, giftwrap, types
from a4a.dialogue import DialogueStore
from a4a.event import Event
from a4a.inbox import InboxError, InboxStore, NoticeTracker


@pytest.fixture(autouse=True)
def no_network():
    """These tests must remain fully offline, and the complete boundary is enforced.

    A local `socket.connect` stub previously guarded only one of four paths: async
    connections, datagrams, and name resolution bypassed the assertion. The suite once
    had eight such copies; one boundary now protects the entire run.
    """
    with network_guard.no_network("wake snapshot tests prohibit network"):
        yield


@pytest.fixture
def mailbox(tmp_path):
    agent = Agent(["ws://127.0.0.1:1/never"], keys=Keys())
    peer = Keys()
    with DialogueStore(tmp_path / "inbox", agent.pubkey, "test") as store:
        yield store, agent, peer, {peer.pubkey_hex}


def add(mailbox, delivery="one", expires=None):
    store, agent, peer, allowed = mailbox
    tags = [["p", agent.pubkey], ["d", delivery]]
    if expires is not None:
        tags.append(["expiration", str(expires)])
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, tags=tags,
                  content="private body must not leave the inbox").sign(peer)
    assert store.accept(agent, giftwrap.wrap(inner, agent.pubkey, peer),
                        allowed, now=1) == "stored"


def empty_notice(managed=False):
    result = {"consumer": "test", "pending": 0, "seq_hint": 0}
    if managed:
        result.update(needs_reconciliation=0, outgoing_prepared=0)
    return result


@pytest.mark.parametrize("managed", [False, True])
def test_empty_snapshot_has_closed_notice_with_zeros(mailbox, managed):
    store, _, _, allowed = mailbox
    if managed:
        store.activate()
    assert store.work_snapshot(allowed, now=10) == {
        "fingerprint": None, "notice": empty_notice(managed)}
    assert store.db.execute("SELECT count(*) FROM wakeups").fetchone()[0] == 0


def test_snapshot_is_stable_hex_metadata_and_never_spends_budget(mailbox):
    store, agent, _, allowed = mailbox
    add(mailbox)
    snapshot = store.work_snapshot(allowed, now=10)
    expected = hashlib.sha256(json.dumps([
        agent.pubkey, "test", False, [(1, "pending")], [],
    ], separators=(",", ":")).encode()).hexdigest()
    assert snapshot == {"fingerprint": expected,
                        "notice": {"consumer": "test", "pending": 1, "seq_hint": 1}}
    assert re.fullmatch(r"[0-9a-f]{64}", snapshot["fingerprint"])
    assert store.work_snapshot(allowed, now=3700) == snapshot
    with InboxStore(store.path.parent, agent.pubkey, "test") as observer:
        assert observer.work_snapshot(allowed, now=3700) == snapshot
    assert store.db.execute("SELECT count(*) FROM wakeups").fetchone()[0] == 0


def test_same_count_different_rows_changes_fingerprint(mailbox):
    store, agent, _, allowed = mailbox
    add(mailbox)
    before = store.work_snapshot(allowed, now=10)
    claim = store.claim(agent, "test", allowed, now=11)
    store.finish(claim["seq"], claim["lease_token"], "test", "processed", now=12)
    add(mailbox, "two")
    after = store.work_snapshot(allowed, now=13)
    assert before["notice"]["pending"] == after["notice"]["pending"] == 1
    assert before["fingerprint"] != after["fingerprint"]


def test_snapshot_expiry_and_revocation_are_in_callers_transaction(mailbox):
    store, _, _, allowed = mailbox
    add(mailbox, expires=10)
    add(mailbox, "revoked")
    with pytest.raises(RuntimeError, match="rollback"):
        with store._transaction():
            assert store._work_snapshot(set(), 10) == {
                "fingerprint": None, "notice": empty_notice()}
            assert [r[0] for r in store.db.execute("SELECT state FROM messages ORDER BY seq")] == ["expired", "blocked"]
            raise RuntimeError("rollback")
    assert [r[0] for r in store.db.execute("SELECT state FROM messages")] == ["pending", "pending"]
    assert store.work_snapshot(allowed, now=10)["notice"]["pending"] == 1


def test_active_legacy_lease_and_unknown_work_do_not_wake(mailbox):
    store, agent, _, allowed = mailbox
    add(mailbox)
    store.claim(agent, "test", allowed, now=10, lease_seconds=10)
    for now in (11, 20):
        assert store.work_snapshot(allowed, now=now) == {
            "fingerprint": None, "notice": empty_notice()}
    assert store.db.execute("SELECT state FROM messages").fetchone()[0] == "unknown"


def test_managed_lease_expiry_and_revocation_preserve_uncertain_work(mailbox):
    store, _, peer, allowed = mailbox
    add(mailbox)
    legacy = store.work_snapshot(allowed, now=2)
    store.activate()
    pending = store.work_snapshot(allowed, now=2)
    assert legacy["fingerprint"] != pending["fingerprint"]
    store.acquire(peer.pubkey_hex, "worker", allowed, now=3, lease_seconds=10)
    assert store.work_snapshot(allowed, now=4) == {
        "fingerprint": None, "notice": empty_notice(True)}
    expired = store.work_snapshot(allowed, now=13)
    assert expired["notice"] == dict(empty_notice(True), seq_hint=1, needs_reconciliation=1)
    assert expired["fingerprint"] not in (None, pending["fingerprint"])
    assert store.work_snapshot(set(), now=14)["fingerprint"] is None
    assert store.db.execute("SELECT state FROM messages").fetchone()[0] == "unknown"
    assert store.work_snapshot(allowed, now=15) == expired


@pytest.mark.parametrize("state", ["prepared", "dispatching", "unknown"])
def test_outgoing_only_snapshot_works_from_plain_inbox_store(mailbox, state):
    store, agent, peer, allowed = mailbox
    store.activate()
    lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1, lease_seconds=10)
    store.prepare_send(agent, lease["token"], "worker", allowed, "op", "outgoing secret", now=2)
    store.db.execute("UPDATE dialogue_outbox SET state=?", (state,))
    with InboxStore(store.path.parent, agent.pubkey, "test") as observer:
        assert observer.work_snapshot(allowed, now=3)["fingerprint"] is None
        snapshot = observer.work_snapshot(allowed, now=11)
        assert snapshot["fingerprint"] is not None
        assert snapshot["notice"] == dict(
            empty_notice(True), needs_reconciliation=int(state != "prepared"),
            outgoing_prepared=int(state == "prepared"))
        assert observer.work_snapshot(set(), now=12)["fingerprint"] is None
        assert observer.work_snapshot(allowed, now=13) == snapshot


@pytest.mark.parametrize("interval", [True, 9, 3601, 60.0, None])
def test_reservation_rejects_invalid_interval_without_writing(mailbox, interval):
    store, _, _, _ = mailbox
    with store._transaction():
        with pytest.raises(InboxError, match="interval"):
            store._reserve_wake(10, interval, 12)
    assert store.db.execute("SELECT count(*) FROM wakeups").fetchone()[0] == 0


@pytest.mark.parametrize("per_hour", [True, 0, 61, 12.0, None])
def test_reservation_rejects_invalid_budget_without_writing(mailbox, per_hour):
    store, _, _, _ = mailbox
    with store._transaction():
        with pytest.raises(InboxError, match="budget"):
            store._reserve_wake(10, 60, per_hour)
    assert store.db.execute("SELECT count(*) FROM wakeups").fetchone()[0] == 0


def test_reservation_obeys_interval_hour_boundary_and_clock_rollback(mailbox):
    store, _, _, _ = mailbox
    with store._transaction():
        assert store._reserve_wake(100, 10, 2) is True
        assert store._reserve_wake(99, 10, 2) is False
        assert store._reserve_wake(109, 10, 2) is False
        assert store._reserve_wake(110, 10, 2) is True
        assert store._reserve_wake(3699, 10, 2) is False
        assert store._reserve_wake(3700, 10, 2) is True
    assert tuple(store.db.execute("SELECT last,window,count FROM wakeups").fetchone()) == (3700, 3700, 1)


def test_snapshot_and_reservation_roll_back_together(mailbox):
    store, _, _, allowed = mailbox
    add(mailbox, expires=10)
    with pytest.raises(RuntimeError, match="journal failed"):
        with store._transaction():
            assert store._work_snapshot(allowed, 10)["fingerprint"] is None
            assert store._reserve_wake(10, 60, 12) is True
            raise RuntimeError("journal failed")
    assert store.db.execute("SELECT state FROM messages").fetchone()[0] == "pending"
    assert store.db.execute("SELECT count(*) FROM wakeups").fetchone()[0] == 0


def test_notice_uses_shared_snapshot_and_budget_after_commit(mailbox, monkeypatch):
    store, _, _, allowed = mailbox
    add(mailbox)
    seen = NoticeTracker()
    expected = store.work_snapshot(allowed, now=10)
    transaction = store._transaction
    calls = []
    reserve = store._reserve_wake

    def tracked_reserve(now, interval, per_hour):
        assert store.db.in_transaction
        calls.append((now, interval, per_hour))
        return reserve(now, interval, per_hour)

    @contextmanager
    def fail_commit():
        with transaction():
            yield
            raise InboxError("synthetic commit failure")

    monkeypatch.setattr(store, "_reserve_wake", tracked_reserve)
    with monkeypatch.context() as patch:
        patch.setattr(store, "_transaction", fail_commit)
        with pytest.raises(InboxError, match="commit failure"):
            store.notice(allowed, now=10, tracker=seen)
    assert seen._fingerprint is None
    assert store.notice(allowed, now=10, tracker=seen) == expected["notice"]
    assert calls == [(10, 60, 12), (10, 60, 12)]
    assert store.notice(allowed, now=70, tracker=seen) is None
    assert len(calls) == 2
