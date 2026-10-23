"""Durable host-hint recovery with real encrypted inbox state, no network."""
import dataclasses
import json
import socket
from contextlib import contextmanager

import pytest

from a4a import Agent, Keys, giftwrap, types
from a4a.dialogue import DialogueStore
from a4a.event import Event
from a4a.inbox import InboxError
from a4a_mcp.host_signal import Binding, Outcome
from a4a_mcp.wake_journal import WakeJournal, WakeBlocked, journal_status


BINDING = Binding("test-project", "test-session", "test-consumer")
ENDPOINT = "ws://127.0.0.1:9876/"
RELAY = "ws://127.0.0.1:1/never"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("journal tests forbid network")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)


@pytest.fixture
def mailbox(tmp_path):
    peer, keys = Keys(), Keys()
    agent = Agent([RELAY], keys=keys)
    with DialogueStore(tmp_path / "inbox", agent.pubkey, BINDING.consumer) as store:
        journal = WakeJournal(store, BINDING, ENDPOINT, RELAY)
        yield store, agent, peer, {peer.pubkey_hex}, journal


def add(box, delivery="one"):
    store, agent, peer, allowed, _ = box
    inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                  tags=[["p", agent.pubkey], ["d", delivery]],
                  content="private body must never enter wake journal").sign(peer)
    outer = giftwrap.wrap(inner, agent.pubkey, peer)
    assert store.accept(agent, outer, allowed, now=1) == "stored"


def begin(box, now=10, **kwargs):
    options = {"interval": 10, "per_hour": 12, **kwargs}
    return box[-1].begin(box[3], now=now, **options)


def test_empty_work_creates_no_signal_or_budget(mailbox):
    assert begin(mailbox) is None
    store = mailbox[0]
    assert store.db.execute("SELECT COUNT(*) FROM wakeups").fetchone()[0] == 0
    assert journal_status(store, now=10)["state"] == "idle"


def test_commit_precedes_send_and_crash_recovers_by_query(mailbox):
    add(mailbox)
    attempt = begin(mailbox)
    assert attempt.action == "send"
    store, _, _, allowed, journal = mailbox
    assert journal_status(store, now=10)["state"] == "unknown"
    assert store.db.execute("SELECT count FROM wakeups").fetchone()[0] == 1
    reopened = WakeJournal(store, BINDING, ENDPOINT, RELAY)
    recovered = reopened.begin(allowed, now=41, interval=10, per_hour=12)
    assert recovered.action == "query"
    assert recovered.signal == attempt.signal


def test_host_restart_resends_same_signal_only_after_absent(mailbox):
    add(mailbox)
    journal = mailbox[-1]
    first = begin(mailbox)
    journal.finish(first, Outcome("accepted", "queued"), now=11)
    assert begin(mailbox, now=20) is None
    query = begin(mailbox, now=42)
    assert query.action == "query"
    journal.finish(query, Outcome("absent", "not_found"), now=43)
    retry = begin(mailbox, now=44)
    assert retry.action == "send"
    assert retry.signal == first.signal
    assert mailbox[0].status(now=44)["pending"] == 1


def test_retained_work_queries_without_more_wakes(mailbox):
    add(mailbox)
    journal = mailbox[-1]
    first = begin(mailbox)
    journal.finish(first, Outcome("deferred", "busy"), now=11)
    for now in (50, 90, 130):
        query = begin(mailbox, now=now)
        assert query.action == "query"
        journal.finish(query, Outcome("retained", "known"), now=now)
    assert mailbox[0].db.execute("SELECT count FROM wakeups").fetchone()[0] == 1


def test_unknown_query_response_never_authorizes_resend(mailbox):
    add(mailbox)
    first = begin(mailbox)
    mailbox[-1].finish(first, Outcome("unknown", "timeout"), now=11)
    query = begin(mailbox, now=100)
    mailbox[-1].finish(query, Outcome("not_sent", "transport_failed"), now=101)
    assert begin(mailbox, now=500).action == "query"


def test_changed_rows_same_counters_get_new_signal_and_fence_old_ack(mailbox):
    add(mailbox)
    old = begin(mailbox)
    store, agent, _, allowed, journal = mailbox
    claim = store.claim(agent, BINDING.consumer, allowed, now=11)
    store.finish(claim["seq"], claim["lease_token"], BINDING.consumer, "processed", now=12)
    add(mailbox, "two")
    new = begin(mailbox, now=21)
    assert new.signal.signal_id != old.signal.signal_id
    assert not journal.finish(old, Outcome("accepted", "queued"), now=22)
    assert journal_status(store, now=22)["state"] == "unknown"


def test_revocation_prevents_recovery_and_clears_eligible_signal(mailbox):
    add(mailbox)
    first = begin(mailbox)
    journal = mailbox[-1]
    journal.finish(first, Outcome("accepted", "queued"), now=11)
    assert journal.begin(set(), now=50, interval=10, per_hour=12) is None
    assert journal_status(mailbox[0], now=50)["state"] == "idle"


def test_failure_persists_across_new_mail_and_requires_explicit_resume(mailbox):
    add(mailbox)
    first = begin(mailbox)
    journal = mailbox[-1]
    journal.finish(first, Outcome("rejected", "not_authorized"), now=11)
    add(mailbox, "two")
    with pytest.raises(WakeBlocked):
        begin(mailbox, now=100)
    reopened = WakeJournal(mailbox[0], BINDING, ENDPOINT, RELAY)
    assert journal_status(mailbox[0], now=100)["reason"] == "not_authorized"
    reopened.resume(now=101)
    resumed = reopened.begin(mailbox[3], now=102, interval=10, per_hour=12)
    assert resumed is not None


def test_binding_mismatch_never_redirects_existing_journal(mailbox):
    store = mailbox[0]
    for binding, endpoint, relay in (
        (dataclasses.replace(BINDING, target_session_id="other"), ENDPOINT, RELAY),
        (BINDING, "ws://127.0.0.1:9999/", RELAY),
        (BINDING, ENDPOINT, "ws://127.0.0.1:2/"),
    ):
        with pytest.raises(InboxError):
            WakeJournal(store, binding, endpoint, relay)


def test_budget_applies_to_absent_replays_too(mailbox):
    add(mailbox)
    journal = mailbox[-1]
    first = journal.begin(mailbox[3], now=10, interval=10, per_hour=1)
    journal.finish(first, Outcome("accepted", "queued"), now=11)
    query = journal.begin(mailbox[3], now=50, interval=10, per_hour=1)
    journal.finish(query, Outcome("absent", "not_found"), now=51)
    assert journal.begin(mailbox[3], now=100, interval=10, per_hour=1) is None
    retry = journal.begin(mailbox[3], now=3611, interval=10, per_hour=1)
    assert retry.action == "send" and retry.signal == first.signal


def test_journal_failure_rolls_back_wake_budget(mailbox, monkeypatch):
    add(mailbox)
    store = mailbox[0]
    original = store._transaction

    @contextmanager
    def fail():
        with original():
            yield
            raise InboxError("synthetic commit failure")

    with monkeypatch.context() as patch:
        patch.setattr(store, "_transaction", fail)
        with pytest.raises(InboxError):
            begin(mailbox)
    assert store.db.execute("SELECT COUNT(*) FROM wakeups").fetchone()[0] == 0
    assert begin(mailbox).action == "send"


def test_no_body_or_transport_credential_in_journal(mailbox):
    add(mailbox)
    begin(mailbox)
    row = mailbox[0].db.execute("SELECT * FROM host_wake").fetchone()
    assert "private body" not in json.dumps(dict(row))
    assert "token" not in json.dumps(journal_status(mailbox[0], now=10))


def test_managed_outgoing_only_and_active_lease(mailbox):
    store, agent, peer, allowed, journal = mailbox
    store.activate()
    lease = store.acquire(peer.pubkey_hex, "worker", allowed, now=1, lease_seconds=5)
    store.prepare_send(agent, lease["token"], "worker", allowed, "op", "private", now=2)
    assert journal.begin(allowed, now=3, interval=10, per_hour=12) is None
    attempt = begin(mailbox, now=10)
    assert attempt.signal.mode == "dialogue"
    assert attempt.signal.outgoing_prepared == 1
    assert attempt.signal.pending == attempt.signal.seq_hint == 0


def test_clock_rollback_is_not_silent_indefinite_delay(mailbox):
    add(mailbox)
    begin(mailbox, now=100)
    with pytest.raises(InboxError, match="clock"):
        begin(mailbox, now=50)


@pytest.mark.parametrize("now", [True, -1, 2**53, "10"])
def test_wake_clock_must_be_a_bounded_number(mailbox, now):
    with pytest.raises(InboxError, match="clock"):
        begin(mailbox, now=now)


def test_status_distinguishes_an_unconfigured_journal(mailbox):
    store = mailbox[0]
    store.db.execute("DROP TABLE host_wake")
    assert journal_status(store, now=10) == {
        "state": "unconfigured", "host_wake": "unverified"
    }


def test_status_rejects_a_corrupt_journal_state(mailbox):
    store = mailbox[0]
    store.db.execute("UPDATE host_wake SET state='corrupt' WHERE singleton=1")
    with pytest.raises(InboxError, match="invalid host wake journal"):
        journal_status(store, now=10)


@pytest.mark.parametrize("binding", [
    object(),
    Binding("test-project", "test-session", "other-consumer"),
])
def test_binding_must_be_typed_and_match_the_inbox_consumer(mailbox, binding):
    with pytest.raises(InboxError, match="binding differs"):
        WakeJournal(mailbox[0], binding, ENDPOINT, RELAY)


@pytest.mark.parametrize("endpoint", [None, "ws://localhost:9876/",
                                       "ws://127.0.0.1:0/", "ws://127.0.0.1:65536/"])
def test_endpoint_must_be_numeric_ipv4_loopback_with_a_valid_port(mailbox, endpoint):
    with pytest.raises(InboxError, match="numeric IPv4 loopback"):
        WakeJournal(mailbox[0], BINDING, endpoint, RELAY)


def test_begin_rejects_a_corrupt_journal_state(mailbox):
    mailbox[0].db.execute("UPDATE host_wake SET state='corrupt' WHERE singleton=1")
    with pytest.raises(InboxError, match=r"^invalid host wake journal$"):
        begin(mailbox)


@pytest.mark.parametrize("changes, message", [
    ({"interval": 9}, "interval"),
    ({"interval": 3601}, "interval"),
    ({"interval": True}, "interval"),
    ({"per_hour": 0}, "budget"),
    ({"per_hour": 61}, "budget"),
    ({"per_hour": True}, "budget"),
])
def test_begin_rejects_invalid_rate_limits(mailbox, changes, message):
    with pytest.raises(InboxError, match=message):
        begin(mailbox, **changes)


def test_finish_rejects_a_clock_rollback(mailbox):
    add(mailbox)
    attempt = begin(mailbox, now=100)
    with pytest.raises(InboxError, match="clock"):
        mailbox[-1].finish(attempt, Outcome("accepted", "queued"), now=99)


def test_resume_requires_a_persisted_rejection(mailbox):
    with pytest.raises(InboxError, match="no rejected attempt"):
        mailbox[-1].resume(now=10)
