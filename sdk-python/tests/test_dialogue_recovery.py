"""Recover from fail-closed refusal when a prepared letter can no longer be sent.

Relay-set verification deliberately fails closed: a letter prepared for one set of
operators cannot be sent through another, or an added relay would silently receive
metadata the owner never agreed to disclose.

But refusal without recovery is only half a solution. The prepared row remained in
the journal forever: `work()` always reported unfinished work, and restoring the old
relay set could send the letter after an arbitrary delay. A reviewer found this in a
live store rather than by speculation.

These tests cover the entire recovery path and its boundaries: only a prepared letter,
owned by the caller under the same lease, may be abandoned, and it never resurrects.
"""
import importlib

import network_guard
import pytest
from a4a import Agent, Keys
from a4a.inbox import InboxConflict


@pytest.fixture
def setup(tmp_path):
    api = importlib.import_module("a4a.dialogue")
    keys, peer = Keys(), Keys()
    agent = Agent(["ws://127.0.0.1:1/never"], keys=keys)
    path = tmp_path / "inbox"
    with api.DialogueStore(path, keys.pubkey_hex, "general") as store:
        store.activate()
    return api, path, agent, peer


@pytest.fixture(autouse=True)
def local_only():
    mark = len(network_guard.unexpected())
    yield
    assert not network_guard.unexpected()[mark:], "test contacted addresses it did not start"


def open_store(setup, **kwargs):
    api, path, agent, _ = setup
    return api.DialogueStore(path, agent.pubkey, "general", **kwargs)


def _prepared_under(setup, urls, operation_id="op", text="text"):
    """Prepare a letter under a specified relay set and return its lease."""
    api, path, agent, peer = setup
    agent.relay = Agent(urls, keys=agent.keys).relay
    store = open_store(setup)
    lease = store.acquire(peer.pubkey_hex, "w", {peer.pubkey_hex}, now=1)
    store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, operation_id, text, now=2)
    return store, lease, agent


def test_abandoning_a_prepared_letter_ends_the_unfinished_work(setup):
    """An abandoned letter no longer counts as unfinished work.

    This is the missing exit: previously `work()` reported a prepared letter forever,
    and the owner could not distinguish "still needs work" from "cannot be completed".
    """
    api, path, agent, peer = setup
    store, lease, agent = _prepared_under(setup, ["ws://127.0.0.1:1/never"])
    with store:
        assert store.work({peer.pubkey_hex}, now=3)[0]["outgoing"] == {"prepared": 1}
        receipt = store.abandon(agent, lease["token"], "w", {peer.pubkey_hex}, "op", now=4)
        assert receipt["state"] == "abandoned"
        assert store.work({peer.pubkey_hex}, now=5) == [], "work is still marked unfinished"


async def test_an_abandoned_letter_never_goes_out_even_if_the_old_set_returns(setup):
    """An abandoned letter stays unsent even when the original relay set returns.

    Without a terminal state, the row was a delayed shot waiting in the journal. The
    original relay set made sending possible again after an arbitrary delay and
    without the owner's knowledge.
    """
    api, path, agent, peer = setup
    store, lease, agent = _prepared_under(setup, ["ws://127.0.0.1:1/never"])
    sent = []

    async def publish(event, **kwargs):
        sent.append(event)

    with store:
        store.abandon(agent, lease["token"], "w", {peer.pubkey_hex}, "op", now=4)
        agent.relay.publish = publish
        receipt = await store.dispatch(agent, lease["token"], "w", {peer.pubkey_hex}, "op", now=5)
    assert sent == [], "abandoned letter was sent"
    assert receipt["state"] == "abandoned"


def test_only_a_prepared_letter_may_be_abandoned(setup):
    """An unknown outcome cannot be abandoned as though it were resolved.

    The relay may already hold the letter. Resolve that case by reconciliation, not
    deletion.
    """
    api, path, agent, peer = setup
    store, lease, agent = _prepared_under(setup, ["ws://127.0.0.1:1/never"])
    with store:
        seq = store.db.execute("SELECT seq FROM dialogue_outbox").fetchone()["seq"]
        for state in ("dispatching", "unknown", "relay_accepted"):
            store.db.execute("UPDATE dialogue_outbox SET state=? WHERE seq=?", (state, seq))
            with pytest.raises(InboxConflict, match="only a prepared operation"):
                store.abandon(agent, lease["token"], "w", {peer.pubkey_hex}, "op", now=4)


def test_abandoning_requires_the_same_lease_as_sending(setup):
    """Permission to abandon another lease is permission to lose its letter."""
    api, path, agent, peer = setup
    store, lease, agent = _prepared_under(setup, ["ws://127.0.0.1:1/never"])
    with store:
        with pytest.raises(InboxConflict, match="invalid dialogue lease"):
            store.abandon(agent, "foreign-token", "w", {peer.pubkey_hex}, "op", now=4)
        assert store.work({peer.pubkey_hex}, now=5)[0]["outgoing"] == {"prepared": 1}, (
            "letter was abandoned without owning the lease"
        )


def test_history_survives_abandonment(setup):
    """History survives abandonment: envelope and binding remain unchanged.

    Rewriting them would falsify the past. The journal must show that the letter was
    prepared and why it was not sent instead of pretending it never existed.
    """
    api, path, agent, peer = setup
    store, lease, agent = _prepared_under(setup, ["ws://127.0.0.1:1/never"])
    with store:
        before = store.db.execute("SELECT envelope,outer_id,relay FROM dialogue_outbox").fetchone()
        history_before = store.db.execute("SELECT COUNT(*) FROM dialogue_history").fetchone()[0]
        store.abandon(agent, lease["token"], "w", {peer.pubkey_hex}, "op", now=4)
        after = store.db.execute("SELECT envelope,outer_id,relay FROM dialogue_outbox").fetchone()
        assert tuple(after) == tuple(before), "envelope or binding was rewritten"
        assert store.db.execute("SELECT COUNT(*) FROM dialogue_history").fetchone()[0] == history_before


def test_an_abandoned_operation_id_cannot_be_reused(setup):
    """Re-preparing the same operation ID must fail rather than return an old receipt.

    Otherwise an owner who "prepared again" would receive the abandoned letter's
    receipt and believe the new work was complete.
    """
    api, path, agent, peer = setup
    store, lease, agent = _prepared_under(setup, ["ws://127.0.0.1:1/never"])
    with store:
        store.abandon(agent, lease["token"], "w", {peer.pubkey_hex}, "op", now=4)
        with pytest.raises(InboxConflict, match="was abandoned"):
            store.prepare_send(agent, lease["token"], "w", {peer.pubkey_hex}, "op", "text", now=5)


async def test_the_whole_recovery_path_from_a_changed_relay_set(setup):
    """Full path: relay set changed, send failed, old letter abandoned, new one sent.

    This is what was missing: "prepare again" used to leave the old row hanging, so
    `work()` continued reporting unfinished work even after release.
    """
    api, path, agent, peer = setup
    store, lease, agent = _prepared_under(setup, ["ws://127.0.0.1:1/never"])
    sent = []

    async def publish(event, **kwargs):
        sent.append(event)

    with store:
        wider = Agent(["ws://127.0.0.1:1/never", "ws://127.0.0.1:2/never"], keys=agent.keys)
        wider.relay.publish = publish
        with pytest.raises(InboxConflict, match="different relay"):
            await store.dispatch(wider, lease["token"], "w", {peer.pubkey_hex}, "op", now=5)

        store.abandon(agent, lease["token"], "w", {peer.pubkey_hex}, "op", now=6)
        store.prepare_send(wider, lease["token"], "w", {peer.pubkey_hex}, "op-2", "text", now=7)
        await store.dispatch(wider, lease["token"], "w", {peer.pubkey_hex}, "op-2", now=8)

        assert len(sent) == 1, "new letter was not sent"
        assert store.work({peer.pubkey_hex}, now=9) == [], (
            "unfinished work remained after recovery")
