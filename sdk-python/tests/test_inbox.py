"""Durable private inbox, tested with real signed and encrypted events."""
import importlib
import importlib.util
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from a4a import Agent, Keys, giftwrap, types
from a4a.event import Event
from wire_cases import wrapped_with_escaped_content


@pytest.fixture
def api():
    assert importlib.util.find_spec("a4a.inbox") is not None, "durable inbox is missing"
    return importlib.import_module("a4a.inbox")


@pytest.fixture
def people():
    return Keys(), Keys(), Keys()


def letter(sender, recipient, text="private payload", delivery="one", created=100):
    tags = [["p", recipient.pubkey_hex]]
    if delivery is not None:
        tags.append(["d", delivery])
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, content=text, tags=tags, created_at=created)
    inner.sign(sender)
    return giftwrap.wrap(inner, recipient.pubkey_hex, sender, now=200000), inner


def open_store(api, tmp_path, recipient, **kwargs):
    return api.InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "session-a", **kwargs)


def test_store_only_ciphertext_and_survives_reopen(api, tmp_path, people):
    sender, recipient, _ = people
    outer, inner = letter(sender, recipient, "CONFIDENTIAL-MARKER-49")
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    with open_store(api, tmp_path, recipient) as store:
        assert store.accept(agent, outer, {sender.pubkey_hex}, now=200000) == "stored"
    for path in (tmp_path / "inbox").iterdir():
        if path.is_file():
            assert b"CONFIDENTIAL-MARKER-49" not in path.read_bytes()
    with open_store(api, tmp_path, recipient) as store:
        msg = store.claim(agent, "session-a", {sender.pubkey_hex}, now=200001)
        assert msg["inner_id"] == inner.id
        assert msg["outer_id"] == outer.id
        assert msg["content"] == "CONFIDENTIAL-MARKER-49"
        assert msg["from_pubkey"] == sender.pubkey_hex


def test_duplicates_different_wraps_and_identical_text(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    one, inner = letter(sender, recipient)
    rewrap = giftwrap.wrap(inner, recipient.pubkey_hex, sender, now=200000)
    retry, _ = letter(sender, recipient, created=101)
    separate, _ = letter(sender, recipient, delivery="two")
    with open_store(api, tmp_path, recipient) as store:
        assert store.accept(agent, one, {sender.pubkey_hex}, now=200000) == "stored"
        assert store.accept(agent, rewrap, {sender.pubkey_hex}, now=200001) == "duplicate"
        assert store.accept(agent, retry, {sender.pubkey_hex}, now=200002) == "duplicate"
        assert store.accept(agent, separate, {sender.pubkey_hex}, now=200003) == "stored"
        assert store.status(now=200003)["pending"] == 2


def test_delivery_collision_does_not_overwrite(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    one, _ = letter(sender, recipient)
    changed, _ = letter(sender, recipient, text="other payload")
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, one, {sender.pubkey_hex}, now=200000)
        with pytest.raises(api.InboxConflict):
            store.accept(agent, changed, {sender.pubkey_hex}, now=200001)
        assert store.claim(agent, "session-a", {sender.pubkey_hex}, now=200002)["content"] == "private payload"


def test_sender_is_part_of_delivery_identity(api, tmp_path, people):
    sender, recipient, other = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex, other.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        for who in (sender, other):
            outer, _ = letter(who, recipient)
            assert store.accept(agent, outer, allowed, now=200000) == "stored"
        assert store.status(now=200000)["pending"] == 2


def test_missing_delivery_id_uses_inner_id(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient, delivery=None)
    with open_store(api, tmp_path, recipient) as store:
        assert store.accept(agent, outer, {sender.pubkey_hex}, now=200000) == "stored"
        assert store.accept(agent, giftwrap.wrap(inner, recipient.pubkey_hex, sender), {sender.pubkey_hex}, now=200001) == "duplicate"


@pytest.mark.parametrize("mode", ["unknown", "wrong_recipient", "bad_signature", "ack", "expired", "inner_expired", "inner_bad_expiry"])
def test_untrusted_input_never_becomes_work(api, tmp_path, people, mode):
    sender, recipient, other = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, other if mode == "wrong_recipient" else recipient)
    if mode == "bad_signature":
        outer.sig = "0" * 128
    if mode == "ack":
        inner.kind = types.KIND_ACK_RECEIPT
        inner.sign(sender)
        outer = giftwrap.wrap(inner, recipient.pubkey_hex, sender)
    if mode == "expired":
        outer = giftwrap.wrap(inner, recipient.pubkey_hex, sender,
                              extra_tags=[["expiration", "199999"]])
    if mode in ("inner_expired", "inner_bad_expiry"):
        inner.tags.append(["expiration", "199999" if mode == "inner_expired" else "invalid"])
        inner.sign(sender)
        outer = giftwrap.wrap(inner, recipient.pubkey_hex, sender)
    with open_store(api, tmp_path, recipient) as store:
        result = store.accept(agent, outer, set() if mode == "unknown" else {sender.pubkey_hex}, now=200000)
        assert result in ("blocked", "ignored")
        assert store.status(now=200000)["pending"] == 0


def test_claim_is_exclusive_and_finish_requires_token(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, _ = letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as first, open_store(api, tmp_path, recipient) as second:
        first.accept(agent, outer, allowed, now=200000)
        job = first.claim(agent, "session-a", allowed, now=200001, lease_seconds=60)
        assert second.claim(agent, "session-a", allowed, now=200002) is None
        with pytest.raises(api.InboxError):
            second.finish(job["seq"], "wrong", "session-a", "processed", now=200003)
        first.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200004)
        assert first.status(now=200005)["processed"] == 1
        assert second.claim(agent, "session-a", allowed, now=200006) is None


def test_network_completion_outbox_is_durable_fenced_and_idempotent(
        api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient, delivery="ack-outbox")
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        job = store.claim(agent, "session-a", allowed, now=200001)
        pending = store.finish(
            job["seq"], job["lease_token"], "session-a", "processed",
            now=200002, network_ack=True)
        assert pending["ack_state"] == "pending"
        assert pending["inner_id"] == inner.id
        stored = store.db.execute(
            "SELECT token_digest,state FROM completion_acks WHERE seq=?",
            (job["seq"],)).fetchone()
        assert stored["state"] == "pending"
        assert stored["token_digest"] != job["lease_token"]
        assert store.db.execute(
            "SELECT lease_token FROM messages WHERE seq=?", (job["seq"],)
        ).fetchone()[0] is None

        retried = store.finish(
            job["seq"], job["lease_token"], "session-a", "processed",
            now=200003, network_ack=True)
        assert retried["ack_state"] == "pending"
        with pytest.raises(api.InboxConflict, match="changed status"):
            store.finish(job["seq"], job["lease_token"], "session-a", "failed",
                         now=200003, network_ack=True)

        ack_id = "a" * 64
        assert store.mark_completion_ack_sent(
            job["seq"], job["lease_token"], "session-a", ack_id) == ack_id
        sent = store.finish(
            job["seq"], job["lease_token"], "session-a", "processed",
            now=200004, network_ack=True)
        assert sent["ack_state"] == "sent"
        assert sent["ack_event_id"] == ack_id
        with pytest.raises(api.InboxConflict):
            store.finish(job["seq"], "0" * 48, "session-a", "processed",
                         now=200004, network_ack=True)


def test_pending_completion_ack_recovers_after_restart_without_lease_token(
        api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient, delivery="ack-restart")
    path = tmp_path / "inbox"
    with api.InboxStore(path, recipient.pubkey_hex, "session-a") as store:
        store.accept(agent, outer, {sender.pubkey_hex}, now=200000)
        job = store.claim(agent, "session-a", {sender.pubkey_hex}, now=200001)
        store.finish(job["seq"], job["lease_token"], "session-a", "failed",
                     now=200002, network_ack=True)
        seq = job["seq"]
    del job  # Recovery must not depend on retaining the bearer token in memory.

    with api.InboxStore(path, recipient.pubkey_hex, "session-a") as reopened:
        assert reopened.pending_completion_acks("session-a") == [{
            "seq": seq,
            "status": "failed",
            "envelope": outer.model_dump_json(),
            "inner_id": inner.id,
            "delivery_id": "ack-restart",
        }]
        assert reopened.mark_completion_ack_sent_by_seq(
            seq, "session-a", "b" * 64) == "b" * 64
        assert reopened.pending_completion_acks("session-a") == []


def test_network_completion_rollback_when_ack_insert_fails(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, _ = letter(sender, recipient, delivery="ack-atomic")
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        job = store.claim(agent, "session-a", allowed, now=200001)
        # Emulate failure during completion_acks insert to verify atomicity of finish()
        store.db.execute(
            "CREATE TRIGGER fail_ack BEFORE INSERT ON completion_acks "
            "BEGIN SELECT RAISE(ABORT, 'simulated ack outbox write error'); END")
        with pytest.raises(api.InboxError, match="database operation failed"):
            store.finish(job["seq"], job["lease_token"], "session-a", "processed",
                         now=200002, network_ack=True)

        # Whole transaction must be rolled back: message remains processing with lease token, outbox empty
        row = store.db.execute(
            "SELECT state, lease_token FROM messages WHERE seq=?",
            (job["seq"],)).fetchone()
        assert row["state"] == "processing"
        assert row["lease_token"] == job["lease_token"]
        assert store.db.execute("SELECT count(*) FROM completion_acks").fetchone()[0] == 0

        # After removing failure trigger, retry succeeds atomically
        store.db.execute("DROP TRIGGER fail_ack")
        finished = store.finish(job["seq"], job["lease_token"], "session-a", "processed",
                                now=200003, network_ack=True)
        assert finished["ack_state"] == "pending"
        row_after = store.db.execute(
            "SELECT state, lease_token FROM messages WHERE seq=?",
            (job["seq"],)).fetchone()
        assert row_after["state"] == "processed"
        assert row_after["lease_token"] is None
        assert store.db.execute("SELECT count(*) FROM completion_acks").fetchone()[0] == 1


def test_pending_completion_acks_limit_is_bounded_and_checked(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        for i in range(1, 102):
            outer, _ = letter(sender, recipient, delivery=f"ack-limit-{i}", created=100 + i)
            store.accept(agent, outer, allowed, now=200000 + i)
            job = store.claim(agent, "session-a", allowed, now=200000 + i)
            store.finish(job["seq"], job["lease_token"], "session-a", "processed",
                         now=200000 + i, network_ack=True)

        # Default limit=100 caps the output at exactly 100 rows despite 101 pending items
        pending_default = store.pending_completion_acks("session-a")
        assert len(pending_default) == 100

        # Explicit limit within bounds
        assert len(store.pending_completion_acks("session-a", limit=50)) == 50
        assert len(store.pending_completion_acks("session-a", limit=1)) == 1

        # Out of bounds limits must be rejected
        with pytest.raises(api.InboxError, match="invalid completion ACK worklist request"):
            store.pending_completion_acks("session-a", limit=101)
        with pytest.raises(api.InboxError, match="invalid completion ACK worklist request"):
            store.pending_completion_acks("session-a", limit=0)
        with pytest.raises(api.InboxError, match="invalid completion ACK worklist request"):
            store.pending_completion_acks("session-a", limit=-1)
        with pytest.raises(api.InboxError, match="invalid completion ACK worklist request"):
            store.pending_completion_acks("session-a", limit="100")  # type: ignore


def test_expired_claim_is_unknown_not_automatic_reexecution(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, _ = letter(sender, recipient)
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, {sender.pubkey_hex}, now=200000)
        job = store.claim(agent, "session-a", {sender.pubkey_hex}, now=200001, lease_seconds=10)
    with open_store(api, tmp_path, recipient) as store:
        assert store.claim(agent, "session-a", {sender.pubkey_hex}, now=200012) is None
        assert store.status(now=200012)["unknown"] == 1
        with pytest.raises(api.InboxError):
            store.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200013)


def test_unknown_bindings_materializes_expired_lease_without_prior_sweep(
        api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        assert store.claim(agent, "session-a", allowed, now=200001,
                           lease_seconds=1) is not None
        assert store.db.execute("SELECT state FROM messages").fetchone()[0] == "processing"

    # The original process and its claim output are gone. Discovery itself must
    # materialize the expired lease; no status/claim/reconcile sweep runs first.
    with open_store(api, tmp_path, recipient) as store:
        assert store.unknown_bindings("session-a", now=200002) == {
            "unknown": [{"seq": 1, "inner_id": inner.id}],
            "truncated": False,
            "limit": 100,
        }


def test_unknown_bindings_are_bounded_metadata_only_and_state_filtered(
        api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        def add(delivery, created, now):
            outer, inner = letter(sender, recipient, delivery=delivery, created=created)
            assert store.accept(agent, outer, allowed, now=now) == "stored"
            return inner

        unknown_one = add("unknown-one", 101, 200000)
        store.claim(agent, "session-a", allowed, now=200001, lease_seconds=1)
        store.status(now=200002)
        unknown_two = add("unknown-two", 102, 200003)
        store.claim(agent, "session-a", allowed, now=200004, lease_seconds=1)
        store.status(now=200005)

        add("processed", 103, 200006)
        processed = store.claim(agent, "session-a", allowed, now=200007)
        store.finish(processed["seq"], processed["lease_token"], "session-a",
                     "processed", now=200008)
        add("failed", 104, 200009)
        failed = store.claim(agent, "session-a", allowed, now=200010)
        store.finish(failed["seq"], failed["lease_token"], "session-a",
                     "failed", now=200011)
        add("blocked", 105, 200012)
        assert store.claim(agent, "session-a", set(), now=200013) is None
        add("pending", 106, 200014)

        limited = store.unknown_bindings("session-a", limit=1, now=200015)
        assert limited == {"unknown": [{"seq": 1, "inner_id": unknown_one.id}],
                           "truncated": True, "limit": 1}
        complete = store.unknown_bindings("session-a", limit=100, now=200015)
        assert complete["unknown"] == [
            {"seq": 1, "inner_id": unknown_one.id},
            {"seq": 2, "inner_id": unknown_two.id},
        ]
        assert complete["truncated"] is False
        assert all(set(item) == {"seq", "inner_id"} for item in complete["unknown"])

        for consumer, limit in (("other", 1), ("session-a", 0),
                                ("session-a", 101), ("session-a", True)):
            with pytest.raises(api.InboxError, match="listing binding or limit"):
                store.unknown_bindings(consumer, limit=limit, now=200015)

        store.db.execute("INSERT INTO metadata VALUES ('dialogue_mode','1')")
        with pytest.raises(api.InboxConflict, match="dialogue"):
            store.unknown_bindings("session-a", now=200015)


def test_unknown_retry_is_exact_explicit_and_yields_the_same_message_once(
        api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        assert store.accept(agent, outer, allowed, now=200000) == "stored"
        original_digest = store.db.execute("SELECT digest FROM messages").fetchone()[0]
        original = store.claim(agent, "session-a", allowed, now=200001, lease_seconds=10)
        assert store.status(now=200012)["unknown"] == 1

        # A relay replay reaches the dedup tombstone; it is not recovery.
        assert store.accept(agent, outer, allowed, now=200012) == "duplicate"
        assert store.status(now=200012)["unknown"] == 1

        for seq, inner_id, consumer in (
                (original["seq"] + 1, inner.id, "session-a"),
                (original["seq"], "f" * 64, "session-a"),
                (original["seq"], inner.id, "other-consumer")):
            with pytest.raises(api.InboxError, match="reconciliation"):
                store.reconcile_unknown(seq, inner_id, consumer, "retry",
                                        allowed_senders=allowed, now=200012)
            assert store.status(now=200012)["unknown"] == 1

        result = store.reconcile_unknown(original["seq"], inner.id, "session-a", "retry",
                                         allowed_senders=allowed, now=200012)
        assert result == {"state": "pending", "resolution": "retry",
                          "seq": original["seq"], "inner_id": inner.id,
                          "network_ack_sent": False}
        row = store.db.execute(
            "SELECT state,lease_token,lease_until,digest FROM messages").fetchone()
        assert tuple(row) == ("pending", None, None, original_digest)

        retried = store.claim(agent, "session-a", allowed, now=200013)
        assert retried["inner_id"] == inner.id
        assert retried["content"] == original["content"] == "private payload"
        assert retried["lease_token"] != original["lease_token"]
        assert store.claim(agent, "session-a", allowed, now=200013) is None
        assert store.db.execute("SELECT digest FROM messages").fetchone()[0] == original_digest

        with pytest.raises(api.InboxConflict, match="reconciliation"):
            store.reconcile_unknown(original["seq"], inner.id, "session-a", "retry",
                                    allowed_senders=allowed, now=200013)


@pytest.mark.parametrize("state", [
    "pending", "processing", "processed", "failed", "blocked", "expired"])
@pytest.mark.parametrize("resolution", ["retry", "processed", "failed"])
def test_unknown_reconciliation_refuses_every_known_state(
        api, tmp_path, people, state, resolution):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient)
    if state == "expired":
        outer = giftwrap.wrap(inner, recipient.pubkey_hex, sender, now=200000,
                              extra_tags=[["expiration", "200002"]])
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        if state == "blocked":
            assert store.claim(agent, "session-a", set(), now=200001) is None
        elif state == "expired":
            assert store.status(now=200003)["expired"] == 1
        elif state != "pending":
            claimed = store.claim(agent, "session-a", allowed, now=200001, lease_seconds=60)
            if state in ("processed", "failed"):
                store.finish(claimed["seq"], claimed["lease_token"], "session-a", state,
                             now=200002)
        seq = store.db.execute("SELECT seq FROM messages").fetchone()[0]

        retry_policy = {"allowed_senders": allowed} if resolution == "retry" else {}
        with pytest.raises(api.InboxConflict, match="reconciliation") as refused:
            store.reconcile_unknown(seq, inner.id, "session-a", resolution,
                                    now=200003, **retry_policy)
        assert store.db.execute("SELECT state FROM messages").fetchone()[0] == state
        # The refusal names the actual state. On 24.09.2026 an operator retried a
        # letter whose lease was still running and got only "binding or state changed".
        assert f"is {state}" in str(refused.value)
        if state == "processing":
            assert "lease is still active" in str(refused.value)


def test_unknown_reconciliation_is_closed_in_dialogue_mode(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        claimed = store.claim(agent, "session-a", allowed, now=200001, lease_seconds=1)
        assert store.status(now=200003)["unknown"] == 1
        store.db.execute("INSERT INTO metadata VALUES ('dialogue_mode','1')")

        with pytest.raises(api.InboxConflict, match="dialogue"):
            store.reconcile_unknown(claimed["seq"], inner.id, "session-a", "retry",
                                    allowed_senders=allowed, now=200003)
        assert store.status(now=200003)["unknown"] == 1

        store.db.execute("UPDATE metadata SET value='0' WHERE key='dialogue_mode'")
        assert store.reconcile_unknown(
            claimed["seq"], inner.id, "session-a", "retry",
            allowed_senders=allowed, now=200003)["state"] == "pending"


@pytest.mark.parametrize("resolution", ["processed", "failed"])
def test_unknown_can_be_closed_without_returning_to_pending(
        api, tmp_path, people, resolution):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        claimed = store.claim(agent, "session-a", allowed, now=200001, lease_seconds=1)
        result = store.reconcile_unknown(claimed["seq"], inner.id, "session-a", resolution,
                                         now=200003)
        assert result["state"] == resolution
        assert result["network_ack_sent"] is False
        assert store.status(now=200003)[resolution] == 1
        assert store.status(now=200003)["pending"] == 0
        assert store.claim(agent, "session-a", allowed, now=200003) is None
        with pytest.raises(api.InboxConflict, match="reconciliation"):
            store.reconcile_unknown(claimed["seq"], inner.id, "session-a", resolution,
                                    now=200003)


def test_unknown_retry_refuses_expired_work_but_succeeds_before_expiry(
        api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    _, inner = letter(sender, recipient)
    outer = giftwrap.wrap(inner, recipient.pubkey_hex, sender, now=200000,
                          extra_tags=[["expiration", "200005"]])
    allowed = {sender.pubkey_hex}

    with api.InboxStore(tmp_path / "at-expiry", recipient.pubkey_hex, "session-a") as store:
        store.accept(agent, outer, allowed, now=200000)
        claimed = store.claim(agent, "session-a", allowed, now=200001, lease_seconds=1)
        with pytest.raises(api.InboxConflict, match="expired"):
            store.reconcile_unknown(claimed["seq"], inner.id, "session-a", "retry",
                                    allowed_senders=allowed, now=200005)
        assert store.db.execute("SELECT state FROM messages").fetchone()[0] == "unknown"
        assert store.reconcile_unknown(
            claimed["seq"], inner.id, "session-a", "processed", now=200005)[
                "state"] == "processed"

    with api.InboxStore(tmp_path / "before-expiry", recipient.pubkey_hex,
                        "session-a") as store:
        store.accept(agent, outer, allowed, now=200000)
        claimed = store.claim(agent, "session-a", allowed, now=200001, lease_seconds=1)
        assert store.reconcile_unknown(
            claimed["seq"], inner.id, "session-a", "retry",
            allowed_senders=allowed, now=200004)[
                "state"] == "pending"
        retried = store.claim(agent, "session-a", allowed, now=200004)
        assert retried["inner_id"] == inner.id
        assert retried["content"] == "private payload"


def test_unknown_retry_refuses_sender_removed_from_current_policy(
        api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        claimed = store.claim(agent, "session-a", allowed, now=200001,
                              lease_seconds=1)
        assert store.status(now=200003)["unknown"] == 1

        with pytest.raises(api.InboxError, match="binding"):
            store.reconcile_unknown(claimed["seq"], inner.id, "session-a", "retry",
                                    now=200003)
        with pytest.raises(api.InboxConflict, match="current policy"):
            store.reconcile_unknown(claimed["seq"], inner.id, "session-a", "retry",
                                    allowed_senders=set(), now=200003)
        assert store.db.execute("SELECT state FROM messages").fetchone()[0] == "unknown"

        result = store.reconcile_unknown(
            claimed["seq"], inner.id, "session-a", "retry",
            allowed_senders=allowed, now=200003)
        assert result["state"] == "pending"
        assert store.claim(agent, "session-a", allowed, now=200003)[
            "inner_id"] == inner.id


def test_unknown_reconciliation_bounds_sequence_for_sqlite(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        claimed = store.claim(agent, "session-a", allowed, now=200001,
                              lease_seconds=1)
        assert store.status(now=200003)["unknown"] == 1

        with pytest.raises(api.InboxError, match="invalid inbox reconciliation"):
            store.reconcile_unknown(2**63, inner.id, "session-a", "processed",
                                    now=200003)
        assert store.db.execute("SELECT state FROM messages").fetchone()[0] == "unknown"

        maximum = 2**63 - 1
        store.db.execute("UPDATE messages SET seq=? WHERE seq=?",
                         (maximum, claimed["seq"]))
        result = store.reconcile_unknown(maximum, inner.id, "session-a", "processed",
                                         now=200003)
        assert result["seq"] == maximum
        assert result["state"] == "processed"


def test_two_unknown_reconcilers_cannot_both_retry(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        claimed = store.claim(agent, "session-a", allowed, now=200001, lease_seconds=1)
        assert store.status(now=200003)["unknown"] == 1

    barrier = Barrier(2)

    def worker():
        with open_store(api, tmp_path, recipient) as store:
            barrier.wait(timeout=10)
            try:
                return store.reconcile_unknown(claimed["seq"], inner.id, "session-a",
                                               "retry", allowed_senders=allowed,
                                               now=200003)
            except api.InboxConflict as exc:
                return exc

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: worker(), range(2)))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert sum(isinstance(result, api.InboxConflict) for result in results) == 1
    with open_store(api, tmp_path, recipient) as store:
        assert tuple(store.db.execute(
            "SELECT state,lease_token,lease_until FROM messages").fetchone()) == (
                "pending", None, None)


def test_allowlist_revocation_applies_to_stored_work(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, _ = letter(sender, recipient)
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, {sender.pubkey_hex}, now=200000)
        assert store.claim(agent, "session-a", set(), now=200001) is None
        assert store.status(now=200001)["blocked"] == 1


def test_two_simultaneous_consumers_cannot_claim_same_work(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, _ = letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
    barrier = Barrier(2)
    def worker():
        with open_store(api, tmp_path, recipient) as store:
            barrier.wait(timeout=10)
            return store.claim(agent, "session-a", allowed, now=200001)
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: worker(), range(2)))
    assert sum(result is not None for result in results) == 1


def test_completion_at_exact_deadline_is_rejected_without_prior_sweep(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, _ = letter(sender, recipient)
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, {sender.pubkey_hex}, now=200000)
        job = store.claim(agent, "session-a", {sender.pubkey_hex}, now=200001, lease_seconds=10)
        with pytest.raises(api.InboxConflict):
            store.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200011)
        assert store.status(now=200011)["unknown"] == 1


@pytest.mark.parametrize("failure", ["disk_full", "commit"])
def test_database_failure_keeps_cursor_and_never_claims_success(api, tmp_path, people, failure):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, _ = letter(sender, recipient, text="private" * 2500)
    with open_store(api, tmp_path, recipient) as store:
        store.bind_relay(agent.relay.url, 100)
        if failure == "disk_full":
            pages = store.db.execute("PRAGMA page_count").fetchone()[0]
            store.db.execute(f"PRAGMA max_page_count={pages}")
        else:
            store.db.execute("PRAGMA foreign_keys=ON")
            store.db.execute("CREATE TABLE test_parent(id PRIMARY KEY)")
            store.db.execute("CREATE TABLE test_child(id REFERENCES test_parent(id) DEFERRABLE INITIALLY DEFERRED)")
            store.db.execute("CREATE TRIGGER test_commit_failure AFTER INSERT ON messages BEGIN INSERT INTO test_child VALUES(1); END")
        with pytest.raises(api.InboxError) as raised:
            store.accept_page(agent, agent.relay.url, (100, ""), [(200000, outer)], {sender.pubkey_hex}, now=200000)
        assert isinstance(raised.value.__cause__, sqlite3.Error)
        if failure == "disk_full":
            assert raised.value.__cause__.sqlite_errorcode == sqlite3.SQLITE_FULL
        assert store.cursor(agent.relay.url) == (100, "")
        assert store.status(now=200000)["total"] == 0


def test_active_sqlite_journal_never_contains_plaintext_or_keys(api, tmp_path, people):
    sender, recipient, _ = people
    marker = "CONFIDENTIAL-ACTIVE-JOURNAL-74"
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, _ = letter(sender, recipient, marker)
    with open_store(api, tmp_path, recipient) as store:
        with store._transaction():
            store._insert(store._prepare(agent, outer, {sender.pubkey_hex}, 200000))
            assert store.path.with_name("inbox.sqlite3-journal").exists()
            for path in store.path.parent.iterdir():
                if path.is_file():
                    data = path.read_bytes()
                    for secret in (marker, sender.privkey_hex, recipient.privkey_hex):
                        assert secret.encode() not in data


def test_oversized_network_input_does_not_block_later_allowed_mail(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    large, _ = letter(sender, recipient, text="x" * 33000, delivery="large")
    good, _ = letter(sender, recipient, delivery="good")
    with open_store(api, tmp_path, recipient) as store:
        store.bind_relay(agent.relay.url, 0)
        result = store.accept_page(agent, agent.relay.url, (0, ""), [(200000, large), (200001, good)],
                                   {sender.pubkey_hex}, now=200002)
        assert result == ["rejected-size", "stored"]
        assert store.cursor(agent.relay.url) == (200001, good.id)
        assert store.status(now=200002)["pending"] == 1


def test_non_utf8_scalar_is_rejected_without_blocking_later_mail(
        api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    poison, malformed_inner = wrapped_with_escaped_content(
        sender, recipient, "\ud800", delivery="surrogate")
    assert not malformed_inner.verify()
    good, _ = letter(sender, recipient, text="after poison", delivery="good")
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        # The inner event now fails verification before the content/storage layer.
        assert store.accept(agent, poison, allowed, now=199999) == "ignored"
        store.bind_relay(agent.relay.url, 0)
        result = store.accept_page(
            agent, agent.relay.url, (0, ""),
            [(200000, poison), (200001, good)], allowed, now=200002)
        assert result == ["ignored", "stored"]
        assert store.cursor(agent.relay.url) == (200001, good.id)
        message = store.claim(
            agent, "session-a", allowed, now=200003, lease_seconds=10)
        assert message["content"] == "after poison"


@pytest.mark.parametrize("delivery", ["untrusted\ncommands", "x" * 129, "<tag>", ""])
def test_delivery_metadata_cannot_carry_control_text(api, tmp_path, people, delivery):
    sender, recipient, _ = people
    outer, _ = letter(sender, recipient, delivery=delivery)
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    with open_store(api, tmp_path, recipient) as store:
        assert store.accept(agent, outer, {sender.pubkey_hex}, now=200000) == "ignored"
        assert store.notice({sender.pubkey_hex}, now=200001) is None


def test_store_cannot_be_rebound_to_another_identity_or_consumer(api, tmp_path, people):
    _, recipient, other = people
    with open_store(api, tmp_path, recipient):
        pass
    with pytest.raises(api.InboxError):
        api.InboxStore(tmp_path / "inbox", other.pubkey_hex, "session-a")
    with pytest.raises(api.InboxError):
        api.InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "session-b")


def test_capacity_refuses_without_losing_pending_work(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    with open_store(api, tmp_path, recipient, max_items=1) as store:
        first, _ = letter(sender, recipient)
        second, _ = letter(sender, recipient, delivery="two")
        store.accept(agent, first, {sender.pubkey_hex}, now=200000)
        with pytest.raises(api.InboxFull):
            store.accept(agent, second, {sender.pubkey_hex}, now=200001)
        assert store.status(now=200002)["pending"] == 1


def test_history_page_is_atomic_with_cursor(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    events = [letter(sender, recipient, delivery=str(i))[0] for i in range(2)]
    rows = [(200000 + i, ev) for i, ev in enumerate(events)]
    with open_store(api, tmp_path, recipient, max_items=1) as store:
        with pytest.raises(api.InboxFull):
            store.accept_page(agent, "ws://127.0.0.1:1", (0, ""), rows, {sender.pubkey_hex}, now=200010)
        assert store.cursor("ws://127.0.0.1:1") == (0, "")
        assert store.status(now=200010)["pending"] == 0


def test_history_cursor_compare_and_swap(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    event, _ = letter(sender, recipient)
    with open_store(api, tmp_path, recipient) as store:
        store.accept_page(agent, "relay", (0, ""), [(200000, event)], {sender.pubkey_hex}, now=200010)
        assert store.cursor("relay") == (200000, event.id)
        with pytest.raises(api.InboxConflict):
            store.accept_page(agent, "relay", (0, ""), [(200000, event)], {sender.pubkey_hex}, now=200011)


def test_sqlite_write_failure_is_not_success(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, _ = letter(sender, recipient)
    with open_store(api, tmp_path, recipient) as store:
        with sqlite3.connect(store.path) as db:
            db.execute("CREATE TRIGGER fail_write BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'test disk refusal'); END")
        with pytest.raises(api.InboxError):
            store.accept(agent, outer, {sender.pubkey_hex}, now=200000)
        assert store.status(now=200001)["pending"] == 0


def test_notifications_are_bounded_persistent_and_metadata_only(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        assert store.notice(allowed, now=200000, interval=60, per_hour=2) is None
        store.accept(agent, letter(sender, recipient)[0], allowed, now=200000)
        notice = store.notice(allowed, now=200000, interval=60, per_hour=2)
        assert notice == {"consumer": "session-a", "pending": 1, "seq_hint": 1}
        assert store.notice(allowed, now=200030, interval=60, per_hour=2) is None
    with open_store(api, tmp_path, recipient) as store:
        assert store.notice(allowed, now=200031, interval=60, per_hour=2) is None
        assert store.notice(allowed, now=200060, interval=60, per_hour=2)
        assert store.notice(allowed, now=200120, interval=60, per_hour=2) is None
        assert store.status(now=200120)["pending"] == 1


def test_contact_revoked_before_notification_does_not_wake(api, tmp_path, people):
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, letter(sender, recipient)[0], {sender.pubkey_hex}, now=200000)
        assert store.notice(set(), now=200001) is None


def test_wrong_inner_recipient_is_not_admitted(api, tmp_path, people):
    sender, recipient, other = people
    _, inner = letter(sender, other)
    outer = giftwrap.wrap(inner, recipient.pubkey_hex, sender)
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    with open_store(api, tmp_path, recipient) as store:
        assert store.accept(agent, outer, {sender.pubkey_hex}, now=200000) == "ignored"


def test_expired_envelope_is_not_claimed(api, tmp_path, people):
    sender, recipient, _ = people
    _, inner = letter(sender, recipient)
    outer = giftwrap.wrap(inner, recipient.pubkey_hex, sender, extra_tags=[["expiration", "200005"]])
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, {sender.pubkey_hex}, now=200000)
        assert store.claim(agent, "session-a", {sender.pubkey_hex}, now=200006) is None
        assert store.status(now=200006)["expired"] == 1


def test_release_returns_a_live_lease_to_pending_without_ack(api, tmp_path, people):
    """A consumer that certainly did not hand the letter on gives it back itself.

    24.09.2026: an integrator's bridge could not reach its hub for longer than the lease;
    the letter went to unknown and waited for a person. release() lets the bridge
    return it and claim it later.
    """
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, inner = letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        first = store.claim(agent, "session-a", allowed, now=200001, lease_seconds=60)

        assert store.release(first["seq"], first["lease_token"], "session-a",
                             now=200002) == {"seq": first["seq"], "state": "pending"}
        row = store.db.execute("SELECT state,lease_token,lease_until FROM messages").fetchone()
        assert tuple(row) == ("pending", None, None)
        assert store.db.execute("SELECT COUNT(*) FROM completion_acks").fetchone()[0] == 0

        again = store.claim(agent, "session-a", allowed, now=200003)
        assert again["inner_id"] == inner.id and again["lease_token"] != first["lease_token"]
        with pytest.raises(api.InboxConflict, match="release rejected"):
            store.release(first["seq"], first["lease_token"], "session-a", now=200004)


def test_release_after_the_lease_expired_is_refused(api, tmp_path, people):
    """After expiry nobody knows whether work ran: that is reconcile's decision."""
    sender, recipient, _ = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    outer, _ = letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with open_store(api, tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        claimed = store.claim(agent, "session-a", allowed, now=200001, lease_seconds=1)
        with pytest.raises(api.InboxConflict, match="release rejected"):
            store.release(claimed["seq"], claimed["lease_token"], "session-a", now=200005)
        assert store.status(now=200005)["unknown"] == 1
