"""Mutation-derived coverage for the 27 inbox guards unobserved on 2026-09-16.

Baseline 29a7662 found 45 guard-shaped conditions in ``a4a/inbox.py``.  The twelve
inbox-related suites caught 18 mutations and let 27 survive.  Every test below has
both a hostile input and a nearby accepted control; the mutation run is the proof
that the assertion observes the named guard instead of merely staying green.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from a4a import Agent, Keys, giftwrap, types
from a4a import inbox
from a4a.event import Event


@pytest.fixture
def people():
    return Keys(), Keys(), Keys()


def _letter(sender, recipient, *, text="private payload", delivery="one",
            inner_tags=None, outer_tags=None):
    tags = ([['p', recipient.pubkey_hex], ['d', delivery]]
            if inner_tags is None else inner_tags)
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, content=text, tags=tags,
                  created_at=100).sign(sender)
    return giftwrap.wrap(inner, recipient.pubkey_hex, sender, now=200000,
                         extra_tags=outer_tags), inner


def _store(tmp_path, recipient, *, name="inbox", consumer="session-a", **kwargs):
    return inbox.InboxStore(tmp_path / name, recipient.pubkey_hex, consumer, **kwargs)


def _stub_store_permissions(monkeypatch):
    """Keep constructor tests independent of the host ACL implementation."""
    monkeypatch.setattr(
        inbox, "_private_directory",
        lambda path: Path(path).mkdir(mode=0o700, parents=True, exist_ok=True))
    monkeypatch.setattr(inbox.keyfile, "harden_and_check",
                        lambda path, force=False: (True, "test-private"))


def _stub_directory_hardening_tail(monkeypatch):
    """Let _private_directory reach only the guard selected by a test."""
    monkeypatch.setattr(inbox.keyfile, "_windows_current_sid", lambda: "S-1-5-21-test")
    monkeypatch.setattr(inbox.subprocess, "run",
                        lambda *args, **kwargs: SimpleNamespace(returncode=0))
    monkeypatch.setattr(inbox.keyfile, "is_private",
                        lambda path: (True, "test-private"))


# --- lines 48 and 50: notification budget -----------------------------------------

def test_notification_interval_rejects_bool_but_accepts_the_integer_boundary(
        tmp_path, people):
    """A boolean interval otherwise bypasses the numeric wake-rate contract."""
    _, recipient, _ = people
    with _store(tmp_path, recipient) as store:
        with pytest.raises(inbox.InboxError, match="interval"):
            store.notice(set(), now=1, interval=True, per_hour=1)
        assert store.notice(set(), now=1, interval=10, per_hour=1) is None


def test_notification_hourly_budget_rejects_bool_but_accepts_one(tmp_path, people):
    """A boolean hourly budget otherwise becomes an unintended integer quota."""
    _, recipient, _ = people
    with _store(tmp_path, recipient) as store:
        with pytest.raises(inbox.InboxError, match="budget"):
            store.notice(set(), now=1, interval=10, per_hour=True)
        assert store.notice(set(), now=1, interval=10, per_hour=1) is None


# --- lines 55 and 71: private inbox directory -------------------------------------

def test_inbox_directory_refuses_a_link_before_touching_its_target(
        tmp_path, monkeypatch):
    """A linked directory could redirect ACL changes and all mailbox files elsewhere."""
    path = tmp_path / "mail"
    reported_links = {path}
    monkeypatch.setattr(Path, "is_symlink", lambda self: self in reported_links)
    monkeypatch.setattr(inbox.keyfile, "harden_and_check",
                        lambda target, force=False: (True, "test-private"))
    _stub_directory_hardening_tail(monkeypatch)

    with pytest.raises(inbox.InboxError, match="symlink"):
        inbox._private_directory(path)
    assert not path.exists()

    reported_links.clear()
    inbox._private_directory(path)
    assert path.is_dir()


@pytest.mark.parametrize("platform_name", ["nt", "posix"])
def test_inbox_directory_refuses_unverified_permissions_but_accepts_verified_ones(
        tmp_path, monkeypatch, platform_name):
    """Mailbox creation must fail closed when directory privacy cannot be established."""
    path = tmp_path / "mail"
    private = [False]
    monkeypatch.setattr(inbox.os, "name", platform_name)
    monkeypatch.setattr(inbox.keyfile, "harden_and_check",
                        lambda target, force=False: (private[0], "test-result"))
    _stub_directory_hardening_tail(monkeypatch)
    monkeypatch.setattr(inbox.keyfile, "is_private",
                        lambda target: (private[0], "test-result"))

    with pytest.raises(inbox.InboxError, match="protect inbox directory"):
        inbox._private_directory(path)

    private[0] = True
    inbox._private_directory(path)
    assert path.is_dir()


# --- lines 85, 87, 89 and 91: store binding and capacity --------------------------

def test_store_rejects_noncanonical_recipient_but_accepts_exact_pubkey(
        tmp_path, monkeypatch, people):
    """An ambiguous recipient would bind durable ciphertext to no verifiable identity."""
    _stub_store_permissions(monkeypatch)
    _, recipient, _ = people
    with pytest.raises(inbox.InboxError, match="recipient"):
        inbox.InboxStore(tmp_path / "bad", "not-a-public-key", "session-a")
    with _store(tmp_path, recipient, name="good") as store:
        assert store.recipient == recipient.pubkey_hex


def test_store_rejects_unbounded_consumer_name_but_accepts_fixed_local_name(
        tmp_path, monkeypatch, people):
    """A path-like consumer name would break the fixed local ownership binding."""
    _stub_store_permissions(monkeypatch)
    _, recipient, _ = people
    with pytest.raises(inbox.InboxError, match="consumer"):
        inbox.InboxStore(tmp_path / "bad", recipient.pubkey_hex, "other/session")
    with _store(tmp_path, recipient, name="good", consumer="session-a") as store:
        assert store.consumer == "session-a"


def test_store_rejects_boolean_item_limit_but_accepts_one_item(
        tmp_path, monkeypatch, people):
    """A JSON boolean must not silently turn the durable item ceiling into one."""
    _stub_store_permissions(monkeypatch)
    _, recipient, _ = people
    with pytest.raises(inbox.InboxError, match="item limit"):
        _store(tmp_path, recipient, name="bad", max_items=True)
    with _store(tmp_path, recipient, name="good", max_items=1) as store:
        assert store.max_items == 1


def test_store_rejects_subminimum_byte_limit_but_accepts_minimum(
        tmp_path, monkeypatch, people):
    """A tiny byte ceiling otherwise creates a mailbox that fails during normal use."""
    _stub_store_permissions(monkeypatch)
    _, recipient, _ = people
    with pytest.raises(inbox.InboxError, match="byte limit"):
        _store(tmp_path, recipient, name="bad", max_bytes=65535)
    with _store(tmp_path, recipient, name="good", max_bytes=65536) as store:
        assert store.max_bytes == 65536


# --- lines 96 and 105: database path and ACL --------------------------------------

def test_store_refuses_linked_database_path_before_opening_it(
        tmp_path, monkeypatch, people):
    """A linked SQLite name could redirect writes and permission changes to another file."""
    _, recipient, _ = people
    directory = tmp_path / "mail"
    database = directory / "inbox.sqlite3"
    reported_links = {database}
    monkeypatch.setattr(
        inbox, "_private_directory",
        lambda path: Path(path).mkdir(mode=0o700, parents=True, exist_ok=True))
    monkeypatch.setattr(Path, "is_symlink", lambda self: self in reported_links)
    monkeypatch.setattr(inbox.keyfile, "harden_and_check",
                        lambda path, force=False: (True, "test-private"))

    with pytest.raises(inbox.InboxError, match="database must not be a symlink"):
        inbox.InboxStore(directory, recipient.pubkey_hex, "session-a")
    assert not database.exists()

    reported_links.clear()
    with inbox.InboxStore(directory, recipient.pubkey_hex, "session-a") as store:
        assert store.path == database


def test_store_refuses_unverified_database_permissions_but_accepts_verified_file(
        tmp_path, monkeypatch, people):
    """The encrypted envelope database must not open after its ACL check failed."""
    _, recipient, _ = people
    private = [False]
    monkeypatch.setattr(
        inbox, "_private_directory",
        lambda path: Path(path).mkdir(mode=0o700, parents=True, exist_ok=True))
    monkeypatch.setattr(inbox.keyfile, "harden_and_check",
                        lambda path, force=False: (private[0], "test-result"))
    directory = tmp_path / "mail"

    with pytest.raises(inbox.InboxError, match="protect inbox database"):
        inbox.InboxStore(directory, recipient.pubkey_hex, "session-a")

    private[0] = True
    with inbox.InboxStore(directory, recipient.pubkey_hex, "session-a") as store:
        assert store.path.is_file()


# --- lines 158, 160, 162, 165, 171 and 177: envelope preparation ------------------

def test_prepare_rejects_wrong_decoder_identity_but_accepts_bound_identity(
        tmp_path, people):
    """A misbound decoder must fail loudly instead of silently discarding our mail."""
    sender, recipient, stranger = people
    outer, _ = _letter(sender, recipient)
    allowed = {sender.pubkey_hex}
    with _store(tmp_path, recipient) as store:
        with pytest.raises(inbox.InboxConflict, match="decoder identity"):
            store.accept(Agent(["ws://127.0.0.1:1"], keys=stranger), outer, allowed,
                         now=200001)
        assert store.accept(Agent(["ws://127.0.0.1:1"], keys=recipient), outer, allowed,
                            now=200001) == "stored"


def test_prepare_ignores_non_event_input_but_accepts_signed_event(tmp_path, people):
    """A malformed relay row must be ignored, not crash the whole history transaction."""
    sender, recipient, _ = people
    outer, _ = _letter(sender, recipient)
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with _store(tmp_path, recipient) as store:
        assert store.accept(agent, object(), allowed, now=200001) == "ignored"
        assert store.accept(agent, outer, allowed, now=200001) == "stored"


def test_off_target_oversized_outer_is_ignored_not_reported_as_our_size_failure(
        tmp_path, people):
    """Do not treat another recipient's oversized envelope as our warning signal."""
    sender, recipient, stranger = people
    ephemeral = Keys()
    content = "x" * (256 * 1024)
    off_target = Event(kind=giftwrap.KIND_GIFT_WRAP,
                       tags=[["p", stranger.pubkey_hex]], content=content,
                       created_at=100).sign(ephemeral)
    addressed = Event(kind=giftwrap.KIND_GIFT_WRAP,
                      tags=[["p", recipient.pubkey_hex]], content=content,
                      created_at=100).sign(ephemeral)
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    with _store(tmp_path, recipient) as store:
        assert store.accept(agent, off_target, {sender.pubkey_hex}, now=200001) == "ignored"
        assert store.accept(agent, addressed, {sender.pubkey_hex},
                            now=200001) == "rejected-size"


def test_malformed_outer_expiration_is_ignored_but_numeric_future_is_accepted(
        tmp_path, people):
    """A signed nonnumeric expiry must not become a permanently retained message."""
    sender, recipient, _ = people
    bad, _ = _letter(sender, recipient, outer_tags=[["expiration", "tomorrow"]])
    good, _ = _letter(sender, recipient, outer_tags=[["expiration", "300000"]])
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with _store(tmp_path, recipient) as store:
        assert store.accept(agent, bad, allowed, now=200001) == "ignored"
        assert store.accept(agent, good, allowed, now=200001) == "stored"


def test_oversized_outer_metadata_is_rejected_but_same_message_without_padding_is_stored(
        tmp_path, people):
    """Small plaintext must not smuggle an unbounded encrypted envelope through tags."""
    sender, recipient, _ = people
    padded, _ = _letter(sender, recipient,
                        outer_tags=[["padding", "x" * (256 * 1024)]])
    normal, _ = _letter(sender, recipient)
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with _store(tmp_path, recipient) as store:
        assert store.accept(agent, padded, allowed, now=200001) == "rejected-size"
        assert store.accept(agent, normal, allowed, now=200001) == "stored"


def test_prepare_rechecks_inner_recipient_from_decoder_output(tmp_path, people):
    """A decoder regression must not store a validly signed message addressed elsewhere."""
    sender, recipient, stranger = people
    wrong = Event(kind=types.KIND_PRIVATE_RUMOR, content="same payload",
                  tags=[["p", stranger.pubkey_hex], ["d", "wrong"]],
                  created_at=100).sign(sender)
    right = Event(kind=types.KIND_PRIVATE_RUMOR, content="same payload",
                  tags=[["p", recipient.pubkey_hex], ["d", "right"]],
                  created_at=100).sign(sender)
    outer = Event(kind=giftwrap.KIND_GIFT_WRAP,
                  tags=[["p", recipient.pubkey_hex]], content="decoder-stub",
                  created_at=100).sign(Keys())

    class Decoder:
        pubkey = recipient.pubkey_hex
        decoded = wrong

        def _decode_incoming(self, event):
            return {"event": self.decoded, "content": self.decoded.content,
                    "wrapped": True}

    decoder = Decoder()
    with _store(tmp_path, recipient) as store:
        assert store.accept(decoder, outer, {sender.pubkey_hex}, now=200001) == "ignored"
        decoder.decoded = right
        assert store.accept(decoder, outer, {sender.pubkey_hex}, now=200001) == "stored"


# --- lines 226, 233 and 238: relay cursor/pages -----------------------------------

def test_relay_start_rejects_negative_position_but_accepts_zero(tmp_path, people):
    """A negative cursor would make the durable history boundary ambiguous."""
    _, recipient, _ = people
    with _store(tmp_path, recipient) as store:
        with pytest.raises(inbox.InboxError, match="starting point"):
            store.bind_relay("bad-relay", -1)
        assert store.bind_relay("good-relay", 0) == (0, "")


def test_history_page_refuses_501_rows_but_accepts_500(
        tmp_path, monkeypatch, people):
    """A relay must not exceed the transactional CPU and memory batch ceiling."""
    _, recipient, _ = people
    event = SimpleNamespace(id="a" * 64)
    too_many = [(stamp, event) for stamp in range(1, 502)]
    bounded = too_many[:500]
    with _store(tmp_path, recipient) as store:
        monkeypatch.setattr(store, "_prepare", lambda *args, **kwargs: ("ignored", None))
        store.bind_relay("too-many", 0)
        with pytest.raises(inbox.InboxError, match="batch limit"):
            store.accept_page(None, "too-many", (0, ""), too_many, set(), now=1)

        store.bind_relay("bounded", 0)
        result = store.accept_page(None, "bounded", (0, ""), bounded, set(), now=1)
        assert result == ["ignored"] * 500
        assert store.cursor("bounded") == (500, event.id)


def test_history_page_rejects_nonadvancing_order_but_accepts_strict_order(
        tmp_path, monkeypatch, people):
    """Out-of-order input must not move the cursor backwards and lose later mail."""
    _, recipient, _ = people
    first = SimpleNamespace(id="a" * 64)
    second = SimpleNamespace(id="b" * 64)
    with _store(tmp_path, recipient) as store:
        monkeypatch.setattr(store, "_prepare", lambda *args, **kwargs: ("ignored", None))
        store.bind_relay("bad-order", 0)
        with pytest.raises(inbox.InboxError, match="strictly ordered"):
            store.accept_page(None, "bad-order", (0, ""),
                              [(2, second), (1, first)], set(), now=1)

        store.bind_relay("good-order", 0)
        assert store.accept_page(None, "good-order", (0, ""),
                                 [(1, first), (2, second)], set(), now=1) == [
                                     "ignored", "ignored"]
        assert store.cursor("good-order") == (2, second.id)


# --- lines 260, 262, 266 and 276: claiming work -----------------------------------

def test_claim_rejects_wrong_consumer_but_bound_consumer_gets_message(tmp_path, people):
    """A different local worker name must not take ownership of queued private work."""
    sender, recipient, _ = people
    outer, inner = _letter(sender, recipient)
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with _store(tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        with pytest.raises(inbox.InboxConflict, match="wrong inbox consumer"):
            store.claim(agent, "other-worker", allowed, now=200001)
        assert store.claim(agent, "session-a", allowed, now=200001)["inner_id"] == inner.id


def test_claim_rejects_zero_lease_but_accepts_one_second(tmp_path, people):
    """A zero lease would be stale at creation and strand the message immediately."""
    sender, recipient, _ = people
    outer, inner = _letter(sender, recipient)
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with _store(tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        with pytest.raises(inbox.InboxError, match="lease"):
            store.claim(agent, "session-a", allowed, now=200001, lease_seconds=0)
        claimed = store.claim(agent, "session-a", allowed, now=200001, lease_seconds=1)
        assert claimed["inner_id"] == inner.id and claimed["lease_until"] == 200002


def test_legacy_claim_is_closed_in_dialogue_mode_but_works_when_disabled(
        tmp_path, people):
    """Legacy leasing must not bypass the single conversation lease in dialogue mode."""
    sender, recipient, _ = people
    outer, inner = _letter(sender, recipient)
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with _store(tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        store.db.execute("INSERT INTO metadata VALUES ('dialogue_mode','1')")
        with pytest.raises(inbox.InboxConflict, match="conversation lease"):
            store.claim(agent, "session-a", allowed, now=200001)

        store.db.execute("UPDATE metadata SET value='0' WHERE key='dialogue_mode'")
        assert store.claim(agent, "session-a", allowed, now=200001)["inner_id"] == inner.id


def test_claim_refuses_tampered_digest_but_accepts_original_binding(tmp_path, people):
    """A changed durable digest must stop decryption instead of handing out altered work."""
    sender, recipient, _ = people
    outer, inner = _letter(sender, recipient)
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with _store(tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        digest = store.db.execute("SELECT digest FROM messages").fetchone()[0]
        store.db.execute("UPDATE messages SET digest=?", ("0" * 64,))
        with pytest.raises(inbox.InboxConflict, match="verification failed"):
            store.claim(agent, "session-a", allowed, now=200001)

        store.db.execute("UPDATE messages SET digest=?", (digest,))
        assert store.claim(agent, "session-a", allowed, now=200001)["inner_id"] == inner.id


# --- lines 293 and 297: completing work -------------------------------------------

def test_finish_rejects_wrong_consumer_but_bound_consumer_can_complete(tmp_path, people):
    """A different local worker must not complete another consumer's active lease."""
    sender, recipient, _ = people
    outer, _ = _letter(sender, recipient)
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with _store(tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        claimed = store.claim(agent, "session-a", allowed, now=200001)
        with pytest.raises(inbox.InboxError, match="completion"):
            store.finish(claimed["seq"], claimed["lease_token"], "other-worker",
                         "processed", now=200002)
        store.finish(claimed["seq"], claimed["lease_token"], "session-a",
                     "processed", now=200002)
        assert store.status(now=200002)["processed"] == 1


def test_legacy_finish_is_closed_in_dialogue_mode_but_works_when_disabled(
        tmp_path, people):
    """Legacy completion must not bypass dialogue fencing after the mode changes."""
    sender, recipient, _ = people
    outer, _ = _letter(sender, recipient)
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with _store(tmp_path, recipient) as store:
        store.accept(agent, outer, allowed, now=200000)
        claimed = store.claim(agent, "session-a", allowed, now=200001)
        store.db.execute("INSERT INTO metadata VALUES ('dialogue_mode','1')")
        with pytest.raises(inbox.InboxConflict, match="fenced dialogue completion"):
            store.finish(claimed["seq"], claimed["lease_token"], "session-a",
                         "processed", now=200002)

        store.db.execute("UPDATE metadata SET value='0' WHERE key='dialogue_mode'")
        store.finish(claimed["seq"], claimed["lease_token"], "session-a",
                     "processed", now=200002)
        assert store.status(now=200002)["processed"] == 1


# --- lines 544 and 552: receiver health -------------------------------------------

def test_health_rejects_unknown_state_but_accepts_ready(tmp_path, people):
    """An invented receiver state would make every reliability decision ambiguous."""
    _, recipient, _ = people
    with _store(tmp_path, recipient) as store:
        with pytest.raises(inbox.InboxError, match="receiver state"):
            store.set_health("invented", now=1)
        store.set_health("ready", now=1)
        assert store.health(now=2) == {"state": "ready", "checked_at": 1, "stale": False}


def test_health_without_observation_reports_not_started_then_accepts_real_sample(
        tmp_path, people):
    """No receiver row is an explicit third outcome, not a crash or healthy silence."""
    _, recipient, _ = people
    with _store(tmp_path, recipient) as store:
        assert store.health(now=1) == {"state": "not_started", "stale": True}
        store.set_health("ready", now=1)
        assert store.health(now=2)["state"] == "ready"


def test_health_change_is_logged_with_its_caller_repeats_are_not(tmp_path, people, caplog):
    """26.09.2026: a live receiver showed "failed" and nobody could tell which code wrote it.
    Every change of state now names the old state, the new one and the calling function."""
    import logging
    _, recipient, _ = people
    with _store(tmp_path, recipient) as store:
        with caplog.at_level(logging.INFO, logger="a4a.inbox"):
            store.set_health("ready", now=1)
            store.set_health("ready", now=2)
            store.set_health("failed", now=3)
    changes = [r.getMessage() for r in caplog.records if "receiver health" in r.getMessage()]
    assert len(changes) == 2
    assert "not_started -> ready" in changes[0]
    assert "ready -> failed" in changes[1]
    assert "test_health_change_is_logged_with_its_caller_repeats_are_not" in changes[1]
