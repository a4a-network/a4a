"""Inbox pruning: only by owner decision and only after export (2026-09-08).

Processed messages consume space and will eventually fill an inbox. They are also
SIGNED correspondence, the evidence the protocol exists to preserve for disputes.
Automatic age-based deletion is therefore never allowed. Manual pruning must make
accidental destruction of work impossible.

Three rules are verified independently:

1. NEVER touch unfinished work. `pending`, `processing`, and `unknown` have not been
   resolved; deleting them loses a message nobody has handled. Only terminal states
   are eligible.
2. Refuse without an export. Do not "warn and delete": warnings are read after the
   damage is already done.
3. Write the file first, then prune, never the reverse. If export cannot be written,
   remove nothing. Reversing the order loses data precisely when the disk is full,
   the one moment pruning is most likely to run.
"""
import importlib
import importlib.util
import json
import sqlite3
import sys

import pytest

from a4a import Agent, Keys, giftwrap, types
from a4a.event import Event


@pytest.fixture
def api():
    assert importlib.util.find_spec("a4a.inbox") is not None
    return importlib.import_module("a4a.inbox")


@pytest.fixture
def people():
    return Keys(), Keys()



@pytest.fixture
def compactable(api, monkeypatch):
    """Allow destructive compaction inside tests.

    Production rejects it everywhere because archive durability has not been
    established on any platform (the reviewer's explicit decision). Compaction
    behavior still needs coverage: tombstones, reclaimed bytes, and refusal to
    enable dialogues. Otherwise it could decay unnoticed until that boundary is
    established. Tests therefore open the gate EXPLICITLY for the current platform.
    """
    monkeypatch.setattr(api.InboxStore, "DURABLE_ARCHIVE_PLATFORMS", (sys.platform,))

def letter(sender, recipient, delivery, text="payload"):
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, content=text,
                  tags=[["p", recipient.pubkey_hex], ["d", delivery]], created_at=100)
    inner.sign(sender)
    return giftwrap.wrap(inner, recipient.pubkey_hex, sender, now=200000)


def stocked(api, tmp_path, sender, recipient):
    """Create three messages: processed, pending, and processing."""
    store = api.InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "session-a")
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    for n in ("done", "waiting", "busy"):
        store.accept(agent, letter(sender, recipient, n), allowed, now=200000)
    done = store.claim(agent, "session-a", allowed, now=200001)
    store.finish(done["seq"], done["lease_token"], "session-a", "processed", now=200002)
    busy = store.claim(agent, "session-a", allowed, now=200003)
    assert busy is not None
    return store, agent


def test_prune_removes_only_finished_work(api, tmp_path, people, compactable):
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    archive = tmp_path / "archive.json"
    with store:
        report = store.prune(before=200_100, archive=archive, compact=True, now=200004)
        assert report["exported"] == 1, "export did not contain exactly one terminal message"
        counts = store.status(now=200004)
        # Finding OPS-005 changed the contract on 2026-09-09. The old expectation
        # `processed == 0` locked in a BUG: the row and its completion marker
        # vanished together, allowing the message to run again. The row now remains
        # as a tombstone while only envelope bytes are reclaimed.
        assert counts["processed"] == 1, "completion marker vanished with the envelope"
        assert counts["pending"] == 1, "pending message was touched, losing work"
        assert counts["processing"] == 1, "in-flight message and its lease were touched"


def test_pending_completion_ack_keeps_envelope_until_ack_is_sent(
        api, tmp_path, people):
    sender, recipient = people
    store = api.InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "session-a")
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with store:
        store.accept(agent, letter(sender, recipient, "ack-pending"), allowed,
                     now=200000)
        job = store.claim(agent, "session-a", allowed, now=200001)
        store.finish(job["seq"], job["lease_token"], "session-a", "processed",
                     now=200002, network_ack=True)

        pending_archive = tmp_path / "pending.json"
        report = store.prune(before=200100, archive=pending_archive, now=200003)
        assert report["exported"] == 0
        assert store.db.execute(
            "SELECT envelope FROM messages WHERE seq=?", (job["seq"],)
        ).fetchone()[0]

        store.mark_completion_ack_sent(
            job["seq"], job["lease_token"], "session-a", "a" * 64)
        sent_archive = tmp_path / "sent.json"
        report = store.prune(before=200100, archive=sent_archive, now=200004)
        assert report["exported"] == 1


def test_prune_refuses_without_an_archive(api, tmp_path, people):
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    with store:
        with pytest.raises(api.InboxError, match="archive"):
            store.prune(before=200_100, archive=None, now=200004)
        assert store.status(now=200004)["processed"] == 1, "message vanished on refusal"


def test_archive_holds_the_signed_envelope_verbatim(api, tmp_path, people):
    """An evidentiary export must contain the SIGNED event verbatim."""
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    archive = tmp_path / "archive.json"
    with store:
        store.prune(before=200_100, archive=archive, now=200004)
    saved = json.loads(archive.read_text("utf-8"))
    assert len(saved["messages"]) == 1
    envelope = json.loads(saved["messages"][0]["envelope"])
    assert envelope["sig"] and envelope["id"] and envelope["kind"] == giftwrap.KIND_GIFT_WRAP
    assert saved["recipient"] == recipient.pubkey_hex


def test_nothing_is_removed_when_the_archive_cannot_be_written(api, tmp_path, people):
    """Write the file before pruning so a full disk cannot cause data loss."""
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    unwritable = tmp_path / "no-such-directory" / "archive.json"
    with store:
        with pytest.raises(OSError):
            store.prune(before=200_100, archive=unwritable, now=200004)
        assert store.status(now=200004)["processed"] == 1, "message was pruned without export"


def test_prune_respects_the_cutoff(api, tmp_path, people):
    """Leave items newer than the cutoff untouched."""
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    with store:
        report = store.prune(before=199_000, archive=tmp_path / "a.json", now=200004)
        assert report["exported"] == 0
        assert store.status(now=200004)["processed"] == 1


# --- Review findings from 2026-09-09: OPS-004, OPS-005, OPS-006 ------------

def test_prune_refuses_to_overwrite_an_existing_archive(api, tmp_path, people):
    """OPS-004: destruction can occur on SUCCESS rather than failure.

    `open(..., "w")` truncates a file. A second run with the same path and no eligible
    messages replaced evidence with an empty archive. The commit documented that a
    write failure rolled back deletion, but the actual hazard was on the other side.
    """
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    archive = tmp_path / "archive.json"
    with store:
        first = store.prune(before=200_100, archive=archive, now=200004)
        assert first["exported"] == 1
        saved = archive.read_bytes()
        with pytest.raises(api.InboxError, match="archive"):
            store.prune(before=200_100, archive=archive, now=200005)
        assert archive.read_bytes() == saved, "existing export was overwritten"


def test_pruned_message_is_still_remembered_as_done(api, tmp_path, people, compactable):
    """OPS-005: permission to reclaim storage cannot repeat completed work.

    A completed row carries two things: reclaimable bytes and the statement "this
    work is done." The old implementation deleted both while intending only one.

    Keep the marker IN THE SAME table. A separate table creates a compatibility gap:
    an older receiver with an already-open connection would not know about it and
    would accept the message again, as the reviewer noted.
    """
    sender, recipient = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    outer = letter(sender, recipient, "done")
    with api.InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "session-a") as store:
        assert store.accept(agent, outer, allowed, now=200000) == "stored"
        job = store.claim(agent, "session-a", allowed, now=200001)
        store.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200002)
        assert store.accept(agent, outer, allowed, now=200003) == "duplicate"

        store.prune(before=200_100, archive=tmp_path / "a.json", compact=True, now=200004)

        assert store.accept(agent, outer, allowed, now=200005) == "duplicate", \
            "message was accepted after pruning, so work could run twice"
        assert store.claim(agent, "session-a", allowed, now=200006) is None, \
            "pruned message was issued for work again"


def test_pruned_tombstone_still_detects_changed_content(api, tmp_path, people, compactable):
    """The same key with DIFFERENT content remains a conflict, not a duplicate."""
    sender, recipient = people
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    with api.InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "session-a") as store:
        store.accept(agent, letter(sender, recipient, "one", "first text"), allowed, now=200000)
        job = store.claim(agent, "session-a", allowed, now=200001)
        store.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200002)
        store.prune(before=200_100, archive=tmp_path / "a.json", now=200003)
        with pytest.raises(api.InboxConflict):
            store.accept(agent, letter(sender, recipient, "one", "DIFFERENT text"),
                         allowed, now=200004)


def test_prune_frees_envelope_bytes(api, tmp_path, people, compactable):
    """Reclaim envelope bytes while preserving message identity."""
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    with store:
        before_bytes = store.status(now=200004)["bytes"]
        store.prune(before=200_100, archive=tmp_path / "a.json", compact=True, now=200004)
        after = store.status(now=200005)
        assert after["bytes"] < before_bytes, "storage was not reclaimed"
        assert after["total"] == 3, "row vanished with its bytes, leaving no marker"


def test_prune_is_refused_in_dialogue_mode_through_the_base_store(api, tmp_path, people, compactable):
    """OPS-006: dialogue history references these rows.

    Refusal applies to DESTRUCTION. Export remains allowed in dialogue mode because
    it moves nothing; forbidding it would block a harmless operation.

    Emptying an envelope breaks ordinary history reads, not merely an archival view:
    `dialogue_history` references the row and fails when its content is gone.

    Exercise the BASE store because the prune command uses it. Testing only
    `DialogueStore.prune` would miss the real bypass identified in review.
    """
    from a4a.dialogue import DialogueStore

    sender, recipient = people
    path = tmp_path / "inbox"
    with DialogueStore(path, recipient.pubkey_hex, "session-a") as dialogues:
        dialogues.activate()
    with api.InboxStore(path, recipient.pubkey_hex, "session-a") as store:
        assert store.dialogue_enabled()
        with pytest.raises(api.InboxError, match="dialogue"):
            store.prune(before=200_100, archive=tmp_path / "a.json", compact=True, now=200004)
        assert not (tmp_path / "a.json").exists(), "export was created despite refusal"


def test_activation_is_refused_over_a_pruned_inbox(api, tmp_path, people, compactable):
    """OPS-006, second half: once pruning wins, activation must fail.

    Five tombstone fields cannot reconstruct complete inbound history. Enabling
    dialogues over a pruned inbox would promise history that no longer exists.
    """
    from a4a.dialogue import DialogueStore

    sender, recipient = people
    path = tmp_path / "inbox"
    # Do not add an in-flight message: dialogue activation already rejects unfinished
    # requests, which is a separate existing boundary. This test targets another one.
    with api.InboxStore(path, recipient.pubkey_hex, "session-a") as store:
        agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
        allowed = {sender.pubkey_hex}
        store.accept(agent, letter(sender, recipient, "done"), allowed, now=200000)
        job = store.claim(agent, "session-a", allowed, now=200001)
        store.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200002)
        store.prune(before=200_100, archive=tmp_path / "a.json", compact=True, now=200004)
    with DialogueStore(path, recipient.pubkey_hex, "session-a") as dialogues:
        with pytest.raises(api.InboxConflict, match="pruned"):
            dialogues.activate()
        assert not dialogues.dialogue_enabled(), "mode was enabled despite refusal"


def test_activation_over_a_fresh_inbox_still_works(api, tmp_path, people):
    """Negative control: activation still works over an unpruned inbox."""
    from a4a.dialogue import DialogueStore

    sender, recipient = people
    path = tmp_path / "inbox"
    with api.InboxStore(path, recipient.pubkey_hex, "session-a") as store:
        agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
        allowed = {sender.pubkey_hex}
        store.accept(agent, letter(sender, recipient, "done"), allowed, now=200000)
        job = store.claim(agent, "session-a", allowed, now=200001)
        store.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200002)
    with DialogueStore(path, recipient.pubkey_hex, "session-a") as dialogues:
        dialogues.activate()
        assert dialogues.dialogue_enabled()


def test_prune_checks_the_mode_inside_its_transaction(api, tmp_path, people, compactable):
    """Reviewer race: mode used to be checked BEFORE the transaction.

    Verify structure rather than scheduling luck: replace `dialogue_enabled` so it
    returns disabled for every call OUTSIDE a transaction and enabled inside one.
    If the check moves outside again, pruning succeeds and the test fails.
    """
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    real = store.dialogue_enabled

    def only_inside_transaction():
        return store.db.in_transaction

    with store:
        store.dialogue_enabled = only_inside_transaction
        try:
            with pytest.raises(api.InboxError, match="dialogue"):
                store.prune(before=200_100, archive=tmp_path / "a.json", compact=True, now=200004)
        finally:
            store.dialogue_enabled = real
        assert not (tmp_path / "a.json").exists(), "export was created despite refusal"
        assert store.status(now=200005)["bytes"] > 0, "envelope was emptied despite refusal"


def test_destructive_compaction_is_refused_until_durability_is_established(api, tmp_path, people):
    """Do not ship destruction behind an unverified durability promise.

    We `fsync` the file but not its directory, and the Windows procedure has not been
    measured. Until durability is established on a platform, compaction fails
    EVERYWHERE while export remains useful on its own. Asked explicitly whether to
    ship pruning before that boundary exists, the reviewer answered no.
    """
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    with store:
        assert api.InboxStore.DURABLE_ARCHIVE_PLATFORMS == (), \
            "a platform is declared durable without corresponding verification"
        with pytest.raises(api.InboxError, match="durable archive boundary"):
            store.prune(before=200_100, archive=tmp_path / "a.json", compact=True, now=200004)
        assert not (tmp_path / "a.json").exists(), "export was created despite refusal"
        assert store.status(now=200005)["bytes"] > 0, "envelope was emptied despite refusal"


def test_export_only_is_the_default_and_changes_nothing(api, tmp_path, people):
    """Default to export-only, a useful operation that destroys nothing."""
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    with store:
        before = store.status(now=200004)
        report = store.prune(before=200_100, archive=tmp_path / "a.json", now=200004)
        assert report["mode"] == "export-only"
        assert report["exported"] == 1
        assert report["compacted"] == 0, "compaction occurred without an explicit request"
        after = store.status(now=200005)
        assert after["bytes"] == before["bytes"], "export-only changed envelope bytes"
        assert after["compacted"] == 0
        saved = json.loads((tmp_path / "a.json").read_text("utf-8"))
        assert len(saved["messages"]) == 1, "export is empty, making the operation useless"


# --- Concurrent behavioral regression promised during review ---------------
#
# The structural check above guards the LOCATION of the check but says nothing about
# lock mode or cross-connection behavior, as the reviewer correctly noted. These
# tests use two real connections in both orderings, plus a positive control for the
# old code shape. Without it, a green result would not prove that the schedule can
# expose the defect.

def _corrupt(store):
    """Detect the impossible state: dialogues enabled with an empty envelope.

    This state broke ordinary history reads. Check the state rather than a read
    failure so the control does not depend on dialogue-interface details.
    """
    compacted = store.db.execute("SELECT COUNT(*) FROM messages WHERE envelope=''").fetchone()[0]
    return store.dialogue_enabled() and compacted > 0


def _finished_store(api, tmp_path, sender, recipient):
    path = tmp_path / "inbox"
    store = api.InboxStore(path, recipient.pubkey_hex, "session-a")
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    allowed = {sender.pubkey_hex}
    store.accept(agent, letter(sender, recipient, "done"), allowed, now=200000)
    job = store.claim(agent, "session-a", allowed, now=200001)
    store.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200002)
    return path, store


def test_old_shape_reproduces_the_corruption(api, tmp_path, people, compactable):
    """Positive control: the old pre-transaction check corrupts state."""
    from a4a.dialogue import DialogueStore

    sender, recipient = people
    path, store = _finished_store(api, tmp_path, sender, recipient)
    with store:
        # Old shape: inspect mode outside the transaction...
        assert not store.dialogue_enabled()
        with DialogueStore(path, recipient.pubkey_hex, "session-a") as other:
            other.activate()          # ...the second connection enables it...
        with store._transaction():    # ...and only now does the write begin.
            store.db.execute("UPDATE messages SET envelope='' WHERE state='processed'")
        assert _corrupt(store), "schedule does not reproduce the defect; control is empty"


def test_activation_first_blocks_compaction(api, tmp_path, people, compactable):
    from a4a.dialogue import DialogueStore

    sender, recipient = people
    path, store = _finished_store(api, tmp_path, sender, recipient)
    with store:
        with DialogueStore(path, recipient.pubkey_hex, "session-a") as other:
            other.activate()
        with pytest.raises(api.InboxError, match="dialogue"):
            store.prune(before=200_100, archive=tmp_path / "a.json",
                        compact=True, now=200004)
        assert not _corrupt(store), "state was corrupted despite refusal"
        assert not (tmp_path / "a.json").exists()


def test_compaction_first_blocks_activation(api, tmp_path, people, compactable):
    from a4a.dialogue import DialogueStore

    sender, recipient = people
    path, store = _finished_store(api, tmp_path, sender, recipient)
    with store:
        store.prune(before=200_100, archive=tmp_path / "a.json", compact=True, now=200004)
        with DialogueStore(path, recipient.pubkey_hex, "session-a") as other:
            with pytest.raises(api.InboxConflict, match="pruned"):
                other.activate()
            assert not other.dialogue_enabled()
        assert not _corrupt(store), "reverse ordering reached the corrupted state"


def test_second_writer_cannot_commit_inside_an_open_transaction(api, tmp_path, people):
    """Prove what structure alone cannot: another writer cannot enter an open
    transaction because the lock prevents it, not because scheduling was favorable."""
    from a4a.dialogue import DialogueStore

    sender, recipient = people
    path, store = _finished_store(api, tmp_path, sender, recipient)
    with store:
        with DialogueStore(path, recipient.pubkey_hex, "session-a") as other:
            other.db.execute("PRAGMA busy_timeout=200")
            store.db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(api.InboxError):
                    other.activate()
            finally:
                store.db.execute("ROLLBACK")
            assert not other.dialogue_enabled(), "mode enabled during another writer's transaction"


def _raw(store):
    """Return raw table rows WITHOUT calling status().

    The old "export changes nothing" test used `status()`, which itself expires
    records, so the measuring instrument changed the subject. The reviewer found
    this first (OPS-008). The recurring lesson is that a test built from the same
    model as the implementation merely confirms that model.
    """
    return [tuple(r) for r in store.db.execute(
        "SELECT seq,state,lease_token,envelope!='' FROM messages ORDER BY seq")]


def test_export_only_does_not_mutate_anything(api, tmp_path, people):
    """OPS-008: an export promises a copy and must not move any row.

    Expired leases and pending deadlines belong to normal inbox operations, not
    copying. The previous implementation changed `processing` to `unknown`, cleared
    the lease token, changed `pending` to `expired`, and exported two rows instead of one.
    """
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    with store:
        before = _raw(store)
        # Choose a time DEFINITELY later than both the 300-second lease and any
        # deadline. This is where the previous implementation mutated states.
        report = store.prune(before=900_000, archive=tmp_path / "a.json", now=900_000)
        assert _raw(store) == before, "export changed the table"
        assert report["exported"] == 1, "export included non-terminal work"


@pytest.mark.parametrize("value", [None, 0, 1, "", "no", "yes", [], [0], object()])
def test_compact_must_be_a_real_boolean(api, tmp_path, people, value):
    """OPS-009: validate a boolean once, before any side effect.

    An object whose `__bool__` first returned false and then true passed the gate and
    compacted. The reviewer counted six truth checks in one successful run. Validate
    type ONCE before any consequences, then use the validated value, not the original.
    """
    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    with store:
        with pytest.raises(api.InboxError, match="compact"):
            store.prune(before=200_100, archive=tmp_path / "a.json",
                        compact=value, now=200004)
        assert not (tmp_path / "a.json").exists(), "export was created after type refusal"


def test_changing_truth_object_cannot_slip_past_the_gate(api, tmp_path, people):
    """Exercise the reviewer's object: false first, then true."""
    class Flipping:
        def __init__(self):
            self.calls = 0

        def __bool__(self):
            self.calls += 1
            return self.calls > 1

    sender, recipient = people
    store, _ = stocked(api, tmp_path, sender, recipient)
    with store:
        with pytest.raises(api.InboxError, match="compact"):
            store.prune(before=200_100, archive=tmp_path / "a.json",
                        compact=Flipping(), now=200004)
        assert all(row[3] for row in _raw(store)), "envelope was emptied by bypassing the gate"


def test_export_is_allowed_in_dialogue_mode(api, tmp_path, people):
    """Allow export in dialogue mode without changing anything.

    The old prohibition was too broad. The reasoning that "history references rows"
    applies to emptying an envelope, not copying it. Review confirmed that the
    prohibition was unnecessary.
    """
    from a4a.dialogue import DialogueStore

    sender, recipient = people
    path = tmp_path / "inbox"
    with api.InboxStore(path, recipient.pubkey_hex, "session-a") as store:
        agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
        allowed = {sender.pubkey_hex}
        store.accept(agent, letter(sender, recipient, "done"), allowed, now=200000)
        job = store.claim(agent, "session-a", allowed, now=200001)
        store.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200002)
    with DialogueStore(path, recipient.pubkey_hex, "session-a") as dialogues:
        dialogues.activate()
    with api.InboxStore(path, recipient.pubkey_hex, "session-a") as store:
        assert store.dialogue_enabled()
        before = _raw(store)
        report = store.prune(before=200_100, archive=tmp_path / "a.json", now=200004)
        assert report["exported"] == 1
        assert report["mode"] == "export-only"
        assert _raw(store) == before, "export changed the table in dialogue mode"


def _assert_refused_by_the_writer_lock(outcome, what):
    """Require refusal FROM THE WRITER LOCK rather than any arbitrary failure.

    The previous version caught `Exception` and asserted only that something failed.
    A reviewer showed the weakness: replace the competitor with an immediate
    `ValueError` and the test remains green even though nobody touched the database
    or requested a lock. "The operation failed" and "the lock rejected the operation"
    are different claims; proving the first does not prove the second.

    Walk the complete `__cause__` chain and require a real SQLITE_BUSY (code 5).
    RERAISE everything else rather than counting it as success: another failure
    reason is a finding, not proof that the lock worked.
    """
    assert "result" in outcome, f"injected operation never ran; check is vacuous ({what})"
    exc = outcome["result"]
    assert exc != "committed", f"{what}: competing operation committed inside the lock"

    chain, seen = [], exc
    while isinstance(seen, BaseException) and seen not in chain:
        chain.append(seen)
        seen = seen.__cause__
    trace = " <- ".join(f"{type(e).__name__}: {e}" for e in chain)
    busy = [e for e in chain if isinstance(e, sqlite3.OperationalError)
            and getattr(e, "sqlite_errorcode", None) == 5]
    if not busy:
        raise AssertionError(
            f"{what}: refusal did NOT come from the writer lock (expected SQLITE_BUSY): {trace}"
        ) from (exc if isinstance(exc, BaseException) else None)


# --- Real operation overlap (review comment on 441b759) --------------------
#
# Earlier tests were narrower than a real race: winner orderings ran sequentially,
# the old shape used a manual UPDATE, and the lock was opened manually. Here both
# operations are REAL `prune` and `activate` calls that overlap in time: one holds a
# transaction while the other attempts to enter it.

def test_activate_cannot_slip_inside_a_running_prune(api, tmp_path, people, compactable):
    """Dialogue activation cannot commit while pruning holds the writer lock.

    The overlap is real: `activate` runs through a SECOND connection after the prune
    transaction opens and before it closes. A step INSIDE pruning is wrapped, without
    replacing its decision, to insert the competing operation in the middle.

    This fails if the mode check moves outside the transaction again or if `activate`
    stops acquiring the writer lock.
    """
    from a4a.dialogue import DialogueStore

    sender, recipient = people
    path = tmp_path / "inbox"
    store, _ = stocked(api, tmp_path, sender, recipient)
    attempted = {}
    with store:
        other = DialogueStore(path, recipient.pubkey_hex, "session-a")
        other.db.execute("PRAGMA busy_timeout=200")
        # Hook `dialogue_enabled`, which runs INSIDE the prune transaction. `_expire`
        # is unsuitable because OPS-008 removed it from pruning; a check attached to
        # that method would silently never run.
        real_enabled = store.dialogue_enabled

        def intrude():
            if store.db.in_transaction and "result" not in attempted:
                try:
                    other.activate()
                except BaseException as exc:       # noqa: BLE001 - cause inspected below
                    attempted["result"] = exc
                else:
                    attempted["result"] = "committed"
            return real_enabled()

        store.dialogue_enabled = intrude
        try:
            report = store.prune(before=200_100, archive=tmp_path / "a.json",
                                 compact=True, now=200004)
        finally:
            store.dialogue_enabled = real_enabled
            other.db.close()

    _assert_refused_by_the_writer_lock(attempted, "dialogue activation during pruning")
    assert report["compacted"] == 1, "pruning did not complete"
    # Verify the consequence, not only the attempt outcome: dialogues remain disabled
    # and the "enabled with an empty envelope" state was not reached.
    with api.InboxStore(path, recipient.pubkey_hex, "session-a") as after:
        assert not after.dialogue_enabled(), "dialogues were enabled after all"
        assert not _corrupt(after), "corrupted state was reached"


def test_prune_cannot_slip_inside_a_running_activate(api, tmp_path, people, compactable):
    """Symmetrically, pruning cannot commit while activation holds the lock.

    Insert the competing operation inside the `activate` transaction. If pruning
    succeeds, it creates exactly the corrupted state: dialogues enabled with an
    empty envelope.
    """
    from a4a.dialogue import DialogueStore

    sender, recipient = people
    path = tmp_path / "inbox"
    with api.InboxStore(path, recipient.pubkey_hex, "session-a") as prepare:
        agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
        allowed = {sender.pubkey_hex}
        prepare.accept(agent, letter(sender, recipient, "done"), allowed, now=200000)
        job = prepare.claim(agent, "session-a", allowed, now=200001)
        prepare.finish(job["seq"], job["lease_token"], "session-a", "processed", now=200002)
    store = api.InboxStore(path, recipient.pubkey_hex, "session-a")
    outcome = {}
    with store:
        store.db.execute("PRAGMA busy_timeout=200")
        with DialogueStore(path, recipient.pubkey_hex, "session-a") as other:
            # Use the standard `set_trace_callback`, invoked for every SQL statement.
            # Two earlier attempts were invalid: `activate` does not call
            # `dialogue_enabled` (the injection never ran while the test stayed green),
            # and sqlite3.Connection does not allow replacing `db.execute`.
            def intrude(statement):
                if other.db.in_transaction and "result" not in outcome:
                    try:
                        store.prune(before=200_100, archive=tmp_path / "b.json",
                                    compact=True, now=200004)
                    except BaseException as exc:   # noqa: BLE001 - cause inspected below
                        outcome["result"] = exc
                    else:
                        outcome["result"] = "committed"

            other.db.set_trace_callback(intrude)
            try:
                other.activate()
            finally:
                other.db.set_trace_callback(None)

        # Check INSIDE the `with`: afterwards the connection is closed and `_corrupt`
        # would fail on the closed database, reporting a broken test rather than the
        # state it is meant to guard.
        _assert_refused_by_the_writer_lock(outcome, "pruning during dialogue activation")
        assert not _corrupt(store), "corrupted state was reached"
