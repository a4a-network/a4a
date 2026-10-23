"""Offline organization request identity fence; no ACK or worker execution."""

import pytest

from a4a import giftwrap
from a4a.event import Event
from a4a.keys import Keys
from a4a.organization_ledger import (
    OrganizationLedgerConflict,
    OrganizationLedgerError,
    OrganizationRequestLedger,
)
from a4a.organization_mail import OrganizationLetterError


NOW = 1_800_000_000
WEEK = 7 * 24 * 3600
CONVERSATION = "c" * 64
REQUEST = "a" * 32
DELIVERY = "b" * 32


def _descriptor(owner, ingress, generation=1):
    return Event(kind=31008, content="", tags=[
        ["d", f"inbox:{generation}"], ["p", ingress.pubkey_hex],
        ["generation", str(generation)],
        ["not_before", str(NOW - 60)],
        ["expiration", str(NOW + 60)],
    ]).sign(owner)


def _inner(sender, owner, ingress, descriptor, *,
           conversation=CONVERSATION, request=REQUEST,
           delivery=DELIVERY, content="status"):
    return Event(kind=14, content=content, tags=[
        ["p", ingress.pubkey_hex], ["d", delivery],
        ["a4a_owner", owner.pubkey_hex],
        ["a4a_descriptor", descriptor.id],
        ["a4a_request", request],
        ["a4a_conversation", conversation],
    ]).sign(sender)


def _admit(ledger, inner, descriptor, ingress):
    return ledger.admit_inner(inner, descriptor, ingress.pubkey_hex,
                              now=NOW, max_validity_seconds=WEEK)


def test_same_signed_request_is_idempotent_across_restart(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    directory = tmp_path / "ledger"
    with OrganizationRequestLedger(directory, owner.pubkey_hex) as ledger:
        first = _admit(ledger, inner, descriptor, ingress)
        second = _admit(ledger, inner, descriptor, ingress)
        assert first.status == "stored"
        assert second.status == "duplicate"
        assert first.seq == second.seq
        assert second.inner_event_id == inner.id
    with OrganizationRequestLedger(directory, owner.pubkey_hex) as ledger:
        assert _admit(ledger, inner, descriptor, ingress).status == "duplicate"
        record = ledger.get(sender.pubkey_hex, CONVERSATION, REQUEST)
        assert record["inner_id"] == inner.id
        assert record["descriptor_id"] == descriptor.id
        assert record["content_sha256"]
        assert "content" not in record and "envelope" not in record


def test_same_request_id_with_changed_signed_event_is_conflict(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        first = _inner(sender, owner, ingress, descriptor)
        assert _admit(ledger, first, descriptor, ingress).status == "stored"
        changed = _inner(sender, owner, ingress, descriptor,
                         delivery="d" * 32, content="status changed")
        with pytest.raises(OrganizationLedgerConflict, match="logical request"):
            _admit(ledger, changed, descriptor, ingress)
        assert ledger.get(sender.pubkey_hex, CONVERSATION, REQUEST)["inner_id"] == first.id


def test_rotated_ingress_uses_same_owner_ledger_and_fences_cross_key_retry(tmp_path):
    owner, old_ingress, new_ingress, sender = Keys(), Keys(), Keys(), Keys()
    old_proof = _descriptor(owner, old_ingress, 1)
    new_proof = _descriptor(owner, new_ingress, 2)
    old = _inner(sender, owner, old_ingress, old_proof)
    moved = _inner(sender, owner, new_ingress, new_proof, delivery="d" * 32)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        _admit(ledger, old, old_proof, old_ingress)
        with pytest.raises(OrganizationLedgerConflict, match="logical request"):
            _admit(ledger, moved, new_proof, new_ingress)
        assert ledger.get(sender.pubkey_hex, CONVERSATION, REQUEST)["ingress"] == old_ingress.pubkey_hex


def test_delivery_id_reuse_for_different_request_is_conflict(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        _admit(ledger, _inner(sender, owner, ingress, descriptor), descriptor, ingress)
        other = _inner(sender, owner, ingress, descriptor, request="e" * 32)
        with pytest.raises(OrganizationLedgerConflict, match="delivery ID"):
            _admit(ledger, other, descriptor, ingress)


def test_sender_and_conversation_are_part_of_logical_identity(tmp_path):
    owner, ingress, first_sender, second_sender = Keys(), Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        one = _inner(first_sender, owner, ingress, descriptor)
        another_sender = _inner(second_sender, owner, ingress, descriptor)
        another_conversation = _inner(first_sender, owner, ingress, descriptor,
                                      conversation="f" * 64, delivery="d" * 32)
        assert _admit(ledger, one, descriptor, ingress).status == "stored"
        assert _admit(ledger, another_sender, descriptor, ingress).status == "stored"
        assert _admit(ledger, another_conversation, descriptor, ingress).status == "stored"
        assert len({ledger.get(first_sender.pubkey_hex, CONVERSATION, REQUEST)["seq"],
                    ledger.get(second_sender.pubkey_hex, CONVERSATION, REQUEST)["seq"],
                    ledger.get(first_sender.pubkey_hex, "f" * 64, REQUEST)["seq"]}) == 3


def test_competing_local_connections_serialize_duplicate_and_conflict(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    directory = tmp_path / "ledger"
    with OrganizationRequestLedger(directory, owner.pubkey_hex) as first, \
            OrganizationRequestLedger(directory, owner.pubkey_hex) as second:
        inner = _inner(sender, owner, ingress, descriptor)
        assert _admit(first, inner, descriptor, ingress).status == "stored"
        assert _admit(second, inner, descriptor, ingress).status == "duplicate"
        with pytest.raises(OrganizationLedgerConflict):
            _admit(second, _inner(sender, owner, ingress, descriptor,
                                  delivery="d" * 32), descriptor, ingress)


def test_invalid_route_does_not_store_and_capacity_does_not_forget_duplicates(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex,
                                   max_items=1) as ledger:
        bad = _inner(sender, owner, Keys(), descriptor)
        with pytest.raises(OrganizationLetterError):
            _admit(ledger, bad, descriptor, ingress)
        assert ledger.get(sender.pubkey_hex, CONVERSATION, REQUEST) is None
        assert _admit(ledger, inner, descriptor, ingress).status == "stored"
        assert _admit(ledger, inner, descriptor, ingress).status == "duplicate"
        other = _inner(Keys(), owner, ingress, descriptor)
        with pytest.raises(OrganizationLedgerError, match="capacity"):
            _admit(ledger, other, descriptor, ingress)


def test_one_database_cannot_be_reopened_as_another_owner(tmp_path):
    owner = Keys()
    directory = tmp_path / "ledger"
    with OrganizationRequestLedger(directory, owner.pubkey_hex):
        pass
    with pytest.raises(OrganizationLedgerConflict, match="another owner"):
        OrganizationRequestLedger(directory, Keys().pubkey_hex)


def test_encrypted_original_and_route_proof_survive_restart(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    outer = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW)
    directory = tmp_path / "ledger"
    with OrganizationRequestLedger(directory, owner.pubkey_hex) as ledger:
        result = ledger.admit_envelope(outer, descriptor, ingress,
                                       now=NOW, max_validity_seconds=WEEK)
        assert result.status == "stored"
        assert result.envelope_retained is True
        assert ledger.get(sender.pubkey_hex, CONVERSATION, REQUEST)["envelope_retained"] == 1
    with OrganizationRequestLedger(directory, owner.pubkey_hex) as ledger:
        recovered_outer, recovered_descriptor = ledger.load_envelope(result.seq)
        assert recovered_outer.id == outer.id
        assert recovered_descriptor.id == descriptor.id
        assert giftwrap.unwrap(recovered_outer, ingress).id == inner.id
        rewrapped = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW)
        retry = ledger.admit_envelope(rewrapped, descriptor, ingress,
                                      now=NOW, max_validity_seconds=WEEK)
        assert retry.status == "duplicate"
        assert retry.seq == result.seq
        assert retry.envelope_retained is True
        assert ledger.load_envelope(result.seq)[0].id == outer.id


def test_verified_original_reopens_with_historical_route_proof(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    outer = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW)
    directory = tmp_path / "ledger"
    with OrganizationRequestLedger(directory, owner.pubkey_hex) as ledger:
        record = ledger.admit_envelope(outer, descriptor, ingress,
                                       now=NOW, max_validity_seconds=WEEK)
    with OrganizationRequestLedger(directory, owner.pubkey_hex) as ledger:
        original = ledger.load_verified_original(
            record.seq, ingress, max_validity_seconds=WEEK)
        assert (original.inner.id, original.outer.id, original.descriptor.id,
                original.first_seen) == (inner.id, outer.id, descriptor.id, NOW)
        assert inner.content not in repr(original)
        with pytest.raises(OrganizationLedgerError, match="ingress key"):
            ledger.load_verified_original(record.seq, Keys(),
                                          max_validity_seconds=WEEK)
        assert ledger.load_verified_original(999, ingress,
                                             max_validity_seconds=WEEK) is None


def test_verified_original_rejects_swapped_valid_envelope(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    outer = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = ledger.admit_envelope(outer, descriptor, ingress,
                                       now=NOW, max_validity_seconds=WEEK)
        changed = _inner(sender, owner, ingress, descriptor, delivery="d" * 32)
        swapped = giftwrap.wrap(changed, ingress.pubkey_hex, sender, now=NOW)
        ledger.db.execute("""UPDATE request_envelopes SET outer_id=?, envelope=?
            WHERE seq=?""", (swapped.id, swapped.model_dump_json(), record.seq))
        # Both signatures are valid, but the decrypted original is not this request.
        assert ledger.load_envelope(record.seq)[0].id == swapped.id
        with pytest.raises(OrganizationLedgerError, match="stored request"):
            ledger.load_verified_original(record.seq, ingress,
                                          max_validity_seconds=WEEK)


def test_verified_original_rejects_replaced_outer_route(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    outer = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = ledger.admit_envelope(outer, descriptor, ingress,
                                       now=NOW, max_validity_seconds=WEEK)
        outer.tags.append(["p", ingress.pubkey_hex])
        outer.sign(sender)
        ledger.db.execute("""UPDATE request_envelopes SET outer_id=?, envelope=?
            WHERE seq=?""", (outer.id, outer.model_dump_json(), record.seq))
        assert ledger.load_envelope(record.seq)[0].id == outer.id
        with pytest.raises(OrganizationLedgerError, match="recipient is ambiguous"):
            ledger.load_verified_original(record.seq, ingress,
                                          max_validity_seconds=WEEK)


def test_verified_original_refuses_invalid_admission_time_and_metadata_only(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = _admit(ledger, inner, descriptor, ingress)
        assert ledger.load_verified_original(record.seq, ingress,
                                             max_validity_seconds=WEEK) is None
        outer = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW)
        ledger.admit_envelope(outer, descriptor, ingress,
                              now=NOW, max_validity_seconds=WEEK)
        ledger.db.execute("UPDATE requests SET first_seen=? WHERE seq=?",
                          (str(NOW + 120), record.seq))
        with pytest.raises(OrganizationLedgerError, match="historical route proof"):
            ledger.load_verified_original(record.seq, ingress,
                                          max_validity_seconds=WEEK)


def test_metadata_only_record_can_be_upgraded_by_the_same_verified_envelope(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    outer = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        first = _admit(ledger, inner, descriptor, ingress)
        assert first.envelope_retained is False
        assert ledger.load_envelope(first.seq) is None
        upgraded = ledger.admit_envelope(outer, descriptor, ingress,
                                         now=NOW, max_validity_seconds=WEEK)
        assert upgraded.status == "envelope_added"
        assert upgraded.seq == first.seq
        assert upgraded.envelope_retained is True
        assert ledger.get(sender.pubkey_hex, CONVERSATION, REQUEST)["envelope_retained"] == 1


@pytest.mark.parametrize("fault", ["other_recipient", "duplicate_p", "public_owner",
                                   "expired", "tampered"])
def test_invalid_outer_envelope_never_creates_a_request(tmp_path, fault):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    if fault == "other_recipient":
        outer = giftwrap.wrap(inner, Keys().pubkey_hex, sender, now=NOW)
    elif fault == "expired":
        outer = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW,
                              extra_tags=[["expiration", str(NOW - 1)]])
    else:
        outer = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW)
        if fault == "duplicate_p":
            outer.tags.append(["p", ingress.pubkey_hex])
        elif fault == "public_owner":
            outer.tags.append(["a4a_owner", owner.pubkey_hex])
        else:
            outer.content = "tampered"
        if fault != "tampered":
            outer.sign(sender)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        with pytest.raises(OrganizationLedgerError):
            ledger.admit_envelope(outer, descriptor, ingress,
                                  now=NOW, max_validity_seconds=WEEK)
        assert ledger.get(sender.pubkey_hex, CONVERSATION, REQUEST) is None


def test_conflicting_envelope_does_not_replace_retained_original(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    outer = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW)
    changed = _inner(sender, owner, ingress, descriptor,
                     delivery="d" * 32, content="different")
    other_outer = giftwrap.wrap(changed, ingress.pubkey_hex, sender, now=NOW)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        first = ledger.admit_envelope(outer, descriptor, ingress,
                                      now=NOW, max_validity_seconds=WEEK)
        with pytest.raises(OrganizationLedgerConflict, match="logical request"):
            ledger.admit_envelope(other_outer, descriptor, ingress,
                                  now=NOW, max_validity_seconds=WEEK)
        assert ledger.load_envelope(first.seq)[0].id == outer.id


def test_corrupted_retained_envelope_is_not_returned_as_evidence(tmp_path):
    owner, ingress, sender = Keys(), Keys(), Keys()
    descriptor = _descriptor(owner, ingress)
    inner = _inner(sender, owner, ingress, descriptor)
    outer = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        result = ledger.admit_envelope(outer, descriptor, ingress,
                                       now=NOW, max_validity_seconds=WEEK)
        ledger.db.execute("UPDATE request_envelopes SET envelope='{}' WHERE seq=?",
                          (result.seq,))
        with pytest.raises(OrganizationLedgerError, match="malformed"):
            ledger.load_envelope(result.seq)
