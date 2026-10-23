"""Adversarial offline checks for provisional organization assignment."""

import pytest

from a4a import giftwrap
from a4a.delegation import create_delegation, create_revocation
from a4a.event import Event
from a4a.keys import Keys
from a4a.organization_assignment import (
    AssignmentAuthorityError,
    select_dispatch_policy,
    verify_assignment_decision,
)
from a4a.organization_ledger import (
    OrganizationLedgerConflict,
    OrganizationLedgerError,
    OrganizationRequestLedger,
)


NOW = 1_800_000_000
WEEK = 7 * 24 * 3600
CONVERSATION = "c" * 64
REQUEST = "a" * 32


def descriptor(owner, ingress):
    return Event(kind=31008, created_at=NOW - 100, content="", tags=[
        ["d", "inbox:1"], ["p", ingress.pubkey_hex], ["generation", "1"],
        ["not_before", str(NOW - 60)], ["expiration", str(NOW + 600)],
    ]).sign(owner)


def policy(owner, ingress_descriptor, admin, workers, *, generation=1, triage="a4a"):
    return Event(kind=31009, created_at=NOW - 100, content="", tags=[
        ["d", f"dispatch:{generation}"],
        ["a4a_descriptor", ingress_descriptor.id],
        ["generation", str(generation)],
        ["not_before", str(NOW - 60)], ["expiration", str(NOW + 600)],
        ["admin", admin.pubkey_hex], ["triage", triage],
        *[["worker", department, key.pubkey_hex] for department, key in workers],
    ]).sign(owner)


def letter(sender, owner, ingress, route, *, request=REQUEST, delivery="b" * 32):
    return Event(kind=14, created_at=NOW - 1, content="status", tags=[
        ["p", ingress.pubkey_hex], ["d", delivery],
        ["a4a_owner", owner.pubkey_hex], ["a4a_descriptor", route.id],
        ["a4a_request", request], ["a4a_conversation", CONVERSATION],
    ]).sign(sender)


def decision(admin, owner, ingress, route, dispatch, sender, worker, *,
             request=REQUEST, department="a4a", expected=0,
             operation="d" * 32, created_at=NOW - 1,
             expiration=NOW + 100):
    return Event(kind=14, created_at=created_at, content="", tags=[
        ["p", ingress.pubkey_hex], ["a4a_owner", owner.pubkey_hex],
        ["a4a_descriptor", route.id], ["a4a_policy", dispatch.id],
        ["a4a_sender", sender.pubkey_hex],
        ["a4a_conversation", CONVERSATION], ["a4a_request", request],
        ["a4a_department", department], ["a4a_worker", worker.pubkey_hex],
        ["a4a_expected_epoch", str(expected)],
        ["a4a_next_epoch", str(expected + 1)],
        ["a4a_operation", operation], ["expiration", str(expiration)],
    ]).sign(admin)


def claim(worker, owner, sender, signed_decision, *, request=REQUEST,
          epoch=1, claim_id="1" * 32, created_at=NOW - 1,
          expiration=NOW + 100):
    return Event(kind=14, created_at=created_at, content="", tags=[
        ["a4a_owner", owner.pubkey_hex], ["a4a_sender", sender.pubkey_hex],
        ["a4a_conversation", CONVERSATION], ["a4a_request", request],
        ["a4a_decision", signed_decision.id], ["a4a_epoch", str(epoch)],
        ["a4a_claim", claim_id], ["expiration", str(expiration)],
    ]).sign(worker)


def completion(worker, owner, sender, signed_decision, signed_claim, *,
               request=REQUEST, epoch=1, result="f" * 64):
    return Event(kind=14, created_at=NOW - 1, content="", tags=[
        ["a4a_owner", owner.pubkey_hex], ["a4a_sender", sender.pubkey_hex],
        ["a4a_conversation", CONVERSATION], ["a4a_request", request],
        ["a4a_decision", signed_decision.id], ["a4a_epoch", str(epoch)],
        ["a4a_claim_event", signed_claim.id],
        ["a4a_result_sha256", result], ["expiration", str(NOW + 100)],
    ]).sign(worker)


def setup():
    owner, ingress, admin, worker, alternate, sender = [Keys() for _ in range(6)]
    route = descriptor(owner, ingress)
    dispatch = policy(owner, route, admin,
                      [("a4a", worker), ("a4a", alternate)])
    mandate = create_delegation(owner, worker.pubkey_hex, "A4A worker",
                                NOW + 1000, created_at=NOW - 100)
    signed_decision = decision(admin, owner, ingress, route, dispatch,
                               sender, worker)
    return owner, ingress, admin, worker, alternate, sender, route, dispatch, mandate, signed_decision


def verify(signed_decision, dispatch, route, mandate, owner, ingress, **changes):
    params = dict(now=NOW, max_descriptor_validity_seconds=WEEK,
                  max_policy_validity_seconds=WEEK,
                  policy_lookup_complete=True, revocation_lookup_complete=True)
    params.update(changes)
    return verify_assignment_decision(
        signed_decision, [dispatch], route, mandate,
        owner.pubkey_hex, ingress.pubkey_hex, **params)


def admit(ledger, sender, owner, ingress, route, *, request=REQUEST,
          delivery="b" * 32):
    inner = letter(sender, owner, ingress, route, request=request,
                   delivery=delivery)
    outer = giftwrap.wrap(inner, ingress.pubkey_hex, sender, now=NOW)
    return ledger.admit_envelope(outer, route, ingress, now=NOW,
                                 max_validity_seconds=WEEK)


def assign(ledger, signed_decision, dispatch, route, mandate, ingress, *, now=NOW):
    return ledger.apply_signed_assignment(
        signed_decision, [dispatch], route, mandate, ingress.pubkey_hex,
        now=now, max_descriptor_validity_seconds=WEEK,
        max_policy_validity_seconds=WEEK, policy_lookup_complete=True,
        revocation_lookup_complete=True)


def load_assignment_evidence(ledger, seq, ingress, dispatch, mandate, *,
                             now=NOW, revocation=None):
    return ledger.load_current_assignment_evidence(
        seq, ingress, [dispatch], mandate, now=now,
        max_descriptor_validity_seconds=WEEK,
        max_policy_validity_seconds=WEEK,
        policy_lookup_complete=True, revocation_lookup_complete=True,
        worker_revocation=revocation)


def renew(ledger, signed_decision, dispatch, route, mandate, ingress, *,
          now=NOW + 101, revocation=None):
    return ledger.renew_signed_assignment(
        signed_decision, [dispatch], route, mandate, ingress, now=now,
        max_descriptor_validity_seconds=WEEK,
        max_policy_validity_seconds=WEEK, policy_lookup_complete=True,
        revocation_lookup_complete=True, worker_revocation=revocation)


def acquire(ledger, signed_claim, dispatch, mandate, *, now=NOW,
            revocation=None):
    return ledger.claim_signed_attempt(
        signed_claim, [dispatch], mandate, now=now, lease_seconds=30,
        max_policy_validity_seconds=WEEK, policy_lookup_complete=True,
        revocation_lookup_complete=True, worker_revocation=revocation)


def complete(ledger, signed_completion, dispatch, mandate, *, now=NOW):
    return ledger.record_signed_completion(
        signed_completion, [dispatch], mandate, now=now,
        max_policy_validity_seconds=WEEK, policy_lookup_complete=True,
        revocation_lookup_complete=True)


def test_valid_authority_binds_owner_sender_request_scope_and_monotonic_epoch():
    owner, ingress, admin, worker, _, sender, route, dispatch, mandate, signed = setup()
    grant = verify(signed, dispatch, route, mandate, owner, ingress)
    assert (grant.owner_pubkey, grant.sender_pubkey, grant.request_id) == (
        owner.pubkey_hex, sender.pubkey_hex, REQUEST)
    assert (grant.expected_epoch, grant.next_epoch, grant.worker_pubkey) == (
        0, 1, worker.pubkey_hex)
    assert grant.decision_id == signed.id


@pytest.mark.parametrize("fault", [
    "wrong_admin", "wrong_worker", "wrong_department", "wrong_descriptor",
    "wrong_sender", "stale_policy", "missing_lookup", "missing_revocation_lookup",
    "revoked_worker", "missing_mandate", "stale_epoch", "long_decision",
    "unknown_tag", "duplicate_tag", "bad_operation",
])
def test_invalid_or_ambiguous_dispatch_authority_fails_closed(fault):
    owner, ingress, admin, worker, _, sender, route, dispatch, mandate, signed = setup()
    kwargs = {}
    if fault == "wrong_admin":
        signed.sign(Keys())
    elif fault == "wrong_worker":
        signed = decision(admin, owner, ingress, route, dispatch, sender, Keys())
    elif fault == "wrong_department":
        signed = decision(admin, owner, ingress, route, dispatch, sender, worker,
                          department="other")
    elif fault == "wrong_descriptor":
        signed.tags[2][1] = "e" * 64
        signed.sign(admin)
    elif fault == "wrong_sender":
        signed.tags[4][1] = "not-a-key"
        signed.sign(admin)
    elif fault == "stale_policy":
        kwargs["now"] = NOW + 700
    elif fault == "missing_lookup":
        kwargs["policy_lookup_complete"] = False
    elif fault == "missing_revocation_lookup":
        kwargs["revocation_lookup_complete"] = False
    elif fault == "revoked_worker":
        kwargs["worker_revocation"] = create_revocation(owner, mandate)
    elif fault == "missing_mandate":
        mandate = create_delegation(owner, Keys().pubkey_hex, "other",
                                    NOW + 1000, created_at=NOW - 100)
    elif fault == "stale_epoch":
        signed.tags[9][1] = "2"
        signed.sign(admin)
    elif fault == "long_decision":
        signed.tags[-1][1] = str(NOW + 1000)
        signed.sign(admin)
    elif fault == "unknown_tag":
        signed.tags.append(["a4a_override", "yes"])
        signed.sign(admin)
    elif fault == "duplicate_tag":
        signed.tags.append(["a4a_worker", worker.pubkey_hex])
        signed.sign(admin)
    elif fault == "bad_operation":
        signed.tags[-2][1] = "D" * 32
        signed.sign(admin)
    with pytest.raises(AssignmentAuthorityError):
        verify(signed, dispatch, route, mandate, owner, ingress, **kwargs)


def test_policy_generation_selection_rejects_equivocation_and_rollback():
    owner, ingress, admin, worker, _, _, route, first, _, _ = setup()
    second = policy(owner, route, admin, [("a4a", worker)], generation=2)
    chosen = select_dispatch_policy([first, second], owner.pubkey_hex,
                                    now=NOW, max_validity_seconds=WEEK,
                                    lookup_complete=True)
    assert chosen.event_id == second.id
    conflict = policy(owner, route, admin, [("a4a", worker), ("other", Keys())],
                      generation=2)
    with pytest.raises(AssignmentAuthorityError, match="conflicting"):
        select_dispatch_policy([second, conflict], owner.pubkey_hex,
                               now=NOW, max_validity_seconds=WEEK,
                               lookup_complete=True)


def test_sqlite_fence_rejects_wire_integers_outside_signed_storage_range():
    owner, ingress, admin, worker, _, sender, route, dispatch, mandate, _ = setup()
    too_large = 2**63
    oversized_policy = policy(owner, route, admin, [("a4a", worker)],
                              generation=too_large)
    with pytest.raises(AssignmentAuthorityError, match="generation"):
        select_dispatch_policy([oversized_policy], owner.pubkey_hex,
                               now=NOW, max_validity_seconds=WEEK,
                               lookup_complete=True)
    oversized_epoch = decision(admin, owner, ingress, route, dispatch,
                               sender, worker, expected=too_large - 1)
    with pytest.raises(AssignmentAuthorityError, match="epoch"):
        verify(oversized_epoch, dispatch, route, mandate, owner, ingress)


def test_assignment_commit_is_atomic_idempotent_and_survives_restart(tmp_path):
    owner, ingress, _, worker, _, sender, route, dispatch, mandate, signed = setup()
    path = tmp_path / "ledger"
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        first = assign(ledger, signed, dispatch, route, mandate, ingress)
        assert (first.status, first.seq, first.epoch) == ("committed", record.seq, 1)
        assert assign(ledger, signed, dispatch, route, mandate, ingress).status == "duplicate"
        assert ledger.get_assignment(sender.pubkey_hex, CONVERSATION)["worker"] == worker.pubkey_hex
        assert ledger.get_execution(record.seq)["state"] == "assigned"
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        assert assign(ledger, signed, dispatch, route, mandate, ingress).status == "duplicate"
        assert ledger.get_assignment(sender.pubkey_hex, CONVERSATION)["epoch"] == 1


def test_current_assignment_evidence_reopens_original_and_authority_after_restart(tmp_path):
    owner, ingress, _, worker, _, sender, route, dispatch, mandate, signed = setup()
    path = tmp_path / "ledger"
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, signed, dispatch, route, mandate, ingress)
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        evidence = load_assignment_evidence(
            ledger, record.seq, ingress, dispatch, mandate)
        assert evidence.original.inner.content == "status"
        assert evidence.original.inner.pubkey == sender.pubkey_hex
        assert evidence.original.outer.kind == giftwrap.KIND_GIFT_WRAP
        assert evidence.policy_event.id == dispatch.id
        assert evidence.decision_event.id == signed.id
        assert (evidence.assignment.worker_pubkey, evidence.assignment.next_epoch) == (
            worker.pubkey_hex, 1)
        assert "status" not in repr(evidence)
        assert ledger.get_execution(record.seq)["state"] == "assigned"


@pytest.mark.parametrize("fault", [
    "swapped_decision", "swapped_policy", "changed_epoch", "changed_worker",
    "changed_operation", "changed_conversation_decision", "missing_original",
    "unexpected_result",
])
def test_current_assignment_evidence_rejects_broken_chain(tmp_path, fault):
    owner, ingress, admin, worker, _, sender, route, dispatch, mandate, signed = setup()
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, signed, dispatch, route, mandate, ingress)
        if fault == "swapped_decision":
            other = decision(admin, owner, ingress, route, dispatch, sender,
                             worker, operation="e" * 32)
            ledger.db.execute("UPDATE assignment_operations SET decision_event=?",
                              (other.model_dump_json(),))
        elif fault == "swapped_policy":
            other = policy(owner, route, admin, [("a4a", worker)], generation=2)
            ledger.db.execute("UPDATE assignment_operations SET policy_event=?",
                              (other.model_dump_json(),))
        elif fault == "changed_epoch":
            ledger.db.execute("UPDATE request_execution SET epoch=2")
        elif fault == "changed_worker":
            ledger.db.execute("UPDATE request_execution SET worker=?",
                              (Keys().pubkey_hex,))
        elif fault == "changed_operation":
            ledger.db.execute("UPDATE request_execution SET operation_id=?",
                              ("f" * 32,))
        elif fault == "changed_conversation_decision":
            ledger.db.execute("UPDATE conversation_assignments SET decision_id=?",
                              ("f" * 64,))
        elif fault == "missing_original":
            ledger.db.execute("DELETE FROM request_envelopes WHERE seq=?",
                              (record.seq,))
        else:
            ledger.db.execute("UPDATE request_execution SET result_sha256=?",
                              ("f" * 64,))
        with pytest.raises(OrganizationLedgerError, match="assignment evidence"):
            load_assignment_evidence(ledger, record.seq, ingress, dispatch, mandate)
        assert ledger.get_execution(record.seq)["state"] == "assigned"


def test_current_assignment_evidence_requires_live_authority_and_unclaimed_state(tmp_path):
    owner, ingress, _, worker, _, sender, route, dispatch, mandate, signed = setup()
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assert load_assignment_evidence(
            ledger, record.seq, ingress, dispatch, mandate) is None
        assign(ledger, signed, dispatch, route, mandate, ingress)
        with pytest.raises(AssignmentAuthorityError, match="expired"):
            load_assignment_evidence(ledger, record.seq, ingress, dispatch,
                                     mandate, now=NOW + 101)
        with pytest.raises(AssignmentAuthorityError, match="current owner mandate"):
            load_assignment_evidence(
                ledger, record.seq, ingress, dispatch, mandate,
                revocation=create_revocation(owner, mandate))
        with pytest.raises(OrganizationLedgerError, match="matching ingress key"):
            load_assignment_evidence(ledger, record.seq, Keys(), dispatch, mandate)
        with pytest.raises(AssignmentAuthorityError, match="incomplete"):
            ledger.load_current_assignment_evidence(
                record.seq, ingress, [dispatch], mandate, now=NOW,
                max_descriptor_validity_seconds=WEEK,
                max_policy_validity_seconds=WEEK,
                policy_lookup_complete=False, revocation_lookup_complete=True)
        acquire(ledger, claim(worker, owner, sender, signed), dispatch, mandate)
        with pytest.raises(OrganizationLedgerError, match="assignment evidence"):
            load_assignment_evidence(ledger, record.seq, ingress, dispatch, mandate)


def test_expired_unclaimed_assignment_can_be_renewed_without_new_epoch(tmp_path):
    owner, ingress, admin, worker, _, sender, route, dispatch, mandate, old = setup()
    replacement = decision(
        admin, owner, ingress, route, dispatch, sender, worker,
        operation="e" * 32, created_at=NOW + 100,
        expiration=NOW + 200)
    path = tmp_path / "ledger"
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, old, dispatch, route, mandate, ingress)
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        with pytest.raises(AssignmentAuthorityError, match="expired"):
            load_assignment_evidence(ledger, record.seq, ingress, dispatch,
                                     mandate, now=NOW + 101)
        result = renew(ledger, replacement, dispatch, route, mandate, ingress)
        assert (result.status, result.seq, result.epoch, result.worker_pubkey) == (
            "renewed", record.seq, 1, worker.pubkey_hex)
        evidence = load_assignment_evidence(
            ledger, record.seq, ingress, dispatch, mandate, now=NOW + 101)
        assert evidence.decision_event.id == replacement.id
        assert evidence.original.inner.content == "status"
        assert renew(ledger, replacement, dispatch, route, mandate,
                     ingress).status == "duplicate"
        history = ledger.db.execute(
            "SELECT * FROM assignment_operation_history WHERE operation_id=?",
            ("d" * 32,)).fetchone()
        assert history["decision_id"] == old.id
        assert history["superseded_by"] == "e" * 32
        assert history["superseded_at"] == NOW + 101
        assert ledger.get_execution(record.seq)["state"] == "assigned"
        assert ledger.get_execution(record.seq)["operation_id"] == "e" * 32
        assert ledger.get_assignment(sender.pubkey_hex, CONVERSATION)["epoch"] == 1
        old_claim = claim(worker, owner, sender, old,
                          created_at=NOW + 100, expiration=NOW + 200)
        with pytest.raises(OrganizationLedgerConflict, match="current assignment"):
            acquire(ledger, old_claim, dispatch, mandate, now=NOW + 101)
        new_claim = claim(worker, owner, sender, replacement,
                          created_at=NOW + 100, expiration=NOW + 200)
        assert acquire(ledger, new_claim, dispatch, mandate,
                       now=NOW + 101).status == "acquired"


def test_renewal_may_adopt_newer_policy_but_not_a_new_worker(tmp_path):
    owner, ingress, admin, worker, _, sender, route, dispatch, mandate, old = setup()
    current_policy = policy(owner, route, admin, [("a4a", worker)], generation=2)
    replacement = decision(
        admin, owner, ingress, route, current_policy, sender, worker,
        operation="e" * 32, created_at=NOW + 100,
        expiration=NOW + 200)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, old, dispatch, route, mandate, ingress)
        assert renew(ledger, replacement, current_policy, route, mandate,
                     ingress).status == "renewed"
        evidence = load_assignment_evidence(
            ledger, record.seq, ingress, current_policy, mandate,
            now=NOW + 101)
        assert (evidence.assignment.policy_generation,
                evidence.assignment.worker_pubkey) == (2, worker.pubkey_hex)
        old_policy = ledger.db.execute(
            "SELECT policy_event FROM assignment_operation_history"
        ).fetchone()[0]
        assert Event.model_validate_json(old_policy).id == dispatch.id


def test_renewal_fences_old_operation_replay_and_revoked_worker(tmp_path):
    owner, ingress, admin, worker, _, sender, route, dispatch, mandate, old = setup()
    replacement = decision(
        admin, owner, ingress, route, dispatch, sender, worker,
        operation="e" * 32, created_at=NOW + 1,
        expiration=NOW + 101)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, old, dispatch, route, mandate, ingress)
        with pytest.raises(AssignmentAuthorityError, match="current owner mandate"):
            renew(ledger, replacement, dispatch, route, mandate, ingress,
                  now=NOW + 2,
                  revocation=create_revocation(owner, mandate))
        assert ledger.get_execution(record.seq)["operation_id"] == "d" * 32
        assert renew(ledger, replacement, dispatch, route, mandate,
                     ingress, now=NOW + 2).status == "renewed"
        with pytest.raises(OrganizationLedgerConflict, match="superseded"):
            assign(ledger, old, dispatch, route, mandate, ingress,
                   now=NOW + 2)
        assert ledger.get_execution(record.seq)["operation_id"] == "e" * 32


def test_renewal_after_claim_is_forbidden_and_does_not_replace_evidence(tmp_path):
    owner, ingress, admin, worker, _, sender, route, dispatch, mandate, old = setup()
    replacement = decision(
        admin, owner, ingress, route, dispatch, sender, worker,
        operation="e" * 32, created_at=NOW + 1,
        expiration=NOW + 101)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, old, dispatch, route, mandate, ingress)
        acquire(ledger, claim(worker, owner, sender, old), dispatch, mandate)
        with pytest.raises(OrganizationLedgerConflict, match="unclaimed"):
            renew(ledger, replacement, dispatch, route, mandate,
                  ingress, now=NOW + 2)
        assert ledger.get_execution(record.seq)["state"] == "leased"
        assert ledger.get_execution(record.seq)["operation_id"] == "d" * 32
        assert ledger.db.execute(
            "SELECT COUNT(*) FROM assignment_operation_history").fetchone()[0] == 0


@pytest.mark.parametrize("fault", [
    "new_worker", "new_epoch", "same_operation", "same_signed_time",
    "wrong_ingress", "corrupt_old_decision",
])
def test_renewal_rejects_ambiguous_or_changed_assignment(tmp_path, fault):
    owner, ingress, admin, worker, alternate, sender, route, dispatch, mandate, old = setup()
    new_worker = alternate if fault == "new_worker" else worker
    new_mandate = (create_delegation(owner, alternate.pubkey_hex, "alternate",
                                     NOW + 1000, created_at=NOW - 100)
                   if fault == "new_worker" else mandate)
    replacement = decision(
        admin, owner, ingress, route, dispatch, sender, new_worker,
        expected=1 if fault == "new_epoch" else 0,
        operation="d" * 32 if fault == "same_operation" else "e" * 32,
        created_at=NOW - 1 if fault == "same_signed_time" else NOW + 100,
        expiration=NOW + 200)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, old, dispatch, route, mandate, ingress)
        if fault == "corrupt_old_decision":
            ledger.db.execute("UPDATE assignment_operations SET decision_id=?",
                              ("f" * 64,))
        if fault == "wrong_ingress":
            ingress = Keys()
        with pytest.raises((AssignmentAuthorityError, OrganizationLedgerError,
                            OrganizationLedgerConflict), match="renewal|ingress"):
            renew(ledger, replacement, dispatch, route, new_mandate, ingress)
        assert ledger.get_execution(record.seq)["operation_id"] == "d" * 32
        assert ledger.db.execute(
            "SELECT COUNT(*) FROM assignment_operation_history").fetchone()[0] == 0


def test_competing_same_time_renewals_fence_second_decision(tmp_path):
    owner, ingress, admin, worker, _, sender, route, dispatch, mandate, old = setup()
    first = decision(admin, owner, ingress, route, dispatch, sender, worker,
                     operation="e" * 32, created_at=NOW + 100,
                     expiration=NOW + 200)
    second = decision(admin, owner, ingress, route, dispatch, sender, worker,
                      operation="f" * 32, created_at=NOW + 100,
                      expiration=NOW + 200)
    path = tmp_path / "ledger"
    with OrganizationRequestLedger(path, owner.pubkey_hex) as primary, \
            OrganizationRequestLedger(path, owner.pubkey_hex) as contender:
        record = admit(primary, sender, owner, ingress, route)
        assign(primary, old, dispatch, route, mandate, ingress)
        assert renew(primary, first, dispatch, route, mandate, ingress).status == "renewed"
        with pytest.raises(OrganizationLedgerConflict, match="newer signed decision"):
            renew(contender, second, dispatch, route, mandate, ingress)
        assert contender.get_execution(record.seq)["operation_id"] == "e" * 32


def test_failed_renewal_transaction_keeps_previous_decision_and_no_history(tmp_path):
    owner, ingress, admin, worker, _, sender, route, dispatch, mandate, old = setup()
    replacement = decision(
        admin, owner, ingress, route, dispatch, sender, worker,
        operation="e" * 32, created_at=NOW + 100,
        expiration=NOW + 200)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, old, dispatch, route, mandate, ingress)
        ledger.db.execute("""CREATE TRIGGER fail_renewal BEFORE UPDATE
            ON request_execution BEGIN SELECT RAISE(ABORT, 'simulated'); END""")
        with pytest.raises(OrganizationLedgerError, match="renewal database"):
            renew(ledger, replacement, dispatch, route, mandate, ingress)
        assert ledger.get_execution(record.seq)["operation_id"] == "d" * 32
        assert ledger.get_assignment(sender.pubkey_hex, CONVERSATION)["decision_id"] == old.id
        assert ledger.db.execute(
            "SELECT COUNT(*) FROM assignment_operation_history").fetchone()[0] == 0
        assert ledger.db.execute(
            "SELECT decision_id FROM assignment_operations"
        ).fetchone()[0] == old.id


def test_assignment_needs_durable_original_and_fences_conflicting_retry(tmp_path):
    owner, ingress, admin, worker, _, sender, route, dispatch, mandate, signed = setup()
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        inner = letter(sender, owner, ingress, route)
        ledger.admit_inner(inner, route, ingress.pubkey_hex, now=NOW,
                           max_validity_seconds=WEEK)
        with pytest.raises(OrganizationLedgerError, match="retained"):
            assign(ledger, signed, dispatch, route, mandate, ingress)
        admit(ledger, sender, owner, ingress, route)
        first = assign(ledger, signed, dispatch, route, mandate, ingress)
        reused = decision(admin, owner, ingress, route, dispatch, sender,
                          worker, operation="d" * 32, expected=1)
        with pytest.raises(OrganizationLedgerConflict, match="operation ID"):
            assign(ledger, reused, dispatch, route, mandate, ingress)
        assert ledger.get_execution(first.seq)["epoch"] == 1


@pytest.mark.parametrize("fault", ["missing", "corrupt"])
def test_claim_rechecks_retained_original_before_first_lease(tmp_path, fault):
    owner, ingress, _, worker, _, sender, route, dispatch, mandate, signed = setup()
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, signed, dispatch, route, mandate, ingress)
        if fault == "missing":
            ledger.db.execute("DELETE FROM request_envelopes WHERE seq=?", (record.seq,))
        else:
            original_id = ledger.db.execute(
                "SELECT outer_id FROM request_envelopes WHERE seq=?",
                (record.seq,)).fetchone()[0]
            wrong_id = ("0" if original_id[0] != "0" else "1") + original_id[1:]
            ledger.db.execute("UPDATE request_envelopes SET outer_id=? WHERE seq=?",
                              (wrong_id, record.seq))

        with pytest.raises(OrganizationLedgerError, match="retained envelope"):
            acquire(ledger, claim(worker, owner, sender, signed), dispatch, mandate)
        assert ledger.get_execution(record.seq)["state"] == "assigned"


def test_one_unfinished_request_blocks_next_epoch_even_on_other_connection(tmp_path):
    owner, ingress, admin, worker, alternate, sender, route, dispatch, mandate, signed = setup()
    alternate_mandate = create_delegation(owner, alternate.pubkey_hex, "alternate",
                                          NOW + 1000, created_at=NOW - 100)
    path = tmp_path / "ledger"
    with OrganizationRequestLedger(path, owner.pubkey_hex) as first, \
            OrganizationRequestLedger(path, owner.pubkey_hex) as second:
        first_record = admit(first, sender, owner, ingress, route)
        assign(first, signed, dispatch, route, mandate, ingress)
        second_record = admit(second, sender, owner, ingress, route,
                              request="f" * 32, delivery="e" * 32)
        next_decision = decision(admin, owner, ingress, route, dispatch,
                                 sender, alternate, request="f" * 32,
                                 expected=1, operation="c" * 32)
        with pytest.raises(OrganizationLedgerConflict, match="unfinished"):
            assign(second, next_decision, dispatch, route, alternate_mandate, ingress)
        assert first.get_execution(first_record.seq)["state"] == "assigned"
        assert second.get_execution(second_record.seq) is None
        assert second.get_assignment(sender.pubkey_hex, CONVERSATION)["epoch"] == 1


def test_policy_checkpoint_rejects_previous_generation_after_newer_commit(tmp_path):
    owner, ingress, admin, worker, _, sender, route, first_policy, mandate, _ = setup()
    newer = policy(owner, route, admin, [("a4a", worker)], generation=2)
    newer_decision = decision(admin, owner, ingress, route, newer, sender, worker)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        admit(ledger, sender, owner, ingress, route)
        assign(ledger, newer_decision, newer, route, mandate, ingress)
        old_decision = decision(admin, owner, ingress, route, first_policy,
                                sender, worker, expected=1, operation="c" * 32)
        with pytest.raises(OrganizationLedgerConflict, match="policy rollback"):
            assign(ledger, old_decision, first_policy, route, mandate, ingress)


def test_signed_attempt_is_single_acquisition_and_expiry_is_uncertain(tmp_path):
    owner, ingress, _, worker, _, sender, route, dispatch, mandate, signed = setup()
    path = tmp_path / "ledger"
    signed_claim = claim(worker, owner, sender, signed)
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, signed, dispatch, route, mandate, ingress)
        first = acquire(ledger, signed_claim, dispatch, mandate)
        assert (first.status, first.seq, first.epoch) == ("acquired", record.seq, 1)
        assert first.claim_event_id == signed_claim.id
        assert acquire(ledger, signed_claim, dispatch, mandate).status == "duplicate"
        assert ledger.get_execution(record.seq)["claim_event_id"] == signed_claim.id
        assert ledger.get_execution(record.seq)["claim_event"]
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        assert ledger.expire_attempt(record.seq, now=NOW + 29) is False
        assert ledger.expire_attempt(record.seq, now=NOW + 30) is True
        assert ledger.get_execution(record.seq)["state"] == "uncertain"
        assert acquire(ledger, signed_claim, dispatch, mandate,
                       now=NOW + 31).status == "uncertain"
        assert ledger.expire_attempt(record.seq, now=NOW + 31) is False


def test_competing_claim_and_wrong_epoch_cannot_steal_attempt(tmp_path):
    owner, ingress, _, worker, alternate, sender, route, dispatch, mandate, signed = setup()
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, signed, dispatch, route, mandate, ingress)
        with pytest.raises(OrganizationLedgerConflict, match="current assignment"):
            acquire(ledger, claim(worker, owner, sender, signed, epoch=2),
                    dispatch, mandate)
        alternate_mandate = create_delegation(owner, alternate.pubkey_hex, "alternate",
                                              NOW + 1000, created_at=NOW - 100)
        with pytest.raises(OrganizationLedgerConflict, match="current assignment"):
            acquire(ledger, claim(alternate, owner, sender, signed),
                    dispatch, alternate_mandate)
        first = claim(worker, owner, sender, signed)
        assert acquire(ledger, first, dispatch, mandate).status == "acquired"
        with pytest.raises(OrganizationLedgerConflict, match="already holds lease"):
            acquire(ledger, claim(worker, owner, sender, signed,
                                  claim_id="2" * 32), dispatch, mandate)
        assert ledger.mark_attempt_uncertain(record.seq, "e" * 64) is False
        assert ledger.mark_attempt_uncertain(record.seq, first.id) is True
        assert ledger.get_execution(record.seq)["state"] == "uncertain"


def test_claim_needs_current_mandate_and_complete_lookup(tmp_path):
    owner, ingress, _, worker, _, sender, route, dispatch, mandate, signed = setup()
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, signed, dispatch, route, mandate, ingress)
        signed_claim = claim(worker, owner, sender, signed)
        with pytest.raises(AssignmentAuthorityError, match="current owner mandate"):
            acquire(ledger, signed_claim, dispatch, mandate,
                    revocation=create_revocation(owner, mandate))
        with pytest.raises(AssignmentAuthorityError, match="incomplete"):
            ledger.claim_signed_attempt(
                signed_claim, [dispatch], mandate, now=NOW, lease_seconds=30,
                max_policy_validity_seconds=WEEK,
                policy_lookup_complete=False, revocation_lookup_complete=True)
        assert ledger.get_execution(record.seq)["state"] == "assigned"


def test_signed_completion_allows_next_epoch_but_not_a_processed_ack(tmp_path):
    owner, ingress, admin, worker, alternate, sender, route, dispatch, mandate, signed = setup()
    alternate_mandate = create_delegation(owner, alternate.pubkey_hex, "alternate",
                                          NOW + 1000, created_at=NOW - 100)
    path = tmp_path / "ledger"
    signed_claim = claim(worker, owner, sender, signed)
    done = completion(worker, owner, sender, signed, signed_claim)
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        first_record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, signed, dispatch, route, mandate, ingress)
        acquire(ledger, signed_claim, dispatch, mandate)
        finished = complete(ledger, done, dispatch, mandate)
        assert (finished.status, finished.seq, finished.epoch) == (
            "committed", first_record.seq, 1)
        assert complete(ledger, done, dispatch, mandate).status == "duplicate"
        assert ledger.get_execution(first_record.seq)["result_sha256"] == "f" * 64
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        second_record = admit(ledger, sender, owner, ingress, route,
                              request="e" * 32, delivery="f" * 32)
        switch = decision(admin, owner, ingress, route, dispatch, sender,
                          alternate, request="e" * 32,
                          expected=1, operation="3" * 32)
        changed = assign(ledger, switch, dispatch, route, alternate_mandate, ingress)
        assert (changed.seq, changed.epoch, changed.worker_pubkey) == (
            second_record.seq, 2, alternate.pubkey_hex)
        assert ledger.get_assignment(sender.pubkey_hex, CONVERSATION)["epoch"] == 2
        assert ledger.get_execution(first_record.seq)["state"] == "completed"


def test_uncertain_attempt_blocks_vendor_switch_and_late_completion(tmp_path):
    owner, ingress, admin, worker, alternate, sender, route, dispatch, mandate, signed = setup()
    alternate_mandate = create_delegation(owner, alternate.pubkey_hex, "alternate",
                                          NOW + 1000, created_at=NOW - 100)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        first_record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, signed, dispatch, route, mandate, ingress)
        signed_claim = claim(worker, owner, sender, signed)
        acquire(ledger, signed_claim, dispatch, mandate)
        late = completion(worker, owner, sender, signed, signed_claim)
        assert complete(ledger, late, dispatch, mandate, now=NOW + 30).status == "uncertain"
        assert ledger.get_execution(first_record.seq)["state"] == "uncertain"
        admit(ledger, sender, owner, ingress, route,
              request="e" * 32, delivery="f" * 32)
        switch = decision(admin, owner, ingress, route, dispatch, sender,
                          alternate, request="e" * 32,
                          expected=1, operation="3" * 32)
        with pytest.raises(OrganizationLedgerConflict, match="uncertain"):
            assign(ledger, switch, dispatch, route, alternate_mandate, ingress,
                   now=NOW + 30)


def test_forged_or_unrelated_completion_never_terminates_attempt(tmp_path):
    owner, ingress, _, worker, _, sender, route, dispatch, mandate, signed = setup()
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, signed, dispatch, route, mandate, ingress)
        signed_claim = claim(worker, owner, sender, signed)
        acquire(ledger, signed_claim, dispatch, mandate)
        wrong_claim = claim(worker, owner, sender, signed, claim_id="2" * 32)
        unrelated = completion(worker, owner, sender, signed, wrong_claim)
        with pytest.raises(OrganizationLedgerConflict, match="current assignment"):
            complete(ledger, unrelated, dispatch, mandate)
        forged = completion(Keys(), owner, sender, signed, signed_claim)
        with pytest.raises(AssignmentAuthorityError, match="current owner mandate"):
            complete(ledger, forged, dispatch, mandate)
        assert ledger.get_execution(record.seq)["state"] == "leased"


def test_clock_rollback_cannot_revive_expired_attempt(tmp_path):
    owner, ingress, _, worker, _, sender, route, dispatch, mandate, signed = setup()
    path = tmp_path / "ledger"
    signed_claim = claim(worker, owner, sender, signed)
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        record = admit(ledger, sender, owner, ingress, route)
        assign(ledger, signed, dispatch, route, mandate, ingress)
        acquire(ledger, signed_claim, dispatch, mandate)
        assert ledger.expire_attempt(record.seq, now=NOW + 30) is True
    with OrganizationRequestLedger(path, owner.pubkey_hex) as ledger:
        with pytest.raises(OrganizationLedgerError, match="clock moved"):
            complete(ledger, completion(worker, owner, sender, signed, signed_claim),
                     dispatch, mandate, now=NOW + 10)
        assert ledger.get_execution(record.seq)["state"] == "uncertain"


def test_cross_department_history_cannot_be_reassigned_in_first_pilot(tmp_path):
    owner, ingress, admin, worker, alternate, sender, route, _, mandate, _ = setup()
    dispatch = policy(owner, route, admin,
                      [("a4a", worker), ("other", alternate)])
    first = decision(admin, owner, ingress, route, dispatch, sender, worker)
    alternate_mandate = create_delegation(owner, alternate.pubkey_hex, "other",
                                          NOW + 1000, created_at=NOW - 100)
    with OrganizationRequestLedger(tmp_path / "ledger", owner.pubkey_hex) as ledger:
        admit(ledger, sender, owner, ingress, route)
        assign(ledger, first, dispatch, route, mandate, ingress)
        signed_claim = claim(worker, owner, sender, first)
        acquire(ledger, signed_claim, dispatch, mandate)
        complete(ledger, completion(worker, owner, sender, first, signed_claim),
                 dispatch, mandate)
        admit(ledger, sender, owner, ingress, route,
              request="e" * 32, delivery="f" * 32)
        transfer = decision(admin, owner, ingress, route, dispatch, sender,
                            alternate, request="e" * 32, department="other",
                            expected=1, operation="3" * 32)
        with pytest.raises(OrganizationLedgerConflict, match="cross-department"):
            assign(ledger, transfer, dispatch, route, alternate_mandate, ingress)
        assert ledger.get_assignment(sender.pubkey_hex, CONVERSATION)["department"] == "a4a"
