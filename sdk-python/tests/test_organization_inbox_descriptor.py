"""Offline route-proof checks; no descriptor is published by these tests."""

import pytest

from a4a.event import Event
from a4a.keys import Keys
from a4a.organization_inbox import (
    DescriptorCheckpoint,
    DescriptorCheckpointStore,
    DescriptorError,
    FirstContactCheckpoint,
    select_descriptor,
    verify_descriptor,
)


NOW = 1_800_000_000
WEEK = 7 * 24 * 3600


def _event(owner, ingress, *, generation="1", not_before=str(NOW - 60),
           expiration=str(NOW + 60), tags=None, content=""):
    tags = tags if tags is not None else [
        ["d", f"inbox:{generation}"], ["p", ingress.pubkey_hex],
        ["generation", generation], ["not_before", not_before],
        ["expiration", expiration],
    ]
    return Event(kind=31008, tags=tags, content=content).sign(owner)


def test_owner_signed_descriptor_is_verified_offline():
    owner, ingress = Keys(), Keys()
    event = _event(owner, ingress)
    proof = verify_descriptor(event, owner.pubkey_hex, now=NOW,
                              max_validity_seconds=WEEK)
    assert proof.owner_pubkey == owner.pubkey_hex
    assert proof.ingress_pubkey == ingress.pubkey_hex
    assert proof.generation == 1
    assert proof.event_id == event.id


@pytest.mark.parametrize("mutation", [
    lambda tags: tags + [["p", Keys().pubkey_hex]],
    lambda tags: tags + [["unknown", "value"]],
    lambda tags: [["d", "other"]] + tags[1:],
    lambda tags: [["p", "A" * 64]] + tags[2:],
    lambda tags: [["p", "f" * 64, "extra"]] + tags[2:],
    lambda tags: tags[:-1],
])
def test_ambiguous_or_noncanonical_tags_fail_closed(mutation):
    owner, ingress = Keys(), Keys()
    tags = _event(owner, ingress).tags
    with pytest.raises(DescriptorError):
        verify_descriptor(_event(owner, ingress, tags=mutation(tags)),
                          owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK)


@pytest.mark.parametrize("generation", ["0", "01", "+1", "1_0", "١", "a"])
def test_generation_must_be_positive_canonical_uint(generation):
    owner, ingress = Keys(), Keys()
    with pytest.raises(DescriptorError):
        verify_descriptor(_event(owner, ingress, generation=generation),
                          owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK)


def test_wrong_signer_and_tampered_signature_fail():
    owner, other, ingress = Keys(), Keys(), Keys()
    event = _event(other, ingress)
    with pytest.raises(DescriptorError, match="owner"):
        verify_descriptor(event, owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK)
    event = _event(owner, ingress)
    event.tags[1][1] = other.pubkey_hex
    with pytest.raises(DescriptorError, match="signature"):
        verify_descriptor(event, owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK)


def test_owner_key_cannot_be_the_online_ingress():
    owner = Keys()
    with pytest.raises(DescriptorError, match="distinct"):
        verify_descriptor(_event(owner, owner), owner.pubkey_hex,
                          now=NOW, max_validity_seconds=WEEK)


@pytest.mark.parametrize("not_before,expiration", [
    (str(NOW + 1), str(NOW + 100)),
    (str(NOW - 100), str(NOW)),
    (str(NOW), str(NOW)),
    ("00", str(NOW + 100)),
    (str(NOW - 100), "+1800000100"),
    (str(NOW - WEEK), str(NOW + 1)),
])
def test_invalid_or_excessive_validity_fails(not_before, expiration):
    owner, ingress = Keys(), Keys()
    with pytest.raises(DescriptorError):
        verify_descriptor(_event(owner, ingress, not_before=not_before,
                                 expiration=expiration),
                          owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK)


def test_content_and_kind_are_not_ignored():
    owner, ingress = Keys(), Keys()
    with pytest.raises(DescriptorError):
        verify_descriptor(_event(owner, ingress, content="free text"),
                          owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK)
    event = Event(kind=31001, tags=_event(owner, ingress).tags).sign(owner)
    with pytest.raises(DescriptorError):
        verify_descriptor(event, owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK)


def test_address_coordinate_must_match_generation():
    owner, ingress = Keys(), Keys()
    event = _event(owner, ingress, generation="2")
    event.tags[0] = ["d", "inbox:1"]
    event.sign(owner)
    with pytest.raises(DescriptorError, match="address"):
        verify_descriptor(event, owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK)


def test_relay_lookup_must_be_complete_and_same_generation_must_not_fork():
    owner, ingress_a, ingress_b = Keys(), Keys(), Keys()
    a = _event(owner, ingress_a)
    b = _event(owner, ingress_b)
    with pytest.raises(DescriptorError, match="incomplete"):
        select_descriptor([a], owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK, lookup_complete=False,
                          first_contact=FirstContactCheckpoint(owner.pubkey_hex, 1))
    with pytest.raises(DescriptorError, match="conflict"):
        select_descriptor([a, b], owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK, lookup_complete=True,
                          first_contact=FirstContactCheckpoint(owner.pubkey_hex, 1))


def test_first_contact_qr_floor_survives_normal_rotation():
    owner, old_ingress, new_ingress = Keys(), Keys(), Keys()
    old = _event(owner, old_ingress)
    new = _event(owner, new_ingress, generation="2")
    qr = FirstContactCheckpoint(owner.pubkey_hex, 1)
    selected = select_descriptor([old, new], owner.pubkey_hex, now=NOW,
                                 max_validity_seconds=WEEK, lookup_complete=True,
                                 first_contact=qr)
    assert selected.event_id == new.id


def test_qr_generation_floor_rejects_older_route():
    owner, ingress = Keys(), Keys()
    old = _event(owner, ingress)
    with pytest.raises(DescriptorError, match="checkpoint_outdated"):
        select_descriptor([old], owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK, lookup_complete=True,
                          first_contact=FirstContactCheckpoint(owner.pubkey_hex, 2))


def test_established_sender_rejects_rollback_and_accepts_new_generation():
    owner, old_ingress, new_ingress = Keys(), Keys(), Keys()
    old = _event(owner, old_ingress)
    new = _event(owner, new_ingress, generation="2")
    high_water = DescriptorCheckpoint(owner.pubkey_hex, new.id, 2,
                                      new_ingress.pubkey_hex)
    with pytest.raises(DescriptorError, match="rollback"):
        select_descriptor([old], owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK, lookup_complete=True,
                          previous=high_water)
    selected = select_descriptor([new], owner.pubkey_hex, now=NOW,
                                 max_validity_seconds=WEEK, lookup_complete=True,
                                 previous=DescriptorCheckpoint(
                                     owner.pubkey_hex, old.id, 1,
                                     old_ingress.pubkey_hex))
    assert selected.ingress_pubkey == new_ingress.pubkey_hex


def test_same_generation_checkpoint_event_mismatch_fails():
    owner, ingress = Keys(), Keys()
    first = _event(owner, ingress)
    second = _event(owner, ingress, not_before=str(NOW - 59))
    pin = DescriptorCheckpoint(owner.pubkey_hex, first.id, 1, ingress.pubkey_hex)
    with pytest.raises(DescriptorError, match="conflict"):
        select_descriptor([second], owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK, lookup_complete=True,
                          previous=pin)


def test_first_contact_requires_checkpoint_and_identical_relay_copies_are_ok():
    owner, ingress = Keys(), Keys()
    event = _event(owner, ingress)
    with pytest.raises(DescriptorError, match="checkpoint"):
        select_descriptor([event], owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK, lookup_complete=True)
    selected = select_descriptor([event, event], owner.pubkey_hex, now=NOW,
                                 max_validity_seconds=WEEK, lookup_complete=True,
                                 first_contact=FirstContactCheckpoint(owner.pubkey_hex, 1))
    assert selected.event_id == event.id


def test_future_higher_generation_does_not_disable_current_route():
    owner, ingress_a, ingress_b = Keys(), Keys(), Keys()
    old = _event(owner, ingress_a)
    new = _event(owner, ingress_b, generation="2",
                 not_before=str(NOW + 1), expiration=str(NOW + 100))
    selected = select_descriptor([old, new], owner.pubkey_hex, now=NOW,
                                 max_validity_seconds=WEEK, lookup_complete=True,
                                 first_contact=FirstContactCheckpoint(owner.pubkey_hex, 1))
    assert selected.event_id == old.id
    selected = select_descriptor([old, new], owner.pubkey_hex, now=NOW,
                                 max_validity_seconds=WEEK, lookup_complete=True,
                                 previous=DescriptorCheckpoint(
                                     owner.pubkey_hex, old.id, 1,
                                     ingress_a.pubkey_hex))
    assert selected.event_id == old.id
    selected = select_descriptor([old, new], owner.pubkey_hex, now=NOW + 2,
                                 max_validity_seconds=WEEK, lookup_complete=True,
                                 previous=DescriptorCheckpoint(
                                     owner.pubkey_hex, old.id, 1,
                                     ingress_a.pubkey_hex))
    assert selected.event_id == new.id


def test_expired_highest_effective_generation_does_not_fall_back():
    owner, ingress_a, ingress_b = Keys(), Keys(), Keys()
    old = _event(owner, ingress_a, generation="1",
                 not_before=str(NOW - 100), expiration=str(NOW + 100))
    expired_high = _event(owner, ingress_b, generation="2",
                          not_before=str(NOW - 100), expiration=str(NOW))
    with pytest.raises(DescriptorError, match="not active"):
        select_descriptor([old, expired_high], owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK, lookup_complete=True,
                          first_contact=FirstContactCheckpoint(owner.pubkey_hex, 1))


def test_more_than_two_active_generations_fail_closed():
    owner = Keys()
    batch = [_event(owner, Keys(), generation=str(generation))
             for generation in (1, 2, 3)]
    with pytest.raises(DescriptorError, match="too many"):
        select_descriptor(batch, owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK, lookup_complete=True,
                          first_contact=FirstContactCheckpoint(owner.pubkey_hex, 1))


def test_invalid_input_types_fail_with_protocol_error():
    owner, ingress = Keys(), Keys()
    event = _event(owner, ingress)
    with pytest.raises(DescriptorError):
        verify_descriptor(event, None, now=NOW, max_validity_seconds=WEEK)
    with pytest.raises(DescriptorError):
        verify_descriptor(event, owner.pubkey_hex, now=True,
                          max_validity_seconds=WEEK)
    with pytest.raises(DescriptorError):
        DescriptorCheckpoint(owner.pubkey_hex, None, 1, ingress.pubkey_hex)
    with pytest.raises(DescriptorError):
        FirstContactCheckpoint(owner.pubkey_hex, 0)
    with pytest.raises(DescriptorError):
        FirstContactCheckpoint(owner.pubkey_hex, 10**19)
    with pytest.raises(DescriptorError, match="checkpoint type"):
        select_descriptor([event], owner.pubkey_hex, now=NOW,
                          max_validity_seconds=WEEK, lookup_complete=True,
                          first_contact=DescriptorCheckpoint(
                              owner.pubkey_hex, event.id, 1, ingress.pubkey_hex))


def test_checkpoint_store_survives_restart_and_fences_rollback(tmp_path):
    owner, first_ingress, second_ingress = Keys(), Keys(), Keys()
    first = _event(owner, first_ingress)
    second = _event(owner, second_ingress, generation="2")
    directory = tmp_path / "routes"
    with DescriptorCheckpointStore(directory) as store:
        with pytest.raises(DescriptorError, match="QR checkpoint required"):
            store.select_and_record([first], owner.pubkey_hex, now=NOW,
                                    max_validity_seconds=WEEK, lookup_complete=True)
        assert store.get(owner.pubkey_hex) is None
        selected = store.select_and_record(
            [first], owner.pubkey_hex, now=NOW,
            max_validity_seconds=WEEK, lookup_complete=True,
            first_contact=FirstContactCheckpoint(owner.pubkey_hex, 1))
        assert selected.event_id == first.id
    with DescriptorCheckpointStore(directory) as store:
        assert store.get(owner.pubkey_hex).checkpoint.event_id == first.id
        assert store.get(owner.pubkey_hex).checked_at == NOW
        assert store.select_and_record(
            [first, second], owner.pubkey_hex, now=NOW + 1,
            max_validity_seconds=WEEK, lookup_complete=True).event_id == second.id
    with DescriptorCheckpointStore(directory) as store:
        with pytest.raises(DescriptorError, match="rollback"):
            store.select_and_record([first], owner.pubkey_hex, now=NOW + 2,
                                    max_validity_seconds=WEEK, lookup_complete=True)
        assert store.get(owner.pubkey_hex).checkpoint.event_id == second.id


def test_checkpoint_store_does_not_advance_on_incomplete_or_future_lookup(tmp_path):
    owner, old_ingress, future_ingress = Keys(), Keys(), Keys()
    old = _event(owner, old_ingress)
    future = _event(owner, future_ingress, generation="2",
                    not_before=str(NOW + 10), expiration=str(NOW + 100))
    with DescriptorCheckpointStore(tmp_path / "routes") as store:
        qr = FirstContactCheckpoint(owner.pubkey_hex, 1)
        with pytest.raises(DescriptorError, match="incomplete"):
            store.select_and_record([old], owner.pubkey_hex, now=NOW,
                                    max_validity_seconds=WEEK,
                                    lookup_complete=False, first_contact=qr)
        assert store.get(owner.pubkey_hex) is None
        assert store.select_and_record(
            [old, future], owner.pubkey_hex, now=NOW,
            max_validity_seconds=WEEK, lookup_complete=True,
            first_contact=qr).event_id == old.id
        assert store.get(owner.pubkey_hex).checkpoint.generation == 1
        assert store.select_and_record(
            [old, future], owner.pubkey_hex, now=NOW + 10,
            max_validity_seconds=WEEK, lookup_complete=True).event_id == future.id
        assert store.get(owner.pubkey_hex).checkpoint.generation == 2


def test_checkpoint_store_fences_concurrent_stale_client_and_clock(tmp_path):
    owner, first_ingress, second_ingress = Keys(), Keys(), Keys()
    first = _event(owner, first_ingress)
    second = _event(owner, second_ingress, generation="2")
    directory = tmp_path / "routes"
    with DescriptorCheckpointStore(directory) as writer, DescriptorCheckpointStore(directory) as stale:
        writer.select_and_record([first], owner.pubkey_hex, now=NOW,
                                 max_validity_seconds=WEEK, lookup_complete=True,
                                 first_contact=FirstContactCheckpoint(owner.pubkey_hex, 1))
        assert stale.get(owner.pubkey_hex).checkpoint.event_id == first.id
        writer.select_and_record([first, second], owner.pubkey_hex, now=NOW + 2,
                                 max_validity_seconds=WEEK, lookup_complete=True)
        with pytest.raises(DescriptorError, match="rollback"):
            stale.select_and_record([first], owner.pubkey_hex, now=NOW + 3,
                                    max_validity_seconds=WEEK, lookup_complete=True)
        with pytest.raises(DescriptorError, match="clock moved"):
            stale.select_and_record([first, second], owner.pubkey_hex, now=NOW + 1,
                                    max_validity_seconds=WEEK, lookup_complete=True)
        assert stale.get(owner.pubkey_hex).checkpoint.event_id == second.id


def test_checkpoint_store_new_qr_floor_can_raise_minimum(tmp_path):
    owner, first_ingress, second_ingress = Keys(), Keys(), Keys()
    first = _event(owner, first_ingress)
    second = _event(owner, second_ingress, generation="2")
    with DescriptorCheckpointStore(tmp_path / "routes") as store:
        store.select_and_record([first], owner.pubkey_hex, now=NOW,
                                max_validity_seconds=WEEK, lookup_complete=True,
                                first_contact=FirstContactCheckpoint(owner.pubkey_hex, 1))
        with pytest.raises(DescriptorError, match="checkpoint_outdated"):
            store.select_and_record([first], owner.pubkey_hex, now=NOW + 1,
                                    max_validity_seconds=WEEK, lookup_complete=True,
                                    first_contact=FirstContactCheckpoint(owner.pubkey_hex, 2))
        assert store.get(owner.pubkey_hex).checkpoint.event_id == first.id
        assert store.select_and_record(
            [first, second], owner.pubkey_hex, now=NOW + 2,
            max_validity_seconds=WEEK, lookup_complete=True,
            first_contact=FirstContactCheckpoint(owner.pubkey_hex, 2)).event_id == second.id


def test_checkpoint_capacity_fails_closed_without_eviction(tmp_path):
    owner_a, owner_b, ingress_a, ingress_b = Keys(), Keys(), Keys(), Keys()
    event_a = _event(owner_a, ingress_a)
    event_b = _event(owner_b, ingress_b)
    with DescriptorCheckpointStore(tmp_path / "routes", max_owners=1) as store:
        store.select_and_record(
            [event_a], owner_a.pubkey_hex, now=NOW,
            max_validity_seconds=WEEK, lookup_complete=True,
            first_contact=FirstContactCheckpoint(owner_a.pubkey_hex, 1))
        with pytest.raises(DescriptorError, match="capacity"):
            store.select_and_record(
                [event_b], owner_b.pubkey_hex, now=NOW,
                max_validity_seconds=WEEK, lookup_complete=True,
                first_contact=FirstContactCheckpoint(owner_b.pubkey_hex, 1))
        assert store.get(owner_a.pubkey_hex).checkpoint.event_id == event_a.id
        assert store.get(owner_b.pubkey_hex) is None


def test_checkpoint_store_explains_missing_state_and_rejects_invalid_capacity(tmp_path):
    owner, ingress = Keys(), Keys()
    event = _event(owner, ingress)
    with DescriptorCheckpointStore(tmp_path / "routes") as store:
        with pytest.raises(DescriptorError, match="first contact or lost local state"):
            store.select_and_record([event], owner.pubkey_hex, now=NOW,
                                    max_validity_seconds=WEEK, lookup_complete=True)
    with pytest.raises(DescriptorError, match="capacity"):
        DescriptorCheckpointStore(tmp_path / "other", max_owners=0)
