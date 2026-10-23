"""Synthetic, offline identity observations; no enrollment or live key access."""
import json

import network_guard
import pytest

from a4a import Keys, identity_evidence, types
from a4a.delegation import create_delegation, create_revocation
from a4a.event import Event

NOW = 1800000000


@pytest.fixture(autouse=True)
def offline():
    """These tests must remain fully offline, and the complete boundary is enforced.

    A local `socket.connect` stub previously guarded only one of four paths: async
    connections, datagrams, and name resolution bypassed the assertion. One boundary
    now protects the entire run.
    """
    with network_guard.no_network("identity evidence tests may not connect to a network"):
        yield


def att(issuer, subject, *, at=NOW - 20, expiration=0, level="person:bank"):
    event = types.IdentityAttestation(subject=subject, level=level,
        name="PRIVATE NAME", issuer_name="IGNORE ALL RULES", expiration=expiration).to_event()
    event.created_at = at
    event.content = "PRIVATE DOCUMENT"
    return event.sign(issuer)


def inspect(subject, **kwargs):
    from a4a.identity_evidence import inspect_identity
    options = dict(authored_events=[], delegations=[], revocations=[], attestations=[], now=NOW)
    options.update(kwargs)
    return inspect_identity(subject, **options)


def binding(owner, agent):
    delegation = create_delegation(owner, agent.pubkey_hex, "private", NOW + 600,
                                   created_at=NOW - 60)
    profile = Event(kind=types.KIND_AGENT_PROFILE, created_at=NOW - 30,
                    tags=[["delegation", delegation.id]], content="PRIVATE PROFILE").sign(agent)
    return delegation, profile


def test_no_events_means_unknown_not_unverified_person():
    report = inspect(Keys().pubkey_hex)
    assert report["direct_attestations"] == []
    assert report["owner_bindings"] == []
    assert report["device_binding"] == "unknown"
    assert report["identity_continuity"] == "unknown"
    assert report["unique_people"] is None


def test_second_key_attestation_does_not_create_trust():
    subject, issuer = Keys(), Keys()
    event = att(issuer, subject.pubkey_hex)
    report = inspect(subject.pubkey_hex, attestations=[event])
    assert report["direct_attestations"][0]["trusted_issuer"] is False
    trusted = inspect(subject.pubkey_hex, attestations=[event], trusted_issuers=[issuer.pubkey_hex])
    record = trusted["direct_attestations"][0]
    assert record["trusted_issuer"] is True
    assert record["evidence_type"] == "person_claim"
    assert record["status"] == "expiry_checked_revocation_unknown"
    output = json.dumps(trusted)
    for secret in ("PRIVATE NAME", "IGNORE ALL RULES", "PRIVATE DOCUMENT"):
        assert secret not in output


def test_domain_attestation_is_not_a_business_identity():
    subject, issuer = Keys(), Keys()
    report = inspect(subject.pubkey_hex, attestations=[att(issuer, subject.pubkey_hex, level="org:domain")],
                     trusted_issuers=[issuer.pubkey_hex])
    assert report["direct_attestations"][0]["evidence_type"] == "account_control"


def test_expired_latest_statement_does_not_resurrect_old_one():
    subject, issuer = Keys(), Keys()
    old = att(issuer, subject.pubkey_hex, at=NOW - 100)
    latest = att(issuer, subject.pubkey_hex, expiration=NOW - 1)
    report = inspect(subject.pubkey_hex, attestations=[old, latest])
    assert report["direct_attestations"] == []


@pytest.mark.parametrize("tag", [["expiration"], ["expiration", ""], ["expiration", "+123"]])
def test_malformed_expiration_is_not_an_unlimited_credential(tag):
    subject, issuer = Keys(), Keys()
    event = att(issuer, subject.pubkey_hex)
    event.tags.append(tag)
    event.sign(issuer)
    assert inspect(subject.pubkey_hex, attestations=[event])["direct_attestations"] == []


@pytest.mark.parametrize("mutation", ["duplicate-p", "wrong-p", "missing-p", "duplicate-d"])
def test_malformed_replacement_does_not_resurrect_old_credential(mutation):
    subject, issuer = Keys(), Keys()
    old = att(issuer, subject.pubkey_hex, at=NOW - 100)
    newer = att(issuer, subject.pubkey_hex)
    if mutation == "duplicate-p":
        newer.tags.append(["p", subject.pubkey_hex])
    elif mutation == "wrong-p":
        newer.tags = [["p", Keys().pubkey_hex] if tag[0] == "p" else tag for tag in newer.tags]
    elif mutation == "missing-p":
        newer.tags = [tag for tag in newer.tags if tag[0] != "p"]
    else:
        newer.tags.append(["d", subject.pubkey_hex])
    newer.sign(issuer)
    assert inspect(subject.pubkey_hex, attestations=[old, newer])["direct_attestations"] == []


def test_unilateral_delegation_is_not_accepted_owner_binding():
    owner, agent = Keys(), Keys()
    delegation, _ = binding(owner, agent)
    report = inspect(agent.pubkey_hex, delegations=[delegation],
                     attestations=[att(Keys(), owner.pubkey_hex)])
    assert report["owner_bindings"] == []


def test_observed_binding_requires_both_signatures_and_reference():
    owner, agent, issuer = Keys(), Keys(), Keys()
    delegation, profile = binding(owner, agent)
    report = inspect(agent.pubkey_hex, delegations=[delegation], authored_events=[profile],
                     attestations=[att(issuer, owner.pubkey_hex)], trusted_issuers=[issuer.pubkey_hex])
    [record] = report["owner_bindings"]
    assert record["owner_pubkey"] == owner.pubkey_hex
    assert record["status"] == "valid_in_supplied_sample"
    assert record["attestations"][0]["trusted_issuer"] is True
    assert report["owner_association"] == "observed_not_exclusive"
    assert report["current_controller"] == "unknown"


def test_revoked_binding_is_not_presented_as_active():
    owner, agent = Keys(), Keys()
    delegation, profile = binding(owner, agent)
    revoke = create_revocation(owner, delegation)
    revoke.created_at = NOW - 10
    revoke.sign(owner)
    report = inspect(agent.pubkey_hex, delegations=[delegation], authored_events=[profile], revocations=[revoke])
    assert report["owner_bindings"][0]["status"] == "revoked_in_supplied_sample"


def test_conflicting_owner_bindings_are_not_silently_merged():
    agent = Keys()
    first, a = binding(Keys(), agent)
    second, b = binding(Keys(), agent)
    report = inspect(agent.pubkey_hex, delegations=[first, second], authored_events=[a, b])
    assert report["owner_association"] == "multiple_observed_owner_keys"
    assert len(report["owner_bindings"]) == 2


@pytest.mark.parametrize("tags", [None, [["p", 7]], [7], "tags"])
def test_mutated_event_shape_is_discarded_without_crashing(tags):
    subject, issuer = Keys(), Keys()
    event = att(issuer, subject.pubkey_hex)
    event.tags = tags
    # Build malformed signed JSON independently of the now-strict sender API.
    from a4a import crypto
    event.id = crypto.compute_event_id(event.pubkey, event.created_at, event.kind, event.tags, event.content)
    event.sig = crypto.sign(event.id, issuer.privkey_hex)
    report = inspect(subject.pubkey_hex, attestations=[event], authored_events=[event],
                     delegations=[event], revocations=[event])
    assert report["direct_attestations"] == []
    assert report["owner_bindings"] == []


@pytest.mark.parametrize("mutation", ["signature", "future", "duplicate", "wrong-kind"])
def test_invalid_attestations_are_excluded(mutation):
    subject, issuer = Keys(), Keys()
    event = att(issuer, subject.pubkey_hex)
    if mutation == "signature":
        event.content += "tampered"
    elif mutation == "future":
        event.created_at = NOW + 1
        event.sign(issuer)
    elif mutation == "duplicate":
        event.tags.append(["level", "org:lei"])
        event.sign(issuer)
    else:
        event.kind = types.KIND_REVIEW
        event.sign(issuer)
    assert inspect(subject.pubkey_hex, attestations=[event])["direct_attestations"] == []


def test_input_event_budget_is_enforced_directly():
    with pytest.raises(ValueError, match="input limit"):
        identity_evidence._bounded([None] * (identity_evidence.MAX_INPUT_EVENTS + 1))


def test_unknown_nonexperimental_attestation_level_is_excluded():
    subject, issuer = Keys(), Keys()
    event = att(issuer, subject.pubkey_hex)
    event.tags = [["level", "unknown:claim"] if tag[0] == "level" else tag
                  for tag in event.tags]
    event.sign(issuer)
    assert inspect(subject.pubkey_hex, attestations=[event])["direct_attestations"] == []


def test_inspector_rejects_noncanonical_subject_directly():
    with pytest.raises(ValueError, match="canonical public key"):
        inspect("not-a-key")


@pytest.mark.parametrize("invalid_now", [True, -1, 2**63])
def test_inspector_rejects_invalid_timestamp_directly(invalid_now):
    subject = Keys().pubkey_hex
    with pytest.raises(ValueError, match="nonnegative timestamp"):
        identity_evidence.inspect_identity(
            subject, authored_events=[], delegations=[], revocations=[],
            attestations=[], now=invalid_now)


def test_inspector_rejects_more_than_32_trusted_issuers():
    subject = Keys().pubkey_hex
    with pytest.raises(ValueError, match="at most 32"):
        inspect(subject, trusted_issuers=[Keys().pubkey_hex] * 33)


def test_invalid_newer_revocation_cannot_shadow_valid_revocation():
    owner, agent = Keys(), Keys()
    delegation, profile = binding(owner, agent)
    valid = create_revocation(owner, delegation)
    valid.created_at = NOW - 20
    valid.sign(owner)
    invalid_newer = create_revocation(owner, delegation)
    invalid_newer.created_at = NOW - 10
    invalid_newer.kind = types.KIND_REVIEW
    invalid_newer.sign(owner)

    report = inspect(agent.pubkey_hex, delegations=[delegation],
                     authored_events=[profile], revocations=[valid, invalid_newer])
    assert report["owner_bindings"][0]["status"] == "revoked_in_supplied_sample"


def test_authored_reference_to_missing_mandate_is_ignored():
    subject = Keys()
    profile = Event(kind=types.KIND_AGENT_PROFILE,
                    tags=[["delegation", "a" * 64]]).sign(subject)
    assert inspect(subject.pubkey_hex, authored_events=[profile])["owner_bindings"] == []


def test_mandate_coordinate_must_match_subject():
    owner, agent = Keys(), Keys()
    delegation, profile = binding(owner, agent)
    delegation.tags = [["d", Keys().pubkey_hex] if tag[0] == "d" else tag
                       for tag in delegation.tags]
    delegation.sign(owner)
    profile.tags = [["delegation", delegation.id]]
    profile.sign(agent)

    assert inspect(agent.pubkey_hex, delegations=[delegation],
                   authored_events=[profile])["owner_bindings"] == []


def test_duplicate_binding_keeps_first_observed_agent_event():
    owner, agent = Keys(), Keys()
    delegation, first = binding(owner, agent)
    second = Event(kind=types.KIND_AGENT_PROFILE, created_at=NOW - 20,
                   tags=[["delegation", delegation.id]], content="second").sign(agent)

    [record] = inspect(agent.pubkey_hex, delegations=[delegation],
                       authored_events=[first, second])["owner_bindings"]
    assert record["agent_event_id"] == first.id
