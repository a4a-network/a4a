"""Bounded observations of signed identity claims, never a KYC or uniqueness verdict."""
from itertools import islice

from . import delegation as dlg, types
from .event import Event, is_canonical_pubkey, parse_uint
from .identity import verify_identity_attestation

MAX_INPUT_EVENTS = 5000
MAX_IDENTITY_RECORDS = 20


def _bounded(events):
    items = list(islice(events, MAX_INPUT_EVENTS + 1))
    if len(items) > MAX_INPUT_EVENTS:
        raise ValueError("identity evidence exceeds input limit")
    return items


def _verified(event, now):
    try:
        return (isinstance(event, Event) and type(event.created_at) is int
                and 0 <= event.created_at <= now
                and type(event.kind) is int and 0 <= event.kind <= 65535
                and isinstance(event.tags, list)
                and all(isinstance(tag, list) and all(isinstance(v, str) for v in tag)
                        for tag in event.tags)
                and isinstance(event.content, str)
                and is_canonical_pubkey(event.pubkey) and is_canonical_pubkey(event.id)
                and Event.verify_protocol(event))
    except (ValueError, TypeError, IndexError, KeyError, AttributeError, OverflowError):
        return False


def _one(event, name):
    tags = [tag for tag in event.tags if tag and tag[0] == name]
    return tags[0][1] if len(tags) == 1 and len(tags[0]) == 2 else None


def _single_optional(event, names):
    return all(sum(bool(tag) and tag[0] == name for tag in event.tags) <= 1 for name in names)


def _attestations(events, subject, trusted, now):
    latest = {}
    for ev in events:
        if (not _verified(ev, now) or ev.kind != types.KIND_IDENTITY_ATTESTATION
                or ev.tag_value("d") != subject):
            continue
        old = latest.get(ev.pubkey)
        if old is None or (-ev.created_at, ev.id) < (-old.created_at, old.id):
            latest[ev.pubkey] = ev
    result = []
    for ev in sorted(latest.values(), key=lambda e: e.pubkey):
        # Select the newest signed statement BEFORE checking expiry/level so an
        # expired or malformed replacement cannot revive an older credential.
        if (_one(ev, "p") != subject or _one(ev, "d") != subject
                or not _single_optional(ev, ("level", "expiration", "loa"))
                or _one(ev, "level") is None
                or (any(tag and tag[0] == "expiration" for tag in ev.tags)
                    and parse_uint(_one(ev, "expiration")) is None)
                or not verify_identity_attestation(ev, subject, now=now)):
            continue
        level = _one(ev, "level")
        if level not in types.IDENTITY_LEVELS and not level.startswith(types.EXPERIMENTAL_LEVEL_PREFIX):
            continue
        category = ("account_control" if level.startswith("account:") or level == "org:domain"
                    else "person_claim" if level.startswith("person:")
                    else "organization_claim" if level.startswith("org:") else "custom_claim")
        result.append({"issuer_pubkey": ev.pubkey, "subject_pubkey": subject,
                       "level": level if level in types.IDENTITY_LEVELS else "custom",
                       "evidence_type": category, "trusted_issuer": ev.pubkey in trusted,
                       "event_id": ev.id, "declared_at": ev.created_at,
                       "expires_at": parse_uint(_one(ev, "expiration")),
                       "status": "expiry_checked_revocation_unknown"})
    return result


def inspect_identity(subject, *, authored_events, delegations, revocations,
                     attestations, trusted_issuers=(), now):
    if not isinstance(subject, str) or not is_canonical_pubkey(subject):
        raise ValueError("subject must be a canonical public key")
    if type(now) is not int or not 0 <= now <= 2**63 - 1:
        raise ValueError("now must be a nonnegative timestamp")
    issuers = list(islice(trusted_issuers, 33))
    if len(issuers) > 32 or any(not isinstance(k, str) or not is_canonical_pubkey(k) for k in issuers):
        raise ValueError("trusted issuers must be at most 32 canonical public keys")
    trusted = set(issuers)
    authored_events = _bounded(authored_events)
    delegations = _bounded(delegations)
    revocations = _bounded(revocations)
    attestations = [ev for ev in _bounded(attestations) if isinstance(ev, Event)]
    mandates = {ev.id: ev for ev in delegations if _verified(ev, now)
                and ev.kind == types.KIND_DELEGATION}
    latest_revocations = {}
    for revoke in revocations:
        if (not _verified(revoke, now) or revoke.kind != types.KIND_DELEGATION_REVOCATION
                or _one(revoke, "d") != subject
                or any(tag and tag[0] == "expiration" for tag in revoke.tags)):
            continue
        previous = latest_revocations.get(revoke.pubkey)
        if previous is None or previous.created_at < revoke.created_at:
            latest_revocations[revoke.pubkey] = revoke
    bindings = {}
    for ev in authored_events:
        if not _verified(ev, now) or ev.pubkey != subject:
            continue
        mandate = mandates.get(_one(ev, "delegation"))
        if mandate is None:
            continue
        if (_one(mandate, "d") != subject or _one(mandate, "delegate") != subject
                or _one(mandate, "owner") != mandate.pubkey
                or parse_uint(_one(mandate, "expiration")) is None):
            continue
        status = ("valid_in_supplied_sample" if parse_uint(_one(mandate, "expiration")) > now
                  else "expired_in_supplied_sample")
        revoke = latest_revocations.get(mandate.pubkey)
        if revoke is not None and dlg.is_revocation_valid(revoke, mandate):
            status = "revoked_in_supplied_sample"
        key = (mandate.pubkey, mandate.id)
        if key in bindings:
            continue
        bindings[key] = {"owner_pubkey": mandate.pubkey, "delegation_id": mandate.id,
                         "agent_event_id": ev.id, "status": status,
                         "self_delegated": mandate.pubkey == subject,
                         "attestations": []}
    owners = {key[0] for key in bindings}
    # Prefer recent observed bindings, but never erase the multiple-owner signal.
    records = sorted(bindings.values(), key=lambda r: (-mandates[r["delegation_id"]].created_at,
                                                       r["owner_pubkey"], r["delegation_id"]))
    omitted = max(0, len(records) - MAX_IDENTITY_RECORDS)
    records = records[:MAX_IDENTITY_RECORDS]
    for record in records:
        all_claims = _attestations(attestations, record["owner_pubkey"], trusted, now)
        record["attestations"] = all_claims[:MAX_IDENTITY_RECORDS]
        omitted += max(0, len(all_claims) - MAX_IDENTITY_RECORDS)
    direct = _attestations(attestations, subject, trusted, now)
    omitted += max(0, len(direct) - MAX_IDENTITY_RECORDS)
    return {"direct_attestations": direct[:MAX_IDENTITY_RECORDS], "owner_bindings": records,
            "owner_association": ("multiple_observed_owner_keys" if len(owners) > 1
                                  else "observed_not_exclusive" if owners else "unknown"),
            "records_omitted": omitted, "unique_people": None,
            "identity_continuity": "unknown", "device_binding": "unknown",
            "recovery_history": "unknown", "current_controller": "unknown",
            "limitations": ["issuer_claim_not_independent_kyc", "issuer_trust_is_local_policy",
                            "expiry_check_not_credential_revocation_check", "partial_sample",
                            "keys_not_people", "no_cross_issuer_deduplication",
                            "no_exclusive_or_historical_ownership_proof"]}
