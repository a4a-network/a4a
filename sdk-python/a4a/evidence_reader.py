"""Budgeted primary-relay evidence reads. No publishing, discovery or KYC calls."""
import asyncio
from itertools import islice
import time

from . import types
from .event import is_canonical_pubkey
from .identity_evidence import inspect_identity, _one, _verified
from .relay import RelayError

MAX_READ_SECONDS = 45


def validate_options(subject, window_days, limit, reviewer_limit, trusted_issuers):
    if not isinstance(subject, str) or not is_canonical_pubkey(subject):
        raise ValueError("subject must be a canonical public key")
    for name, value, low, high in (("window_days", window_days, 1, 365),
                                   ("limit", limit, 1, 1000),
                                   ("reviewer_limit", reviewer_limit, 0, 10)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{name} must be {low}..{high}")
    issuers = list(islice(trusted_issuers, 33))
    if len(issuers) > 32 or any(not isinstance(k, str) or not is_canonical_pubkey(k) for k in issuers):
        raise ValueError("trusted issuers must be at most 32 canonical public keys")
    return tuple(sorted(set(issuers)))


def _matches(ev, flt, now):
    if not _verified(ev, now):
        return False
    if ev.kind not in flt["kinds"]:
        return False
    if "authors" in flt and ev.pubkey not in flt["authors"]:
        return False
    if "ids" in flt and ev.id not in flt["ids"]:
        return False
    if not flt.get("since", 0) <= ev.created_at <= flt.get("until", now):
        return False
    for name, expected in flt.items():
        if name.startswith("#") and not set(ev.tag_values(name[1:])).intersection(expected):
            return False
    return True


def _relay_scope(relay, queries) -> dict:
    """Describe coverage from MEASURED responses, not configuration.

    This once returned constant `"relay_scope": "configured_primary_relay_only"`, which
    was true only while the client used one node. The first fix counted CONFIGURED
    nodes, repeating the same mistake: an unavailable configured node contributes no
    evidence, yet the report included it in coverage. Overstatement is costly here
    because consumers use this field to decide how much to trust the report.

    Report configured and responding counts separately, using the LOWEST response
    count across all queries. If one query reached only one node, completeness is
    bounded by that node.

    Do not expose relay addresses, only counts. Counts are sufficient to assess
    coverage, while an owner's relay list does not belong in a shareable report.
    """
    clients = getattr(relay, "clients", None)
    configured = len(clients) if clients else 1
    answered = [q["relays_responded"] for q in queries if "relays_responded" in q]
    responded = min(answered) if answered else 0
    return {"relay_scope": ("configured_primary_relay_only" if configured == 1
                            else "configured_relay_set"),
            "relays_configured": configured,
            "relays_responded_at_least": responded}


async def read_counterparty_evidence(relay, subject, *, window_days=30, limit=200,
                                     reviewer_limit=5, trusted_issuers=()):
    issuers = validate_options(subject, window_days, limit, reviewer_limit, trusted_issuers)
    # Import after option validation: no network or profile access is needed here.
    from .evidence import analyze_counterparty

    now = int(time.time())
    since = max(0, now - window_days * 86400)
    queries = []

    async def fetch(label, flt, cap=limit):
        request = {**flt, "until": now, "limit": cap + 1}
        result = await relay.query_bounded(request, max_events=cap + 1)
        # Enforce the smaller transport ceiling; also bound this reader when
        # used with an alternative client ignoring the requested limit.
        inspected = list(islice(result.events, cap + 1))
        accepted = {}
        invalid = 0
        for ev in inspected:
            if _matches(ev, request, now):
                accepted[ev.id] = ev
            else:
                invalid += 1
        chosen = sorted(accepted.values(), key=lambda e: (-e.created_at, e.id))[:cap]
        queries.append({"section": label, "requested_limit": cap + 1,
                        "relays_responded": result.relays_responded,
                        "inspected_events": result.inspected_events, "accepted_events": len(chosen),
                        "discarded_invalid_or_out_of_scope": invalid + result.discarded_invalid_events,
                        "transport_discarded_invalid_events": result.discarded_invalid_events,
                        "connection_dropped_events": result.connection_dropped_events,
                        "possible_truncation": (result.truncated or len(inspected) >= cap
                                                or result.connection_dropped_events > 0)})
        return chosen

    async def collect():
        reviews = await fetch("received_reviews", {"kinds": [types.KIND_REVIEW],
                                                   "#p": [subject], "since": since})
        agreements = await fetch("subject_agreements", {"kinds": [types.KIND_AGREEMENT],
                                                         "#p": [subject], "since": since})
        authored = await fetch("authored_reviews", {"kinds": [types.KIND_REVIEW],
                                                     "authors": [subject], "since": since})
        profiles = await fetch("agent_profiles", {"kinds": [types.KIND_AGENT_PROFILE],
                                                    "authors": [subject]}, cap=min(limit, 20))
        references = {_one(ev, "agreement") for ev in reviews}
        references = {ref for ref in references if isinstance(ref, str) and is_canonical_pubkey(ref)}
        found_ids = {ev.id for ev in agreements}
        missing = sorted(references - found_ids)
        if missing:
            agreements += await fetch("referenced_agreements", {"kinds": [types.KIND_AGREEMENT],
                                                                  "ids": missing})
        unresolved = len(references - {ev.id for ev in agreements})
        preliminary = analyze_counterparty(subject, reviews=reviews, agreements=agreements,
            authored_reviews=authored, now=now, window_days=window_days, reviewer_limit=reviewer_limit)
        reviewers = [record["pubkey"] for record in preliminary["reviews_received"]["top_reviewers"]]
        reviewer_events = []
        reviewer_coverage = []
        # Each author gets its own bounded request: a busy reviewer cannot crowd
        # all the others out of one global author filter.
        for reviewer in reviewers:
            sample = await fetch("reviewer_activity", {"kinds": [types.KIND_REVIEW],
                "authors": [reviewer], "since": since}, cap=min(limit, 500))
            reviewer_events.extend(sample)
            reviewer_coverage.append({"pubkey": reviewer, "query_index": len(queries) - 1})
        signed_by_subject = profiles + authored
        mandate_refs = {_one(ev, "delegation") for ev in signed_by_subject}
        mandate_refs = sorted(ref for ref in mandate_refs
                              if isinstance(ref, str) and is_canonical_pubkey(ref))
        omitted_refs = max(0, len(mandate_refs) - limit)
        mandates = (await fetch("referenced_mandates", {"kinds": [types.KIND_DELEGATION],
                                                       "ids": mandate_refs[:limit]})
                    if mandate_refs else [])
        identity_probe = inspect_identity(subject, authored_events=signed_by_subject,
            delegations=mandates, revocations=[], attestations=[], trusted_issuers=issuers, now=now)
        owners = sorted({record["owner_pubkey"] for record in identity_probe["owner_bindings"]})
        revocations = (await fetch("owner_revocations", {"kinds": [types.KIND_DELEGATION_REVOCATION],
                         "authors": owners, "#d": [subject]}) if owners else [])
        attestations = await fetch("identity_attestations", {"kinds": [types.KIND_IDENTITY_ATTESTATION],
                                                             "#d": sorted(set(owners + [subject]))})
        report = analyze_counterparty(subject, reviews=reviews, agreements=agreements,
            authored_reviews=authored, reviewer_reviews=reviewer_events,
            now=now, window_days=window_days, reviewer_limit=reviewer_limit)
        report["identity"] = inspect_identity(subject, authored_events=signed_by_subject,
            delegations=mandates, revocations=revocations, attestations=attestations,
            trusted_issuers=issuers, now=now)
        report["coverage"] = {
            "queried_at": now, **_relay_scope(relay, queries),
            "network_completeness": "unknown", "snapshot_atomic": False,
            "sample_limit": limit, "queries": queries, "reviewers_queried": reviewers,
            "reviewer_samples": reviewer_coverage,
            "unresolved_agreement_references": unresolved,
            "omitted_mandate_references": omitted_refs,
            "identity_subjects_queried": sorted(set(owners + [subject])),
            "possible_truncation": (bool(omitted_refs) or report["identity"]["records_omitted"] > 0
                                    or any(q["possible_truncation"] for q in queries)),
            "unavailable": ["independent_observation_times", "global_account_age",
                            "private_outreach", "real_service_or_payment", "population_baseline",
                            "verified_reviewer_owner_deduplication", "complaint_lifecycle"],
        }
        return report

    try:
        async with asyncio.timeout(MAX_READ_SECONDS):
            return await collect()
    except TimeoutError:
        raise RelayError("counterparty evidence read budget exceeded; report unavailable") from None
