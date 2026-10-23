"""Bounded, offline evidence summaries for a public key."""
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import islice

from .event import Event, is_canonical_pubkey, parse_uint
from .types import Agreement, KIND_AGREEMENT, KIND_REVIEW


_MAX_EVENTS = 5000
_DAY = 86400
_MAX_TIMESTAMP = 2 ** 63 - 1
_LIMITATIONS = (
    "keys_not_people",
    "collusion_possible",
    "signatures_not_work_or_payment",
    "declared_times_not_observed_times",
    "partial_sample",
)
_AGREEMENT_TAGS = {
    "intent": 2, "offer": 2, "price": 3, "deadline": 2,
    "agent_a": 2, "agent_b": 2, "sig_a": 2, "sig_b": 2, "status": 2,
}


@dataclass(frozen=True)
class _SignedAgreement:
    digest: str
    parties: frozenset[str]
    created_at: int
    price: int


@dataclass(frozen=True)
class _Review:
    event: Event
    target: str
    rating: int
    agreement_id: str | None


def _canonical_key(value) -> bool:
    return isinstance(value, str) and is_canonical_pubkey(value)


def _timestamp(value) -> bool:
    return type(value) is int and 0 <= value <= _MAX_TIMESTAMP


def _bounded(events: Iterable[Event], name: str) -> list[Event]:
    try:
        result = list(islice(iter(events), _MAX_EVENTS + 1))
    except TypeError:
        raise ValueError(f"{name} must be an iterable of events") from None
    if len(result) > _MAX_EVENTS:
        raise ValueError(f"{name} exceeds the {_MAX_EVENTS}-event bound")
    return result


def _verified(event: Event, kind: int) -> bool:
    # Event instances can be constructed or mutated without Pydantic validation.
    if not isinstance(event, Event):
        return False
    try:
        if (type(event.kind) is not int or event.kind != kind
                or not _timestamp(event.created_at)
                or not _canonical_key(event.id) or not _canonical_key(event.pubkey)
                or not isinstance(event.sig, str) or not isinstance(event.content, str)
                or not isinstance(event.tags, list)):
            return False
        if any(not isinstance(tag, list) or not tag
               or any(not isinstance(value, str) for value in tag) for tag in event.tags):
            return False
        return Event.verify_protocol(event)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return False


def _single_tags(event: Event, widths: dict[str, int], required: set[str]) -> dict | None:
    selected = {}
    for tag in event.tags:
        name = tag[0]
        if name in widths:
            if name in selected or len(tag) != widths[name]:
                return None
            selected[name] = tag
    return selected if required <= selected.keys() else None


def _signed_agreement(event: Event, subject: str, now: int) -> _SignedAgreement | None:
    if not _verified(event, KIND_AGREEMENT) or event.created_at > now:
        return None
    tags = _single_tags(event, _AGREEMENT_TAGS, set(_AGREEMENT_TAGS) - {"status"})
    if tags is None or any(not tag[1] for tag in tags.values()) or not tags["price"][2]:
        return None
    a, b = tags["agent_a"][1], tags["agent_b"][1]
    if (not _canonical_key(a) or not _canonical_key(b) or a == b
            or subject not in (a, b) or event.pubkey not in (a, b)):
        return None
    try:
        deal = Agreement.from_event(event)
        if not deal.verify_signatures():
            return None
        return _SignedAgreement(deal.digest(), frozenset((a, b)), event.created_at, deal.price)
    except (TypeError, ValueError, IndexError, KeyError):
        return None


def _review(event: Event, since: int, now: int,
            *, bound_to_agreement: bool = False) -> _Review | None:
    if not _verified(event, KIND_REVIEW) or not since <= event.created_at <= now:
        return None
    widths = {"p": 2, "rating": 2}
    if bound_to_agreement:
        widths["agreement"] = 2
    tags = _single_tags(event, widths, set(widths))
    if tags is None:
        return None
    target = tags["p"][1]
    rating = parse_uint(tags["rating"][1])
    if not _canonical_key(target) or event.pubkey == target or rating not in range(1, 6):
        return None
    agreement_id = tags["agreement"][1] if bound_to_agreement else None
    if bound_to_agreement and not _canonical_key(agreement_id):
        return None
    return _Review(event, target, rating, agreement_id)


def _raw_reviews(events: list[Event], authors: set[str], since: int,
                 now: int) -> dict[str, _Review]:
    found = {}
    for event in events:
        statement = _review(event, since, now)
        if statement is not None and event.pubkey in authors:
            found[event.id] = statement
    return found


def _activity(reviews: Iterable[_Review]) -> dict:
    reviews = list(reviews)
    return {
        "signed_review_statements": len(reviews),
        "five_star_statements": sum(review.rating == 5 for review in reviews),
        "distinct_target_keys": len({review.target for review in reviews}),
    }


def _latest_key(review: _Review) -> tuple[int, str]:
    return review.event.created_at, review.event.id


def _peak_24h(reviews: Iterable[_Review]) -> int:
    timestamps = sorted(review.event.created_at for review in reviews)
    left = peak = 0
    for right, timestamp in enumerate(timestamps):
        while timestamp - timestamps[left] > _DAY:
            left += 1
        peak = max(peak, right - left + 1)
    return peak


def analyze_counterparty(subject: str, *, reviews: Iterable[Event], agreements: Iterable[Event],
                         authored_reviews: Iterable[Event] = (),
                         reviewer_reviews: Iterable[Event] = (), now: int,
                         window_days: int = 30, reviewer_limit: int = 5) -> dict:
    """Summarize a bounded sample of signed key history, without a trust verdict.

    ``now`` and event timestamps are exact integers (not bool) in 0..2**63-1.
    The window starts at max(0, now - window_days * 86400). Its endpoints and
    rolling 24-hour endpoints are inclusive.
    Each collection is consumed at most 5001 times and rejected above 5000 entries.
    Invalid options raise ValueError; invalid events are discarded, not trusted.

    Incoming reviews require a subject-party agreement with a valid outer signature,
    a party publisher, and both inner signatures. Critical scalar tags must be single
    and exact-width. Agreement ``p`` routing tags are not authority; the two signed
    party fields are. Old valid agreements remain reference evidence. Deal counts use
    the earliest declared timestamp among supplied valid copies of each digest.
    Future agreements are excluded. Event-ID duplicates never add evidence. For each
    (reviewer, digest), the greatest (created_at, event ID) eligible review wins.

    Authored/reviewer activity counts only their respective supplied raw statements,
    deduplicated by event ID. Their agreement tags are not interpreted or verified.
    Only the subject / selected top-reviewer authors are included, respectively.
    Top reviewers sort by count descending, then pubkey ascending; their evidence IDs
    are the three newest eligible entries, using the same deterministic ID tie-break.

    ``discarded`` has one count per input collection: supplied entries not represented
    in that collection's aggregate, including duplicate/superseded events, unselected
    authors, and old agreements retained only for review eligibility. All report keys
    are fixed; no content, names, URLs, or arbitrary tags are returned. The static
    limitations apply even to large, internally consistent samples.
    """
    if not _canonical_key(subject):
        raise ValueError("subject must be a canonical lowercase hex public key")
    if type(window_days) is not int or not 1 <= window_days <= 365:
        raise ValueError("window_days must be an integer from 1 to 365")
    if type(reviewer_limit) is not int or not 0 <= reviewer_limit <= 10:
        raise ValueError("reviewer_limit must be an integer from 0 to 10")
    if not _timestamp(now):
        raise ValueError("now must be an integer from 0 to 2**63-1, not bool")
    inputs = {name: _bounded(events, name) for name, events in (
        ("reviews", reviews), ("agreements", agreements),
        ("authored_reviews", authored_reviews), ("reviewer_reviews", reviewer_reviews),
    )}
    since = max(0, now - window_days * _DAY)

    by_id: dict[str, _SignedAgreement] = {}
    by_digest: dict[str, _SignedAgreement] = {}
    for event in inputs["agreements"]:
        agreement = _signed_agreement(event, subject, now)
        if agreement is None:
            continue
        by_id[event.id] = agreement
        previous = by_digest.get(agreement.digest)
        if previous is None or agreement.created_at < previous.created_at:
            by_digest[agreement.digest] = agreement
    in_window = [deal for deal in by_digest.values() if since <= deal.created_at <= now]

    latest: dict[tuple[str, str], _Review] = {}
    seen_ids = set()
    for event in inputs["reviews"]:
        review = _review(event, since, now, bound_to_agreement=True)
        if review is None or review.target != subject:
            continue
        agreement = by_id.get(review.agreement_id)
        if agreement is None or event.pubkey not in agreement.parties or event.id in seen_ids:
            continue
        seen_ids.add(event.id)
        key = (event.pubkey, agreement.digest)
        previous = latest.get(key)
        if previous is None or _latest_key(review) > _latest_key(previous):
            latest[key] = review

    eligible = list(latest.values())
    counts = Counter(review.event.pubkey for review in eligible)
    ranked = sorted(counts, key=lambda pubkey: (-counts[pubkey], pubkey))
    selected = ranked[:reviewer_limit]
    authored = _raw_reviews(inputs["authored_reviews"], {subject}, since, now)
    reviewer_statements = _raw_reviews(inputs["reviewer_reviews"], set(selected), since, now)
    received_by_author = defaultdict(list)
    activity_by_author = defaultdict(list)
    for review in eligible:
        received_by_author[review.event.pubkey].append(review)
    for review in reviewer_statements.values():
        activity_by_author[review.event.pubkey].append(review)

    total = len(eligible)
    top_reviewers = [{
        "pubkey": pubkey,
        "eligible_reviews": counts[pubkey],
        "share": counts[pubkey] / total,
        "reviewer_activity": _activity(activity_by_author[pubkey]),
        "evidence_ids": [review.event.id for review in
                         sorted(received_by_author[pubkey], key=_latest_key, reverse=True)[:3]],
    } for pubkey in selected]
    return {
        "version": 1,
        "subject": subject,
        "window": {"since": since, "until": now, "timestamp_basis": "author_declared_unverified"},
        "reviews_received": {
            "eligible_reviews": total,
            "distinct_reviewer_keys": len(counts),
            "five_star_reviews": sum(review.rating == 5 for review in eligible),
            "top_reviewer_share": counts[ranked[0]] / total if total else None,
            "top_three_reviewers_share": sum(counts[key] for key in ranked[:3]) / total
            if total else None,
            "peak_24h_reviews": _peak_24h(eligible),
            "top_reviewers": top_reviewers,
        },
        "authored_review_activity": _activity(authored.values()),
        "agreements": {
            "distinct_signed_agreements": len(in_window),
            "zero_price_agreements": sum(deal.price == 0 for deal in in_window),
        },
        "discarded": {
            "reviews": len(inputs["reviews"]) - total,
            "agreements": len(inputs["agreements"]) - len(in_window),
            "authored_reviews": len(inputs["authored_reviews"]) - len(authored),
            "reviewer_reviews": len(inputs["reviewer_reviews"]) - len(reviewer_statements),
        },
        "limitations": list(_LIMITATIONS),
    }
