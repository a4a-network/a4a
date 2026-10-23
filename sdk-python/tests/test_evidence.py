"""Synthetic signed evidence only; sockets are forbidden before importing the analyzer."""
import json
import socket
from itertools import count, repeat

import pytest


NOW = 1_800_000_000
DAY = 86400
MAX_TIME = 2 ** 63 - 1
SINCE = NOW - 30 * DAY
LIMITATIONS = [
    "keys_not_people", "collusion_possible", "signatures_not_work_or_payment",
    "declared_times_not_observed_times", "partial_sample",
]


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Evidence tests must not use sockets or DNS")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, forbidden)


@pytest.fixture
def analyze(no_sockets):
    from a4a.evidence import analyze_counterparty
    return analyze_counterparty


class Samples:
    def __init__(self):
        from a4a import Keys, crypto, types
        from a4a.event import Event
        self.Keys, self.crypto, self.types, self.Event = Keys, crypto, types, Event
        self.subject, self.peer, self.other = self.key(1), self.key(2), self.key(3)
        self.serial = count(1)

    def key(self, number):
        return self.Keys(f"{number:064x}")

    def deal(self, *, a=None, b=None, price=0, at=NOW, publisher=None):
        a, b = a or self.peer, b or self.subject
        marker = next(self.serial)
        ag = self.types.Agreement(
            intent_id=f"{marker:064x}", offer_id=f"{marker + 10000:064x}",
            price=price, currency="USD", deadline=NOW + DAY,
            agent_a=a.pubkey_hex, agent_b=b.pubkey_hex, sig_a="", sig_b="",
            content="SECRET NAME https://private.invalid/terms",
        )
        ag.sig_a = self.crypto.sign(ag.digest(), a.privkey_hex)
        ag.sig_b = self.crypto.sign(ag.digest(), b.privkey_hex)
        ev = ag.to_event(publisher=(publisher or a).pubkey_hex)
        ev.created_at = at
        return ev.sign(publisher or a)

    def review(self, deal=None, *, author=None, target=None, rating="5", at=NOW):
        tags = [["p", target if target is not None else self.subject.pubkey_hex],
                ["rating", rating], ["d", str(next(self.serial))],
                ["private-url", "https://private.invalid/review"]]
        if deal is not None:
            tags.append(["agreement", deal.id if isinstance(deal, self.Event) else deal])
        ev = self.Event(kind=self.types.KIND_REVIEW, tags=tags,
                        content="SECRET NAME https://private.invalid/body")
        ev.created_at = at
        return ev.sign(author or self.peer)

    def change(self, event, *, author=None, remove=None, replace=None, append=None, **fields):
        ev = event.model_copy(deep=True)
        if remove is not None:
            ev.tags = [t for t in ev.tags if t[0] != remove]
        if replace is not None:
            ev.tags = [replace if t[0] == replace[0] else t for t in ev.tags]
        if append is not None:
            ev.tags.append(append)
        for name, value in fields.items():
            setattr(ev, name, value)
        # A peer can sign arbitrary JSON without the SDK's sender validation.
        # Keep invalid wire-format fixtures independent of Event.sign().
        signer = author or self.peer
        ev.pubkey = signer.pubkey_hex
        ev.id = self.crypto.compute_event_id(ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content)
        ev.sig = self.crypto.sign(ev.id, signer.privkey_hex)
        return ev


@pytest.fixture
def samples(no_sockets):
    return Samples()


def activity(statements=0, five=0, targets=0):
    return {"signed_review_statements": statements, "five_star_statements": five,
            "distinct_target_keys": targets}


def report(analyze, samples, reviews=(), agreements=(), **options):
    return analyze(samples.subject.pubkey_hex, reviews=reviews, agreements=agreements,
                   now=NOW, **options)


def test_socket_guard_is_active_before_analyzer_use():
    with pytest.raises(AssertionError, match="sockets"):
        socket.socket()
    with pytest.raises(AssertionError, match="DNS"):
        socket.getaddrinfo("never.invalid", 443)


def test_empty_report_exact_interface(analyze, samples):
    assert report(analyze, samples) == {
        "version": 1, "subject": samples.subject.pubkey_hex,
        "window": {"since": SINCE, "until": NOW,
                   "timestamp_basis": "author_declared_unverified"},
        "reviews_received": {
            "eligible_reviews": 0, "distinct_reviewer_keys": 0, "five_star_reviews": 0,
            "top_reviewer_share": None, "top_three_reviewers_share": None,
            "peak_24h_reviews": 0, "top_reviewers": [],
        },
        "authored_review_activity": activity(),
        "agreements": {"distinct_signed_agreements": 0, "zero_price_agreements": 0},
        "discarded": {"reviews": 0, "agreements": 0, "authored_reviews": 0,
                      "reviewer_reviews": 0},
        "limitations": LIMITATIONS,
    }


@pytest.mark.parametrize("subject", [None, True, 123, "", "a" * 63, "A" * 64,
                                     "g" * 64, "a" * 64 + "\n"])
def test_subject_must_be_canonical(analyze, subject):
    with pytest.raises(ValueError, match="subject"):
        analyze(subject, reviews=[], agreements=[], now=NOW)


@pytest.mark.parametrize("name,value", [
    ("window_days", v) for v in (True, False, 0, 366, 1.0, "30", None)
] + [("reviewer_limit", v) for v in (True, False, -1, 11, 5.0, "5", None)]
  + [("now", v) for v in (True, False, -1, float("nan"), float("inf"),
                         float("-inf"), "1800000000", None, 10 ** 400,
                         0.0, float(NOW), NOW + 0.5, MAX_TIME + 1)])
def test_options_are_strictly_validated(analyze, samples, name, value):
    kwargs = {"now": NOW, name: value}
    with pytest.raises(ValueError, match=name):
        analyze(samples.subject.pubkey_hex, reviews=[], agreements=[], **kwargs)


@pytest.mark.parametrize("days,limit,now", [
    (1, 0, 0), (365, 10, NOW), (30, 5, MAX_TIME),
    (1, 5, DAY - 1), (1, 5, DAY), (1, 5, DAY + 1),
])
def test_integer_timestamp_boundaries_and_clamped_window(analyze, samples, days, limit, now):
    result = analyze(samples.subject.pubkey_hex, reviews=[], agreements=[], now=now,
                     window_days=days, reviewer_limit=limit)
    assert result["window"] == {"since": max(0, now - days * DAY), "until": now,
                                "timestamp_basis": "author_declared_unverified"}
    assert type(result["window"]["since"]) is int
    assert type(result["window"]["until"]) is int


@pytest.mark.parametrize("now", [0, MAX_TIME])
def test_signed_events_at_timestamp_boundaries_count(analyze, samples, now):
    deal = samples.deal(at=now)
    review = samples.review(deal, at=now)
    authored = samples.review(author=samples.subject, target=samples.peer.pubkey_hex, at=now)
    result = analyze(samples.subject.pubkey_hex, reviews=[review], agreements=[deal], now=now,
                     authored_reviews=[authored], reviewer_reviews=[review])
    assert result["reviews_received"]["eligible_reviews"] == 1
    assert result["reviews_received"]["peak_24h_reviews"] == 1
    assert result["agreements"]["distinct_signed_agreements"] == 1
    assert result["authored_review_activity"] == activity(1, 1, 1)
    assert result["reviews_received"]["top_reviewers"][0]["reviewer_activity"] == activity(1, 1, 1)


def test_counts_concentration_top_order_and_bounded_evidence_ids(analyze, samples):
    keys = [samples.key(i) for i in range(2, 8)]
    counts = [4, 3, 2, 1, 1, 1]
    deals, reviews = [], []
    for key, number in zip(keys, counts):
        for i in range(number):
            deal = samples.deal(a=key, price=0 if i == 0 else 7)
            deals.append(deal)
            reviews.append(samples.review(deal, author=key, rating="4" if i == 1 else "5"))
    result = report(analyze, samples, reviews, deals)
    incoming = result["reviews_received"]
    assert incoming["eligible_reviews"] == 12
    assert incoming["distinct_reviewer_keys"] == 6
    assert incoming["five_star_reviews"] == 9
    assert incoming["top_reviewer_share"] == pytest.approx(4 / 12)
    assert incoming["top_three_reviewers_share"] == pytest.approx(9 / 12)
    assert incoming["peak_24h_reviews"] == 12
    expected = sorted(zip(keys, counts), key=lambda pair: (-pair[1], pair[0].pubkey_hex))[:5]
    for top, (key, number) in zip(incoming["top_reviewers"], expected, strict=True):
        assert top == {
            "pubkey": key.pubkey_hex, "eligible_reviews": number, "share": number / 12,
            "reviewer_activity": activity(),
            "evidence_ids": sorted((r.id for r in reviews if r.pubkey == key.pubkey_hex),
                                   reverse=True)[:3],
        }
    assert result["agreements"] == {"distinct_signed_agreements": 12, "zero_price_agreements": 6}
    text = json.dumps(result)
    for private in ("SECRET", "NAME", "https://", "private-url", "content", "tags"):
        assert private not in text


@pytest.mark.parametrize("limit", [0, 1, 5, 10])
def test_reviewer_limit_does_not_change_concentration(analyze, samples, limit):
    deals = [samples.deal(a=samples.key(i)) for i in range(2, 13)]
    reviews = [samples.review(d, author=samples.key(i)) for i, d in enumerate(deals, 2)]
    incoming = report(analyze, samples, reviews, deals, reviewer_limit=limit)["reviews_received"]
    assert incoming["eligible_reviews"] == 11
    assert incoming["top_reviewer_share"] == pytest.approx(1 / 11)
    assert incoming["top_three_reviewers_share"] == pytest.approx(3 / 11)
    assert [r["pubkey"] for r in incoming["top_reviewers"]] == sorted(r.pubkey for r in reviews)[:limit]


@pytest.mark.parametrize("rating", ["+5", "05", " 5", "5 ", "5.0", "5e0", "\u0665", "0", "6"])
def test_incoming_rating_is_canonical(analyze, samples, rating):
    deal = samples.deal()
    result = report(analyze, samples, [samples.review(deal, rating=rating)], [deal])
    assert result["reviews_received"]["eligible_reviews"] == 0
    assert result["discarded"]["reviews"] == 1


@pytest.mark.parametrize("tag", ["p", "rating", "agreement"])
@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra-value"])
def test_incoming_critical_tags_are_single_and_well_formed(analyze, samples, tag, mutation):
    deal = samples.deal()
    review = samples.review(deal)
    original = next(t for t in review.tags if t[0] == tag)
    if mutation == "missing":
        bad = samples.change(review, remove=tag)
    elif mutation == "duplicate":
        bad = samples.change(review, append=original[:])
    else:
        bad = samples.change(review, replace=original + ["ambiguous"])
    assert bad.verify()
    result = report(analyze, samples, [bad], [deal])
    assert result["reviews_received"]["eligible_reviews"] == 0
    assert result["discarded"]["reviews"] == 1


@pytest.mark.parametrize("case", ["wrong-kind", "forged-signature", "wrong-target", "self",
                                  "outsider", "noncanonical-target", "missing-agreement",
                                  "future", "old", "bool-time", "fractional-time", "negative-time"])
def test_incoming_untrusted_events_are_filtered(analyze, samples, case):
    deal = samples.deal()
    review = samples.review(deal)
    if case == "wrong-kind":
        review = samples.change(review, kind=samples.types.KIND_TASK_RESULT)
    elif case == "forged-signature":
        review.sig = "0" * 128
    elif case == "wrong-target":
        review = samples.change(review, replace=["p", samples.other.pubkey_hex])
    elif case == "self":
        review = samples.change(review, author=samples.subject)
    elif case == "outsider":
        review = samples.change(review, author=samples.other)
    elif case == "noncanonical-target":
        review = samples.change(review, replace=["p", samples.subject.pubkey_hex.upper()])
    elif case == "missing-agreement":
        review = samples.change(review, replace=["agreement", "f" * 64])
    else:
        timestamp = {"future": NOW + 1, "old": SINCE - 1, "bool-time": True,
                     "fractional-time": NOW - 0.5, "negative-time": -1}[case]
        review = samples.change(review, created_at=timestamp)
    result = report(analyze, samples, [review], [deal])
    assert result["reviews_received"]["eligible_reviews"] == 0
    assert result["discarded"]["reviews"] == 1


@pytest.mark.parametrize("tag", ["intent", "offer", "price", "deadline", "agent_a", "agent_b",
                                 "sig_a", "sig_b"])
@pytest.mark.parametrize("mutation", ["missing", "duplicate", "extra-value"])
def test_agreement_critical_tags_are_single_and_well_formed(analyze, samples, tag, mutation):
    deal = samples.deal()
    original = next(t for t in deal.tags if t[0] == tag)
    if mutation == "missing":
        deal = samples.change(deal, remove=tag)
    elif mutation == "duplicate":
        deal = samples.change(deal, append=original[:])
    else:
        deal = samples.change(deal, replace=original + ["ambiguous"])
    assert deal.verify()
    result = report(analyze, samples, [samples.review(deal)], [deal])
    assert result["agreements"]["distinct_signed_agreements"] == 0
    assert result["reviews_received"]["eligible_reviews"] == 0
    assert result["discarded"]["agreements"] == 1


@pytest.mark.parametrize("case", ["wrong-kind", "forged-outer", "forged-inner", "half-signed",
                                  "outsider-publisher", "same-party", "noncanonical-party",
                                  "noncanonical-price", "noncanonical-deadline", "duplicate-status",
                                  "unrelated-parties", "future", "bool-time", "empty-tag"])
def test_agreements_require_real_distinct_parties_and_all_signatures(analyze, samples, case):
    deal = samples.deal()
    if case == "wrong-kind":
        deal = samples.change(deal, kind=samples.types.KIND_REVIEW)
    elif case == "forged-outer":
        deal.sig = "0" * 128
    elif case in ("forged-inner", "half-signed"):
        deal = samples.change(deal, replace=["sig_b", "0" * 128 if case == "forged-inner" else ""])
    elif case == "outsider-publisher":
        deal = samples.change(deal, author=samples.other)
        assert deal.verify() and samples.types.Agreement.from_event(deal).verify_signatures()
    elif case == "same-party":
        deal = samples.deal(a=samples.subject, b=samples.subject)
        assert deal.verify() and samples.types.Agreement.from_event(deal).verify_signatures()
    elif case == "noncanonical-party":
        deal = samples.change(deal, replace=["agent_b", samples.subject.pubkey_hex.upper()])
    elif case == "noncanonical-price":
        deal = samples.change(deal, replace=["price", "00", "USD"])
    elif case == "noncanonical-deadline":
        deal = samples.change(deal, replace=["deadline", "+1800000000"])
    elif case == "duplicate-status":
        deal = samples.change(deal, append=["status", "agreed"])
    elif case == "unrelated-parties":
        deal = samples.deal(b=samples.other)
    elif case in ("future", "bool-time"):
        deal = samples.change(deal, created_at=NOW + 1 if case == "future" else True)
    else:
        deal = samples.change(deal, append=[])
    result = report(analyze, samples, [samples.review(deal)], [deal])
    assert result["agreements"]["distinct_signed_agreements"] == 0
    assert result["reviews_received"]["eligible_reviews"] == 0
    assert result["discarded"]["agreements"] == 1


def test_old_agreement_is_review_evidence_but_copies_do_not_refresh_deal_count(analyze, samples):
    old = samples.deal(at=SINCE - 1)
    copy = samples.change(old, created_at=NOW, author=samples.subject)
    review = samples.review(copy)
    result = report(analyze, samples, [review], [copy, old, copy])
    assert result["reviews_received"]["eligible_reviews"] == 1
    assert result["agreements"] == {"distinct_signed_agreements": 0, "zero_price_agreements": 0}
    assert result["discarded"]["agreements"] == 3
    assert result == report(analyze, samples, [review], [old, copy, copy])


def test_latest_review_per_digest_and_id_tie_are_order_independent(analyze, samples):
    deal = samples.deal(at=NOW - 100)
    copy = samples.change(deal, created_at=NOW)
    old = samples.review(deal, at=NOW - 1)
    tied = [samples.review(copy, rating="1"), samples.review(deal, rating="5")]
    winner = max(tied, key=lambda e: e.id)
    forged = samples.change(winner)
    forged.sig = "0" * 128
    events = [forged, old, *tied, winner]
    result = report(analyze, samples, events, [copy, deal, copy])
    incoming = result["reviews_received"]
    assert incoming["eligible_reviews"] == 1
    assert incoming["five_star_reviews"] == int(winner.tag_value("rating") == "5")
    assert incoming["top_reviewers"][0]["evidence_ids"] == [winner.id]
    assert result["agreements"] == {"distinct_signed_agreements": 1, "zero_price_agreements": 1}
    assert result["discarded"]["reviews"] == 4
    assert result["discarded"]["agreements"] == 2
    assert result == report(analyze, samples, list(reversed(events)), [deal, copy, deal])


def test_invalid_newer_review_does_not_replace_eligible_review(analyze, samples):
    deal = samples.deal()
    good = samples.review(deal, at=NOW - 10)
    bad = samples.review(deal, rating="1", at=NOW + 1)
    result = report(analyze, samples, [good, bad], [deal])["reviews_received"]
    assert result["eligible_reviews"] == result["five_star_reviews"] == 1
    assert result["top_reviewers"][0]["evidence_ids"] == [good.id]


def test_window_endpoints_are_inclusive(analyze, samples):
    deals = [samples.deal(at=SINCE), samples.deal(at=NOW)]
    reviews = [samples.review(deals[0], at=SINCE), samples.review(deals[1], at=NOW)]
    result = report(analyze, samples, reviews, deals)
    assert result["reviews_received"]["eligible_reviews"] == 2
    assert result["agreements"]["distinct_signed_agreements"] == 2


def test_peak_is_a_rolling_24_hours_not_calendar_days(analyze, samples):
    start = (NOW // DAY - 3) * DAY + 23 * 3600
    times = [start, start + 2 * 3600, start + 23 * 3600, start + DAY, start + DAY + 1]
    deals = [samples.deal(at=start - 1) for _ in times]
    reviews = [samples.review(deal, at=at) for deal, at in zip(deals, times)]
    result = report(analyze, samples, reviews[::-1] + [reviews[0]], deals)
    assert result["reviews_received"]["peak_24h_reviews"] == 4


def test_raw_activity_is_statements_not_verified_transactions(analyze, samples):
    deal = samples.deal()
    incoming = samples.review(deal)
    authored = [samples.review(author=samples.subject, target=samples.peer.pubkey_hex),
                samples.review("unverified-reference", author=samples.subject,
                               target=samples.other.pubkey_hex, rating="2")]
    peer_raw = [samples.review(), samples.review("unverified-reference", rating="3",
                                                 target=samples.other.pubkey_hex)]
    not_selected = samples.review(author=samples.other)
    result = report(analyze, samples, [incoming], [deal],
                    authored_reviews=authored + [authored[0], incoming],
                    reviewer_reviews=peer_raw + [peer_raw[0], not_selected])
    assert result["authored_review_activity"] == activity(2, 1, 2)
    assert result["reviews_received"]["top_reviewers"][0]["reviewer_activity"] == activity(2, 1, 2)
    assert result["discarded"]["authored_reviews"] == 2
    assert result["discarded"]["reviewer_reviews"] == 2
    zero = report(analyze, samples, [incoming], [deal], reviewer_limit=0, reviewer_reviews=peer_raw)
    assert zero["reviews_received"]["top_reviewers"] == []
    assert zero["discarded"]["reviewer_reviews"] == 2


@pytest.mark.parametrize("case", ["wrong-kind", "forged", "old", "future", "self", "other-author",
                                  "missing-p", "duplicate-p", "duplicate-rating", "bad-rating",
                                  "bad-target"])
@pytest.mark.parametrize("collection", ["authored_reviews", "reviewer_reviews"])
def test_raw_activity_filters_untrusted_statements(analyze, samples, case, collection):
    deal = samples.deal()
    incoming = samples.review(deal)
    author = samples.subject if collection == "authored_reviews" else samples.peer
    raw = samples.review(author=author, target=samples.other.pubkey_hex)
    if case == "wrong-kind":
        raw = samples.change(raw, author=author, kind=samples.types.KIND_TASK_RESULT)
    elif case == "forged":
        raw.sig = "0" * 128
    elif case in ("old", "future"):
        raw = samples.change(raw, author=author, created_at=SINCE - 1 if case == "old" else NOW + 1)
    elif case == "self":
        raw = samples.change(raw, author=author, replace=["p", author.pubkey_hex])
    elif case == "other-author":
        raw = samples.change(raw, author=samples.other)
    elif case == "missing-p":
        raw = samples.change(raw, author=author, remove="p")
    elif case == "duplicate-p":
        raw = samples.change(raw, author=author, append=["p", samples.other.pubkey_hex])
    elif case == "duplicate-rating":
        raw = samples.change(raw, author=author, append=["rating", "5"])
    elif case == "bad-rating":
        raw = samples.change(raw, author=author, replace=["rating", "+5"])
    else:
        raw = samples.change(raw, author=author, replace=["p", "BAD TARGET"])
    result = report(analyze, samples, [incoming], [deal], **{collection: [raw]})
    assert result["discarded"][collection] == 1
    assert result["authored_review_activity"] == activity()
    assert result["reviews_received"]["top_reviewers"][0]["reviewer_activity"] == activity()


@pytest.mark.parametrize("collection", ["reviews", "agreements", "authored_reviews", "reviewer_reviews"])
def test_each_collection_accepts_5000_but_rejects_5001(analyze, samples, collection):
    deal = samples.deal()
    incoming = samples.review(deal)
    authored = samples.review(author=samples.subject, target=samples.peer.pubkey_hex)
    values = {"reviews": [incoming], "agreements": [deal], "authored_reviews": [authored],
              "reviewer_reviews": [incoming]}
    event = values[collection][0]
    values[collection] = repeat(event, 5000)
    result = analyze(samples.subject.pubkey_hex, now=NOW, **values)
    assert result["discarded"][collection] == 4999
    values[collection] = repeat(event, 5001)
    with pytest.raises(ValueError, match=collection):
        analyze(samples.subject.pubkey_hex, now=NOW, **values)


def test_oversize_generator_consumption_is_bounded(analyze, samples):
    def too_many():
        yield from repeat(None, 5001)
        raise AssertionError("Analyzer consumed beyond the bound")
    with pytest.raises(ValueError, match="reviews"):
        report(analyze, samples, reviews=too_many())


def test_malformed_objects_are_discarded_and_inputs_unchanged(analyze, samples):
    deal = samples.deal()
    good = samples.review(deal)
    malformed = samples.Event.model_construct(kind=31005, created_at=NOW, tags=None)
    before = [deal.model_dump(), good.model_dump()]
    result = report(analyze, samples, [None, {}, malformed, good], [None, deal])
    assert result["reviews_received"]["eligible_reviews"] == 1
    assert result["discarded"]["reviews"] == 3
    assert result["discarded"]["agreements"] == 1
    assert before == [deal.model_dump(), good.model_dump()]


def test_verifier_does_not_touch_attributes_of_non_event_objects():
    from a4a import evidence, types

    class Poison:
        @property
        def kind(self):
            raise AssertionError("non-Event attributes must not be inspected")

    assert evidence._verified(Poison(), types.KIND_REVIEW) is False


def test_bound_review_rejects_noncanonical_agreement_id_directly(samples):
    from a4a import evidence

    event = samples.review("not-a-canonical-event-id")
    assert evidence._review(event, SINCE, NOW, bound_to_agreement=True) is None


@pytest.mark.parametrize("field,value", [
    ("kind", 31005.0), ("created_at", "1800000000"), ("id", None),
    ("pubkey", "A" * 64), ("sig", None), ("content", {}),
    ("tags", [["p", 123]]), ("tags", {"p": "a" * 64}),
])
def test_mutated_event_fields_never_crash_or_count(analyze, samples, field, value):
    deal = samples.deal()
    review = samples.review(deal)
    setattr(review, field, value)
    result = report(analyze, samples, [review], [deal])
    assert result["reviews_received"]["eligible_reviews"] == 0
    assert result["discarded"]["reviews"] == 1


@pytest.mark.parametrize("collection", ["reviews", "agreements", "authored_reviews", "reviewer_reviews"])
def test_noniterable_collection_is_a_named_input_error(analyze, samples, collection):
    kwargs = {"reviews": [], "agreements": [], collection: None}
    with pytest.raises(ValueError, match=collection):
        analyze(samples.subject.pubkey_hex, now=NOW, **kwargs)


def test_all_collection_bounds_are_checked_before_signatures(analyze, samples, monkeypatch):
    deal = samples.deal()
    review = samples.review(deal)

    def unexpected_verification(event):
        raise AssertionError("Oversized input must fail before signature work")

    monkeypatch.setattr(samples.Event, "verify", unexpected_verification)
    with pytest.raises(ValueError, match="reviewer_reviews"):
        report(analyze, samples, [review], [deal], reviewer_reviews=repeat(review, 5001))


def test_evidence_ids_are_only_the_three_newest_eligible_winners(analyze, samples):
    deals = [samples.deal() for _ in range(5)]
    times = [NOW - 100, NOW - 1, NOW - 50, NOW, NOW + 1]
    reviews = [samples.review(deal, at=at) for deal, at in zip(deals, times)]
    result = report(analyze, samples, reviews, deals)["reviews_received"]
    assert result["eligible_reviews"] == 4
    assert result["top_reviewers"][0]["evidence_ids"] == [reviews[i].id for i in (3, 1, 2)]


def test_raw_repeated_statements_do_not_become_verified_transaction_counts(analyze, samples):
    deal = samples.deal()
    reviews = [samples.review(deal, at=NOW - 1), samples.review(deal, rating="4")]
    result = report(analyze, samples, reviews, [deal], reviewer_reviews=reviews)
    incoming = result["reviews_received"]
    assert incoming["eligible_reviews"] == 1
    assert incoming["five_star_reviews"] == 0
    assert incoming["top_reviewers"][0]["reviewer_activity"] == activity(2, 1, 1)
    assert result["discarded"]["reviews"] == 1
    assert result["discarded"]["reviewer_reviews"] == 0


def test_raw_activity_is_only_for_selected_top_reviewers(analyze, samples):
    selected, excluded = sorted([samples.peer, samples.other], key=lambda k: k.pubkey_hex)
    deals = [samples.deal(a=selected), samples.deal(a=excluded)]
    reviews = [samples.review(deal, author=key) for deal, key in zip(deals, [selected, excluded])]
    raw = [samples.review(author=selected), samples.review(author=excluded),
           samples.review(author=excluded)]
    result = report(analyze, samples, reviews, deals, reviewer_reviews=raw, reviewer_limit=1)
    top = result["reviews_received"]["top_reviewers"]
    assert len(top) == 1 and top[0]["pubkey"] == selected.pubkey_hex
    assert top[0]["reviewer_activity"] == activity(1, 1, 1)
    assert result["discarded"]["reviewer_reviews"] == 2


def test_report_does_not_share_mutable_limitations(analyze, samples):
    result = report(analyze, samples)
    result["limitations"].clear()
    assert report(analyze, samples)["limitations"] == LIMITATIONS
