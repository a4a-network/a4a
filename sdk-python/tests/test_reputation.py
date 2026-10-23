import time

import pytest

from a4a.event import Event
from a4a.keys import Keys
from a4a.reputation import compute_reputation, web_of_trust
from a4a.types import KIND_REVIEW, KIND_TRUST_ASSERTION

NOW = time.time()


#: Agent being rated. A review without a `p` tag is now rejected: its absence used to
#: bypass the "do not rate yourself" check, allowing an agent to give itself a 5
#: (internal audit F10, 2026-08-29). Fixtures must identify the recipient.
SUBJECT = "7a" * 32


def _review(rating: int, days_ago: float, subject: str = SUBJECT) -> Event:
    ev = Event(kind=KIND_REVIEW,
               tags=[["rating", str(rating)], ["p", subject]], content="")
    ev.created_at = int(NOW - days_ago * 86400)
    return ev.sign(Keys())


def test_empty_reviews():
    rep = compute_reputation([], now=NOW)
    assert rep.score == 0.0 and rep.total_reviews == 0


def test_fresh_reviews_average():
    rep = compute_reputation([_review(5, 0), _review(3, 0)], now=NOW)
    assert rep.score == pytest.approx(4.0)
    assert rep.total_reviews == 2


def test_age_decay_lowers_old_review_weight():
    # A recent 5 and a year-old 1: the old review weighs 0.5 and the recent one 1.0.
    rep = compute_reputation([_review(5, 0), _review(1, 365)], now=NOW)
    assert rep.score == pytest.approx((5 * 1.0 + 1 * 0.5) / 1.5)


def test_decay_floor_is_half():
    rep = compute_reputation([_review(4, 10 * 365)], now=NOW)  # very old
    assert rep.score == pytest.approx(4.0)  # weight 0.5, but there are no other reviews


def test_web_of_trust_is_implemented():
    # Previously a stub, now implemented (spec section 15); see test_web_of_trust.py.
    # Sign the assertion because the trust graph verifies incoming event signatures (F16).
    me_keys, friend = Keys(), "2b" * 32
    me = me_keys.pubkey_hex
    ta = Event(kind=KIND_TRUST_ASSERTION,
               tags=[["trust", friend], ["weight", "0.7"]], content="", created_at=0)
    ta.sign(me_keys)
    assert web_of_trust([ta], me, friend) == 0.7
    assert web_of_trust([], me, "3c" * 32) == 0.1   # baseline


def test_review_without_rating_tag_is_skipped():
    no_rating = Event(kind=KIND_REVIEW, tags=[["p", SUBJECT]], content="no rating")
    no_rating.created_at = int(NOW)
    no_rating = no_rating.sign(Keys())
    rep = compute_reputation([_review(4, 0), no_rating], now=NOW)
    assert rep.score == 4.0 and rep.total_reviews == 1


def test_review_with_malformed_rating_is_skipped():
    bad = Event(kind=KIND_REVIEW, tags=[["rating", "five"], ["p", SUBJECT]], content="")
    bad.created_at = int(NOW)
    bad = bad.sign(Keys())
    rep = compute_reputation([_review(4, 0), bad], now=NOW)
    assert rep.score == 4.0 and rep.total_reviews == 1


def test_out_of_scale_ratings_are_skipped():
    rep = compute_reputation(
        [_review(4, 0), _review(1000000, 0), _review(-50, 0), _review(0, 0)], now=NOW)
    assert rep.score == 4.0 and rep.total_reviews == 1
