"""Sybil-resistant reputation (2026-08-17 audit, finding F1).

Two gaps existed before these changes:
  1. there was no author deduplication, so one key publishing N reviews of the same
     subject received N times the weight;
  2. stranger weight (WOT_BASELINE = 0.1) is positive and review count was unbounded,
     allowing a mass of Sybil keys to outweigh trusted reviewers.

The defenses are unconditional author deduplication and binding reviews to real deals
(`agreements=` counts only reviews by parties to a signed Agreement).
"""
import time

import pytest

from a4a import crypto, types
from a4a.event import Event
from a4a.keys import Keys
from a4a.reputation import build_trust_graph, compute_reputation

NOW = time.time()


def _review(author: Keys, target: str, rating: int, agreement_id: str = "",
            days_ago: float = 0.0):
    ev = types.Review(agreement_id=agreement_id, target=target,
                      rating=rating).to_event()
    ev.created_at = int(NOW - days_ago * 86400)
    return ev.sign(author)


def _agreement(a: Keys, b: Keys, *, valid_signatures: bool = True):
    """Return a deal signed by both parties (kind 31004)."""
    ag = types.Agreement(intent_id="i1", offer_id="o1", price=1000,
                         deadline=int(NOW) + 86400,
                         agent_a=a.pubkey_hex, agent_b=b.pubkey_hex,
                         sig_a="", sig_b="")
    digest = ag.digest()
    ag.sig_a = crypto.sign(digest, a.privkey_hex) if valid_signatures else "00" * 64
    ag.sig_b = crypto.sign(digest, b.privkey_hex) if valid_signatures else "00" * 64
    ev = ag.to_event()
    ev.created_at = int(NOW)
    return ev.sign(a)


def _trust(author: Keys, trusted: str, weight: float):
    ev = types.TrustAssertion(trusted=trusted, weight=weight).to_event()
    ev.created_at = int(NOW)
    return ev.sign(author)


# --- Author deduplication --------------------------------------------------

def test_multiple_reviews_from_one_author_count_once():
    """One author has one vote; 1,000 reviews do not receive 1,000 times the weight."""
    spammer, honest, victim = Keys(), Keys(), Keys()
    spam = [_review(spammer, victim.pubkey_hex, 5) for _ in range(1000)]
    fair = [_review(honest, victim.pubkey_hex, 1)]
    rep = compute_reputation(spam + fair, now=NOW)
    assert rep.total_reviews == 2, "more than one review per author was counted"
    assert rep.score == pytest.approx(3.0), "spammer received more than one vote of weight"


def test_latest_review_from_author_wins():
    """An author may change their mind; count only the latest review."""
    author, victim = Keys(), Keys()
    old = _review(author, victim.pubkey_hex, 5, days_ago=10)
    new = _review(author, victim.pubkey_hex, 2, days_ago=0)
    rep = compute_reputation([old, new], now=NOW)
    assert rep.total_reviews == 1
    assert rep.score == pytest.approx(2.0)


# --- Bind reviews to agreements -------------------------------------------

def test_review_without_agreement_is_ignored_when_binding_required():
    author, victim = Keys(), Keys()
    rev = _review(author, victim.pubkey_hex, 5, agreement_id="deadbeef")
    rep = compute_reputation([rev], now=NOW, agreements=[])
    assert rep.total_reviews == 0 and rep.score == 0.0


def test_review_from_real_party_of_agreement_counts():
    author, victim = Keys(), Keys()
    ag = _agreement(author, victim)
    rev = _review(author, victim.pubkey_hex, 4, agreement_id=ag.id)
    rep = compute_reputation([rev], now=NOW, agreements=[ag])
    assert rep.total_reviews == 1 and rep.score == pytest.approx(4.0)


def test_review_from_outsider_referencing_someone_elses_agreement_is_ignored():
    """Another party's agreement grants no review right to an outsider."""
    outsider, victim, party_a, party_b = Keys(), Keys(), Keys(), Keys()
    ag = _agreement(party_a, party_b)
    rev = _review(outsider, victim.pubkey_hex, 5, agreement_id=ag.id)
    rep = compute_reputation([rev], now=NOW, agreements=[ag])
    assert rep.total_reviews == 0


def test_review_is_ignored_when_target_is_not_party_of_agreement():
    """Ignore a party's review of someone who did not participate in the deal."""
    author, partner, victim = Keys(), Keys(), Keys()
    ag = _agreement(author, partner)
    rev = _review(author, victim.pubkey_hex, 5, agreement_id=ag.id)
    rep = compute_reputation([rev], now=NOW, agreements=[ag])
    assert rep.total_reviews == 0


def test_agreement_with_forged_party_signatures_is_ignored():
    """Count only mutually signed deals because agent_a/agent_b tags are trivial to forge."""
    author, victim = Keys(), Keys()
    ag = _agreement(author, victim, valid_signatures=False)
    rev = _review(author, victim.pubkey_hex, 5, agreement_id=ag.id)
    rep = compute_reputation([rev], now=NOW, agreements=[ag])
    assert rep.total_reviews == 0


def test_self_review_is_ignored():
    """Ignore self-review even when backed by a self-agreement."""
    me = Keys()
    ag = _agreement(me, me)
    rev = _review(me, me.pubkey_hex, 5, agreement_id=ag.id)
    rep = compute_reputation([rev], now=NOW, agreements=[ag])
    assert rep.total_reviews == 0


def test_one_review_per_agreement_per_author():
    """One deal grants one review; repeats for the same deal do not multiply weight."""
    author, victim = Keys(), Keys()
    ag = _agreement(author, victim)
    revs = [_review(author, victim.pubkey_hex, 5, agreement_id=ag.id) for _ in range(50)]
    rep = compute_reputation(revs, now=NOW, agreements=[ag])
    assert rep.total_reviews == 1


# --- Complete attack scenario ---------------------------------------------

def test_sybil_flood_cannot_move_score_of_real_deals():
    """Reproduce finding F1: 1,000 Sybil keys against five trusted reviews.

    Before the fix, score moved from 1.0 to 4.81. With agreement binding, Sybils
    have no victim-signed deals, so none of their reviews count.
    """
    me, victim = Keys(), Keys()
    honest = [Keys() for _ in range(5)]
    assertions = [_trust(me, h.pubkey_hex, 1.0) for h in honest]
    graph = build_trust_graph(assertions)

    agreements = [_agreement(h, victim) for h in honest]
    real = [_review(h, victim.pubkey_hex, 1, agreement_id=ag.id)
            for h, ag in zip(honest, agreements)]

    sybils = [Keys() for _ in range(1000)]
    flood = [_review(s, victim.pubkey_hex, 5, agreement_id="ff" * 32) for s in sybils]

    rep = compute_reputation(real + flood, now=NOW, agreements=agreements,
                             trust_graph=graph, me=me.pubkey_hex)
    assert rep.total_reviews == 5
    assert rep.score == pytest.approx(1.0)


# --- Agent.get_reputation integration -------------------------------------

async def test_agent_reputation_requires_agreement_end_to_end():
    """Across a relay, count a real-deal review and reject one without a deal."""
    from a4a.agent import Agent
    from tests.fake_relay import FakeRelay

    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b, \
                   Agent([relay.url]) as sybil:
            terms = types.Agreement(
                intent_id="i1", offer_id="o1", price=1000, currency="USD",
                deadline=int(NOW) + 86400, agent_a=a.pubkey, agent_b=b.pubkey,
                sig_a="", sig_b="")
            agreement = terms.model_copy(update={"sig_a": a.sign_agreement(terms),
                                                 "sig_b": b.sign_agreement(terms)})
            agreement_id = await a.publish_agreement(agreement)

            await a.publish_review(agreement_id, b.pubkey, 5, "backed by a real deal")
            await sybil.publish_review("ff" * 32, b.pubkey, 1, "without a deal")

            # `require_agreement=False` is now EXPLICIT. Since 2026-09-05 the
            # default is strict, making loose evaluation an intentional caller
            # choice rather than an accidental omission.
            loose = await a.get_reputation(b.pubkey, require_agreement=False)
            assert loose.total_reviews == 2, "loose mode should count both reviews"

            strict = await a.get_reputation(b.pubkey, require_agreement=True)
            assert strict.total_reviews == 1
            assert strict.score == pytest.approx(5.0)


# --- Internal audit findings from 2026-08-29 -------------------------------

def test_one_agreement_republished_gives_one_vote():
    """F2: republishing one agreement still grants only one vote.

    Agreement digest excludes event ID, so ONE real mutually signed deal can be
    published repeatedly with the same signatures and a new ID. "One author, one
    vote" deduplication used event ID and failed to collapse these copies, allowing
    one deal to yield fifty votes. This contradicted the promised resilience of
    `require_agreement`, the only mode recommended for trust decisions.
    """
    a, b = Keys(), Keys()
    digest = types.agreement_digest("i" * 64, "o" * 64, 100, "USD", 0,
                                    a.pubkey_hex, b.pubkey_hex)
    ag = types.Agreement(intent_id="i" * 64, offer_id="o" * 64, price=100,
                         currency="USD", deadline=0, agent_a=a.pubkey_hex,
                         agent_b=b.pubkey_hex,
                         sig_a=crypto.sign(digest, a.privkey_hex),
                         sig_b=crypto.sign(digest, b.privkey_hex))
    agreements, reviews = [], []
    for i in range(50):
        ev = ag.to_event()
        ev.created_at = 1000 + i          # Same content, different time, different ID.
        agreements.append(ev.sign(a))
        rev = types.Review(agreement_id=ev.id, target=b.pubkey_hex, rating=5).to_event()
        # Use the test's synthetic clock. Core audit F13 now rejects a review dated
        # in the future relative to `now`.
        rev.created_at = 1000 + i
        reviews.append(rev.sign(a))
    rep = compute_reputation(reviews, agreements=agreements, now=1000,
                             subject=b.pubkey_hex)
    assert rep.total_reviews == 1, f"one deal yielded {rep.total_reviews} votes"


def test_reviews_about_other_agents_are_not_counted():
    """F3: ignore valid reviews about OTHER agents mixed in by an untrusted relay."""
    victim, other, author = Keys(), Keys(), Keys()
    digest = types.agreement_digest("i" * 64, "o" * 64, 1, "USD", 0,
                                    author.pubkey_hex, other.pubkey_hex)
    ag = types.Agreement(intent_id="i" * 64, offer_id="o" * 64, price=1, currency="USD",
                         deadline=0, agent_a=author.pubkey_hex, agent_b=other.pubkey_hex,
                         sig_a=crypto.sign(digest, author.privkey_hex),
                         sig_b=crypto.sign(digest, other.privkey_hex)).to_event().sign(author)
    # Set event time EXPLICITLY. The previous version used wall-clock time while
    # evaluating at now=1000. The review fell beyond the allowed future horizon
    # (1900) and was rejected BEFORE addressee validation. The test stayed green
    # with validation REMOVED and therefore proved nothing. An external reviewer
    # found this while reviewing the file for translation (TEST-REP-001).
    foreign = types.Review(agreement_id=ag.id, target=other.pubkey_hex, rating=5)
    foreign = foreign.to_event()
    foreign.created_at = 1000
    foreign = foreign.sign(author)
    rep = compute_reputation([foreign], agreements=[ag], now=1000,
                             subject=victim.pubkey_hex)
    assert rep.total_reviews == 0, "review of another agent affected the victim's reputation"

    # POSITIVE control using the same data: the review must count when querying ITS
    # actual subject. Otherwise "always zero" is indistinguishable from "zero because
    # validation works," recreating the vacuity fixed here.
    rep_own = compute_reputation([foreign], agreements=[ag], now=1000,
                                 subject=other.pubkey_hex)
    assert rep_own.total_reviews == 1, (
        "review of the queried subject was ignored; check became vacuous again")


def test_malformed_agreement_does_not_break_reputation():
    """F4: a malformed agreement must not break reputation for everyone.

    An empty tag passes signature and model validation but used to break agreement
    parsing. One such relay event disabled reputation calculation for ALL users.
    """
    a = Keys()
    ev = Event(kind=types.KIND_AGREEMENT, tags=[[], ["d", "x"]], content="")
    ev.sign(a)
    rep = compute_reputation([], agreements=[ev], now=1000, subject="ff" * 32)
    assert rep.total_reviews == 0


def test_review_without_p_tag_is_dropped():
    """F10: drop a review without a `p` target tag.

    Without `p`, the self-review check never ran: `target is None` made the condition
    false, so basic mode let an agent rate itself five. A server-side `#p` filter will
    not return this event, but it can enter `compute_reputation` through a caller-built
    list or an untrusted relay that inserts it. The protocol also defines a targetless
    review as incomplete.
    """
    me = Keys()
    ev = Event(kind=types.KIND_REVIEW, tags=[["rating", "5"], ["d", "x"]], content="")
    ev.created_at = 1000
    ev.sign(me)
    assert compute_reputation([ev]).total_reviews == 0, "targetless review was counted"


async def test_default_reputation_is_the_safe_one():
    """Safe behavior must be the default, not a reward for careful reading.

    A 2026-09-05 live measurement used ten disposable keys and twenty events over 21
    seconds. Any caller using the method without arguments saw an honest agent fall
    from 5.0/5 to 1.4/5. The MCP tool defaulted to strict mode while the library did
    not, protecting our agent but not third-party implementations built on our SDK.
    """
    import inspect

    from a4a import Agent

    assert inspect.signature(Agent.get_reputation).parameters[
        "require_agreement"].default is True, "reputation default became loose again"


async def test_cheap_review_spam_does_not_move_the_default_score():
    """Exercise the complete attack through behavior rather than signature inspection."""
    from a4a import Agent
    from tests.fake_relay import FakeRelay

    victim, honest = Keys(), Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], honest) as a:
            deleg = "d" * 64
            agreement = types.Agreement(
                intent_id="i" * 64, offer_id="o" * 64, price=1, currency="USD",
                deadline=2 ** 31, agent_a=honest.pubkey_hex, agent_b=victim.pubkey_hex,
                sig_a="", sig_b="")
            # Include both signatures. Strict mode counts a review only for a MUTUALLY
            # signed deal. The first test version forgot this and produced zero instead
            # of one: the rule worked, but the test was wrong.
            agreement = agreement.model_copy(update={
                "sig_a": a.sign_agreement(agreement),
                "sig_b": crypto.sign(agreement.digest(), victim.privkey_hex)})
            a.delegation_id = deleg
            aid = await a.publish_agreement(agreement)
            await a.publish_review(aid, victim.pubkey_hex, 5, "")

            for i in range(10):                      # Ten disposable "unhappy" reviewers.
                spam = Keys()
                ev = types.Review(agreement_id="f" * 64, target=victim.pubkey_hex,
                                  rating=1, content="").to_event(deleg)
                await a.relay.publish(ev.sign(spam))

            default = await a.get_reputation(victim.pubkey_hex)
            loose = await a.get_reputation(victim.pubkey_hex, require_agreement=False)
    assert default.total_reviews == 1 and default.score == pytest.approx(5.0), \
        f"default allowed manipulation: {default.score} from {default.total_reviews} reviews"
    assert loose.total_reviews == 11, "loose mode must count everything or the test is empty"
    assert loose.score < 2, f"attack failed even in loose mode: {loose.score}"
