"""Self-dealing inflates reputation with signatures controlled by the rated party.

`require_agreement=True` blocks one attack: inventing a review of somebody requires
their agreement signature. It does not block a second attack, which needed measurement
rather than assumption. On 2026-08-30, thirty agreements with self-controlled keys
produced **5.00 and thirty votes in every mode**, including weighted mode.

Weighting cannot help mathematically: the score is a weighted mean, so equal ratings
cancel their weights. Thirty five-star reviews weighted 0.1 still produce exactly 5.0.

Computation alone cannot solve this in an open network with free keys. Decision-makers
need the missing fact: how many votes came from identities on their own trust paths.
"""
import time

from a4a import crypto, types
from a4a.agent import Agent
from a4a.keys import Keys
from a4a.types import Agreement, agreement_digest

from tests.fake_relay import FakeRelay

N = 12


async def _self_deal(relay_url: str, target: Agent, count: int) -> list[Keys]:
    """Create `count` real self-controlled deals and one five-star review per key."""
    deadline = int(time.time()) + 3600
    sybils = []
    for i in range(count):
        sybil = Keys()
        intent, offer = f"i{i}".ljust(64, "0"), f"o{i}".ljust(64, "0")
        digest = agreement_digest(intent, offer, 1000, "USD", deadline,
                                  sybil.pubkey_hex, target.pubkey)
        terms = Agreement(intent_id=intent, offer_id=offer, price=1000, currency="USD",
                          deadline=deadline, agent_a=sybil.pubkey_hex,
                          agent_b=target.pubkey, sig_a="", sig_b="")
        deal = terms.model_copy(update={"sig_a": crypto.sign(digest, sybil.privkey_hex),
                                        "sig_b": target.sign_agreement(terms)})
        async with Agent([relay_url], keys=sybil) as s:
            deal_id = await s.publish_agreement(deal)
            await s.publish_review(deal_id, target.pubkey, 5, "excellent")
        sybils.append(sybil)
    return sybils


async def test_self_dealt_reviews_still_produce_a_perfect_score():
    """Pin the protection BOUNDARY rather than pretending this attack is solved.

    This deliberately asserts an undesirable fact: the mode described as Sybil-
    resistant does not stop this attack. While true, it belongs in the suite so future
    documentation cannot claim protection without a failing check.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as target, Agent([relay.url]) as observer:
            await _self_deal(relay.url, target, N)
            strict = await observer.get_reputation(target.pubkey, require_agreement=True)
    assert strict.total_reviews == N
    # Use a tolerance because the weighted floating-point mean may produce
    # 4.999999999999997. Exact equality would create a spurious intermittent failure.
    assert abs(strict.score - 5.0) < 1e-9


async def test_trusted_reviews_exposes_that_nobody_known_vouched():
    """Expose an actionable fact: none of these reviewers is on a known trust path."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as target, Agent([relay.url]) as observer:
            await _self_deal(relay.url, target, N)
            rep = await observer.get_reputation(target.pubkey, require_agreement=True,
                                                weighted=True)
    assert rep.total_reviews == N, "votes must count; the question is whether to trust them"
    assert rep.trusted_reviews == 0, (
        "no author should be trusted because the rated party created every key")


async def test_a_review_from_someone_we_trust_is_counted_as_trusted():
    """Control: `trusted_reviews` must not remain meaningless and permanently zero."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as target, Agent([relay.url]) as observer, \
                Agent([relay.url]) as friend:
            deadline = int(time.time()) + 3600
            digest = agreement_digest("i" * 64, "o" * 64, 1000, "USD", deadline,
                                      friend.pubkey, target.pubkey)
            terms = Agreement(intent_id="i" * 64, offer_id="o" * 64, price=1000,
                              currency="USD", deadline=deadline,
                              agent_a=friend.pubkey, agent_b=target.pubkey,
                              sig_a="", sig_b="")
            deal = terms.model_copy(update={"sig_a": friend.sign_agreement(terms),
                                            "sig_b": target.sign_agreement(terms)})
            deal_id = await friend.publish_agreement(deal)
            await friend.publish_review(deal_id, target.pubkey, 5, "all good")
            await observer.publish_trust(friend.pubkey, 1.0)

            rep = await observer.get_reputation(target.pubkey, require_agreement=True,
                                                weighted=True)
    assert rep.total_reviews == 1
    assert rep.trusted_reviews == 1
