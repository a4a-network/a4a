"""Completion reputation (§2.3.1): whether an agent delivered its deals.

This metric emerged from the fifth-wave economic review. The harmed party had only
one signal: a review rating, the most subjective and cheapest to manipulate (a
2026-09-05 measurement dropped another agent's reputation from 5.0 to 1.4 in 21
seconds). The most objective signal remained unused on the network: both parties
signed a deal, its deadline passed, and no result appeared.

These tests cover both what the metric counts and what it does NOT count: an
unconcluded deal, somebody else's result, a future-deadline deal, and a forgery
from an untrusted relay.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from a4a import Agent, Keys, crypto, types                       # noqa: E402
from a4a.event import Event                                      # noqa: E402
from a4a.reputation import compute_completion_reputation         # noqa: E402
from tests.fake_relay import FakeRelay                           # noqa: E402

PAST = 1_700_000_000
FUTURE = 2_000_000_000
NOW = 1_800_000_000


def _deal(a: Keys, b: Keys, deadline: int, *, both: bool = True, marker: str = "x") -> Event:
    ag = types.Agreement(intent_id=marker * 64, offer_id="o" * 64, price=1, currency="USD",
                         deadline=deadline, agent_a=a.pubkey_hex, agent_b=b.pubkey_hex,
                         sig_a="", sig_b="")
    digest = ag.digest()
    ag = ag.model_copy(update={
        "sig_a": crypto.sign(digest, a.privkey_hex),
        "sig_b": crypto.sign(digest, b.privkey_hex) if both else ""})
    return ag.to_event("d" * 64, publisher=a.pubkey_hex).sign(a)


def _result(who: Keys, agreement_ev: Event) -> Event:
    return Event(kind=types.KIND_TASK_RESULT, tags=[
        ["agreement", agreement_ev.id], ["e", agreement_ev.id],
        ["task_id", "t"], ["result_url", "https://x/y"], ["d", "r" + agreement_ev.id[:8]],
    ], content="").sign(who)


def test_counts_only_concluded_deals_whose_deadline_has_passed():
    worker, customer = Keys(), Keys()
    done = _deal(customer, worker, PAST, marker="a")
    open_deal = _deal(customer, worker, PAST, marker="b")
    future = _deal(customer, worker, FUTURE, marker="c")          # deadline not reached
    half = _deal(customer, worker, PAST, both=False, marker="e")  # one signature
    rep = compute_completion_reputation(
        [done, open_deal, future, half], [_result(worker, done)],
        agent=worker.pubkey_hex, now=NOW)
    assert (rep.completed, rep.total_deals) == (1, 2), f"{rep}"
    assert rep.score == 0.5


def test_result_from_someone_else_does_not_count():
    """Otherwise anyone, including the customer, could attest completion."""
    worker, customer, stranger = Keys(), Keys(), Keys()
    deal = _deal(customer, worker, PAST)
    rep = compute_completion_reputation([deal], [_result(stranger, deal)],
                                        agent=worker.pubkey_hex, now=NOW)
    assert (rep.completed, rep.total_deals) == (0, 1)


def test_forged_signature_does_not_add_to_the_denominator():
    """Events arrive from an untrusted relay, so signatures are verified here.

    Without this check, anyone could assign a failed deal to an agent, recreating
    exactly the manipulation this metric is meant to avoid unlike review ratings.
    """
    worker, customer = Keys(), Keys()
    deal = _deal(customer, worker, PAST)
    broken = Event(kind=deal.kind, created_at=deal.created_at,
                   tags=[t if t[0] != "sig_b" else ["sig_b", "0" * 128] for t in deal.tags],
                   content=deal.content).sign(customer)
    rep = compute_completion_reputation([broken], [], agent=worker.pubkey_hex, now=NOW)
    assert rep.total_deals == 0, "deal with an invalid signature entered the denominator"


def test_half_and_full_versions_are_one_deal():
    """Deal identity is the terms digest, not the event ID (§1.2).

    Half-signed and complete versions both remain on the network. Without merging,
    one agreement would count twice and distort the denominator precisely for the
    party that honestly completed it.
    """
    worker, customer = Keys(), Keys()
    full = _deal(customer, worker, PAST)
    half = _deal(customer, worker, PAST, both=False)
    again = _deal(customer, worker, PAST)          # same terms, different event
    rep = compute_completion_reputation([full, half, again], [_result(worker, full)],
                                        agent=worker.pubkey_hex, now=NOW)
    assert rep.total_deals == 1, f"one agreement was counted {rep.total_deals} times"


def test_weighted_ignores_deals_with_strangers():
    """Self-dealing is the metric's first stated boundary; trust paths mitigate it."""
    from a4a.reputation import build_trust_graph

    me, worker, friend, alter_ego = Keys(), Keys(), Keys(), Keys()
    real = _deal(friend, worker, PAST, marker="a")
    fake = _deal(alter_ego, worker, PAST, marker="b")
    # The graph edge comes from the `trust` tag, not `p`. The first test version
    # supplied `p`, producing an empty graph; weighted mode discarded EVERYTHING and
    # the test passed for the wrong reason until the loose-mode control was added.
    trust = Event(kind=types.KIND_TRUST_ASSERTION, tags=[
        ["trust", friend.pubkey_hex], ["p", friend.pubkey_hex],
        ["d", friend.pubkey_hex], ["weight", "1.0"]],
        content="").sign(me)
    graph = build_trust_graph([trust])
    rep = compute_completion_reputation(
        [real, fake], [_result(worker, real), _result(worker, fake)],
        agent=worker.pubkey_hex, now=NOW, trust_graph=graph, me=me.pubkey_hex)
    assert (rep.completed, rep.total_deals) == (1, 1), f"{rep}"

    loose = compute_completion_reputation(
        [real, fake], [_result(worker, real), _result(worker, fake)],
        agent=worker.pubkey_hex, now=NOW)
    assert loose.total_deals == 2, "both must count without a graph or the test is vacuous"


def test_nothing_to_judge_is_not_a_bad_score():
    """Zero deals means "nothing to judge", not "bad worker"."""
    rep = compute_completion_reputation([], [], agent="a" * 64, now=NOW)
    assert (rep.score, rep.total_deals, rep.completed) == (0.0, 0, 0)


async def test_over_the_wire_reads_someone_elses_deals():
    """An observer must see others' deals; `get_agreements` returns only its own.

    This was the economic-review finding: a third party saw zero deals when two
    existed because the method was designed around "mine".
    """
    worker, customer = Keys(), Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], customer) as c:
            deal = _deal(customer, worker, PAST)
            await c.relay.publish(deal)
            await c.relay.publish(_result(worker, deal))
        async with Agent([relay.url], Keys()) as observer:
            mine = await observer.get_agreements()
            rep = await observer.get_completion_reputation(worker.pubkey_hex)
    assert mine == [], "the observer has no deals of its own, as expected"
    assert (rep.completed, rep.total_deals) == (1, 1), f"{rep}"


# --- three zeros: "nothing to judge", "could not verify", "did not deliver" -----------
#
# Historical regression: none of 18 deals passed the new signature verifier after
# signature domains were separated that day, and the metric silently returned zero.
# That zero looked exactly like an honest "the worker delivered nothing": an accusation
# against a specific person rather than "we could not verify this".

def _deal_with_alien_signatures(a: Keys, b: Keys, deadline: int) -> Event:
    """Deal with two signatures that DO NOT verify under our digest formula."""
    ag = types.Agreement(intent_id="z" * 64, offer_id="o" * 64, price=1, currency="USD",
                         deadline=deadline, agent_a=a.pubkey_hex, agent_b=b.pubkey_hex,
                         sig_a="", sig_b="")
    alien = "f" * 64                      # "digest" under the previous formula
    ag = ag.model_copy(update={"sig_a": crypto.sign(alien, a.privkey_hex),
                               "sig_b": crypto.sign(alien, b.privkey_hex)})
    return ag.to_event("d" * 64, publisher=a.pubkey_hex).sign(a)


def test_unverifiable_deals_are_counted_and_named_not_silently_dropped():
    worker, customer = Keys(), Keys()
    rep = compute_completion_reputation(
        [_deal_with_alien_signatures(customer, worker, PAST)], [],
        agent=worker.pubkey_hex, now=NOW)
    assert rep.unverifiable == 1, "unverifiable deal disappeared silently"
    assert rep.total_deals == 0, "unverifiable deal entered the denominator"
    assert rep.completed == 0


def test_three_zeros_are_distinguishable():
    """Core property: the response reveals WHICH kind of zero it represents."""
    worker, customer = Keys(), Keys()
    nothing = compute_completion_reputation([], [], agent=worker.pubkey_hex, now=NOW)
    unproven = compute_completion_reputation(
        [_deal_with_alien_signatures(customer, worker, PAST)], [],
        agent=worker.pubkey_hex, now=NOW)
    failed = compute_completion_reputation(
        [_deal(customer, worker, PAST)], [], agent=worker.pubkey_hex, now=NOW)

    assert (nothing.total_deals, nothing.unverifiable) == (0, 0), "nothing to judge"
    assert (unproven.total_deals, unproven.unverifiable) == (0, 1), "could not verify"
    assert (failed.total_deals, failed.unverifiable) == (1, 0), "did not deliver"
    # All three score 0.0, so the response shape itself must distinguish them.
    assert nothing.score == unproven.score == failed.score == 0.0


def test_half_signed_deal_is_not_called_unverifiable():
    """A half-signed deal is not a deal at all, so nobody is accountable for it.

    It must not be mixed with an unverifiable deal: one means "there was no
    agreement", while the other means "there was an agreement we cannot verify".
    """
    worker, customer = Keys(), Keys()
    rep = compute_completion_reputation([_deal(customer, worker, PAST, both=False)], [],
                                        agent=worker.pubkey_hex, now=NOW)
    assert (rep.total_deals, rep.unverifiable) == (0, 0)
