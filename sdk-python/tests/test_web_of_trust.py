"""Web of Trust (§15): trust graph and Sybil-resistant review weighting."""
from a4a import types
from a4a.agent import Agent
from a4a.event import Event
from a4a.keys import Keys
from a4a.reputation import (build_trust_graph, compute_reputation, trust_weight,
                            web_of_trust)
from tests.fake_relay import FakeRelay


#: Symbolic name to REAL key pair. There are two reasons: event parsing rejects a
#: noncanonical pubkey (F7), and `build_trust_graph` now verifies incoming assertion
#: signatures (F16), so an invented key cannot sign an event. Trust-graph keys are
#: plain dictionary strings and do not undergo validation, so symbolic names remain
#: acceptable there.
_KEYS: dict[str, Keys] = {}


def _keys(name: str) -> Keys:
    return _KEYS.setdefault(name, Keys())


def _pk(name: str) -> str:
    return _keys(name).pubkey_hex


def _ta(author, trusted, weight, created_at=1000):
    ev = Event(kind=types.KIND_TRUST_ASSERTION,
               tags=[["trust", _pk(trusted)], ["weight", str(weight)]],
               content="", created_at=created_at)
    return ev.sign(_keys(author))


def _review(author, rating, created_at, subject="7a" * 32):
    # The `p` tag is required: recipient-free reviews are discarded (core audit F10).
    ev = Event(kind=types.KIND_REVIEW,
               tags=[["rating", str(rating)], ["p", subject]],
               content="", created_at=created_at)
    return ev.sign(_keys(author))


# --- trust graph ---------------------------------------------------------------

def test_build_trust_graph_latest_wins():
    g = build_trust_graph([_ta("A", "B", 0.5, 100), _ta("A", "B", 0.9, 200)])
    assert g == {_pk("A"): {_pk("B"): 0.9}}


def test_build_trust_graph_skips_bad_weight():
    g = build_trust_graph([_ta("A", "B", 1.5), _ta("A", "C", 0.7)])  # 1.5 outside [0,1]
    assert g == {_pk("A"): {_pk("C"): 0.7}}


# --- trust_weight (BFS, product, depth, baseline) ------------------------------

def test_trust_weight_direct_and_chain():
    g = {"me": {"c": 0.8}, "c": {"t": 0.5}}
    assert trust_weight(g, "me", "c") == 0.8
    assert trust_weight(g, "me", "t") == 0.8 * 0.5


def test_trust_weight_best_path_wins():
    g = {"me": {"t": 0.5, "c": 0.9}, "c": {"t": 0.9}}
    assert trust_weight(g, "me", "t") == 0.9 * 0.9   # 0.81 beats direct 0.5


def test_trust_weight_baseline_and_self():
    assert trust_weight({}, "me", "stranger") == 0.1
    assert trust_weight({}, "me", "me") == 1.0


def test_trust_weight_depth_limit():
    g = {"me": {"a": 1.0}, "a": {"b": 1.0}, "b": {"c": 1.0}, "c": {"d": 1.0}, "d": {"t": 1.0}}
    assert trust_weight(g, "me", "t", max_depth=4) == 0.1   # five hops exceed limit
    assert trust_weight(g, "me", "t", max_depth=5) == 1.0


# --- F2: explicit distrust differs from an unknown key -------------------------

def test_explicit_distrust_is_zero_not_baseline():
    """A direct zero-weight edge means "I distrust this key", not missing data.

    Both cases previously returned the 0.1 baseline (audit F2).
    """
    assert trust_weight({"me": {"t": 0.0}}, "me", "t") == 0.0
    assert trust_weight({}, "me", "t") == 0.1          # unknown key keeps baseline


def test_direct_distrust_beats_indirect_path():
    """My direct statement outweighs every recommendation through intermediaries."""
    g = {"me": {"t": 0.0, "c": 1.0}, "c": {"t": 1.0}}
    assert trust_weight(g, "me", "t") == 0.0


def test_distrusted_key_cannot_lower_weight_of_others():
    """A key I distrust must not affect third-party weights.

    Otherwise anyone could lower an unknown key from 0.1 to 0.0 by publishing trust
    from a key I distrust. Distrust does not propagate along a chain.
    """
    g = {"me": {"bad": 0.0}, "bad": {"t": 1.0}}
    assert trust_weight(g, "me", "t") == 0.1


def test_distrust_of_a_friend_is_not_transitive():
    """Deliberate rule: a trusted intermediary's distrust does NOT zero the target.

    It merely prevents a positive path. Distrust is not transitive, as in PGP.
    """
    g = {"me": {"c": 1.0}, "c": {"t": 0.0}}
    assert trust_weight(g, "me", "t") == 0.1


def test_web_of_trust_wrapper():
    assert web_of_trust([_ta("me", "friend", 0.8)], _pk("me"), _pk("friend")) == 0.8


# --- review weighting: WoT suppresses Sybils ----------------------------------

def test_weighted_reputation_favors_trusted_over_sybils():
    now = 1_000_000
    reviews = [_review("friend", 5, now)] + [_review(f"s{i}", 1, now) for i in range(3)]
    graph = {_pk("me"): {_pk("friend"): 1.0}}            # friend trusted; Sybils at 0.1
    unweighted = compute_reputation(reviews, now=now).score
    weighted = compute_reputation(reviews, now=now, trust_graph=graph, me=_pk("me")).score
    assert unweighted < 2.5      # three Sybil ratings of 1 pull average down (~2.0)
    assert weighted > 4.0        # trusted friend's vote dominates


# --- relay integration --------------------------------------------------------

async def test_publish_trust_and_weighted_reputation_over_relay():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as me, Agent([relay.url]) as friend, \
                Agent([relay.url]) as sybil, Agent([relay.url]) as target:
            await friend.publish_review("agr1", target.pubkey, 5, "excellent")
            await sybil.publish_review("agr2", target.pubkey, 1, "rating attack")

            # Without WoT, the Sybil pulls the rating down. These reviews are not
            # tied to deals because this checks weighting rather than strict
            # agreement-backed Sybil resistance, so loose mode is explicit.
            plain = await me.get_reputation(target.pubkey, require_agreement=False)
            # I trust the friend, so the friend's review dominates.
            await me.publish_trust(friend.pubkey, 1.0, reason="verified")
            weighted = await me.get_reputation(target.pubkey, weighted=True,
                                               require_agreement=False)

            assert plain.total_reviews == 2
            assert weighted.score > plain.score      # WoT moves score toward trusted rating
            assert weighted.score > 4.0
