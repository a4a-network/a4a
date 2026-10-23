"""Previously unguarded reputation defenses, each protecting against forgery.

ORIGIN OF THIS FILE. On 2026-09-15 a mutation tool disabled defenses one by one and
checked whether the test suite noticed. In the reputation module, six suites detected
20 of 33 defenses, while 12 were detected by none.

Twelve defenses whose removal breaks no test are twelve places where a future change
could silently remove validation. The defenses worked; what was missing was proof
that they would KEEP working.

This file covers the costliest cases, where removal enables FORGED reputation rather
than a small numerical error. Every test has the same structure: a hostile case that
must be rejected and a positive control using equivalent data. Otherwise "always
zero" is indistinguishable from "the defense works."
"""
import pytest

from a4a import Keys, types
from a4a.event import Event
from a4a.reputation import (FUTURE_TOLERANCE_SECONDS, build_trust_graph,
                            compute_delivery_reputation)

HORIZON = 1000


def _trust(author: Keys, subject: str, weight: str, *, created_at: int = 900,
           kind: int = types.KIND_TRUST_ASSERTION) -> Event:
    ev = Event(kind=kind, tags=[["trust", subject], ["weight", weight]],
               content="", created_at=created_at)
    return ev.sign(author)


# --- Line 78: invalid signature and future timestamp ------------------------

def test_trust_assertion_with_a_broken_signature_is_ignored():
    """A trust assertion with an invalid signature creates no trust edge.

    Without this defense an attacker can INVENT an assertion in another person's
    name and make the graph accept a relationship that does not exist, without the
    author's key.
    """
    author, subject = Keys(), Keys()
    good = _trust(author, subject.pubkey_hex, "1.0")
    forged = _trust(author, subject.pubkey_hex, "1.0")
    forged.sig = "0" * 128                      # Replace signature; event remains structurally valid.

    graph = build_trust_graph([forged], now=HORIZON)
    assert not graph.get(author.pubkey_hex), "assertion with an invalid signature created a trust edge"

    # POSITIVE control: the same assertion with a valid signature creates an edge.
    graph_ok = build_trust_graph([good], now=HORIZON)
    assert graph_ok.get(author.pubkey_hex), "valid assertion created no edge; check is vacuous"


def test_trust_assertion_from_the_future_is_ignored():
    """Ignore an event from the future so the author's clock cannot define truth.

    The threshold is `now + FUTURE_TOLERANCE_SECONDS`, not `now`, intentionally
    allowing small clock skew. The first test used one second after `now` and proved
    NOTHING because the event remained within tolerance, reproducing the same class
    of testing error this file was created to fix.
    """
    author, subject = Keys(), Keys()
    future = _trust(author, subject.pubkey_hex, "1.0",
                    created_at=HORIZON + FUTURE_TOLERANCE_SECONDS + 1)
    assert not build_trust_graph([future], now=HORIZON).get(author.pubkey_hex), \
        "assertion beyond the time horizon was accepted"
    present = _trust(author, subject.pubkey_hex, "1.0", created_at=HORIZON - 1)
    assert build_trust_graph([present], now=HORIZON).get(author.pubkey_hex), \
        "assertion within the time horizon was ignored; check is vacuous"


# --- Line 457: delivery with an invalid signature ---------------------------

def _delivery(author: Keys, to: str, ident: str, *, created_at: int = 500) -> Event:
    return Event(kind=types.KIND_PRIVATE_MESSAGE,
                 tags=[["d", ident], ["p", to]], content="", created_at=created_at).sign(author)


def test_delivery_with_a_broken_signature_is_not_counted():
    """Exclude a delivery with an invalid signature from the denominator.

    Without this defense an attacker can damage another user's reputation by
    inventing deliveries in the recipient's name and leaving them unacknowledged,
    reducing the acknowledgement ratio without the victim's key.
    """
    sender, victim = Keys(), Keys()
    forged = _delivery(sender, victim.pubkey_hex, "a" * 64)
    forged.sig = "0" * 128

    rep = compute_delivery_reputation([forged], acks=[],
                                      agent=victim.pubkey_hex)
    assert rep.total_deliveries == 0, "delivery with an invalid signature was counted"

    good = _delivery(sender, victim.pubkey_hex, "b" * 64)
    rep_ok = compute_delivery_reputation([good], acks=[],
                                         agent=victim.pubkey_hex)
    assert rep_ok.total_deliveries == 1, "valid delivery was ignored; check is vacuous"


# --- Line 474: acknowledgement without a matching delivery ------------------

def test_acknowledgement_without_a_matching_delivery_is_ignored():
    """Ignore an acknowledgement without a matching delivery.

    Without this defense reputation can be INFLATED by acknowledging invented
    identifiers, increasing the ratio without a single real delivery.
    """
    sender, victim = Keys(), Keys()
    ack_only = Event(kind=types.KIND_ACK_RECEIPT,
                     tags=[["d", "f" * 64], ["status", "processed"]],
                     content="", created_at=600).sign(victim)
    rep = compute_delivery_reputation([], acks=[ack_only],
                                      agent=victim.pubkey_hex)
    assert rep.total_deliveries == 0 and rep.acknowledged == 0, \
        "acknowledgement without delivery was counted, allowing reputation inflation"

    # POSITIVE control: acknowledgement of a real matching delivery is counted.
    ident = "c" * 64
    delivery = _delivery(sender, victim.pubkey_hex, ident)
    ack = Event(kind=types.KIND_ACK_RECEIPT,
                tags=[["d", ident], ["status", "processed"]],
                content="", created_at=600).sign(victim)
    rep_ok = compute_delivery_reputation([delivery], acks=[ack],
                                         agent=victim.pubkey_hex)
    assert rep_ok.acknowledged == 1, "real acknowledgement was ignored; check is vacuous"


# =====================================================================================
# SECOND PASS. The 2026-09-16 run covered ALL eleven suites touching this module:
# nobody detected 8 of 33 defenses. Seven are covered below. The eighth (line 214,
# `raw is None` before `parse_uint`) cannot be distinguished by a test and is not a
# gap; the end of this file explains why.
#
# All seven reject the wrong kind of CORRECTLY SIGNED event. Signatures do not help
# here because the attacker signs with their own key and forges nobody else's.
# =====================================================================================

from a4a import crypto                                            # noqa: E402
from a4a.reputation import (agreement_parties,                    # noqa: E402
                            compute_completion_reputation, compute_reputation)


def _as_kind(ev: Event, kind: int, author: Keys) -> Event:
    """Republish the same event as a DIFFERENT kind with a valid author signature.

    This models bypassing a kind check: the content stays valid, only the numeric
    `kind` changes, and the event is honestly re-signed. Nothing is forged.
    """
    ev.kind = kind
    ev.sig = ""
    return ev.sign(author)


# --- Line 76: trust graph accepted events of ANY kind -----------------------

def test_trust_edge_is_not_built_from_an_event_of_another_kind():
    """Build trust edges only from TrustAssertion events (31020).

    Without a kind check, any event carrying `trust` and `weight` tags can declare
    trust: a private message, review, or profile. A relay normally applies filters,
    but event lists can also come from untrusted sources, so we must verify kind.
    """
    author, subject = Keys(), Keys()
    disguised = _as_kind(_trust(author, subject.pubkey_hex, "1.0"),
                         types.KIND_PRIVATE_MESSAGE, author)
    assert not build_trust_graph([disguised], now=HORIZON).get(author.pubkey_hex), \
        "event of another kind declared trust"

    proper = _trust(author, subject.pubkey_hex, "1.0")
    assert build_trust_graph([proper], now=HORIZON).get(author.pubkey_hex), \
        "real trust assertion created no edge; check is vacuous"


# --- Line 82: trust edge to NOBODY ------------------------------------------

def test_trust_assertion_without_a_subject_creates_no_edge():
    """An assertion with an empty `trust` tag creates no edge.

    Without this defense the graph gains an empty-name vertex: trust in "nobody."

    CORRECTION to the first version: this does NOT join paths. Two authors pointing
    at the empty vertex remain strangers to each other; the reviewer verified what
    had only been assumed. The cost is smaller and concerns correctness: the graph
    contains a relationship with nobody, forcing traversal code to know about an
    artifact vertex.
    """
    author = Keys()
    empty = _trust(author, "", "1.0")
    assert not build_trust_graph([empty], now=HORIZON).get(author.pubkey_hex), \
        "assertion without a subject created an edge"

    named = _trust(author, Keys().pubkey_hex, "1.0")
    assert build_trust_graph([named], now=HORIZON).get(author.pubkey_hex), \
        "assertion with a subject created no edge; check is vacuous"


# --- Line 92: dust instead of trust ----------------------------------------

def test_dust_weight_is_not_trust():
    """A weight below the meaningful threshold creates no edge.

    0.0000000001 is neither trust nor distrust; it is serialization noise.

    CORRECTION to the first comment: this cannot buy trust. A weight of 1e-10 is
    below the stranger baseline (WOT_BASELINE = 0.1), making the path worse than no
    path. Review corrected the unsupported claim that it outweighed the baseline.

    The real cost is elsewhere. Edges are deduplicated by (author, subject), with the
    newest assertion winning. Without this defense, later dust REPLACES a genuine
    earlier edge, turning numeric underflow into a statement the author never made.
    With the defense, the earlier edge remains, matching the code's rule that a value
    rounded to zero is not a declaration of distrust.
    """
    author, subject = Keys(), Keys()
    dust = _trust(author, subject.pubkey_hex, "0.0000000001")      # 1e-10 < MIN_MEANINGFUL.
    assert not build_trust_graph([dust], now=HORIZON).get(author.pubkey_hex), \
        "weight below the meaningful threshold created a trust edge"

    underflow = _trust(author, subject.pubkey_hex, "0." + "0" * 400 + "1")
    assert not build_trust_graph([underflow], now=HORIZON).get(author.pubkey_hex), \
        "weight that rounded to zero created a trust edge"

    real = _trust(author, subject.pubkey_hex, "0.5")
    assert build_trust_graph([real], now=HORIZON).get(author.pubkey_hex), \
        "meaningful weight created no edge; check is vacuous"


# --- Agreements: shared helper ---------------------------------------------

DEAL_PAST, DEAL_NOW = 1_700_000_000, 1_800_000_000


def _deal(a: Keys, b: Keys, *, deadline: int = DEAL_PAST, marker: str = "a") -> Event:
    ag = types.Agreement(intent_id=marker * 64, offer_id="o" * 64, price=1, currency="USD",
                         deadline=deadline, agent_a=a.pubkey_hex, agent_b=b.pubkey_hex,
                         sig_a="", sig_b="")
    digest = ag.digest()
    ag = ag.model_copy(update={"sig_a": crypto.sign(digest, a.privkey_hex),
                               "sig_b": crypto.sign(digest, b.privkey_hex)})
    return ag.to_event("d" * 64, publisher=a.pubkey_hex).sign(a)


# --- Line 160: another event kind granted review rights ---------------------

def test_agreement_of_another_kind_grants_no_right_to_review():
    """Treat only Agreement events (31004) as proof of a deal.

    `agreement_parties` decides WHO may submit a counted review: both reviewer and
    subject must be parties to the named deal. Without a kind check, any event with
    matching tags becomes an agreement.

    CORRECTION to the first version: "self-issued" was inaccurate. Both signatures
    are genuine and a separate signature check catches forgery. This test isolates
    strict event-kind validation, independent of signatures.
    """
    a, b = Keys(), Keys()
    deal = _deal(a, b)
    disguised = _as_kind(_deal(a, b, marker="b"), types.KIND_PRIVATE_MESSAGE, a)
    assert agreement_parties([disguised]) == {}, "event of another kind was accepted as a deal"
    assert agreement_parties([deal]), "real agreement was rejected; check is vacuous"


def test_review_backed_by_a_disguised_agreement_is_not_counted():
    """Carry the same bypass through to its effect on another user's reputation."""
    author, victim = Keys(), Keys()
    disguised = _as_kind(_deal(author, victim), types.KIND_PRIVATE_MESSAGE, author)
    review = Event(kind=types.KIND_REVIEW, created_at=DEAL_NOW - 10,
                   tags=[["rating", "1"], ["p", victim.pubkey_hex],
                         ["agreement", disguised.id]], content="").sign(author)
    rep = compute_reputation([review], now=DEAL_NOW, agreements=[disguised],
                             subject=victim.pubkey_hex)
    assert rep.total_reviews == 0, "review backed by a nonexistent deal was counted"

    real = _deal(author, victim, marker="c")
    honest = Event(kind=types.KIND_REVIEW, created_at=DEAL_NOW - 10,
                   tags=[["rating", "1"], ["p", victim.pubkey_hex],
                         ["agreement", real.id]], content="").sign(author)
    rep_ok = compute_reputation([honest], now=DEAL_NOW, agreements=[real],
                                subject=victim.pubkey_hex)
    assert rep_ok.total_reviews == 1, "review backed by a real deal was ignored; check is vacuous"


# --- Line 367: completion reputation accepted another event kind ------------

def test_completion_ignores_agreements_of_another_kind():
    """Count only Agreement events (31004) as unfinished deals.

    CORRECTION to the first version: an attacker cannot construct this ALONE. Both
    digest signatures are genuine and the counterparty signature is independently
    verified. Review confirmed directly that replacing the victim's signature with
    the attacker's causes rejection even when kind validation is DISABLED.

    This defense is therefore not the only boundary; it enforces strict event kind.
    An event of another kind carrying a real agreement body must not become a deal.
    Its value is independence from signature validation.
    """
    worker, customer = Keys(), Keys()
    disguised = _as_kind(_deal(customer, worker), types.KIND_TASK_RESULT, customer)
    rep = compute_completion_reputation([disguised], [], agent=worker.pubkey_hex,
                                        now=DEAL_NOW)
    assert rep.total_deals == 0, "event of another kind was accepted as a deal"

    real = _deal(customer, worker, marker="d")
    rep_ok = compute_completion_reputation([real], [], agent=worker.pubkey_hex, now=DEAL_NOW)
    assert rep_ok.total_deals == 1, "real agreement was ignored; check is vacuous"


# --- Line 373: OTHER PARTIES' deals were counted ----------------------------

def test_completion_ignores_deals_the_agent_is_not_a_party_to():
    """Count only deals that name the evaluated agent as a party.

    Without this defense the denominator includes STRANGERS' deals. An untrusted relay
    answering a query for the victim's deals can mix in real expired agreements from
    other parties. They are valid and signed by both sides, yet the victim is blamed
    for leaving them unfinished. No victim key or invented data is required.
    """
    victim, stranger_a, stranger_b = Keys(), Keys(), Keys()
    others = _deal(stranger_a, stranger_b)
    rep = compute_completion_reputation([others], [], agent=victim.pubkey_hex, now=DEAL_NOW)
    assert rep.total_deals == 0, "another party's deal affected completion reputation"

    own = _deal(stranger_a, victim, marker="e")
    rep_ok = compute_completion_reputation([own], [], agent=victim.pubkey_hex, now=DEAL_NOW)
    assert rep_ok.total_deals == 1, "agent's own deal was ignored; check is vacuous"


# --- Line 453: delivery without an identifier -------------------------------

def test_delivery_without_an_identifier_is_not_counted():
    """Exclude a delivery without a `d` tag from the denominator.

    The identifier is the only link between an acknowledgement and its delivery.
    Without it, acknowledgement is impossible: the delivery remains permanently
    unacknowledged and depresses the ratio at the cost of one omitted tag.
    """
    sender, victim = Keys(), Keys()
    nameless = Event(kind=types.KIND_PRIVATE_MESSAGE, tags=[["p", victim.pubkey_hex]],
                     content="", created_at=500).sign(sender)
    real = _delivery(sender, victim.pubkey_hex, "a" * 64)
    rep = compute_delivery_reputation([nameless, real], acks=[], agent=victim.pubkey_hex)
    assert rep.total_deliveries == 1, \
        f"delivery without an identifier was counted: {rep.total_deliveries} instead of 1"


# --- Line 214: redundancy, NOT A GAP ---------------------------------------
#
# No test can distinguish `if raw is None: continue` before `rating =
# parse_uint(raw)`: `parse_uint(None)` itself returns None, and the adjacent `if rating
# is None: continue` produces THE SAME result. Disabling the first check does not
# change behavior.
#
# This is a limitation of the mutation instrument, not a coverage gap. "Survived"
# means disabling the line did not change behavior, which can indicate either an
# untested defense or redundancy; only code review distinguishes them. The early exit
# remains because it is cheaper than parsing a known-empty input. This explanation
# prevents a future run from assigning someone to write an impossible test.
