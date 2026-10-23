"""Reputation engine (specification Part VI, §15): reviews and weighted Web of Trust."""
import time
from collections import deque
from dataclasses import dataclass

from .event import Event, parse_decimal, parse_uint
from .types import (KIND_ACK_RECEIPT, KIND_AGREEMENT, KIND_PRIVATE_MESSAGE,
                    KIND_REVIEW, KIND_TASK_RESULT, KIND_TRUST_ASSERTION,
                    Agreement, agreement_digest)

WOT_BASELINE = 0.1        # Trust assigned to a stranger (no graph path), spec §15.4.
WOT_MAX_DEPTH = 4         # BFS depth limit, spec §15.5.


@dataclass
class Reputation:
    score: float
    total_reviews: int
    #: Number of counted votes from identities reachable through the caller's trust
    #: graph (weight greater than the stranger baseline).
    #:
    #: Why this is separate: `require_agreement=True` blocks fabricated reviews of
    #: someone with whom the author never dealt, because the target's signature is
    #: required. It does not block self-dealing: the target legitimately signs deals
    #: between keys it controls. A 2026-08-30 measurement showed that thirty self-deals
    #: produce a 5.00 score and thirty votes in every mode, including weighted mode;
    #: equal ratings cancel their weights in a weighted average.
    #:
    #: Computation cannot solve this in an open network where keys are free. This field
    #: exposes the missing fact to a decision-maker: "thirty votes, zero known voters."
    #: Without a trust graph (`trust_graph`/`me` omitted), it stays 0, meaning "not
    #: measured," not "nobody is trusted."
    trusted_reviews: int = 0


#: Clock-skew allowance. Events dated farther into the future are discarded because
#: `created_at` has no protocol upper bound, while both "latest wins" deduplication and
#: age decay favor the newest event. An author could replace an honest rating of one
#: with a five dated ten years ahead, keeping it maximally weighted indefinitely
#: (2026-08-29 internal audit, F13/F16).
FUTURE_TOLERANCE_SECONDS = 900

#: Below this value a weight is considered rounded to zero, not explicit distrust.
#: float("1e-400") collapses to 0.0, while semantic zero overrides every path; without
#: this threshold, an unfortunate rounding result became a blacklist marker (F16).
MIN_MEANINGFUL_WEIGHT = 1e-9


def _underflowed_to_zero(raw: str, value: float) -> bool:
    """Return whether a nonzero textual weight collapsed to 0.0 while parsing.

    The distinction must use the source string, not the value: `float("1e-400")` IS
    zero, so a magnitude threshold cannot help afterward. Semantic graph zero means
    explicit distrust and overrides every path, so failed rounding used to turn a
    tiny positive weight into a blacklist marker (2026-08-29 internal audit, F16).
    """
    if value != 0.0:
        return False
    return any(c in "123456789" for c in raw)


def build_trust_graph(assertions: list[Event],
                      now: float | None = None) -> dict[str, dict[str, float]]:
    """Build a trust graph from TrustAssertion events: {author: {trusted: weight}}.

    An edge A→B with weight w ∈ [0,1] means "A trusts B at w." The newest assertion
    by `created_at` wins for each (author, trusted) pair. Invalid/out-of-range events
    are skipped.

    Signatures are verified HERE because this public function accepts events from any
    source; relying on callers to obtain them through RelayClient was not a boundary.
    """
    now = now if now is not None else time.time()
    horizon = now + FUTURE_TOLERANCE_SECONDS
    graph: dict[str, dict[str, float]] = {}
    latest: dict[tuple[str, str], float] = {}
    for ev in assertions:
        if ev.kind != KIND_TRUST_ASSERTION:
            continue
        if ev.created_at > horizon or not ev.verify_protocol():
            continue
        trusted = ev.tag_value("trust")
        raw = ev.tag_value("weight")
        if not trusted or raw is None:
            continue
        # Accept only canonical decimals. `float()` accepted "+0.5", "5e-1", and
        # "0.5_0", making the same event create an edge here but not in a strict
        # implementation (2026-09-04 wire probe).
        w = parse_decimal(raw)
        if w is None:
            continue
        if not 0.0 <= w <= 1.0:
            continue
        if _underflowed_to_zero(raw, w) or 0.0 < w < MIN_MEANINGFUL_WEIGHT:
            continue  # Rounded to zero; this is not an assertion of distrust.
        key = (ev.pubkey, trusted)
        if ev.created_at >= latest.get(key, -1.0):
            latest[key] = ev.created_at
            graph.setdefault(ev.pubkey, {})[trusted] = w
    return graph


def trust_weight(graph: dict[str, dict[str, float]], me: str, target: str,
                 max_depth: int = WOT_MAX_DEPTH, baseline: float = WOT_BASELINE) -> float:
    """Return trust weight from `me` to `target` through the graph (spec §15).

    Direct trust equals the edge weight. Chained trust is the product along a path
    (`w(A→C)·w(C→B)`); the best (maximum) path wins, with BFS depth ≤ max_depth.
    No path yields `baseline` (0.1); self-trust is 1.0.

    A direct `me→target` edge of 0.0 ASSERTS distrust rather than omitting a claim. It
    returns 0.0 and overrides every intermediary path (audit F2); previously explicit
    distrust and an unknown identity both produced the baseline.

    Distrust is NOT transitive (as in PGP): a zero edge does not carry a path, but it
    does not propagate zero either. Otherwise a key I distrust could reduce any third
    party from baseline to zero merely by publishing trust in that party.
    """
    if me == target:
        return 1.0
    direct = graph.get(me, {}).get(target)
    if direct is not None and direct == 0.0:
        return 0.0
    best: dict[str, float] = {me: 1.0}
    result = 0.0
    queue: deque[tuple[str, float, int]] = deque([(me, 1.0, 0)])
    while queue:
        node, acc, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for nxt, w in graph.get(node, {}).items():
            prod = acc * w
            if nxt == target:
                result = max(result, prod)
            elif prod > best.get(nxt, 0.0):
                best[nxt] = prod
                queue.append((nxt, prod, depth + 1))
    return result if result > 0.0 else baseline


def web_of_trust(assertions: list[Event], me: str, target: str) -> float:
    """Build a TrustAssertion graph and return trust_weight(me→target)."""
    return trust_weight(build_trust_graph(assertions), me, target)


def agreement_parties(agreements: list[Event]) -> dict[str, tuple[str, frozenset[str]]]:
    """Return {Agreement event id: (terms digest, {agent_a, agent_b})}.

    Count only MUTUALLY signed agreements. The `agent_a`/`agent_b` tags are trivial to
    forge, so both parties' signatures over the digest must verify.

    The mapping key is the event id, but its value includes the **terms digest**, which
    defines agreement identity. The digest is signed BEFORE publication and excludes
    the event id, so the same agreement can be published repeatedly with unchanged
    signatures but a new id. Deduplicating by id failed to collapse these copies, and
    one real agreement could produce fifty votes (2026-08-29 internal audit, F2).

    Malformed or forged events are silently skipped because the input is untrusted.
    """
    parties: dict[str, tuple[str, frozenset[str]]] = {}
    for ev in agreements:
        if ev.kind != KIND_AGREEMENT or not ev.verify_protocol():
            continue
        try:
            ag = Agreement.from_event(ev)
            if not ag.verify_signatures():
                continue
            digest = agreement_digest(ag.intent_id, ag.offer_id, ag.price, ag.currency,
                                      ag.deadline, ag.agent_a, ag.agent_b)
        except (ValueError, TypeError, IndexError, KeyError):
            # Empty or shortened tags can pass signature and model validation but used
            # to break parsing with IndexError/KeyError (F4).
            continue
        parties[ev.id] = (digest, frozenset({ag.agent_a, ag.agent_b}))
    return parties


def compute_reputation(reviews: list[Event], now: float | None = None, *,
                       trust_graph: dict[str, dict[str, float]] | None = None,
                       me: str | None = None,
                       agreements: list[Event] | None = None,
                       subject: str | None = None) -> Reputation:
    """Return a weighted rating.

    Review weight is trust_weight(graph, me, author) · age_decay, where
    age_decay = max(0.5, 1 − days/365) (spec §15).

    Without `agreements`, only each author's newest review counts. With `agreements`,
    deduplication uses author plus agreement digest: republishing the same agreement
    adds no vote, while distinct agreements by one author produce distinct reviews.

    `agreements` contains Agreement events (31004) proving review eligibility. When
    supplied, ONLY reviews whose `agreement` tag names a mutually signed agreement
    between the author and target count. This rejects reviews lacking the target's
    agreement signature, but not self-dealing or collusion: someone controlling both
    parties can sign arbitrarily many distinct agreements.

    Without `trust_graph`/`me`, trust_weight is 1.0 (all reviews equal). With Web of
    Trust, a stranger's review has baseline weight 0.1 and a trusted review up to 1.0.

    Neither weighting nor `agreements` provides general Sybil resistance: stranger
    weight is positive, and keys/self-deals are unlimited. Equal ratings cancel their
    weights in the average. `trusted_reviews` counts entries with graph weight > 0.1,
    not independent people or services; a path may traverse the rated key. History
    belongs to a key, not a verified current owner, so key transfer does not reset it.
    A rating proves neither payment, actual work, nor authority.
    """
    now = now if now is not None else time.time()
    horizon = now + FUTURE_TOLERANCE_SECONDS
    parties = agreement_parties(agreements) if agreements is not None else None
    # Deduplicate each key to its newest review by created_at.
    latest: dict[tuple[str, str], Event] = {}
    for ev in reviews:
        if ev.kind != KIND_REVIEW or not ev.verify_protocol():
            continue
        if ev.created_at > horizon:
            continue  # A future review would win both deduplication and age weight (F13).
        raw = ev.tag_value("rating")
        if raw is None:
            continue
        # Canonical syntax only: `int()` accepted "+5", " 5", and Arabic "٥", so the
        # same vote counted here but not in a strict implementation (wire probe).
        rating = parse_uint(raw)
        if rating is None:
            continue  # Silently skip malformed network ratings.
        if not 1 <= rating <= 5:
            continue  # Ignore network ratings outside the protocol scale.
        target = ev.tag_value("p")
        # Always reject a review without a target. Previously the "no self-review"
        # check simply did not run when `p` was absent, so the review counted and an
        # agent could give itself a five in baseline mode. A server-side `#p` filter
        # would not return it, but manually assembled inputs or a hostile relay could.
        # A targetless review is incomplete under the protocol regardless (F10).
        if not target:
            continue
        if ev.pubkey == target:
            continue  # Self-reviews do not count.
        # Check the review target explicitly. Reviews arrive from an untrusted relay,
        # which can mix valid reviews of OTHER identities and their real agreements
        # into a query about the victim. Without this check they became the victim's
        # reputation (2026-08-29 internal audit, F3).
        if subject is not None and target != subject:
            continue
        agreement_id = ev.tag_value("agreement") or ""
        if parties is not None:
            found = parties.get(agreement_id)
            if found is None:
                continue  # No supporting agreement.
            digest, pair = found
            if ev.pubkey not in pair or target not in pair:
                continue  # Author or target is not a party to this agreement.
            # Deduplicate by agreement DIGEST, not event id. Republishing the same
            # agreement preserves signatures but produces a new id (F2).
            key = (ev.pubkey, digest)
        else:
            key = (ev.pubkey, "")  # Without agreements, each author gets one vote.
        prev = latest.get(key)
        if prev is None or ev.created_at >= prev.created_at:
            latest[key] = ev

    total_weight = 0.0
    weighted_sum = 0.0
    count = 0
    trusted = 0
    for ev in latest.values():
        rating = parse_uint(ev.tag_value("rating"))  # Already parsed above.
        days = max(0.0, (now - ev.created_at) / 86400)
        decay = max(0.5, 1.0 - days / 365)
        tw = 1.0
        if trust_graph is not None and me is not None:
            tw = trust_weight(trust_graph, me, ev.pubkey)
            # Strictly above baseline: exactly baseline means no path (a stranger).
            # Explicit distrust can be lower and does not make the voter known.
            if tw > WOT_BASELINE:
                trusted += 1
        weight = decay * tw
        weighted_sum += rating * weight
        total_weight += weight
        count += 1
    score = weighted_sum / total_weight if total_weight else 0.0
    return Reputation(score=score, total_reviews=count, trusted_reviews=trusted)


@dataclass
class DeliveryReputation:
    """Reputation from verifiable delivery (v0.3 plan, P2).

    Derived from network-observable events: signed acknowledgements (kind 31034)
    issued by an agent for deliveries addressed to it (kind 31033). Any observer can
    compute it WITHOUT decryption because only the d and p tags are needed.
    """
    score: float           # processed / total_deliveries (0.0 when there are none)
    total_deliveries: int  # Unique deliveries addressed to the agent.
    acknowledged: int      # Deliveries with any ACK (received/processed/failed).
    processed: int         # Deliveries with successful status=processed ACK.


@dataclass
class CompletionReputation:
    """COMPLETION reputation (spec §2.3.1): did the agent finish its agreements?

    Why this sits beside reviews: an injured party previously had only review ratings,
    the most subjective and cheapest signal to manipulate. A 2026-09-05 measurement
    dropped another identity's reputation from 5.0 to 1.4 in 21 seconds using reviews.
    Meanwhile the strongest objective signal was unused: both parties signed an
    agreement, its deadline passed, and no result exists—facts any observer can see.

    **Why it is harder to corrupt than reviews.** The agent controls its denominator:
    an agreement needs TWO signatures, so the agent signs only work it accepts. Nobody
    can unilaterally assign it a failed agreement. Without an arbiter, this also
    distinguishes a vanished executor from a dissatisfied customer: the former posts
    no result; the latter rates poorly despite a published result.

    **Limits every reader must understand (§2.3.1):**
    1. self-deals inflate it just like reviews—the agent deals with its own keys and
       publishes the results; the mitigation is the same `trust_graph`;
    2. publishing a result does not prove good work; the protocol records events, not
       quality;
    3. a missing result is not always the executor's fault; the customer may have
       cancelled out of band. This is a signal, not a verdict.

    **Three zeros that must not be conflated (§2.3.1).** A zero is read as "completed
    nothing," a claim about a particular identity. Therefore distinguish:

    1. `total_deals == 0 and unverifiable == 0`: nothing to judge because no agreement
       has passed its deadline. This is no rating, not a bad rating;
    2. `unverifiable > 0`: agreements exist, but this code cannot verify their
       signatures. Agreements signed using the old digest formula look this way (the
       domains were separated on 2026-09-05, and none of the 18 earlier production
       agreements verifies under the new code). Calling that "not completed" would be
       a baseless accusation;
    3. `total_deals > 0 and completed == 0`: only this means "not completed."

    Case 2 is the most dangerous because it looks **exactly like** case 3 unless the
    reader knows the data history. We found it while reviewing our own run: zero meaning
    "not measured" was indistinguishable from zero meaning "measured and empty," while
    also accusing an identity.
    """

    score: float        # completed / total_deals (0.0 when there is nothing to count)
    total_deals: int    # Concluded agreements past deadline where agent is a party.
    completed: int      # Those for which the agent published a result (31032).
    unverifiable: int   # Agreements whose signatures THIS code cannot verify.


def compute_completion_reputation(agreements: list[Event],
                                  results: list[Event],
                                  *,
                                  agent: str,
                                  now: int | None = None,
                                  trust_graph: dict[str, dict[str, float]] | None = None,
                                  me: str | None = None) -> CompletionReputation:
    """Compute completion reputation from an agent's agreements and results (31032).

    Events come from an untrusted relay, so verify everything locally: both signatures
    over the digest, that the agent is actually a party, and that it published the result.

    Identify an agreement by its TERMS DIGEST, not event id. Half-signed and fully
    signed versions have different ids; without joining them one deal counts twice.

    With `trust_graph` and `me`, count only counterparties reachable through the
    evaluator's trust graph. Without it, self-deals are indistinguishable from real
    ones, as stated in the class docstring's first limitation.
    """
    now = int(time.time()) if now is None else now
    concluded: dict[str, set[str]] = {}            # digest -> complete event IDs
    unverifiable: dict[str, str] = {}               # digest -> event id
    for ev in agreements:
        if ev.kind != KIND_AGREEMENT or not ev.verify_protocol():
            continue
        try:
            deal = Agreement.from_event(ev)
        except Exception:                            # noqa: BLE001 — untrusted network input
            continue
        if agent not in (deal.agent_a, deal.agent_b):
            continue
        if not deal.sig_a or not deal.sig_b:
            continue                                  # Half-signed is not an agreement.
        if deal.deadline >= now:
            continue                                  # Deadline has not passed; too early to judge.
        peer = deal.agent_b if deal.agent_a == agent else deal.agent_a
        if trust_graph is not None and me is not None:
            if trust_weight(trust_graph, me, peer) <= WOT_BASELINE:
                continue                              # Stranger counterparties do not count.
        if not deal.verify_signatures():
            # Both signatures exist but fail: another digest formula, forgery, or
            # corruption in transit. Do not drop this silently, because "could not
            # verify" would become indistinguishable from the accusation "did not finish."
            unverifiable.setdefault(deal.digest(), ev.id)
            continue
        concluded.setdefault(deal.digest(), set()).add(ev.id)

    if not concluded:
        return CompletionReputation(score=0.0, total_deals=0, completed=0,
                                    unverifiable=len(unverifiable))

    # A result links to its agreement with `e`. Count only results published by the
    # agent itself; otherwise anyone could attest to "completion." Empty and bare
    # tags are valid Nostr input and contribute no reference. Each complete event
    # for a terms digest is an alias, so query order cannot change the outcome.
    done_ids = {eid for ev in results if ev.kind == KIND_TASK_RESULT and ev.pubkey == agent
                and ev.verify_protocol()
                for eid in ev.tag_values("e")}
    completed = sum(1 for aliases in concluded.values() if aliases & done_ids)
    total = len(concluded)
    return CompletionReputation(score=completed / total, total_deals=total,
                                completed=completed, unverifiable=len(unverifiable))


#: Maximum unacknowledged deliveries from one sender included in the denominator.
#:
#: The denominator includes every message addressed to an agent, and becoming a target
#: requires no consent. Any outsider could therefore spend fifty cheap events to lower
#: an honest reputation from 1.00 to 0.06, with no defense because a target cannot opt
#: out (2026-08-29 internal audit). This cap limits ONE party's influence. Keys are
#: free, so the cap only raises the attack cost; the trust graph below closes it.
MAX_UNACKED_PER_SENDER = 3


def compute_delivery_reputation(messages: list[Event],
                                acks: list[Event],
                                *,
                                agent: str | None = None,
                                trust_graph: dict[str, dict[str, float]] | None = None,
                                me: str | None = None,
                                max_unacked_per_sender: int | None = MAX_UNACKED_PER_SENDER,
                                ) -> DeliveryReputation:
    """Compute delivery reputation from messages to, and ACKs issued by, an agent.

    `messages` are deliveries addressed to the agent (kind 31033, #p==agent); `acks`
    are acknowledgements ISSUED by the agent (kind 31034, author==agent).

    **The evaluator chooses who enters the denominator.** Supply `trust_graph` and
    `me` to exclude deliveries from senders at stranger-level trust (`WOT_BASELINE`).
    Without a graph all senders count, but `max_unacked_per_sender` limits one party.

    `agent` identifies whose score this is and SHOULD be supplied. Lists come from an
    untrusted relay, which can mix in someone else's ACKs (letting outsiders draw the
    score) or deliveries to another target (inflating anyone's denominator). Omitting
    `agent` disables these checks only for compatibility.

    Signatures are verified here because this public function accepts arbitrary events.

    The metric is still NOT Sybil-resistant in the other direction: an agent can send
    itself fake deliveries and acknowledge them. The same graph mitigates cheap upward
    inflation; binding evidence to agreements, as `compute_reputation` does, is needed
    for a stronger boundary.
    """
    acks = [ev for ev in acks
            if ev.kind == KIND_ACK_RECEIPT and ev.verify_protocol()
            and (agent is None or ev.pubkey == agent)]
    acked_ids = {d for ev in acks if (d := ev.tag_value("d"))}
    deliveries: set[str] = set()
    unacked_seen: dict[str, int] = {}
    for ev in messages:
        if ev.kind != KIND_PRIVATE_MESSAGE:
            continue
        d = ev.tag_value("d")
        if not d:
            continue
        if agent is not None and ev.tag_value("p") != agent:
            continue  # Delivery to another agent does not enter this denominator.
        if not ev.verify_protocol():
            continue
        if trust_graph is not None and me is not None:
            # Exclude baseline-weight strangers; otherwise creating one key is enough
            # to damage someone else's reputation.
            if trust_weight(trust_graph, me, ev.pubkey) <= WOT_BASELINE:
                continue
        if d not in acked_ids and max_unacked_per_sender is not None:
            seen = unacked_seen.get(ev.pubkey, 0)
            if seen >= max_unacked_per_sender:
                continue
            unacked_seen[ev.pubkey] = seen + 1
        deliveries.add(d)
    latest_status: dict[str, str | None] = {}
    latest_time: dict[str, float] = {}
    for ev in acks:
        d = ev.tag_value("d")
        if not d or d not in deliveries:
            continue  # Ignore ACKs without a matching delivery to this agent.
        if ev.created_at >= latest_time.get(d, -1.0):
            latest_time[d] = ev.created_at
            latest_status[d] = ev.tag_value("status")
    total = len(deliveries)
    processed = sum(1 for st in latest_status.values() if st == "processed")
    score = processed / total if total else 0.0
    return DeliveryReputation(score=score, total_deliveries=total,
                              acknowledged=len(latest_status), processed=processed)
