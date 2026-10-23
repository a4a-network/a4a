"""Verifiable sender facts: statements that others SIGNED about the key.

This module never calls an LLM or judges message text. It uses only
cryptographically verifiable data, so triage costs zero tokens.

**Cost is part of the defense.** The first implementation collected every fact
for every sender: attestations, reputation, connection, and trust weight. That
required five or six relay queries, TWO of which downloaded the full trust graph.
A spammer paid for one cheap event while we performed half a dozen reads, creating
our own load amplifier (found during adversarial review on 2026-08-28). Therefore:

1. facts are collected LAZILY and only when the policy can use them;
2. a sender the policy cannot admit costs only the mutual-connection checks and
   never triggers a trust-graph download;
3. the global trust graph is fetched once per window (``TrustGraphCache``), not
   once per sender.
"""
import asyncio
import logging
import time
from dataclasses import dataclass

from a4a import types
from a4a.types import assurance_of
from a4a.reputation import WOT_BASELINE, build_trust_graph, trust_weight

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SenderFacts:
    pubkey: str
    attested_by: tuple[str, ...]  # Trusted issuers that attested this sender.
    trust: float                  # WoT graph weight (baseline when no path exists).
    # Number of ACCEPTED REVIEWS after one-author-one-vote deduplication, not the
    # number of agreements. Reporting "12 agreements" would overstate the evidence
    # when several reviews concern the same agreement (review 2026-08-28, A20).
    reviews: int
    rating: float                 # Rating with require_agreement enabled.
    connected: bool               # A mutual connection already exists.
    complete: bool = True         # False when the relay did not return all facts.
    # Assurance for each attestation (low/substantial/high), ordered like
    # attested_by. Trusting an issuer differs from trusting every attestation it
    # produces; one issuer may provide both low- and high-assurance evidence
    # (internal audit 2026-08-29).
    attested_loa: tuple[str, ...] = ()


class TrustGraphCache:
    """Cache the global trust graph for a bounded time window.

    The graph is global and sender-independent, so fetching it per sender creates
    the same amplification. A short TTL keeps freshness ahead of extra savings.
    """

    def __init__(self, ttl_seconds: float = 300.0):
        # The cache must expire. Streaming mode has no polling cycles, so without a
        # TTL it would live until restart and ignore newly declared owner distrust
        # (review finding 2026-08-28).
        self.ttl = ttl_seconds
        self._graph: dict | None = None
        self._fetched_at = 0.0
        # Two streaming tasks share the cache. Without a lock, both may observe an
        # empty value and fetch the graph concurrently (review 2026-08-28, A16).
        self._lock = asyncio.Lock()

    async def graph(self, agent) -> dict:
        async with self._lock:
            return await self._graph_locked(agent)

    async def _graph_locked(self, agent) -> dict:
        now = time.monotonic()
        if self._graph is None or now - self._fetched_at >= self.ttl:
            try:
                assertions = await agent.relay.query(
                    {"kinds": [types.KIND_TRUST_ASSERTION]})
                self._graph = build_trust_graph(assertions)
                self._fetched_at = now
            except Exception as e:
                # Do NOT cache an empty graph, or one relay failure would classify
                # everyone as a stranger until the process restarts.
                log.warning("trust graph unavailable (%s); treating all as strangers", e)
                return self._graph or {}
        return self._graph


async def collect(agent, pubkey: str, policy, cache: TrustGraphCache | None = None
                  ) -> SenderFacts:
    """Collect only the facts about ``pubkey`` needed by THIS policy.

    This is not "every fact about the key": facts the policy cannot use are not
    requested. Relay failures degrade the evidence but do not crash triage.
    """
    try:
        connected = await agent.is_connected(pubkey)
    except Exception as e:
        log.warning("connection check for %s failed (%s); deferring decision",
                    pubkey[:12], e)
        # A relay failure means "unknown", not "not connected". Treating it as a
        # rejection could permanently lose a partner request after a brief outage
        # (review finding 2026-08-28).
        return SenderFacts(pubkey=pubkey, attested_by=(), trust=WOT_BASELINE,
                           reviews=0, rating=0.0, connected=False, complete=False)

    # Cheap rejection: if the policy cannot admit unconnected senders, the verdict
    # is already known and attestations, reputation, and graph fetches add no value.
    if not connected and not policy.can_allow_unconnected():
        return SenderFacts(pubkey=pubkey, attested_by=(), trust=WOT_BASELINE,
                           reviews=0, rating=0.0, connected=False)

    attested: tuple[str, ...] = ()
    attested_loa: tuple[str, ...] = ()
    if policy.trusted_issuers:
        try:
            found = await agent.get_identity(
                pubkey, trusted_issuers=list(policy.trusted_issuers))
            attested = tuple(a["issuer"] for a in found)
            attested_loa = tuple(assurance_of(a.get("level", "")) for a in found)
        except Exception as e:
            log.warning("attestations for %s unavailable: %s", pubkey[:12], e)
            attested, attested_loa = (), ()

    cache = cache if cache is not None else TrustGraphCache()
    graph = await cache.graph(agent)

    reviews, rating = 0, 0.0
    if policy.min_reviews > 0:
        try:
            # Pass the graph explicitly or get_reputation will rebuild it for EVERY
            # sender and bypass the cache (review 2026-08-28, A11).
            rep = await agent.get_reputation(pubkey, weighted=True,
                                             require_agreement=True,
                                             trust_graph=graph)
            reviews, rating = rep.total_reviews, rep.score
        except Exception as e:
            log.warning("reputation for %s unavailable: %s", pubkey[:12], e)
    # Calculate weight from the graph instead of substituting a constant. After
    # audit fix F2, a zero-weight edge means explicit owner distrust and remains
    # distinguishable from "no path".
    trust = trust_weight(graph, agent.pubkey, pubkey)

    return SenderFacts(pubkey=pubkey, attested_by=attested, attested_loa=attested_loa,
                       trust=trust, reviews=reviews, rating=rating, connected=connected)
