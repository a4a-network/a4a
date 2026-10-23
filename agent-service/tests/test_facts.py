"""Tests for collecting verifiable sender facts.

Build the trust graph from REAL signed kind-31020 events. Mocking the graph would
test the mock instead of the logic these facts are meant to exercise.
"""
from a4a import types
from a4a.event import Event
from a4a.keys import Keys

from a4a_agent import facts
from a4a_agent.policy import Policy


def _trust_edge(author: Keys, trusted: str, weight: float) -> Event:
    ta = types.TrustAssertion(trusted=trusted, weight=weight)
    return ta.to_event().sign(author)


class StubRelay:
    def __init__(self, events=()):
        self._events = list(events)
        self.queries = 0

    async def query(self, filters):
        self.queries += 1
        kinds = filters.get("kinds", [])
        return [e for e in self._events if not kinds or e.kind in kinds]


class StubAgent:
    """Replace Agent so fact-collection tests never access the network."""

    def __init__(self, identities=None, reputation=(0, 0.0), connected=False,
                 trust_events=()):
        self._identities = identities or []
        self._reputation = reputation
        self._connected = connected
        self.keys = Keys()
        self.pubkey = self.keys.pubkey_hex
        self.relay = StubRelay(trust_events)
        self.calls = []

    async def get_identity(self, pubkey, trusted_issuers=None, include_self_issued=False):
        self.calls.append("get_identity")
        if trusted_issuers is None:
            return self._identities
        return [a for a in self._identities if a["issuer"] in trusted_issuers]

    async def get_reputation(self, pubkey, weighted=False, require_agreement=False,
                             trust_graph=None):
        self.calls.append("get_reputation")
        assert require_agreement, "ratings must be bound to signed agreements"
        assert weighted, "ratings must be weighted by trust"

        class R:
            total_reviews = self._reputation[0]
            score = self._reputation[1]

        return R()

    async def is_connected(self, pubkey):
        self.calls.append("is_connected")
        return self._connected


async def test_collects_attestations_from_trusted_issuers_only():
    agent = StubAgent(identities=[{"issuer": "good", "level": "platform"},
                                  {"issuer": "unknown", "level": "gov_id"}])
    f = await facts.collect(agent, "ff" * 32, Policy(trusted_issuers=("good",)))
    assert f.attested_by == ("good",)


async def test_collects_deals_and_rating():
    agent = StubAgent(reputation=(12, 4.8))
    f = await facts.collect(agent, "ff" * 32, Policy(min_reviews=1))
    assert f.reviews == 12 and f.rating == 4.8


async def test_reports_connection_state():
    agent = StubAgent(connected=True)
    f = await facts.collect(agent, "ff" * 32, Policy())
    assert f.connected is True


async def test_survives_relay_errors():
    """Relay unavailability degrades facts instead of crashing triage."""

    class Broken(StubAgent):
        async def get_reputation(self, pubkey, weighted=False, require_agreement=False,
                                 trust_graph=None):
            raise RuntimeError("relay unavailable")

    f = await facts.collect(Broken(), "ff" * 32, Policy(min_reviews=1))
    assert f.reviews == 0 and f.rating == 0.0


# --- Graph trust weight (plan deviation; see facts.collect) ----------------------

async def test_trust_is_baseline_for_stranger():
    agent = StubAgent()
    f = await facts.collect(agent, "ff" * 32, Policy(min_trust=0.5))
    assert f.trust == 0.1


async def test_trust_reflects_direct_edge():
    agent = StubAgent()
    target = "ab" * 32
    agent.relay = StubRelay([_trust_edge(agent.keys, target, 0.9)])
    f = await facts.collect(agent, target, Policy(min_trust=0.5))
    assert f.trust == 0.9


async def test_explicit_distrust_is_visible_to_policy():
    """A zero-weight edge is explicit distrust and must not become baseline."""
    agent = StubAgent(connected=True)
    target = "ab" * 32
    agent.relay = StubRelay([_trust_edge(agent.keys, target, 0.0)])
    f = await facts.collect(agent, target, Policy())
    assert f.trust == 0.0


# --- Cost: a sender certain to be rejected must remain cheap ---------------------

async def test_hopeless_sender_costs_only_the_connection_check():
    """Cold-start policy rejects unconnected senders without expensive reads."""
    agent = StubAgent()
    f = await facts.collect(agent, "ff" * 32, Policy())
    assert agent.calls == ["is_connected"]
    assert agent.relay.queries == 0, "trust graph fetched for a certain rejection"
    assert f.connected is False and f.attested_by == ()


async def test_trust_graph_cache_is_shared_between_senders():
    agent = StubAgent(connected=True)
    cache = facts.TrustGraphCache()
    for _ in range(5):
        await facts.collect(agent, "ab" * 32, Policy(), cache)
    assert agent.relay.queries == 1, "trust graph was fetched once per sender"


async def test_trust_graph_not_refetched_by_reputation_call():
    """A11: reputation calculation must reuse the cached trust graph.

    Otherwise ``get_reputation(weighted=True)`` rebuilds it for EVERY sender in
    addition to the cached query, violating the policy's cost bound.
    """
    graph_queries = []

    class Relay(StubRelay):
        async def query(self, filters):
            if types.KIND_TRUST_ASSERTION in filters.get("kinds", []):
                graph_queries.append(1)
            return await super().query(filters)

    class Agent2(StubAgent):
        async def get_reputation(self, pubkey, weighted=False, require_agreement=False,
                                 trust_graph=None):
            assert trust_graph is not None, "graph omitted and will be downloaded again"
            return type("R", (), {"total_reviews": 3, "score": 4.5})()

    agent = Agent2(connected=True)
    agent.relay = Relay()
    cache = facts.TrustGraphCache()
    for _ in range(3):
        await facts.collect(agent, "ab" * 32, Policy(min_reviews=1), cache)
    assert len(graph_queries) == 1, f"graph downloaded {len(graph_queries)} times"


async def test_trust_graph_cache_is_not_fetched_twice_concurrently():
    """A16: concurrent streaming tasks must share one graph fetch."""
    import asyncio

    class SlowRelay(StubRelay):
        def __init__(self):
            super().__init__()
            self.calls = 0

        async def query(self, filters):
            self.calls += 1
            await asyncio.sleep(0.05)
            return []

    agent = StubAgent()
    agent.relay = SlowRelay()
    cache = facts.TrustGraphCache()
    await asyncio.gather(cache.graph(agent), cache.graph(agent), cache.graph(agent))
    assert agent.relay.calls == 1, f"graph downloaded {agent.relay.calls} times"
