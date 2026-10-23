"""Agent profile discovery: profiles could be published but not read.

The landing page promises to find the right agent and make an agreement, meaning
AGENT discovery rather than intent search alone. The SDK could publish a profile
(31001) but provided no way to read one; finding someone required already knowing
their key. This was the same publish-without-read class as task streaming (audit,
2026-08-29).
"""
import time

from a4a import types
from a4a.agent import Agent
from tests.fake_relay import FakeRelay


async def _publish(agent, caps, category, langs=("ru",)):
    await agent.publish_profile(types.AgentProfile(
        capabilities=list(caps), category=category, languages=list(langs),
        content=f"agent {category}"))


async def test_get_profile_returns_what_was_published():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as seeker:
            await _publish(a, ["landing pages", "code review"], "development")
            got = await seeker.get_profile(a.pubkey)
    assert got is not None, "published profile cannot be read"
    assert got.category == "development"
    assert "landing pages" in got.capabilities


async def test_get_profile_of_unknown_key_is_none_not_an_error():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as seeker:
            assert await seeker.get_profile("ab" * 32) is None


async def test_find_agents_filters_by_category():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as dev, Agent([relay.url]) as des, \
                Agent([relay.url]) as seeker:
            await _publish(dev, ["code"], "development")
            await _publish(des, ["mockups"], "design")
            found = await seeker.find_agents(category="design")
    keys = {p.source.pubkey for p in found}
    assert des.pubkey in keys and dev.pubkey not in keys


class _SloppyRelayView:
    """Relay that IGNORES tag filters and returns everything.

    This is required to test client-side post-filtering. An honest test relay would
    remove unrelated events itself, allowing the test to pass with no client filter
    at all. That exact mistake made the first version stay green when filtering was
    removed.
    """

    def __init__(self, inner):
        self.inner = inner

    async def query(self, filters):
        stripped = {k: v for k, v in filters.items() if not k.startswith("#")}
        return await self.inner.query(stripped)

    def __getattr__(self, name):
        return getattr(self.inner, name)


async def test_find_agents_filters_by_capability_client_side():
    """Repeat capability filtering client-side because relay output is untrusted."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b, \
                Agent([relay.url]) as seeker:
            await _publish(a, ["seo", "copywriting"], "marketing")
            await _publish(b, ["design"], "marketing")
            seeker.relay = _SloppyRelayView(seeker.relay)
            found = await seeker.find_agents(capability="seo")
    assert [p.source.pubkey for p in found] == [a.pubkey], \
        "sloppy relay injected an agent without the requested capability"


async def test_profile_carries_search_facets_for_foreign_relays():
    """NIP-01 indexes only single-letter tags, so copy search facets into `t`.

    This mirrors intents and makes profiles discoverable on third-party relays.
    """
    ev = types.AgentProfile(capabilities=["seo"], category="marketing",
                            languages=["ru"]).to_event()
    facets = {t[1] for t in ev.tags if t[0] == "t"}
    assert "a4a:cat:marketing" in facets
    assert "a4a:cap:seo" in facets
    assert "a4a:lang:ru" in facets


async def test_get_profile_tie_break_is_deterministic():
    """For equal timestamps, expose the profile version with the smaller ID.

    This is the NIP-01 replaceable-event rule. Without it, relay ordering controls
    selection: owners see different capabilities across relays and agents receive
    requests for skills they no longer offer.

    Deliberately publish the LARGER-ID version first. Python sorting is stable, so
    without an explicit rule it would win; a test publishing events in convenient
    order would prove nothing.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as author, Agent([relay.url]) as reader:
            stamp = int(time.time())
            built = []
            for cap in ("skill-A", "skill-B"):
                ev = types.AgentProfile(capabilities=[cap], category="design").to_event()
                ev.created_at = stamp
                ev.sign(author.keys)
                built.append((ev.id, cap, ev))
            built.sort(reverse=True)              # larger ID first
            for _, _, ev in built:
                await author.relay.publish(ev)

            smallest_cap = min(built)[1]
            got = await reader.get_profile(author.pubkey)
            assert got is not None and got.capabilities == [smallest_cap], got
