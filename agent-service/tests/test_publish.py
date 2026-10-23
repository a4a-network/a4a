"""Agent presence tests: without a profile and relay list it is unreachable."""
from a4a.agent import Agent

from a4a_agent.publish import publish_presence
from tests.fake_relay import FakeRelay


async def test_publishes_profile_and_relay_list():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as observer:
            ids = await publish_presence(project, (relay.url,))
            assert ids["profile_id"] and ids["relay_list_id"]
            found = await observer.relay.query({"kinds": [31001], "authors": [project.pubkey]})
            assert found, "the agent profile is not visible on the network"


async def test_relay_list_lets_a_stranger_resolve_where_to_write():
    """A relay list lets an unknown agent discover where to deliver messages.

    Test resolution rather than publication itself; otherwise this test would
    prove only that the event was written to storage.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as stranger:
            await publish_presence(project, (relay.url,))
            resolved = await stranger.resolve_relays(project.pubkey)
            assert relay.url in resolved


async def test_relay_list_announces_only_listened_relay():
    """A10: announce only the relay the SDK actually listens to.

    The SDK currently connects to the first relay in the list. Advertising every
    configured relay could send a message to a relay where the recipient is not
    connected, leaving it unread and unacknowledged and producing a dead letter
    that lowers the sender's delivery reputation.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as observer:
            await publish_presence(project, (relay.url, "wss://relay.example/never"))
            resolved = await observer.resolve_relays(project.pubkey)
            assert resolved == [relay.url], f"unexpected relay advertised: {resolved}"
