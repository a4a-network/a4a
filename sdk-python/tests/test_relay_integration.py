"""Integration with a live A4A relay; run docker compose up -d first."""
import time
import pytest

from a4a.event import Event
from a4a.delegation import create_delegation
from a4a.keys import Keys
from a4a.relay import RelayClient, RelayError

RELAY_URL = "ws://localhost:8080"

pytestmark = pytest.mark.integration


async def test_publish_and_query_real_relay():
    unique_d = Keys().pubkey_hex[:16]  # unique marker for this run
    async with RelayClient(RELAY_URL) as client:
        # The owner's mandate is required: the production configuration requires
        # delegation for A4A kinds (2026-08-29). Follow the same path as a real agent.
        agent_keys, owner = Keys(), Keys()
        deleg = create_delegation(owner, agent_keys.pubkey_hex, "integration",
                                  int(time.time()) + 86400)
        await client.publish(deleg)
        ev = Event(kind=31002,
                   tags=[["category", "development"], ["intent_type", "service_request"],
                         ["d", unique_d], ["delegation", deleg.id]],
                   content="integration test").sign(agent_keys)
        await client.publish(ev)
        found = await client.query({"kinds": [31002], "#d": [unique_d]})
        assert [e.id for e in found] == [ev.id]


async def test_real_relay_rejects_bad_signature():
    async with RelayClient(RELAY_URL) as client:
        ev = Event(kind=31002, content="original").sign(Keys())
        ev.content = "forgery"  # id and signature no longer match
        with pytest.raises(RelayError):
            await client.publish(ev)
