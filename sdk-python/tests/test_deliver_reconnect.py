"""A dropped connection while waiting for an ACK is not the end of the delivery.

Seen on 23.09.2026 against the Singapore node: `deliver_with_ack` raised
`RelayUnreachable: relay connection lost` in the middle of waiting for a slow
recipient, although the message was already published and the recipient did
acknowledge it. On a long network path a connection drop is ordinary; the delivery
should reconnect and keep looking for the ACK, or at worst end as `dead_letter` -
never as an exception that hides a message which was actually delivered.
"""
import asyncio

from a4a.agent import Agent
from tests.fake_relay import FakeRelay


async def test_ack_is_found_after_the_connection_drops_mid_wait():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            async def ack_late():
                await asyncio.sleep(3)
                messages = await bob.read_private_messages()
                await bob.acknowledge(messages[0], status="processed")

            async def cut():
                await asyncio.sleep(1.5)
                await relay.drop_connections()

            tasks = [asyncio.create_task(ack_late()), asyncio.create_task(cut())]
            result = await alice.deliver_with_ack(
                bob.pubkey, "slow recipient", retries=3, ack_timeout=2.0,
                poll_interval=0.3, private=True)
            await asyncio.gather(*tasks)
    assert result["status"] == "acknowledged"
