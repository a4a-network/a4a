"""NIP-65 addressing: publish/resolve relay lists and deliver to recipient relays (P3)."""
import asyncio

import pytest

from a4a import giftwrap, types
from a4a.agent import Agent
from a4a.event import Event
from a4a.keys import Keys
from a4a.relay import RelayError
from tests.fake_relay import FakeRelay


async def test_publish_and_resolve_relay_list_returns_inbox_relays():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as agent, Agent([relay.url]) as observer:
            await agent.publish_relay_list([
                ("ws://read.example", "read"),
                ("ws://write.example", "write"),
                "ws://both.example",              # no marker means read and write
            ])
            urls = await observer.resolve_relays(agent.pubkey)
            # The inbox is where the agent reads: "read" and unmarked; exclude write-only.
            assert set(urls) == {"ws://read.example", "ws://both.example"}


async def test_resolve_relays_empty_when_no_list_published():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as agent:
            assert await agent.resolve_relays(Keys().pubkey_hex) == []


async def test_publish_to_relays_is_best_effort():
    async with FakeRelay() as good, FakeRelay() as _other:
        async with Agent([good.url]) as agent:
            ev = agent._build_private_message(Keys().pubkey_hex, "x", "did-1")
            ev.sign(agent.keys)
            results = await agent.publish_to_relays(
                ev, [good.url, "ws://127.0.0.1:1"])   # second relay is unreachable
            assert results[good.url] is None                 # success
            assert results["ws://127.0.0.1:1"] is not None    # error recorded, no crash
            assert any(e["id"] == ev.id for e in good.events)


async def test_deliver_with_ack_resolves_and_delivers_to_recipient_relay():
    # main is the shared relay Bob listens to; inbox comes from Bob's relay list.
    async with FakeRelay() as main, FakeRelay() as inbox:
        # allow_internal_relays: two local relays are normal in development, but a
        # third party's relay list pointing to loopback is rejected by default.
        alice_ctx = Agent([main.url], allow_internal_relays=True)
        async with alice_ctx as alice, Agent([main.url]) as bob:
            await bob.publish_relay_list([(inbox.url, "read")])

            async def recv_and_ack():
                for _ in range(40):
                    msgs = await bob.read_private_messages()
                    if msgs:
                        await bob.acknowledge(msgs[0], status="received")
                        return
                    await asyncio.sleep(0.05)

            task = asyncio.create_task(recv_and_ack())
            result = await alice.deliver_with_ack(
                bob.pubkey, "delivery over NIP-65", retries=4,
                ack_timeout=1.5, poll_interval=0.05,
                resolve_recipient_relays=True)
            await task

            assert result["status"] == "acknowledged"
            # A copy of the message must also reach the recipient's inbox relay.
            assert any(e["kind"] == types.KIND_PRIVATE_MESSAGE for e in inbox.events)


async def test_deliver_with_ack_reads_receipt_from_disjoint_recipient_relay():
    """The return receipt must not depend on accidental relay overlap.

    Alice discovers Bob's inbox through her own relay, but Bob reads and writes only
    through a different relay. The message and ACK therefore cross genuinely disjoint
    relay sets; neither relay federates events to the other.
    """
    async with FakeRelay() as discovery, FakeRelay() as inbox:
        async with (Agent([discovery.url], allow_internal_relays=True) as alice,
                    Agent([inbox.url], allow_internal_relays=True) as bob):
            relay_list = Event(
                kind=types.KIND_RELAY_LIST,
                tags=[["r", inbox.url, "read"]],
                content="",
            ).sign(bob.keys)
            # Bob advertises the inbox where Alice can discover it, without using the
            # discovery relay for messages or acknowledgements.
            await bob.publish_to_relays(relay_list, [discovery.url])

            async def recv_and_ack():
                for _ in range(40):
                    messages = await bob.read_private_messages()
                    if messages:
                        await bob.acknowledge(messages[0], status="processed")
                        return
                    await asyncio.sleep(0.05)
                raise AssertionError("Bob did not receive the message on his inbox relay")

            task = asyncio.create_task(recv_and_ack())
            result = await alice.deliver_with_ack(
                bob.pubkey,
                "delivery across disjoint relay sets",
                retries=0,
                ack_timeout=1.5,
                poll_interval=0.05,
                resolve_recipient_relays=True,
            )
            await task

            assert result["status"] == "acknowledged"
            assert result["ack_status"] == "processed"
            assert not any(e["kind"] == types.KIND_ACK_RECEIPT
                           for e in discovery.events)
            assert any(e["kind"] == types.KIND_ACK_RECEIPT for e in inbox.events)


async def test_private_delivery_and_wrapped_ack_cross_disjoint_relay_sets():
    """Gift wrapping must preserve privacy without requiring a shared relay."""
    async with FakeRelay() as discovery, FakeRelay() as inbox:
        async with (Agent([discovery.url], allow_internal_relays=True) as alice,
                    Agent([inbox.url], allow_internal_relays=True) as bob):
            relay_list = Event(
                kind=types.KIND_RELAY_LIST,
                tags=[["r", inbox.url, "read"]],
                content="",
            ).sign(bob.keys)
            await bob.publish_to_relays(relay_list, [discovery.url])

            async def recv_and_ack():
                for _ in range(40):
                    messages = await bob.read_private_messages()
                    if messages:
                        assert messages[0]["wrapped"] is True
                        await bob.acknowledge(messages[0], status="processed")
                        return
                    await asyncio.sleep(0.05)
                raise AssertionError("Bob did not receive the wrapped message")

            task = asyncio.create_task(recv_and_ack())
            result = await alice.deliver_with_ack(
                bob.pubkey,
                "private delivery across disjoint relay sets",
                private=True,
                retries=0,
                ack_timeout=1.5,
                poll_interval=0.05,
                resolve_recipient_relays=True,
            )
            await task

            assert result["status"] == "acknowledged"
            assert result["ack_status"] == "processed"
            assert len(inbox.events) == 2
            assert all(event["kind"] == giftwrap.KIND_GIFT_WRAP
                       for event in inbox.events)
            assert all(event["pubkey"] not in (alice.pubkey, bob.pubkey)
                       for event in inbox.events)
            assert all(not any(tag[0] == "d" for tag in event["tags"])
                       for event in inbox.events)


@pytest.mark.parametrize("private", [False, True])
async def test_deliver_with_ack_retries_initial_recipient_ack_connection(private):
    """A transient ACK-reader handshake failure must not create a false dead letter."""
    async with FakeRelay() as discovery, FakeRelay() as inbox:
        async with (Agent([discovery.url], allow_internal_relays=True) as alice,
                    Agent([inbox.url], allow_internal_relays=True) as bob):
            relay_list = Event(
                kind=types.KIND_RELAY_LIST,
                tags=[["r", inbox.url, "read"]],
                content="",
            ).sign(bob.keys)
            await bob.publish_to_relays(relay_list, [discovery.url])

            # Only the first new connection fails. Bob is already connected, the
            # later best-effort message publication succeeds, and Alice must retry
            # opening her ACK reader instead of abandoning the return path.
            inbox.reject_next_handshakes(1)

            async def recv_and_ack():
                for _ in range(40):
                    messages = await bob.read_private_messages()
                    if messages:
                        await bob.acknowledge(messages[0], status="processed")
                        return
                    await asyncio.sleep(0.05)
                raise AssertionError("Bob did not receive the message on his inbox relay")

            task = asyncio.create_task(recv_and_ack())
            result = await alice.deliver_with_ack(
                bob.pubkey,
                "delivery after a transient ACK-reader failure",
                private=private,
                retries=0,
                ack_timeout=1.5,
                poll_interval=0.05,
                resolve_recipient_relays=True,
            )
            await task

            assert result["status"] == "acknowledged"
            assert result["ack_status"] == "processed"


async def test_deliver_with_ack_survives_recipient_relay_disconnect():
    """An ACK arriving after relay reconnection must complete the delivery."""
    async with FakeRelay() as discovery, FakeRelay() as inbox:
        async with (Agent([discovery.url], allow_internal_relays=True) as alice,
                    Agent([inbox.url], allow_internal_relays=True) as bob):
            relay_list = Event(
                kind=types.KIND_RELAY_LIST,
                tags=[["r", inbox.url, "read"]],
                content="",
            ).sign(bob.keys)
            await bob.publish_to_relays(relay_list, [discovery.url])

            async def recv_disconnect_and_ack():
                for _ in range(40):
                    messages = await bob.read_private_messages()
                    if messages:
                        await inbox.drop_connections()
                        # RelayClient's first reconnect occurs after one second. Retry
                        # the ACK publication too, so the assertion is about Alice's
                        # return-path recovery rather than scheduling order.
                        for _ in range(30):
                            try:
                                await bob.acknowledge(messages[0], status="processed")
                            except RelayError:
                                await asyncio.sleep(0.1)
                            else:
                                return
                        raise AssertionError("Bob could not publish after relay recovery")
                    await asyncio.sleep(0.05)
                raise AssertionError("Bob did not receive the message on his inbox relay")

            task = asyncio.create_task(recv_disconnect_and_ack())
            result = await alice.deliver_with_ack(
                bob.pubkey,
                "delivery through a recovering recipient relay",
                retries=0,
                ack_timeout=4.0,
                poll_interval=0.1,
                resolve_recipient_relays=True,
            )
            await task

            assert result["status"] == "acknowledged"
            assert result["ack_status"] == "processed"
