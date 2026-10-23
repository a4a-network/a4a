"""A peer's relay list controls OUR outbound connections and must therefore be bounded.

Under NIP-65, a recipient advertises where it reads incoming messages and the sender
connects to that list. A stranger therefore controls the number and addresses of
outbound connections. Internal addresses were already rejected (review S7,
2026-08-28), but the COUNT was unbounded and traversal was sequential: a 10-second
timeout across 100 advertised relays could stall the owner's agent for 17 minutes.

Worse than one sender's stall, a recipient can amplify traffic by naming somebody
else's host as its relay and making every sender connect to it.
"""
import asyncio
import time

import network_guard

from a4a import types
from a4a.agent import Agent, MAX_RECIPIENT_RELAYS
from a4a.event import Event
from a4a.keys import Keys

from tests.fake_relay import FakeRelay


async def _announce(agent: Agent, keys: Keys, urls: list[str]) -> None:
    ev = Event(kind=types.KIND_RELAY_LIST,
               tags=[["r", u] for u in urls], content="")
    ev.sign(keys)
    await agent.relay.publish(ev)


async def test_recipient_relay_list_is_capped():
    """A list of 100 addresses must not produce 100 outbound connections."""
    async with FakeRelay() as relay:
        victim = Keys()
        async with Agent([relay.url], keys=victim, allow_internal_relays=True) as owner, \
                Agent([relay.url], allow_internal_relays=True) as sender:
            await _announce(owner, victim, [f"ws://127.0.0.1:{9000 + i}" for i in range(100)])
            urls = await sender.resolve_relays(victim.pubkey_hex)
    assert len(urls) == MAX_RECIPIENT_RELAYS, len(urls)


async def test_unreachable_relays_are_walked_concurrently():
    """Traversal must cost ONE timeout rather than the sum of all timeouts.

    A sequential loop made each address a separate wait, allowing the list owner to
    choose the sender's stall duration. Compare traversal of one address with three;
    concurrent traversal makes their duration nearly equal.
    """
    async def silent(reader, writer):
        try:
            await asyncio.sleep(60)
        finally:
            writer.close()

    servers = []
    try:
        # Start silent relays on EPHEMERAL ports and declare them to the boundary.
        # Fixed ports 9971-9973 could be occupied, causing `start_server` to fail; before
        # this fix the client also reached them outside the test boundary.
        ports = []
        for _ in range(3):
            server = await asyncio.start_server(silent, "127.0.0.1", 0)
            servers.append(server)
            port = server.sockets[0].getsockname()[1]
            network_guard.allow("127.0.0.1", port)
            ports.append(port)
        urls = [f"ws://127.0.0.1:{p}" for p in ports]

        async with FakeRelay() as relay:
            async with Agent([relay.url], allow_internal_relays=True) as sender:
                ev = Event(kind=1, tags=[], content="x")
                ev.sign(sender.keys)

                t0 = time.monotonic()
                await sender.publish_to_relays(ev, urls[:1], timeout=1)
                one = time.monotonic() - t0

                t0 = time.monotonic()
                results = await sender.publish_to_relays(ev, urls, timeout=1)
                three = time.monotonic() - t0
    finally:
        for s in servers:
            s.close()
        for port in ports:
            network_guard.forget("127.0.0.1", port)

    assert len(results) == 3 and all(results.values()), results
    assert three < one * 2, (
        f"three addresses took {three:.1f}s versus {one:.1f}s for one, indicating "
        "sequential traversal")
