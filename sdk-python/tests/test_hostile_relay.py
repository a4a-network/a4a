"""Hostile relay: how the SDK handles garbage responses.

We fuzzed relay ingress from the beginning with 222 malformed messages. The reverse
direction had never been tested even though its consequences are worse: the relay is
an explicitly UNTRUSTED party, while its replies are parsed by code inside the owner's
perimeter.

The requirement is simple and practical: regardless of what the relay sends, the
client must not leak an unhandled exception, hang, or accept unverified data.

The first probe was vacuous because frames must target a REAL subscription. The client
ignores unknown identifiers, so a fabricated ID simply timed out and created a false
impression of resilience.
"""
import asyncio
import json

import pytest
import websockets
from a4a import types
from a4a.relay import RelayClient

import network_guard

BIG_TAGS = {"id": "a" * 64, "pubkey": "b" * 64, "sig": "c" * 128, "created_at": 1,
            "kind": 1, "tags": [["t", "x" * 100] for _ in range(2000)], "content": ""}


def _cases(sid: str) -> dict[str, list[str]]:
    def ev(body: str) -> str:
        return f'["EVENT","{sid}",{body}]'

    return {
        "not JSON": ["not json at all"],
        "JSON but not an array": ['{"a":"b"}'],
        "EVENT without event": [f'["EVENT","{sid}"]'],
        "EVENT number instead of event": [ev("42")],
        "EVENT all fields null": [ev('{"id":null,"pubkey":null,"sig":null,'
                                    '"created_at":null,"kind":null,"tags":null,'
                                    '"content":null}')],
        "EVENT two thousand tags": [ev(json.dumps(BIG_TAGS))],
        "EVENT created_at as string": [ev('{"id":"' + "a" * 64 + '","pubkey":"' + "b" * 64
                                         + '","sig":"' + "c" * 128
                                         + '","created_at":"soon","kind":1,"tags":[],'
                                           '"content":""}')],
        "EVENT deeply nested": [ev("[" * 200 + "]" * 200)],
        "EOSE twice": [f'["EOSE","{sid}"]', f'["EOSE","{sid}"]'],
        "OK for unrelated event": ['["OK","' + "f" * 64 + '",true,""]'],
    }


async def _serve(case: str):
    async def handler(ws):
        try:
            sid = json.loads(await ws.recv())[1]
        except Exception:  # noqa: BLE001
            return
        for frame in _cases(sid)[case]:
            try:
                await ws.send(frame)
            except Exception:  # noqa: BLE001
                return
        try:
            # Send EOSE and exit immediately. Keeping the connection after the reply
            # is unnecessary, and `wait_closed()` waits for handlers; with a pause,
            # this suite took 100 seconds.
            await ws.send(f'["EOSE","{sid}"]')
        except Exception:  # noqa: BLE001
            pass

    return await websockets.serve(handler, "127.0.0.1", 0, max_size=None)


@pytest.mark.parametrize("case", list(_cases("x")))
async def test_hostile_frames_are_discarded_without_damage(case):
    server = await _serve(case)
    # Use an ephemeral port and register it with the test boundary. A fixed port
    # (previously 9948) could silently hand the test to an unrelated listener, making
    # "garbage resilience" depend on somebody else's responses.
    port = server.sockets[0].getsockname()[1]
    network_guard.allow("127.0.0.1", port)
    try:
        async with RelayClient(f"ws://127.0.0.1:{port}", timeout=5) as rc:
            got = await asyncio.wait_for(
                rc.query({"kinds": [types.KIND_INTENT], "limit": 5}), timeout=20)
    finally:
        server.close()
        await server.wait_closed()
        network_guard.forget("127.0.0.1", port)
    assert got == [], f"unverified event accepted for case {case!r}: {got}"
