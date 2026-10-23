"""The fake relay refusal must be HTTP 503 under every supported library version.

This check follows two consecutive defects in the same place, both with green suites.

FIRST: the fixture returned a tuple used by an obsolete implementation. On a current
version, the client received a CORRUPTED handshake instead of a refusal. An external
reviewer found this by measuring bytes sent to the socket (TEST-HS-001).

SECOND: replacing the tuple with the current call broke the opposite environment,
producing HTTP 500 in the venv used by the suite. The manual check had used the system
interpreter, where the dependency version differed.

Both times the FULL SUITE REMAINED GREEN: a neighboring check proves recovery after a
refusal and accepts any form of failure, including a broken handshake or HTTP 500.
This test therefore pins the refusal code SEPARATELY and explicitly.
"""
import pytest
import websockets

from tests.fake_relay import FakeRelay


async def test_refusal_is_http_503_whatever_the_library_version():
    async with FakeRelay() as relay:
        relay.reject_next_handshakes(1)
        with pytest.raises(Exception) as refusal:
            async with websockets.connect(relay.url):
                pass
        text = f"{type(refusal.value).__name__}: {refusal.value}"

    # Exactly 503. HTTP 500 and no response are DIFFERENT failures, and a client may
    # handle each differently. A test that accepts any failure does not cover this one.
    assert "503" in text, f"refusal is not HTTP 503: {text}"


async def test_normal_connection_still_works_after_the_refusal():
    """POSITIVE control: the refusal happens ONCE.

    Without this, "relay always refuses" is indistinguishable from "relay refused once,"
    and the preceding test remains green with a permanently broken fixture.
    """
    async with FakeRelay() as relay:
        relay.reject_next_handshakes(1)
        with pytest.raises(Exception):
            async with websockets.connect(relay.url):
                pass
        async with websockets.connect(relay.url) as ws:
            assert ws.open if hasattr(ws, "open") else True
