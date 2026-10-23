"""What users see when something goes wrong.

An unclear error makes a correctly functioning product feel broken. These tests cover
three cases where an internal detail escaped instead of actionable guidance.
"""
import pytest

from a4a.agent import Agent
from a4a.keys import Keys
from a4a.relay import RelayError
from a4a import types
from tests.fake_relay import FakeRelay


async def test_unreachable_relay_names_the_address_not_a_winsock_code():
    """Name the unreachable relay instead of exposing a Windows socket error code."""
    with pytest.raises(RelayError) as e:
        async with Agent(["ws://127.0.0.1:1"]):
            pass
    msg = str(e.value)
    assert "ws://127.0.0.1:1" in msg, "the error omits the unreachable relay address"
    assert "WinError" not in msg


async def test_bad_recipient_says_what_is_wrong_not_how_ecdh_failed():
    """Explain an invalid recipient instead of exposing an internal ECDH failure."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a:
            with pytest.raises(ValueError) as e:
                await a.send_private_message("not-a-key", "hello")
    msg = str(e.value)
    assert "ECDH" not in msg and "fromhex" not in msg
    assert "not-a-key" in msg or "pubkey" in msg.lower()


async def test_missing_mandate_tells_what_to_call():
    """Turn the common "delegation required" refusal into actionable guidance."""
    async with FakeRelay(reject_reason="blocked: A4A delegation required for this kind") as relay:
        async with Agent([relay.url]) as a:
            with pytest.raises(RelayError) as e:
                await a.publish_intent(types.Intent(
                    intent_type="service_request", category="design", need="x",
                    budget_min=0, budget_max=1, deadline=0))
    assert "ensure_registered" in str(e.value), \
        "the mandate refusal does not identify the required call"
