"""History-fetch failures must NAME their cause without exposing peer-controlled text.

On 2026-09-15 an agent saw "inbox history unavailable or malformed," concluded that
its relay was an obsolete broken build, and nearly upgraded a shared node. The relay
was healthy and byte-for-byte identical to production; the cause was elsewhere. One
generic message made malformed JSON, a rejected status, and a schema mismatch
indistinguishable.

The safety boundary remains correct: a PEER controls the body and error text, so they
must not be logged. The exception TYPE is ours, however, and reveals no peer data.
"""
import pytest

from a4a.inbox_receiver import InboxError, InboxHistory


class _Broken(InboxHistory):
    def __init__(self, payload):
        super().__init__("wss://example.invalid", "a" * 64)
        self._payload = payload

    async def _fetch(self, url):
        return self._payload


async def test_malformed_json_names_the_exception_type():
    with pytest.raises(InboxError) as refusal:
        await _Broken("not JSON at all").page((0, ""))
    text = str(refusal.value)
    assert "JSONDecodeError" in text or "ValueError" in text, (
        f"cause is unnamed: {text!r}; an operator cannot distinguish this failure")


async def test_peer_text_is_still_not_leaked():
    """NEGATIVE control: peer response content must not enter the error message.

    Without this control, "name the cause" is indistinguishable from "repeat peer
    text," and the diagnostic improvement could weaken the safety boundary.
    """
    secret = "SECRET_TEXT_FROM_A_PEER_NODE"
    with pytest.raises(InboxError) as refusal:
        await _Broken(f'{{"rows": "{secret}"}}').page((0, ""))
    assert secret not in str(refusal.value), "peer-controlled text leaked into the error"
