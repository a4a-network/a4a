"""Verify model-facing relay and validation errors through framework `call_tool`.

A probe on 2026-09-04 showed relay rejection reaching the model as a framework
exception with SDK advice to call `agent.ensure_registered(owner_keys, name)`, a method
the model cannot access as a tool. It also showed `a4a_publish_offer(price=-5)` being
published even though the SDK reader then ignored the invalid event.
"""
import json

import pytest

from a4a_mcp import identity, inbox_runtime, server
from fake_relay import FakeRelay
from tool_call import call_text

REVOKED = "blocked: invalid or expired A4A delegation: delegation revoked by its owner"


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")


async def _call(name: str, args: dict) -> str:
    return await call_text(server.mcp, name, args)


PUBLISHING = {
    "a4a_publish_profile": {"capabilities": ["x"], "category": "development"},
    "a4a_publish_intent": {"text": "", "category": "development"},
    "a4a_publish_offer": {"intent_id": "a" * 64, "price": 1},
    "a4a_send_task": {"agreement_id": "a" * 64, "description": "", "executor": "c" * 64},
    "a4a_update_task_status": {"task_id": "t", "agreement_id": "a" * 64, "status": "accepted"},
    "a4a_submit_task_result": {"task_id": "t", "agreement_id": "a" * 64,
                               "result_url": "https://example.org/results/123"},
    "a4a_publish_review": {"agreement_id": "a" * 64, "peer_pubkey": "c" * 64, "rating": 5},
    "a4a_request_connection": {"peer_pubkey": "c" * 64},
    "a4a_accept_connection": {"peer_pubkey": "c" * 64},
    "a4a_send_private": {"to_pubkey": "c" * 64, "text": "x"},
    "a4a_deliver": {"to_pubkey": "c" * 64, "text": "x", "new_letter": True},
}


@pytest.mark.parametrize("tool, args", list(PUBLISHING.items()), ids=list(PUBLISHING))
async def test_relay_refusal_reaches_the_model_verbatim_with_tool_level_advice(
        mcp_home, monkeypatch, tool, args):
    async with FakeRelay(reject_reason=REVOKED) as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        if tool in ("a4a_request_connection", "a4a_accept_connection",
                    "a4a_send_private", "a4a_deliver"):
            identity.load_or_create_identity()
            inbox_runtime.configure("relay-errors", ["c" * 64], start_after=0)
        out = await _call(tool, args)
    assert REVOKED in out, "the relay reason must reach the caller verbatim"
    assert "ensure_registered" not in out, "developer-only advice reached the model"
    assert "owner revoked" in out and "Do not repeat" in out and "Notify the owner" in out


async def test_relay_refusal_other_reasons_get_matching_advice(mcp_home, monkeypatch):
    cases = {
        "blocked: delegation required for kind 31002": "cannot find the agent's delegation",
        "invalid: created_at is out of acceptable range": "clock",
        "blocked: something else": "Fix the cause",
    }
    for reason, expected in cases.items():
        async with FakeRelay(reject_reason=reason) as relay:
            monkeypatch.setenv("A4A_RELAY", relay.url)
            identity.load_or_create_identity()
            inbox_runtime.configure("relay-errors", ["c" * 64], start_after=0, replace=True)
            out = await _call("a4a_request_connection", {"peer_pubkey": "c" * 64})
        assert reason in out and expected in out, (reason, out)


async def test_negative_numbers_are_refused_before_publishing(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await _call("a4a_publish_offer", {"intent_id": "a" * 64, "price": -5})
        assert "price=-5" in out and "Negative values" in out
        out = await _call("a4a_publish_intent", {"text": "x", "category": "development",
                                                  "budget_min": -1})
        assert "budget_min=-1" in out
        out = await _call("a4a_make_agreement", {"intent_id": "a" * 64, "offer_id": "b" * 64,
                                                  "price": -1, "deadline_days": 1,
                                                  "peer_pubkey": "c" * 64})
        assert "price=-1" in out
        out = await _call("a4a_update_task_status", {"task_id": "t", "agreement_id": "a" * 64,
                                                      "status": "accepted", "progress": 101})
        assert "between 0 and 100" in out
        published = [e["kind"] for e in relay.events if e["kind"] not in (31000,)]
    assert published == [], "an event containing an invalid number reached the wire"


async def test_non_canonical_number_strings_are_coerced_or_refused_by_the_schema(
        mcp_home, monkeypatch):
    """Document schema handling of noncanonical numeric strings.

    The tool schema rejects "45 000" before our code, while the framework coerces "+5"
    to 5 and publishes the canonical value. This is expected behavior, not a gap.
    """
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        # Versions 1.x and 2.x use different exception classes and locate ToolError in
        # different modules. The model sees the text, so that is what this verifies.
        with pytest.raises(Exception) as info:
            await _call("a4a_publish_offer", {"intent_id": "a" * 64, "price": "45 000"})
        assert "price" in str(info.value)
        await _call("a4a_publish_offer", {"intent_id": "a" * 64, "price": "+5"})
        offers = [e for e in relay.events if e["kind"] == 31003]
    assert [t for t in offers[0]["tags"] if t[0] == "price"][0][1] == "5"
