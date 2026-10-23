"""MCP findings from a context-free external review of the public slice (2026-09-04).

99: a 365-day mandate despite the rule "days, not years"; 101: ValidationError reached
the model as a bare "Error executing tool"; 102: reversed budget bounds,
`deadline_days=0`, review of a nonexistent agreement, and reputation queried with a
non-key; 103: `peer_pubkey` equal to our own key; 104: a forged signature slot displayed
as "awaiting partner signature"; 106: `get_offers` omitted ETA.
"""
import json

import pytest
from a4a import Agent, Keys, crypto, types

from a4a_mcp import identity, server
from fake_relay import FakeRelay
from tool_call import call_text


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")


async def _call(name, args):
    return await call_text(server.mcp, name, args)


async def test_mandate_days_come_from_env_and_default_to_thirty(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        monkeypatch.delenv("A4A_MANDATE_DAYS", raising=False)
        await _call("a4a_publish_profile", {"capabilities": ["x"], "category": "development"})
        deleg = next(e for e in relay.events if e["kind"] == 31000)
        exp = int(next(t[1] for t in deleg["tags"] if t[0] == "expiration"))
        assert 29 * 86400 <= exp - deleg["created_at"] <= 31 * 86400
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        monkeypatch.setenv("A4A_MANDATE_DAYS", "7")
        await _call("a4a_publish_profile", {"capabilities": ["x"], "category": "development"})
        deleg = next(e for e in relay.events if e["kind"] == 31000)
        exp = int(next(t[1] for t in deleg["tags"] if t[0] == "expiration"))
        assert 6 * 86400 <= exp - deleg["created_at"] <= 8 * 86400
    monkeypatch.setenv("A4A_MANDATE_DAYS", "0")
    with pytest.raises(ValueError, match="outlive the timestamping delay"):
        server._mandate_days()


async def test_bogus_category_and_non_key_arguments_get_a_list_not_a_traceback(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await _call("a4a_publish_intent", {"text": "x", "category": "bogus"})
        assert "Unknown category" in out and "development" in out
        out = await _call("a4a_publish_intent", {"text": "x", "category": "development",
                                                  "intent_type": "bogus"})
        assert "Unknown intent_type" in out and "service_request" in out
        out = await _call("a4a_send_task", {"agreement_id": "a" * 64, "description": "",
                                            "executor": "not-a-key"})
        assert "executor must be a hex public key" in out
        out = await _call("a4a_update_task_status", {"task_id": "t", "agreement_id": "a" * 64,
                                                      "status": "bogus"})
        assert "Unknown status" in out
        assert [e["kind"] for e in relay.events if e["kind"] != 31000] == []


async def test_semantic_argument_checks_happen_before_publishing(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await _call("a4a_publish_intent", {"text": "", "category": "development",
                                                  "budget_min": 10, "budget_max": 5})
        assert "greater than budget_max" in out
        out = await _call("a4a_publish_intent", {"text": "", "category": "development",
                                                  "deadline_days": 0})
        assert "at least 1" in out
        out = await _call("a4a_publish_review", {"agreement_id": "a" * 64, "peer_pubkey": "c" * 64,
                                                  "rating": 5})
        assert "not found" in out
        out = await _call("a4a_get_reputation", {"pubkey": "not-a-key"})
        assert "pubkey must be a hex public key" in out
        assert [e["kind"] for e in relay.events if e["kind"] != 31000] == []


async def test_deal_with_own_key_is_refused(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        out = await _call("a4a_make_agreement", {"intent_id": "a" * 64, "offer_id": "b" * 64,
                                                  "price": 1, "deadline_days": 1, "peer_pubkey": me})
        assert "your own key" in out
        assert [e["kind"] for e in relay.events if e["kind"] == 31004] == []


async def test_forged_signature_in_our_slot_is_named_in_the_list_and_on_cosign(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        async with Agent([relay.url]) as proposer:
            terms = types.Agreement(intent_id="i" * 64, offer_id="o" * 64, price=1, deadline=1,
                                    agent_a=proposer.pubkey, agent_b=me, sig_a="", sig_b="")
            digest = terms.digest()
            forged = terms.model_copy(update={
                "sig_a": crypto.sign(digest, proposer.keys.privkey_hex),
                "sig_b": crypto.sign(digest, proposer.keys.privkey_hex)})   # Our slot, peer key.
            forged_id = await proposer.publish_agreement(forged)
        listing = await _call("a4a_get_agreements", {})
        assert "SIGNATURE IN YOUR SLOT IS INVALID" in listing
        assert "waiting for counterparty signature" not in listing
        out = await _call("a4a_cosign_agreement", {"agreement_id": forged_id})
        assert "signature in your slot is invalid" in out


async def test_get_offers_shows_the_eta(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as worker:
            await worker.ensure_registered(Keys(), "worker")
            await worker.publish_offer(types.Offer(intent_id="a" * 64, price=5, eta=1_900_000_000,
                                                   content="offer"))
        out = await _call("a4a_get_offers", {"intent_id": "a" * 64})
    assert "eta=2030-03-17" in out


async def test_model_validation_error_reaches_the_model_as_text(mcp_home, monkeypatch):
    """Expose SDK validation details instead of a generic framework tool error."""
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await _call("a4a_publish_offer", {"intent_id": "a" * 64, "price": 10 ** 23})
    assert out.startswith("Invalid value") and "price" in out
