"""Require every tool response to identify the next step for an unaided model.

An end-to-end run between two independent identities through MCP on a production node
completed on 2026-09-04, but another model would have stalled at four response-text
gaps: `a4a_make_agreement` did not explain how the peer discovers the agreement or that
its ID changes after countersigning; `a4a_send_task` did not say where the worker finds
the task; the reputation warning made an honest first deal look fabricated; and
`a4a_encrypt_file` did not explain where to place the blob without storage.
"""
import pytest
from a4a import Agent

from a4a_mcp import identity, server
from fake_relay import FakeRelay
from tool_call import call_text


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")


async def _call(name: str, args: dict) -> str:
    return await call_text(server.mcp, name, args)


async def test_make_agreement_names_how_peer_signs_and_that_id_changes(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await _call("a4a_make_agreement", {"intent_id": "a" * 64, "offer_id": "b" * 64,
                                                  "price": 1, "deadline_days": 1,
                                                  "peer_pubkey": "c" * 64})
    assert "a4a_get_agreements" in out and "a4a_cosign_agreement" in out
    assert "NEW ID" in out and "SIGNED BY BOTH" in out


async def test_send_task_names_where_executor_sees_it(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await _call("a4a_send_task", {"agreement_id": "a" * 64, "description": "",
                                            "executor": "c" * 64})
    assert "a4a_get_tasks" in out and "a4a_get_task_results" in out


async def test_reputation_warning_explains_when_zero_known_is_normal(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        # An honest agreement and review between two parties unknown to the observer.
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            from a4a import Agreement, agreement_digest
            digest = agreement_digest("i" * 64, "o" * 64, 1, "USD", 1, a.pubkey, b.pubkey)
            terms = Agreement(intent_id="i" * 64, offer_id="o" * 64, price=1, deadline=1,
                              agent_a=a.pubkey, agent_b=b.pubkey, sig_a="", sig_b="")
            ag = terms.model_copy(update={"sig_a": a.sign_agreement(terms),
                                          "sig_b": b.sign_agreement(terms)})
            ag_id = await a.publish_agreement(ag)
            await a.publish_review(ag_id, b.pubkey, 5, "ok")
            out = await _call("a4a_get_reputation", {"pubkey": b.pubkey})
    assert "1 review records" in out and "expected" in out and "does not discredit" in out
    assert "constructed this history" in out, "the caution remains"


async def test_encrypt_file_says_where_to_put_the_blob(mcp_home, tmp_path):
    src = tmp_path / "f.bin"
    src.write_bytes(b"x" * 10)
    out = await _call("a4a_encrypt_file", {"path": str(src)})
    assert "provides no storage" in out and "https" in out and "ipfs" in out and "a4a_send_file" in out
