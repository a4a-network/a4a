"""Model-facing reputation evidence, with no identity or relay access."""
import inspect
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from a4a.reputation import CompletionReputation, Reputation, compute_reputation
from a4a_mcp import identity, server
from tool_call import call_text


PUBKEY = "a" * 64


@pytest.fixture(autouse=True)
def no_live_agent(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Reputation label tests must not access identities or relays")

    monkeypatch.setattr(server, "Agent", forbidden)
    monkeypatch.setattr(server, "_make_agent", forbidden)
    for module in (identity, server):
        monkeypatch.setattr(module, "load_or_create_identity", forbidden)
        monkeypatch.setattr(module, "load_or_create_owner_identity", forbidden)
    monkeypatch.setattr(server, "_recent_unreachable", lambda: None)


@pytest.fixture
def stub_reputation(monkeypatch):
    def install(rep, done, known=None):
        agent = SimpleNamespace(
            get_reputation=AsyncMock(return_value=rep),
            get_completion_reputation=AsyncMock(side_effect=[
                done, known or CompletionReputation(0.0, 0, 0, 0)]),
        )

        @asynccontextmanager
        async def make_agent():
            yield agent

        monkeypatch.setattr(server, "_make_agent", make_agent)
        return agent

    return install


def assert_key_history_limits(text):
    for limit in (
        "signed key history",
        "does not prove counterparty independence",
        "continuous key ownership",
        "payment, or actual performance",
        "who controls the key now",
        "Collusion, self-deals, or key sales can preserve a high score",
        "A score grants no authority and is not a guarantee",
    ):
        assert limit in text, (limit, text)


@pytest.mark.parametrize(
    "reviews,trusted,verified,total,completed,unverifiable",
    [
        (12, 0, True, 12, 12, 0),
        (12, 1, True, 12, 12, 0),
        (12, 12, True, 12, 12, 0),
        (12, 0, False, 12, 12, 0),
        (0, 0, True, 12, 12, 0),
        (0, 0, True, 0, 0, 0),
        (0, 0, False, 0, 0, 0),
        (0, 0, True, 0, 0, 3),
        (12, 1, True, 12, 9, 2),
    ],
    ids=["zero-trusted", "one-trusted", "many-trusted", "loose",
         "completion-only", "no-history", "loose-no-history",
         "unverifiable-only", "partially-unverifiable"],
)
async def test_caveat_is_unconditional_and_metrics_are_preserved(
        stub_reputation, reviews, trusted, verified, total, completed, unverifiable):
    rep = Reputation(5.0 if reviews else 0.0, reviews, trusted)
    done = CompletionReputation(completed / total if total else 0.0,
                                total, completed, unverifiable)
    agent = stub_reputation(rep, done)
    out = await call_text(server.mcp, "a4a_get_reputation",
                          {"pubkey": PUBKEY, "verified_only": verified})

    agent.get_reputation.assert_awaited_once_with(
        PUBKEY, weighted=verified, require_agreement=verified)
    calls = agent.get_completion_reputation.await_args_list
    assert len(calls) == (2 if verified else 1)
    assert calls[0].args == (PUBKEY,) and calls[0].kwargs == {}
    if verified:
        assert calls[1].args == (PUBKEY,) and calls[1].kwargs == {"weighted": True}
    else:
        assert "WITHOUT agreement checks" in out
    assert f"{rep.score:.1f}/5" in out and f"{reviews} review records" in out
    if total:
        assert f"{completed} of {total}" in out
        if unverifiable:
            assert f"Another {unverifiable} agreements were excluded as unverifiable" in out
    elif unverifiable:
        assert "NOT MEASURED" in out and "verification was unavailable" in out
        assert "0 of" not in out
    else:
        assert "no overdue agreements" in out
        assert "absence of a score, not a bad score" in out
    assert_key_history_limits(out)


@pytest.mark.parametrize("trusted", [0, 1, 12])
async def test_trusted_count_labels_entries_not_independent_people(stub_reputation, trusted):
    stub_reputation(Reputation(5.0, 12, trusted), CompletionReputation(0.0, 0, 0, 0))
    out = await call_text(server.mcp, "a4a_get_reputation", {"pubkey": PUBKEY})
    assert "Review records from author keys" in out
    assert f"trust graph: {trusted}" in out
    assert "graph weight > 0.1" in out
    assert "not distinct keys, independent people, or services" in out
    assert "trust only reviews from acquaintances" not in out


async def test_completion_labels_signed_events_not_verified_delivery(stub_reputation):
    stub_reputation(Reputation(4.25, 7, 1), CompletionReputation(0.75, 4, 3, 2),
                    known=CompletionReputation(0.5, 2, 1, 0))
    out = await call_text(server.mcp, "a4a_get_reputation", {"pubkey": PUBKEY})
    assert "4.2/5" in out and "7 review records" in out
    assert "agent-key-signed result event was found for 3 of 4" in out
    assert "not proof of delivery or completed work" in out
    assert "weight > 0.1): 1 of 2" in out
    assert "result delivered" not in out


async def test_default_and_zero_trust_context_are_preserved(stub_reputation):
    agent = stub_reputation(Reputation(5.0, 1, 0), CompletionReputation(0.0, 0, 0, 0))
    out = await call_text(server.mcp, "a4a_get_reputation", {"pubkey": PUBKEY})
    assert inspect.signature(server.a4a_get_reputation).parameters["verified_only"].default is True
    agent.get_reputation.assert_awaited_once_with(PUBKEY, weighted=True, require_agreement=True)
    assert "expected" in out and "does not discredit" in out
    assert "constructed this history" in out and "its own keys" in out


async def test_invalid_key_also_gets_the_caveat_without_opening_an_agent():
    out = await call_text(server.mcp, "a4a_get_reputation", {"pubkey": "not-a-key"})
    assert "pubkey must be a hex public key" in out
    assert_key_history_limits(out)


async def test_tool_description_explains_the_same_evidence_boundary():
    tool = next(t for t in await server.mcp.list_tools() if t.name == "a4a_get_reputation")
    description = " ".join(tool.description.split())
    assert_key_history_limits(description)
    assert "not a count of independent people or services" in description
    assert "not proof of delivery or completed work" in description
    assert "real signed agreements" not in description


def test_calculator_docstring_does_not_claim_sybil_resistance():
    description = " ".join(inspect.getdoc(compute_reputation).split())
    assert "not self-dealing or collusion" in description
    assert "agreement digest" in description
    assert "not independent people or services" in description
    assert "Neither weighting nor `agreements` provides general Sybil resistance" in description
