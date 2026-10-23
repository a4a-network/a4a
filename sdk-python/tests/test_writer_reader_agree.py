"""SDK writers and readers share one grammar; revoked mandates are not reused.

Found on 2026-09-04 by probing through MCP, a model-facing wrapper over the SDK:
1. `a4a_publish_offer(price=-5)` emitted tag "-5", while `Offer.from_event` accepted
   only canonical `0|[1-9][0-9]*`; the model could not read its own event.
2. After delegation revocation, `ensure_registered` returned the REVOKED mandate
   because it checked only expiration. Every publication failed "revoked by its owner,"
   while the SDK hint recommended ensure_registered, forming a loop.
3. `RelayError` carried only developer guidance; SDK wrappers also need the relay's
   reason verbatim so they can provide advice in their own terms.
"""
import time

import pytest
from pydantic import ValidationError

from a4a import Agent, Keys, types
from a4a.agent import _safe_from_event
from a4a.delegation import create_revocation
from a4a.relay import RelayError
from tests.fake_relay import FakeRelay

NOW = int(time.time())


def _writers():
    yield "Intent.budget_min", lambda v: types.Intent(
        intent_type="service_request", category="development", need="x",
        budget_min=v, budget_max=1, deadline=NOW)
    yield "Intent.budget_max", lambda v: types.Intent(
        intent_type="service_request", category="development", need="x",
        budget_min=0, budget_max=v, deadline=NOW)
    yield "Intent.deadline", lambda v: types.Intent(
        intent_type="service_request", category="development", need="x",
        budget_min=0, budget_max=1, deadline=v)
    yield "Offer.price", lambda v: types.Offer(intent_id="a" * 64, price=v, eta=NOW)
    yield "Offer.eta", lambda v: types.Offer(intent_id="a" * 64, price=1, eta=v)
    yield "Agreement.price", lambda v: types.Agreement(
        intent_id="a" * 64, offer_id="b" * 64, price=v, deadline=NOW, agent_a="c" * 64,
        agent_b="d" * 64, sig_a="", sig_b="")
    yield "Agreement.deadline", lambda v: types.Agreement(
        intent_id="a" * 64, offer_id="b" * 64, price=1, deadline=v, agent_a="c" * 64,
        agent_b="d" * 64, sig_a="", sig_b="")
    yield "Invoice.amount", lambda v: types.Invoice(
        bolt11="ln", amount=v, agreement_id="a" * 64, payer="c" * 64, payee="d" * 64)
    yield "SearchIntent.budget_max", lambda v: types.SearchIntent(query="q", budget_max=v)
    yield "IdentityAttestation.expiration", lambda v: types.IdentityAttestation(
        subject="c" * 64, level="account:email", expiration=v)
    yield "TaskRequest.deadline", lambda v: types.TaskRequest(
        agreement_id="a" * 64, task_id="t", description="x", deadline=v)


@pytest.mark.parametrize("label, make", list(_writers()), ids=[l for l, _ in _writers()])
def test_writer_rejects_negative_and_reader_reads_what_writer_emits(label, make):
    with pytest.raises(ValidationError):
        make(-1)
    model = make(5)
    ev = model.to_event().sign(Keys())
    assert _safe_from_event(type(model), ev) is not None, \
        "the writer emitted an event its reader cannot parse"


def test_zero_is_a_valid_value_for_writers():
    assert types.Offer(intent_id="a" * 64, price=0, eta=0).to_event().tag_value("eta") == "0"


async def test_ensure_registered_issues_a_new_delegation_after_revocation():
    owner = Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as agent:
            first = await agent.ensure_registered(owner, "bot")
            deleg = next(e for e in await agent.relay.query({"ids": [first]}))
            await agent.relay.publish(create_revocation(owner, deleg))
            second = await agent.ensure_registered(owner, "bot")
            assert second != first, "revoked mandate was reused"
            fresh = next(e for e in await agent.relay.query({"ids": [second]}))
            assert fresh.created_at >= deleg.created_at
            # Control: without another revocation, the mandate survives repeated calls.
            assert await agent.ensure_registered(owner, "bot") == second


async def test_revocation_by_a_stranger_does_not_force_reissue():
    """A stranger's revocation with d=our agent is not our owner's revocation."""
    owner, stranger = Keys(), Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as agent:
            first = await agent.ensure_registered(owner, "bot")
            deleg = next(e for e in await agent.relay.query({"ids": [first]}))
            await agent.relay.publish(create_revocation(stranger, deleg))
            assert await agent.ensure_registered(owner, "bot") == first


async def test_relay_error_carries_the_raw_reason():
    reason = "blocked: invalid or expired A4A delegation: delegation revoked by its owner"
    async with FakeRelay(reject_reason=reason) as relay:
        async with Agent([relay.url]) as agent:
            with pytest.raises(RelayError) as info:
                await agent.request_connection("c" * 64)
    assert info.value.reason == reason
    assert "ensure_registered" in str(info.value), "developer guidance must remain in the message"
