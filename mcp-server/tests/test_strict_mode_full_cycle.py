"""Run a complete deal when publishing the work subject is forbidden (finding 117).

A restriction that breaks real work will be removed on day one, and rightly so. It is
not enough to verify that a tool refuses publication: with the restriction enabled,
the deal must still progress from intent to review while the work subject travels over
the private channel.

This verifies two properties together:
1. the cycle completes through intent, search, offer, two-signature agreement, task,
   result, review, and reputation;
2. no public network event contains the work subject, while the counterparty still
   receives it through NIP-44.

The second property is more important: without it, strict mode would merely disable
half the protocol.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk-python"))

from a4a import Agent, Keys, types                             # noqa: E402
from a4a_mcp import identity, inbox_runtime, policy, server    # noqa: E402
from tests.fake_relay import FakeRelay                         # noqa: E402

#: Customer information that the public network must never learn in any form.
SECRET = "\u043B\u0435\u043D\u0434\u0438\u043D\u0433 \u0434\u043B\u044F \u0441\u0442\u043E\u043C\u0430\u0442\u043E\u043B\u043E\u0433\u0438\u0438 \u0432 \u0417\u0435\u043B\u0435\u043D\u043E\u0433\u0440\u0430\u0434\u0435, \u0441\u0434\u0430\u0442\u044C \u043A \u043F\u044F\u0442\u043D\u0438\u0446\u0435"


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    monkeypatch.setattr(identity, "OWNER_FILE", tmp_path / ".a4a" / "owner.json",
                        raising=False)


@pytest.fixture
def strict(monkeypatch):
    """Configure the locked strict policy shipped to an integrator."""
    monkeypatch.setattr(policy, "BUILD_POLICY", {"public_text": "deny", "locked": True})


async def test_whole_deal_goes_through_without_publishing_the_subject(
        mcp_home, strict, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex

        # 1. First attempt what a model naturally does: describe the task in prose.
        # Strict mode must reject it.
        #
        # Without this attempt the test protects nothing: it stays green with the
        # safeguard disabled because it never tries to publish text. Mutation-tested.
        refused = await server.a4a_publish_intent(
            category="design", need="landing_page", text=SECRET,
            budget_min=1000, budget_max=50000)
        assert "is not published" in refused, refused

        # Only then publish an intent without a description: label, budget, deadline.
        out = await server.a4a_publish_intent(
            category="design", need="landing_page", budget_min=1000, budget_max=50000)
        assert "published" in out.lower(), out

        async with Agent([relay.url]) as worker:
            await worker.register(Keys(), "local test worker")
            inbox_runtime.configure("strict-cycle", [worker.pubkey], start_after=0)
            # 2. The worker discovers it by category; the label remains searchable.
            listing = await server.a4a_search_intents(category="design")
            assert "landing_page" in listing, listing

            intents = await worker.search_intents(category="design")
            intent_id = intents[0].source.id
            offer_id = await worker.publish_offer(types.Offer(
                intent_id=intent_id, price=45000, eta=0, content="\u0441\u0434\u0435\u043B\u0430\u044E"))

            # 3. Conclude a two-signature agreement. Numeric terms may be public.
            await server.a4a_make_agreement(
                intent_id=intent_id, offer_id=offer_id, price=45000,
                deadline_days=7, peer_pubkey=worker.pubkey)
            deals = await worker.get_agreements(counterparty=me)
            agreement_id = await worker.co_sign_agreement(deals[0])

            # 4. Create the task. Again first try placing the brief in a public field;
            # descriptions are most detailed after agreement, when the risk is highest.
            refused = await server.a4a_send_task(
                agreement_id=agreement_id, executor=worker.pubkey,
                description=SECRET, deadline_days=3)
            assert "is not published" in refused, refused

            await server.a4a_send_task(agreement_id=agreement_id,
                                       executor=worker.pubkey, deadline_days=3)
            await server.a4a_send_private(to_pubkey=worker.pubkey, text=SECRET)

            tasks = await worker.get_tasks(agreement_id=agreement_id)
            assert len(tasks) == 1, "the task did not reach the worker"
            inbox = await worker.read_private_messages()
            assert any(SECRET in m["content"] for m in inbox), \
                "the worker did not receive the brief needed to perform the task"

            # 5. Submit the result and review.
            await worker.submit_task_result(tasks[0].task_id, agreement_id,
                                            "https://ok.example/result")
            results = await server.a4a_get_task_results(agreement_id)
            assert "https://ok.example/result" in results
            refused = await server.a4a_publish_review(
                agreement_id=agreement_id, peer_pubkey=worker.pubkey, rating=5,
                text=f"\u043E\u0442\u043B\u0438\u0447\u043D\u043E, {SECRET}")
            assert "is not published" in refused, refused

            out = await server.a4a_publish_review(
                agreement_id=agreement_id, peer_pubkey=worker.pubkey, rating=5)
            assert "5/5" in out
            rep = await server.a4a_get_reputation(worker.pubkey)
            assert "5" in rep

        # 6. Most importantly, no public event contains the work subject.
        for ev in relay.events:
            if ev["kind"] == 1059:            # Expected encrypted gift-wrap envelope.
                continue
            blob = json.dumps(ev, ensure_ascii=False)
            assert "\u0441\u0442\u043E\u043C\u0430\u0442\u043E\u043B\u043E\u0433" not in blob and "\u0417\u0435\u043B\u0435\u043D\u043E\u0433\u0440\u0430\u0434" not in blob, \
                f"work subject leaked into event kind {ev['kind']}: {blob[:200]}"


async def test_the_same_cycle_leaks_the_subject_without_the_strict_mode(
        mcp_home, monkeypatch):
    """Without strict mode, the model publishes the subject and it remains public.

    Without this inverse check the first test proves nothing: it would also pass against
    a relay that simply stores no events.
    """
    monkeypatch.setattr(policy, "BUILD_POLICY", {})
    monkeypatch.delenv("A4A_PUBLIC_TEXT", raising=False)
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        await server.a4a_publish_intent(category="design", text=SECRET)
        public = [e for e in relay.events if e["kind"] == types.KIND_INTENT]
    assert any(SECRET in e["content"] for e in public), \
        "permissive mode must publish text unchanged or it is not permissive"
