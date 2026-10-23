"""Exercise the complete protocol cycle through MCP, from intent to review.

MCP is the primary surface: a connected assistant interacts with the network only
through it. Until 2026-08-29 it exposed 11 tools for roughly 36 SDK methods, with gaps
directly on the advertised path: an agreement could be proposed but a peer's proposal
could not be discovered; reputation could be read but not created; execution was
missing entirely. Per-tool tests did not reveal this because each tool worked in
isolation. The defect becomes visible only across a full cycle.

The counterparty here is a regular SDK agent, as it would be in production: the other
side runs an independent implementation rather than another instance of our server.
"""
import json

import pytest
from a4a import Agent, Keys, types

from a4a_mcp import identity, inbox_runtime, server
from fake_relay import FakeRelay


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    monkeypatch.setattr(identity, "OWNER_FILE", tmp_path / ".a4a" / "owner.json",
                        raising=False)


async def test_deal_cycle_from_intent_to_review(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex

        await server.a4a_publish_intent(need="landing_page", category="design",
                                        budget_min=1000, budget_max=50000)
        async with Agent([relay.url]) as worker:
            await worker.register(Keys(), "local test worker")
            intents = await worker.search_intents(category="design")
            assert len(intents) == 1
            intent_id = intents[0].source.id
            offer_id = await worker.publish_offer(types.Offer(
                intent_id=intent_id, price=45000, eta=0))

            out = await server.a4a_make_agreement(
                intent_id=intent_id, offer_id=offer_id, price=45000,
                deadline_days=7, peer_pubkey=worker.pubkey)
            assert "31004" in out or "agreement" in out.lower()

            # The counterparty discovers the agreement from the network. This was the
            # missing capability the test was written to cover.
            deals = await worker.get_agreements(counterparty=me)
            assert len(deals) == 1, "the worker did not discover the agreement"
            assert not deals[0].verify_signatures(), "the proposal cannot have two signatures"

            # The peer then signs it. Without the countersignature the proposal binds
            # neither party, and before 2026-08-29 there was no way to obtain it.
            agreement_id = await worker.co_sign_agreement(deals[0])
            done = [a for a in await worker.get_agreements(counterparty=me)
                    if a.verify_signatures()]
            assert len(done) == 1, "the network has no concluded agreement"

            await server.a4a_send_task(agreement_id=agreement_id,
                                       description="",
                                       executor=worker.pubkey, deadline_days=3)
            tasks = await worker.get_tasks(agreement_id=agreement_id)
            assert [t.description for t in tasks] == [""]

            # The actual image policy stays in place: client details travel privately.
            inbox_runtime.configure("deal-cycle-private", [worker.pubkey], start_after=0)
            details = "Owned synthetic client brief: build five landing-page blocks"
            out = await server.a4a_send_private(worker.pubkey, text=details)
            messages = await worker.read_private_messages()
            assert any(m["content"] == details for m in messages), out
            assert details not in json.dumps(relay.events)

            await worker.submit_task_result(tasks[0].task_id, agreement_id,
                                            "https://ok.example/result")
            results = await server.a4a_get_task_results(agreement_id)
            assert "https://ok.example/result" in results
            assert "UNTRUSTED DATA" in results, "a remote result was presented as local"

            out = await server.a4a_publish_review(
                agreement_id=agreement_id, peer_pubkey=worker.pubkey, rating=5)
            assert "5/5" in out
            rep = await server.a4a_get_reputation(worker.pubkey)
            assert "5" in rep


async def test_cosign_makes_a_proposed_agreement_binding(mcp_home, monkeypatch):
    """Cover the reverse path: a peer proposes and we countersign through MCP.

    This verifies the tool's defining contract: before the countersignature the
    proposal is not binding; after it, the agreement is concluded.
    """
    from a4a.types import Agreement, agreement_digest

    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        async with Agent([relay.url]) as proposer:
            await proposer.register(Keys(), "local test proposer")
            digest = agreement_digest("a" * 64, "b" * 64, 1000, "USD", 0,
                                      proposer.pubkey, me)
            terms = Agreement(
                intent_id="a" * 64, offer_id="b" * 64, price=1000, currency="USD",
                deadline=0, agent_a=proposer.pubkey, agent_b=me, sig_a="", sig_b="")
            proposed = terms.model_copy(update={"sig_a": proposer.sign_agreement(terms)})
            proposed_id = await proposer.publish_agreement(proposed)

            listed = await server.a4a_get_agreements()
            assert "WAITING FOR YOUR SIGNATURE" in listed, listed

            out = await server.a4a_cosign_agreement(proposed_id)
            assert "concluded" in out.lower(), out

            done = [a for a in await proposer.get_agreements(counterparty=me)
                    if a.verify_signatures()]
            assert len(done) == 1, "the network has no concluded agreement"
            assert done[0].price == 1000


async def test_cosign_signs_exactly_the_requested_agreement(mcp_home, monkeypatch):
    """Sign the requested agreement rather than the first available proposal.

    The tool searches every agreement involving us. Without the final ID filter it
    would silently sign the first result, potentially with another price, subject, or
    counterparty, while still reporting that the agreement was concluded.
    """
    from a4a.types import Agreement, agreement_digest

    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        async with Agent([relay.url]) as proposer:
            await proposer.register(Keys(), "local test proposer")
            ids = {}
            for price in (100, 777):
                offer_id = f"{price:064x}"
                digest = agreement_digest("a" * 64, offer_id, price, "USD", 0,
                                          proposer.pubkey, me)
                terms = Agreement(
                    intent_id="a" * 64, offer_id=offer_id, price=price,
                    currency="USD", deadline=0, agent_a=proposer.pubkey, agent_b=me,
                    sig_a="", sig_b="")
                ids[price] = await proposer.publish_agreement(
                    terms.model_copy(update={"sig_a": proposer.sign_agreement(terms)}))

            out = await server.a4a_cosign_agreement(ids[777])
            assert "concluded" in out.lower(), out

            done = [a for a in await proposer.get_agreements(counterparty=me)
                    if a.verify_signatures()]
            assert [a.price for a in done] == [777], "the wrong agreement was signed"


async def test_cosign_refuses_agreement_that_is_not_ours(mcp_home, monkeypatch):
    """Refuse to sign an agreement that does not name our key as a party."""
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await server.a4a_cosign_agreement("f" * 64)
    assert "not found" in out.lower()


async def test_review_rejects_rating_out_of_range(mcp_home, monkeypatch):
    """Return a clear machine-readable rejection instead of leaking an SDK error."""
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await server.a4a_publish_review(agreement_id="a" * 64,
                                              peer_pubkey="b" * 64, rating=9)
    assert "between 1 and 5" in out


async def test_task_status_rejects_unknown_value(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await server.a4a_update_task_status(
            task_id="t", agreement_id="a", status="\u0432\u044B\u0434\u0443\u043C\u043A\u0430")
    assert "in_progress" in out and "\u0432\u044B\u0434\u0443\u043C\u043A\u0430" in out


async def test_connection_handshake_needs_both_sides(mcp_home, monkeypatch):
    """Verify the mutual connection handshake advertised as contact before chat.

    A one-sided request is insufficient; the connection exists only after the peer
    sends a matching request.
    """
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        async with Agent([relay.url]) as peer:
            inbox_runtime.configure("connection-cycle", [peer.pubkey], start_after=0)
            await server.a4a_request_connection(peer.pubkey)
            assert not await peer.is_connected(me), "a one-sided request created a connection"

            incoming = await peer.get_connection_requests()
            assert [r["from_pubkey"] for r in incoming] == [me]

            await peer.request_connection(me, "\u0438 \u044F \u043D\u0435 \u043F\u0440\u043E\u0442\u0438\u0432")
            assert await peer.is_connected(me)

            listed = await server.a4a_get_connection_requests()
            assert peer.pubkey in listed
            assert "UNTRUSTED DATA" in listed, "a stranger's profile lacks framing"


async def test_connection_request_from_a_stranger_is_not_shown(mcp_home, monkeypatch):
    """Hide connection requests from senders outside the owner's allowed peers.

    The introduction is text a stranger chose, and the listing hands it to the model.
    The filter existed, but the only test used an allowed sender, so removing the
    filter left the suite green. Both the key and the text must stay out.
    """
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        async with Agent([relay.url]) as friend, Agent([relay.url]) as stranger:
            inbox_runtime.configure("connection-filter", [friend.pubkey], start_after=0)
            await friend.request_connection(me, "allowed introduction")
            await stranger.request_connection(me, "STRANGER-INTRO-MUST-NOT-REACH-THE-MODEL")

            listed = await server.a4a_get_connection_requests()

    assert friend.pubkey in listed, "the allowed request disappeared: the check proves nothing"
    assert stranger.pubkey not in listed
    assert "STRANGER-INTRO-MUST-NOT-REACH-THE-MODEL" not in listed


async def test_make_agreement_refuses_a_deal_with_yourself(mcp_home, monkeypatch):
    """Reject self-dealing with a clear response suitable for a machine caller.

    Self-dealing is meaningless and would also poison reputation because a review
    would formally come from a party to a signed agreement.
    """
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        out = await server.a4a_make_agreement(
            intent_id="i" * 64, offer_id="o" * 64, price=10, deadline_days=1,
            peer_pubkey=me)
    assert "counterparty" in out.lower() and "peer_pubkey" in out


async def test_cosign_twice_says_already_signed(mcp_home, monkeypatch):
    """A repeated call must not create a duplicate and must report that explicitly.

    A single-signature proposal remains on the relay, so without this guard it could
    be signed repeatedly. The parties would then have distinct agreements with the
    same terms, allowing tasks to attach to one and reviews to another.
    """
    from a4a.types import Agreement, agreement_digest

    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        me = identity.load_or_create_identity().pubkey_hex
        async with Agent([relay.url]) as proposer:
            await proposer.register(Keys(), "local test proposer")
            digest = agreement_digest("a" * 64, "b" * 64, 500, "USD", 0,
                                      proposer.pubkey, me)
            terms = Agreement(
                intent_id="a" * 64, offer_id="b" * 64, price=500, currency="USD",
                deadline=0, agent_a=proposer.pubkey, agent_b=me, sig_a="", sig_b="")
            proposed_id = await proposer.publish_agreement(
                terms.model_copy(update={"sig_a": proposer.sign_agreement(terms)}))

            first = await server.a4a_cosign_agreement(proposed_id)
            assert "concluded" in first.lower()
            second = await server.a4a_cosign_agreement(proposed_id)
            assert "already concluded" in second.lower(), second

            signed = [a for a in await proposer.get_agreements(counterparty=me)
                      if a.verify_signatures()]
            assert len(signed) == 1, "the network contains duplicate concluded agreements"


async def test_reputation_warns_when_no_one_known_vouched(mcp_home, monkeypatch):
    """Expose self-dealing risk instead of returning only an attractive score.

    Requiring a signed agreement prevents reviews of parties with whom the author did
    no business. An agent can still create extra keys and sign real agreements with
    itself, manufacturing a 5.0 score. The actionable signal available here is that
    none of the reviewers are known to the caller.
    """
    import time as _time

    from a4a import crypto
    from a4a.keys import Keys
    from a4a.types import Agreement, agreement_digest

    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as target:
            deadline = int(_time.time()) + 3600
            for i in range(3):
                sybil = Keys()
                intent, offer = f"i{i}".ljust(64, "0"), f"o{i}".ljust(64, "0")
                digest = agreement_digest(intent, offer, 1000, "USD", deadline,
                                          sybil.pubkey_hex, target.pubkey)
                terms = Agreement(intent_id=intent, offer_id=offer, price=1000,
                                  currency="USD", deadline=deadline,
                                  agent_a=sybil.pubkey_hex, agent_b=target.pubkey,
                                  sig_a="", sig_b="")
                deal = terms.model_copy(update={"sig_a": crypto.sign(digest, sybil.privkey_hex),
                                                "sig_b": target.sign_agreement(terms)})
                async with Agent([relay.url], keys=sybil) as s:
                    deal_id = await s.publish_agreement(deal)
                    await s.publish_review(deal_id, target.pubkey, 5, "\u0432\u0435\u043B\u0438\u043A\u043E\u043B\u0435\u043F\u043D\u043E")

            out = await server.a4a_get_reputation(target.pubkey)

    assert "5.0/5" in out, out
    assert "trust graph: 0" in out, "the absence of trusted reviewer paths is not stated"
    assert "its own keys" in out, "the self-dealing risk is not stated"
