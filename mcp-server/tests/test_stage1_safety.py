"""Registered-tool regressions for the approved stage-1 MCP safety fixes."""
import pytest

from a4a import Agent, Keys, crypto, types
from a4a.event import Event
from a4a.sanitize import wrap_untrusted
from a4a_mcp import identity, inbox_runtime, policy, server
from fake_relay import FakeRelay
from tool_call import call_text


@pytest.fixture
def actors(monkeypatch, tmp_path):
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    keys = {name: Keys() for name in ("peer", "third", "owner")}
    keys["me"] = identity.load_or_create_identity()
    monkeypatch.setattr(server, "load_or_create_identity", lambda: keys["me"])
    monkeypatch.setattr(server, "load_or_create_owner_identity", lambda: keys["owner"])
    monkeypatch.setattr(policy, "BUILD_POLICY", {})
    monkeypatch.setenv("A4A_PUBLIC_TEXT", "allow")
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    monkeypatch.setenv("A4A_MANDATE_DAYS", "30")
    server._forget_unreachable()
    return keys


@pytest.fixture
def locked(actors, monkeypatch):
    monkeypatch.setattr(policy, "BUILD_POLICY", {"public_text": "deny", "locked": True})
    # A permissive runtime setting must not undo the build policy.
    monkeypatch.setenv("A4A_PUBLIC_TEXT", "allow")


async def seed_terms(relay, actors, intent_author, offer_author, currency="USD",
                     peer_delegation=None):
    intent_id, offer_id = "a" * 64, "b" * 64
    if intent_author:
        async with Agent([relay.url], keys=actors[intent_author]) as author:
            if intent_author == "peer":
                author.delegation_id = peer_delegation
            intent_id = await author.publish_intent(types.Intent(
                intent_type="service_request", category="development", need="landing_page",
                budget_min=1, budget_max=10, deadline=0, currency=currency))
    if offer_author:
        async with Agent([relay.url], keys=actors[offer_author]) as author:
            if offer_author == "peer":
                author.delegation_id = peer_delegation
            offer_id = await author.publish_offer(types.Offer(
                intent_id=intent_id, price=5, eta=0, currency=currency))
    return dict(intent_id=intent_id, offer_id=offer_id, price=5, deadline_days=1)


def record_signatures(monkeypatch):
    signed = []
    real_sign = crypto.sign

    def sign(digest, private_key):
        signed.append(digest)
        return real_sign(digest, private_key)

    monkeypatch.setattr(crypto, "sign", sign)
    return signed


@pytest.mark.parametrize("intent_author,offer_author", [
    ("me", "peer"), ("peer", "me"), (None, "peer"), ("peer", None),
])
async def test_make_agreement_rejects_different_requested_peer(
        actors, monkeypatch, intent_author, offer_author):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        args = await seed_terms(relay, actors, intent_author, offer_author)
        before = list(relay.events)
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, "a4a_make_agreement", {
            **args, "peer_pubkey": actors["third"].pubkey_hex})
        assert relay.events == before, "refusal must not publish even a mandate"
        assert signed == [], "refusal must precede every signature"
        assert "peer_pubkey" in out and "does not match" in out, out


@pytest.mark.parametrize("intent_author,offer_author,requested_peer", [
    ("me", "me", "peer"),
    ("peer", "peer", "peer"),
    ("peer", "third", "peer"),
    (None, None, "me"),
])
async def test_make_agreement_rejects_self_and_third_party_terms(
        actors, monkeypatch, intent_author, offer_author, requested_peer):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        args = await seed_terms(relay, actors, intent_author, offer_author)
        before = list(relay.events)
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, "a4a_make_agreement", {
            **args, "peer_pubkey": actors[requested_peer].pubkey_hex})
        assert relay.events == before, "invalid parties must not publish even a mandate"
        assert signed == []
        assert "\u043E\u043F\u0443\u0431\u043B\u0438\u043A\u043E\u0432\u0430\u043D" not in out, out
        assert "counterparty" in out or "parties" in out, out


@pytest.mark.parametrize("intent_author,offer_author,our_role", [
    ("me", "peer", "a"), ("peer", "me", "b"),
    ("me", None, "a"), (None, "me", "b"),
    (None, "peer", "a"), ("peer", None, "b"), (None, None, "a"),
])
async def test_make_agreement_signs_only_the_requested_parties(
        actors, monkeypatch, intent_author, offer_author, our_role):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        args = await seed_terms(relay, actors, intent_author, offer_author)
        peer = actors["peer"].pubkey_hex
        out = await call_text(server.mcp, "a4a_make_agreement", {**args, "peer_pubkey": peer})
        agreements = [e for e in relay.events if e["kind"] == types.KIND_AGREEMENT]
        assert len(agreements) == 1, out
        agreement = types.Agreement.from_event(Event(**agreements[0]))
        assert {agreement.agent_a, agreement.agent_b} == {actors["me"].pubkey_hex, peer}
        assert getattr(agreement, "agent_" + our_role) == actors["me"].pubkey_hex
        assert crypto.verify(agreement.digest(), getattr(agreement, "sig_" + our_role),
                             actors["me"].pubkey_hex)
        assert getattr(agreement, "sig_" + ("b" if our_role == "a" else "a")) == ""
        assert peer in out and "Agreement published" in out


@pytest.mark.parametrize("tool,args,field", [
    ("a4a_accept_connection", {"intro": "Details of a client project"}, "intro"),
    ("a4a_request_connection", {"intro": "Details of a client project"}, "intro"),
    ("a4a_publish_profile", {"capabilities": ["web_development"], "category": "development",
                             "description": "Details of a client project"}, "description"),
    ("a4a_publish_profile", {"capabilities": ["web_development", "Details of a client project"],
                             "category": "development"}, "capabilities"),
    ("a4a_publish_profile", {"capabilities": ["web_development\n"],
                             "category": "development"}, "capabilities"),
])
async def test_locked_policy_rejects_connection_and_profile_text(
        locked, actors, monkeypatch, tool, args, field):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        if "connection" in tool:
            args = {**args, "peer_pubkey": actors["peer"].pubkey_hex}
            inbox_runtime.configure("stage1-connection-text", [actors["peer"].pubkey_hex],
                                    start_after=0)
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, tool, args)
        assert relay.events == [], out
        assert signed == []
        assert field in out and "build" in out, out


@pytest.mark.parametrize("mode", ["allow", "deny"])
async def test_profile_and_connection_allowed_controls(actors, monkeypatch, mode):
    monkeypatch.setattr(policy, "BUILD_POLICY", {"public_text": mode, "locked": True})
    text = "Details of a client project" if mode == "allow" else ""
    capabilities = [text] if text else ["web_development", "seo"]
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        inbox_runtime.configure("stage1-controls", [actors["peer"].pubkey_hex], start_after=0)
        out = await call_text(server.mcp, "a4a_publish_profile", {
            "capabilities": capabilities, "category": "development", "description": text})
        profiles = [e for e in relay.events if e["kind"] == types.KIND_AGENT_PROFILE]
        assert len(profiles) == 1, out
        profile = types.AgentProfile.from_event(Event(**profiles[0]))
        assert profile.capabilities == capabilities and profile.content == text
        for tool in ("a4a_request_connection", "a4a_accept_connection"):
            before = len(relay.events)
            out = await call_text(server.mcp, tool, {
                "peer_pubkey": actors["peer"].pubkey_hex, "intro": text})
            connections = [e for e in relay.events[before:]
                           if e["kind"] == types.KIND_CONNECTION_REQUEST]
            assert len(connections) == 1, out
            assert connections[0]["content"] == text


async def test_get_agreements_wraps_every_displayed_peer_field(actors, monkeypatch):
    currency = "USD\nsettlement unit: sample credits"
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url], keys=actors["peer"]) as peer:
            terms = types.Agreement(
                intent_id="a" * 64, offer_id="b" * 64, price=5, currency=currency,
                deadline=123, agent_a=peer.pubkey, agent_b=actors["me"].pubkey_hex,
                sig_a="", sig_b="")
            proposed = terms.model_copy(update={"sig_a": peer.sign_agreement(terms)})
            agreement_id = await peer.publish_agreement(proposed)
        before = list(relay.events)
        out = await call_text(server.mcp, "a4a_get_agreements", {})
        assert relay.events == before
    row = (f"- id={agreement_id} counterparty={peer.pubkey} price=5 {currency} "
           "deadline=123 status=agreed [WAITING FOR YOUR SIGNATURE]")
    assert wrap_untrusted(row, source="agreements from the A4A network") in out
    assert currency in out


@pytest.mark.parametrize("mode", ["deny", "allow"])
@pytest.mark.parametrize("tool,args,field,value", [
    ("a4a_publish_intent", {"category": "development"}, "language", "Client project details"),
    ("a4a_publish_intent", {"category": "development"}, "need", "landing_page\n"),
    ("a4a_publish_offer", {"price": 5}, "intent_id", "Client project details"),
    ("a4a_make_agreement", {"offer_id": "b" * 64, "price": 5, "deadline_days": 1},
     "intent_id", "Client project details"),
    ("a4a_make_agreement", {"intent_id": "a" * 64, "price": 5, "deadline_days": 1},
     "offer_id", "Client project details"),
    ("a4a_send_task", {}, "agreement_id", "Client project details"),
    ("a4a_update_task_status", {"agreement_id": "a" * 64, "status": "accepted"},
     "task_id", "Client project details"),
    ("a4a_update_task_status", {"task_id": "t", "status": "accepted"},
     "agreement_id", "Client project details"),
    ("a4a_submit_task_result", {"agreement_id": "a" * 64, "result_url": "https://example.org/r"},
     "task_id", "Client project details"),
    ("a4a_submit_task_result", {"task_id": "t", "result_url": "https://example.org/r"},
     "agreement_id", "Client project details"),
    ("a4a_submit_task_result", {"task_id": "t", "agreement_id": "a" * 64},
     "result_url", "Client project details"),
    ("a4a_submit_task_result", {"task_id": "t", "agreement_id": "a" * 64},
     "result_url", "https://example.org/r\nClient project details"),
])
async def test_public_metadata_cannot_carry_free_text(
        actors, monkeypatch, mode, tool, args, field, value):
    monkeypatch.setattr(policy, "BUILD_POLICY", {"public_text": mode, "locked": True})
    args = {**args, field: value}
    if tool == "a4a_make_agreement":
        args["peer_pubkey"] = actors["peer"].pubkey_hex
    if tool == "a4a_send_task":
        args["executor"] = actors["peer"].pubkey_hex
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, tool, args)
        if mode == "deny":
            assert relay.events == [], out
            assert signed == []
            assert field in out and "build" in out, out
        else:
            published = [e for e in relay.events if e["kind"] != types.KIND_DELEGATION]
            assert len(published) == 1, out
            assert any(value in tag[1:] for tag in published[0]["tags"])


@pytest.mark.parametrize("tool", ["a4a_request_connection", "a4a_accept_connection"])
async def test_connection_peer_is_validated_before_any_publication(actors, monkeypatch, tool):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, tool, {"peer_pubkey": "Client project details"})
        assert relay.events == []
        assert signed == []
        assert "peer_pubkey must be a hex public key" in out, out


async def test_locked_make_agreement_does_not_republish_currency_text(
        locked, actors, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        args = await seed_terms(relay, actors, "me", "peer", currency="USD\nSample credits")
        before = list(relay.events)
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, "a4a_make_agreement", {
            **args, "peer_pubkey": actors["peer"].pubkey_hex})
        assert relay.events == before, out
        assert signed == []
        assert "currency" in out and "build" in out, out


@pytest.mark.parametrize("mode", ["deny", "allow"])
@pytest.mark.parametrize("field", ["content", "currency", "intent_id", "offer_id"])
async def test_cosign_applies_public_text_policy_to_republished_terms(
        actors, monkeypatch, mode, field):
    monkeypatch.setattr(policy, "BUILD_POLICY", {"public_text": mode, "locked": True})
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url], keys=actors["peer"]) as peer:
            await peer.register(Keys(), "local test peer")
            values = dict(intent_id="a" * 64, offer_id="b" * 64, price=5, currency="USD",
                          deadline=123, agent_a=peer.pubkey, agent_b=actors["me"].pubkey_hex,
                          sig_a="", sig_b="")
            values[field] = "Client project details"
            terms = types.Agreement(**values)
            proposed = terms.model_copy(update={"sig_a": peer.sign_agreement(terms)})
            agreement_id = await peer.publish_agreement(proposed)
        before = list(relay.events)
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, "a4a_cosign_agreement", {"agreement_id": agreement_id})
        if mode == "deny":
            assert relay.events == before, out
            assert signed == []
            assert field in out and "build" in out, out
        else:
            agreements = [e for e in relay.events[len(before):]
                          if e["kind"] == types.KIND_AGREEMENT]
            assert len(agreements) == 1, out
            signed_terms = types.Agreement.from_event(Event(**agreements[0]))
            assert signed_terms.verify_signatures()
            assert getattr(signed_terms, field) == values[field]


async def test_locked_structured_workflow_and_private_text_still_work(
        locked, actors, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        inbox_runtime.configure("stage1-private", [actors["peer"].pubkey_hex], start_after=0)
        await call_text(server.mcp, "a4a_publish_intent", {
            "category": "development", "need": "landing_page", "language": "en-US"})
        intent_id = next(e["id"] for e in relay.events if e["kind"] == types.KIND_INTENT)
        async with Agent([relay.url], keys=actors["peer"]) as peer:
            await peer.register(Keys(), "local test peer")
            offer_id = await peer.publish_offer(types.Offer(intent_id=intent_id, price=5, eta=0))
            await call_text(server.mcp, "a4a_make_agreement", {
                "intent_id": intent_id, "offer_id": offer_id, "price": 5,
                "deadline_days": 1, "peer_pubkey": peer.pubkey})
            proposal = (await peer.get_agreements())[0]
            agreement_id = await peer.co_sign_agreement(proposal)
            await call_text(server.mcp, "a4a_send_task", {
                "agreement_id": agreement_id, "executor": peer.pubkey})
            task = (await peer.get_tasks(agreement_id))[0]
            await call_text(server.mcp, "a4a_update_task_status", {
                "agreement_id": agreement_id, "task_id": task.task_id, "status": "accepted"})
            out = await call_text(server.mcp, "a4a_submit_task_result", {
                "agreement_id": agreement_id, "task_id": task.task_id,
                "result_url": "https://example.org/results/123"})
            results = await peer.get_task_results(agreement_id)
            assert len(results) == 1, out
            assert results[0].result_url == "https://example.org/results/123"
            text = "Client project details"
            await call_text(server.mcp, "a4a_send_private", {"to_pubkey": peer.pubkey, "text": text})
            messages = await peer.read_private_messages()
            assert any(m["content"] == text for m in messages)
            assert all(text not in e["content"] for e in relay.events)


@pytest.mark.parametrize("our_role", ["a", "b"])
async def test_locked_cosign_allows_sdk_default_content(locked, actors, monkeypatch, our_role):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url], keys=actors["peer"]) as peer:
            await peer.register(Keys(), "local test peer")
            parties = (actors["me"].pubkey_hex, peer.pubkey)
            if our_role == "b":
                parties = parties[::-1]
            terms = types.Agreement(
                intent_id="a" * 64, offer_id="b" * 64, price=5, deadline=123,
                agent_a=parties[0], agent_b=parties[1], sig_a="", sig_b="")
            peer_slot = "sig_b" if our_role == "a" else "sig_a"
            proposed = terms.model_copy(update={peer_slot: peer.sign_agreement(terms)})
            agreement_id = await peer.publish_agreement(proposed)
            out = await call_text(server.mcp, "a4a_cosign_agreement", {"agreement_id": agreement_id})
            agreements = await peer.get_agreements()
            assert len(agreements) == 1
            assert agreements[0].verify_signatures(), out


@pytest.mark.parametrize("result_url", ["", "   "])
async def test_locked_result_url_may_be_blank(locked, monkeypatch, result_url):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await call_text(server.mcp, "a4a_submit_task_result", {
            "agreement_id": "a" * 64, "task_id": "t", "result_url": result_url})
        results = [e for e in relay.events if e["kind"] == types.KIND_TASK_RESULT]
        assert len(results) == 1, out
        assert "submitted" in out


@pytest.mark.parametrize("our_role", ["a", "b"])
@pytest.mark.parametrize("delegation,allowed", [
    ("Client project details in copied delegation", False),
    ("g" * 64, False), ("a" * 64 + "\n", False),
    ("c" * 64, True), ("", True), (None, True),
])
async def test_make_checks_copied_peer_delegation_before_signing(
        locked, actors, monkeypatch, our_role, delegation, allowed):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        authors = ("me", "peer") if our_role == "a" else ("peer", "me")
        args = await seed_terms(relay, actors, *authors, peer_delegation=delegation)
        before = list(relay.events)
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, "a4a_make_agreement", {
            **args, "peer_pubkey": actors["peer"].pubkey_hex})
        if not allowed:
            assert relay.events == before, out
            assert signed == []
            assert "delegation" in out and "build" in out, out
        else:
            agreement = next(Event(**e) for e in relay.events[len(before):]
                             if e["kind"] == types.KIND_AGREEMENT)
            peer_field = "delegation_b" if our_role == "a" else "delegation_a"
            assert agreement.tag_value(peer_field) == (delegation or None), out


@pytest.mark.parametrize("our_role", ["a", "b"])
@pytest.mark.parametrize("field", ["delegation", "delegation_a", "delegation_b"])
@pytest.mark.parametrize("delegation", ["Client project details in copied delegation", "d" * 64, ""])
async def test_cosign_checks_source_delegation_references(
        locked, actors, monkeypatch, our_role, field, delegation):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url], keys=actors["peer"]) as peer:
            await peer.register(Keys(), "local test peer")
            parties = (actors["me"].pubkey_hex, peer.pubkey)
            if our_role == "b":
                parties = parties[::-1]
            terms = types.Agreement(intent_id="a" * 64, offer_id="b" * 64,
                                    price=5, deadline=123, agent_a=parties[0],
                                    agent_b=parties[1], sig_a="", sig_b="")
            peer_slot = "sig_b" if our_role == "a" else "sig_a"
            terms = terms.model_copy(update={peer_slot: peer.sign_agreement(terms)})
            event = terms.to_event(publisher_delegation=peer.delegation_id,
                                   publisher=peer.pubkey)
            # Mutate only the field under test on a real publisher's signed proposal.
            event.tags = [tag for tag in event.tags if tag[0] != field]
            event.tags.append([field, delegation])
            agreement_id = await peer._publish(event)
        before = list(relay.events)
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, "a4a_cosign_agreement", {"agreement_id": agreement_id})
        if delegation.startswith("Client"):
            assert relay.events == before, out
            assert signed == []
            assert field in out and "build" in out, out
        else:
            completed = [types.Agreement.from_event(Event(**e))
                         for e in relay.events[len(before):] if e["kind"] == types.KIND_AGREEMENT]
            assert len(completed) == 1 and completed[0].verify_signatures(), out


@pytest.mark.parametrize("task_id", [
    "550E8400-E29B-41D4-A716-446655440000",
    "550e8400-e29b-41d4-a716-446655440000",
    "550E8400E29B41D4A716446655440000",
    "Task.Release:2026_09-05",
    "A" * 64,
])
async def test_locked_task_identifiers_round_trip_from_get_tasks(
        locked, actors, monkeypatch, task_id):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url], keys=actors["peer"]) as peer:
            terms = types.Agreement(intent_id="a" * 64, offer_id="b" * 64,
                                    price=5, deadline=123, agent_a=peer.pubkey,
                                    agent_b=actors["me"].pubkey_hex, sig_a="", sig_b="")
            terms = terms.model_copy(update={
                "sig_a": peer.sign_agreement(terms),
                "sig_b": crypto.sign(terms.digest(), actors["me"].privkey_hex)})
            agreement_id = await peer.publish_agreement(terms)
            await peer._publish(types.TaskRequest(
                task_id=task_id, agreement_id=agreement_id, description="", deadline=123,
                executor=actors["me"].pubkey_hex).to_event())
        listing = await call_text(server.mcp, "a4a_get_tasks", {"agreement_id": agreement_id})
        assert task_id in listing
        for tool, extra, kind in (
                ("a4a_update_task_status", {"status": "accepted"}, types.KIND_TASK_STATUS),
                ("a4a_submit_task_result", {"result_url": "https://example.org/r"}, types.KIND_TASK_RESULT)):
            before = len(relay.events)
            out = await call_text(server.mcp, tool, {
                "task_id": task_id, "agreement_id": agreement_id, **extra})
            events = [Event(**e) for e in relay.events[before:] if e["kind"] == kind]
            assert len(events) == 1, out
            assert events[0].tag_value("task_id") == task_id


@pytest.mark.parametrize("task_id", ["Task\n123", "Task\x7f123", "A" * 257])
@pytest.mark.parametrize("tool", ["a4a_update_task_status", "a4a_submit_task_result"])
async def test_locked_task_identifier_rejects_controls_and_unbounded_values(
        locked, monkeypatch, tool, task_id):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        extra = {"status": "accepted"} if tool == "a4a_update_task_status" else {"result_url": ""}
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, tool, {
            "task_id": task_id, "agreement_id": "a" * 64, **extra})
        assert relay.events == [] and signed == [], out
        assert "task_id" in out


@pytest.mark.parametrize("result_url", [
    "ftp://example.org/results/report.zip", "sftp://example.org/results/report.zip",
    "ipfs://bafybeigdyrzt/sample.txt", "s3://results-bucket/report.zip",
    "urn:uuid:550E8400-E29B-41D4-A716-446655440000", "https://example.org/r",
])
async def test_locked_result_allows_structured_uris(locked, monkeypatch, result_url):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await call_text(server.mcp, "a4a_submit_task_result", {
            "task_id": "t", "agreement_id": "a" * 64, "result_url": result_url})
        results = [Event(**e) for e in relay.events if e["kind"] == types.KIND_TASK_RESULT]
        assert len(results) == 1, out
        assert results[0].tag_value("result_url") == result_url


@pytest.mark.parametrize("result_url", [
    "Client project details", "ftp://example.org/report\nnotes", " \t\n",
    "https://example.org/report\x7fnotes", "https://example.org/report\u200bnotes",
    "javascript:alert(1)", "JaVaScRiPt://example.org/alert(1)",
    "data:text/html,<script>alert(1)</script>", "vbscript:msgbox(1)",
])
async def test_locked_result_rejects_prose_controls_and_active_uris(
        locked, monkeypatch, result_url):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, "a4a_submit_task_result", {
            "task_id": "t", "agreement_id": "a" * 64, "result_url": result_url})
        assert relay.events == [], out
        assert signed == []
        assert "result_url" in out and "build" in out, out


@pytest.mark.parametrize("our_role", ["a", "b"])
@pytest.mark.parametrize("defect", ["unrelated", "self", "peer_missing", "peer_invalid",
                                   "ours_invalid", "ours_present"])
async def test_cosign_rejects_invalid_proposal_before_mandate(
        actors, monkeypatch, our_role, defect):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url], keys=actors["peer"]) as peer:
            parties = (actors["me"].pubkey_hex, peer.pubkey)
            if our_role == "b":
                parties = parties[::-1]
            if defect == "unrelated":
                parties = (peer.pubkey, actors["third"].pubkey_hex)
            elif defect == "self":
                parties = (actors["me"].pubkey_hex,) * 2
            terms = types.Agreement(intent_id="a" * 64, offer_id="b" * 64,
                                    price=5, deadline=123, agent_a=parties[0],
                                    agent_b=parties[1], sig_a="", sig_b="")
            peer_slot = "sig_b" if our_role == "a" else "sig_a"
            signatures = {peer_slot: peer.sign_agreement(terms)}
            if defect == "peer_missing":
                signatures[peer_slot] = ""
            elif defect == "peer_invalid":
                signatures[peer_slot] = crypto.sign(terms.digest(), actors["third"].privkey_hex)
            elif defect in ("ours_invalid", "ours_present"):
                signer = actors["third"] if defect == "ours_invalid" else actors["me"]
                signatures["sig_" + our_role] = crypto.sign(terms.digest(), signer.privkey_hex)
            agreement_id = await peer.publish_agreement(terms.model_copy(update=signatures))
        before = list(relay.events)
        signed = record_signatures(monkeypatch)
        out = await call_text(server.mcp, "a4a_cosign_agreement", {"agreement_id": agreement_id})
        assert relay.events == before, out
        assert signed == []
        assert "Cannot sign" in out, out
