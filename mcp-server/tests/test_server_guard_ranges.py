"""Direct negative controls for the first release-critical ``server.py`` guards."""

import time
from types import SimpleNamespace

import pytest
from a4a import Agreement, crypto, delegation, types

from a4a_mcp import identity, server


@pytest.fixture(autouse=True)
def clear_relay_failure_cache():
    server._forget_unreachable()
    yield
    server._forget_unreachable()


class _Context:
    def __init__(self, agent):
        self.agent = agent

    async def __aenter__(self):
        return self.agent

    async def __aexit__(self, *_exc):
        return False


def test_relay_url_override_replaces_the_whole_configured_set(monkeypatch):
    monkeypatch.setenv("A4A_RELAY", "ws://real.example,ws://other.example")
    monkeypatch.setattr(server, "_relay_url", lambda: "ws://fixture.invalid")

    assert server._relay_urls() == ["ws://fixture.invalid"]


def test_empty_first_relay_is_rejected(monkeypatch):
    monkeypatch.setenv("A4A_RELAY", ",ws://second.example")

    with pytest.raises(ValueError, match="is empty"):
        server._relay_url()


async def test_missing_owner_does_not_query_untrusted_relay(monkeypatch):
    class Relay:
        async def query(self, _filters):
            raise AssertionError("relay must not be queried without an owner identity")

    agent = type("AgentStub", (), {"pubkey": "b" * 64, "relay": Relay()})()
    monkeypatch.setattr(identity, "owner_public_key", lambda: None)

    assert await server._find_existing_mandate(agent) is None


async def test_mandate_lookup_skips_wrong_kind_before_valid_candidate(monkeypatch):
    owner = "a" * 64
    agent_key = "b" * 64
    now = int(time.time())
    tags = [["d", agent_key], ["delegate", agent_key], ["owner", owner],
            ["expiration", str(now + 7200)]]

    class Candidate:
        def __init__(self, event_id, kind):
            self.id = event_id
            self.kind = kind
            self.pubkey = owner
            self.created_at = now
            self.tags = tags

        def verify(self):
            return True

        def tag_value(self, name):
            return next((tag[1] for tag in self.tags if tag and tag[0] == name), None)

    class Relay:
        async def query(self, _filters):
            return [Candidate("wrong-kind", types.KIND_INTENT),
                    Candidate("valid-delegation", types.KIND_DELEGATION)]

    agent = type("AgentStub", (), {"pubkey": agent_key, "relay": Relay()})()
    monkeypatch.setattr(identity, "owner_public_key", lambda: owner)
    monkeypatch.setattr(delegation, "delegation_target",
                        lambda event: event.tag_value("delegate"))

    assert await server._find_existing_mandate(agent) == "valid-delegation"


def test_non_positive_mandate_lifetime_is_rejected(monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_DAYS", "0")

    with pytest.raises(ValueError, match="at least 1"):
        server._mandate_days()


async def test_profile_category_is_rejected_before_mandated_agent(monkeypatch):
    class ForbiddenContext:
        async def __aenter__(self):
            raise AssertionError("invalid category reached the publishing boundary")

        async def __aexit__(self, *_exc):
            return False

    monkeypatch.setattr(server, "_mandated", ForbiddenContext)

    result = await server.a4a_publish_profile([], "not-a-category")

    assert result.startswith("Unknown category:")
    assert "development" in result


async def test_empty_intent_search_has_an_explicit_result(monkeypatch):
    class Agent:
        async def search_intents(self, **_filters):
            return []

    monkeypatch.setattr(server, "_make_agent", lambda: _Context(Agent()))

    assert await server.a4a_search_intents() == "No intents matched the specified filters."


async def test_find_agents_rejects_bad_category_before_agent_creation(monkeypatch):
    monkeypatch.setattr(
        server, "_make_agent",
        lambda: (_ for _ in ()).throw(AssertionError("invalid category reached relay")))

    result = await server.a4a_find_agents(category="not-a-category")

    assert result.startswith("Unknown category:")
    assert "development" in result


async def test_empty_agent_search_has_an_explicit_result(monkeypatch):
    class Agent:
        async def find_agents(self, **_filters):
            return []

    monkeypatch.setattr(server, "_make_agent", lambda: _Context(Agent()))

    assert await server.a4a_find_agents() == "No agents matched the specified filters."


async def test_empty_offer_search_has_an_explicit_result(monkeypatch):
    class Agent:
        async def get_offers(self, _intent_id):
            return []

    monkeypatch.setattr(server, "_make_agent", lambda: _Context(Agent()))

    intent_id = "a" * 64
    assert await server.a4a_get_offers(intent_id) == (
        f"No offers have been published for intent {intent_id}."
    )


async def test_agreement_rejects_bad_peer_key_before_identity_access(monkeypatch):
    monkeypatch.setattr(
        server, "load_or_create_identity",
        lambda: (_ for _ in ()).throw(AssertionError("invalid key reached identity")))

    result = await server.a4a_make_agreement(
        "c" * 64, "d" * 64, 1, 1, "not-a-key")

    assert result.startswith("peer_pubkey must be a hex public key")


async def test_agreement_rejects_same_discovered_parties(monkeypatch):
    our = "a" * 64
    peer = "b" * 64

    class Event:
        pubkey = our
        tags = []

        @staticmethod
        def tag_value(_name):
            return None

    class Relay:
        async def query(self, _filters):
            return [Event()]

    agent = SimpleNamespace(pubkey=our, relay=Relay())
    monkeypatch.setattr(server, "load_or_create_identity",
                        lambda: SimpleNamespace(pubkey_hex=our))
    monkeypatch.setattr(server, "_make_agent", lambda: _Context(agent))
    monkeypatch.setattr(
        server, "_mandated",
        lambda: (_ for _ in ()).throw(AssertionError("invalid agreement reached signing")))

    result = await server.a4a_make_agreement("c" * 64, "d" * 64, 1, 1, peer)

    assert "both deal parties are identical" in result


async def test_empty_agreement_search_has_an_explicit_result(monkeypatch):
    class Agent:
        pubkey = "a" * 64

        async def get_agreements(self, **_filters):
            return []

    monkeypatch.setattr(server, "_make_agent", lambda: _Context(Agent()))

    assert await server.a4a_get_agreements() == (
        "No agreements involving this agent were found."
    )


def test_agreement_state_reports_fully_signed_before_slot_advice():
    agreement = SimpleNamespace(
        agent_a="a" * 64, agent_b="b" * 64, sig_a="", sig_b="",
        digest=lambda: "digest", verify_signatures=lambda: True)

    assert server._agreement_state(agreement, agreement.agent_a) == "SIGNED BY BOTH"


def test_agreement_state_rejects_invalid_partner_signature(monkeypatch):
    agreement = SimpleNamespace(
        agent_a="a" * 64, agent_b="b" * 64, sig_a="our-signature", sig_b="bad-signature",
        digest=lambda: "digest", verify_signatures=lambda: False)
    monkeypatch.setattr(crypto, "verify",
                        lambda _digest, signature, _key: signature == "our-signature")

    assert "counterparty signature is invalid" in server._agreement_state(
        agreement, agreement.agent_a)


class _AgreementEvent:
    kind = types.KIND_AGREEMENT


async def test_cosign_reports_missing_proposal(monkeypatch):
    class Relay:
        async def query(self, _filters):
            return []

    agent = SimpleNamespace(pubkey="a" * 64, relay=Relay())
    monkeypatch.setattr(server, "_make_agent", lambda: _Context(agent))

    result = await server.a4a_cosign_agreement("c" * 64)

    assert "not found on the relay" in result


async def test_cosign_rejects_identical_parties(monkeypatch):
    our = "a" * 64
    proposal = SimpleNamespace(agent_a=our, agent_b=our)

    class Relay:
        async def query(self, _filters):
            return [_AgreementEvent()]

    agent = SimpleNamespace(pubkey=our, relay=Relay())
    monkeypatch.setattr(server, "_make_agent", lambda: _Context(agent))
    monkeypatch.setattr(server, "_safe_agreement", lambda _event: proposal)

    assert "both agreement parties are identical" in await server.a4a_cosign_agreement("c" * 64)


async def test_cosign_requires_the_other_partys_signature(monkeypatch):
    our = "b" * 64
    proposal = SimpleNamespace(
        agent_a="a" * 64, agent_b=our, sig_a="", sig_b="", digest=lambda: "digest")

    class Relay:
        async def query(self, _filters):
            return [_AgreementEvent()]

    agent = SimpleNamespace(pubkey=our, relay=Relay())
    monkeypatch.setattr(server, "_make_agent", lambda: _Context(agent))
    monkeypatch.setattr(server, "_safe_agreement", lambda _event: proposal)

    assert "other party's signature is missing" in await server.a4a_cosign_agreement("c" * 64)


async def test_cosign_distinguishes_an_already_concluded_agreement(monkeypatch):
    our = "b" * 64
    proposal = Agreement(
        intent_id="c" * 64, offer_id="d" * 64, price=1, deadline=int(time.time()) + 86400,
        agent_a="a" * 64, agent_b=our, sig_a="peer-signature", sig_b="")

    class Relay:
        async def query(self, _filters):
            return [_AgreementEvent()]

    reader = SimpleNamespace(pubkey=our, relay=Relay())

    class Existing:
        @staticmethod
        def verify_signatures():
            return True

        @staticmethod
        def digest():
            return proposal.digest()

    class Signer:
        async def get_agreements(self):
            return [Existing()]

        async def co_sign_agreement(self, _proposal):
            return "e" * 64

    monkeypatch.setattr(crypto, "verify", lambda *_args: True)
    monkeypatch.setattr(server, "_make_agent", lambda: _Context(reader))
    monkeypatch.setattr(server, "_mandated", lambda: _Context(Signer()))
    monkeypatch.setattr(server, "_safe_agreement", lambda _event: proposal)

    result = await server.a4a_cosign_agreement("f" * 64)

    assert "already concluded" in result


async def test_task_rejects_negative_deadline_before_signing(monkeypatch):
    monkeypatch.setattr(
        server, "_mandated",
        lambda: (_ for _ in ()).throw(AssertionError("negative deadline reached signing")))

    result = await server.a4a_send_task("c" * 64, "b" * 64, deadline_days=-1)

    assert "deadline_days=-1" in result


async def test_empty_task_search_has_an_explicit_result(monkeypatch):
    class Agent:
        async def get_tasks(self, **_filters):
            return []

    monkeypatch.setattr(server, "_make_agent", lambda: _Context(Agent()))

    assert await server.a4a_get_tasks() == "No tasks assigned to you were found."


async def test_empty_task_result_search_has_an_explicit_result(monkeypatch):
    class Agent:
        async def get_task_results(self, _agreement_id, _task_id):
            return []

    monkeypatch.setattr(server, "_make_agent", lambda: _Context(Agent()))

    agreement_id = "c" * 64
    result = await server.a4a_get_task_results(agreement_id)
    assert result == f"No results have been published for agreement {agreement_id}."


async def test_review_rejects_bad_peer_key_before_mandate(monkeypatch):
    monkeypatch.setattr(
        server, "_mandated",
        lambda: (_ for _ in ()).throw(AssertionError("invalid review reached signing")))

    result = await server.a4a_publish_review("c" * 64, "not-a-key", 5)

    assert result.startswith("peer_pubkey must be a hex public key")


async def test_empty_connection_request_search_has_an_explicit_result(monkeypatch):
    class Agent:
        async def get_connection_requests(self):
            return []

    monkeypatch.setattr(server.inbox_runtime, "active_policy", lambda: None)
    monkeypatch.setattr(server.inbox_runtime, "allowed_messages", lambda messages: messages)
    monkeypatch.setattr(server, "_make_agent", lambda: _Context(Agent()))

    assert await server.a4a_get_connection_requests() == (
        "There are no incoming connection requests."
    )


@pytest.mark.parametrize("function", [server.a4a_send_private,
                                      server.a4a_deliver])
async def test_private_send_rejects_bad_recipient_before_policy(monkeypatch, function):
    monkeypatch.setattr(
        server.inbox_runtime, "require_legacy_send",
        lambda _peer: (_ for _ in ()).throw(AssertionError("invalid key reached policy")))

    result = await function("not-a-key", "hello")

    assert result.startswith("to_pubkey must be a hex public key")


@pytest.mark.parametrize("function", [server.a4a_send_private,
                                      server.a4a_deliver])
async def test_private_send_rejects_oversize_plaintext_before_mandate(
        monkeypatch, function):
    monkeypatch.setattr(server.inbox_runtime, "require_legacy_send", lambda _peer: None)
    monkeypatch.setattr(
        server, "_mandated",
        lambda: (_ for _ in ()).throw(AssertionError("oversize text reached signing")))

    options = {"new_letter": True} if function is server.a4a_deliver else {}
    result = await function("b" * 64, "x" * (32 * 1024 + 1), **options)

    assert "exceeds 32 KiB" in result


async def test_empty_private_inbox_has_an_explicit_result(monkeypatch):
    class Agent:
        async def read_private_messages(self):
            return []

    monkeypatch.setattr(server.inbox_runtime, "active_policy", lambda: None)
    monkeypatch.setattr(server.inbox_runtime, "allowed_messages", lambda messages: messages)
    monkeypatch.setattr(server, "_make_agent", lambda: _Context(Agent()))

    assert await server.a4a_read_private() == "There are no incoming private messages."


def test_unverifiable_missing_mandate_names_the_archive_boundary():
    advice = server._unverifiable_advice("mandate not found")

    assert "archive of replaced delegations" in advice
    assert "Past authority cannot be checked" in advice


async def test_file_send_rejects_bad_recipient_before_policy(monkeypatch):
    monkeypatch.setattr(
        server.inbox_runtime, "require_legacy_send",
        lambda _peer: (_ for _ in ()).throw(AssertionError("invalid key reached policy")))

    result = await server.a4a_send_file("not-a-key", "missing", "https://example.test/blob")

    assert result.startswith("to_pubkey must be a hex public key")


async def test_file_send_rejects_missing_blob_before_key_lookup(tmp_path, monkeypatch):
    monkeypatch.setattr(server.inbox_runtime, "require_legacy_send", lambda _peer: None)
    monkeypatch.setattr(
        server.identity, "peek_file_key",
        lambda _sha: (_ for _ in ()).throw(AssertionError("missing blob reached key store")))
    missing = tmp_path / "missing.a4a"

    result = await server.a4a_send_file(
        "b" * 64, str(missing), "https://example.test/blob")

    assert result == f"Blob not found: {missing}"


async def test_file_open_rejects_missing_blob_before_output_access(tmp_path, monkeypatch):
    monkeypatch.setattr(server.inbox_runtime, "active_policy", lambda: None)
    missing = tmp_path / "missing.a4a"
    output = tmp_path / "output.txt"

    result = await server.a4a_open_file(str(missing), str(output))

    assert result == f"Blob not found: {missing}"
    assert not output.exists()


def test_trusted_issuer_setting_has_a_size_bound(monkeypatch):
    monkeypatch.setenv("A4A_TRUSTED_ISSUERS", "a" * 4097)

    with pytest.raises(ValueError, match="configuration size limit"):
        server._evidence_trusted_issuers()
