"""Organization trust is explicit, bounded, and absent from legacy policies."""

import json
import time

import pytest

from a4a.inbox import InboxError
from a4a import Agent, Keys, giftwrap, types
from a4a.delegation import create_delegation
from a4a.event import Event
from a4a_mcp import dialogue_runtime, identity, inbox_runtime
from fake_relay import FakeRelay


@pytest.fixture
def policy_file(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:9")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    identity.load_or_create_identity()
    return tmp_path / ".a4a" / "inbox-policy.json"


def test_allowed_owners_is_explicit_and_legacy_policy_stays_closed(policy_file):
    policy = inbox_runtime.configure("c", [], start_after=0)
    assert policy.allowed_owners == frozenset()
    data = json.loads(policy_file.read_text(encoding="utf-8"))
    data.pop("allowed_owners", None)
    policy_file.write_text(json.dumps(data), encoding="utf-8")
    assert inbox_runtime.load_policy().allowed_owners == frozenset()


def test_allowed_owners_accepts_only_exact_unique_keys(policy_file):
    owner = "a" * 64
    policy = inbox_runtime.configure("c", [], start_after=0, allowed_owners=[owner])
    assert policy.allowed_owners == frozenset({owner})
    for owners in (["*"], [owner, owner], [owner.upper()], [owner] * 101):
        data = json.loads(policy_file.read_text(encoding="utf-8"))
        data["allowed_owners"] = owners
        policy_file.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(InboxError, match="allowed_owners"):
            inbox_runtime.load_policy()


def test_owner_agent_display_uses_only_signed_mandate_name():
    owner, agent = Keys(), Keys()
    mandate = create_delegation(owner, agent.pubkey_hex, "Sales", int(time.time()) + 3600)
    identity = inbox_runtime.owner_agent_identity(agent.pubkey_hex, mandate)
    assert identity["organization_pubkey"] == owner.pubkey_hex
    assert identity["agent_pubkey"] == agent.pubkey_hex
    assert identity["agent_name"] == "Sales"
    assert identity["display"] == f"{owner.pubkey_hex[:12]}… · Sales"
    with pytest.raises(InboxError, match="does not match"):
        inbox_runtime.owner_agent_identity(Keys().pubkey_hex, mandate)


def test_owner_trust_does_not_enter_unimplemented_dialogue_routing(policy_file):
    inbox_runtime.configure("c", [], start_after=0, allowed_owners=["a" * 64])
    with pytest.raises(InboxError, match="cannot be enabled"):
        dialogue_runtime.enable()


def test_existing_dialogue_policy_cannot_be_replaced_with_owner_trust(policy_file):
    inbox_runtime.configure("c", [], start_after=0)
    dialogue_runtime.enable()
    before = policy_file.read_bytes()
    with pytest.raises(InboxError, match="while dialogue mode is active"):
        inbox_runtime.configure("c", [], start_after=0, replace=True,
                                allowed_owners=["a" * 64])
    assert policy_file.read_bytes() == before


async def test_claim_shows_owner_signed_agent_name(policy_file, monkeypatch):
    owner, sender = Keys(), Keys()
    recipient = identity.load_or_create_identity()
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        inbox_runtime.configure("c", [], start_after=0,
                                allowed_owners=[owner.pubkey_hex])
        mandate = create_delegation(owner, sender.pubkey_hex, "Sales", int(time.time()) + 3600)
        async with Agent([relay.url], keys=sender) as publisher:
            await publisher.relay.publish(mandate)
        inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                      tags=[["p", recipient.pubkey_hex], ["d", "claim-owner"]],
                      content="hello").sign(sender)
        outer = giftwrap.wrap(inner, recipient.pubkey_hex, sender)
        with inbox_runtime.open_runtime() as (_, agent, store):
            assert store.accept(agent, outer, {sender.pubkey_hex}) == "stored"
            store.set_health("ready")
        result = await inbox_runtime.claim_authorized()
        message = result["message"]
        assert result["state"] == "processing"
        assert message["sender_identity"]["organization_pubkey"] == owner.pubkey_hex
        assert message["sender_identity"]["agent_name"] == "Sales"
        assert message["sender_identity"]["display"].endswith(" · Sales")
        inbox_runtime.complete(message["seq"], message["lease_token"], "processed")


async def test_exact_peer_remains_claimable_offline_with_owner_policy(policy_file):
    peer, owner = Keys(), Keys()
    recipient = identity.load_or_create_identity()
    inbox_runtime.configure("c", [peer.pubkey_hex], start_after=0,
                            allowed_owners=[owner.pubkey_hex])
    inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                  tags=[["p", recipient.pubkey_hex], ["d", "exact-peer"]],
                  content="locally stored").sign(peer)
    outer = giftwrap.wrap(inner, recipient.pubkey_hex, peer)
    with inbox_runtime.open_runtime() as (_, agent, store):
        assert store.accept(agent, outer, {peer.pubkey_hex}) == "stored"
        store.set_health("ready")
    # The fixture's relay URL is deliberately unavailable. An owner lookup for
    # this exact peer would turn a local queued letter into a network dependency.
    result = await inbox_runtime.claim_authorized()
    assert result["message"]["from_pubkey"] == peer.pubkey_hex
    assert "sender_identity" not in result["message"]
    inbox_runtime.complete(result["message"]["seq"],
                           result["message"]["lease_token"], "processed")


async def test_manual_view_filters_agents_by_current_owner_mandate(policy_file, monkeypatch):
    owner, sender, stranger = Keys(), Keys(), Keys()
    recipient = identity.load_or_create_identity()
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        inbox_runtime.configure("c", [], start_after=0,
                                allowed_owners=[owner.pubkey_hex])
        mandate = create_delegation(owner, sender.pubkey_hex, "Sales", int(time.time()) + 3600)
        async with Agent([relay.url], keys=sender) as publisher:
            await publisher.relay.publish(mandate)
        async with Agent([relay.url], keys=recipient) as reader:
            messages = [{"from_pubkey": sender.pubkey_hex},
                        {"from_pubkey": stranger.pubkey_hex}]
            shown = await inbox_runtime.allowed_messages_authorized(reader, messages)
        assert [m["from_pubkey"] for m in shown] == [sender.pubkey_hex]
        assert shown[0]["sender_identity"]["agent_name"] == "Sales"
