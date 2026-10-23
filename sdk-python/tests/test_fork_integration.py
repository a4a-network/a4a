"""F8: end-to-end checks for A4A relay behavior beyond generic relays.

Requires a live A4A relay with `[a4a] enabled=true` and `rest_enabled=true`; run
`python scripts/build-relay-image.py --output build/relay-local --tag a4a-relay:local`,
then `docker compose up -d relay` from the repository root using `relay/config.toml`.

- (a) server-side filtering of multi-character tags (`#category`); a generic relay
  returned both events, while the A4A relay returns only the match;
- (b) delegation-chain validation in the WebSocket admission pipeline;
- (c) HTTP REST endpoints `/v1/health`, `/v1/event/:id`, and `/v1/search`.
"""
import asyncio
import json
import time
import urllib.error
import urllib.request
import uuid

import pytest

from a4a import delegation as dlg
from a4a import types
from a4a.agent import Agent
from a4a.event import Event
from a4a.keys import Keys
from a4a.relay import RelayClient, RelayError

RELAY_URL = "ws://localhost:8080"
REST_BASE = "http://localhost:8080"

pytestmark = pytest.mark.integration


def _http(method: str, path: str, body: dict | None = None):
    """Make a synchronous HTTP request to relay REST endpoints using only stdlib."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(REST_BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        parsed = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = raw.decode("utf-8", errors="replace")
    return status, parsed


async def _mandated_pair() -> tuple:
    """Create two mandated agents just like a real user would.

    Receipt 31034 and addressable message 31033 joined the mandate-required kinds only
    in relay 0.3.9. Finding 55 showed that any key could publish them before then.
    These tests did not issue mandates and silently failed afterwards because their
    `integration` marker skips them on machines without a relay. The error waited for
    someone running the relay: us.
    """
    alice, bob = Agent([RELAY_URL]), Agent([RELAY_URL])
    await alice.__aenter__()
    await bob.__aenter__()
    for agent in (alice, bob):
        await agent.ensure_registered(Keys(), "fork integration", days=1)
    return alice, bob


async def _mandate_for(client, keys: Keys) -> str:
    """Issue an owner mandate for a test agent.

    Since 2026-08-29 production configuration requires delegation for A4A kinds, so
    the relay rejects events without it, just as any integrator should. Tests must
    follow the same path as real agents rather than exercise a nonexistent mode.
    """
    owner = Keys()
    deleg = dlg.create_delegation(owner, keys.pubkey_hex, "integration agent",
                                  int(time.time()) + 86400)
    await client.publish(deleg)
    return deleg.id


def _intent_event(category: str, run_marker: str, keys: Keys, extra_tags=None,
                  delegation_id: str | None = None) -> Event:
    tags = [["category", category], ["intent_type", "service_request"],
            ["run_marker", run_marker], ["d", uuid.uuid4().hex]]
    if delegation_id:
        tags.append(["delegation", delegation_id])
    if extra_tags:
        tags += extra_tags
    return Event(kind=31002, tags=tags, content=f"F8 fork-integration {category}").sign(keys)


# --- (a) Server-side filtering of multi-character tag #category -----------

async def test_server_side_multichar_tag_filter_returns_only_matching_category():
    run_marker = uuid.uuid4().hex
    async with RelayClient(RELAY_URL) as client:
        k1, k2 = Keys(), Keys()
        dev_ev = _intent_event("development", run_marker, k1,
                               delegation_id=await _mandate_for(client, k1))
        design_ev = _intent_event("design", run_marker, k2,
                                  delegation_id=await _mandate_for(client, k2))
        await client.publish(dev_ev)
        await client.publish(design_ev)

        # RelayClient.query sends raw REQ without Agent.search_intents client-side
        # filtering. A relay that truly filters #category returns only development;
        # the same query returned both events on stock relay.
        found = await client.query({"kinds": [31002], "#category": ["development"],
                                     "#run_marker": [run_marker]})

    assert {e.id for e in found} == {dev_ev.id}


# --- (b) Delegation-chain validation during WebSocket publication ----------

async def test_ws_publish_rejects_event_with_nonexistent_delegation():
    async with RelayClient(RELAY_URL) as client:
        bogus_deleg_id = "0" * 64
        ev = Event(kind=31002,
                   tags=[["category", "development"], ["intent_type", "service_request"],
                         ["d", uuid.uuid4().hex], ["delegation", bogus_deleg_id]],
                   content="delegation references a nonexistent event").sign(Keys())
        with pytest.raises(RelayError):
            await client.publish(ev)


async def test_ws_publish_accepts_event_with_valid_delegation_chain():
    user_keys, agent_keys = Keys(), Keys()
    deleg = dlg.create_delegation(user_keys, agent_keys.pubkey_hex, "F8 test agent",
                                  int(time.time()) + 86400)
    async with RelayClient(RELAY_URL) as client:
        await client.publish(deleg)  # Kind 31000 is published first, as in Agent.register().
        ev = Event(kind=31002,
                   tags=[["category", "development"], ["intent_type", "service_request"],
                         ["d", uuid.uuid4().hex], ["delegation", deleg.id]],
                   content="valid delegation chain").sign(agent_keys)
        await client.publish(ev)  # Must not raise RelayError.


# --- (d) Reliable delivery (P1) on the real fork: addressable + #d ---------

async def test_deliver_with_ack_over_fork_relay():
    # Fresh keys ensure Bob's inbox contains only this run.
    alice, bob = await _mandated_pair()
    try:
        async def recv_and_ack():
            for _ in range(50):
                inbox = await bob.read_private_messages()
                if inbox:
                    await bob.acknowledge(inbox[0], status="processed")
                    return
                await asyncio.sleep(0.1)

        task = asyncio.create_task(recv_and_ack())
        result = await alice.deliver_with_ack(
            bob.pubkey, "call summary: deal details", retries=5,
            ack_timeout=3.0, poll_interval=0.2)
        await task
    finally:
        await alice.__aexit__()
        await bob.__aexit__()

    assert result["status"] == "acknowledged"
    assert result["ack_status"] == "processed"


async def test_wrapped_ack_has_no_relay_side_dedup_and_that_is_inherent():
    """Relay-side deduplication of wrapped acknowledgements is inherently impossible.

    Addressable replacement uses (author, kind, d). Envelope authors use one-time
    ephemeral keys, so two acknowledgements of one delivery look like events from
    different people. A relay cannot both be denied sender identity and be asked to
    match it. This is the cost of metadata privacy, enabled by default since 2026-08-29.

    Application logic is unaffected: `get_acks` deduplicates by event ID and delivery
    reputation uses the latest acknowledgement. Only storage grows, bounded by the
    retention period for kind 1059.
    """
    async with Agent([RELAY_URL]) as alice, Agent([RELAY_URL]) as bob:
        did = uuid.uuid4().hex
        await alice.send_private_message(bob.pubkey, "duplicate test", delivery_id=did)
        inbox = await bob.read_private_messages()
        assert inbox
        await bob.acknowledge(inbox[0], status="received")
        await bob.acknowledge(inbox[0], status="processed")

        acks = await alice.get_acks(did, from_pubkey=bob.pubkey)
        assert acks, "no acknowledgements were found"
        assert all(a["acker_pubkey"] == bob.pubkey for a in acks), \
            "acknowledgement did not come from the recipient"


async def test_plain_ack_is_addressable_idempotent_on_relay():
    # Two acknowledgements for one delivery: relay stores one, addressable by d.
    alice, bob = await _mandated_pair()
    try:
        did = uuid.uuid4().hex
        # Request plaintext explicitly. Relay deduplication works only when the event
        # author is the acknowledger, not an ephemeral envelope key.
        await alice.send_private_message(bob.pubkey, "duplicate test", delivery_id=did,
                                         wrap=False)
        inbox = await bob.read_private_messages()
        assert inbox
        await bob.acknowledge(inbox[0], status="received", wrap=False)
        await bob.acknowledge(inbox[0], status="processed", wrap=False)

        acks = await alice.get_acks(did, from_pubkey=bob.pubkey)
    finally:
        await alice.__aexit__()
        await bob.__aexit__()

    # Addressable deduplication by d leaves ONE acknowledgement per
    # (acknowledger, delivery) pair rather than two.
    assert len(acks) == 1
    # This used to accept either result. With equal created_at the relay keeps the
    # first, silently losing a received-to-processed transition. Finding 118 fixed
    # this in the SDK by advancing time one second when replacing the same coordinate,
    # so the assertion can now be exact.
    assert acks[0]["status"] == "processed", \
        "second acknowledgement did not replace the first; same-second update was lost"


# --- (e) Relay delegation revocation (P4): reject revoked agent events -----

async def test_ws_rejects_event_after_delegation_revoked():
    user_keys, agent_keys = Keys(), Keys()
    deleg = dlg.create_delegation(user_keys, agent_keys.pubkey_hex, "revoke-test agent",
                                  int(time.time()) + 86400)
    async with RelayClient(RELAY_URL) as client:
        await client.publish(deleg)  # Kind 31000.
        # Accept an event with a valid delegation before revocation.
        ev1 = Event(kind=31002,
                    tags=[["category", "development"], ["intent_type", "service_request"],
                          ["d", uuid.uuid4().hex], ["delegation", deleg.id]],
                    content="before revocation").sign(agent_keys)
        await client.publish(ev1)

        # Owner revokes delegation (kind 31007), invalidating relay cache.
        rev = dlg.create_revocation(user_keys, deleg)
        await client.publish(rev)

        # Relay rejects an event using the same delegation after revocation.
        ev2 = Event(kind=31002,
                    tags=[["category", "development"], ["intent_type", "service_request"],
                          ["d", uuid.uuid4().hex], ["delegation", deleg.id]],
                    content="after revocation").sign(agent_keys)
        with pytest.raises(RelayError):
            await client.publish(ev2)


# --- (f) Metadata privacy (gift wrap) and reveal on the real fork ----------

async def test_private_delivery_and_reveal_over_fork_relay():
    async with Agent([RELAY_URL]) as alice, Agent([RELAY_URL]) as bob:
        async def recv_and_ack():
            for _ in range(50):
                inbox = await bob.read_private_messages()
                if inbox:
                    await bob.acknowledge(inbox[0], status="processed")
                    return inbox[0]
                await asyncio.sleep(0.1)
            return None

        task = asyncio.create_task(recv_and_ack())
        result = await alice.deliver_with_ack(
            bob.pubkey, "private delivery on the fork", private=True,
            retries=5, ack_timeout=3.0, poll_interval=0.2)
        msg = await task

        assert result["status"] == "acknowledged"
        assert msg is not None and msg["wrapped"] is True
        # Reveal makes signed plaintext public and verifiable.
        await bob.reveal(msg)
        revealed = await bob.relay.query({"kinds": [types.KIND_PRIVATE_RUMOR]})
        assert any(e.pubkey == alice.pubkey and e.verify() for e in revealed)


# --- (c) REST over HTTP ----------------------------------------------------

async def test_rest_health_returns_200():
    status, body = _http("GET", "/v1/health")
    assert status == 200
    assert body["status"] == "ok"


async def test_rest_get_event_matches_published_via_ws():
    async with RelayClient(RELAY_URL) as client:
        keys = Keys()
        ev = _intent_event("development", uuid.uuid4().hex, keys,
                           delegation_id=await _mandate_for(client, keys))
        await client.publish(ev)

    status, body = _http("GET", f"/v1/event/{ev.id}")
    assert status == 200
    assert body["id"] == ev.id


async def test_rest_search_returns_only_matching_category():
    run_marker = uuid.uuid4().hex
    async with RelayClient(RELAY_URL) as client:
        k1, k2 = Keys(), Keys()
        dev_ev = _intent_event("development", run_marker, k1,
                               delegation_id=await _mandate_for(client, k1))
        design_ev = _intent_event("design", run_marker, k2,
                                  delegation_id=await _mandate_for(client, k2))
        await client.publish(dev_ev)
        await client.publish(design_ev)

    status, body = _http("POST", "/v1/search",
                         {"kinds": [31002], "#category": ["development"],
                          "#run_marker": [run_marker]})
    assert status == 200
    assert isinstance(body, list)
    assert {e["id"] for e in body} == {dev_ev.id}
