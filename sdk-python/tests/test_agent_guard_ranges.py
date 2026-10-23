"""Direct negative controls for release-critical ranges in :mod:`a4a.agent`."""

import contextlib
import asyncio
import json
import time

import pytest

from a4a import delegation, timestamp, types
from a4a.agent import Agent
from a4a.event import Event
from a4a.keys import Keys
from a4a.relay import QueryResult, RelayClient


class _QueryRelay:
    def __init__(self, events):
        self.events = list(events)

    async def query(self, _filters):
        return list(self.events)


def _bare_agent(relay, keys=None):
    agent = object.__new__(Agent)
    agent.keys = keys or Keys()
    agent.relay = relay
    agent.delegation_id = None
    agent._last_addressable = {}
    return agent


def _profile(keys, *, category="development", capabilities=("code",), languages=("en",),
             created_at=None):
    event = types.AgentProfile(
        capabilities=list(capabilities), category=category,
        languages=list(languages)).to_event()
    if created_at is not None:
        event.created_at = created_at
    return event.sign(keys)


def _intent(keys, *, category="development", intent_type="service_request", language="en"):
    return types.Intent(
        intent_type=intent_type, category=category, need="work",
        budget_min=0, budget_max=0, deadline=int(time.time()) + 86400,
        language=language).to_event().sign(keys)


def test_addressable_event_without_coordinate_is_not_remembered():
    agent = _bare_agent(_QueryRelay([]))
    event = Event(kind=types.KIND_AGENT_PROFILE, tags=[], content="missing d")

    agent._bump_created_at(event)

    assert agent._last_addressable == {}


@pytest.mark.parametrize("decoy_kind", ["owner", "delegate"])
async def test_ensure_registered_ignores_wrong_owner_or_delegate(decoy_kind):
    owner = Keys()
    agent_keys = Keys()
    stranger = Keys()
    expiry = int(time.time()) + 30 * 86400
    if decoy_kind == "owner":
        decoy = delegation.create_delegation(
            stranger, agent_keys.pubkey_hex, "wrong owner", expiry)
    else:
        decoy = delegation.create_delegation(
            owner, stranger.pubkey_hex, "wrong delegate", expiry)
    valid = delegation.create_delegation(owner, agent_keys.pubkey_hex, "valid", expiry)

    class Relay:
        def __init__(self):
            self.published = []
            self.clients = [self]
            self.url = "ws://synthetic.invalid"
            self._ws = object()

        async def publish(self, event):
            self.published.append(event)

        async def query(self, filters):
            if filters["kinds"] == [types.KIND_DELEGATION]:
                return [decoy, valid]
            return []

        async def query_bounded(self, filters, *, max_events):
            return QueryResult(events=[decoy, valid], inspected_events=2)

    agent = _bare_agent(Relay(), agent_keys)

    assert await agent.ensure_registered(owner, "agent") == valid.id
    assert agent.relay.published == [], "an existing exact mandate needs no copy"


async def test_ensure_registered_does_not_reuse_revoked_delegation(monkeypatch):
    owner = Keys()
    agent_keys = Keys()
    now = int(time.time())
    old = delegation.create_delegation(
        owner, agent_keys.pubkey_hex, "old", now + 30 * 86400, created_at=now - 2)
    revoked = delegation.create_revocation(owner, old)
    valid = delegation.create_delegation(
        owner, agent_keys.pubkey_hex, "new", now + 30 * 86400,
        created_at=revoked.created_at + 1)
    monkeypatch.setattr(time, "time", lambda: valid.created_at)

    class Relay:
        def __init__(self):
            self.published = []
            self.clients = [self]
            self.url = "ws://synthetic.invalid"
            self._ws = object()

        async def publish(self, event):
            self.published.append(event)

        async def query(self, filters):
            if filters["kinds"] == [types.KIND_DELEGATION]:
                return [old, valid]
            return [revoked]

        async def query_bounded(self, filters, *, max_events):
            return QueryResult(events=[old, valid, revoked], inspected_events=3)

    agent = _bare_agent(Relay(), agent_keys)

    assert await agent.ensure_registered(owner, "agent") == valid.id
    assert agent.relay.published == [], "neither revoked nor existing exact mandates are copied"


async def test_get_profile_ignores_event_from_wrong_author():
    target = Keys()
    wrong = Keys()
    now = int(time.time())
    decoy = _profile(wrong, capabilities=("decoy",), created_at=now + 1)
    valid = _profile(target, capabilities=("valid",), created_at=now)
    agent = _bare_agent(_QueryRelay([decoy, valid]))

    profile = await agent.get_profile(target.pubkey_hex)

    assert profile is not None
    assert profile.capabilities == ["valid"]
    assert profile.source.pubkey == target.pubkey_hex


async def test_find_agents_deduplicates_one_profile_per_author():
    author = Keys()
    events = [_profile(author, capabilities=("first",)),
              _profile(author, capabilities=("second",))]
    agent = _bare_agent(_QueryRelay(events))

    found = await agent.find_agents()

    assert len(found) == 1
    assert found[0].source.pubkey == author.pubkey_hex


async def test_find_agents_skips_malformed_profile():
    malformed = Event(
        kind=types.KIND_AGENT_PROFILE,
        tags=[["category", "not-a-category"]], content="bad").sign(Keys())
    valid = _profile(Keys())
    agent = _bare_agent(_QueryRelay([malformed, valid]))

    found = await agent.find_agents()

    assert [profile.source.id for profile in found] == [valid.id]


@pytest.mark.parametrize(
    ("filters", "accepted", "rejected"),
    [
        ({"category": "design"}, {"category": "design"}, {"category": "development"}),
        ({"language": "de"}, {"languages": ("de",)}, {"languages": ("en",)}),
    ],
)
async def test_find_agents_rechecks_relay_facets(filters, accepted, rejected):
    good = _profile(Keys(), **accepted)
    decoy = _profile(Keys(), **rejected)
    agent = _bare_agent(_QueryRelay([decoy, good]))

    found = await agent.find_agents(**filters)

    assert [profile.source.id for profile in found] == [good.id]


def test_intent_match_rechecks_type_and_language():
    intent = types.Intent(
        intent_type="service_request", category="development", need="work",
        budget_min=0, budget_max=0, deadline=int(time.time()) + 86400, language="en")

    assert not Agent._intent_matches(intent, None, "product_buy", None)
    assert not Agent._intent_matches(intent, None, None, "de")


async def test_intent_subscription_skips_malformed_and_mismatched_events():
    malformed = Event(kind=types.KIND_INTENT, tags=[], content="bad").sign(Keys())
    mismatched = _intent(Keys(), category="design")
    valid = _intent(Keys(), category="development")

    class Relay:
        def subscribe(self, _filters):
            async def events():
                for event in (malformed, mismatched, valid):
                    yield event
            return events()

    agent = _bare_agent(Relay())
    received = []
    stream = agent.subscribe_intents(
        category="development", intent_type="service_request", language="en")
    async with contextlib.aclosing(stream) as events:
        async for intent in events:
            received.append(intent)
            break

    assert [intent.source.id for intent in received] == [valid.id]


async def test_task_event_reader_rechecks_agreement_and_task_coordinates():
    agreement_id = "a" * 64
    party = Keys()
    agent = _bare_agent(_QueryRelay([]))
    task_id = "wanted"

    def result_event(agreement, task):
        return types.TaskResult(
            task_id=task, agreement_id=agreement,
            result_url="https://example.test/result").to_event().sign(party)

    wrong_agreement = result_event("b" * 64, task_id)
    wrong_task = result_event(agreement_id, "other")
    valid = result_event(agreement_id, task_id)
    agent.relay = _QueryRelay([wrong_agreement, wrong_task, valid])

    async def parties(_agreement_id):
        return frozenset((party.pubkey_hex,))

    agent._agreement_parties = parties

    found = await agent._task_events(types.KIND_TASK_RESULT, agreement_id, task_id)

    assert [event.id for event in found] == [valid.id]


async def test_agreement_reader_skips_malformed_and_rechecks_counterparty():
    me = Keys()
    wanted = Keys()
    other = Keys()
    agent = _bare_agent(_QueryRelay([]), me)

    def agreement_event(peer):
        return types.Agreement(
            intent_id="c" * 64, offer_id="d" * 64, price=1,
            deadline=int(time.time()) + 86400, agent_a=me.pubkey_hex,
            agent_b=peer.pubkey_hex, sig_a="", sig_b="").to_event().sign(me)

    malformed = Event(
        kind=types.KIND_AGREEMENT,
        tags=[["price", "not-a-number", "USD"]], content="bad").sign(me)
    decoy = agreement_event(other)
    valid = agreement_event(wanted)

    async def agreements_of(_pubkey):
        return [malformed, decoy, valid]

    agent._agreements_of = agreements_of

    found = await agent.get_agreements(counterparty=wanted.pubkey_hex)

    assert [agreement.source.id for agreement in found] == [valid.id]


async def test_task_reader_rechecks_model_executor_filter_and_parties():
    me = Keys()
    party = Keys()
    outsider = Keys()
    other_executor = Keys()
    agreement_id = "a" * 64
    other_agreement = "b" * 64
    agent = _bare_agent(_QueryRelay([]), me)

    malformed = Event(
        kind=types.KIND_TASK_REQUEST,
        tags=[["agreement", agreement_id], ["task_id", "bad"],
              ["deadline", "not-a-number"], ["executor", me.pubkey_hex]],
        content="bad").sign(party)

    def task_event(keys, agreement, executor, task_id):
        return types.TaskRequest(
            agreement_id=agreement, task_id=task_id, description="work",
            deadline=int(time.time()) + 86400, executor=executor).to_event().sign(keys)

    wrong_executor = task_event(party, agreement_id, other_executor.pubkey_hex, "executor")
    wrong_filter = task_event(party, other_agreement, me.pubkey_hex, "filter")
    wrong_party = task_event(outsider, agreement_id, me.pubkey_hex, "outsider")
    valid = task_event(party, agreement_id, me.pubkey_hex, "valid")
    agent.relay = _QueryRelay(
        [malformed, wrong_executor, wrong_filter, wrong_party, valid])

    async def parties(agreement):
        if agreement == agreement_id:
            return frozenset((me.pubkey_hex, party.pubkey_hex))
        return frozenset((me.pubkey_hex, party.pubkey_hex))

    agent._agreement_parties = parties

    found = await agent.get_tasks(agreement_id=agreement_id)

    assert [task.source.id for task in found] == [valid.id]


async def test_identity_reader_skips_cryptographically_valid_malformed_model():
    subject = Keys()
    issuer = Keys()
    malformed = Event(
        kind=types.KIND_IDENTITY_ATTESTATION,
        tags=[["p", subject.pubkey_hex], ["level", "not-a-level"]],
        content="bad").sign(issuer)
    agent = _bare_agent(_QueryRelay([malformed]))

    assert await agent.get_identity(subject.pubkey_hex) == []


async def test_connection_request_reader_skips_malformed_and_wrong_recipient():
    me = Keys()
    sender = Keys()
    other = Keys()
    malformed = Event(
        kind=types.KIND_CONNECTION_REQUEST,
        tags=[["p", "not-a-key"]], content="bad").sign(sender)
    wrong = types.ConnectionRequest(
        to_pubkey=other.pubkey_hex, intro="wrong").to_event().sign(sender)
    valid = types.ConnectionRequest(
        to_pubkey=me.pubkey_hex, intro="valid").to_event().sign(sender)
    agent = _bare_agent(_QueryRelay([malformed, wrong, valid]), me)

    found = await agent.get_connection_requests()

    assert len(found) == 1
    assert found[0]["event"].id == valid.id


async def test_disconnect_without_own_request_does_not_publish():
    agent = _bare_agent(_QueryRelay([]))
    published = []

    async def broadcast(event):
        published.append(event)

    agent._broadcast = broadcast

    assert await agent.disconnect("b" * 64) is None
    assert published == []


async def test_unweighted_delivery_reputation_does_not_load_trust_graph():
    class Relay:
        def __init__(self):
            self.calls = 0

        async def query(self, _filters):
            self.calls += 1
            if self.calls > 2:
                raise AssertionError("unweighted reputation queried trust assertions")
            return []

    relay = Relay()
    agent = _bare_agent(relay)

    await agent.get_delivery_reputation("b" * 64, weighted=False)

    assert relay.calls == 2


async def test_acknowledge_without_delivery_id_fails_before_publish():
    agent = _bare_agent(_QueryRelay([]))
    published = []

    async def publish(event):
        published.append(event)
        return event.id

    agent._publish = publish
    message = Event(
        kind=types.KIND_PRIVATE_MESSAGE,
        tags=[["p", agent.pubkey]], content="no delivery id").sign(Keys())

    with pytest.raises(ValueError, match="no d tag"):
        await agent.acknowledge(message, wrap=False)
    assert published == []


def _ack_event(keys, delivery_id, to_pubkey, *, kind=types.KIND_ACK_RECEIPT):
    event = types.AckReceipt(
        delivery_id=delivery_id, acked_event_id="e" * 64,
        to_pubkey=to_pubkey, status="processed").to_event()
    event.kind = kind
    return event.sign(keys)


async def test_open_ack_reader_rechecks_delivery_and_recipient():
    me = Keys()
    acker = Keys()
    wanted = "delivery-wanted"
    wrong_delivery = _ack_event(acker, "delivery-other", me.pubkey_hex)
    wrong_recipient = _ack_event(acker, wanted, Keys().pubkey_hex)
    valid = _ack_event(acker, wanted, me.pubkey_hex)
    agent = _bare_agent(_QueryRelay([wrong_delivery, wrong_recipient, valid]), me)

    async def no_wrapped(_delivery_id, from_pubkey=None):
        return []

    agent._get_wrapped_acks = no_wrapped

    found = await agent.get_acks(wanted)

    assert [ack["event"].id for ack in found] == [valid.id]


async def test_wrapped_ack_reader_rechecks_delivery_and_recipient():
    me = Keys()
    acker = Keys()
    wanted = "delivery-wanted"
    wrong_kind = _ack_event(acker, wanted, me.pubkey_hex, kind=types.KIND_PRIVATE_MESSAGE)
    wrong_delivery = _ack_event(acker, "delivery-other", me.pubkey_hex)
    wrong_recipient = _ack_event(acker, wanted, Keys().pubkey_hex)
    valid = _ack_event(acker, wanted, me.pubkey_hex)
    agent = _bare_agent(_QueryRelay([]), me)

    async def inbox(_since):
        return [wrong_kind, wrong_delivery, wrong_recipient, valid]

    agent._unwrap_inbox = inbox

    found = await agent._get_wrapped_acks(wanted)

    assert [ack["event"].id for ack in found] == [valid.id]


async def test_delivery_rejects_negative_retry_count_before_sending():
    agent = _bare_agent(_QueryRelay([]))

    async def send(*_args, **_kwargs):
        raise AssertionError("negative retries reached send")

    agent.send_private_message = send

    with pytest.raises(ValueError, match="retries cannot be negative"):
        await agent.deliver_with_ack("b" * 64, "hello", retries=-1, private=True)


@pytest.mark.parametrize(("kwargs", "parameter"), [
    ({"retries": True}, "retries"),
    ({"retries": 1.5}, "retries"),
    ({"ack_timeout": True}, "ack_timeout"),
    ({"ack_timeout": -0.1}, "ack_timeout"),
    ({"ack_timeout": float("inf")}, "ack_timeout"),
    ({"ack_timeout": float("nan")}, "ack_timeout"),
    ({"poll_interval": True}, "poll_interval"),
    ({"poll_interval": 0}, "poll_interval"),
    ({"poll_interval": float("inf")}, "poll_interval"),
    ({"poll_interval": float("nan")}, "poll_interval"),
])
async def test_delivery_rejects_invalid_wait_controls_before_network(kwargs, parameter):
    agent = _bare_agent(_QueryRelay([]))

    async def resolve(*_args, **_kwargs):
        raise AssertionError("invalid delivery controls reached relay resolution")

    agent.resolve_relays = resolve

    with pytest.raises(ValueError, match=parameter):
        await agent.deliver_with_ack(
            "b" * 64, "hello", resolve_recipient_relays=True, **kwargs)


async def test_delivery_returns_first_matching_ack():
    agent = _bare_agent(_QueryRelay([]))

    async def send(*_args, **_kwargs):
        return "event-id"

    async def acknowledgements(*_args, **_kwargs):
        return [{"status": "processed"}]

    agent.send_private_message = send
    agent._get_wrapped_acks = acknowledgements

    result = await agent.deliver_with_ack(
        "b" * 64, "hello", retries=0, ack_timeout=0, private=True)

    assert result["status"] == "acknowledged"
    assert result["ack_status"] == "processed"
    assert result["attempts"] == 1


async def test_resolve_relays_returns_empty_for_missing_declaration():
    agent = _bare_agent(_QueryRelay([]))

    assert await agent.resolve_relays("b" * 64) == []


async def test_delegation_validation_without_reference_does_not_query_relay():
    class Relay:
        async def query(self, _filters):
            raise AssertionError("event without delegation reached relay")

    agent = _bare_agent(Relay())
    event = Event(kind=types.KIND_INTENT, tags=[], content="no delegation").sign(Keys())

    assert not await agent.validate_delegation(event)


async def test_delegation_validation_stops_on_ambiguous_delegate_tags():
    owner = Keys()
    delegate = Keys()
    other = Keys()
    malformed = Event(
        kind=types.KIND_DELEGATION,
        tags=[["d", delegate.pubkey_hex], ["delegate", other.pubkey_hex],
              ["owner", owner.pubkey_hex],
              ["expiration", str(int(time.time()) + 86400)]],
        content="ambiguous").sign(owner)
    event = Event(
        kind=types.KIND_INTENT,
        tags=[["delegation", malformed.id]], content="work").sign(delegate)

    class Relay:
        def __init__(self):
            self.calls = 0

        async def query(self, _filters):
            self.calls += 1
            return [malformed] if self.calls == 1 else []

    relay = Relay()
    agent = _bare_agent(relay)

    assert not await agent.validate_delegation(event)
    assert relay.calls == 1


async def test_notary_discovery_skips_non_object_retired_entries(monkeypatch):
    current = "a" * 64
    retired = "b" * 64
    payload = json.dumps({
        "a4a": {"notary": current,
                "notary_retired": ["bad", {"pubkey": retired, "until": 123}]}
    }).encode()

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        @staticmethod
        def read():
            return payload

    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: Response())
    agent = _bare_agent(_QueryRelay([]))
    agent._own_relays = ("wss://relay.example",)

    assert await agent._notary_keys() == (current, {retired: 123})


async def test_rest_event_rejects_non_object_before_parsing(monkeypatch):
    async def to_thread(_function):
        return ["not", "an", "event"]

    monkeypatch.setattr(asyncio, "to_thread", to_thread)
    monkeypatch.setattr(
        RelayClient, "_parse_event",
        lambda _raw: (_ for _ in ()).throw(AssertionError("non-object reached parser")))
    agent = _bare_agent(_QueryRelay([]))

    assert await agent._fetch_rest_event("/v1/event/x", "x") is None


async def test_stamp_prefers_pending_over_unverifiable(monkeypatch):
    notary = "a" * 64
    stamps = [type("Stamp", (), {"pubkey": notary})(),
              type("Stamp", (), {"pubkey": notary})()]
    agent = _bare_agent(_QueryRelay(stamps))

    async def notary_keys():
        return notary, {}

    agent._notary_keys = notary_keys
    # Put unverifiable first to prove selection follows state priority, not relay order.
    verdicts = iter((timestamp.StampVerdict("unverifiable", detail="bad"),
                     timestamp.StampVerdict("pending", detail="waiting")))
    monkeypatch.setattr(timestamp, "verify_stamp", lambda *_args: next(verdicts))

    verdict = await agent.get_stamp("e" * 64, headers=object())

    assert verdict.state == "pending"


async def test_authority_without_delegation_stops_before_stamp_lookup():
    agent = _bare_agent(_QueryRelay([]))
    event = Event(kind=types.KIND_REVIEW, tags=[], content="unsigned authority").sign(Keys())

    async def stamp(*_args, **_kwargs):
        raise AssertionError("event without delegation reached stamp lookup")

    agent.get_stamp = stamp

    verdict = await agent.authority_at(event, headers=object())

    assert verdict["state"] == "unauthorized"
    assert "no delegation tag" in verdict["detail"]
