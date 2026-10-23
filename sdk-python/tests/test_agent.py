import asyncio
import contextlib
import time

import pytest

from a4a import types
from a4a import delegation as dlg
from a4a.agent import Agent
from a4a.event import Event
from a4a.keys import Keys
from tests.fake_relay import FakeRelay

DEADLINE = int(time.time()) + 5 * 86400


def test_agent_requires_relay():
    with pytest.raises(ValueError):
        Agent([])


def _intent():
    return types.Intent(intent_type="service_request", category="development",
                        need="landing_page", budget_min=30000, budget_max=50000,
                        deadline=DEADLINE, content="Landing page needed")


def _intent_design():
    return types.Intent(intent_type="service_request", category="design",
                        need="logo", budget_min=10000, budget_max=20000,
                        deadline=DEADLINE, content="Logo needed")


def _strip_multichar_tag_filters(filters: dict) -> dict:
    """Emulate generic relay behavior for multi-character tag names.

    Tags such as #category, #intent_type, and #language are not indexed and are
    silently ignored by the server, so the relay returns every event of the
    requested kind as though the filter were absent.
    """
    return {k: v for k, v in filters.items()
            if not (k.startswith("#") and len(k) > 2)}


async def test_full_agent_flow_over_fake_relay():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            await a.register(Keys(), "Customer")
            await b.register(Keys(), "Contractor")
            assert a.delegation_id and b.delegation_id

            intent_id = await a.publish_intent(_intent())
            found = await b.search_intents(category="development",
                                           intent_type="service_request")
            assert intent_id in [i.source.id for i in found]

            offer_id = await b.publish_offer(types.Offer(
                intent_id=intent_id, price=45000, eta=DEADLINE, content="Ready"))
            offers = await a.get_offers(intent_id)
            assert [o.source.id for o in offers] == [offer_id]
            assert await a.validate_delegation(offers[0].source)

            terms = types.Agreement(
                intent_id=intent_id, offer_id=offer_id, price=45000,
                deadline=DEADLINE, agent_a=a.pubkey, agent_b=b.pubkey,
                sig_a="", sig_b="")
            agreement = terms.model_copy(update={"sig_a": a.sign_agreement(terms),
                                                 "sig_b": b.sign_agreement(terms)})
            assert agreement.verify_signatures()
            agreement_id = await a.publish_agreement(agreement,
                                                     delegation_b=b.delegation_id)

            task_id = await a.send_task(agreement_id, "Build a landing page", DEADLINE,
                                        executor=b.pubkey)
            await b.update_task_status(task_id, agreement_id, "in_progress", 50)
            await b.submit_task_result(task_id, agreement_id, "https://example.com/r")

            await a.publish_review(agreement_id, b.pubkey, 5, "Excellent")
            rep = await a.get_reputation(b.pubkey)
            assert rep.total_reviews == 1 and rep.score == pytest.approx(5.0)


async def test_search_filters_budget_client_side():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a:
            await a.publish_intent(_intent())  # Budget: 30k-50k.
            hits = await a.search_intents(category="development", budget_min=60000)
            assert hits == []


async def test_search_intents_filters_category_client_side_when_relay_ignores_tag_filter():
    """Filter intents client-side when a real relay ignores facet filters.

    Generic relays do not index multi-character tags such as #category, so they
    silently ignore the server-side filter and return every intent of the
    requested kind. FakeRelay supports these filters and would otherwise mask
    the bug, so this test makes relay.query behave like a generic relay.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a:
            dev_id = await a.publish_intent(_intent())
            design_id = await a.publish_intent(_intent_design())

            orig_query = a.relay.query

            async def query_like_real_relay(filters):
                return await orig_query(_strip_multichar_tag_filters(filters))

            a.relay.query = query_like_real_relay

            found = await a.search_intents(category="development")
            assert [i.source.id for i in found] == [dev_id]
            assert design_id not in [i.source.id for i in found]


async def test_subscribe_intents_filters_category_client_side_when_relay_ignores_tag_filter():
    """Apply the same client-side filtering to a live subscription."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as consumer, Agent([relay.url]) as producer:
            received = []

            orig_subscribe = consumer.relay.subscribe

            def subscribe_like_real_relay(filters):
                return orig_subscribe(_strip_multichar_tag_filters(filters))

            consumer.relay.subscribe = subscribe_like_real_relay

            async def consume():
                async with contextlib.aclosing(
                        consumer.subscribe_intents(category="development")) as gen:
                    async for intent in gen:
                        received.append(intent)
                        break  # Wait for the first intent that reaches the consumer.

            task = asyncio.create_task(consume())
            await asyncio.sleep(0.2)  # Let the subscription start.
            await producer.publish_intent(_intent_design())  # Must be filtered out.
            await producer.publish_intent(_intent())  # Must be delivered.
            await asyncio.wait_for(task, timeout=5)
            assert len(received) == 1
            assert received[0].category == "development"


async def test_validate_delegation_fails_without_tag():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a:
            # Intent without delegation: the agent never called register().
            intent_id = await a.publish_intent(_intent())
            found = await a.search_intents(category="development")
            ev = next(i.source for i in found if i.source.id == intent_id)
            assert not await a.validate_delegation(ev)


async def test_publish_profile_roundtrip():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a:
            await a.register(Keys(), "Profile agent")
            eid = await a.publish_profile(types.AgentProfile(
                capabilities=["web_development"], category="development",
                languages=["en"], content="profile"))
            events = await a.relay.query({"kinds": [types.KIND_AGENT_PROFILE]})
            assert [e.id for e in events] == [eid]
            assert events[0].tag_value("d") == "profile"
            assert events[0].tag_value("delegation") == a.delegation_id


async def test_subscribe_intents_live_and_cleanup_on_break():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as consumer, Agent([relay.url]) as producer:
            received = []

            async def consume():
                async with contextlib.aclosing(
                        consumer.subscribe_intents(category="development")) as gen:
                    async for intent in gen:
                        received.append(intent)
                        break  # Consumer exits early.

            task = asyncio.create_task(consume())
            await asyncio.sleep(0.2)  # Let the subscription start.
            await producer.publish_intent(_intent())
            await asyncio.wait_for(task, timeout=5)
            assert len(received) == 1
            await asyncio.sleep(0.1)  # Let the aclose chain finish.
            assert consumer.relay.clients[0]._subs == {}
            assert consumer.relay.clients[0]._sub_filters == {}


async def test_search_skips_malformed_intent():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a:
            good_id = await a.publish_intent(_intent())
            bad = Event(kind=types.KIND_INTENT,
                        tags=[["intent_type", "service_request"], ["category", "development"],
                              ["need", "x"], ["budget_min", "not-a-number"], ["budget_max", "50000"],
                              ["currency", "USD"], ["deadline", "1"], ["language", "ru"],
                              ["d", "bad-intent"]],
                        content="malformed intent").sign(Keys())
            await a.relay.publish(bad)
            found = await a.search_intents(category="development")
            assert [i.source.id for i in found] == [good_id]


async def test_get_offers_skips_malformed_offer():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            intent_id = await a.publish_intent(_intent())
            good_offer_id = await b.publish_offer(types.Offer(
                intent_id=intent_id, price=45000, eta=DEADLINE, content="ok"))
            bad = Event(kind=types.KIND_OFFER,
                        tags=[["intent", intent_id], ["price", "not-a-number", "USD"],
                              ["eta", "1"], ["d", "bad-offer"]],
                        content="malformed offer").sign(Keys())
            await b.relay.publish(bad)
            offers = await a.get_offers(intent_id)
            assert [o.source.id for o in offers] == [good_offer_id]


# --- Private messages (NIP-44) --------------------------------------------

async def test_send_and_read_private_message():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            secret = "confidential meeting summary: contract price EUR 1,000,000"
            ev_id = await alice.send_private_message(bob.pubkey, secret)
            assert ev_id

            inbox = await bob.read_private_messages()
            assert len(inbox) == 1
            assert inbox[0]["from_pubkey"] == alice.pubkey
            assert inbox[0]["content"] == secret
            assert inbox[0]["event"].id == ev_id

            # Inspect what is actually stored ON THE RELAY, not what the SDK
            # returned. Since 2026-08-29 the message is sent in an envelope, and
            # `event` here is the inner rumor. It is intentionally plaintext
            # INSIDE that envelope. The previous assertion inspected the rumor
            # and would fail after the default changed even though relay secrecy
            # remained intact, so inspect the published events instead.
            stored = await bob.relay.query({"kinds": [1059, 31033]})
            assert stored, "nothing was published to the relay"
            for ev in stored:
                assert secret not in ev.content, "secret is plaintext on the relay"


async def test_private_message_not_readable_by_third_party():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob, \
                  Agent([relay.url]) as mallory:
            await alice.send_private_message(bob.pubkey, "for Bob only")
            # Mallory is not the recipient: #p does not match, so the event is
            # not returned at all.
            assert await mallory.read_private_messages() == []


async def test_read_private_messages_skips_undecryptable_event():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            good_id = await alice.send_private_message(bob.pubkey, "valid message")
            # This event targets Bob (#p matches), but its content is not a
            # valid NIP-44 payload.
            bad = Event(kind=types.KIND_PRIVATE_MESSAGE,
                        tags=[["p", bob.pubkey], ["d", "bad-pm"]],
                        content="this is not a base64 NIP-44 payload").sign(Keys())
            await alice.relay.publish(bad)

            inbox = await bob.read_private_messages()
            assert [m["event"].id for m in inbox] == [good_id]


async def test_multiple_private_messages_from_same_sender_all_delivered():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            # Kind 31033 is parameterized replaceable (NIP-33). Without a
            # unique d tag the relay would replace one message with the other;
            # this test protects against that regression.
            id1 = await alice.send_private_message(bob.pubkey, "message 1")
            id2 = await alice.send_private_message(bob.pubkey, "message 2")
            assert id1 != id2

            inbox = await bob.read_private_messages()
            contents = {m["content"] for m in inbox}
            assert contents == {"message 1", "message 2"}


# --- Third-party relays: do not trust server-side filtering ----------------

class _StockRelayView:
    """Model a stock relay that does not index multi-character tag names.

    Such a relay silently ignores the filter and returns every matching event.
    This behavior is documented in `Agent._intent_matches`. The wrapper lets us
    test compatibility with third-party relays rather than only our fork.
    """

    def __init__(self, inner):
        self.inner = inner

    async def query(self, filters):
        stripped = {k: v for k, v in filters.items()
                    if not (k.startswith("#") and len(k) > 2)}
        return await self.inner.query(stripped)

    def __getattr__(self, name):
        return getattr(self.inner, name)


async def test_get_offers_filters_by_intent_on_stock_relay():
    """Never return offers for another intent from an untrusted relay."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as buyer, Agent([relay.url]) as seller:
            await seller.publish_offer(types.Offer(intent_id="intent-ours", price=100, eta=3))
            await seller.publish_offer(types.Offer(intent_id="intent-other", price=200, eta=5))
            buyer.relay = _StockRelayView(buyer.relay)
            offers = await buyer.get_offers("intent-ours")
            assert [o.intent_id for o in offers] == ["intent-ours"]


class _StrfryLikeRelay:
    """Model strfry rejecting a query that uses a multi-character tag filter.

    A live survey of public relays on 2026-08-28 confirmed this behavior in the
    network's dominant relay implementation.
    """

    def __init__(self, inner):
        self.inner = inner
        self.rejections = 0

    async def query(self, filters):
        if any(k.startswith("#") and len(k) > 2 for k in filters):
            self.rejections += 1
            from a4a.relay import RelayError
            raise RelayError("bad req: unindexed tag filter")
        return await self.inner.query(filters)

    def __getattr__(self, name):
        return getattr(self.inner, name)


async def test_search_intents_survives_relay_rejecting_our_tag_filters():
    """Search must work when a third-party relay rejects our facet filters."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as seeker, Agent([relay.url]) as poster:
            common = dict(intent_type="service_request", budget_min=0, budget_max=100,
                          deadline=0)
            await poster.publish_intent(types.Intent(
                need="landing page needed", category="design", **common))
            await poster.publish_intent(types.Intent(
                need="backend needed", category="development", **common))
            strfry = _StrfryLikeRelay(seeker.relay)
            seeker.relay = strfry
            found = await seeker.search_intents(category="design")
            # This used to exercise a retry after rejection. Facets are now
            # duplicated in the indexable `t` tag, so the query should never
            # contain the filter that strfry rejects.
            assert strfry.rejections == 0, "query contained an unindexed filter"
            assert [i.category for i in found] == ["design"]


# --- Review findings: validation and untrusted addresses -------------------

async def test_negative_expiration_is_rejected_with_clear_error():
    """S6: reject a negative lifetime as an argument error.

    It creates an event that is already expired. Our relay rejects it with an
    opaque transport error; another relay may accept and immediately delete it,
    making the message silently disappear.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            with pytest.raises(ValueError, match="expires_in"):
                await a.send_private_message(b.pubkey, "text", expires_in=-1)


async def test_resolve_relays_drops_internal_addresses():
    """S7: reject internal addresses supplied by an untrusted relay-list event.

    Otherwise a recipient could advertise an address inside our perimeter and
    make resolved delivery connect to it. Validate both scheme and host just as
    strictly as file links.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as victim, Agent([relay.url]) as evil:
            await evil.publish_relay_list([
                "ws://127.0.0.1:6379/", "http://169.254.169.254/", relay.url])
            resolved = await victim.resolve_relays(evil.pubkey)
            assert resolved == [relay.url], f"internal addresses were not removed: {resolved}"

async def test_revocation_is_found_for_an_older_copy_of_the_delegation():
    """A revocation applies to an agent, not one signed delegation copy.

    Kind 31000 is addressable: reissuing a delegation replaces it and changes
    its ID. The old copy was public, so anyone may have retained it. A revocation
    names the copy held by the owner in its `e` tag.

    `is_revocation_valid` accounts for this and intentionally ignores `e`.
    `Agent.validate_delegation`, however, used to fetch revocations with
    `{"#e": [delegation ID]}`. A valid revocation therefore never reached
    validation when an agent referenced another copy. Validation was independent
    of the copy, but retrieval was still tied to it.

    The relay (core audit F6) and `is_revocation_valid` had already removed that
    coupling; this test guards the corresponding client fix.
    """
    user, agent = Keys(), Keys()
    expiration = int(time.time()) + 86400

    # Two signed copies of one delegation use different names and therefore
    # have different IDs, just as they would after reissue.
    old_copy = dlg.create_delegation(user, agent.pubkey_hex, "Agent v1", expiration)
    new_copy = dlg.create_delegation(user, agent.pubkey_hex, "Agent v2", expiration)
    assert old_copy.id != new_copy.id, "setup is invalid: copies must differ"

    # The owner revokes the agent while holding the CURRENT copy.
    revocation = dlg.create_revocation(user, new_copy)
    assert revocation.tag_value("e") == new_copy.id
    assert revocation.tag_value("d") == agent.pubkey_hex

    # The agent publishes an event that references the OLD copy.
    ev = Event(kind=types.KIND_INTENT,
               tags=[["delegation", old_copy.id]], content="x").sign(agent)

    async with FakeRelay() as relay:
        async with Agent([relay.url]) as checker:
            for e in (old_copy, new_copy, revocation):
                await checker.relay.publish(e)
            assert not await checker.validate_delegation(ev), (
                "the owner revoked the agent, but delegation validation still "
                "authorizes it because revocation lookup is tied to one `e` copy")
