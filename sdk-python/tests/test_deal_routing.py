"""End-to-end deal between TWO independent agents on an ordinary relay.

The `two-agents-deal.py` example completes the whole cycle, but both agents live in
one process: the worker receives deal and task IDs through Python variables. That
does not happen on a network; the counterparty must FIND events addressed to it.

Here agents exchange only what actually reaches the relay. The relay is deliberately
"stock": its wrapper drops filters for multi-character tags, as ordinary foreign
relays do (our fork indexes them, but the network generally does not).
"""
import asyncio
import time

import pytest
from a4a import types
from a4a.agent import Agent
from a4a.keys import Keys
from a4a.types import agreement_digest

from tests.fake_relay import FakeRelay


class _StockRelayView:
    """Relay without multi-character tag filtering, matching the wider network."""

    def __init__(self, inner):
        self.inner = inner

    async def query(self, filters):
        stripped = {k: v for k, v in filters.items()
                    if not (k.startswith("#") and len(k) > 2)}
        return await self.inner.query(stripped)

    def __getattr__(self, name):
        return getattr(self.inner, name)


async def _make_deal(customer, worker, intent_id, offer_id, price=1000):
    terms = types.Agreement(
        intent_id=intent_id, offer_id=offer_id, price=price, currency="USD",
        deadline=0, agent_a=customer.pubkey, agent_b=worker.pubkey, sig_a="", sig_b="")
    agreement = terms.model_copy(update={"sig_a": customer.sign_agreement(terms),
                                         "sig_b": worker.sign_agreement(terms)})
    return await customer.publish_agreement(agreement)


async def test_worker_finds_agreement_addressed_to_it_on_stock_relay():
    """A worker must discover ITS deal without knowing the ID in advance."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as customer, Agent([relay.url]) as worker, \
                Agent([relay.url]) as stranger:
            await _make_deal(customer, worker, "i" * 64, "o" * 64, price=1000)
            # Another deal from the same customer must not reach this worker.
            await _make_deal(customer, stranger, "i2" * 32, "o2" * 32, price=2000)

            worker.relay = _StockRelayView(worker.relay)
            mine = await worker.get_agreements()
            assert [a.price for a in mine] == [1000], \
                "a foreign deal was returned or the addressed deal was missed"
            assert mine[0].agent_b == worker.pubkey


async def test_worker_finds_task_addressed_to_it_on_stock_relay():
    """A worker must discover the task assigned to it."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as customer, Agent([relay.url]) as worker, \
                Agent([relay.url]) as stranger:
            agreement_id = await _make_deal(customer, worker, "i" * 64, "o" * 64)
            other_id = await _make_deal(customer, stranger, "i2" * 32, "o2" * 32)
            await customer.send_task(agreement_id, "build a landing page", deadline=0,
                                     executor=worker.pubkey)
            await customer.send_task(other_id, "another worker's task", deadline=0,
                                     executor=stranger.pubkey)

            worker.relay = _StockRelayView(worker.relay)
            tasks = await worker.get_tasks()
            assert [t.description for t in tasks] == ["build a landing page"]
            assert tasks[0].agreement_id == agreement_id


async def test_task_updates_reach_customer_on_stock_relay():
    """Reverse path: the customer must discover status and result events."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as customer, Agent([relay.url]) as worker:
            agreement_id = await _make_deal(customer, worker, "i" * 64, "o" * 64)
            task_id = await customer.send_task(agreement_id, "work", deadline=0,
                                               executor=worker.pubkey)
            await worker.update_task_status(task_id, agreement_id, "completed", 100)
            await worker.submit_task_result(task_id, agreement_id, "done")

            customer.relay = _StockRelayView(customer.relay)
            statuses = await customer.get_task_statuses(agreement_id, task_id)
            results = await customer.get_task_results(agreement_id, task_id)
            assert [s.status for s in statuses] == ["completed"]
            assert len(results) == 1


async def test_send_task_refuses_executor_that_is_not_a_key():
    """The worker key is the address used to discover a task.

    Accepting an arbitrary value would publish an unreachable task and report
    success. The refusal must state the reason instead of leaking from deep inside
    cryptographic code.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as customer:
            with pytest.raises(ValueError, match="executor must be"):
                await customer.send_task("a" * 64, "work", deadline=0,
                                         executor="John Smith")
            with pytest.raises(ValueError, match="executor must be"):
                # Uppercase is valid hex but not the canonical key representation.
                await customer.send_task("a" * 64, "work", deadline=0,
                                         executor="A" * 64)


class _NoReplaceRelayView:
    """Relay that returns every version instead of applying NIP-33 replacement.

    This is not limited to malicious relays. Replacement is a server duty, but
    events may predate the policy, arrive from another relay during synchronization,
    or be stored by an implementation that lacks support. Readers must select a
    version themselves rather than relying on somebody else's correctness.
    """

    def __init__(self, inner):
        self.inner = inner

    async def query(self, filters):
        return await self.inner.query(filters)

    def __getattr__(self, name):
        return getattr(self.inner, name)


async def test_connection_requests_collapse_to_one_per_sender():
    """One sender yields one request even when the network stores several versions.

    A connection request uses `d`=recipient, so the sender-to-us pair has exactly one
    semantic version. Returning all versions makes the owner's agent process the same
    person twice, creating two notifications and two replies. Show the latest version
    because the sender may revise their introduction.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender, Agent([relay.url]) as me:
            await sender.request_connection(me.pubkey, "first introduction")
            await asyncio.sleep(1.1)          # created_at has one-second granularity
            await sender.request_connection(me.pubkey, "revised introduction")

            raw = await me.relay.query({"kinds": [types.KIND_CONNECTION_REQUEST],
                                        "#p": [me.pubkey]})
            assert len(raw) == 2, "both versions must remain on the relay"

            got = await me.get_connection_requests()
            assert len(got) == 1, [r["intro"] for r in got]
            assert got[0]["intro"] == "revised introduction"


async def test_connection_requests_tie_break_is_deterministic():
    """At equal timestamps, the smaller ID wins under the NIP-01 tie-break rule.

    One second is coarse enough for two versions to collide. Without an explicit
    rule, whichever version a relay returned first would be shown, so the owner
    could see different results across relays and refreshes.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as sender, Agent([relay.url]) as me:
            stamp = int(time.time())
            made = {}
            for intro in ("version A", "version B"):
                cr = types.ConnectionRequest(to_pubkey=me.pubkey, intro=intro)
                ev = cr.to_event()
                ev.created_at = stamp
                ev.tags = [t for t in ev.tags if t[0] != "d"] + [["d", me.pubkey]]
                ev.sign(sender.keys)
                await sender.relay.publish(ev)
                made[ev.id] = intro

            got = await me.get_connection_requests()
            assert len(got) == 1
            assert got[0]["intro"] == made[min(made)], "the smaller ID was not selected"
