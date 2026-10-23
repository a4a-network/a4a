"""Task flows lacked a validating reader (internal audit, 2026-08-29).

The SDK could PUBLISH TaskRequest, TaskStatus, and TaskResult but provided no way to
read them. An integrator therefore wrote `{"kinds":[31032], "#task_id":[...]}` directly
and accepted a "result" from anyone: the relay returned every matching event without
checking who could publish a result for the agreement. The natural "take the first
result" implementation handed control to a stranger.
"""
import time

import pytest

from a4a import crypto, types
from a4a.event import Event
from a4a.agent import Agent
from a4a.keys import Keys
from tests.fake_relay import FakeRelay


async def _signed_agreement(a: Agent, b: Agent) -> str:
    """Create a mutually signed agreement and return its event ID."""
    digest = types.agreement_digest("i" * 64, "o" * 64, 100, "USD", 0, a.pubkey, b.pubkey)
    ag = types.Agreement(intent_id="i" * 64, offer_id="o" * 64, price=100,
                         currency="USD", deadline=0, agent_a=a.pubkey, agent_b=b.pubkey,
                         sig_a=crypto.sign(digest, a.keys.privkey_hex),
                         sig_b=crypto.sign(digest, b.keys.privkey_hex))
    ev = ag.to_event()
    ev.sign(a.keys)
    await a.relay.publish(ev)
    return ev.id


async def test_result_from_a_stranger_is_not_returned():
    """Reject a stranger's result for somebody else's agreement."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b, \
                Agent([relay.url]) as stranger:
            agreement_id = await _signed_agreement(a, b)
            task_id = await a.send_task(agreement_id, "prepare a report",
                                        int(time.time()) + 3600, executor=b.pubkey)
            await stranger.submit_task_result(task_id, agreement_id,
                                              "https://evil.example/payload")
            results = await a.get_task_results(agreement_id, task_id)
            assert results == [], "a stranger's result was returned as authentic"


async def test_result_from_the_counterparty_is_returned():
    """Positive control: the reader must return a legitimate counterparty result."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            agreement_id = await _signed_agreement(a, b)
            task_id = await a.send_task(agreement_id, "prepare a report",
                                        int(time.time()) + 3600, executor=b.pubkey)
            await b.submit_task_result(task_id, agreement_id, "https://ok.example/r")
            results = await a.get_task_results(agreement_id, task_id)
            assert len(results) == 1
            assert results[0].result_url == "https://ok.example/r"


async def test_result_without_a_mutually_signed_agreement_is_not_returned():
    """An agreement without both signatures grants neither party authority."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            fake = types.Agreement(intent_id="i" * 64, offer_id="o" * 64, price=100,
                                   currency="USD", deadline=0,
                                   agent_a=a.pubkey, agent_b=b.pubkey,
                                   sig_a="00" * 64, sig_b="00" * 64)
            ev = fake.to_event()
            ev.sign(a.keys)
            await a.relay.publish(ev)
            await b.submit_task_result("t1", ev.id, "https://ok.example/r")
            assert await a.get_task_results(ev.id, "t1") == []


async def test_status_reader_applies_the_same_rule():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b, \
                Agent([relay.url]) as stranger:
            agreement_id = await _signed_agreement(a, b)
            await b.update_task_status("t1", agreement_id, "in_progress", 50)
            await stranger.update_task_status("t1", agreement_id, "completed", 100)
            statuses = await a.get_task_statuses(agreement_id, "t1")
            assert [s.status for s in statuses] == ["in_progress"]


@pytest.mark.parametrize("model,reader", [
    (types.TaskStatus, "get_task_statuses"),
    (types.TaskResult, "get_task_results"),
])
async def test_task_reader_rejects_signed_wrong_kind_from_agreement_party(model, reader):
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            agreement_id = await _signed_agreement(a, b)
            fields = {"task_id": "t1", "agreement_id": agreement_id}
            fields.update({"status": "in_progress", "progress": 50}
                          if model is types.TaskStatus else {"result_url": "https://ok.example/r"})
            valid = model(**fields).to_event().sign(b.keys)
            wrong_kind = Event(kind=1, tags=valid.tags, content="wrong kind").sign(b.keys)

            async def untrusted_query(_filters):
                return [wrong_kind, valid]

            a._query_tolerant = untrusted_query
            results = await getattr(a, reader)(agreement_id, "t1")
            assert [item.source.id for item in results] == [valid.id]


@pytest.mark.parametrize("field,value", [("progress", "999"), ("status", "invented")])
async def test_invalid_signed_status_does_not_hide_valid_statuses(field, value):
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            agreement_id = await _signed_agreement(a, b)
            valid = types.TaskStatus(task_id="t1", agreement_id=agreement_id,
                                     status="in_progress", progress=50).to_event().sign(b.keys)
            tags = [[tag[0], value] if tag[0] == field else list(tag) for tag in valid.tags]
            invalid = Event(kind=types.KIND_TASK_STATUS, tags=tags).sign(b.keys)

            async def untrusted_query(_filters):
                return [invalid, valid]

            a._query_tolerant = untrusted_query
            statuses = await a.get_task_statuses(agreement_id, "t1")
            assert [item.source.id for item in statuses] == [valid.id]


def test_all_three_task_kinds_name_the_task_the_same_way():
    """All task event kinds must identify the task with the same tag.

    TaskRequest used `task_id` while TaskStatus and TaskResult used `task`. Each class
    round-tripped independently, but one filter could not collect the whole task flow,
    and the protocol registry documented no distinction. Different names for the same
    meaning cause implementations to diverge.
    """
    req = types.TaskRequest(agreement_id="a" * 64, task_id="t1",
                            description="d", deadline=0).to_event()
    st = types.TaskStatus(task_id="t1", agreement_id="a" * 64,
                          status="in_progress", progress=1).to_event()
    res = types.TaskResult(task_id="t1", agreement_id="a" * 64,
                           result_url="https://e.example/r").to_event()
    for ev, name in ((req, "TaskRequest"), (st, "TaskStatus"), (res, "TaskResult")):
        assert ev.tag_value("task_id") == "t1", f"{name} omits the task_id tag"


def test_legacy_task_tag_is_still_understood():
    """Events published before tag unification must remain readable."""
    legacy = Event(kind=types.KIND_TASK_RESULT,
                         tags=[["task", "t1"], ["agreement", "a" * 64],
                               ["result_url", "https://e.example/r"]])
    assert types.TaskResult.from_event(legacy).task_id == "t1"
