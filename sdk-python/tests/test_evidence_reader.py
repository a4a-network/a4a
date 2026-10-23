"""Bounded reader tests. All real transports are explicitly loopback-only."""
import asyncio
import json
import time

import network_guard
import pytest

from a4a import Agent, Keys, crypto, evidence_reader, types
from a4a.event import Event
from a4a.relay import QueryResult, RelayError
from tests.fake_relay import FakeRelay


@pytest.fixture(autouse=True)
def loopback_only():
    """This file used to contain a third independent network boundary.

    It checked only that an address was loopback and only for synchronous sockets.
    This was insufficient twice over: async connections bypassed it entirely, and a
    loopback address does not mean it belongs to this test; anything may listen on
    127.0.0.1.

    One `network_guard` now covers the whole run. This fixture remains so an escape
    fails THIS test rather than only the final suite result.
    """
    mark = len(network_guard.unexpected())
    yield
    new = network_guard.unexpected()[mark:]
    assert not new, f"test accessed addresses it did not create: {sorted(set(new))}"


def agreement(a, b, now):
    ag = types.Agreement(intent_id="a" * 64, offer_id="b" * 64, price=0,
        deadline=now + 60, agent_a=a.pubkey_hex, agent_b=b.pubkey_hex, sig_a="", sig_b="")
    digest = ag.digest()
    ag.sig_a, ag.sig_b = crypto.sign(digest, a.privkey_hex), crypto.sign(digest, b.privkey_hex)
    ev = ag.to_event()
    ev.created_at = now - 20
    return ev.sign(a)


def review(author, target, ag, now, index=0):
    ev = types.Review(agreement_id=ag.id, target=target, rating=5,
                     content="PRIVATE TEXT MUST NOT REACH THE MODEL").to_event()
    ev.created_at = now - index
    return ev.sign(author)


def _matching_event_and_filter():
    author, target = Keys(), Keys()
    ev = Event(kind=types.KIND_REVIEW, created_at=100,
               tags=[["p", target.pubkey_hex]], content="safe").sign(author)
    flt = {"kinds": [types.KIND_REVIEW], "authors": [author.pubkey_hex],
           "ids": [ev.id], "since": 99, "until": 101,
           "#p": [target.pubkey_hex]}
    assert evidence_reader._matches(ev, flt, now=101)
    return ev, flt


def test_validate_options_rejects_noncanonical_subject_directly():
    with pytest.raises(ValueError, match="canonical public key"):
        evidence_reader.validate_options("not-a-key", 30, 200, 5, ())


def test_matcher_rejects_event_with_invalid_signature():
    ev, flt = _matching_event_and_filter()
    ev.sig = "0" * 128
    assert not evidence_reader._matches(ev, flt, now=101)


def test_matcher_rejects_wrong_kind():
    ev, flt = _matching_event_and_filter()
    flt["kinds"] = [types.KIND_AGREEMENT]
    assert not evidence_reader._matches(ev, flt, now=101)


def test_matcher_rejects_wrong_author():
    ev, flt = _matching_event_and_filter()
    flt["authors"] = [Keys().pubkey_hex]
    assert not evidence_reader._matches(ev, flt, now=101)


def test_matcher_rejects_wrong_event_id():
    ev, flt = _matching_event_and_filter()
    flt["ids"] = ["f" * 64 if ev.id != "f" * 64 else "e" * 64]
    assert not evidence_reader._matches(ev, flt, now=101)


def test_matcher_rejects_event_outside_time_window():
    ev, flt = _matching_event_and_filter()
    flt["since"] = ev.created_at + 1
    assert not evidence_reader._matches(ev, flt, now=101)


def test_matcher_rejects_missing_required_tag_value():
    ev, flt = _matching_event_and_filter()
    flt["#p"] = [Keys().pubkey_hex]
    assert not evidence_reader._matches(ev, flt, now=101)


async def test_real_reader_reads_only_and_explains_scope():
    a, b = Keys(), Keys()
    now = int(time.time())
    ag = agreement(a, b, now)
    rev = review(b, a.pubkey_hex, ag, now - 1)
    async with FakeRelay() as relay:
        relay.events = [ev.model_dump() for ev in (ag, rev)]
        original = list(relay.events)
        async with Agent([relay.url], keys=Keys()) as observer:
            report = await observer.get_counterparty_evidence(a.pubkey_hex)
        assert relay.events == original
    assert report["reviews_received"]["eligible_reviews"] == 1
    assert report["coverage"]["network_completeness"] == "unknown"
    assert report["coverage"]["relay_scope"] == "configured_primary_relay_only"
    assert report["coverage"]["relays_configured"] == 1
    assert report["coverage"]["relays_responded_at_least"] == 1
    assert report["coverage"]["reviewers_queried"] == [b.pubkey_hex]
    assert report["identity"]["unique_people"] is None
    assert "PRIVATE TEXT" not in json.dumps(report)


async def test_missing_agreement_reference_is_reported():
    a, b = Keys(), Keys()
    now = int(time.time())
    ag = agreement(a, b, now)
    rev = review(b, a.pubkey_hex, ag, now - 1)
    async with FakeRelay() as relay:
        relay.events = [rev.model_dump()]
        async with Agent([relay.url], keys=Keys()) as observer:
            report = await observer.get_counterparty_evidence(a.pubkey_hex)
    assert report["coverage"]["unresolved_agreement_references"] == 1
    assert report["reviews_received"]["eligible_reviews"] == 0


async def test_local_limit_survives_a_relay_ignoring_limit(monkeypatch):
    a, b = Keys(), Keys()
    now = int(time.time())
    ag = agreement(a, b, now)
    calls = []
    events = [review(b, a.pubkey_hex, ag, now - 1, i) for i in range(20)]
    observer = Agent(["ws://127.0.0.1:1/never"], keys=Keys())
    async def query(flt, *, max_events):
        assert max_events == flt["limit"]
        calls.append(flt)
        return QueryResult(events, len(events), 0, True)
    monkeypatch.setattr(observer.relay, "query_bounded", query)
    report = await observer.get_counterparty_evidence(a.pubkey_hex, limit=3, reviewer_limit=0)
    assert report["coverage"]["possible_truncation"] is True
    assert all(item["accepted_events"] <= 3 for item in report["coverage"]["queries"])
    assert all(0 < c["limit"] <= 4 for c in calls)


async def test_reader_failure_does_not_return_clean_zero(monkeypatch):
    observer = Agent(["ws://127.0.0.1:1/never"], keys=Keys())
    async def query(flt, *, max_events):
        raise RelayError("test refused")
    monkeypatch.setattr(observer.relay, "query_bounded", query)
    with pytest.raises(RelayError, match="test refused"):
        await observer.get_counterparty_evidence(Keys().pubkey_hex)


async def test_reader_deadline_refuses_the_entire_report(monkeypatch):
    from a4a import evidence_reader
    observer = Agent(["ws://127.0.0.1:1/never"], keys=Keys())
    async def query(flt, **kwargs):
        await asyncio.sleep(60)
        return []
    monkeypatch.setattr(observer.relay, "query_bounded", query)
    monkeypatch.setattr(evidence_reader, "MAX_READ_SECONDS", 0.01)
    with pytest.raises(RelayError, match="budget exceeded"):
        await observer.get_counterparty_evidence(Keys().pubkey_hex)


async def test_reader_fetches_invalid_replacements_by_coordinate():
    subject, issuer = Keys(), Keys()
    now = int(time.time())
    old = types.IdentityAttestation(subject=subject.pubkey_hex, level="person:bank").to_event()
    old.created_at = now - 60
    old.sign(issuer)
    newer = old.model_copy(deep=True)
    newer.created_at = now - 1
    newer.tags = [tag for tag in newer.tags if tag[0] != "p"]
    newer.sign(issuer)
    async with FakeRelay() as relay:
        relay.events = [ev.model_dump() for ev in (old, newer)]
        async with Agent([relay.url], keys=Keys()) as observer:
            report = await observer.get_counterparty_evidence(subject.pubkey_hex)
    assert report["identity"]["direct_attestations"] == []


@pytest.mark.parametrize("kwargs", [{"window_days": 0}, {"limit": 0}, {"limit": 1001},
                                   {"reviewer_limit": 11}, {"window_days": True},
                                   {"trusted_issuers": ["invalid"]}])
async def test_bad_options_fail_before_query(monkeypatch, kwargs):
    observer = Agent(["ws://127.0.0.1:1/never"], keys=Keys())
    async def forbidden(flt, **kwargs):
        raise AssertionError("invalid options must not query")
    monkeypatch.setattr(observer.relay, "query_bounded", forbidden)
    with pytest.raises(ValueError):
        await observer.get_counterparty_evidence(Keys().pubkey_hex, **kwargs)


async def test_transport_enforces_per_query_cap_when_relay_ignores_limit():
    key = Keys()
    now = int(time.time())
    events = [Event(kind=1, created_at=now - i, content=str(i)).sign(key) for i in range(12)]
    async with FakeRelay(honour_limit=False) as relay:
        relay.events = [ev.model_dump() for ev in events]
        async with Agent([relay.url], keys=Keys()) as observer:
            result = await observer.relay.query({"kinds": [1], "limit": 4}, max_events=4)
    assert len(result) == 4


async def test_invalid_signatures_count_toward_transport_cap(monkeypatch):
    key = Keys()
    now = int(time.time())
    events = [Event(kind=1, created_at=now - i).sign(key).model_dump() for i in range(12)]
    for ev in events:
        ev["sig"] = "0" * 128
    async with FakeRelay(honour_limit=False) as relay:
        relay.events = events
        async with Agent([relay.url], keys=Keys()) as observer:
            parsed = []
            # Fan-out transport keeps parsing in the concrete per-relay client.
            underlying = observer.relay.clients[0]
            original = underlying._parse_event
            def parse(ev):
                parsed.append(ev)
                return original(ev)
            monkeypatch.setattr(underlying, "_parse_event", parse)
            result = await observer.relay.query({"kinds": [1], "limit": 3}, max_events=3)
    assert result == []
    assert len(parsed) == 3


@pytest.mark.parametrize("count,inspected,truncated", [(1, 1, False), (10, 3, True)])
async def test_invalid_transport_events_are_visible_in_coverage(count, inspected, truncated):
    subject, peer = Keys(), Keys()
    now = int(time.time())
    ag = agreement(subject, peer, now)
    events = [review(peer, subject.pubkey_hex, ag, now - 1, i).model_dump() for i in range(count)]
    for ev in events:
        ev["sig"] = "0" * 128
    async with FakeRelay(honour_limit=False) as relay:
        relay.events = events
        async with Agent([relay.url], keys=Keys()) as observer:
            report = await observer.get_counterparty_evidence(subject.pubkey_hex, limit=2, reviewer_limit=0)
    coverage = report["coverage"]["queries"][0]
    assert coverage["inspected_events"] == inspected
    assert coverage["discarded_invalid_or_out_of_scope"] == inspected
    assert coverage["possible_truncation"] is truncated
    assert coverage["accepted_events"] == 0


async def test_connection_queue_loss_cannot_look_like_complete_empty_sample(monkeypatch):
    observer = Agent(["ws://127.0.0.1:1/never"], keys=Keys())
    async def query(flt, **kwargs):
        return QueryResult([], 0, 0, False, connection_dropped_events=7)
    monkeypatch.setattr(observer.relay, "query_bounded", query)
    report = await observer.get_counterparty_evidence(Keys().pubkey_hex, reviewer_limit=0)
    assert report["coverage"]["possible_truncation"] is True
    assert all(q["connection_dropped_events"] == 7 for q in report["coverage"]["queries"])


@pytest.mark.parametrize("cap", [0, -1, True, 5001, 1.5])
async def test_transport_rejects_invalid_cap_before_network(cap):
    observer = Agent(["ws://127.0.0.1:1/never"], keys=Keys())
    with pytest.raises(ValueError, match="max_events"):
        await observer.relay.query({"kinds": [1]}, max_events=cap)


async def test_coverage_names_the_whole_relay_set_when_several_were_queried():
    """Coverage must count relays rather than repeat a constant string.

    Before fan-out transport, the report always said "primary relay only." The reader
    now queries every configured relay, so that old string understated coverage in the
    exact field consumers use to decide how much to trust the report.
    """
    subject = Keys().pubkey_hex
    async with FakeRelay() as first, FakeRelay() as second:
        async with Agent([first.url, second.url], keys=Keys()) as observer:
            report = await observer.get_counterparty_evidence(subject)
    assert report["coverage"]["relay_scope"] == "configured_relay_set"
    assert report["coverage"]["relays_configured"] == 2
    assert report["coverage"]["relays_responded_at_least"] == 2


async def test_coverage_counts_only_the_relays_that_actually_answered():
    """A configured relay that never answers does not contribute to coverage.

    The first fix counted CONFIGURED relays, repeating the same falsehood as the prior
    constant string: an unreachable relay contributes no evidence, yet the report
    credited it toward completeness. A reviewer caught this.
    """
    async with FakeRelay() as alive:
        async with Agent([alive.url, "ws://127.0.0.1:1/never"], keys=Keys()) as observer:
            report = await observer.get_counterparty_evidence(Keys().pubkey_hex)
    coverage = report["coverage"]
    assert coverage["relays_configured"] == 2, "exactly two relays are configured"
    assert coverage["relays_responded_at_least"] == 1, (
        "a silent relay counted toward coverage, overstating evidence completeness")
