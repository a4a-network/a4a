"""Historical authority: verifiable facts must not imply an unproven ordering.

Timestamps are synthetic (`tests/ots_builder.py`) and headers come from
`StaticHeaders`. These tests verify real signatures and OTS paths against a local
relay double, not Bitcoin.
"""
import base64
import time

import pytest

from a4a import Agent, Keys, types
from a4a import timestamp as ts
from a4a.delegation import create_delegation, create_revocation, validate_delegation
from a4a.event import Event
from tests.fake_relay import FakeRelay
from tests.ots_builder import build_ots, display_root

NOW = int(time.time())
T_EVENT = NOW - 3600            # time of the block containing the event
H_EVENT = 1000


class World:
    """Owner, agent, delegation, timestamped event, and block headers."""

    def __init__(self):
        self.owner, self.agent, self.notary = Keys(), Keys(), Keys()
        self.deleg = create_delegation(self.owner, self.agent.pubkey_hex, "bot",
                                       NOW + 86400, created_at=T_EVENT - 600)
        self.event = Event(kind=types.KIND_AGREEMENT, tags=[["delegation", self.deleg.id]]).sign(self.agent)
        self.blocks: dict[int, tuple[str, int]] = {}
        self.stamp = self.make_stamp(self.event.id, H_EVENT, T_EVENT)

    def make_stamp(self, event_id: str, height: int, block_time: int, pending: bool = False,
                   sibling: str | None = None) -> Event:
        """`sibling` is the adjacent leaf ID; both events share ONE tree and block."""
        if pending:
            ots, _ = build_ots(bytes.fromhex(event_id), pending_uri="https://cal.example")
        elif sibling is not None:
            ots, root = build_ots(bytes.fromhex(event_id), height=height,
                                  salt=bytes.fromhex(sibling), prepend=True)
            assert self.blocks[height][0] == display_root(root), \
                "sibling leaf must produce the same root"
        else:
            ots, root = build_ots(bytes.fromhex(event_id), height=height)
            self.blocks[height] = (display_root(root), block_time)
        return Event(kind=1040, tags=[["e", event_id, "wss://relay"], ["k", "31004"]],
                     content=base64.b64encode(ots).decode()).sign(self.notary)

    @property
    def headers(self):
        return ts.StaticHeaders(self.blocks)


@pytest.fixture
def world(monkeypatch):
    w = World()

    async def keys(self):
        return w.notary.pubkey_hex, {}
    monkeypatch.setattr(Agent, "_notary_keys", keys)   # FakeRelay has no NIP-11
    return w


async def _publish(relay, *events):
    async with Agent([relay.url]) as pub:
        for ev in events:
            await pub.relay.publish(ev)


async def test_missing_revocation_does_not_prove_historical_authority(world):
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, world.stamp)
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.authority_at(world.event, world.headers)
    assert verdict["state"] == "indeterminate" and verdict["at"] == T_EVENT
    assert verdict["evidence_version"] == 1
    assert verdict["stamp"].block_height == H_EVENT
    assert verdict["evidence"]["delegation_chain_valid"] is True
    assert verdict["evidence"]["revocations_checked"] is True
    assert verdict["evidence"]["revocations"] == []
    assert verdict["evidence"]["history_complete"] is False


async def test_earlier_revocation_anchor_does_not_prove_revocation_before_event(world):
    rev = create_revocation(world.owner, world.deleg)
    rev_stamp = world.make_stamp(rev.id, H_EVENT - 10, T_EVENT - 7200)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, world.stamp, rev, rev_stamp)
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.authority_at(world.event, world.headers)
    assert verdict["state"] == "indeterminate"
    assert verdict["revocation_stamp"].block_height == H_EVENT - 10
    assert verdict["evidence"]["revocations"][0]["id"] == rev.id


async def test_later_revocation_anchor_does_not_prove_authority(world):
    rev = create_revocation(world.owner, world.deleg)
    rev_stamp = world.make_stamp(rev.id, H_EVENT + 10, T_EVENT + 7200)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, world.stamp, rev, rev_stamp)
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.authority_at(world.event, world.headers)
    assert verdict["state"] == "indeterminate"
    assert verdict["revocation_stamp"].block_height == H_EVENT + 10


async def test_revocation_in_the_same_block_is_indeterminate(world):
    rev = create_revocation(world.owner, world.deleg)
    # One tree: event is the left leaf (append rev.id), revocation is the right leaf
    # (prepend event.id).
    world.stamp = world.make_stamp(world.event.id, H_EVENT, T_EVENT)
    world.blocks[H_EVENT] = (display_root(__import__("hashlib").sha256(
        bytes.fromhex(world.event.id) + bytes.fromhex(rev.id)).digest()), T_EVENT)
    ots, _ = build_ots(bytes.fromhex(world.event.id), height=H_EVENT, salt=bytes.fromhex(rev.id))
    world.stamp = Event(kind=1040, tags=[["e", world.event.id], ["k", "31004"]],
                        content=base64.b64encode(ots).decode()).sign(world.notary)
    rev_stamp = world.make_stamp(rev.id, H_EVENT, T_EVENT, sibling=world.event.id)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, world.stamp, rev, rev_stamp)
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.authority_at(world.event, world.headers)
    assert verdict["state"] == "indeterminate"
    assert verdict["revocation_stamp"].block_height == H_EVENT


async def test_unstamped_revocation_is_indeterminate_not_revoked(world):
    """Branch F3(b): "unknown", not "revoked"."""
    rev = create_revocation(world.owner, world.deleg)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, world.stamp, rev)
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.authority_at(world.event, world.headers)
    assert verdict["state"] == "indeterminate"
    assert verdict["evidence"]["revocations"][0]["stamp"].state == "absent"


async def test_no_stamp_is_unverifiable_and_names_non_notarised_kinds(world):
    intent = Event(kind=types.KIND_INTENT, tags=[["delegation", world.deleg.id]]).sign(world.agent)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, intent)
        async with Agent([relay.url], Keys()) as reader:
            history = await reader.authority_at(world.event, world.headers)
            public = await reader.authority_at(intent, world.headers)
    assert history["state"] == "unverifiable" and "no timestamp" in history["detail"]
    assert public["state"] == "unverifiable" and "not notarised" in public["detail"]


async def test_pending_stamp_is_unverifiable_with_the_calendar_named(world):
    pending = world.make_stamp(world.event.id, 0, 0, pending=True)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, pending)
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.authority_at(world.event, world.headers)
    assert verdict["state"] == "unverifiable" and "cal.example" in verdict["detail"]


async def test_missing_delegation_is_unverifiable_not_unauthorized(world):
    async with FakeRelay() as relay:
        await _publish(relay, world.event, world.stamp)        # delegation absent from relay
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.authority_at(world.event, world.headers)
    assert verdict["state"] == "unverifiable" and "mandate not found" in verdict["detail"]
    assert verdict["evidence"]["delegation_chain_valid"] is None
    assert verdict["evidence"]["revocations_checked"] is False


async def test_self_declared_delegation_date_is_not_a_historical_verdict(world):
    late = create_delegation(world.owner, world.agent.pubkey_hex, "bot", NOW + 86400,
                             created_at=T_EVENT + 1)
    event = Event(kind=types.KIND_AGREEMENT, tags=[["delegation", late.id]]).sign(world.agent)
    stamp = world.make_stamp(event.id, H_EVENT + 1, T_EVENT)
    async with FakeRelay() as relay:
        await _publish(relay, late, event, stamp)
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.authority_at(event, world.headers)
    assert verdict["state"] == "indeterminate"
    assert verdict["evidence"]["delegation_created_at"] == T_EVENT + 1
    assert verdict["evidence"]["delegation_chain_valid"] is True


async def test_get_stamp_prefers_the_earliest_confirmed_of_several(world):
    later = world.make_stamp(world.event.id, H_EVENT + 50, T_EVENT + 50_000)
    async with FakeRelay() as relay:
        await _publish(relay, world.stamp, later)
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.get_stamp(world.event.id, world.headers)
    assert verdict.confirmed and verdict.block_height == H_EVENT


def test_validate_delegation_at_uses_t_not_the_wall_clock(world):
    expired_now = create_delegation(world.owner, world.agent.pubkey_hex, "bot",
                                    NOW - 100, created_at=NOW - 10_000)
    event = Event(kind=types.KIND_AGREEMENT, tags=[["delegation", expired_now.id]]).sign(world.agent)
    assert not validate_delegation(event, expired_now)
    assert validate_delegation(event, expired_now, at=NOW - 5_000), "still valid at T"
    assert not validate_delegation(event, expired_now, at=NOW - 20_000), "not yet issued at T"


# --- replaced-delegation archive (0.3.13, branch F4) -------------------------------

async def test_reissued_delegation_is_recovered_from_the_archive(world, monkeypatch):
    """The archive restores the signature chain but proves no historical authority."""
    v2 = create_delegation(world.owner, world.agent.pubkey_hex, "bot", NOW + 86400,
                           created_at=T_EVENT - 500)
    asked: list[str] = []

    async def archive(self, delegation_id):
        asked.append(delegation_id)
        return world.deleg if delegation_id == world.deleg.id else None
    monkeypatch.setattr(Agent, "_fetch_delegation_history", archive)
    async with FakeRelay() as relay:
        await _publish(relay, v2, world.event, world.stamp)        # v1 absent from relay
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.authority_at(world.event, world.headers)
    assert asked == [world.deleg.id], "archive must be queried exactly once for v1 ID"
    assert verdict["state"] == "indeterminate" and verdict["at"] == T_EVENT
    assert verdict["evidence"]["delegation_chain_valid"] is True


async def test_archive_answers_are_checked_like_any_event(world, monkeypatch):
    """The archive is untrusted: wrong kind, wrong ID, or bad signature is rejected."""
    forged = Event(**{**world.deleg.model_dump(), "content": "tampered"})  # signature mismatch
    cases = {
        "wrong kind": Event(kind=types.KIND_INTENT, tags=world.deleg.tags).sign(world.owner),
        "tampered": forged,
        "404": None,
    }
    for label, answer in cases.items():
        async def archive(self, delegation_id, _a=answer):
            return _a
        monkeypatch.setattr(Agent, "_fetch_rest_event",
                            lambda self, path, eid, _a=answer: _archive_like(path, eid, _a))
        async with FakeRelay() as relay:
            await _publish(relay, world.event, world.stamp)
            async with Agent([relay.url], Keys()) as reader:
                verdict = await reader.authority_at(world.event, world.headers)
        assert verdict["state"] == "unverifiable" and "archive" in verdict["detail"], label


async def _archive_like(path, event_id, answer):
    """REST double: empty `/v1/event`; delegation-history returns validated `answer`.

    Apply the same parsing, signature, and ID checks as a real response.
    """
    if not path.startswith("/v1/delegation-history/") or answer is None:
        return None
    from a4a.relay import RelayClient
    ev = RelayClient._parse_event(answer.model_dump())
    return ev if ev is not None and ev.id == event_id else None


async def test_delegation_expired_before_the_stamp_is_indeterminate_not_unauthorized(world):
    """A timestamp is an upper bound, not proof of signing time.

    A one-hour mandate timestamped three hours later may still contain an honest
    event and cannot be called unauthorized. Reproduced on a local notary on
    2026-09-04.
    """
    short = create_delegation(world.owner, world.agent.pubkey_hex, "bot", T_EVENT - 100,
                              created_at=T_EVENT - 3700)
    event = Event(kind=types.KIND_AGREEMENT, tags=[["delegation", short.id]]).sign(world.agent)
    stamp = world.make_stamp(event.id, H_EVENT + 3, T_EVENT)
    async with FakeRelay() as relay:
        await _publish(relay, event, stamp)
        async with Agent([relay.url], Keys()) as reader:
            reader._fetch_event_rest = _returning(short)       # expired mandate only via REST
            verdict = await reader.authority_at(event, world.headers)
    assert verdict["state"] == "indeterminate"
    assert verdict["evidence"]["delegation_expiration"] == T_EVENT - 100
    assert "longer than the delay" not in verdict["detail"]


@pytest.mark.parametrize("offset", [-7200, 7200])
async def test_changing_only_anchor_schedule_never_establishes_event_order(world, offset):
    """Both events may predate both anchors; anchor schedule does not order them."""
    rev = create_revocation(world.owner, world.deleg)
    stamp = world.make_stamp(rev.id, H_EVENT + (1 if offset > 0 else -1), T_EVENT + offset)
    assert ts.verify_stamp(stamp, rev.id, world.headers).confirmed
    assert ts.verify_stamp(world.stamp, world.event.id, world.headers).confirmed
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, world.stamp, rev, stamp)
        async with Agent([relay.url]) as reader:
            verdict = await reader.authority_at(world.event, world.headers)
    assert verdict["state"] == "indeterminate"
    assert verdict["evidence"]["event_order_proven"] is False
    assert verdict["evidence"]["signature_time_proven"] is False


async def test_invalid_signature_is_unauthorized_without_network_lookup(world, monkeypatch):
    forged = world.event.model_copy(update={"content": "changed after signing"})

    async def unexpected(*args, **kwargs):
        pytest.fail("invalid signature must be rejected before any network lookup")

    reader = Agent(["ws://127.0.0.1:1"])
    monkeypatch.setattr(reader, "get_stamp", unexpected)
    verdict = await reader.authority_at(forged, world.headers)
    assert verdict["state"] == "unauthorized"
    assert verdict["evidence"]["event_signature_valid"] is False


async def test_wrong_delegate_is_structurally_unauthorized(world):
    event = Event(kind=types.KIND_AGREEMENT,
                  tags=[["delegation", world.deleg.id]]).sign(Keys())
    stamp = world.make_stamp(event.id, H_EVENT + 1, T_EVENT)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, event, stamp)
        async with Agent([relay.url]) as reader:
            verdict = await reader.authority_at(event, world.headers)
    assert verdict["state"] == "unauthorized"
    assert verdict["evidence"]["event_signature_valid"] is True
    assert verdict["evidence"]["delegation_chain_valid"] is False


async def test_all_observed_revocations_are_reported_without_early_verdict(world):
    rev_a = create_revocation(world.owner, world.deleg, reason="a")
    rev_b = create_revocation(world.owner, world.deleg, reason="b")
    confirmed = world.make_stamp(rev_b.id, H_EVENT - 1, T_EVENT - 10)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, world.stamp, rev_a, rev_b, confirmed)
        async with Agent([relay.url]) as reader:
            verdict = await reader.authority_at(world.event, world.headers)
    assert verdict["state"] == "indeterminate"
    observations = verdict["evidence"]["revocations"]
    assert {r["id"] for r in observations} == {rev_a.id, rev_b.id}
    assert {r["stamp"].state for r in observations} == {"absent", "confirmed"}
    assert verdict["evidence"]["history_complete"] is False


async def test_stamp_of_unsigned_event_id_cannot_prove_signature_time(world):
    from a4a import crypto

    unsigned = Event(kind=types.KIND_AGREEMENT, pubkey=world.agent.pubkey_hex,
                     tags=[["delegation", world.deleg.id]])
    event_id = crypto.compute_event_id(unsigned.pubkey, unsigned.created_at,
                                       unsigned.kind, unsigned.tags, unsigned.content)
    stamp = world.make_stamp(event_id, H_EVENT + 1, T_EVENT)
    assert not unsigned.sig
    assert ts.verify_stamp(stamp, event_id, world.headers).confirmed
    signed = unsigned.sign(world.agent)
    assert signed.id == event_id and signed.verify()
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, signed, stamp)
        async with Agent([relay.url]) as reader:
            verdict = await reader.authority_at(signed, world.headers)
    assert verdict["state"] == "indeterminate"
    assert verdict["evidence"]["event_signature_valid"] is True
    assert verdict["evidence"]["signature_time_proven"] is False


def _returning(ev):
    async def fetch(event_id):
        return ev if ev.id == event_id else None
    return fetch


# --- NIP-11 notary keys: rotation and foreign authors --------------------------------

def _keys(current: str | None, retired: dict[str, int] | None = None):
    async def fetch(self):
        return current, dict(retired or {})
    return fetch


async def test_stamps_from_unlisted_authors_are_ignored_even_if_valid(world, monkeypatch):
    """Kind 1040 from an arbitrary key is not a trusted timestamp.

    Even with a genuine proof, an outsider could timestamp a revocation in a fresh
    block and make it appear "later than the event".
    """
    monkeypatch.setattr(Agent, "_notary_keys", _keys("ee" * 32))
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, world.stamp)  # random stamp author
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.get_stamp(world.event.id, world.headers)
    assert verdict.state == "absent"


async def test_relay_without_notary_yields_absent_with_reason(world, monkeypatch):
    monkeypatch.setattr(Agent, "_notary_keys", _keys(None))
    async with FakeRelay() as relay:
        await _publish(relay, world.stamp)
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.get_stamp(world.event.id, world.headers)
    assert verdict.state == "absent" and "declares no notary" in verdict.detail


async def test_unreadable_notary_declaration_is_not_reported_as_absent(world, monkeypatch):
    from a4a.agent import NotaryDiscoveryError

    async def unavailable(_self):
        raise NotaryDiscoveryError("synthetic NIP-11 failure")

    monkeypatch.setattr(Agent, "_notary_keys", unavailable)
    async with FakeRelay() as relay:
        await _publish(relay, world.stamp)
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.get_stamp(world.event.id, world.headers)
    assert verdict.state == "unverifiable"
    assert "could not inspect the NIP-11" in verdict.detail
    assert "cannot be concluded" in verdict.detail


async def test_notary_discovery_preserves_transport_failure_as_third_state(monkeypatch):
    from a4a.agent import NotaryDiscoveryError
    import a4a.agent as agent_module

    async def unavailable(_callable):
        raise OSError("synthetic NIP-11 transport failure")

    monkeypatch.setattr(agent_module.asyncio, "to_thread", unavailable)
    reader = Agent(["ws://127.0.0.1:1"], Keys())
    with pytest.raises(NotaryDiscoveryError, match="could not be inspected"):
        await reader._notary_keys()


async def test_retired_key_is_accepted_only_up_to_until(world, monkeypatch):
    old_notary = Keys()
    stamp = world.make_stamp(world.event.id, H_EVENT, T_EVENT)
    stamp = Event(kind=stamp.kind, tags=stamp.tags, content=stamp.content).sign(old_notary)
    async with FakeRelay() as relay:
        await _publish(relay, stamp)
        async with Agent([relay.url], Keys()) as reader:
            monkeypatch.setattr(Agent, "_notary_keys",
                                _keys("ee" * 32, {old_notary.pubkey_hex: T_EVENT}))
            ok = await reader.get_stamp(world.event.id, world.headers)          # T == until
            monkeypatch.setattr(Agent, "_notary_keys",
                                _keys("ee" * 32, {old_notary.pubkey_hex: T_EVENT - 1}))
            late = await reader.get_stamp(world.event.id, world.headers)        # T > until
    assert ok.confirmed and ok.block_time == T_EVENT
    assert late.state == "unverifiable" and "after retirement" in late.detail
    assert late.block_height == H_EVENT, "verdict retains the genuine block"


async def test_current_key_stamp_wins_over_a_late_retired_one(world, monkeypatch):
    old_notary, new_notary = Keys(), Keys()
    late = world.make_stamp(world.event.id, H_EVENT + 5, T_EVENT + 5000)
    late = Event(kind=late.kind, tags=late.tags, content=late.content).sign(old_notary)
    good = Event(kind=world.stamp.kind, tags=world.stamp.tags,
                 content=world.stamp.content).sign(new_notary)
    monkeypatch.setattr(Agent, "_notary_keys",
                        _keys(new_notary.pubkey_hex, {old_notary.pubkey_hex: T_EVENT}))
    async with FakeRelay() as relay:
        await _publish(relay, late, good)
        async with Agent([relay.url], Keys()) as reader:
            verdict = await reader.get_stamp(world.event.id, world.headers)
    assert verdict.confirmed and verdict.block_height == H_EVENT
