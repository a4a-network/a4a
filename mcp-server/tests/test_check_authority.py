"""Test model-facing `a4a_check_authority` facts and historical inference limits.

Calls go through `call_tool` against FakeRelay with synthetic `ots_builder` stamps and
`StaticHeaders`.
"""
import base64
import json
import time

import pytest
from a4a import Agent, Keys, types
from a4a import timestamp as ts
from a4a.delegation import create_delegation, create_revocation
from a4a.event import Event

from a4a_mcp import identity, server
from fake_relay import FakeRelay
from ots_builder import build_ots, display_root
from tool_call import call_text

NOW = int(time.time())
T_EVENT, H_EVENT = NOW - 3600, 1000


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")


@pytest.mark.parametrize("configured", [None, "http://127.0.0.1:3002"])
def test_header_source_is_independent_of_local_relay(mcp_home, monkeypatch, configured):
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:8080")
    if configured is None:
        monkeypatch.delenv("A4A_HEADERS_URL", raising=False)
    else:
        monkeypatch.setenv("A4A_HEADERS_URL", configured)
    requested = []

    def get(self, url):
        requested.append(url)
        return "a" * 64 if "/block-height/" in url else json.dumps({"merkle_root": "b" * 64, "timestamp": 123})

    monkeypatch.setattr(ts.EsploraHeaders, "_http_get", get)
    headers = server._headers()
    assert headers.block(1000) == ("b" * 64, 123)
    base = configured or "https://blockstream.info/api"
    assert requested == [f"{base}/block-height/1000", f"{base}/block/" + "a" * 64]
    assert headers.block(1000) == ("b" * 64, 123)
    assert len(requested) == 2, "the cache did not serve the repeated read"


class World:
    def __init__(self):
        self.owner, self.agent, self.notary = Keys(), Keys(), Keys()
        self.deleg = create_delegation(self.owner, self.agent.pubkey_hex, "\u0431\u043E\u0442", NOW + 86400,
                                       created_at=T_EVENT - 600)
        self.event = Event(kind=types.KIND_REVIEW,
                           tags=[["delegation", self.deleg.id], ["p", "c" * 64], ["rating", "5"],
                                 ["agreement", "a" * 64]]).sign(self.agent)
        self.blocks: dict[int, tuple[str, int]] = {}
        self.stamp = self.make_stamp(self.event.id, H_EVENT, T_EVENT)

    def make_stamp(self, event_id, height, block_time, pending=False):
        if pending:
            ots, _ = build_ots(bytes.fromhex(event_id), pending_uri="https://cal.example")
        else:
            ots, root = build_ots(bytes.fromhex(event_id), height=height)
            self.blocks[height] = (display_root(root), block_time)
        return Event(kind=1040, tags=[["e", event_id], ["k", "31005"]],
                     content=base64.b64encode(ots).decode()).sign(self.notary)


@pytest.fixture
def world(monkeypatch):
    w = World()
    monkeypatch.setattr(server, "_headers", lambda: ts.StaticHeaders(w.blocks))

    async def keys(self):
        return w.notary.pubkey_hex, {}
    monkeypatch.setattr(Agent, "_notary_keys", keys)   # FakeRelay does not implement NIP-11.
    return w


async def _publish(relay, *events):
    async with Agent([relay.url]) as pub:
        for ev in events:
            await pub.relay.publish(ev)


async def _check(relay, monkeypatch, event_id):
    monkeypatch.setenv("A4A_RELAY", relay.url)
    return await call_text(server.mcp, "a4a_check_authority", {"event_id": event_id})


async def test_confirmed_stamp_does_not_tell_model_to_trust_historical_authority(mcp_home, monkeypatch, world):
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, world.stamp)
        out = await _check(relay, monkeypatch, world.event.id)
    assert out.startswith("INDETERMINATE") and f"T = {T_EVENT}" in out and f"block {H_EVENT}" in out
    assert "may rely" not in out
    assert "does not prove" in out and "history completeness" in out


async def test_revocation_evidence_never_becomes_a_publication_order_claim(mcp_home, monkeypatch, world):
    rev = create_revocation(world.owner, world.deleg)
    early = world.make_stamp(rev.id, H_EVENT - 10, T_EVENT - 7200)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, world.stamp, rev, early)
        out = await _check(relay, monkeypatch, world.event.id)
    assert out.startswith("INDETERMINATE") and f"block {H_EVENT - 10}" in out
    assert "REVOKED BEFORE PUBLICATION" not in out
    async with FakeRelay() as relay:                      # The same review without a stamp.
        await _publish(relay, world.deleg, world.event, world.stamp, rev)
        out = await _check(relay, monkeypatch, world.event.id)
    assert out.startswith("INDETERMINATE") and "wait for a timestamp" not in out
    assert "will not recover order" in out


async def test_unverifiable_states_name_the_reason_and_the_next_step(mcp_home, monkeypatch, world):
    intent = Event(kind=types.KIND_INTENT, tags=[["delegation", world.deleg.id]]).sign(world.agent)
    pending = world.make_stamp(world.event.id, 0, 0, pending=True)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, intent)
        no_stamp = await _check(relay, monkeypatch, world.event.id)
        not_notarised = await _check(relay, monkeypatch, intent.id)
        await _publish(relay, pending)
        waiting = await _check(relay, monkeypatch, world.event.id)
    assert no_stamp.startswith("UNVERIFIABLE") and "still be in transit" in no_stamp
    assert "does not timestamp" in not_notarised and "31005" in not_notarised
    assert "retry in 1–3 hours" in waiting


async def test_headers_unavailable_points_at_a4a_headers_url(mcp_home, monkeypatch, world):
    def broken(url):
        raise OSError("dns down")
    monkeypatch.setattr(server, "_headers", lambda: ts.EsploraHeaders(_opener=broken))
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, world.stamp)
        out = await _check(relay, monkeypatch, world.event.id)
    assert out.startswith("UNVERIFIABLE") and "A4A_HEADERS_URL" in out and "dns down" in out


async def test_owner_signed_kinds_are_not_called_unauthorised(mcp_home, monkeypatch, world):
    stamp = world.make_stamp(world.deleg.id, H_EVENT + 1, T_EVENT + 1)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, stamp)
        out = await _check(relay, monkeypatch, world.deleg.id)
    assert "signed directly by the owner" in out and "UNAUTHORIZED" not in out
    assert f"block {H_EVENT + 1}" in out


async def test_missing_event_and_bad_id_are_messages(mcp_home, monkeypatch, world):
    async with FakeRelay() as relay:
        out = await _check(relay, monkeypatch, "f" * 64)
        bad = await _check(relay, monkeypatch, "\u043D\u0435 id")
    assert "was not found" in out and "64 lowercase hexadecimal" in bad


async def test_output_carries_no_event_text_and_no_keys(mcp_home, monkeypatch, world):
    world.event = Event(kind=types.KIND_REVIEW, content="\u0421\u0415\u041A\u0420\u0415\u0422\u041D\u042B\u0419 \u0422\u0415\u041A\u0421\u0422 \u041E\u0422\u0417\u042B\u0412\u0410",
                        tags=[["delegation", world.deleg.id]]).sign(world.agent)
    stamp = world.make_stamp(world.event.id, H_EVENT + 2, T_EVENT)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, world.event, stamp)
        out = await _check(relay, monkeypatch, world.event.id)
    assert "\u0421\u0415\u041A\u0420\u0415\u0422\u041D\u042B\u0419" not in out and world.agent.privkey_hex not in out


async def test_fresh_event_without_stamp_is_told_the_stamp_is_on_its_way(mcp_home, monkeypatch, world):
    """Distinguish a fresh pending stamp from a stale event with no notary coverage."""
    fresh = Event(kind=types.KIND_REVIEW, tags=[["delegation", world.deleg.id]]).sign(world.agent)
    stale = Event(kind=types.KIND_REVIEW, tags=[["delegation", world.deleg.id]],
                  created_at=NOW - 4 * 3600).sign(world.agent)
    async with FakeRelay() as relay:
        await _publish(relay, world.deleg, fresh, stale)
        out_fresh = await _check(relay, monkeypatch, fresh.id)
        out_stale = await _check(relay, monkeypatch, stale.id)
    assert "still be in transit" in out_fresh and "under three hours old" in out_fresh
    assert "still be in transit" not in out_stale and "one or two hours" in out_stale


@pytest.mark.parametrize("state,evidence_version", [
    (state, None) for state in ("authorized_at", "revoked_before", "unauthorized",
                               "indeterminate", "unverifiable", "unknown-future-state")
] + [("indeterminate", 0), ("indeterminate", 2), ("unknown-future-state", 1)])
async def test_old_sdk_verdict_cannot_reintroduce_historical_permission(
        mcp_home, monkeypatch, world, state, evidence_version):
    async def old_verdict(self, event, headers):
        result = {"state": state, "at": T_EVENT,
                  "stamp": ts.StampVerdict("confirmed", block_height=H_EVENT, block_time=T_EVENT),
                  "revocation_stamp": None, "detail": "OLD_UNSAFE_AUTHORITY_CLAIM"}
        if evidence_version is not None:
            result["evidence_version"] = evidence_version
        return result

    monkeypatch.setattr(Agent, "authority_at", old_verdict)
    async with FakeRelay() as relay:
        await _publish(relay, world.event)
        out = await _check(relay, monkeypatch, world.event.id)
    assert out.startswith("UNVERIFIABLE")
    assert "update the SDK" in out
    assert "OLD_UNSAFE_AUTHORITY_CLAIM" not in out
