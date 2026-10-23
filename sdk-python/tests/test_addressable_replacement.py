"""Finding 118: same-second addressable-event corrections silently failed.

Under NIP-33, equal `created_at` values make the relay retain the copy with the
SMALLER `id`, not the last one received. Reissuing the same coordinate within one
second, such as removing profile text, correcting an attestation, or withdrawing a
connection introduction, therefore did nothing roughly half the time. The relay
answered OK, the author believed the correction succeeded, and readers saw the old
version. Silence is the defect: publication appears successful.

Reproduced on staging on 2026-09-05 (a4a-9c): review text remained after reissuance;
replacement succeeded when `created_at` was moved one minute later.
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from a4a import Agent, AgentProfile, Keys, types                # noqa: E402
from a4a.event import Event                                     # noqa: E402
from tests.fake_relay import FakeRelay                           # noqa: E402


def _nip33_winner(events: list[dict]) -> dict:
    """Return the NIP-33 winner: newest timestamp, then smaller ID on a tie.

    Reproduce the rule literally instead of importing our code so this test compares
    behavior with the SPECIFICATION rather than with itself.
    """
    return sorted(events, key=lambda e: (-e["created_at"], e["id"]))[0]


async def test_two_profiles_in_the_same_second_the_second_one_wins():
    """Run twelve rounds deliberately.

    At equal timestamps the smaller random ID wins, so one run passes broken code
    about half the time. Such a test is worse than none because it creates false
    confidence. Twelve rounds with fresh keys leave randomness a one-in-four-thousand
    chance of hiding the defect.
    """
    for _ in range(12):
        async with FakeRelay() as relay:
            async with Agent([relay.url], Keys()) as agent:
                agent.delegation_id = "d" * 64
                await agent.publish_profile(AgentProfile(
                    capabilities=["web"], category="development",
                    content="built a website for a medical clinic"))
                # Remove project details immediately, within the same second.
                await agent.publish_profile(AgentProfile(
                    capabilities=["web"], category="development", content=""))
            profiles = [e for e in relay.events if e["kind"] == types.KIND_AGENT_PROFILE]
        assert len(profiles) == 2
        assert _nip33_winner(profiles)["content"] == "", \
            "old profile remained on the network; correction silently failed"


async def test_created_at_strictly_increases_for_the_same_coordinate():
    keys = Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys) as agent:
            agent.delegation_id = "d" * 64
            for i in range(5):
                await agent.publish_profile(AgentProfile(
                    capabilities=["web"], category="development", content=str(i)))
        stamps = [e["created_at"] for e in relay.events
                  if e["kind"] == types.KIND_AGENT_PROFILE]
    assert stamps == sorted(set(stamps)) and len(stamps) == 5, \
        f"timestamps repeat or move backwards: {stamps}"


async def test_different_coordinates_do_not_push_each_other_forward():
    """Bumping applies ONLY within one coordinate or timestamps drift into the future.

    Relays reject future-dated events, so a frequently publishing agent would block
    itself within minutes.
    """
    keys = Keys()
    now = int(time.time())
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys) as agent:
            agent.delegation_id = "d" * 64
            for i in range(20):
                await agent.publish_trust(f"{i:064x}", weight=0.5)
        stamps = [e["created_at"] for e in relay.events
                  if e["kind"] == types.KIND_TRUST_ASSERTION]
    assert max(stamps) <= now + 1, f"timestamp drifted {max(stamps) - now}s into the future"


async def test_unique_d_events_are_untouched():
    """Intents and offers use unique `d` values, so they are not replacements."""
    keys = Keys()
    now = int(time.time())
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys) as agent:
            agent.delegation_id = "d" * 64
            for i in range(3):
                await agent.publish_intent(types.Intent(
                    intent_type="service_request", category="development",
                    need="landing_page", budget_min=0, budget_max=1,
                    deadline=now + 86400))
        stamps = [e["created_at"] for e in relay.events if e["kind"] == types.KIND_INTENT]
    assert all(s <= now + 1 for s in stamps), stamps


async def test_bump_is_a_no_op_for_non_addressable_kinds():
    """Ordinary non-3xxxx events are outside the rule entirely."""
    keys = Keys()
    agent = Agent(["ws://127.0.0.1:1/never"], keys)
    ev = Event(kind=1, tags=[["d", "something"]], content="")
    before = ev.created_at
    agent._bump_created_at(ev)
    agent._bump_created_at(ev)
    assert ev.created_at == before
