"""Replacing a REPLACEABLE event in the same second used to fail silently.

External review finding HEAL-005. Tie protection existed only for ADDRESSABLE events
(30000-40000), but NIP-01 applies the same rule to REPLACEABLE events
(0, 3, 10000-20000): when `created_at` is equal, a relay keeps the copy with the
SMALLER `id`, not the latest publication.

Why this matters: an agent relay list is replaceable kind 10002. Network self-healing
depends on an agent publishing a new list when a relay dies. If a same-second update
loses to the old event roughly half the time, the replacement never propagates even
though the relay says "accepted" and keeps the old list. The silent failure is the bug.
"""
from a4a import Agent
from a4a.event import Event
from tests.fake_relay import FakeRelay


async def _bumped(agent, kind: int, tags: list[list[str]]) -> tuple[int, int]:
    """Publish one coordinate twice in one second and return both timestamps."""
    first = Event(kind=kind, tags=list(tags), content="first", created_at=100)
    second = Event(kind=kind, tags=list(tags), content="second", created_at=100)
    agent._bump_created_at(first)
    agent._bump_created_at(second)
    return first.created_at, second.created_at


async def test_relay_list_replacement_in_the_same_second_wins():
    """A replacement relay list (10002) must receive a timestamp one second later."""
    async with FakeRelay() as r:
        async with Agent([r.url]) as agent:
            times = await _bumped(agent, 10002, [])
    assert times == (100, 101), (
        f"two relay-list publications received timestamps {times}; at equal timestamps "
        "the smaller ID wins and silently prevents relay replacement")


async def test_addressable_event_still_bumped_positive_control():
    """POSITIVE control: preserve the existing addressable-event behavior."""
    async with FakeRelay() as r:
        async with Agent([r.url]) as agent:
            times = await _bumped(agent, 31002, [["d", "x"]])
    assert times == (100, 101)


async def test_ordinary_event_is_not_bumped_negative_control():
    """NEGATIVE control: ordinary events are not replaceable and need no time bump.

    Without this, "bump everything" is indistinguishable from "bump only when needed,"
    so the preceding test would pass with a known-invalid implementation.
    """
    async with FakeRelay() as r:
        async with Agent([r.url]) as agent:
            times = await _bumped(agent, 1, [])
    assert times == (100, 100), "ordinary event copies do not compete and need no bump"
