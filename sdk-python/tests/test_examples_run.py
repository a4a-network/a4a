"""Every example in `sdk-python/examples/` must run to completion.

Why. The examples are part of the public slice and onboarding references them: §5
calls `two-agents-deal.py` the source of truth. Yet nobody ran them for months, and
`private-summary-delivery.py` was completely broken. It searched the relay for an
addressed message (kind 31033), while private messages have defaulted to gift-wrap
since 2026-08-29, so no 31033 event existed and step three raised `StopIteration`.
An outsider-style onboarding walkthrough found this on 2026-09-05; tests missed it
because example coverage did not exist.

Examples are product surface, not repository decoration. A broken example is worse
than no example because it undermines confidence in everything else.

Run them against `FakeRelay`, without Docker, in the normal suite on every change.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.fake_relay import FakeRelay                          # noqa: E402

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _load(name: str):
    """Import an example as a module without invoking its `__main__` entry point."""
    path = EXAMPLES / name
    spec = importlib.util.spec_from_file_location(f"example_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", ["two-agents-deal.py", "private-summary-delivery.py"])
async def test_example_runs_to_the_end(name, capsys):
    module = _load(name)
    async with FakeRelay() as relay:
        module.RELAY = relay.url
        await module.main()
    out = capsys.readouterr().out
    assert "✅" in out, f"{name} did not complete: {out[-300:]}"


async def test_deal_example_leaves_nothing_behind(capsys):
    """The deal demo must clean up after itself.

    Its keys are disposable while the owner's mandate is protected from expiry
    deletion. Without cleanup, every run would leave an agent nobody could remove.
    This is minor on a local relay, but the address changes in one line.
    """
    module = _load("two-agents-deal.py")
    async with FakeRelay() as relay:
        module.RELAY = relay.url
        await module.main()
        left = [e for e in relay.events if e["kind"] != 5]
        deletions = [e for e in relay.events if e["kind"] == 5]
    assert deletions, "the demo performed no cleanup"
    assert left == [], f"the demo left {len(left)} events on the relay"


async def test_deal_example_keeps_events_when_asked(monkeypatch, capsys):
    """`--keep` preserves events so the relay can display the demo."""
    module = _load("two-agents-deal.py")
    monkeypatch.setattr(module.sys, "argv", ["two-agents-deal.py", "--keep"])
    async with FakeRelay() as relay:
        module.RELAY = relay.url
        await module.main()
        left = [e for e in relay.events if e["kind"] != 5]
    assert left, "events must remain when --keep is supplied"


# --- pilot_counterpart: cleanup after rehearsal ----------------------------------------
#
# Unlike the demo, this agent is long-lived and must NOT clean up on every exit; its
# purpose is a stable address and reputation. But rehearsal is not production work,
# so its traces need not remain. Verify cleanup, target batching, and refusal without
# a key file (without those keys, the mandate can no longer be removed).

def _pilot():
    return _load("pilot_counterpart.py")


async def test_pilot_cleanup_removes_everything_both_keys_published():
    from a4a import Agent, Keys, types
    from a4a.event import Event

    module = _pilot()
    owner, agent_keys = Keys(), Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], agent_keys) as agent:
            from a4a.delegation import create_delegation
            deleg = create_delegation(owner, agent_keys.pubkey_hex, "rehearsal", 2 ** 31)
            await agent.relay.publish(deleg)
            agent.delegation_id = deleg.id
            await agent.relay.publish(Event(
                kind=types.KIND_INTENT, tags=[["d", "x"]], content="").sign(agent_keys))

            removed = await module.cleanup_identity(agent.relay, [agent_keys, owner])
            left = [e for e in await agent.relay.query(
                {"authors": [agent_keys.pubkey_hex, owner.pubkey_hex]}) if e.kind != 5]
    assert removed == 2, f"removed {removed}"
    assert left == [], "mandate or intent survived cleanup"


async def test_pilot_cleanup_splits_targets_into_batches():
    """A relay may silently truncate long tag lists and leave a hidden tail."""
    from a4a import Agent, Keys, types
    from a4a.event import Event

    module = _pilot()
    keys = Keys()
    count = module.CLEANUP_BATCH + 3
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys) as agent:
            for i in range(count):
                await agent.relay.publish(Event(
                    kind=types.KIND_INTENT, tags=[["d", str(i)]], content="").sign(keys))
            removed = await module.cleanup_identity(agent.relay, [keys])
            deletions = [e for e in relay.events if e["kind"] == 5]
    assert removed == count
    assert len(deletions) == 2, "cleanup targets were not split into batches"
    assert all(len([t for t in d["tags"] if t[0] == "e"]) <= module.CLEANUP_BATCH
               for d in deletions)


async def test_pilot_refuses_cleanup_without_identity(monkeypatch, capsys):
    module = _pilot()
    monkeypatch.setattr(module.sys, "argv",
                        ["pilot_counterpart.py", "ws://127.0.0.1:1/never", "--cleanup"])
    assert await module.main() == 2
    assert "--identity" in capsys.readouterr().err


async def test_pilot_cleanup_reads_past_one_page():
    """A long-lived agent exceeds one result page, so cleanup must fetch the tail.

    This is the same class as `live_cleanup`: one query looks exhaustive until event
    count exceeds a page, while the report confidently states how many were removed.
    A reviewer found it while testing arbitrary-length lists.
    """
    import time

    from a4a import Agent, Keys, types
    from a4a.event import Event

    module = _pilot()
    keys = Keys()
    total = 500 + 11                                   # counterpart page size is 500
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys) as agent:
            base = int(time.time()) - total
            for i in range(total):
                ev = Event(kind=types.KIND_INTENT, tags=[["d", str(i)]], content="")
                ev.created_at = base + i // 3          # groups of three per second
                ev.sign(keys)
                await agent.relay.publish(ev)
            page = await agent.relay.query({"authors": [keys.pubkey_hex], "limit": 500})
            assert len(page) == 500, "fake relay did not truncate results; test is vacuous"
            removed = await module.cleanup_identity(agent.relay, [keys])
            left = [e for e in await agent.relay.query(
                {"authors": [keys.pubkey_hex], "limit": 5000}) if e.kind != 5]
    assert removed == total, f"removed {removed} of {total}"
    assert left == [], f"{len(left)} events remain"
