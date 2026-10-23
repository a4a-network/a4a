"""Check the project agent against a REAL relay (design acceptance section 6).

Why this is separate from tests: every automated test uses `FakeRelay`, an in-memory
mapping that does not verify signatures, implement addressable-event semantics, or run
the production relay code. "Tests are green" and "works with the relay" are distinct
claims.

Run with an active relay; the local fork is the default:

    A4A_RELAY_URL=ws://localhost:8080 \\
        agent-service/.venv/Scripts/python.exe agent-service/live_check.py

The result is written to a file and printed. Every step is either OK or FAIL with
evidence. Nothing is published to the public network: the relay address is explicit
and defaults to local.
"""
import asyncio
import os
import sys
import tempfile
from pathlib import Path

RELAY = os.environ.get("A4A_RELAY_URL", "ws://localhost:8080")
REPORT = Path(os.environ.get("A4A_LIVE_REPORT", "live-check-report.txt"))

# Keep the check identity in a temporary directory so production keys remain untouched.
_TMP_HOME = tempfile.mkdtemp(prefix="a4a-live-check-")
os.environ["A4A_AGENT_HOME"] = _TMP_HOME

from a4a.agent import Agent                       # noqa: E402
from a4a.relay import FanOutRelayClient           # noqa: E402
from a4a_agent import identity                    # noqa: E402
from a4a_agent.config import Config               # noqa: E402
from a4a_agent.policy import Policy               # noqa: E402
from a4a_agent.publish import publish_presence    # noqa: E402
from a4a_agent.service import ProjectAgent        # noqa: E402

_lines: list[str] = []
_failed = 0


def _check_agent(relays, keys=None):
    # The default relay spaces excess subscriptions six seconds apart. Keep the
    # acceptance deadline bounded but above that interval; SDK defaults stay intact.
    agent = Agent(relays, keys)
    agent.relay = FanOutRelayClient(relays, timeout=10.0)
    agent.relay.read_deadline = 10.0
    return agent


def check(ok: bool, title: str, detail: str = "") -> None:
    global _failed
    if not ok:
        _failed += 1
    _lines.append(f"{'OK   ' if ok else 'FAIL '} {title}" + (f" — {detail}" if detail else ""))



async def _with_mandate(agent):
    """Give a test agent the owner mandate required for A4A event kinds.

    This makes the check MORE REALISTIC rather than harder: a real spammer can issue a
    mandate for the cost of one event. The flood scenario therefore proves the stronger
    statement that possessing a mandate does not itself grant access.
    """
    from a4a.keys import Keys
    await agent.ensure_registered(Keys(), name="check agent")
    return agent


async def main() -> int:
    notifications: list[str] = []
    keys = identity.load_or_create_identity()
    _lines.append(f"relay: {RELAY}")
    _lines.append(f"project agent address: {keys.apub}")

    async with _check_agent([RELAY], keys=keys) as project:
        # Owner mandate: without it, agent events carry no chain to the owner and a
        # delegation-enforcing relay rejects them. Reuse one found on the relay and
        # issue a new mandate only when absent or near expiration.
        await project.ensure_registered(identity.load_or_create_owner_identity(),
                                        name="A4A project agent")

        # 1. Presence: profile and relay list are visible on the network.
        ids = await publish_presence(project, (RELAY,))
        async with _check_agent([RELAY]) as observer:
            profiles = await observer.relay.query(
                {"kinds": [31001], "authors": [project.pubkey]})
            resolved = await observer.resolve_relays(project.pubkey)
        check(bool(ids["profile_id"]) and bool(profiles), "agent profile is visible",
              f"31001 events: {len(profiles)}")
        check(RELAY in resolved, "another agent resolves the relay list", str(resolved))

        cfg = Config(policy=Policy(), max_replies_per_sender=3)
        svc = ProjectAgent(project, cfg, lambda text: (notifications.append(text), True)[1])

        # 2. A common question from another key receives a scripted reply.
        async with _check_agent([RELAY]) as asker:
            await _with_mandate(asker)
            await asker.send_private_message(project.pubkey, "what is A4A?")
            await asyncio.sleep(0.3)
            report = await svc.process_messages()
            await asyncio.sleep(0.3)
            replies = await asker.read_private_messages()
            answered = [m for m in replies if "protocol" in m["content"].lower()]
        check(report["answered"] == 1, "common question received a scripted reply", str(report))
        check(bool(answered), "reply reached the sender through the relay",
              f"messages received: {len(replies)}")

        # 3. A stranger's request is archived without waking the owner.
        before = len(notifications)
        async with _check_agent([RELAY]) as stranger:
            await _with_mandate(stranger)
            await stranger.request_connection(project.pubkey, "buying links cheaply")
            await asyncio.sleep(0.3)
            report = await svc.process_connection_requests()
        check(report["archived"] >= 1 and report["escalated"] == 0,
              "stranger request was archived", str(report))
        check(len(notifications) == before, "stranger did not disturb the owner",
              f"notifications: {len(notifications) - before}")

        # 4. A repeated cycle does not process the same event again.
        again = await svc.process_connection_requests()
        check(again["archived"] == 0 and again["escalated"] == 0,
              "repeated cycle does not reprocess old events", str(again))

        # 5. Flood: 20 different keys produce zero notifications.
        flood_keys = [_check_agent([RELAY]) for _ in range(20)]
        for a in flood_keys:
            await a.__aenter__()
            await _with_mandate(a)
        try:
            for i, a in enumerate(flood_keys):
                await a.request_connection(project.pubkey, f"spam {i}")
            await asyncio.sleep(0.5)
            before = len(notifications)
            report = await svc.process_connection_requests()
        finally:
            for a in flood_keys:
                await a.__aexit__(None, None, None)
        check(report["archived"] == 20 and len(notifications) == before,
              "a flood of 20 requests did not reach the owner", str(report))

        # 6. A policy-approved request produces a notification with verifiable facts.
        async with _check_agent([RELAY]) as issuer, _check_agent([RELAY]) as good:
            await _with_mandate(issuer)
            await _with_mandate(good)
            await issuer.attest_identity(good.pubkey, level="account:telegram")
            await good.request_connection(project.pubkey, "we want to discuss integration")
            await asyncio.sleep(0.3)
            trusted_cfg = Config(policy=Policy(trusted_issuers=(issuer.pubkey,)))
            svc2 = ProjectAgent(project, trusted_cfg,
                                lambda t: (notifications.append(t), True)[1],
                                processed=svc.processed)
            report = await svc2.process_connection_requests()
        check(report["escalated"] == 1, "attested request was escalated", str(report))
        last = notifications[-1] if notifications else ""
        check("verified by issuer" in last, "notification includes a verifiable fact")
        check("UNTRUSTED DATA" in last, "peer text is framed as untrusted")

    return _failed


if __name__ == "__main__":
    try:
        failed = asyncio.run(asyncio.wait_for(main(), timeout=420.0))
    finally:
        # The temporary directory contains the check agent's private key and must not
        # remain on disk after the run (review A21, 2026-08-28).
        import shutil
        shutil.rmtree(_TMP_HOME, ignore_errors=True)
    _lines.append("")
    _lines.append("RESULT: all checks passed" if not failed else f"RESULT: {failed} failures")
    REPORT.write_text("\n".join(_lines), encoding="utf-8")
    print(f"report: {REPORT.resolve()}")
    sys.exit(1 if failed else 0)
