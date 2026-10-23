"""Live verification of findings 54 and 55, testing both positive and negative paths.

Finding 54: a delegation without a `d` tag passed validation and became irrevocable
because revocation lookup uses the `d` coordinate. Rule 8 must reject its use.

Finding 55: kinds 31033 (private message) and 31034 (acknowledgement) were absent from
`required_for_kinds`, so any key could publish them without a mandate.

Both directions are deliberate. "Bad input rejected" without "good input accepted" is
only half the truth, and it remains green on a relay that rejects EVERYTHING.

    python scripts/live-delegation-gate-check.py wss://eu1.a4a.network

Events receive a short lifetime to minimize relay residue.
"""
import asyncio
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "sdk-python"))

from a4a import types                       # noqa: E402
from a4a.delegation import create_delegation  # noqa: E402
from a4a.event import Event                 # noqa: E402
from a4a.keys import Keys                   # noqa: E402
from a4a.relay import RelayClient, RelayError  # noqa: E402
from live_cleanup import sweep                 # noqa: E402
from node_banner import node_line              # noqa: E402

# The relay address is REQUIRED. A localhost/production default caused a false alarm after
# the 2026-09-04 release because the script silently queried the wrong node.
def _relay_from_argv() -> str:
    if len(sys.argv) < 2 or not sys.argv[1].startswith(("ws://", "wss://")):
        sys.exit(f"usage: python {sys.argv[0]} ws://host:port|wss://host; relay address "
                 "is required and intentionally has no default")
    return sys.argv[1]

URL = _relay_from_argv()

# The report must name its node. Without this line, "verified" is indistinguishable from
# "verified elsewhere," which happened twice on 2026-09-04 and 2026-09-05.
print(node_line(URL))
TTL = 3600


def _expiring(ev: Event) -> Event:
    """Set lifetime by REPLACING the existing tag, never by appending another.

    Before 2026-09-04 this used `append`. SDK models already added a 30-day `expiration`,
    so events carried two tags and the relay chose the FIRST: thirty days. The script
    believed it left one-hour residue while actually leaving probes for a month. An agent
    reviewing only wire data noticed the duplicate. The relay now selects the nearest
    expiration, but this script must still send one tag because other relays may choose
    differently.
    """
    ev.tags = [t for t in ev.tags if t[0] != "expiration"]
    ev.tags.append(["expiration", str(int(time.time()) + TTL)])
    return ev


async def publish(relay: RelayClient, ev: Event) -> str | None:
    """Return rejection text, or None when the event is accepted."""
    try:
        await relay.publish(ev)
        return None
    except RelayError as e:
        return str(e)[:90]


async def main() -> int:
    owner, agent = Keys(), Keys()
    results: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str) -> None:
        # Print detail ONLY on failure. Fallback text describes failure ("ACCEPTED - hole
        # open" or "rejected - everything broken") and previously appeared beside YES,
        # directly contradicting successful results (observed live on 2026-09-05).
        results.append((label, ok, detail if not ok else ""))

    async with RelayClient(URL) as relay:
        expiration = int(time.time()) + TTL

        # --- Finding 54 ---
        # Delegation WITHOUT `d`. Kind 31000 itself requires no mandate, so it is stored.
        bad_deleg = Event(kind=types.KIND_DELEGATION, content="probe without d", tags=[
            ["delegate", agent.pubkey_hex],
            ["owner", owner.pubkey_hex],
            ["expiration", str(expiration)],
        ]).sign(owner)
        err = await publish(relay, bad_deleg)
        check("delegation without `d` stored (expected: 31000 needs no mandate)",
              err is None, err or "accepted")

        # An agent event authorized by it must NOT be accepted.
        ev = _expiring(types.Intent(
            intent_type="service_request", category="design", need="probe 54",
            budget_min=0, budget_max=1, deadline=expiration,
        ).to_event(bad_deleg.id))
        ev.sign(agent)
        err = await publish(relay, ev)
        check("FINDING 54: event under delegation without `d` is REJECTED",
              err is not None, err or "ACCEPTED - vulnerability remains")

        # Positive path: a valid delegation must work.
        good_deleg = _expiring(create_delegation(
            owner, agent.pubkey_hex, "probe", expiration))
        good_deleg.sign(owner)
        err = await publish(relay, good_deleg)
        check("valid delegation accepted", err is None, err or "accepted")

        ev = _expiring(types.Intent(
            intent_type="service_request", category="design", need="probe 54b",
            budget_min=0, budget_max=1, deadline=expiration,
        ).to_event(good_deleg.id))
        ev.sign(agent)
        err = await publish(relay, ev)
        check("CONTROL: event under VALID delegation accepted",
              err is None, err or "rejected - everything is broken")

        # --- Finding 55 ---
        for kind, name in ((types.KIND_PRIVATE_MESSAGE, "31033 private message"),
                           (types.KIND_ACK_RECEIPT, "31034 acknowledgement")):
            ev = _expiring(Event(kind=kind, content="probe 55", tags=[
                ["p", owner.pubkey_hex], ["d", "probe-%d" % kind],
            ])).sign(agent)
            err = await publish(relay, ev)
            check("FINDING 55: %s rejected WITHOUT mandate" % name,
                  err is not None, err or "ACCEPTED - vulnerability remains")

            ev = _expiring(Event(kind=kind, content="probe 55", tags=[
                ["p", owner.pubkey_hex], ["d", "probe-ok-%d" % kind],
                ["delegation", good_deleg.id],
            ])).sign(agent)
            err = await publish(relay, ev)
            check("CONTROL: %s accepted WITH mandate" % name,
                  err is None, err or "rejected")

    # Remove test residue. Mandates and revocations do not expire from relay history
    # (the 2026-09-05 audit found 92 disposable test mandates in production).
    await sweep(URL, [owner, agent])

    width = max(len(r[0]) for r in results)
    failed = 0
    for label, ok, detail in results:
        if not ok:
            failed += 1
        print("%-*s  %s  %s" % (width, label, "YES" if ok else "NO ", detail))
    print()
    print("failed: %d of %d" % (failed, len(results)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
