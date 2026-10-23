"""Live revocation-acceptance check for release 0.3.10, covering both directions.

Closed defects: a revocation dated before its delegation returned OK=true but never took
effect (68); the old format (`d` = delegation event ID) was accepted but inert (72); an
uppercase `d` was accepted but never found (72); the node parsed `expiration = "+N"` as a
number while the SDK did not (74); rejection omitted its reason (63).

Every rejection has a paired acceptance. "Bad input rejected" without "good input
accepted" is only half the truth and remains green on a relay that rejects everything.

    python scripts/live-revocation-check.py wss://eu1.a4a.network
"""
import asyncio
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "sdk-python"))

from a4a import types                       # noqa: E402
from a4a.delegation import (create_delegation, create_revocation,  # noqa: E402
                            validate_delegation)
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
    ev.tags = [t for t in ev.tags if t[0] != "expiration"]
    ev.tags.append(["expiration", str(int(time.time()) + TTL)])
    return ev


async def publish(relay: RelayClient, ev: Event) -> str | None:
    try:
        await relay.publish(ev)
        return None
    except RelayError as e:
        return str(e)[:110]


def intent(agent: Keys, deleg_id: str, label: str, expiration: int) -> Event:
    ev = _expiring(types.Intent(
        intent_type="service_request", category="design", need=label,
        budget_min=0, budget_max=1, deadline=expiration,
    ).to_event(deleg_id))
    return ev.sign(agent)


async def main() -> int:
    results: list[tuple[str, bool, str]] = []

    def check(label: str, ok: bool, detail: str) -> None:
        # Print detail ONLY on failure. Fallback text describes failure and previously
        # appeared beside YES, directly contradicting success (observed 2026-09-05).
        results.append((label, ok, detail if not ok else ""))

    async with RelayClient(URL) as relay:
        expiration = int(time.time()) + TTL

        # --- 68: revocation predates delegation -----------------------------------
        owner, agent = Keys(), Keys()
        deleg = _expiring(create_delegation(owner, agent.pubkey_hex, "probe 68", expiration))
        deleg.sign(owner)
        check("delegation accepted", await publish(relay, deleg) is None, "")
        skewed = create_revocation(owner, deleg)
        skewed.created_at = deleg.created_at - 90
        skewed.sign(owner)
        err = await publish(relay, skewed)
        check("68: revocation predating delegation REJECTED with reason",
              err is not None and "dated earlier" in err,
              err or "ACCEPTED - inert revocation confirmed")
        err = await publish(relay, intent(agent, deleg.id, "probe 68 before revocation", expiration))
        check("CONTROL: agent accepted before real revocation", err is None, err or "accepted")
        proper = create_revocation(owner, deleg)
        proper.sign(owner)
        check("CONTROL: valid revocation accepted", await publish(relay, proper) is None, "")
        err = await publish(relay, intent(agent, deleg.id, "probe 68 after", expiration))
        check("63: agent rejected after revocation with 'revoked' reason",
              err is not None and "revoked" in err, err or "ACCEPTED")

        # --- 72: legacy format and letter case ------------------------------------
        owner2, agent2 = Keys(), Keys()
        deleg2 = _expiring(create_delegation(owner2, agent2.pubkey_hex, "probe 72", expiration))
        deleg2.sign(owner2)
        check("delegation 2 accepted", await publish(relay, deleg2) is None, "")
        old_style = Event(kind=types.KIND_DELEGATION_REVOCATION, content="", tags=[
            ["d", deleg2.id], ["e", deleg2.id]]).sign(owner2)
        err = await publish(relay, old_style)
        check("72: legacy revocation (d = e = id) REJECTED",
              err is not None and "not the delegation event id" in err, err or "ACCEPTED")
        upper = Event(kind=types.KIND_DELEGATION_REVOCATION, content="", tags=[
            ["d", agent2.pubkey_hex.upper()]]).sign(owner2)
        err = await publish(relay, upper)
        check("75: revocation with uppercase d REJECTED with case reason",
              err is not None and "lowercase hex" in err, err or "ACCEPTED")
        err = await publish(relay, intent(agent2, deleg2.id, "probe 72 control", expiration))
        check("CONTROL: agent 2 accepted after inert revocations", err is None, err or "rejected")

        # --- 79: revocations never carry expiration -------------------------------
        # NEVER expire a revocation: it would disappear from queries after an hour and
        # make the delegation appear live again. Include it here only to test rejection.
        timed = create_revocation(owner2, deleg2)
        timed.tags.append(["expiration", str(expiration)])
        timed.sign(owner2)
        err = await publish(relay, timed)
        check("79: revocation with expiration tag REJECTED with reason",
              err is not None and "expiration" in err,
              err or "ACCEPTED - delegation will revive after one hour")

        # --- 74 and 126: noncanonical expiration ----------------------------------
        #
        # Before 0.3.20 the node STORED a delegation with "+N" but rejected only agent
        # events using it. Node/SDK consensus relied on storage accepting what readers did
        # not trust. That has a cost: an unparsed expiration enters the database as NO
        # expiration and is served forever. Finding 126 measured nine such production
        # mandates on 2026-09-05; only they would remain after valid ones expired.
        #
        # The node now rejects the event itself. Consensus becomes stronger because both
        # node and SDK refuse it; this check compares both verdicts on the same event.
        owner3, agent3 = Keys(), Keys()
        deleg3 = create_delegation(owner3, agent3.pubkey_hex, "probe 74", expiration)
        deleg3.tags = [t for t in deleg3.tags if t[0] != "expiration"]
        deleg3.tags.append(["expiration", "+%d" % expiration])
        deleg3.sign(owner3)
        err = await publish(relay, deleg3)
        check("126: delegation with expiration='+N' REJECTED on ingestion",
              err is not None and "expir" in err,
              err or "ACCEPTED - malformed notation disables expiration")

        # The SDK must reject the same object regardless of node behavior.
        probe = intent(agent3, deleg3.id, "probe 74", expiration)
        check("74: SDK rejects mandate with '+N' (consensus: both reject)",
              not validate_delegation(probe, deleg3), "SDK treated mandate as valid")

        # Positive path: canonical expiration must pass or "everything rejected" looks
        # indistinguishable from a working rule.
        deleg3ok = create_delegation(owner3, agent3.pubkey_hex, "probe 74 control", expiration)
        deleg3ok = _expiring(deleg3ok)
        deleg3ok.sign(owner3)
        check("CONTROL: delegation with canonical expiration accepted",
              await publish(relay, deleg3ok) is None, "")
        err = await publish(relay, intent(agent3, deleg3ok.id, "probe 74 control", expiration))
        check("CONTROL: agent event under it accepted", err is None, err or "rejected")

        # The general 0.3.20 rule is broader than delegations: reject noncanonical
        # expiration on every kind or any client can disable its own lifetime.
        for label, raw in (("'+N'", "+%d" % expiration), ("with leading zero", "0%d" % expiration),
                           ("nonnumeric", "yesterday")):
            ev = Event(kind=types.KIND_INTENT, tags=[
                ["d", "probe-126-%s" % raw[:4]], ["category", "development"],
                ["intent_type", "service_request"], ["delegation", deleg2.id],
                ["expiration", raw]]).sign(agent2)
            err = await publish(relay, ev)
            check("126: ordinary event with %s expiration REJECTED" % label,
                  err is not None and "expir" in err,
                  err or "ACCEPTED - event will live forever")

    # Remove test residue. Mandates and revocations do not expire from storage. On
    # 2026-09-05, wss://eu1.a4a.network stored 93 mandates and 26 revocations while REQ
    # exposed only 21 and 16; expired history was hidden but not deleted. Name the node
    # explicitly because an earlier unlabeled measurement cost half an hour to attribute.
    await sweep(URL, [owner, agent, owner2, agent2, owner3, agent3])

    width = max(len(r[0]) for r in results)
    failed = 0
    for label, ok, detail in results:
        failed += 0 if ok else 1
        print("%-*s  %s  %s" % (width, label, "YES" if ok else "NO ", detail))
    print()
    print("failed: %d of %d" % (failed, len(results)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
