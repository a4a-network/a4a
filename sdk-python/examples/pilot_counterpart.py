"""Counterparty agent: maintain a worker profile and complete incoming intents.

Why. A pilot, like any first integration, requires a live counterparty: another agent
publishes an intent and waits. This example is that counterparty. It is not a
single-process demo: it connects to a relay, waits for OTHER AGENTS' intents, and
completes the entire cycle using only information available on the network.

What it does, step by step (each action is logged):
  1. obtains an owner mandate (31000), issued once and preserved across restarts;
  2. publishes a discoverable worker profile (31001);
  3. waits for intents (31002) in its category, subscribing with polling fallback;
  4. answers a new intent with an offer (31003) priced within its budget;
  5. when the customer publishes a signed agreement (31004), validates its terms and
     countersigns it, concluding the deal;
  6. accepts a task (31030), reports status (31031), and after `--work-seconds`
     publishes a result (31032);
  7. waits for the customer's review (31005) and publishes its own.

There is no LLM and no randomness: decisions use numeric event fields, making every
run reproducible and auditable through its log.

Run (the relay address is mandatory; there is deliberately no default):

    python examples/pilot_counterpart.py ws://localhost:8083
    python examples/pilot_counterpart.py wss://eu1.a4a.network --category development \\
        --price 45000 --work-seconds 5 --once

`--once` handles one intent and exits (rehearsal mode); without it, the agent runs
until stopped. `--identity` stores keys so the agent address survives restarts.

**Cleanup after rehearsal.** Unlike a demo, this agent is long-lived and must NOT clean
up on every exit: its purpose is to keep a stable address and build reputation. A
rehearsal is not real work, however, so its traces need not remain on the network:

    python examples/pilot_counterpart.py ws://localhost:8083 --identity a.json --cleanup
    python examples/pilot_counterpart.py wss://eu1.a4a.network --identity a.json \\
        --once --cleanup-after

`--cleanup` deletes everything published by the agent and owner keys in `--identity`,
then exits. `--cleanup-after` does the same after a successful `--once` rehearsal.
Without `--identity`, the keys are disposable and cannot be used for later cleanup;
their kind-31000 mandate is protected from expiration-based deletion. Always use an
identity file and clean up after experiments on a production network.
"""
import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from a4a import Agent, AgentProfile, Keys, Offer, types  # noqa: E402
from a4a.event import Event                            # noqa: E402
from a4a.relay import RelayError                       # noqa: E402

STEP = {}


def log(step: str, text: str) -> None:
    """Log each step with the current time, step label, and observed fact."""
    STEP[step] = STEP.get(step, 0) + 1
    print(f"[{time.strftime('%H:%M:%S')}] {step:<22} {text}", flush=True)


def _keys(path: str | None) -> tuple[Keys, Keys]:
    """Load owner and agent keys, or create and persist a new pair.

    The agent address must survive restarts or reputation and connections are lost on
    every launch. The format matches the MCP server: the two keys are stored together.
    """
    if not path:
        return Keys(), Keys()
    p = Path(path)
    if p.exists():
        data = json.loads(p.read_text(encoding="utf-8"))
        return Keys(data["owner_privkey_hex"]), Keys(data["privkey_hex"])
    owner, agent = Keys(), Keys()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"owner_privkey_hex": owner.privkey_hex,
                             "privkey_hex": agent.privkey_hex,
                             "pubkey_hex": agent.pubkey_hex}, indent=2), encoding="utf-8")
    return owner, agent


#: Maximum targets in one deletion event. This matches `scripts/live_cleanup.py`:
#: relays may silently truncate long tag lists, leaving a hidden undeleted tail while
#: the report appears successful.
CLEANUP_BATCH = 64


async def cleanup_identity(relay, keys_list: list[Keys]) -> int:
    """Delete everything these keys published, batching targets into kind-5 events.

    An identity can delete only its own events, so each key signs its own deletion.
    Deletion events remain because nothing can remove them; this is the explicit cost
    of cleanup.
    """
    removed = 0
    for keys in keys_list:
        # Page through history because a node returns only the newest `limit` events.
        # One query would silently omit an older tail while still producing a confident
        # deletion count. The `until` boundary is inclusive, so do not subtract a
        # second; that would lose everything written in the same second. Instead stop
        # when the next page contains no NEW events, which also prevents an endless loop.
        mine, until = [], None
        seen: set[str] = set()
        while True:
            flt = {"authors": [keys.pubkey_hex], "limit": 500}
            if until is not None:
                flt["until"] = until
            page = await relay.query(flt)
            fresh = [e for e in page if e.id not in seen]
            mine.extend(fresh)
            seen.update(e.id for e in page)
            if len(page) < 500 or not fresh:
                break
            until = min(e.created_at for e in page)
        ids = [e.id for e in mine if e.kind != 5]
        for start in range(0, len(ids), CLEANUP_BATCH):
            batch = ids[start:start + CLEANUP_BATCH]
            deletion = Event(kind=5, tags=[["e", i] for i in batch],
                             content="cleanup after rehearsal")
            deletion.sign(keys)
            try:
                await relay.publish(deletion)
                removed += len(batch)
            except RelayError as e:      # cleanup is non-critical; report and continue
                log("cleanup", f"failed for {keys.pubkey_hex[:12]}…: {e}")
    return removed


def _price_for(intent: types.Intent, asking: int) -> int:
    """Set our asking price within the intent's minimum and maximum budget."""
    price = min(asking, intent.budget_max) if intent.budget_max else asking
    return max(price, intent.budget_min)


async def _wait_for(check, timeout: float, poll: float = 1.0):
    """Poll for the first non-empty result, returning `None` after `timeout`."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        got = await check()
        if got:
            return got
        await asyncio.sleep(poll)
    return None


async def serve_one(agent: Agent, intent: types.Intent, args) -> bool:
    """Complete one intent cycle, returning True after reaching the review stage."""
    customer = intent.source.pubkey
    intent_id = intent.source.id
    log("2 intent", f"from {customer[:12]}… {intent.content[:48]!r}; budget "
                    f"{intent.budget_min}–{intent.budget_max} {intent.currency}")

    price = _price_for(intent, args.price)
    offer_id = await agent.publish_offer(Offer(
        intent_id=intent_id, price=price, eta=int(time.time()) + args.work_seconds + 60,
        content=args.offer_text))
    log("3 offer", f"id {offer_id[:12]}… price {price} {intent.currency}")

    # The customer publishes the agreement; wait for it on the network, addressed to us.
    async def proposed():
        deals = await agent.get_agreements(counterparty=customer)
        return [d for d in deals
                if d.offer_id == offer_id and not d.verify_signatures()
                and not (d.sig_b if d.agent_b == agent.pubkey else d.sig_a)]
    pending = await _wait_for(proposed, args.timeout)
    if not pending:
        log("4 agreement", f"customer did not publish within {args.timeout:.0f}s; "
                            "leaving the intent open")
        return False
    deal = pending[0]
    if deal.price != price or deal.intent_id != intent_id:
        # Never sign agreement terms that differ from the offer.
        log("4 agreement", f"REFUSED: terms differ from the offer "
                           f"(price {deal.price} versus {price})")
        return False
    agreement_id = await agent.co_sign_agreement(deal)
    log("4 agreement", f"countersigned; concluded version {agreement_id[:12]}…")

    tasks = await _wait_for(lambda: agent.get_tasks(agreement_id=agreement_id), args.timeout)
    if not tasks:
        log("5 task", f"no task assigned within {args.timeout:.0f}s; ending the cycle")
        return False
    task = tasks[0]
    log("5 task", f"task_id {task.task_id[:12]}… {task.description[:48]!r}")

    await agent.update_task_status(task.task_id, agreement_id, "accepted", 0,
                                   "accepted for execution")
    await agent.update_task_status(task.task_id, agreement_id, "in_progress", 50,
                                   "work in progress")
    log("6 status", f"accepted → in_progress; working for {args.work_seconds}s")
    await asyncio.sleep(args.work_seconds)
    await agent.update_task_status(task.task_id, agreement_id, "completed", 100, "complete")
    result_url = f"{args.result_url}?task={task.task_id[:8]}"
    await agent.submit_task_result(task.task_id, agreement_id, result_url, "result submitted")
    log("7 result", f"completed, {result_url}")

    # The customer's review signals closure on their side; publish ours in response.
    async def review_from_customer():
        events = await agent.relay.query(
            {"kinds": [types.KIND_REVIEW], "authors": [customer], "#p": [agent.pubkey]})
        return [e for e in events if e.tag_value("agreement") == agreement_id]
    got = await _wait_for(review_from_customer, args.timeout)
    if got:
        rating = types.Review.from_event(got[0]).rating
        log("8 review", f"customer rated the work {rating}/5")
    else:
        log("8 review", f"customer did not review within {args.timeout:.0f}s; "
                        "publishing ours anyway")
    await agent.publish_review(agreement_id, customer, 5, args.review_text)
    log("8 review", "our review is published; cycle closed")
    return True


async def _finish(agent, keys: Keys, owner: Keys, args) -> int:
    """Finish a rehearsal, cleaning up first when --cleanup-after is set."""
    if args.cleanup_after:
        removed = await cleanup_identity(agent.relay, [keys, owner])
        log("cleanup", f"removed {removed} events after rehearsal")
    return 0


async def main() -> int:
    ap = argparse.ArgumentParser(description="A4A pilot counterparty agent")
    ap.add_argument("relay", nargs="?", help="required ws:// or wss:// relay address")
    ap.add_argument("--category", default="development")
    ap.add_argument("--capability", action="append", default=None,
                    help="profile capability; may be repeated")
    ap.add_argument("--price", type=int, default=45000, help="requested offer price")
    ap.add_argument("--work-seconds", type=int, default=3,
                    help="simulated task duration")
    ap.add_argument("--timeout", type=float, default=120,
                    help="seconds to wait for each counterparty step")
    ap.add_argument("--identity", default=None,
                    help="key file that preserves the agent address across restarts")
    ap.add_argument("--mandate-days", type=int, default=30)
    ap.add_argument("--mandate-hours", type=int, default=0,
                    help="short mandate in hours for production-network experiments, "
                         "avoiding long-lived test delegations")
    ap.add_argument("--once", action="store_true", help="handle one intent and exit")
    ap.add_argument("--cleanup", action="store_true",
                    help="delete everything published by --identity keys and exit")
    ap.add_argument("--cleanup-after", action="store_true",
                    help="clean up after a successful --once rehearsal")
    ap.add_argument("--offer-text", default="Ready to proceed on the requested schedule.")
    ap.add_argument("--review-text", default="Clear requirements and prompt acceptance.")
    ap.add_argument("--result-url", default="https://example.org/a4a-pilot-result")
    args = ap.parse_args()
    if not args.relay or not args.relay.startswith(("ws://", "wss://")):
        print("usage: python examples/pilot_counterpart.py ws://host:port [--category …]\n"
              "the relay address is required; there is deliberately no default",
              file=sys.stderr)
        return 2
    if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") != "utf8":
        sys.stdout.reconfigure(encoding="utf-8")

    if (args.cleanup or args.cleanup_after) and not args.identity:
        print("--cleanup and --cleanup-after require --identity: without a key file, "
              "every run creates a new agent whose protected mandate cannot be removed",
              file=sys.stderr)
        return 2

    owner, keys = _keys(args.identity)

    # Cleanup is an explicit mode, not an exit side effect. This agent is long-lived,
    # and deleting its history on every exit would defeat its purpose.
    if args.cleanup:
        async with Agent([args.relay], keys=keys) as agent:
            removed = await cleanup_identity(agent.relay, [keys, owner])
        log("cleanup", f"removed {removed} agent and owner events from {args.relay}")
        return 0

    async with Agent([args.relay], keys=keys) as agent:
        if args.mandate_hours:
            # An hourly mandate is only for experiments. It is SHORTER than the
            # timestamp allowance (~3 hours), so the agent's history remains
            # temporally unprovable (section 2.9). Use at least one day for real work.
            from a4a.delegation import create_delegation
            deleg = create_delegation(owner, agent.pubkey, "A4A pilot counterpart (test)",
                                      int(time.time()) + args.mandate_hours * 3600)
            await agent.relay.publish(deleg)
            agent.delegation_id = deleg.id
            term = (f"{args.mandate_hours}h "
                    "(test: shorter than the timestamp allowance)")
        else:
            await agent.ensure_registered(owner, "A4A pilot counterpart", days=args.mandate_days)
            term = f"{args.mandate_days}d"
        log("1 mandate", f"agent {agent.pubkey[:12]}… mandate "
                         f"{agent.delegation_id[:12]}… for {term}, relay {args.relay}")
        await agent.publish_profile(AgentProfile(
            capabilities=args.capability or ["landing_page", "web_development"],
            category=args.category, languages=["ru", "en"],
            content="A4A counterparty agent: accepting intents and delivering results."))
        log("1 profile", f"category {args.category}, capabilities "
                         f"{', '.join(args.capability or ['landing_page', 'web_development'])}")

        served, seen = 0, set()
        # Subscription is primary; polling is the fallback because subscriptions with
        # multi-character tags fail on third-party relays (a known SDK limitation).
        while True:
            try:
                async for intent in agent.subscribe_intents(category=args.category):
                    if intent.source.id in seen or intent.source.pubkey == agent.pubkey:
                        continue
                    seen.add(intent.source.id)
                    if await serve_one(agent, intent, args):
                        served += 1
                    if args.once:
                        return await _finish(agent, keys, owner, args)
            except Exception as e:      # noqa: BLE001 - subscription loss is recoverable
                log("subscription", f"ended ({type(e).__name__}); switching to polling")
            fresh = [i for i in await agent.search_intents(category=args.category)
                     if i.source.id not in seen and i.source.pubkey != agent.pubkey]
            for intent in fresh:
                seen.add(intent.source.id)
                if await serve_one(agent, intent, args):
                    served += 1
                if args.once:
                    return await _finish(agent, keys, owner, args)
            await asyncio.sleep(2)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

# Pilot day-one rehearsal (2026-09-04, ws://localhost:8083; an MCP client played the
# customer): the full cycle produced 14 events in 7.7 seconds. Customer: intent 31002,
# agreement 31004 (one signature), task 31030, review 31005. Counterparty: profile
# 31001, offer 31003, countersigned agreement 31004, three statuses 31031, result
# 31032, review 31005. Two mandates 31000 were also present; OWNER keys sign them, so
# agent-key queries do not include them.
