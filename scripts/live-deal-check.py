"""End-to-end agreement between two SEPARATE agents through a LIVE relay.

Green FakeRelay tests and "works on the network" are different claims. Here the parties
exchange nothing except relay events: the worker DISCOVERS agreement and task IDs exactly
as it would on a different machine.

This check verifies that agreements and tasks carry a single-letter
recipient tag so the other party can discover them on any compatible relay:

    python scripts/live-deal-check.py wss://eu1.a4a.network  # project relay
    python scripts/live-deal-check.py ws://localhost:8080      # local relay

The run publishes several expiring NIP-40 events and then cleans them up. Never publish
them to a relay you do not own or have permission to test.
"""
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk-python"))

from a4a import types                                    # noqa: E402
from a4a.agent import Agent                              # noqa: E402
from a4a.keys import Keys                                # noqa: E402
from a4a.types import Agreement                          # noqa: E402
from live_cleanup import sweep                            # noqa: E402
from node_banner import node_line              # noqa: E402

# The relay address is REQUIRED. A localhost/production default caused a false alarm after
# the 2026-09-04 release because the script silently queried the wrong node.
def _relay_from_argv() -> str:
    if len(sys.argv) < 2 or not sys.argv[1].startswith(("ws://", "wss://")):
        sys.exit(f"usage: python {sys.argv[0]} ws://host:port|wss://host; relay address "
                 "is required and intentionally has no default")
    return sys.argv[1]

RELAY = _relay_from_argv()

# The report must name its node. Without this line, "verified" is indistinguishable from
# "verified elsewhere," which happened twice on 2026-09-04 and 2026-09-05.
print(node_line(RELAY))
DEADLINE = int(time.time()) + 3 * 86400
ok = True


def check(label: str, cond: bool, extra: str = "") -> None:
    global ok
    ok = ok and cond
    print(("  OK   " if cond else "  FAIL ") + label + (" - " + extra if extra else ""))


async def main() -> int:
    print("relay:", RELAY)
    customer_owner, worker_owner = Keys(), Keys()
    async with Agent([RELAY]) as customer, Agent([RELAY]) as worker:
        await customer.ensure_registered(customer_owner, "live check: customer", days=1)
        await worker.ensure_registered(worker_owner, "live check: worker", days=1)
        print("customer ", customer.pubkey[:16], "worker", worker.pubkey[:16])

        marker = "live-check-" + str(int(time.time()))
        intent_id = await customer.publish_intent(types.Intent(
            intent_type="service_request", category="design", need=marker,
            budget_min=1, budget_max=100, deadline=DEADLINE,
            content="routing check " + marker))

        found = await worker.search_intents(category="design")
        check("worker sees intent", any(i.need == marker for i in found),
              "intents found: %d" % len(found))

        offer_id = await worker.publish_offer(types.Offer(
            intent_id=intent_id, price=50, eta=DEADLINE, content=marker))
        offers = await customer.get_offers(intent_id)
        check("customer sees offer", any(o.source.id == offer_id for o in offers))

        terms = Agreement(
            intent_id=intent_id, offer_id=offer_id, price=50, currency="USD",
            deadline=DEADLINE, agent_a=customer.pubkey, agent_b=worker.pubkey,
            sig_a="", sig_b="")
        proposed_id = await customer.publish_agreement(
            terms.model_copy(update={"sig_a": customer.sign_agreement(terms)}))

        # Critical property: the worker DISCOVERS the agreement knowing only its own key.
        mine = await worker.get_agreements(counterparty=customer.pubkey)
        check("worker finds agreement on the network",
              any(a.source.id == proposed_id for a in mine),
              "agreements found: %d" % len(mine))
        pending = [a for a in mine if a.source.id == proposed_id]
        check("agreement is not final with one signature",
              bool(pending) and not pending[0].verify_signatures())

        agreement_id = await worker.co_sign_agreement(pending[0]) if pending else ""
        done = [a for a in await customer.get_agreements(counterparty=worker.pubkey)
                if a.verify_signatures()]
        check("agreement is final after counter-signature", len(done) >= 1)

        await customer.send_task(agreement_id, "complete " + marker, DEADLINE,
                                 executor=worker.pubkey)
        tasks = await worker.get_tasks(agreement_id=agreement_id)
        check("worker finds assigned task",
              any(t.description == "complete " + marker for t in tasks),
              "tasks found: %d" % len(tasks))

        if tasks:
            await worker.submit_task_result(tasks[0].task_id, agreement_id,
                                            "https://example.org/" + marker)
            results = await customer.get_task_results(agreement_id, tasks[0].task_id)
            check("customer receives result", len(results) == 1)

            await customer.publish_review(agreement_id, worker.pubkey, 5, marker)
            rep = await customer.get_reputation(worker.pubkey, require_agreement=True)
            check("review counts against signed agreement", rep.total_reviews == 1,
                  "reviews: %d" % rep.total_reviews)

    # Live checks publish real events with real keys and must remove them. Mandates and
    # reviews do not expire from relay history (the 2026-09-05 audit found 92 disposable
    # test mandates in production).
    await sweep(RELAY, [customer.keys, worker.keys, customer_owner, worker_owner])
    print("RESULT:", "all checks passed" if ok else "FAILURES DETECTED")
    return 0 if ok else 1


raise SystemExit(asyncio.run(main()))
