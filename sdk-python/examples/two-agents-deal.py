"""A4A demo: two agents discover each other and make a deal.

Requires a local relay: run docker compose up -d from the repository root.
Run: .venv/Scripts/python examples/two-agents-deal.py
     .venv/Scripts/python examples/two-agents-deal.py --keep  # preserve events

The demo cleans up after itself (see `cleanup`). Its keys are disposable: they exist
for one run and disappear with the process. That is appropriate for a demo, but the
owner mandate (kind 31000) is protected from expiration-based deletion; otherwise a
revoked delegation could appear valid again to readers. Without cleanup, every run
would therefore leave an agent on the network that NOBODY can remove because the
owner keys no longer exist. This is minor on a local relay, but changing one address
to a production relay would make the litter permanent.
"""
import asyncio
import sys
import time

from a4a import Agent, AgentProfile, Agreement, Intent, Keys, Offer
from a4a.event import Event
from a4a.relay import RelayError

# A Windows console may use a legacy code page, so select UTF-8 output to make the
# demo work without PYTHONIOENCODING.
if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") != "utf8":
    sys.stdout.reconfigure(encoding="utf-8")

RELAY = "ws://localhost:8080"
DEADLINE = int(time.time()) + 5 * 86400


def step(n: int, title: str) -> None:
    print(f"\n--- Step {n}: {title} ---")


async def cleanup(relay, keys_list: list[Keys]) -> int:
    """Delete everything published by these keys using one kind-5 event per key.

    An identity can delete only its own events, so each key signs its own deletion.
    The deletion event itself remains because nothing can remove it; this is the
    explicit cost of cleanup.
    """
    removed = 0
    for keys in keys_list:
        mine = await relay.query({"authors": [keys.pubkey_hex]})
        ids = [e.id for e in mine if e.kind != 5]
        if not ids:
            continue
        deletion = Event(kind=5, tags=[["e", i] for i in ids], content="demo cleanup")
        deletion.sign(keys)
        try:
            await relay.publish(deletion)
            removed += len(ids)
        except RelayError as e:            # cleanup is non-critical; report and continue
            print(f"  cleanup failed for {keys.pubkey_hex[:12]}…: {e}")
    return removed


async def main() -> None:
    print("=== A4A: two-agent deal demo ===")
    keep = "--keep" in sys.argv
    user_a, user_b = Keys(), Keys()  # agent owners

    async with Agent([RELAY]) as customer, Agent([RELAY]) as worker:
        step(0, "Registration (delegating authority to agents)")
        await customer.ensure_registered(user_a, "Customer agent")
        await worker.ensure_registered(user_b, "Worker agent")
        print(f"customer: {customer.pubkey[:16]}…  worker: {worker.pubkey[:16]}…")

        step(1, "Worker profile (kind 31001)")
        await worker.publish_profile(AgentProfile(
            capabilities=["web_development", "landing_page"],
            category="development", languages=["ru", "en"],
            price_range=(5000, 50000, "USD"),
            content="Web development: landing pages and websites"))

        step(2, "Customer intent (kind 31002)")
        intent_id = await customer.publish_intent(Intent(
            intent_type="service_request", category="development",
            need="landing_page", budget_min=30000, budget_max=50000,
            deadline=DEADLINE,
            content="Need a responsive five-section landing page for an AI startup."))
        print(f"intent: {intent_id[:16]}…")

        step(3, "Worker discovers available jobs")
        found = await worker.search_intents(category="development",
                                            intent_type="service_request")
        target = next((i for i in found if i.source.id == intent_id), None)
        if target is None:
            sys.exit("Intent was not found during discovery; check the relay")
        print(f"job found: {target.content!r}; budget up to "
              f"{target.budget_max} {target.currency}")

        step(4, "Worker offer (kind 31003)")
        offer_id = await worker.publish_offer(Offer(
            intent_id=intent_id, price=45000, eta=DEADLINE,
            content="I can deliver this in five days."))

        step(5, "Agreement signed by both parties (kind 31004)")
        offers = await customer.get_offers(intent_id)
        if not offers:
            sys.exit("No offers were found for the intent; check the relay")
        chosen = offers[0]
        if not await customer.validate_delegation(chosen.source):
            sys.exit("The worker delegation chain is invalid; canceling the deal")
        # Sign the agreement model. sign_agreement derives the domain-separated digest
        # (section 1.1) from the terms and rejects ready-made 32-byte signing inputs.
        terms = Agreement(
            intent_id=intent_id, offer_id=chosen.source.id,
            price=chosen.price, currency=chosen.currency, deadline=DEADLINE,
            agent_a=customer.pubkey, agent_b=worker.pubkey, sig_a="", sig_b="")
        agreement = terms.model_copy(update={
            "sig_a": customer.sign_agreement(terms),
            "sig_b": worker.sign_agreement(terms)})
        if not agreement.verify_signatures():
            sys.exit("Agreement signatures did not verify")
        agreement_id = await customer.publish_agreement(
            agreement, delegation_b=worker.delegation_id)
        print(f"deal concluded: {agreement_id[:16]}…; "
              f"price {agreement.price} {agreement.currency}")

        # The customer published the deal. The worker learns about it FROM THE NETWORK,
        # not a variable: real agents live on different machines and cannot share an
        # in-memory ID. This exact flow was impossible before 2026-08-29.
        mine = await worker.get_agreements(counterparty=customer.pubkey)
        if not mine or mine[0].source.id != agreement_id:
            sys.exit("The worker could not find its deal on the network")
        print(f"worker independently found the deal: {mine[0].source.id[:16]}…")

        step(6, "Execution: TaskRequest → TaskStatus → TaskResult (31030-31032)")
        await customer.send_task(agreement_id,
                                 "Build the landing page according to the brief", DEADLINE,
                                 executor=worker.pubkey)
        tasks = await worker.get_tasks(agreement_id=agreement_id)
        if not tasks:
            sys.exit("The worker did not receive its assigned task")
        task_id = tasks[0].task_id
        print(f"worker received the task: {tasks[0].description!r}")
        await worker.update_task_status(task_id, agreement_id, "in_progress", 50,
                                        "Three of five sections complete")
        await worker.update_task_status(task_id, agreement_id, "completed", 100)
        await worker.submit_task_result(task_id, agreement_id,
                                        "https://my-landing.example.com")
        print("result submitted")

        step(7, "Mutual reviews (kind 31005) and reputation")
        await customer.publish_review(agreement_id, worker.pubkey, 5,
                                      "Excellent work delivered on time")
        await worker.publish_review(agreement_id, customer.pubkey, 5,
                                    "Clear brief and prompt acceptance")
        rep = await customer.get_reputation(worker.pubkey)
        print(f"worker reputation: {rep.score:.1f}/5 ({rep.total_reviews} reviews)")

        if keep:
            print("\n(--keep: events remain on the network for inspection)")
        else:
            removed = await cleanup(customer.relay,
                                    [user_a, user_b, customer.keys, worker.keys])
            print(f"\ncleanup: removed {removed} demo events "
                  f"(run with --keep to inspect them on the relay)")

    print("\n✅ Deal completed successfully")


if __name__ == "__main__":
    asyncio.run(main())
