"""Deliver one private message with ACK through ONE relay, with a slow recipient.

Tests pass on FakeRelay; this measures the real relay a release is about to run. On
23.09.2026 the 0.3.23 image with the code-default `subscriptions_per_min = 10` broke
exactly this path: the limiter stalls a connection, and `deliver_with_ack` polling for
the ACK died with "no relay connection" whenever the recipient answered after 12 s. The
test suites were green. Only a timed delivery against the real relay showed it.

Two throwaway identities are created per run; each publishes one gift wrap. There is no
default relay: an explicit address is required, so the check can never silently measure
localhost while the operator believes it measured a production node.

    python scripts/check-delivery-ack.py --relay wss://ru2.a4a.network
    python scripts/check-delivery-ack.py --relay ws://127.0.0.1:18423 --delays 2 12 30
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "sdk-python"))
from a4a import Agent  # noqa: E402

WINDOW = 20.0  # a4a_deliver: one attempt plus three retries of five seconds


async def _ack_after(agent: Agent, delay: float, stop: asyncio.Event):
    while not stop.is_set():
        messages = await agent.read_private_messages()
        if messages:
            await asyncio.sleep(delay)
            await agent.acknowledge(messages[0], status="processed")
            return
        await asyncio.sleep(0.5)


async def one(relay: str, delay: float) -> tuple[bool, str]:
    async with Agent([relay]) as sender, Agent([relay]) as recipient:
        stop = asyncio.Event()
        task = asyncio.create_task(_ack_after(recipient, delay, stop))
        started = time.monotonic()
        try:
            result = await sender.deliver_with_ack(
                recipient.pubkey, "delivery check", retries=3, ack_timeout=5.0,
                poll_interval=0.5, private=True)
        finally:
            stop.set()
            task.cancel()
        elapsed = time.monotonic() - started
    expected = "acknowledged" if delay < WINDOW - 3 else "dead_letter"
    ok = result["status"] == expected
    return ok, (f"delay {delay:>4.0f}s: {result['status']:12} attempts {result['attempts']} "
                f"{elapsed:5.1f}s (expected {expected})")


async def main(relay: str, delays: list[float]) -> int:
    failures = 0
    for delay in delays:
        try:
            ok, line = await one(relay, delay)
        except Exception as error:
            ok, line = False, f"delay {delay:>4.0f}s: ERROR {type(error).__name__}: {error}"
        failures += not ok
        print(("ok      " if ok else "FAILED  ") + line)
    print(f"\n{relay}: {len(delays) - failures}/{len(delays)} as expected")
    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--relay", required=True, help="exactly one relay URL (no default)")
    parser.add_argument("--delays", type=float, nargs="+", default=[2.0, 12.0])
    args = parser.parse_args()
    logging.disable(logging.WARNING)
    sys.exit(asyncio.run(main(args.relay, args.delays)))
