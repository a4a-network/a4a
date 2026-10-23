"""Entry point for ``python -m a4a_agent``."""
import asyncio
import contextlib
import logging
import os

from a4a.agent import Agent

from . import config, identity, notify, publish
from .service import (MANDATE_CHECK_INTERVAL_SECONDS, ProjectAgent,
                      _renew_mandate_loop)


def _setup_logging() -> None:
    """Configure required operational logging.

    Without logs, a healthy service and one silently dropping all work look the
    same (review 2026-08-28, A13). ``A4A_LOG_LEVEL`` controls verbosity.
    """
    logging.basicConfig(
        level=os.environ.get("A4A_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )


async def main() -> None:
    _setup_logging()
    cfg = config.from_env()
    keys = identity.load_or_create_identity()
    logging.getLogger(__name__).info(
        "project agent: %s, relay: %s",
        keys.apub,
        cfg.relays[0] if cfg.relays else "none",
    )
    async with Agent(list(cfg.relays), keys=keys) as agent:
        # The owner mandate links agent events to the owner. A relay that requires
        # delegation will reject events without it. Search for an existing mandate
        # on the relay and issue one only when missing or close to expiry.
        await agent.ensure_registered(identity.load_or_create_owner_identity(),
                                     name="A4A project agent")

        # Renew during operation, not only at startup. Otherwise, an agent running
        # beyond the renewal window would eventually stop publishing without an
        # obvious failure because subscriptions and inbound reads would continue.
        stop = asyncio.Event()
        renew = asyncio.create_task(_renew_mandate_loop(
            agent, identity.load_or_create_owner_identity(),
            interval_seconds=MANDATE_CHECK_INTERVAL_SECONDS, stop=stop))

        await publish.publish_presence(agent, cfg.relays)
        svc = ProjectAgent(agent, cfg, lambda text: notify.send(
            cfg.telegram_token, cfg.telegram_chat_id, text))
        # Stream instead of polling: process the backlog, then remain on live
        # subscriptions. Polling every 30 seconds cost four times more than the
        # messages themselves (cost model 2026-08-28; see specification section 2.8).
        try:
            await svc.serve()
        finally:
            # The renewal task must not outlive the service or the process will hang.
            stop.set()
            renew.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await renew


if __name__ == "__main__":
    asyncio.run(main())
