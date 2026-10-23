"""Sidecar entry point: ``python -m a4a_notary [--once]``.

Configuration comes only from the environment (the container runs beside the relay):

``A4A_RELAY_URL``
    Relay address. Defaults to ``ws://relay:8080``, the Compose service name.
``A4A_NOTARY_KEY_FILE``
    Hex private-key file. Created with mode 0600 on first start. The logged pubkey goes
    into relay configuration as ``a4a.notary_pubkey``.
``A4A_NOTARY_DB``
    SQLite state path; defaults to ``/data/notary.db``.
``A4A_NOTARY_INTERVAL``
    Seconds between passes; defaults to 3600, or one batch per hour.
``A4A_OTS_CALENDARS``
    Comma-separated calendars; defaults to four public calendars.
``A4A_RELAY_PUBLIC_URL``
    Public relay address placed in kind 1040's ``e`` tag so readers can retrieve the
    event. This must be the public URL, not the container's internal address.

Network errors skip one pass and are retried on the next. State errors (a key cannot be
created or the database cannot open) remain fatal because waiting cannot repair them.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket
import sys
import time
from pathlib import Path

from a4a.keys import Keys
from a4a.relay import RelayClient, RelayUnreachable

from .history import RelayWithHistory

from . import calendar as cal
from .service import NotaryService
from .store import Store

log = logging.getLogger("a4a.notary")


def load_or_create_keys(path: Path) -> Keys:
    if path.exists():
        return Keys(path.read_text(encoding="ascii").strip())
    keys = Keys()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(keys.privkey_hex + "\n")
    log.warning("created notary key %s with pubkey %s; add the pubkey to relay config "
                "as a4a.notary_pubkey or readers will reject attestations", path, keys.pubkey_hex)
    return keys


def settings_from_env(env: dict[str, str] = os.environ) -> dict:
    return {
        "relay_url": env.get("A4A_RELAY_URL", "ws://relay:8080"),
        "public_url": env.get("A4A_RELAY_PUBLIC_URL", env.get("A4A_RELAY_URL", "ws://relay:8080")),
        "key_file": Path(env.get("A4A_NOTARY_KEY_FILE", "/data/notary.key")),
        "db": Path(env.get("A4A_NOTARY_DB", "/data/notary.db")),
        "interval": int(env.get("A4A_NOTARY_INTERVAL", "3600")),
        "calendars": [c.strip() for c in env.get("A4A_OTS_CALENDARS", ",".join(cal.DEFAULT_CALENDARS)).split(",") if c.strip()],
    }


async def one_pass(cfg: dict, keys: Keys, store: Store) -> dict:
    async with RelayClient(cfg["relay_url"]) as relay:
        notary = NotaryService(RelayWithHistory(relay, cfg["relay_url"]), store, keys,
                               cfg["public_url"], calendars=cfg["calendars"])
        return await notary.run_once()


async def main_loop(cfg: dict, once: bool) -> int:
    keys = load_or_create_keys(cfg["key_file"])
    log.info("notary %s -> relay %s, public URL %s, calendars %s, interval %d s",
             keys.pubkey_hex[:12], cfg["relay_url"], cfg["public_url"], cfg["calendars"], cfg["interval"])
    store = Store(cfg["db"])
    while True:
        started = time.monotonic()
        try:
            result = await one_pass(cfg, keys, store)
            log.info("pass: %s; state %s", result, store.stats())
        except cal.NoCalendarAnswered as e:
            log.warning("calendars did not respond: %s; retrying in %d s", e, cfg["interval"])
        except (OSError, ConnectionError, RelayUnreachable) as e:  # Network or relay failure: retry.
            log.warning("pass failed: %s; retrying in %d s", e, cfg["interval"])
        if once:
            return 0
        await asyncio.sleep(max(1.0, cfg["interval"] - (time.monotonic() - started)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="a4a_notary")
    parser.add_argument("--once", action="store_true", help="run one pass and exit")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Calendars use urllib without their own timeout; otherwise a stalled calendar holds
    # the pass forever.
    socket.setdefaulttimeout(20)
    return asyncio.run(main_loop(settings_from_env(), args.once))


if __name__ == "__main__":
    sys.exit(main())
