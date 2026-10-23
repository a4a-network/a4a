"""Node history via REST `/v1/history?after=<first_seen>&after_id=<id>&limit=<n>&page=2`.

NIP-01 `REQ` can filter only on author-supplied `created_at`, while a trustworthy
timestamp must use the node's RECEIPT time—the only evidence for "no later than T"
(finding 86). Collection therefore uses the relay's paginated REST API, while
publication and monitoring continue over WebSocket.
"""
from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from collections.abc import Callable

from a4a.event import Event

Opener = Callable[[str], str]
MAX_HISTORY_PAGE_BYTES = 2 * 1024 * 1024


def rest_base(relay_url: str) -> str:
    """ws://host:port → http://host:port, wss:// → https://."""
    if relay_url.startswith("wss://"):
        return "https://" + relay_url[len("wss://"):].rstrip("/")
    if relay_url.startswith("ws://"):
        return "http://" + relay_url[len("ws://"):].rstrip("/")
    return relay_url.rstrip("/")


def _http_get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "a4a-notary"})
    with urllib.request.urlopen(req, timeout=20) as r:
        body = r.read(MAX_HISTORY_PAGE_BYTES + 1)
        if len(body) > MAX_HISTORY_PAGE_BYTES:
            raise RuntimeError("history response exceeds the 2 MiB limit")
        return body.decode("utf-8")


class RelayWithHistory:
    """RelayClient wrapper: query/publish use WebSocket; history uses REST."""

    def __init__(self, relay, relay_url: str, opener: Opener = _http_get):
        self._relay, self._base, self._opener = relay, rest_base(relay_url), opener

    async def query(self, flt):
        return await self._relay.query(flt)

    async def publish(self, ev):
        return await self._relay.publish(ev)

    async def history(self, after: int, limit: int, after_id: str = "") -> list[tuple[int, Event]]:
        if after_id and (len(after_id) != 64 or any(c not in "0123456789abcdef" for c in after_id)):
            raise ValueError("invalid history cursor id")
        url = (f"{self._base}/v1/history?after={int(after)}&limit={int(limit)}"
               f"&page=2&after_id={after_id}")
        try:
            body = await asyncio.to_thread(self._opener, url)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise RuntimeError(
                    "relay has no /v1/history endpoint; a4a-relay 0.3.14 or newer "
                    "is required for receipt-time history (finding 86)") from e
            raise
        if len(body.encode("utf-8")) > MAX_HISTORY_PAGE_BYTES:
            raise RuntimeError("history response exceeds the 2 MiB limit")
        page = json.loads(body)
        if not isinstance(page, dict) or page.get("version") != 2 or not isinstance(page.get("rows"), list):
            raise RuntimeError("relay does not support bounded history page=2; upgrade the relay first")
        rows = page["rows"]
        if len(rows) > min(max(limit, 1), 5000):
            raise RuntimeError("history response exceeds the requested row limit")
        out: list[tuple[int, Event]] = []
        previous = (after, after_id)
        for row in rows:
            fs = row["first_seen"]
            if type(fs) is not int or not 0 <= fs <= 2**63 - 1:
                raise RuntimeError("invalid history reception time")
            event = Event.model_validate(row["event"])
            if len(event.id) != 64 or any(c not in "0123456789abcdef" for c in event.id):
                raise RuntimeError("invalid history event id")
            position = (fs, event.id)
            if position <= previous:
                raise RuntimeError("history cursor did not advance in strict order")
            previous = position
            out.append((fs, event))
        expected = {"first_seen": previous[0], "id": previous[1]} if rows else None
        if "next_cursor" not in page or page["next_cursor"] != expected:
            raise RuntimeError("history next_cursor does not match the last row")
        return out
