"""Describe the node under test at the start of every live-check report.

WHY. On 2026-09-04, a gate check reported "3 of 8" and appeared to expose a production
hole, but it had silently queried a local node; production logs showed no connection.
The next day, checks ran for a day and a half against staging 0.3.7 while the repository
contained 0.3.17. The relay address became a required argument, but its version remained
invisible.

A report that omits node identity and version cannot distinguish "verified" from
"verified elsewhere." One opening line prevents this entire failure class.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


def _http_from_ws(relay_url: str) -> str:
    if relay_url.startswith("wss://"):
        return "https://" + relay_url[len("wss://"):].rstrip("/")
    if relay_url.startswith("ws://"):
        return "http://" + relay_url[len("ws://"):].rstrip("/")
    return relay_url.rstrip("/")


def node_line(relay_url: str, timeout: float = 10.0) -> str:
    """Return `node: <version> at <address>`, or an honest unknown with its reason.

    Never raise: this line annotates a report rather than deciding its outcome.
    """
    req = urllib.request.Request(
        _http_from_ws(relay_url), headers={"Accept": "application/nostr+json"}
    )
    try:
        info = json.load(urllib.request.urlopen(req, timeout=timeout))
    except (urllib.error.URLError, OSError, ValueError) as e:
        return f"node: version unknown ({type(e).__name__}) at {relay_url}"
    version = info.get("version") or "version not declared"
    a4a = info.get("a4a") or {}
    marks = []
    if a4a:
        marks.append("A4A")
        if a4a.get("notary"):
            marks.append("notary")
        kinds = a4a.get("delegation_required_for_kinds") or []
        if kinds:
            marks.append(f"mandate for {len(kinds)} kinds")
    suffix = f" [{', '.join(marks)}]" if marks else ""
    return f"node: {version} at {relay_url}{suffix}"
