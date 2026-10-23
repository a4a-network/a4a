"""Minimal in-memory Nostr relay for unit tests; signatures are not validated."""
import json

import websockets

import network_guard


class FakeRelay:
    def __init__(self, respond_ok: bool = True, respond_eose: bool = True,
                 reject_reason: str | None = None, closed_reason: str | None = None,
                 honour_limit: bool = True, honour_filters: bool = True):
        # closed_reason makes REQ return CLOSED with this reason, matching relay
        # 0.3.16 behavior for an unsupported filter (finding 111). The client must
        # surface the reason rather than wait for EOSE until timeout.
        self.closed_reason = closed_reason
        # honour_limit=False makes the relay IGNORE `limit` and send every match.
        # This is realistic: `limit` is only a request to an untrusted relay, so
        # the reader's own cap is the only protection against an unbounded stream.
        self.honour_limit = honour_limit
        # honour_filters=False sends EVERYTHING to subscribers without applying
        # filters. This directly models a malicious relay: a filter is a request,
        # and the relay may send an event addressed to SOMEONE ELSE. The client must
        # verify locally. Only a dishonest relay can exercise that defense; an honest
        # one would discard the hostile event before it arrived, making tests vacuous.
        self.honour_filters = honour_filters
        # reject_reason makes EVENT fail with this reason so tests can verify how
        # the SDK explains relay rejection to the user. The refused event is not
        # stored, applied, or streamed: a refusal is not a stored copy.
        self.reject_reason = reject_reason
        # respond_ok=False makes the relay stay silent after EVENT (timeout tests).
        self.respond_ok = respond_ok
        # respond_eose=False suppresses EOSE (query timeout tests).
        self.respond_eose = respond_eose
        self.events: list[dict] = []
        # Subscriptions from ALL connections; live events must reach other clients.
        self._subs: list[dict] = []  # {"ws": ..., "sid": ..., "filters": [...]}
        self._connections = set()
        self._reject_handshakes = 0
        self._server = None
        self.url: str | None = None

    async def __aenter__(self):
        self._server = await websockets.serve(
            self._handler, "127.0.0.1", 0, process_request=self._process_request
        )
        port = self._server.sockets[0].getsockname()[1]
        self.url = f"ws://127.0.0.1:{port}"
        # Register with the test-run boundary. Connections are allowed only to
        # endpoints actually created by THIS run's fixtures. A loopback listener
        # alone does not prove ownership; without registration, a foreign service
        # reusing the same port number would appear legitimate.
        network_guard.allow("127.0.0.1", port)
        self._guarded = ("127.0.0.1", port)
        return self

    def reject_next_handshakes(self, n: int = 1):
        """Reject the next n connection attempts at HTTP level."""
        self._reject_handshakes += n

    async def _process_request(self, first, second):
        """Reject at HTTP level using the response form expected by the active server.

        The library has two server implementations with DIFFERENT contracts:

            legacy (websockets.legacy.server)  (path, headers) -> tuple
            modern (websockets.asyncio)        (connection, request) -> respond()

        One form cannot serve both. Our test environment uses 13.1 with legacy
        `serve`, while external review runs on 17.1 with the modern implementation.
        A fixture tied to one version silently behaves incorrectly on the other.

        HISTORY OF THIS CODE. It first returned a tuple and claimed the modern form
        was unused. That was true on 13.1, but on 17.1 clients received a MALFORMED
        handshake instead of a clean 503 (review finding TEST-HS-001). Replacing the
        tuple with `respond()` then broke the opposite direction: 13.1 returned HTTP
        500 because verification used the system interpreter while the suite uses its
        venv. The full suite stayed GREEN both times because it proved recovery after
        failure while accepting any failure shape.
        """
        if self._reject_handshakes <= 0:
            return None
        self._reject_handshakes -= 1
        body = "relay busy" + chr(10)
        respond = getattr(first, "respond", None)
        if callable(respond):          # Modern: first is the connection.
            return respond(503, body)
        return (503, [], body.encode("utf-8"))   # Legacy: first is the path.

    async def __aexit__(self, *exc):
        self._server.close()
        await self._server.wait_closed()
        # Remove registration. The OS can reuse the port, and a record surviving
        # into the next run would authorize an unrelated service.
        if getattr(self, "_guarded", None):
            network_guard.forget(*self._guarded)
            self._guarded = None

    async def _handler(self, ws):
        self._connections.add(ws)
        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg[0] == "EVENT":
                    ev = msg[1]
                    if self.reject_reason is not None:
                        await ws.send(json.dumps(
                            ["OK", ev["id"], False, self.reject_reason]))
                        continue
                    self.events.append(ev)
                    self._apply_deletion(ev)
                    if self.respond_ok:
                        await ws.send(json.dumps(["OK", ev["id"], True, ""]))
                    for sub in self._subs:
                        if not self.honour_filters or any(self._match(f, ev) for f in sub["filters"]):
                            await sub["ws"].send(json.dumps(["EVENT", sub["sid"], ev]))
                elif msg[0] == "REQ":
                    sid, filters = msg[1], msg[2:]
                    if self.closed_reason is not None:
                        await ws.send(json.dumps(["CLOSED", sid, self.closed_reason]))
                        continue
                    self._subs.append({"ws": ws, "sid": sid, "filters": filters})
                    for ev in (self.events if not self.honour_filters else self._matching(filters)):
                        await ws.send(json.dumps(["EVENT", sid, ev]))
                    if self.respond_eose:
                        await ws.send(json.dumps(["EOSE", sid]))
                elif msg[0] == "CLOSE":
                    self._subs = [s for s in self._subs
                                  if not (s["ws"] is ws and s["sid"] == msg[1])]
        finally:
            self._subs = [s for s in self._subs if s["ws"] is not ws]
            self._connections.discard(ws)

    def _apply_deletion(self, ev: dict) -> None:
        """Apply NIP-09 deletion to `e` targets from the SAME author only.

        This became necessary when both `Agent.disconnect` and relay-side delegation
        termination started relying on deletion. Without it, both test groups could
        silently pass or fail for the wrong reason because the fake relay diverged
        from real behavior exactly where the tests were focused.
        """
        if ev.get("kind") != 5:
            return
        targets = {t[1] for t in ev.get("tags", []) if len(t) >= 2 and t[0] == "e"}
        if not targets:
            return
        self.events = [e for e in self.events
                       if not (e["id"] in targets and e["pubkey"] == ev["pubkey"])]

    async def drop_connections(self):
        """Drop every active connection without stopping the server."""
        for ws in list(self._connections):
            await ws.close()

    async def send_raw(self, text: str):
        """Send raw text to every connection for reader robustness tests."""
        for ws in list(self._connections):
            await ws.send(text)

    def _matching(self, filters: list[dict]) -> list[dict]:
        """Return REQ results with real-relay `limit` semantics.

        Before 2026-09-05 the double ignored `limit` and returned EVERY match. No test
        could detect truncation: code that fetched once and assumed completeness was
        green here while silently losing the tail in production. This surfaced when
        live-check cleanup fetched events once with `limit=1000`.

        NIP-01 returns the NEWEST events for `limit`, so sort by descending
        `created_at`. Otherwise `until` pagination would appear to work only because
        insertion order happened to cooperate.
        """
        out: list[dict] = []
        for flt in filters:
            found = [ev for ev in self.events if self._match(flt, ev)]
            # `.get` is deliberate. Tests insert malformed events, and sorting must
            # not crash the server; that would turn a client robustness check into a
            # connection timeout.
            def _order(e):
                # `created_at` may be a string in deliberately malformed events.
                # Their order is irrelevant; avoiding a crash is what matters.
                ts = e.get("created_at", 0)
                return (-ts if isinstance(ts, int) else 0, str(e.get("id", "")))

            found.sort(key=_order)
            lim = flt.get("limit")
            if self.honour_limit and isinstance(lim, int) and lim >= 0:
                found = found[:lim]
            for ev in found:
                if ev not in out:
                    out.append(ev)
        return out

    @staticmethod
    def _match(flt: dict, ev: dict) -> bool:
        if "ids" in flt and ev["id"] not in flt["ids"]:
            return False
        if "kinds" in flt and ev["kind"] not in flt["kinds"]:
            return False
        if "authors" in flt and ev["pubkey"] not in flt["authors"]:
            return False
        # NIP-01 `since` and `until` bounds are inclusive. The double must implement
        # them or time-filter tests prove only that filters do not interfere.
        if "since" in flt and ev["created_at"] < flt["since"]:
            return False
        if "until" in flt and ev["created_at"] > flt["until"]:
            return False
        for key, wanted in flt.items():
            if key.startswith("#"):
                have = [t[1] for t in ev["tags"] if len(t) >= 2 and t[0] == key[1:]]
                if not set(have) & set(wanted):
                    return False
        return True
