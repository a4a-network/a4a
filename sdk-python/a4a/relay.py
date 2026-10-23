"""Asynchronous Nostr relay WebSocket client: publish / query / subscribe."""
import asyncio
from dataclasses import dataclass
import json
import logging
import secrets
import time

import websockets

from .event import Event

log = logging.getLogger(__name__)

#: Maximum number of events the reader accepts per query, regardless of what the relay sends.
#:
#: A filter's `limit` is a REQUEST that a well-behaved relay will honor. This ceiling
#: protects against a malicious relay, which may send a million events and can only be
#: stopped by the reader. Measurement on 2026-08-30 against a relay with 14,164 events:
#: an unlimited query returned all 14,164 in 1.3 seconds.
#:
#: The value is high enough not to truncate legitimate responses: the largest valid
#: result is reviews of an active agent and transactions over its full history, measured
#: in hundreds rather than tens of thousands. Truncation is logged; otherwise a partial
#: response would look like "there is nothing else on the network."
MAX_EVENTS_PER_QUERY = 5_000

#: How long to wait for a graceful connection close.
#:
#: Otherwise a silent node costs TWO full timeouts: first it does not answer the
#: handshake, then it does not answer the close. Measurement on 2026-08-30: one
#: connection to an accepting but silent port took 20 seconds with a 10-second timeout.
#: Closing is cleanup and is not worth a long wait.
CLOSE_TIMEOUT = 2

_EOSE = object()
_CLOSED = object()


class _ClosedByRelay:
    """The relay closed our subscription with a reason in a `CLOSED` message (NIP-01).

    This is a separate type rather than the generic `_CLOSED`: the latter means the
    connection was lost, while this is the relay's response for a specific subscription
    and its text must reach the caller verbatim.
    """

    __slots__ = ("reason",)

    def __init__(self, reason: str):
        self.reason = reason


def _closed_hint(reason: str) -> str:
    """Explain a subscription close using the same rule as a publish rejection:
    follow the relay's reason, not its prefix (finding 107)."""
    low = reason.lower()
    if "could not parse" in low or low.startswith("invalid:"):
        return (". The filter could not be parsed; check the types: `kinds` and numeric "
                "fields must contain numbers, while `authors`/`ids` must contain hex "
                "strings without null")
    if low.startswith("rate-limited:"):
        return ". The relay is rate-limiting requests; retry later or narrow the filter"
    if low.startswith("blocked:") or low.startswith("auth-required:"):
        return ". The relay rejected the subscription; see its policy (NIP-11)"
    return ""


def _canonical_relay_key(url: str) -> str:
    """Return a relay-address comparison key using CAUTIOUS canonicalization, not DNS.

    `wss://x/` and `wss://x` are the same node: parsing either address yields the `/`
    resource. Comparing raw strings treated them as different, so `min_accepted=2`
    could be satisfied by ONE storage system merely by adding a slash. An external
    reviewer found this on the third pass over the same finding (HEAL-004).

    Only indisputably equivalent forms are collapsed: scheme, lowercase hostname,
    default port, and empty path. Different paths and queries are NOT merged because
    they may route to different nodes behind one name. Names are deliberately not
    resolved to addresses: resolution depends on who asks and when, which would make
    the key unstable.

    What this does not provide: different canonical addresses still do not prove
    storage independence. Two machines from one hosting provider can have distinct
    names, share a rack, and fail together.
    """
    import ipaddress
    from urllib.parse import urlsplit
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    # Canonicalize numeric addresses: `[::1]` and `[0:0:0:0:0:0:0:1]` are the same
    # machine written differently, but string comparison treated them as different
    # nodes. Hostnames are NOT resolved: resolution depends on who asks and when, which
    # would make the key unstable.
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    port = parts.port or {"ws": 80, "wss": 443, "http": 80, "https": 443}.get(scheme, 0)
    # Collapse ONLY an empty path with the root path. An earlier version stripped
    # trailing slashes from every path and merged `/a` with `/a/`, even though they are
    # distinct resources that a node may route to different stores. Fixing one bypass
    # had created another.
    path = "" if parts.path in ("", "/") else parts.path
    return f"{scheme}://{host}:{port}{path}{'?' + parts.query if parts.query else ''}"


class InsufficientCopies(Exception):
    """The event was accepted, but fewer copies exist than were required.

    This is separate from a generic failure because "nodes are unavailable" and "too
    few copies" require different remedies. The former means waiting or changing nodes;
    the latter means deciding whether that durability is acceptable for THIS event.
    One exception for both cases would force callers to parse prose, which is already a
    recognized defect.
    """

    def __init__(self, event_id: str, accepted: int, required: int, configured: int):
        self.accepted, self.required, self.configured = accepted, required, configured
        super().__init__(f"event {event_id[:16]} was accepted by {accepted} of "
                         f"{configured} nodes; at least {required} were required")


class RelayError(Exception):
    """The relay rejected an event or did not respond in time.

    `reason` is the relay's rejection text VERBATIM, without the SDK hint. The hint in
    `str(e)` is written for code calling the SDK ("call ensure_registered"); a wrapper
    such as MCP that speaks to a model needs the raw reason so it can give advice in its
    own terms (found by an MCP probe on 2026-09-04). An empty string means the failure
    did not come from the relay (timeout or disconnect).
    """

    def __init__(self, message: str, reason: str = ""):
        super().__init__(message)
        self.reason = reason


class RelayUnreachable(RelayError):
    """A node cannot be reached: address, network, or timeout, but NOT a semantic rejection.

    Callers need different actions, so this has its own type. A node rejection
    ("delegation expired", "non-canonical number") concerns the event: change the event
    and a retry makes sense. Unreachability concerns the environment: the address,
    network, or a stopped container. Repeating the same command cannot help until the
    external state changes.

    A message string cannot safely distinguish the cases because wrappers such as the
    MCP server would then depend on our phrasing. It is also a matter of the user's
    MONEY: every model turn costs something, and an ambiguous error invites another
    attempt, turning an unreachable node into a spending loop.
    """


@dataclass(frozen=True)
class QueryResult:
    """Local collection evidence, not a claim that the relay supplied all history."""

    events: list[Event]
    inspected_events: int
    discarded_invalid_events: int
    truncated: bool
    connection_dropped_events: int = 0
    #: Number of relays that ACTUALLY answered this query. Always 1 for a single client;
    #: for a fan-out client it counts responders, not configured relays. Configuration
    #: size is not coverage: an unreachable node contributes nothing, and counting it
    #: overstates completeness precisely where completeness informs a decision.
    relays_responded: int = 1


class RelayClient:
    #: Maximum number of unread events per subscription.
    #:
    #: Signatures are verified only AFTER items leave the queue, so filtering cannot
    #: throttle the stream: a relay (or a spammer using it) can fill the queue faster
    #: than the consumer parses it, and a long-running subscribed agent—the standard
    #: post-polling scenario—grows until OOM. On overflow the OLDEST item is dropped:
    #: subscriptions are for fresh events, and losing them to a backlog created by an
    #: outsider is worse than losing the tail of history.
    MAX_QUEUED_EVENTS = 10_000

    def __init__(self, url: str, timeout: float = 10.0):
        self.url = url
        self.timeout = timeout
        self._ws = None
        self._reader_task: asyncio.Task | None = None
        self._pending_ok: dict[str, asyncio.Future] = {}
        #: Bodies of pending publications, retained for replay after reconnecting.
        self._pending_events: dict[str, Event] = {}
        self._subs: dict[str, asyncio.Queue] = {}
        self._sub_filters: dict[str, list[dict]] = {}
        self._closed_reason: str | None = None
        #: Number of events dropped on overflow, used to diagnose backpressure.
        self._dropped_events = 0

    def _register_subscription(self, sid: str, filters: list[dict],
                               queue: asyncio.Queue) -> None:
        """Remember a subscription TOGETHER with its filters, including one-shot `query()`.

        Previously `query()` was recorded only in `_subs`, while reconnect replay uses
        `_sub_filters`. After an ordinary network interruption, a pending query waited
        for an EOSE that nobody could send and timed out; the caller could not
        distinguish that from a silent relay (internal audit F11, 2026-08-29).
        """
        self._subs[sid] = queue
        self._sub_filters[sid] = filters

    def _forget_subscription(self, sid: str) -> None:
        self._subs.pop(sid, None)
        self._sub_filters.pop(sid, None)

    async def _resend_pending(self) -> None:
        """Replay pending publications. A Nostr event is idempotent by ID, so replay is
        safe: the relay responds with duplicate rather than creating another event."""
        for ev in list(self._pending_events.values()):
            try:
                await self._ws.send(json.dumps(["EVENT", ev.model_dump()]))
            except Exception:      # noqa: BLE001 — one event must not break reconnection
                return

    def _on_reconnected(self) -> None:
        """Clear the previous disconnect reason so it cannot explain a later failure."""
        self._closed_reason = None

    def _new_queue(self) -> asyncio.Queue:
        return asyncio.Queue(maxsize=self.MAX_QUEUED_EVENTS)

    def _offer(self, queue: asyncio.Queue, item) -> None:
        """Enqueue an item, evicting the oldest one on overflow."""
        while True:
            try:
                queue.put_nowait(item)
                return
            except asyncio.QueueFull:
                self._dropped_events += 1
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:      # A race drained the queue; simply retry.
                    pass

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *exc):
        await self.aclose()

    async def connect(self) -> None:
        """Connect to the relay, reporting failure as an actionable `RelayError` with its URL.

        The raw OS error used to leak out (for example, "[WinError 1225] The connection
        could not be established..."). It told callers neither which relay failed nor
        what to do about it (audit, 2026-08-29).
        """
        try:
            self._ws = await websockets.connect(self.url, open_timeout=self.timeout,
                                                close_timeout=CLOSE_TIMEOUT)
        except asyncio.TimeoutError as e:
            raise RelayUnreachable(
                f"relay {self.url} did not respond within {self.timeout}s. Check the "
                f"address and network availability") from e
        except (OSError, websockets.WebSocketException, ValueError) as e:
            raise RelayUnreachable(
                f"could not connect to relay {self.url}: {type(e).__name__}. Check the "
                f"address (ws:// or wss:// is required) and that the relay is running") from e
        self._reader_task = asyncio.create_task(self._reader())

    async def aclose(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._ws:
            await self._ws.close()
        self._ws = None

    def _wake_subscribers(self, reason: str) -> None:
        """Wake all live subscription consumers after the connection is lost permanently."""
        self._closed_reason = reason
        for queue in self._subs.values():
            queue.put_nowait(_CLOSED)

    async def _reader(self) -> None:
        # Every exit from this loop must wake subscribers. Previously only
        # ConnectionClosed was caught; any other exception (such as an invalid
        # connection state) silently killed the task. The process remained alive while
        # the subscription waited on an unbounded queue read and received no messages.
        # This silent failure looked exactly like "nobody wrote today" (review S5,
        # 2026-08-28).
        reason = "relay connection lost"
        try:
            while True:
                try:
                    raw = await self._ws.recv()
                except websockets.ConnectionClosed:
                    if not await self._reconnect():
                        reason = "relay connection lost and reconnection failed"
                        break
                    continue
                try:
                    self._dispatch(json.loads(raw))
                except Exception:
                    continue  # A malformed relay message must not kill the reader.
        except BaseException as e:      # noqa: BLE001 — includes task cancellation
            reason = f"relay read interrupted: {type(e).__name__}"
            raise
        finally:
            self._fail_pending(reason)
            self._wake_subscribers(reason)

    def _dispatch(self, msg) -> None:
        if msg[0] == "OK":
            if len(msg) < 3:
                return  # Ignore truncated OK; the future will wait for timeout/retry.
            fut = self._pending_ok.get(msg[1])
            if fut and not fut.done():
                # Compare with True rather than testing truthiness. The second OK field
                # was not type-checked, and the JSON string "false" is truthy in Python.
                # A relay responding ["OK", id, "false", "blocked: spam"] appeared to
                # accept the event: publish() returned normally, the caller considered
                # the message delivered, and no retry happened. This was silent data
                # loss and also let a relay swallow inconvenient events (core audit F9).
                fut.set_result((msg[2] is True, msg[3] if len(msg) > 3 else ""))
            self._pending_ok.pop(msg[1], None)
        elif msg[0] == "EVENT":
            queue = self._subs.get(msg[1])
            if queue:
                self._offer(queue, msg[2])
        elif msg[0] == "EOSE":
            queue = self._subs.get(msg[1])
            if queue:
                self._offer(queue, _EOSE)
        elif msg[0] == "CLOSED":
            # NIP-01: the relay closed the subscription and supplied a reason
            # (`invalid:`, `blocked:`, `rate-limited:`, and so on). Without this branch,
            # the client waited for an EOSE that would never arrive, then timed out with
            # a useless "no EOSE" error, losing the relay's reason entirely (finding
            # 111, 2026-09-05).
            queue = self._subs.get(msg[1])
            if queue:
                self._offer(queue, _ClosedByRelay(msg[2] if len(msg) > 2 else ""))

    def _fail_pending(self, reason: str) -> None:
        for fut in self._pending_ok.values():
            if not fut.done():
                fut.set_exception(RelayError(reason))
        self._pending_ok.clear()
        self._pending_events.clear()

    async def _reconnect(self) -> bool:
        """Reconnect and restore live subscriptions. Return False on failure."""
        for delay in (1, 2, 4):
            await asyncio.sleep(delay)
            try:
                self._ws = await websockets.connect(self.url, open_timeout=self.timeout,
                                                close_timeout=CLOSE_TIMEOUT)
                for sid, filters in self._sub_filters.items():
                    await self._ws.send(json.dumps(["REQ", sid, *filters]))
                await self._resend_pending()
            except (OSError, websockets.WebSocketException):
                continue  # Handshake failure or disconnect: try again.
            self._on_reconnected()
            return True
        return False

    async def _safe_send(self, payload: list) -> None:
        if self._ws is None:
            raise RelayError("no relay connection; call connect()")
        try:
            await self._ws.send(json.dumps(payload))
        except websockets.WebSocketException as e:
            raise RelayUnreachable(f"relay connection lost: {e}") from e

    async def publish(self, event: Event, *, replay_on_reconnect: bool = True) -> None:
        """Send an event and await OK; raise RelayError on rejection, timeout, or no connection."""
        if type(replay_on_reconnect) is not bool:
            raise ValueError("replay_on_reconnect must be a boolean")
        if event.id in self._pending_ok:
            raise RelayError("publication of this event is already pending")
        fut = asyncio.get_running_loop().create_future()
        self._pending_ok[event.id] = fut
        # Managed outboxes reconcile uncertain sends themselves; transport replay
        # would bypass their lease fencing after a different worker takes over.
        if replay_on_reconnect:
            self._pending_events[event.id] = event
        try:
            await self._safe_send(["EVENT", event.model_dump()])
            accepted, reason = await asyncio.wait_for(fut, self.timeout)
        except asyncio.TimeoutError:
            raise RelayUnreachable(f"no OK response from {self.url} within {self.timeout}s")
        finally:
            self._pending_ok.pop(event.id, None)
            self._pending_events.pop(event.id, None)
        if not accepted:
            hint = ""
            if "delegation required" in reason:
                # The most common first error after mandatory delegation is enabled.
                # The relay names the reason honestly, but not the remedy.
                hint = (". The agent has no owner delegation; call "
                        "agent.ensure_registered(owner_keys, name) once at startup")
            elif "invalid or expired A4A delegation" in reason:
                # Since 0.3.11, the reason after the colon matters more than the prefix.
                # Reporting "expired" for a delegation issued to a DIFFERENT key sent
                # users toward the wrong fix (external verification, 2026-09-04).
                if "revoked" in reason:
                    hint = (". The owner revoked the delegation; only the owner can issue a new one: "
                            "agent.ensure_registered(owner_keys, name)")
                elif "different delegate" in reason or "delegate" in reason and "tag" in reason:
                    hint = (". The delegation names a different key, or its d/delegate tags do "
                            "not match the agent key; check which key signed the event and which "
                            "key the delegation names")
                elif "expired" in reason:
                    hint = (". The delegation expired; issue a new one through "
                            "agent.ensure_registered(owner_keys, name)")
                else:
                    hint = (". The relay rejected the delegation (see the reason above); issue "
                            "a new one through agent.ensure_registered(owner_keys, name)")
            elif "created_at" in reason and "range" in reason:
                # Clock skew is among the most common reasons that nothing works for a
                # new user. The relay text obscures it by mentioning a "range", while
                # the MACHINE CLOCK needs fixing. A wrong diagnosis is costly because
                # the user starts checking keys, networking, and installation.
                #
                # Subtlety: if the LOCAL machine clock is wrong, the event carries that
                # same time and the local difference is near zero. Therefore the local
                # skew is named only when it is actually large; otherwise the problem is
                # skew relative to the relay, which cannot be measured here.
                skew = int(event.created_at - time.time())
                where = (f"the event timestamp is {abs(skew)}s "
                         f"{'ahead of' if skew > 0 else 'behind'} this machine's clock; "
                         f"the event was not assembled just now"
                         if abs(skew) > 60 else
                         "this machine's clock differs from the relay's clock: the event "
                         "uses the local time, and the relay rejected that timestamp")
                hint = (f". {where}. Synchronize the clock "
                        f"(Windows: w32tm /resync, Linux: timedatectl set-ntp true)")
            raise RelayError(f"relay rejected the event: {reason}{hint}", reason=reason)

    @staticmethod
    def _parse_event(item) -> Event | None:
        """Parse a network event; return None for malformed data or an invalid signature."""
        try:
            ev = Event(**item)
            ev.validate_numeric_tags()
        except Exception:
            return None
        return ev if ev.verify() else None

    async def query(self, filters: dict | list[dict], *, max_events: int | None = None) -> list[Event]:
        """Run a one-shot query. Explicit max_events bounds ALL EVENT inspections, even malformed ones."""
        return (await self._query(filters, max_events=max_events)).events

    async def query_bounded(self, filters: dict | list[dict], *, max_events: int) -> QueryResult:
        """Bound raw EVENT inspection and report transport discards/truncation."""
        if type(max_events) is not int or not 1 <= max_events <= MAX_EVENTS_PER_QUERY:
            raise ValueError(f"max_events must be 1..{MAX_EVENTS_PER_QUERY}")
        return await self._query(filters, max_events=max_events)

    async def _query(self, filters: dict | list[dict], *, max_events: int | None) -> QueryResult:
        ceiling = MAX_EVENTS_PER_QUERY if max_events is None else max_events
        if type(ceiling) is not int or not 1 <= ceiling <= MAX_EVENTS_PER_QUERY:
            raise ValueError(f"max_events must be 1..{MAX_EVENTS_PER_QUERY}")
        filters = [filters] if isinstance(filters, dict) else filters
        sid = secrets.token_hex(8)
        queue: asyncio.Queue = self._new_queue()
        dropped_before = self._dropped_events
        self._register_subscription(sid, filters, queue)
        await self._safe_send(["REQ", sid, *filters])
        events: list[Event] = []
        inspected = discarded = 0
        truncated = False
        try:
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), self.timeout)
                except asyncio.TimeoutError:
                    raise RelayUnreachable(f"no EOSE from {self.url} within {self.timeout}s")
                if item is _EOSE:
                    break
                if isinstance(item, _ClosedByRelay):
                    raise RelayError(
                        f"relay {self.url} closed the subscription: {item.reason}"
                        + _closed_hint(item.reason), reason=item.reason)
                if item is _CLOSED:
                    raise RelayUnreachable(
                        self._closed_reason or "relay connection lost")
                inspected += 1
                ev = self._parse_event(item)
                if ev is not None:
                    events.append(ev)
                else:
                    discarded += 1
                # Legacy callers retain their accepted-event ceiling. Explicitly
                # budgeted reads count invalid events too, before signature work.
                used = inspected if max_events is not None else len(events)
                if used >= ceiling:
                    truncated = True
                    log.warning(
                        "query to %s stopped after inspecting %d events and accepting %d. "
                        "The response is INCOMPLETE; narrow the filter",
                        self.url, inspected, len(events))
                    break
        finally:
            self._forget_subscription(sid)
            try:
                await self._ws.send(json.dumps(["CLOSE", sid]))
            except Exception:
                pass  # The connection may already be closed; local cleanup still succeeded.
        return QueryResult(events, inspected, discarded, truncated,
                           max(0, self._dropped_events - dropped_before))

    async def subscribe(self, filters: dict | list[dict]):
        """Yield an endless live stream of valid events, skipping EOSE markers."""
        filters = [filters] if isinstance(filters, dict) else filters
        sid = secrets.token_hex(8)
        queue: asyncio.Queue = self._new_queue()
        self._register_subscription(sid, filters, queue)
        await self._safe_send(["REQ", sid, *filters])
        try:
            while True:
                item = await queue.get()
                if item is _EOSE:
                    continue
                if isinstance(item, _ClosedByRelay):
                    raise RelayError(
                        f"relay {self.url} closed the subscription: {item.reason}"
                        + _closed_hint(item.reason), reason=item.reason)
                if item is _CLOSED:
                    raise RelayError(self._closed_reason or "connection lost")
                ev = self._parse_event(item)
                if ev is not None:
                    yield ev
        finally:
            self._forget_subscription(sid)
            try:
                await self._ws.send(json.dumps(["CLOSE", sid]))
            except Exception:
                pass  # The connection may already be closed; local cleanup still succeeded.



def _offer_keeping_sentinel(queue: asyncio.Queue, item, sentinel) -> None:
    """Enqueue without waiting, evicting the oldest EVENT from a bounded queue.

    Two independent review findings caused permanent hangs for the same reason: the
    end-of-stream marker lived in the same lossy queue as events.

    FAN-008: blindly evicting the oldest item discarded the completion marker of an
    already-finished client. Both sources ended, but the consumer waited for a second
    marker that no longer existed.

    FAN-009: waiting for room to enqueue the completion marker blocked on a full queue
    that nobody was consuming, so stream shutdown hung until timeout.

    Hence the rule: **terminal state must not share a lossy queue with ordinary data on
    equal terms**. The marker cannot be evicted and is inserted without waiting; room
    is made by dropping an event. A full queue contains thousands of events but at most
    one marker per node, so room is always available.
    """
    while True:
        try:
            queue.put_nowait(item)
            return
        except asyncio.QueueFull:
            rescued = []
            while True:
                try:
                    oldest = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if oldest is sentinel:
                    rescued.append(oldest)
                    continue
                break                      # Exactly one event was dropped.
            for saved in rescued:
                queue.put_nowait(saved)


class FanOutRelayClient:
    """Read from ALL configured nodes and merge results instead of reading only the first.

    A4A nodes neither communicate nor replicate data among themselves: a message exists
    exactly where it was stored. Redundancy therefore comes from the sender placing an
    envelope on several advertised recipient nodes and the recipient reading all of
    them. While readers inspected only the first node, redundancy was written but never
    used: losing one node meant losing uncollected messages, and a publication on a
    European node was invisible to a reader using an Asian one.

    The interface mirrors `RelayClient` so calling code does not change: thirty-two
    sites in `Agent` use `self.relay` and continue to work unchanged.

    Result ordering is conservative: events from the first node in its order, followed
    by events it did not have. With a single node, behavior is byte-for-byte identical
    to the previous implementation; this is intentional so the change has no effect on
    single-node deployments.

    `url` is the FIRST node's address. It remains the storage key where a key must be
    node-specific: a receiver cursor tracks `first_seen`, which is local to a node, so
    sharing one cursor across nodes is meaningless. Changing the key would orphan rows
    already stored.

    The dialogue log NO LONGER relies on this address; it stores a fingerprint of the
    complete configured set (`dialogue._relay_fingerprint`). Comparing only the first
    node answered the wrong question—"is the first list item unchanged?" rather than
    "is this the same set?"—so reordering addresses left prepared messages unsent and
    adding a node went unnoticed.

    REST history catch-up is no longer single-node either: the receiver has one cursor
    per node (`InboxReceiver.histories`). Until 2026-09-08 this text claimed the
    opposite—"it remains single-node; that is separate work"—after the work was already
    complete.
    """


    def __init__(self, urls: list[str], **kwargs):
        if not urls:
            raise ValueError("at least one relay address is required")
        # IDENTICAL addresses are collapsed BEFORE any counting. Otherwise the same node
        # listed twice provided two "copies" in one store: losing the node left zero
        # copies even though min_accepted=2 had succeeded. An external reviewer found
        # this by measurement, not reasoning (HEAL-004, second pass).
        #
        # WHAT THIS DOES NOT PROVIDE: distinct names may still point to one machine or
        # data center. Different ADDRESSES do not imply independent storage. Deduplication
        # removes only the obvious case.
        seen, unique = set(), []
        for u in urls:
            key = _canonical_relay_key(u)
            if key in seen:
                log.warning("address %s is listed more than once; duplicate copies do not count", key)
                continue
            seen.add(key)
            unique.append(u)
        if len(unique) > self.MAX_RELAYS:
            raise ValueError(
                f"at most {self.MAX_RELAYS} nodes are allowed because the aggregate raw-event "
                f"inspection budget grows with their count; received {len(unique)}")
        self.clients = [RelayClient(u, **kwargs) for u in unique]
        self.url = self.clients[0].url

    async def connect(self) -> None:
        """Connect to every node. One success is enough; the others may be under maintenance."""
        results = await asyncio.gather(*(c.connect() for c in self.clients),
                                       return_exceptions=True)
        failures = [r for r in results if isinstance(r, BaseException)]
        if len(failures) == len(self.clients):
            # Preserve the original error: it contains the node's verbatim rejection
            # reason, which a caller such as an MCP wrapper uses to form its own advice.
            raise failures[0]
        for client, result in zip(self.clients, results):
            if isinstance(result, BaseException):
                log.warning("relay %s is unavailable: %s", client.url, result)

    async def aclose(self) -> None:
        await asyncio.gather(*(c.aclose() for c in self.clients), return_exceptions=True)

    async def publish(self, event: Event, *, replay_on_reconnect: bool = True,
                      min_accepted: int = 1) -> int:
        """Publish to every node and return the NUMBER THAT ACCEPTED the event.

        Why a count rather than "success": A4A nodes do not exchange data, so event
        durability depends on how many nodes accepted it. n copies survive the loss of
        n-1 nodes, not n. Acceptance is also weaker than PERSISTENCE: retention may evict
        an accepted event or recovery may lose it. The previous version returned nothing
        and treated one accepting node as success; an event on ONE node looked exactly
        like an event on three, so a three-node list appeared to provide redundancy that
        did not exist.

        An external reviewer demonstrated this experimentally (HEAL-004): A accepted,
        B and C rejected, the call succeeded, then losing A left zero copies.

        `min_accepted` serves callers for whom redundancy is required rather than merely
        desirable: they can ENFORCE it instead of hoping for it. The default is 1, which
        preserves prior behavior for callers that ignore the count.

        A publication still cannot disappear silently: zero acceptances is an error.
        """
        if type(min_accepted) is not int or min_accepted < 1:
            raise ValueError("min_accepted must be an integer of at least 1")
        if min_accepted > len(self.clients):
            # Reject an impossible requirement BEFORE writing to the network. The prior
            # version published first and failed afterward, leaving a network copy that
            # the caller believed did not exist.
            raise ValueError(
                f"{min_accepted} copies are required, but only {len(self.clients)} distinct "
                f"nodes are configured; the requirement cannot be satisfied")
        results = await asyncio.gather(
            *(c.publish(event, replay_on_reconnect=replay_on_reconnect) for c in self.clients),
            return_exceptions=True)
        failures = [(c.url, r) for c, r in zip(self.clients, results) if isinstance(r, BaseException)]
        accepted = len(self.clients) - len(failures)
        if not accepted:
            # The original node failure carries both its verbatim reason and an SDK hint
            # for the caller. Wrapping it here would erase both.
            raise failures[0][1]
        for url, error in failures:
            log.warning("relay %s did not accept event %s: %s", url, event.id[:16], error)
        if accepted < len(self.clients):
            # State partial redundancy as a NUMBER rather than expecting callers to
            # infer it from failure strings; a caller unaware of the issue will not know
            # that subtraction is required.
            log.warning("event %s was accepted by %d of %d nodes; redundancy is below configuration",
                        event.id[:16], accepted, len(self.clients))
        if accepted < min_accepted:
            raise InsufficientCopies(event.id, accepted, min_accepted, len(self.clients))
        return accepted

    #: Wait limit for the ENTIRE fan-out, in seconds.
    #:
    #: Every node has its own limit (10 seconds). The fan-out queried them concurrently
    #: but waited for the last one, so a single stuck node added its ten seconds to EVERY
    #: read. Performance could only be restored by removing it manually.
    #:
    #: Why this is not a quorum, despite that being the obvious first idea: A4A nodes do
    #: not exchange data, and an event may exist on exactly one node. "A majority
    #: answered, do not wait for the rest" would silently lose messages on a lagging
    #: node and look exactly like "there are no messages."
    #:
    #: Therefore this is a deadline rather than a quorum. A late node is NOT counted as
    #: responding, so the caller sees reduced coverage. Completeness is not promised;
    #: its absence is reported.
    read_deadline: float = 5.0

    #: Aggregate INSPECTION budget per query, in events.
    #:
    #: The real consumed resource is not the number of addresses but signature
    #: verification for every raw event. The old "at most five nodes" ceiling roughly
    #: approximated this work: without it, aggregate verification grew linearly with the
    #: list length and the protection could be bypassed by adding addresses.
    #:
    #: That approximation blocked legitimate behavior. Self-regeneration requires
    #: reading the UNION of advertised nodes and a recently retired node: five plus one
    #: is six, which the old rule prohibited (HEAL-006). Silently raising the ceiling
    #: would have diluted the protection itself.
    #:
    #: The budget therefore applies to the ENTIRE query and is divided among nodes.
    #: Aggregate work stays the same with two nodes or ten. The cost is explicit: a
    #: wider fan-out gives each node a smaller window, and result truncation is exposed
    #: by a flag rather than hidden. None means "read the global limit at call time."
    #: Capturing the value at class creation would freeze it forever: tests replacing
    #: the global limit would not reach it, and the fan-out would request more from a
    #: node than the node accepts.
    read_budget: int | None = None

    #: The CONNECTION count ceiling protects a different resource from inspection.
    #:
    #: The budget above limits parsing work, but each node also costs a socket, a TLS
    #: handshake, and a slot waiting for the read deadline. Division does not reduce
    #: those costs, so they retain a separate, independently justified ceiling.
    MAX_RELAYS: int = 16

    def _per_relay_ceiling(self, nodes: int) -> int:
        """Return one node's share of the inspection budget, never below one event."""
        budget = MAX_EVENTS_PER_QUERY if self.read_budget is None else self.read_budget
        if nodes > budget:
            raise ValueError(
                f"{nodes} nodes with an inspection budget of {budget} leave less than "
                "one event per node; this fan-out is meaningless")
        return max(1, budget // nodes)

    async def _gather(self, call):
        tasks = [asyncio.ensure_future(call(c)) for c in self.clients]
        done, pending = await asyncio.wait(tasks, timeout=self.read_deadline)
        for task in pending:
            task.cancel()
        if pending:
            # Cancelled tasks need not be awaited for results, but they must not be
            # discarded silently. A node that missed the deadline must be named;
            # otherwise reduced coverage looks like "those nodes had nothing."
            await asyncio.gather(*pending, return_exceptions=True)
        results = []
        for client, task in zip(self.clients, tasks):
            if task in done:
                results.append(task.exception() or task.result())
            else:
                log.warning("relay %s missed the %.1fs deadline and was excluded from this read",
                            client.url, self.read_deadline)
                results.append(asyncio.TimeoutError(
                    f"relay {client.url} did not respond within {self.read_deadline}s"))
        good, unavailable = [], []
        for client, result in zip(self.clients, results):
            if isinstance(result, (RelayError, OSError, asyncio.TimeoutError)):
                # One unreachable node must not hide messages stored on other nodes.
                log.warning("relay %s did not answer the query: %s", client.url, result)
                unavailable.append(result)
            elif isinstance(result, BaseException):
                # A caller error (invalid limit or filter) is not a node failure.
                # Swallowing it here would report "network unavailable" when the actual
                # problem is an invalid argument.
                raise result
            else:
                good.append(result)
        if not good:
            # Preserve the reason: readers need the actual node failure, not our summary.
            raise unavailable[0]
        return good

    @staticmethod
    def _merge(batches: list[list[Event]], ceiling: int) -> tuple[list[Event], bool]:
        merged: list[Event] = []
        seen: set[str] = set()
        for batch in batches:
            for event in batch:
                if event.id in seen:
                    continue
                seen.add(event.id)
                merged.append(event)
                if len(merged) >= ceiling:
                    # The caller set this ceiling; returning more would violate its contract.
                    return merged, True
        return merged, False

    async def query(self, filters: dict | list[dict], *, max_events: int | None = None) -> list[Event]:
        # Reject an invalid limit HERE, before any network access. It used to reach the
        # node and fail there; after per-node shares were introduced it was silently
        # CLAMPED to the valid range, and the caller error surfaced as "no connection,"
        # a network problem that did not exist. Clamping cannot repair an invalid argument.
        if max_events is not None and (type(max_events) is not int
                                       or not 1 <= max_events <= MAX_EVENTS_PER_QUERY):
            raise ValueError(f"max_events must be 1..{MAX_EVENTS_PER_QUERY}")
        share = self._per_relay_ceiling(len(self.clients))
        if max_events is not None:
            share = min(share, max_events)
        batches = await self._gather(lambda c: c.query(filters, max_events=share))
        if len(batches) == 1:
            return batches[0]   # Single-node invariant: return the result untouched.
        ceiling = MAX_EVENTS_PER_QUERY if max_events is None else max_events
        return self._merge(batches, ceiling)[0]

    async def query_bounded(self, filters: dict | list[dict], *, max_events: int) -> QueryResult:
        # The limit check is intentionally repeated here. A single client rejects it
        # before any network access, and fan-out must behave the same way; otherwise an
        # invalid argument would look like relay unavailability.
        if type(max_events) is not int or not 1 <= max_events <= MAX_EVENTS_PER_QUERY:
            raise ValueError(f"max_events must be 1..{MAX_EVENTS_PER_QUERY}")
        share = min(self._per_relay_ceiling(len(self.clients)), max_events)
        results = await self._gather(lambda c: c.query_bounded(filters, max_events=share))
        if len(results) == 1:
            # Single-node invariant: return the result as-is rather than rebuilding it.
            # Rebuilding would require every QueryResult field and break providers of
            # partial results; more importantly, it would violate the promise that
            # nothing changes for one node.
            return results[0]
        events, over_ceiling = self._merge([r.events for r in results], max_events)
        return QueryResult(
            events=events,
            inspected_events=sum(r.inspected_events for r in results),
            discarded_invalid_events=sum(r.discarded_invalid_events for r in results),
            # Truncation by any node or by merging means the result is truncated.
            # Reporting otherwise would promise completeness that does not exist.
            truncated=over_ceiling or any(r.truncated for r in results),
            connection_dropped_events=sum(r.connection_dropped_events for r in results),
            relays_responded=len(results),
        )

    async def subscribe(self, filters: dict | list[dict]):
        """Merge live streams from all nodes, deduplicating by event identifier.

        One node's failure does not end the stream: fan-out exists to survive losing a
        node, not to fail with it. The stream ends only after all nodes go silent.
        """
        if len(self.clients) == 1:
            # Single-node invariant. Merging is unnecessary here and used to CHANGE
            # behavior: an unbounded buffer replaced the client's bounded one, and a
            # subscription failure became a silent end of stream. Return the stream as
            # is, including its oldest-item eviction and exceptions.
            async for event in self.clients[0].subscribe(filters):
                yield event
            return

        # A buffer limit is mandatory. Without one, a slow consumer accumulates events
        # without bound while a single client evicts them. Reviewer measurement: 25,001
        # events produced, one yielded, and 25,001 left in the queue.
        queue: asyncio.Queue = asyncio.Queue(maxsize=RelayClient.MAX_QUEUED_EVENTS)
        done = object()
        failures: list[BaseException] = []

        def offer(item):
            _offer_keeping_sentinel(queue, item, done)

        async def pump(client):
            try:
                async for event in client.subscribe(filters):
                    offer(event)
            except asyncio.CancelledError:
                raise
            except BaseException as exc:      # noqa: BLE001 — preserve the reason; see below
                log.warning("subscription to %s was interrupted: %s", client.url, exc)
                failures.append(exc)
            finally:
                offer(done)

        tasks = [asyncio.create_task(pump(c)) for c in self.clients]
        known: set[str] = set()
        finished = 0
        try:
            while finished < len(tasks):
                item = await queue.get()
                if item is done:
                    finished += 1
                    continue
                if item.id in known:
                    continue
                known.add(item.id)
                if len(known) > 20_000:
                    known.clear()  # Bound memory so a spam stream cannot grow forever.
                    known.add(item.id)
                yield item
            if len(failures) == len(tasks):
                # Every node failed. A silent end of stream would look like "there are
                # no more messages" even if the subscription was rejected (for example,
                # "blocked: ..."). Preserve the original failure instead of summarizing it.
                raise failures[0]
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
