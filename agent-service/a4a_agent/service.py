"""Service loop: receive -> facts -> policy -> reply, escalation, or archive.

Ordering is essential: policy runs BEFORE anyone examines the text. A stranger
costs the owner neither attention nor tokens.

PLAN DEVIATIONS (2026-08-28), both discovered while writing tests:

1. **Processed-event log.** Events remain on the relay. Without durable memory,
   every pass would answer every message again and repeatedly wake the owner for
   the same request. The identity directory holds a log that survives restarts.
2. **Per-sender reply limit.** The design requires this because the relay has no
   per-key limit, only global ``messages_per_sec``. Without it, one key could force
   publication of one event for every question it sends.
"""
import asyncio
import json
import logging
import os
import time

from . import facts, identity, notify, responder
from .policy import decide

log = logging.getLogger(__name__)

_LOG_CAP = 5000  # Months of history while keeping the file small.


class ProcessedLog:
    """Processed event IDs ordered by age, with the oldest evicted first."""

    def __init__(self, path=None, cap: int = _LOG_CAP):
        self.path = path or (identity.identity_dir() / "processed.json")
        self.cap = cap
        self._ids: list[str] = []
        self._seen: set[str] = set()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            # The file may contain null, an object, or a string. Validate its type
            # instead of assuming it (a 2026-08-28 review found this crash).
            if isinstance(data, list):
                self._ids = [x for x in data if isinstance(x, str)]
                self._seen = set(self._ids)
        except (OSError, ValueError, TypeError):
            pass  # Missing or corrupt file: start with an empty log.

    def __contains__(self, event_id: str) -> bool:
        return event_id in self._seen

    def add(self, event_id: str) -> None:
        if event_id in self._seen:
            return
        self._ids.append(event_id)
        self._seen.add(event_id)
        if len(self._ids) > self.cap:
            dropped, self._ids = self._ids[:-self.cap], self._ids[-self.cap:]
            self._seen.difference_update(dropped)

    def save(self) -> None:
        # Write atomically. If the process stops during a direct overwrite, a
        # truncated file would cause duplicate replies and owner notifications
        # after restart (review finding 2026-08-28).
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._ids), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as e:
            # The log is an optimization rather than a critical path, so failure
            # must not crash the service. It must not be silent either, because a
            # restart would resend replies (review 2026-08-28, A13).
            log.warning("processed-event log was not saved: %s", e)


class ReplyThrottle:
    """Track scripted replies per sender in the current time window.

    Streaming mode has no polling cycle, so a per-cycle limit becomes a time-window
    limit. Otherwise it either never resets or never constrains anything.
    """

    def __init__(self, limit: int, window_seconds: int, total_limit: int | None = None):
        self.limit = limit
        self.window = window_seconds
        # Global stream cap: rotating keys bypasses a per-key limit for free.
        self.total_limit = total_limit
        self._counts: dict[str, tuple[float, int]] = {}
        self._total: tuple[float, int] = (0.0, 0)

    def allow(self, sender: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if self.total_limit is not None:
            t_started, t_count = self._total
            if now - t_started >= self.window:
                t_started, t_count = now, 0
            if t_count >= self.total_limit:
                self._total = (t_started, t_count)
                return False
            self._total = (t_started, t_count + 1)
        started, count = self._counts.get(sender, (now, 0))
        if now - started >= self.window:
            started, count = now, 0
        if count >= self.limit:
            self._counts[sender] = (started, count)
            return False
        self._counts[sender] = (started, count + 1)
        return True


#: How often a running agent rechecks its mandate.
#:
#: Mandates used to be issued only at STARTUP. An agent running beyond the renewal
#: window eventually crossed the expiry boundary and the relay rejected everything
#: it published. Subscriptions still worked, so it read incoming messages while
#: replies silently failed (internal audit 2026-08-29).
MANDATE_CHECK_INTERVAL_SECONDS = 12 * 3600


async def _renew_mandate_loop(agent, owner_keys, *, interval_seconds: float,
                              stop: asyncio.Event, name: str = "A4A project agent"):
    """Periodically renew the agent mandate while the service is running."""
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_seconds)
            return
        except asyncio.TimeoutError:
            pass
        try:
            await agent.ensure_registered(owner_keys, name=name)
        except Exception as e:  # noqa: BLE001 - connection loss must not stop the service
            log.warning("mandate renewal failed (%s); retrying next cycle", e)


class ProjectAgent:
    def __init__(self, agent, cfg, notifier, processed=None):
        self.agent = agent
        self.cfg = cfg
        self.notifier = notifier  # callable(text) -> bool
        self.processed = processed if processed is not None else ProcessedLog()

    async def _handle_request(self, req, cache) -> str:
        """Handle one connection request and return its outcome."""
        event_id = req["event"].id
        if event_id in self.processed:
            return "skipped"
        sender = req["from_pubkey"]
        f = await facts.collect(self.agent, sender, self.cfg.policy, cache)
        if not f.complete:
            # No complete facts means no basis for a verdict. Do not mark the
            # request processed so a later pass can retry it.
            log.info("request from %s deferred: facts unavailable", sender[:12])
            return "deferred"
        verdict = decide(f, self.cfg.policy)
        if not verdict.allow:
            self.processed.add(event_id)
            # Deliberately avoid waking the owner for a rejected stranger, but keep
            # an operational trace. Without it, the public-address operator cannot
            # tell whether anyone tried to connect or whether policy rejects all
            # requests (finding 113, reproduced live on 2026-09-04).
            log.info("request from %s archived: %s", sender[:12],
                     "; ".join(verdict.reasons) or "no policy condition was met")
            return "archived"
        # Mark processed ONLY after confirmed delivery. Otherwise, a Telegram
        # failure could silently destroy the only policy-approved request; see
        # test_failed_notification_is_retried_not_lost.
        if await self._notify(notify.format_escalation(
                sender, req["intro"], verdict.reasons)):
            self.processed.add(event_id)
            log.info("request from %s escalated to the owner", sender[:12])
            return "escalated"
        log.warning("request from %s NOT delivered to owner; retrying", sender[:12])
        return "undelivered"

    async def process_connection_requests(self) -> dict:
        report = {"escalated": 0, "archived": 0, "undelivered": 0,
                  "deferred": 0}
        cache = facts.TrustGraphCache()  # One trust graph per pass, not per sender.
        for req in await self.agent.get_connection_requests():
            outcome = await self._handle_request(req, cache)
            if outcome in report:
                report[outcome] += 1
        self.processed.save()
        return report

    async def _handle_message(self, msg, cache, throttle) -> str:
        """Handle one incoming message and return its outcome."""
        event_id = msg["event"].id
        if event_id in self.processed:
            return "skipped"
        sender = msg["from_pubkey"]
        reply = responder.answer(msg["content"])
        if reply is not None:
            # Do NOT mark a throttled question processed. Otherwise it will never
            # receive an answer after the window opens or the service restarts,
            # appearing to the sender as a swallowed question (review, A6).
            if not throttle.allow(sender):
                return "throttled"
            try:
                # Reply in the SAME mode. A sender using wrapped messages chose to
                # hide metadata; an unwrapped reply would reveal the relationship
                # they asked to conceal (review 2026-08-28, S2).
                await self.agent.send_private_message(
                    sender, reply, wrap=msg.get("wrapped", False))
            except Exception as e:
                # The relay may not return OK before timeout. Neither swallow the
                # message nor terminate the subscription (review, A7).
                log.warning("reply to %s failed (%s); retrying later", sender[:12], e)
                return "undelivered"
            self.processed.add(event_id)
            return "answered"
        f = await facts.collect(self.agent, sender, self.cfg.policy, cache)
        if not f.complete:
            return "deferred"  # See the comment in _handle_request.
        verdict = decide(f, self.cfg.policy)
        if not verdict.allow:
            self.processed.add(event_id)
            return "archived"
        if await self._notify(notify.format_escalation(
                sender, msg["content"], verdict.reasons)):
            self.processed.add(event_id)  # Only after confirmed delivery.
            return "escalated"
        return "undelivered"

    async def _notify(self, text: str) -> bool:
        """Notify the owner without blocking the event loop.

        ``notify.send`` is synchronous and uses httpx with a 15-second timeout.
        Calling it directly from this coroutine could stall the websocket reader,
        whose timeout is shorter, so a slow Telegram request could stop message
        intake entirely (review finding 2026-08-28).
        """
        return await asyncio.to_thread(self.notifier, text)

    def _throttle(self):
        return ReplyThrottle(self.cfg.max_replies_per_sender,
                             self.cfg.reply_window_seconds,
                             total_limit=self.cfg.max_replies_total)

    async def process_messages(self) -> dict:
        report = {"answered": 0, "escalated": 0, "throttled": 0,
                  "undelivered": 0, "deferred": 0}
        cache = facts.TrustGraphCache()  # One trust graph per pass, not per sender.
        throttle = self._throttle()
        since = int(time.time()) - self.cfg.inbox_window_days * 86400
        for msg in await self.agent.read_private_messages(since=since):
            outcome = await self._handle_message(msg, cache, throttle)
            if outcome in report:
                report[outcome] += 1
        self.processed.save()
        return report

    async def serve(self, stop: asyncio.Event | None = None) -> None:
        """Stream mode: process the backlog once, then use LIVE subscriptions.

        Polling the relay every 30 seconds costs four times more than the worker
        agent's messages (2026-08-28 model): each empty update check is small, but
        nearly one hundred thousand occur monthly. Subscriptions remove that cost.
        """
        # Log startup-pass reports: this is the only record of what accumulated
        # during downtime (finding 113).
        log.info("startup pass, requests: %s", await self.process_connection_requests())
        log.info("startup pass, messages: %s", await self.process_messages())

        cache = facts.TrustGraphCache()
        throttle = self._throttle()
        stop = stop or asyncio.Event()

        async def keep_alive(name, subscribe, handle):
            """Keep a subscription alive across connection interruptions.

            SDK reconnection makes three attempts and then raises. Without this
            loop, the public address would silently stop responding until manual
            intervention (review finding 2026-08-28). A process supervisor remains
            useful but is not required for every transient interruption.
            """
            while not stop.is_set():
                try:
                    async for item in subscribe():
                        await handle(item)
                        self.processed.save()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    log.warning("subscription '%s' stopped (%s); reconnecting in "
                                "%s seconds", name, e, self.cfg.reconnect_delay_seconds)
                    await asyncio.sleep(self.cfg.reconnect_delay_seconds)

        def window():
            """Calculate the window when subscribing, not when the service starts.

            After a long outage, a new subscription must not fetch an unbounded
            historical backlog.
            """
            return int(time.time()) - self.cfg.inbox_window_days * 86400

        async def messages():
            await keep_alive("messages",
                             lambda: self.agent.subscribe_private_messages(since=window()),
                             lambda m: self._handle_message(m, cache, throttle))

        async def requests():
            await keep_alive("requests",
                             lambda: self.agent.subscribe_connection_requests(since=window()),
                             lambda r: self._handle_request(r, cache))

        tasks = [asyncio.create_task(messages()), asyncio.create_task(requests()),
                 asyncio.create_task(stop.wait())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        errors = []
        for t in done:
            error = t.exception()
            if error is not None:
                errors.append(error)
        if errors:
            # Retrieve every completed task exception before propagating the first.
            # Otherwise simultaneous subscription failures produce an unobserved
            # background exception and obscure the primary operational failure.
            raise errors[0]
