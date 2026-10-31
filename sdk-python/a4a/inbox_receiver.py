"""Receive without an LLM: bounded reception-history pages plus WS wake hints."""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import sqlite3
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx

from .event import Event, is_canonical_pubkey
from .inbox import (InboxAuthorizationUnavailable, InboxConflict, InboxError,
                    InboxFull, InboxPolicyChanged,
                    InboxStorageError, NoticeTracker)
from .inbox_lock import receiver_lock
from .relay import RelayError
from .relay import RelayClient

log = logging.getLogger(__name__)

#: Failures that belong to US rather than a relay and cannot be repaired by another
#: source. They must be listed explicitly because remote history failures inherit
#: the same `InboxError` and cannot be distinguished by their base class.
_LOCAL_FAILURES = (InboxFull, InboxConflict, InboxPolicyChanged,
                   InboxAuthorizationUnavailable, InboxStorageError, sqlite3.Error)
MAX_PAGE_BYTES = 2 * 1024 * 1024
PAGE_SIZE = 250


async def owner_mandates_for_senders(agent, allowed_owners, candidates):
    """Resolve current signed mandates for candidate agent keys, without caching."""
    candidates = set(candidates)
    if not candidates or not allowed_owners:
        return {}
    try:
        await agent.relay.connect()
        mandates = await agent.active_owner_mandates(set(candidates), allowed_owners)
    except (RelayError, ValueError) as exc:
        raise InboxAuthorizationUnavailable(
            "owner authorization unavailable; cursor and lease retained") from exc
    finally:
        await agent.relay.aclose()
    return mandates


async def authorized_sender_keys(agent, exact_peers, allowed_owners, candidates):
    """Resolve owner trust before a queue operation; never cache revocable authority."""
    permitted = set(exact_peers)
    mandates = await owner_mandates_for_senders(
        agent, allowed_owners, set(candidates) - permitted)
    return permitted | mandates.keys()


class InboxHistory:
    """Addressed A4A inbox page=2, not the notarization /v1/history endpoint."""

    def __init__(self, relay_url, recipient, *, fetch=None):
        if not is_canonical_pubkey(recipient):
            raise InboxError("inbox history needs an exact recipient public key")
        self.recipient = recipient
        try:
            parts = urlsplit(relay_url)
            valid = parts.scheme in ("ws", "wss") and parts.hostname and not (
                parts.username or parts.password or parts.query or parts.fragment)
            parts.port
        except ValueError as exc:
            raise InboxError("invalid inbox relay URL") from exc
        if not valid:
            raise InboxError("inbox needs an explicit ws/wss relay URL without credentials, query or fragment")
        self.base = urlunsplit(("https" if parts.scheme == "wss" else "http",
                               parts.netloc, parts.path.rstrip("/"), "", ""))
        self.fetch = fetch or self._fetch

    async def _fetch(self, url):
        # A cancellable async socket, not a worker thread which survives EOF.
        # Reject compression before reading: decoding must not bypass the byte cap.
        async with asyncio.timeout(15):
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=15,
                                         headers={"User-Agent": "a4a-inbox/1", "Accept-Encoding": "identity"}) as client:
                async with client.stream("GET", url) as response:
                    if response.status_code != 200:
                        raise InboxError(f"inbox history HTTP status {response.status_code}; cursor retained")
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise InboxError("compressed inbox history refused")
                    length = response.headers.get("content-length")
                    if length is not None and (not re.fullmatch(r"[0-9]{1,12}", length) or int(length) > MAX_PAGE_BYTES):
                        raise InboxError("history page exceeds size limit or has invalid length")
                    raw = bytearray()
                    async for chunk in response.aiter_raw(chunk_size=65536):
                        if len(raw) + len(chunk) > MAX_PAGE_BYTES:
                            raise InboxError("history page exceeds 2 MiB")
                        raw.extend(chunk)
                    return raw.decode("utf-8")

    async def page(self, cursor):
        stamp, event_id = cursor
        if type(stamp) is not int or not 0 <= stamp <= 2**63 - 1 or (event_id and not re.fullmatch(r"[0-9a-f]{64}", event_id)):
            raise InboxError("invalid inbox history cursor")
        url = self.base + "/v1/inbox?" + urlencode({"recipient": self.recipient, "after": stamp, "after_id": event_id, "limit": PAGE_SIZE, "page": 2})
        try:
            body = await self.fetch(url)
            if len(body.encode("utf-8")) > MAX_PAGE_BYTES:
                raise InboxError("history page exceeds 2 MiB")
            data = json.loads(body)
            if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 2:
                raise InboxError("relay does not support A4A inbox page=2")
            if data.get("recipient") != self.recipient:
                raise InboxError("inbox history recipient is missing or incorrect")
            rows = data.get("rows")
            if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
                raise InboxError("history page has invalid row count")
            output, previous = [], cursor
            for row in rows:
                first_seen = row["first_seen"]
                event = Event.model_validate(row["event"])
                if type(first_seen) is not int or not 0 <= first_seen <= 2**63 - 1 or not re.fullmatch(r"[0-9a-f]{64}", event.id):
                    raise InboxError("history row has invalid position")
                position = (first_seen, event.id)
                if position <= previous:
                    raise InboxError("history page does not advance strictly")
                previous = position
                output.append((first_seen, event))
            expected = {"first_seen": previous[0], "id": previous[1]} if output else None
            if "next_cursor" not in data or data["next_cursor"] != expected:
                raise InboxError("history cursor does not match last row")
            return output
        except InboxError:
            raise
        except Exception as exc:
            # The peer controls HTTP bodies and errors; never include them in logs. But the
            # EXCEPTION TYPE is ours, not theirs, and naming it costs nothing while turning
            # one opaque verdict into a diagnosable one.
            #
            # Why this matters, from a real incident on 2026-09-15: an agent saw
            # "unavailable or malformed" and concluded its relay was a broken old build.
            # The relay was fine and identical to production; the cause was elsewhere. One
            # generic message made three distinct failures — bad JSON, a rejected status, a
            # schema mismatch — indistinguishable, and the wrong repair was nearly applied
            # to a shared node.
            raise InboxError(
                f"inbox history unavailable or malformed ({type(exc).__name__})") from exc


class InboxReceiver:
    def __init__(self, agent, store, allowed_senders, *, start_after,
                 history=None, max_pages=50, poll_seconds=30, ack_on_receipt=False,
                 allowed_owners=None, intake_mode=None, blocked_senders=None,
                 inband_authorizer=None):
        if type(max_pages) is not int or not 1 <= max_pages <= 100:
            raise InboxError("invalid history work budget")
        if type(poll_seconds) is not int or not 5 <= poll_seconds <= 60:
            raise InboxError("history recovery interval must be 5..60 seconds")
        self.agent, self.store, self.allowed_senders = agent, store, allowed_senders
        self.allowed_owners = allowed_owners or (lambda: frozenset())
        self.intake_mode = intake_mode or (lambda: "closed")
        self.blocked_senders = blocked_senders or (lambda: frozenset())
        self.inband_authorizer = inband_authorizer
        # Opt-in per mailbox. Without it the sender hears nothing until someone
        # completes the work, which on 23.09.2026 left a pilot sender retrying into
        # an hour of silence although both letters had arrived within seconds.
        self.ack_on_receipt = ack_on_receipt is True
        # The receiver reads from ALL of the agent's relays, each with its own cursor.
        #
        # A history cursor is `first_seen`, the time a SPECIFIC relay received the
        # event. This value is local: applying one relay's cursor to another would
        # denote a different instant. The original single-relay receiver therefore
        # reflected an apparent storage constraint rather than mere omission. No
        # schema change was actually needed: the cursor table is already keyed by
        # relay, and messages are deduplicated by sender plus delivery ID, so fetching
        # one envelope from two relays does not duplicate it.
        #
        # An independent review found this as FAN-001 after service documentation had
        # already claimed that the receiver read from all relays. At that time the
        # claim was false.
        clients = getattr(agent.relay, "clients", None)
        self.urls = [c.url for c in clients] if clients else [agent.relay.url]
        #: The first relay remains the stable key used to bind inbox policy and name
        #: dialogue-journal records.
        self.url = self.urls[0]
        # An injected history implementation (tests and custom integrations) belongs
        # to the first relay. Replacing every relay transport with one object would
        # read the same source repeatedly and mistake that for redundancy.
        self.histories = {url: (history if url == self.url and history else
                                InboxHistory(url, agent.pubkey)) for url in self.urls}
        self.history = self.histories[self.url]
        self.max_pages, self.poll_seconds = max_pages, poll_seconds
        for url in self.urls:
            self.store.bind_relay(url, start_after)
        self.hint = asyncio.Event()
        self.stream_connected = False

    async def sync_once(self):
        with receiver_lock(self.store.path.parent):
            return await self._sync_once()

    async def notice_once(self, *, interval=60, per_hour=12, on_tick=None):
        """One owned CLI pass; even health cleanup must not race another watcher."""
        with receiver_lock(self.store.path.parent):
            try:
                await self._sync_once()
                if on_tick is not None:
                    await on_tick()
                return self.store.notice(await self._eligible_senders(), interval=interval,
                                         per_hour=per_hour)
            except InboxPolicyChanged:
                self.store.set_health("failed")
                raise
            except InboxError:
                self.store.set_health("failed")
                raise
            finally:
                if self.store.health().get("state") not in ("failed", "backlog"):
                    self.store.set_health("stopped")

    def _policy_senders(self):
        try:
            return self.allowed_senders()
        except InboxPolicyChanged:
            raise
        except InboxError as exc:
            # A local policy failure is not a recoverable relay outage.
            raise InboxPolicyChanged("inbox sender policy unavailable") from exc

    def _policy_owners(self):
        try:
            return self.allowed_owners()
        except InboxPolicyChanged:
            raise
        except InboxError as exc:
            raise InboxPolicyChanged("inbox owner policy unavailable") from exc

    async def _eligible_senders(self):
        peers = self._policy_senders()
        owners = self._policy_owners()
        permitted = await authorized_sender_keys(
            self.agent, peers, owners,
            self.store.pending_sender_keys())
        if peers != self._policy_senders() or owners != self._policy_owners():
            raise InboxPolicyChanged("inbox authorization changed during owner lookup")
        return permitted

    async def _sync_once(self):
        """Catch up history on EVERY relay, each with its own cursor.

        One relay's failure does not cancel catch-up on the others. Otherwise, one
        offline relay would hide messages held by the rest, just as before fan-out.
        Failure is reported only when NO relay responded; reporting an outage after
        messages were received would misrepresent inbox health.
        """
        added = 0
        backlog = False
        failures = []
        for url in self.urls:
            try:
                got, hit_budget = await self._sync_relay(url)
                added += got
                backlog = backlog or hit_budget
            except _LOCAL_FAILURES:
                # A local failure—inbox capacity, policy change, cursor conflict, or
                # database error—is NOT repaired by another relay and is not history
                # unavailability. Swallowing it here would let the receiver report
                # “ready” based on an empty page from a neighbor even though the
                # message was not saved and its cursor did not advance (review
                # finding FAN-010). Propagate it unchanged.
                try:
                    self.store.set_health("failed")
                except (InboxStorageError, sqlite3.Error):
                    # The same local fault may also prevent writing health. Keep
                    # the original refusal and report that its state was not saved.
                    log.error("a4a-inbox local failure; failed health could not be persisted")
                raise
            except Exception as exc:      # noqa: BLE001 - failure of one specific relay
                log.warning("a4a-inbox history unavailable on %s: %s", url, exc)
                failures.append(exc)
        if len(failures) == len(self.urls):
            self.store.set_health("failed")
            raise failures[0]
        self.store.set_health("backlog" if backlog else "ready")
        return added

    async def _sync_relay(self, url):
        """Synchronize one relay with its own cursor and history.

        Return `(items_added, page_budget_exhausted)`. A tuple is used rather than an
        exception because an exception would discard the count of already received
        messages and make budget exhaustion look like relay failure.
        """
        added = 0
        history = self.histories[url]
        for _ in range(self.max_pages):
            cursor = self.store.cursor(url)
            rows = await history.page(cursor)
            if not rows:
                return added, False
            peers = self._policy_senders()
            if self.inband_authorizer is not None:
                for _, event in rows:
                    try:
                        if self.inband_authorizer(self.agent, event):
                            peers = self._policy_senders()
                    except Exception:
                        log.exception("a4a-inbox in-band invitation authorizer failed; ignoring")
            owners = self._policy_owners()
            candidates = set()
            if owners:
                for _, event in rows:
                    message = self.agent._decode_incoming(event)
                    if message is not None:
                        candidates.add(message["from_pubkey"])
            permitted = await authorized_sender_keys(
                self.agent, peers, owners, candidates)
            if peers != self._policy_senders() or owners != self._policy_owners():
                raise InboxPolicyChanged("inbox authorization changed during owner lookup")
            result = self.store.accept_page(
                self.agent, url, cursor, rows, permitted,
                intake_mode=self.intake_mode(),
                blocked_senders=self.blocked_senders(),
            )
            added += result.count("stored")
            if self.ack_on_receipt:
                # Only letters that were STORED: blocked senders are exactly the ones who
                # must not learn that this mailbox exists and is watched.
                await self._acknowledge_receipts(
                    [event for (_stamp, event), kind in zip(rows, result) if kind == "stored"])
            if "rejected-size" in result:
                log.warning("a4a-inbox rejected oversized network messages: %d", result.count("rejected-size"))
            if "rejected-content" in result:
                log.warning("a4a-inbox rejected non-UTF-8 message content: %d",
                            result.count("rejected-content"))
        return added, True

    async def _acknowledge_receipts(self, events):
        """Send a `received` ACK for each newly stored letter; best effort.

        `received` means "in the mailbox, not yet processed". The binding `processed`
        (or `failed`) ACK still follows from completion and replaces this one, since
        ACKs for one delivery are addressable. A failure here is logged and left: the
        letter is stored either way, and the completion ACK is durable on its own.
        """
        if not events:
            return
        try:
            await self.agent.relay.connect()
            for event in events:
                message = self.agent._decode_incoming(event)
                if message is not None:
                    await self.agent.acknowledge(message, status="received")
        except RelayError as exc:
            log.warning("a4a-inbox could not send receipt ACKs: %s", exc)
        finally:
            await self.agent.relay.aclose()

    async def _stream_hints(self):
        """Keep one subscription per relay; one failure does not stop the others.

        The entry point intentionally remains argument-free because tests replace it.
        Changing its signature for an implementation detail would break external
        stubs unnecessarily. Fan-out happens internally.
        """
        tasks = [asyncio.create_task(self._stream_relay(u)) for u in self.urls]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _stream_relay(self, url):
        """Maintain a live subscription to ONE relay.

        Subscriptions are not merged: their only signal is “wake up and query
        history.” History itself is read separately from each relay by cursor.
        """
        while True:
            try:
                relay = RelayClient(url)
                # A hint is recoverable from history. Never keep thousands of
                # encrypted envelopes in RAM merely to announce pending work.
                relay.MAX_QUEUED_EVENTS = 8
                async with relay:
                    self.stream_connected = True
                    # No history is needed here. Only reception-history pages can
                    # establish whether an old/backdated envelope is newly received.
                    filters = {"kinds": [1059, 31033], "#p": [self.agent.pubkey], "limit": 0}
                    async with contextlib.aclosing(relay.subscribe(filters)) as events:
                        async for event in events:
                            if event.tag_value("p") == self.agent.pubkey:
                                # Relay history seals reception seconds before paging.
                                await asyncio.sleep(1.1)
                                self.hint.set()
            except asyncio.CancelledError:
                raise
            except Exception:
                self.stream_connected = False
                log.warning("a4a-inbox stream unavailable on %s; bounded history recovery remains active", url)
                await asyncio.sleep(self.poll_seconds)
            finally:
                self.stream_connected = False

    @contextlib.asynccontextmanager
    async def _running(self):
        with receiver_lock(self.store.path.parent):
            self.store.set_health("starting")
            stream = asyncio.create_task(self._stream_hints())
            try:
                yield
            except Exception:
                self.store.set_health("failed")
                raise
            finally:
                owner = asyncio.current_task()
                cancelling = owner.cancelling()
                stream.cancel()
                # Repeated cancellation must not interrupt transport cleanup or
                # release ownership before the stream has actually stopped.
                while not stream.done():
                    try:
                        await asyncio.shield(stream)
                    except asyncio.CancelledError:
                        pass
                with contextlib.suppress(asyncio.CancelledError):
                    stream.result()
                if self.store.health().get("state") != "failed":
                    self.store.set_health("stopped")
                if owner.cancelling() > cancelling:
                    raise asyncio.CancelledError

    async def _ticks(self):
        """Shared bounded recovery/timer loop; the caller owns _running()."""
        while True:
            self.hint.clear()
            try:
                await self._sync_once()
            except InboxPolicyChanged:
                raise
            except InboxError:
                # Locally retained work is still readable during an outage.
                log.warning("a4a-inbox recovery failed; pending work and cursor retained")
            yield
            try:
                await asyncio.wait_for(self.hint.wait(), timeout=self.poll_seconds)
            except asyncio.TimeoutError:
                pass

    async def run_ticks(self, callback, *, once=False):
        """Await a zero-argument async callback after each owned sync/timer tick.

        No notice or wake budget is consumed here. Callback and policy failures
        propagate with failed health; cancellation joins the WS stream cleanup.
        With once=True, return after the first callback and owned cleanup.
        """
        async with self._running():
            async for _ in self._ticks():
                self._policy_senders()
                await callback()
                if once:
                    return

    async def notices(self, *, interval=60, per_hour=12, on_tick=None):
        """Only fixed local metadata leaves this iterator; messages stay in SQLite."""
        async with self._running():
            tracker = NoticeTracker()
            async for _ in self._ticks():
                try:
                    if on_tick is not None:
                        await on_tick()
                    notice = self.store.notice(await self._eligible_senders(), interval=interval,
                                               per_hour=per_hour, tracker=tracker)
                    if notice:
                        yield notice
                except InboxPolicyChanged:
                    raise
                except InboxError:
                    self.store.set_health("failed")
                    log.warning("a4a-inbox notice failed; pending work retained")
