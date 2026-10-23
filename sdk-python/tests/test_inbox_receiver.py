"""History validation and streaming hints never masquerade as durable delivery."""
import importlib
import importlib.util
import json
import asyncio

import network_guard
import pytest

from a4a import Agent, Keys, giftwrap, types
from a4a.event import Event
from a4a.inbox import InboxStore, InboxError, InboxFull
from wire_cases import wrapped_with_escaped_content


@pytest.fixture
def api():
    assert importlib.util.find_spec("a4a.inbox_receiver") is not None, "inbox receiver is missing"
    return importlib.import_module("a4a.inbox_receiver")


def wrapped(sender, recipient, text="new secret"):
    inner = Event(kind=types.KIND_PRIVATE_RUMOR, tags=[["p", recipient.pubkey_hex], ["d", "unique"]], content=text)
    inner.sign(sender)
    return giftwrap.wrap(inner, recipient.pubkey_hex, sender)


def _wrapped_with(sender, recipient, text, delivery_id):
    """Create an envelope with a SPECIFIED delivery identifier.

    The shared `wrapped` helper assigns `d=unique` to every message, so two
    different payloads hit deduplication before capacity. Capacity checks need
    distinct identifiers; otherwise they test something other than advertised.
    """
    inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                  tags=[["p", recipient.pubkey_hex], ["d", delivery_id]], content=text)
    inner.sign(sender)
    return giftwrap.wrap(inner, recipient.pubkey_hex, sender)


def page(rows, recipient):
    return json.dumps({"version": 2, "recipient": recipient, "rows": [{"first_seen": fs, "event": ev.model_dump()} for fs, ev in rows],
                       "next_cursor": {"first_seen": rows[-1][0], "id": rows[-1][1].id} if rows else None})


async def test_pages_are_consumed_until_empty_not_until_short(api):
    recipient, sender = Keys(), Keys()
    ev = wrapped(sender, recipient)
    calls = []
    async def fetch(url):
        calls.append(url)
        return page([(100, ev)], recipient.pubkey_hex) if len(calls) == 1 else page([], recipient.pubkey_hex)
    history = api.InboxHistory("ws://127.0.0.1:17404", recipient.pubkey_hex, fetch=fetch)
    rows = await history.page((0, ""))
    assert rows[0][1].id == ev.id
    assert "page=2" in calls[0]
    assert "/v1/inbox?" in calls[0] and "recipient=" + recipient.pubkey_hex in calls[0]
    assert await history.page((100, ev.id)) == []


@pytest.mark.parametrize("case", ["array", "cursor", "order", "oversize", "row_count",
                                  "row_position", "unrequested_version", "wrong_recipient",
                                  "missing_recipient"])
async def test_malformed_or_incomplete_pages_fail(api, case):
    recipient, sender = Keys(), Keys()
    ev = wrapped(sender, recipient)
    body = json.loads(page([(100, ev)], recipient.pubkey_hex))
    if case == "array":
        body = body["rows"]
    elif case == "cursor":
        body["next_cursor"]["id"] = "a" * 64
    elif case == "order":
        body["rows"].append(body["rows"][0])
    elif case == "row_count":
        body["rows"] = body["rows"] * (api.PAGE_SIZE + 1)
    elif case == "row_position":
        body["rows"][0]["first_seen"] = True
    elif case == "unrequested_version":
        body["version"] = 1
    elif case == "wrong_recipient":
        body["recipient"] = sender.pubkey_hex
    elif case == "missing_recipient":
        del body["recipient"]
    async def fetch(url):
        return "x" * (2 * 1024 * 1024 + 1) if case == "oversize" else json.dumps(body)
    history = api.InboxHistory("ws://127.0.0.1:17404", recipient.pubkey_hex, fetch=fetch)
    expected = {"oversize": "2 MiB", "row_count": "row count",
                "row_position": "invalid position"}.get(case)
    with pytest.raises(InboxError, match=expected):
        await history.page((0, ""))


def test_history_rejects_noncanonical_recipient_before_any_request(api):
    with pytest.raises(InboxError, match="recipient public key"):
        api.InboxHistory("ws://127.0.0.1:17404", "not-a-key")


@pytest.mark.parametrize("cursor", [(-1, ""), (True, ""), (0, "A" * 64)])
async def test_history_rejects_invalid_cursor_before_fetch(api, cursor):
    called = False

    async def fetch(url):
        nonlocal called
        called = True
        return "{}"

    history = api.InboxHistory("ws://127.0.0.1:17404", Keys().pubkey_hex,
                               fetch=fetch)
    with pytest.raises(InboxError, match="invalid inbox history cursor"):
        await history.page(cursor)
    assert called is False


@pytest.mark.parametrize("kwargs, expected", [
    ({"max_pages": 0}, "work budget"),
    ({"max_pages": True}, "work budget"),
    ({"poll_seconds": 4}, "recovery interval"),
    ({"poll_seconds": True}, "recovery interval"),
])
def test_receiver_rejects_invalid_work_limits_before_initialization(api, kwargs, expected):
    with pytest.raises(InboxError, match=expected):
        api.InboxReceiver(None, None, None, start_after=0, **kwargs)


@pytest.mark.parametrize("url", ["https://example.org", "ws://user:password@example.org", "ws://example.org/?other=1", "ws://example.org/#fragment"])
def test_unambiguous_owner_configured_relay_url_only(api, url):
    with pytest.raises(InboxError):
        api.InboxHistory(url, Keys().pubkey_hex)


async def test_sync_persists_before_advancing_cursor_and_restarts(api, tmp_path):
    recipient, sender = Keys(), Keys()
    ev = wrapped(sender, recipient)
    agent = Agent(["ws://127.0.0.1:17404"], keys=recipient)
    queries = []
    class History:
        async def page(self, cursor):
            queries.append(cursor)
            return [(200, ev)] if cursor[0] < 200 else []
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
        receiver = api.InboxReceiver(agent, store, lambda: {sender.pubkey_hex}, start_after=150, history=History())
        assert await receiver.sync_once() == 1
        assert queries == [(150, ""), (200, ev.id)]
        assert store.health()["state"] == "ready"
        assert store.status()["pending"] == 1
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
        receiver = api.InboxReceiver(agent, store, lambda: {sender.pubkey_hex}, start_after=150, history=History())
        assert await receiver.sync_once() == 0
        assert store.status()["pending"] == 1


async def test_sync_rejects_non_utf8_scalar_and_advances_past_it(api, tmp_path):
    recipient, sender = Keys(), Keys()
    poison, malformed_inner = wrapped_with_escaped_content(
        sender, recipient, "\ud800", delivery="surrogate")
    assert not malformed_inner.verify()
    good = _wrapped_with(sender, recipient, "after poison", "good")
    agent = Agent(["ws://127.0.0.1:17404"], keys=recipient)
    calls = []

    class History:
        async def page(self, cursor):
            calls.append(cursor)
            if cursor == (150, ""):
                return [(200, poison), (201, good)]
            return []

    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
        receiver = api.InboxReceiver(
            agent, store, lambda: {sender.pubkey_hex}, start_after=150,
            history=History())
        assert await receiver.sync_once() == 1
        assert store.health()["state"] == "ready"
        assert store.cursor(agent.relay.url) == (201, good.id)
        assert store.status()["pending"] == 1
    assert calls == [(150, ""), (201, good.id)]


async def test_sync_refusal_does_not_advance(api, tmp_path):
    recipient, sender = Keys(), Keys()
    ev = wrapped(sender, recipient)
    agent = Agent(["ws://127.0.0.1:17404"], keys=recipient)
    class History:
        async def page(self, cursor):
            raise InboxError("test refusal")
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
        receiver = api.InboxReceiver(agent, store, lambda: {sender.pubkey_hex}, start_after=150, history=History())
        with pytest.raises(InboxError):
            await receiver.sync_once()
        assert store.cursor(agent.relay.url) == (150, "")
        assert store.health()["state"] == "failed"


async def test_backlog_limit_is_reported_not_complete(api, tmp_path):
    recipient, sender = Keys(), Keys()
    ev = wrapped(sender, recipient)
    agent = Agent(["ws://127.0.0.1:17404"], keys=recipient)
    class History:
        async def page(self, cursor):
            return [(cursor[0] + 1, ev)]
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
        receiver = api.InboxReceiver(agent, store, lambda: {sender.pubkey_hex}, start_after=150, history=History(), max_pages=2)
        assert await receiver.sync_once() == 1
        assert store.health()["state"] == "backlog"


async def test_cancel_closes_stalled_http_socket_without_lingering_reader(api):
    connected, closed = asyncio.Event(), asyncio.Event()
    writers, tasks = [], []
    async def serve(reader, writer):
        writers.append(writer)
        tasks.append(asyncio.current_task())
        try:
            await reader.readuntil(b"\r\n\r\n")
            connected.set()
            await reader.read()
            closed.set()
        finally:
            writer.close()
    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    network_guard.allow("127.0.0.1", port)
    history = api.InboxHistory(f"ws://127.0.0.1:{port}", Keys().pubkey_hex)
    request = asyncio.create_task(history.page((0, "")))
    try:
        await asyncio.wait_for(connected.wait(), 3)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        await asyncio.wait_for(closed.wait(), 1)
    finally:
        request.cancel()
        await asyncio.gather(request, return_exceptions=True)
        for writer in writers:
            writer.close()
        server.close()
        await server.wait_closed()
        network_guard.forget("127.0.0.1", port)
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.parametrize("mode", ["redirect", "oversize", "oversize_no_length", "compressed", "ok"])
async def test_actual_http_response_limits_and_no_redirects(api, mode):
    recipient = Keys().pubkey_hex
    connections = 0
    async def serve(reader, writer):
        nonlocal connections
        connections += 1
        try:
            await reader.readuntil(b"\r\n\r\n")
            body = page([], recipient).encode()
            header = b"HTTP/1.1 200 OK\r\n"
            if mode == "redirect":
                header = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/forbidden\r\n"
            if mode in ("oversize", "oversize_no_length"):
                body = b"x" * (2 * 1024 * 1024 + 1)
            if mode == "compressed":
                header += b"Content-Encoding: gzip\r\n"
            if mode != "oversize_no_length":
                header += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            writer.write(header + b"Connection: close\r\n\r\n" + body)
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    network_guard.allow("127.0.0.1", port)
    history = api.InboxHistory(f"ws://127.0.0.1:{port}", recipient)
    try:
        if mode == "ok":
            assert await history.page((0, "")) == []
        else:
            expected = {"redirect": "HTTP status", "oversize": "size limit",
                        "oversize_no_length": "2 MiB", "compressed": "compressed"}[mode]
            with pytest.raises(InboxError, match=expected):
                await history.page((0, ""))
        assert connections == 1
    finally:
        server.close()
        await server.wait_closed()
        network_guard.forget("127.0.0.1", port)


async def test_stream_reader_itself_stops_before_buffering_an_oversized_body(api):
    async def serve(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            writer.write(b"x" * (api.MAX_PAGE_BYTES + 1))
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    network_guard.allow("127.0.0.1", port)
    history = api.InboxHistory(f"ws://127.0.0.1:{port}", Keys().pubkey_hex)
    try:
        with pytest.raises(InboxError, match="2 MiB"):
            await history._fetch(f"http://127.0.0.1:{port}/v1/inbox")
    finally:
        server.close()
        await server.wait_closed()
        network_guard.forget("127.0.0.1", port)


async def test_changed_policy_stops_receiver_and_marks_failure(api, tmp_path):
    from a4a.inbox import InboxPolicyChanged
    recipient = Keys()
    agent = Agent(["ws://127.0.0.1:1"], keys=recipient)
    stopped = asyncio.Event()
    class History:
        async def page(self, cursor):
            return []
    def revoked():
        raise InboxPolicyChanged("test revocation")
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
        receiver = api.InboxReceiver(agent, store, revoked, start_after=0, history=History())
        async def stream():
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()
        receiver._stream_hints = stream
        source = receiver.notices()
        with pytest.raises(InboxPolicyChanged):
            await anext(source)
        assert store.health()["state"] == "failed"


async def test_history_is_recovered_from_every_relay_with_its_own_cursor(api, tmp_path):
    """A message stored ONLY on the second relay must reach the inbox.

    Reviewer finding FAN-001: the receiver used one address for both the live
    subscription and history catch-up, so the agent's relay fanout never reached
    it. A history cursor (`first_seen`) is relay-local, so multiple relays cannot
    share one cursor; each relay needs its own.

    Failure condition stated before the run: the message from the second relay
    is not saved, or the relay cursors are mixed up.
    """
    recipient, sender = Keys(), Keys()
    only_on_second = wrapped(sender, recipient, "stored only on the second relay")
    first, second = "ws://127.0.0.1:7001", "ws://127.0.0.1:7002"
    asked = {first: [], second: []}

    class History:
        def __init__(self, url, rows):
            self.url, self.rows = url, rows

        async def page(self, cursor):
            asked[self.url].append(cursor)
            return self.rows if cursor == (150, "") else []

    agent = Agent([first, second], keys=recipient)
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
        receiver = api.InboxReceiver(agent, store, lambda: {sender.pubkey_hex}, start_after=150)
        assert receiver.urls == [first, second], "the receiver must know both relays"
        receiver.histories = {first: History(first, []),
                              second: History(second, [(200, only_on_second)])}
        assert await receiver.sync_once() == 1, "the message from the second relay was not saved"
        assert store.status()["pending"] == 1
        # Only the relay that returned rows advances its cursor. Applying another
        # relay's `first_seen` here would skip unread messages.
        assert store.cursor(first) == (150, "")
        assert store.cursor(second) == (200, only_on_second.id)
    assert asked[first] and asked[second], "both relays must be queried"


async def test_one_dead_relay_does_not_hide_mail_lying_on_the_others(api, tmp_path):
    """One relay failure must not cancel catch-up from the others.

    Otherwise one offline relay would hide messages stored on the others, which
    is precisely the failure mode the fanout was designed to eliminate.
    """
    recipient, sender = Keys(), Keys()
    ev = wrapped(sender, recipient, "from a live relay")
    first, second = "ws://127.0.0.1:7001", "ws://127.0.0.1:7002"

    class Dead:
        async def page(self, cursor):
            raise InboxError("relay unavailable")

    class Alive:
        async def page(self, cursor):
            return [(200, ev)] if cursor == (150, "") else []

    agent = Agent([first, second], keys=recipient)
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
        receiver = api.InboxReceiver(agent, store, lambda: {sender.pubkey_hex}, start_after=150)
        receiver.histories = {first: Dead(), second: Alive()}
        assert await receiver.sync_once() == 1, "the live relay must be read"
        assert store.health()["state"] == "ready", "one dead relay is not an inbox failure"
        # Silence from ALL relays must remain a loud failure.
        receiver.histories = {first: Dead(), second: Dead()}
        with pytest.raises(InboxError):
            await receiver.sync_once()
        assert store.health()["state"] == "failed"


async def test_local_failure_is_not_healed_by_an_empty_sibling_relay(api, tmp_path):
    """An empty page from a sibling relay must not mask inbox overflow.

    Reviewer finding FAN-010. ANY exception used to be treated as a relay
    failure, so local problems such as overflow, policy changes, or database
    errors were recorded as "history unavailable", while the inbox was declared
    ready if any sibling returned an empty page. The message was not saved and
    the cursor did not move, yet externally this looked like "all good, no mail".

    Failure condition stated before the run: `sync_once` returns without an
    error, or the inbox state becomes ready.
    """
    recipient, sender = Keys(), Keys()
    # DISTINCT delivery identifiers. With the same `d` (as used by the shared
    # `wrapped` helper), InboxConflict fires first and the test would pass without
    # exercising overflow. The reviewer proved this by removing InboxFull from
    # the local-failure list: the test still stayed green. A false-green test is
    # worse than no test.
    already = _wrapped_with(sender, recipient, "first", "d-1")
    incoming = _wrapped_with(sender, recipient, "second", "d-2")
    first, second = "ws://127.0.0.1:7001", "ws://127.0.0.1:7002"

    class Empty:
        async def page(self, cursor):
            return []

    class HasOne:
        async def page(self, cursor):
            return [(200, incoming)] if cursor == (150, "") else []

    agent = Agent([first, second], keys=recipient)
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test", max_items=1) as store:
        store.accept_page(agent, first, (0, ""), [(100, already)], {sender.pubkey_hex})
        receiver = api.InboxReceiver(agent, store, lambda: {sender.pubkey_hex}, start_after=150)
        receiver.histories = {first: Empty(), second: HasOne()}
        # Require overflow specifically, not just any exception; otherwise the
        # test cannot distinguish a full inbox from a conflict or policy change.
        with pytest.raises(InboxFull):
            await receiver.sync_once()
        assert store.health()["state"] == "failed", "a local failure must be loud"
        assert store.cursor(second) == (150, ""), "the cursor must not move for an unsaved message"


@pytest.mark.parametrize("failure", ["full", "conflict", "policy", "database"])
async def test_each_local_failure_type_passes_through_untouched(api, tmp_path, failure):
    """Provide a control for EACH kind of local failure.

    Local failures must be enumerated by name because remote history failures
    inherit the same base class. Removing any name from the list must therefore
    fail its corresponding test, or the list could silently shrink later.

    The failure is deliberately raised from history: this checks CLASSIFICATION
    by type, not its origin. A failure classified as local must not become
    "relay unavailable" regardless of where it originated.
    """
    import sqlite3
    from a4a.inbox import InboxConflict, InboxFull, InboxPolicyChanged
    raised = {"full": InboxFull("inbox full"), "conflict": InboxConflict("cursor conflict"),
              "policy": InboxPolicyChanged("policy changed"),
              "database": sqlite3.Error("database unavailable")}[failure]
    recipient, sender = Keys(), Keys()
    first, second = "ws://127.0.0.1:7001", "ws://127.0.0.1:7002"

    class Empty:
        async def page(self, cursor):
            return []

    class Local:
        async def page(self, cursor):
            raise raised

    agent = Agent([first, second], keys=recipient)
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
        receiver = api.InboxReceiver(agent, store, lambda: {sender.pubkey_hex}, start_after=150)
        receiver.histories = {first: Empty(), second: Local()}
        with pytest.raises(type(raised)):
            await receiver.sync_once()
        assert store.health()["state"] == "failed"


async def test_a_remote_history_failure_is_still_tolerated_when_a_sibling_answers(api, tmp_path):
    """Conversely, one remote history failure must still be tolerated.

    Without this case, classification could be "fixed" by treating every error
    as local, letting one unavailable relay hide messages stored on the others.
    """
    recipient, sender = Keys(), Keys()
    ev = _wrapped_with(sender, recipient, "from the live relay", "d-live")
    first, second = "ws://127.0.0.1:7001", "ws://127.0.0.1:7002"

    class Remote:
        async def page(self, cursor):
            raise InboxError("inbox history unavailable or malformed")

    class Alive:
        async def page(self, cursor):
            return [(200, ev)] if cursor == (150, "") else []

    agent = Agent([first, second], keys=recipient)
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
        receiver = api.InboxReceiver(agent, store, lambda: {sender.pubkey_hex}, start_after=150)
        receiver.histories = {first: Remote(), second: Alive()}
        assert await receiver.sync_once() == 1
        assert store.health()["state"] == "ready"


async def test_real_sqlite_full_is_not_healed_by_empty_sibling(api, tmp_path):
    """Real transaction wrapping must retain the local failure classification."""
    import sqlite3
    from a4a.inbox import InboxStorageError

    recipient, sender = Keys(), Keys()
    first, second = "ws://127.0.0.1:7001", "ws://127.0.0.1:7002"
    rows = [(200 + i, _wrapped_with(sender, recipient, "x" * 8192, f"full-{i}"))
            for i in range(3)]

    class HasPage:
        async def page(self, cursor):
            return rows if cursor == (150, "") else []

    class Empty:
        async def page(self, cursor):
            return []

    agent = Agent([first, second], keys=recipient)
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test", max_bytes=65536) as store:
        receiver = api.InboxReceiver(agent, store, lambda: {sender.pubkey_hex}, start_after=150)
        store.set_health("starting")
        receiver.histories = {first: HasPage(), second: Empty()}
        with pytest.raises(InboxStorageError) as caught:
            await receiver.sync_once()
        assert isinstance(caught.value.__cause__, sqlite3.OperationalError)
        assert caught.value.__cause__.sqlite_errorcode == sqlite3.SQLITE_FULL
        assert store.health()["state"] == "failed"
        assert store.cursor(first) == (150, "")
        assert store.status()["pending"] == 0


async def test_unwritable_failed_health_preserves_local_refusal(api, tmp_path, monkeypatch, caplog):
    from a4a.inbox import InboxStorageError

    recipient = Keys()
    first, second = "ws://127.0.0.1:7001", "ws://127.0.0.1:7002"
    original = InboxStorageError("local write failed")

    class Local:
        async def page(self, cursor):
            raise original

    class Empty:
        async def page(self, cursor):
            return []

    agent = Agent([first, second], keys=recipient)
    with InboxStore(tmp_path / "db", recipient.pubkey_hex, "test") as store:
        receiver = api.InboxReceiver(agent, store, lambda: set(), start_after=150)
        receiver.histories = {first: Local(), second: Empty()}

        def cannot_record_health(_state):
            raise InboxStorageError("health write failed")

        monkeypatch.setattr(store, "set_health", cannot_record_health)
        with pytest.raises(InboxStorageError) as caught:
            await receiver.sync_once()
        assert caught.value is original
        assert "failed health could not be persisted" in caplog.text
