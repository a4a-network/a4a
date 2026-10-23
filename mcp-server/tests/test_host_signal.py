"""Source-contract tests; never connect to an owner relay or live host instance."""

import asyncio
import dataclasses
import importlib.metadata
import json
from pathlib import Path
import re
import socket
import time
from unittest.mock import AsyncMock

import network_guard
import pytest

from a4a_mcp import host_signal as adapter


TOKEN = "synthetic-test-wake-token"
SIGNAL_ID = "0123456789abcdef0123456789abcdef"
BINDING = adapter.Binding("test-project", "test-session", "test-consumer")


def notice(**changes):
    return {"consumer": "test-consumer", "pending": 1, "seq_hint": 7, **changes}


def signal(**changes):
    return adapter.prepare_signal(notice(**changes), BINDING, signal_id=SIGNAL_ID)


def reply(status="accepted", reason="queued", success=True, **changes):
    return json.dumps({
        "type": "mcp:a4a_inbox_signal:response", "requestId": 1,
        "version": "1", "signalId": SIGNAL_ID, "success": success,
        "status": status, "reasonCode": reason, **changes,
    })


def query_reply(status="retained", reason="known", success=True, **changes):
    return reply(status, reason, success,
                 **{"type": "mcp:a4a_signal_status:response", **changes})


def welcome(**changes):
    return json.dumps({"type": "welcome", "clientId": "01234567-89ab-cdef-0123-456789abcdef",
                       "message": "Connected to Host", **changes})


class _OwnedEndpoints:
    """Track test-owned endpoints while using the single shared network boundary."""

    def __init__(self):
        self._mine: set[tuple[str, int]] = set()

    def add(self, address: tuple[str, int]) -> None:
        host, port = address
        self._mine.add((host, int(port)))
        network_guard.allow(host, port)

    def release(self) -> None:
        for host, port in self._mine:
            network_guard.forget(host, port)
        self._mine.clear()


@pytest.fixture(autouse=True)
def only_test_owned_sockets():
    """Register test-owned endpoints with the shared suite network boundary.

    This file once had a second independent implementation: its own `socket.connect`
    patch, allowlist, and final assertion. While the suite boundary was equally narrow,
    the copies merely duplicated each other. Once the shared boundary covered asyncio,
    they conflicted: the local patch replaced the shared one during a test, while async
    connections bypassed it. Tests that started local nodes then hit a shared boundary
    that had never been told about those endpoints.

    Two guards with different allowlists are worse than one because each assumes it is
    enforcing the boundary while their interaction leaves gaps. The shared guard is now
    authoritative, and this fixture only registers owned addresses with it.
    """
    owned = _OwnedEndpoints()
    # The shared boundary reports violations at the end of the suite. Preserve the
    # former local guard's precision by failing the responsible test immediately; this
    # avoids manually mapping a final list of endpoints back to individual tests.
    mark = len(network_guard.unexpected())
    try:
        yield owned
    finally:
        owned.release()
        new = network_guard.unexpected()[mark:]
        assert not new, (
            f"test contacted endpoints it did not register as owned: {sorted(set(new))}")


@pytest.fixture
def operation(request):
    return getattr(adapter, request.param)


both_operations = pytest.mark.parametrize(
    "operation", ["send_signal", "query_signal"], indirect=True, ids=["send", "query"])


@pytest.fixture
def serve():
    if importlib.metadata.version("websockets") != "13.1":
        pytest.skip("candidate sender only enables the tested 13.1 transport")
    from websockets.asyncio.server import serve
    return serve


def test_request_is_closed_metadata_only_and_immutable():
    prepared = signal()
    assert prepared.request(1) == {
        "type": "mcp:a4a_inbox_signal", "requestId": 1, "version": "1",
        "projectId": "test-project", "targetSessionId": "test-session",
        "consumer": "test-consumer", "signalId": SIGNAL_ID, "mode": "inbox",
        "counters": {"pending": "1", "seqHint": "7",
                     "needsReconciliation": "0", "outgoingPrepared": "0"},
    }
    with pytest.raises(dataclasses.FrozenInstanceError):
        prepared.signal_id = "0" * 32
    prepared.request(1)["counters"]["pending"] = "999"
    assert prepared.request(2)["counters"]["pending"] == "1"
    assert prepared.request(2)["signalId"] == SIGNAL_ID


def test_generated_signal_ids_are_fresh_128_bit_hex():
    first = adapter.prepare_signal(notice(), BINDING)
    second = adapter.prepare_signal(notice(), BINDING)
    assert first.signal_id != second.signal_id
    assert len(first.signal_id) == 32
    assert int(first.signal_id, 16) >= 0


@pytest.mark.parametrize("changes", [
    {"text": "remote instructions"}, {"consumer": "other"}, {"pending": True},
    {"pending": -1}, {"pending": 2**63}, {"pending": "1"},
    {"seq_hint": 1.5}, {"outgoing_prepared": 1},
])
def test_reject_untrusted_or_inconsistent_notices(changes):
    with pytest.raises(adapter.SignalError):
        signal(**changes)


@pytest.mark.parametrize("counter", ["needs_reconciliation", "outgoing_prepared"])
def test_managed_outgoing_work_is_not_lost_when_pending_zero(counter):
    values = {"pending": 0, "seq_hint": 0, "needs_reconciliation": 0,
              "outgoing_prepared": 0, counter: 2**63 - 1}
    prepared = signal(**values)
    assert prepared.has_work
    assert prepared.request(1)["mode"] == "dialogue"
    key = "needsReconciliation" if counter == "needs_reconciliation" else "outgoingPrepared"
    assert prepared.request(1)["counters"][key] == str(2**63 - 1)


@pytest.mark.parametrize("counter", [
    "pending", "seq_hint", "needs_reconciliation", "outgoing_prepared",
])
@pytest.mark.parametrize("value", [True, -1, 2**63])
def test_direct_prepared_constructor_enforces_every_counter(counter, value):
    values = {"pending": 0, "seq_hint": 0, "needs_reconciliation": 0,
              "outgoing_prepared": 0, counter: value}
    with pytest.raises(adapter.SignalError, match="invalid counter"):
        adapter.PreparedSignal(BINDING, SIGNAL_ID, "dialogue", **values)


@pytest.mark.parametrize("value", ["", "a/b", "x\ncommand", "a" * 129, 1, None])
def test_binding_requires_exact_local_ids(value):
    with pytest.raises(adapter.SignalError):
        adapter.Binding(value, "test-session", "test-consumer")
    with pytest.raises(adapter.SignalError):
        adapter.Binding("test-project", value, "test-consumer")


@pytest.mark.parametrize("binding", [None, object(), {}])
def test_prepare_signal_requires_a_validated_binding_object(binding):
    with pytest.raises(adapter.SignalError, match="invalid local binding"):
        adapter.prepare_signal(notice(), binding, signal_id=SIGNAL_ID)


@pytest.mark.parametrize("request_id", [0, -1, True, "1", 2**31])
def test_request_id_has_cross_language_bound(request_id):
    with pytest.raises(adapter.SignalError):
        signal().request(request_id)


@pytest.mark.parametrize("status,reason,success", [
    ("accepted", "queued", True), ("deferred", "busy", True),
    ("duplicate", "already_seen", True),
    *[("rejected", code, False) for code in (
        "not_authorized", "unknown_pair", "unsupported_version", "invalid_signal",
        "signal_id_conflict", "no_work", "host_blocked")],
])
def test_known_response_pairs(status, reason, success):
    outcome = adapter.parse_response(reply(status, reason, success), signal(), 1)
    assert (outcome.status, outcome.reason) == (status, reason)


@pytest.mark.parametrize("frame", [
    reply(requestId=2), reply(requestId=True), reply(version=1),
    reply(signalId="f" * 32), reply(type="other"), reply(success=1),
    reply(status="processed"), reply(reason="busy"), reply(success=False),
    reply(extra="secret"), b"binary", "not-json", "[]", "null",
    '{"type":"one","type":"two"}', "x" * 4097,
    '{"depth":' + '[' * 1500 + '0' + ']' * 1500 + '}',
])
def test_invalid_ack_is_unknown_not_success(frame):
    outcome = adapter.parse_response(frame, signal(), 1)
    assert (outcome.status, outcome.reason) == ("unknown", "invalid_response")


def test_frame_limit_counts_utf8_bytes_not_only_characters():
    frame = json.dumps({"padding": "é" * 2050}, ensure_ascii=False)
    assert len(frame) <= 4096 < len(frame.encode("utf-8"))
    with pytest.raises(ValueError, match="invalid frame"):
        adapter._read_object(frame)


def test_legacy_denial_is_redacted():
    frame = json.dumps({"type": "mcp:a4a_inbox_signal:response", "requestId": 1,
                        "success": False, "error": TOKEN})
    result = adapter.parse_response(frame, signal(), 1)
    assert result.status == "rejected"
    assert result.reason == "access_denied"
    assert TOKEN not in repr(result)


@pytest.mark.parametrize("endpoint", [
    "wss://127.0.0.1:9876/", "ws://localhost:9876/", "ws://example.com/",
    "ws://127.0.0.2:9876/", "ws://127.0.0.1:9876/?token=x",
    "ws://user:pass@127.0.0.1:9876/", "ws://127.0.0.1:9876/#x",
    "ws://127.0.0.1:9876/path", "ws://127.0.0.1:0/",
    " ws://127.0.0.1:9876/", "ws://127.0.0.1:09876/",
])
@both_operations
async def test_invalid_endpoint_fails_before_network(endpoint, operation):
    with pytest.raises(adapter.SignalError):
        await operation(signal(), token=TOKEN, endpoint=endpoint)


@pytest.mark.parametrize("token", ["", None, "abc\r\nX-Foo: injected", "x" * 4097])
@both_operations
async def test_explicit_valid_header_token_required(token, operation):
    with pytest.raises(adapter.SignalError):
        await operation(signal(), token=token)


@both_operations
async def test_empty_notice_opens_no_socket(operation, monkeypatch):
    def unexpected_transport():
        pytest.fail("empty work must not load a transport")

    monkeypatch.setattr(adapter, "_connect_factory", unexpected_transport)
    result = await operation(signal(pending=0), token=TOKEN)
    assert (result.status, result.reason) == ("no_work", "empty")


async def test_real_loopback_exchange_and_explicit_retry(only_test_owned_sockets, monkeypatch, serve):
    captured = []
    monkeypatch.setenv("ALL_PROXY", "http://do-not-connect.invalid:1")
    monkeypatch.setenv("WS_PROXY", "http://do-not-connect.invalid:1")

    async def handler(ws):
        await ws.send(welcome())
        captured.append((ws.request, json.loads(await ws.recv())))
        await ws.send(reply())

    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        only_test_owned_sockets.add(("127.0.0.1", port))
        prepared = signal()
        for _ in range(2):
            result = await adapter.send_signal(prepared, token=TOKEN,
                                              endpoint=f"ws://127.0.0.1:{port}/")
            assert result.status == "accepted"
    assert len(captured) == 2
    assert captured[0][1] == captured[1][1] == prepared.request(1)
    assert captured[0][0].headers["X-A4A-Host-Token"] == TOKEN
    assert captured[0][0].path == "/"
    assert TOKEN not in json.dumps(captured[0][1])


@pytest.mark.parametrize("action,reason", [("drop", "transport_failed"),
    ("stall", "timeout"), ("bad", "invalid_response"), ("binary", "invalid_response"),
    ("oversize", "transport_failed")])
@both_operations
async def test_ack_loss_never_retries_or_claims_success(
        action, reason, only_test_owned_sockets, serve, operation):
    seen = []

    async def handler(ws):
        seen.append(await ws.recv())
        if action == "stall":
            await ws.wait_closed()
        elif action == "bad":
            await ws.send("bad-ack")
        elif action == "binary":
            await ws.send(b"binary")
        elif action == "oversize":
            await ws.send("x" * 4097)

    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        only_test_owned_sockets.add(("127.0.0.1", port))
        result = await operation(signal(), token=TOKEN, timeout=0.3,
                                 endpoint=f"ws://127.0.0.1:{port}/")
    assert (result.status, result.reason) == ("unknown", reason)
    assert len(seen) == 1


@both_operations
async def test_redirect_cannot_forward_credential(only_test_owned_sockets, serve, operation):
    from websockets.http11 import Response
    from websockets.datastructures import Headers

    visited = []

    async def unexpected(ws):
        visited.append(True)

    async with serve(unexpected, "127.0.0.1", 0) as target:
        target_port = target.sockets[0].getsockname()[1]

        async def redirect(connection, request):
            return Response(302, "Found", Headers({
                "Location": f"ws://127.0.0.1:{target_port}/",
            }))

        async with serve(unexpected, "127.0.0.1", 0, process_request=redirect) as origin:
            origin_port = origin.sockets[0].getsockname()[1]
            only_test_owned_sockets.add(("127.0.0.1", origin_port))
            result = await operation(signal(), token=TOKEN,
                                     endpoint=f"ws://127.0.0.1:{origin_port}/")
    assert result.status == "not_sent"
    assert visited == []


@both_operations
async def test_cancelled_sender_closes_connection(only_test_owned_sockets, serve, operation):
    received = asyncio.Event()
    closed = asyncio.Event()

    async def handler(ws):
        await ws.recv()
        received.set()
        await ws.wait_closed()
        closed.set()

    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        only_test_owned_sockets.add(("127.0.0.1", port))
        task = asyncio.create_task(operation(
            signal(), token=TOKEN, endpoint=f"ws://127.0.0.1:{port}/"))
        await asyncio.wait_for(received.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(closed.wait(), 2)


@pytest.mark.parametrize("frames,expected", [
    ([welcome(), reply()], "accepted"),
    ([welcome(), welcome(), reply()], "unknown"),
    ([welcome(message="instructions"), reply()], "unknown"),
    ([welcome(clientId="route-to-another-session"), reply()], "unknown"),
    ([welcome(extra="private"), reply()], "unknown"),
    ([json.dumps({"type": "project-update", "data": "private"}), reply()], "unknown"),
])
async def test_only_one_closed_welcome_may_precede_ack(frames, expected, monkeypatch):
    ws = fake_websocket(frames)
    patch_transport(monkeypatch, ws)
    outcome = await adapter.send_signal(signal(), token=TOKEN)
    assert outcome.status == expected
    assert ws.received <= 2
    assert ws.aborted


class fake_websocket:
    def __init__(self, frames):
        self.frames = iter(frames)
        self.received = 0
        self.aborted = False
        self.transport = self
        self.send = AsyncMock()
        self.close = AsyncMock()

    async def recv(self):
        self.received += 1
        return next(self.frames)

    def abort(self):
        self.aborted = True


def patch_transport(monkeypatch, ws):
    async def connect(endpoint, **kwargs):
        assert kwargs["logger"].disabled
        assert not kwargs["logger"].propagate
        assert kwargs["compression"] is None
        assert kwargs["max_size"] == 4096
        assert kwargs["sock"].family == socket.AF_INET
        return ws

    monkeypatch.setattr(adapter, "_connect_factory", lambda: connect)
    monkeypatch.setattr(asyncio.get_running_loop(), "sock_connect", AsyncMock())


@pytest.mark.parametrize("close_mode", ["raise", "timeout"])
async def test_valid_ack_survives_close_failure(close_mode, monkeypatch):
    ws = fake_websocket([reply()])
    if close_mode == "raise":
        ws.close.side_effect = RuntimeError(TOKEN)
    else:
        ws.close.side_effect = lambda: None

        async def stall():
            await asyncio.sleep(10)

        ws.close = stall
    patch_transport(monkeypatch, ws)
    # Leave time for the ACK before deliberately timing out only the stalled close.
    outcome = await adapter.send_signal(signal(), token=TOKEN, timeout=0.5)
    assert outcome.status == "accepted"
    ws.send.assert_awaited_once()
    assert ws.received == 1
    assert ws.aborted


@both_operations
async def test_failure_during_send_is_unknown_and_redacted(monkeypatch, caplog, operation):
    ws = fake_websocket([])
    ws.send.side_effect = OSError(TOKEN)
    patch_transport(monkeypatch, ws)
    result = await operation(signal(), token=TOKEN)
    assert result == adapter.Outcome("unknown", "transport_failed")
    assert TOKEN not in repr(result) + caplog.text
    ws.send.assert_awaited_once()
    assert ws.aborted


@both_operations
async def test_connect_timeout_is_not_sent(monkeypatch, operation):
    ws = fake_websocket([])
    patch_transport(monkeypatch, ws)

    async def stall(*args):
        await asyncio.sleep(10)

    monkeypatch.setattr(asyncio.get_running_loop(), "sock_connect", stall)
    result = await operation(signal(), token=TOKEN, timeout=0.02)
    assert result == adapter.Outcome("not_sent", "timeout")
    ws.send.assert_not_awaited()


@pytest.mark.parametrize("stage", ["create", "configure"])
@both_operations
@pytest.mark.requires_host_signal
async def test_socket_setup_failure_is_not_sent_and_redacted(stage, monkeypatch, operation):
    class FailingSocket:
        closed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def setblocking(self, value):
            raise OSError(TOKEN)

        def close(self):
            self.closed = True

    sock = FailingSocket()

    def factory(*args):
        if stage == "create":
            raise OSError(TOKEN)
        return sock

    with monkeypatch.context() as patch:
        patch.setattr(adapter.socket, "socket", factory)
        result = await operation(signal(), token=TOKEN)
    assert result == adapter.Outcome("not_sent", "transport_failed")
    assert TOKEN not in repr(result)
    assert sock.closed == (stage == "configure")


@pytest.mark.parametrize("stage", ["after_welcome", "post_ack_close"])
@both_operations
async def test_cancellation_propagates_after_welcome_or_ack(stage, monkeypatch, operation):
    ack = query_reply() if operation.__name__ == "query_signal" else reply()
    ws = fake_websocket([welcome(), ack])
    blocked = asyncio.Event()
    original_recv = ws.recv

    async def stall():
        blocked.set()
        await asyncio.sleep(10)

    if stage == "after_welcome":
        async def recv():
            if ws.received == 1:
                await stall()
            return await original_recv()
        ws.recv = recv
    else:
        ws.close = stall
    patch_transport(monkeypatch, ws)
    task = asyncio.create_task(operation(signal(), token=TOKEN))
    await asyncio.wait_for(blocked.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert ws.aborted


@pytest.mark.parametrize("timeout", [0, -1, True, "5", float("nan"), float("inf"), 31, 10**1000])
@both_operations
async def test_invalid_deadline_fails_before_network(timeout, operation):
    with pytest.raises(adapter.SignalError):
        await operation(signal(), token=TOKEN, timeout=timeout)


@both_operations
async def test_untested_transport_fails_before_network(monkeypatch, operation):
    monkeypatch.setattr(adapter.importlib.metadata, "version", lambda _: "99.0")
    with pytest.raises(adapter.SignalError, match="untested transport"):
        await operation(signal(), token=TOKEN)


@pytest.mark.parametrize("signal_id", ["", "0" * 31, "G" * 32, "A" * 32, False])
def test_invalid_signal_ids(signal_id):
    with pytest.raises(adapter.SignalError):
        adapter.prepare_signal(notice(), BINDING, signal_id=signal_id)


def test_direct_prepared_constructor_cannot_bypass_mode_validation():
    with pytest.raises(adapter.SignalError):
        dataclasses.replace(signal(), needs_reconciliation=1)
    with pytest.raises(adapter.SignalError):
        dataclasses.replace(signal(), mode="execute-command")


def test_managed_legacy_notice_omitted_prepared_is_zero():
    result = signal(needs_reconciliation=1)
    assert result.mode == "dialogue"
    assert result.outgoing_prepared == 0


def test_duplicate_json_key_and_surrogate_never_accept():
    duplicate = reply().replace('"success": true', '"success": false, "success": true')
    assert adapter.parse_response(duplicate, signal(), 1).status == "unknown"
    assert adapter.parse_response("\ud800", signal(), 1).status == "unknown"


@pytest.mark.parametrize("operation", ["send_signal", "query_signal"])
@pytest.mark.parametrize("decision", [False, "error"])
async def test_final_preflight_runs_after_connection_before_any_frame(operation, decision, monkeypatch):
    ws = fake_websocket([])
    patch_transport(monkeypatch, ws)
    checked = []

    def preflight():
        checked.append(True)
        if decision == "error":
            raise RuntimeError(TOKEN)
        return decision

    result = await getattr(adapter, operation)(signal(), token=TOKEN, before_send=preflight)
    assert result == adapter.Outcome("not_sent", "preflight_failed" if decision == "error" else "superseded")
    assert checked == [True]
    ws.send.assert_not_awaited()
    assert ws.aborted
    assert TOKEN not in repr(result)


async def test_valid_preflight_sends_normally(monkeypatch):
    ws = fake_websocket([reply()])
    patch_transport(monkeypatch, ws)
    result = await adapter.send_signal(signal(), token=TOKEN, before_send=lambda: True)
    assert result.status == "accepted"
    ws.send.assert_awaited_once()


@both_operations
@pytest.mark.parametrize("kind", ["noncallable", "async_callable"])
async def test_invalid_preflight_is_rejected_before_transport(kind, operation, monkeypatch):
    async def async_preflight():
        return True

    before_send = object() if kind == "noncallable" else async_preflight
    monkeypatch.setattr(adapter, "_connect_factory",
                        lambda: pytest.fail("invalid preflight reached transport"))
    with pytest.raises(adapter.SignalError, match="synchronous callable"):
        await operation(signal(), token=TOKEN, before_send=before_send)


@both_operations
async def test_preflight_exhausting_deadline_never_sends(only_test_owned_sockets, serve, operation):
    frames = []

    async def host(ws):
        async for frame in ws:
            frames.append(frame)

    def slow_preflight():
        time.sleep(0.35)
        return True

    async with serve(host, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        only_test_owned_sockets.add(("127.0.0.1", port))
        result = await operation(signal(), token=TOKEN, timeout=0.2,
                                 endpoint=f"ws://127.0.0.1:{port}/", before_send=slow_preflight)
    assert result == adapter.Outcome("not_sent", "timeout")
    assert frames == []


@pytest.mark.parametrize("status,reason,success", [
    ("retained", "known", True), ("absent", "not_found", True),
    *[("rejected", code, False) for code in (
        "not_authorized", "unknown_pair", "unsupported_version", "invalid_signal",
        "signal_id_conflict", "no_work", "host_blocked")],
])
def test_query_known_response_pairs(status, reason, success):
    result = adapter.parse_query_response(query_reply(status, reason, success), signal(), 1)
    assert result == adapter.Outcome(status, reason)


@pytest.mark.parametrize("frame", [
    reply(), reply("rejected", "not_authorized", False),
    query_reply(type="mcp:a4a_inbox_signal:response"),
    query_reply(type="mcp:a4a_signal_status"),
    query_reply(requestId=2), query_reply(requestId=True), query_reply(requestId=1.0),
    query_reply(version=1), query_reply(signalId="f" * 32),
    query_reply(success=1), query_reply(success=False),
    query_reply("absent", "known"), query_reply("retained", "not_found"),
    query_reply("absent", "not_found", False),
    query_reply("accepted", "queued"), query_reply("deferred", "busy"),
    query_reply("duplicate", "already_seen"),
    query_reply("rejected", "not_authorized"),
    query_reply("rejected", "unsupported_query", False),
    query_reply(status=[]), query_reply(reason={}), query_reply(extra=TOKEN),
    b"binary", "not-json", "[]", "null", "x" * 4097, "\ud800",
    query_reply().replace('"success": true', '"success": false, "success": true'),
    query_reply().replace('"version": "1"', '"version": "2", "version": "1"'),
    json.dumps({"padding": "\u00e9" * 2100}, ensure_ascii=False),
    '{"depth":' + '[' * 1500 + '0' + ']' * 1500 + '}',
])
def test_query_invalid_response_remains_unknown(frame):
    result = adapter.parse_query_response(frame, signal(), 1)
    assert result == adapter.Outcome("unknown", "invalid_response")
    assert TOKEN not in repr(result)


@pytest.mark.parametrize("missing", [
    "type", "requestId", "version", "signalId", "success", "status", "reasonCode",
])
def test_query_requires_all_seven_response_fields(missing):
    data = json.loads(query_reply())
    del data[missing]
    assert adapter.parse_query_response(json.dumps(data), signal(), 1) == adapter.Outcome(
        "unknown", "invalid_response")


@pytest.mark.parametrize("status,reason", [("retained", "known"), ("absent", "not_found")])
@pytest.mark.parametrize("response_type", [
    "mcp:a4a_inbox_signal:response", "mcp:a4a_signal_status:response",
])
def test_query_statuses_never_enter_send_parser(status, reason, response_type):
    result = adapter.parse_response(query_reply(status, reason, type=response_type), signal(), 1)
    assert result == adapter.Outcome("unknown", "invalid_response")


@pytest.mark.parametrize("changes,expected", [
    ({}, adapter.Outcome("rejected", "access_denied")),
    ({"type": "mcp:a4a_inbox_signal:response"}, adapter.Outcome("unknown", "invalid_response")),
    ({"requestId": True}, adapter.Outcome("unknown", "invalid_response")),
    ({"requestId": 2}, adapter.Outcome("unknown", "invalid_response")),
    ({"success": 0}, adapter.Outcome("unknown", "invalid_response")),
    ({"error": {}}, adapter.Outcome("unknown", "invalid_response")),
    ({"extra": TOKEN}, adapter.Outcome("unknown", "invalid_response")),
])
def test_query_early_denial_is_strict_and_redacted(changes, expected, caplog):
    frame = json.dumps({"type": "mcp:a4a_signal_status:response", "requestId": 1,
                        "success": False, "error": TOKEN, **changes})
    result = adapter.parse_query_response(frame, signal(), 1)
    assert result == expected
    assert TOKEN not in repr(result) + caplog.text
    assert adapter.parse_response(frame, signal(), 1).status == (
        "rejected" if changes.get("type") == "mcp:a4a_inbox_signal:response" else "unknown")


@pytest.mark.parametrize("request_id", [0, -1, True, "1", 2**31])
async def test_query_invalid_request_id_fails_before_network(request_id):
    with pytest.raises(adapter.SignalError):
        await adapter.query_signal(signal(), token=TOKEN, request_id=request_id)
    with pytest.raises(adapter.SignalError):
        adapter.parse_query_response(query_reply(), signal(), request_id)


@pytest.mark.parametrize("prepared", [None, {}, notice(), SIGNAL_ID])
@both_operations
async def test_only_prepared_signals_can_reach_transport(prepared, operation):
    with pytest.raises(adapter.SignalError):
        await operation(prepared, token=TOKEN)


@pytest.mark.parametrize("changes", [
    {}, {"pending": 0, "seq_hint": 0, "needs_reconciliation": 1, "outgoing_prepared": 0},
    {"pending": 0, "seq_hint": 0, "needs_reconciliation": 0, "outgoing_prepared": 2**63 - 1},
])
@pytest.mark.parametrize("status,reason", [("retained", "known"), ("absent", "not_found")])
async def test_real_loopback_query_preserves_full_signal(
        changes, status, reason, only_test_owned_sockets, monkeypatch, serve, caplog):
    captured = []
    monkeypatch.setenv("ALL_PROXY", "http://do-not-connect.invalid:1")
    monkeypatch.setenv("WS_PROXY", "http://do-not-connect.invalid:1")

    async def handler(ws):
        await ws.send(welcome())
        request = json.loads(await ws.recv())
        captured.append((ws.request, request))
        await ws.send(query_reply(status, reason, requestId=request["requestId"]))

    prepared = signal(**changes)
    original = prepared.request(1)
    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        only_test_owned_sockets.add(("127.0.0.1", port))
        for request_id in (1, 2**31 - 1):
            result = await adapter.query_signal(prepared, token=TOKEN,
                                               endpoint=f"ws://127.0.0.1:{port}/",
                                               request_id=request_id)
            assert result == adapter.Outcome(status, reason)
    assert len(captured) == 2
    for (transport, request), request_id in zip(captured, (1, 2**31 - 1)):
        assert request == {**prepared.request(request_id), "type": "mcp:a4a_signal_status"}
        assert transport.headers["X-A4A-Host-Token"] == TOKEN
        assert transport.path == "/"
        assert TOKEN not in json.dumps(request)
    assert prepared.request(1) == original
    assert TOKEN not in caplog.text


@pytest.mark.parametrize("frames,expected", [
    ([query_reply()], adapter.Outcome("retained", "known")),
    ([welcome(), query_reply("absent", "not_found")], adapter.Outcome("absent", "not_found")),
    ([query_reply("rejected", "unsupported_version", False)],
     adapter.Outcome("rejected", "unsupported_version")),
    ([reply()], adapter.Outcome("unknown", "invalid_response")),
    ([reply("rejected", "unsupported_version", False)],
     adapter.Outcome("unknown", "invalid_response")),
    ([welcome(), welcome(), query_reply()], adapter.Outcome("unknown", "invalid_response")),
    ([welcome(extra=TOKEN), query_reply()], adapter.Outcome("unknown", "invalid_response")),
    ([welcome(message=TOKEN), query_reply()], adapter.Outcome("unknown", "invalid_response")),
    ([welcome(clientId="another-session"), query_reply()], adapter.Outcome("unknown", "invalid_response")),
    ([json.dumps({"type": "project-update", "data": TOKEN}), query_reply()],
     adapter.Outcome("unknown", "invalid_response")),
])
async def test_query_is_one_bounded_exchange_without_send_fallback(frames, expected, monkeypatch):
    ws = fake_websocket(frames)
    patch_transport(monkeypatch, ws)
    send = AsyncMock(side_effect=AssertionError("query must never submit a wake"))
    monkeypatch.setattr(adapter, "send_signal", send)
    outcome = await adapter.query_signal(signal(), token=TOKEN)
    assert outcome == expected
    assert ws.received <= 2
    ws.send.assert_awaited_once()
    assert json.loads(ws.send.call_args.args[0]) == {
        **signal().request(1), "type": "mcp:a4a_signal_status"}
    send.assert_not_awaited()
    assert ws.aborted


@pytest.mark.parametrize("close_mode", ["raise", "timeout"])
async def test_query_retained_survives_close_failure(close_mode, monkeypatch):
    ws = fake_websocket([query_reply()])
    if close_mode == "raise":
        ws.close.side_effect = RuntimeError(TOKEN)
    else:
        async def stall():
            await asyncio.sleep(10)

        ws.close = stall
    patch_transport(monkeypatch, ws)
    result = await adapter.query_signal(signal(), token=TOKEN, timeout=0.5)
    assert result == adapter.Outcome("retained", "known")
    ws.send.assert_awaited_once()
    assert ws.received == 1
    assert ws.aborted


def test_unsupported_transport_version_is_refused_before_any_connection():
    """Verify transport-version rejection on every dependency profile.

    A paired channel test existed for an unsupported MCP SDK, but transport had no such
    proof despite the safeguard being present. This became visible when positive adapter
    tests began skipping on baseline versions: skipping them would leave no evidence
    that the version guard worked.

    This test supplies the version itself and does not require a working adapter, so it
    runs with or without the optional profile. Rejection must occur before any connection
    because version resolution precedes handing an address to the transport.
    """
    import importlib.metadata
    import pytest
    adapter = load_adapter() if "load_adapter" in globals() else None
    module = adapter or __import__("a4a_mcp.host_signal", fromlist=["_connect_factory"])
    real = importlib.metadata.version

    def unsupported(name):
        return "99.0.0" if name == "websockets" else real(name)

    original = module.importlib.metadata.version
    module.importlib.metadata.version = unsupported
    try:
        with pytest.raises(module.SignalError, match="untested transport version"):
            module._connect_factory()
    finally:
        module.importlib.metadata.version = original
