"""Real test-owned HTTP/WS, encrypted relay pages, disk reopen and host restart.

The host records queued hints, not actual model turns. No production host, relay,
credential or project state is used by these tests.
"""
import contextlib
import importlib.metadata
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from a4a import Agent, Keys, giftwrap, keyfile, types
from a4a.event import Event
from a4a.dialogue import DialogueStore
from a4a.inbox import InboxStore

from a4a_mcp import wake_runtime
from a4a_mcp.wake_journal import journal_status
from test_host_signal import only_test_owned_sockets
from test_wake_journal import BINDING, RELAY, add


TOKEN = "synthetic-e2e-wake-only-token"
BODY = "synthetic private message that must stay out of host hints"


@pytest.mark.parametrize("action", ["send", "query"])
@pytest.mark.parametrize("change", ["revoke", "lease", "invalid_policy"])
@pytest.mark.requires_host_signal
async def test_handshake_change_prevents_signal_frame(
        tmp_path, only_test_owned_sockets, action, change):
    from websockets.asyncio.server import serve
    from a4a.inbox import InboxPolicyChanged
    from a4a_mcp.host_signal import Outcome
    from a4a_mcp.wake_journal import WakeJournal, WakeBlocked

    peer, keys = Keys(), Keys()
    agent = Agent([RELAY], keys=keys)
    allowed = {peer.pubkey_hex}
    frames = []
    changed = False
    with DialogueStore(tmp_path / "inbox", agent.pubkey, BINDING.consumer) as store:
        if change == "lease":
            store.activate()
        add((store, agent, peer, allowed, None))

        async def handshake(connection, request):
            nonlocal changed
            changed = True
            if change == "revoke":
                allowed.clear()
            elif change == "lease":
                assert store.acquire(peer.pubkey_hex, "worker", allowed, now=50, lease_seconds=100)

        async def host(ws):
            async for frame in ws:
                frames.append(frame)

        def peers():
            if change == "invalid_policy" and changed:
                raise InboxPolicyChanged(TOKEN)
            return allowed

        async with serve(host, "127.0.0.1", 0, process_request=handshake) as server:
            port = server.sockets[0].getsockname()[1]
            only_test_owned_sockets.add(("127.0.0.1", port))
            journal = WakeJournal(store, BINDING, f"ws://127.0.0.1:{port}/", RELAY)
            if action == "query":
                previous = journal.begin(allowed, now=10, interval=10, per_hour=12)
                journal.finish(previous, Outcome("accepted", "queued"), now=10)
            worker = wake_runtime.WakeRunner(journal, peers, lambda: TOKEN, clock=lambda: 50,
                                             interval=10, per_hour=12)
            if change == "invalid_policy":
                with pytest.raises(WakeBlocked) as exc:
                    await worker.tick()
                assert TOKEN not in str(exc.value)
                assert journal_status(store, now=50)["reason"] == "preflight_failed"
            else:
                await worker.tick()
                assert journal_status(store, now=50)["state"] == "idle"
        assert changed and frames == []


@pytest.mark.parametrize("managed", [False, True])
async def test_lost_ack_disk_reopen_host_restart_and_drain(
        tmp_path, monkeypatch, only_test_owned_sockets, managed):
    if importlib.metadata.version("websockets") != "13.1":
        pytest.skip("candidate transport currently enables 13.1")
    from websockets.asyncio.server import serve
    from websockets.http11 import Response
    from websockets.datastructures import Headers

    owner, peer, stranger = Keys(), Keys(), Keys()
    directory = tmp_path / "inbox"
    token_file = tmp_path / "wake-token"
    token_file.write_bytes(TOKEN.encode("ascii"))
    assert keyfile.harden_and_check(token_file, force=True)[0]
    pages = []
    for index, sender in enumerate((peer, stranger), 1):
        inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                      tags=[["p", owner.pubkey_hex], ["d", f"delivery-{index}"]],
                      content=BODY).sign(sender)
        outer = giftwrap.wrap(inner, owner.pubkey_hex, sender)
        pages.append({"first_seen": 100 + index, "event": outer.model_dump()})

    async def relay_http(connection, request):
        if request.headers.get("Upgrade", "").lower() == "websocket":
            return None
        url = urlsplit(request.path)
        assert url.path == "/v1/inbox"
        query = parse_qs(url.query, keep_blank_values=True)
        assert query["recipient"] == [owner.pubkey_hex]
        cursor = (int(query["after"][0]), query["after_id"][0])
        rows = [row for row in pages if (row["first_seen"], row["event"]["id"]) > cursor]
        next_cursor = {"first_seen": rows[-1]["first_seen"], "id": rows[-1]["event"]["id"]} if rows else None
        body = json.dumps({"version": 2, "recipient": owner.pubkey_hex,
                           "rows": rows, "next_cursor": next_cursor}).encode()
        return Response(200, "OK", Headers({"Content-Type": "application/json"}), body)

    async def relay_ws(ws):
        async for raw in ws:
            request = json.loads(raw)
            if request[0] == "REQ":
                await ws.send(json.dumps(["EOSE", request[1]]))

    queued = []
    operations = []
    retained = {}
    drop_ack = [True]

    async def host(ws):
        assert ws.request.headers["X-A4A-Host-Token"] == TOKEN
        await ws.send(json.dumps({"type": "welcome",
            "clientId": "01234567-89ab-cdef-0123-456789abcdef", "message": "Connected to Host"}))
        request = json.loads(await ws.recv())
        assert set(request) == {"type", "requestId", "version", "projectId", "consumer",
                                "targetSessionId", "signalId", "mode", "counters"}
        assert request["projectId"] == "isolated-test-project"
        assert request["consumer"] == "isolated-test-consumer"
        assert request["targetSessionId"] == "isolated-test-session"
        assert request["mode"] == ("dialogue" if managed else "inbox")
        assert request["counters"]["pending"] == "1"
        assert BODY not in json.dumps(request) and TOKEN not in json.dumps(request)
        signal_id = request["signalId"]
        body = {key: value for key, value in request.items() if key not in ("type", "requestId")}
        operations.append(request["type"])
        if request["type"] == "mcp:a4a_inbox_signal":
            if signal_id not in retained:
                retained[signal_id] = body
                queued.append(signal_id)
            else:
                assert retained[signal_id] == body
            if drop_ack[0]:
                drop_ack[0] = False
                return
            status, reason = "accepted", "queued"
        else:
            assert request["type"] == "mcp:a4a_signal_status"
            if signal_id in retained:
                assert retained[signal_id] == body
                status, reason = "retained", "known"
            else:
                status, reason = "absent", "not_found"
        await ws.send(json.dumps({"type": request["type"] + ":response",
            "requestId": request["requestId"], "version": "1", "signalId": signal_id,
            "success": True, "status": status, "reasonCode": reason}))

    async with serve(relay_ws, "127.0.0.1", 0, process_request=relay_http) as relay_server:
        relay_port = relay_server.sockets[0].getsockname()[1]
        only_test_owned_sockets.add(("127.0.0.1", relay_port))
        relay_url = f"ws://127.0.0.1:{relay_port}"
        policy = SimpleNamespace(start_after=0, allowed_peers=frozenset({peer.pubkey_hex}),
            consumer="isolated-test-consumer", relay=relay_url, notify_interval=10, notify_per_hour=12,
            ack_on_receipt=False)
        with DialogueStore(directory, owner.pubkey_hex, policy.consumer) as store:
            if managed:
                store.activate()

        @contextlib.contextmanager
        def runtime():
            # Each receiver invocation opens a new SQLite connection from disk.
            with InboxStore(directory, owner.pubkey_hex, policy.consumer) as store:
                yield policy, Agent([relay_url], keys=owner), store

        monkeypatch.setattr(wake_runtime.inbox_runtime, "open_runtime", runtime)
        monkeypatch.setattr(wake_runtime.inbox_runtime, "refresh_policy", lambda _: policy)
        clock = [10]
        original = wake_runtime.WakeRunner
        monkeypatch.setattr(wake_runtime, "WakeRunner",
            lambda *args, **kwargs: original(*args, **kwargs, clock=lambda: clock[0]))
        app = await serve(host, "127.0.0.1", 0, reuse_address=True)
        port = app.sockets[0].getsockname()[1]
        only_test_owned_sockets.add(("127.0.0.1", port))
        endpoint = f"ws://127.0.0.1:{port}/"

        async def once():
            return await wake_runtime.run_wake("isolated-test-project", "isolated-test-session",
                                               token_file, endpoint=endpoint, once=True)

        try:
            first = await once()
            assert first["state"] == "unknown" and len(queued) == 1
            clock[0] = 50
            assert (await once())["state"] == "retained"
            assert len(queued) == 1
            assert operations == ["mcp:a4a_inbox_signal", "mcp:a4a_signal_status"]

            app.close()
            await app.wait_closed()
            retained.clear()
            app = await serve(host, "127.0.0.1", port, reuse_address=True)
            clock[0] = 100
            assert (await once())["state"] == "prepared"
            clock[0] = 101
            assert (await once())["state"] == "retained"
            assert len(queued) == 2 and queued[0] == queued[1]

            with DialogueStore(directory, owner.pubkey_hex, policy.consumer) as store:
                if managed:
                    lease = store.acquire(peer.pubkey_hex, "worker", policy.allowed_peers,
                                          now=102, lease_seconds=100)
                    # Holding the lease alone removes this work from eligible hints.
                    assert lease is not None
                else:
                    message = store.claim(Agent([relay_url], keys=owner), policy.consumer,
                                          policy.allowed_peers, now=102)
                    assert message["content"] == BODY
                    store.finish(message["seq"], message["lease_token"], policy.consumer, "processed", now=103)
                assert store.status(now=103)["total"] == 1, "stranger must never enter eligible work"
            clock[0] = 104
            before = len(operations)
            assert (await once())["state"] == "idle"
            assert len(operations) == before
        finally:
            app.close()
            await app.wait_closed()
