"""Owner-configured contacts and local managed inbox, with temporary identities."""
import contextlib
import importlib
import importlib.util
import json
import logging
from dataclasses import replace

import pytest

from a4a import Agent, Keys, files, giftwrap, types
from a4a.event import Event
from a4a.inbox import InboxError
from a4a_mcp import identity, server
from fake_relay import FakeRelay

MANAGED_FILE_REFERENCE = files.build_file_reference(
    "https://public-looking.example/blob", "c" * 64, "b" * 64,
    name="private-name.pdf")


def _json_layers(value, count):
    for _ in range(count):
        value = json.dumps(value)
    return value


MANAGED_FILE_CONTENTS = (
    MANAGED_FILE_REFERENCE,
    json.dumps(MANAGED_FILE_REFERENCE),
    json.dumps({"payload": MANAGED_FILE_REFERENCE}),
    json.dumps([MANAGED_FILE_REFERENCE]),
    json.dumps({MANAGED_FILE_REFERENCE: 1}),
    _json_layers(MANAGED_FILE_REFERENCE, 4),
    '{"payload":' + json.dumps(MANAGED_FILE_REFERENCE),
    '[' + json.dumps(MANAGED_FILE_REFERENCE),
    'prefix ' + json.dumps(MANAGED_FILE_REFERENCE),
    'prefix ' + json.dumps(MANAGED_FILE_REFERENCE)[:-1],
    json.dumps(MANAGED_FILE_REFERENCE)[1:],
    json.dumps(MANAGED_FILE_REFERENCE)[1:-1],
)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / "home")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / "home" / "identity.json")
    monkeypatch.setenv("A4A_MANDATE_AUTO", "0")
    return tmp_path / "home"


@pytest.fixture
def runtime():
    assert importlib.util.find_spec("a4a_mcp.inbox_runtime") is not None, "managed inbox runtime is missing"
    return importlib.import_module("a4a_mcp.inbox_runtime")


def test_missing_policy_is_closed_and_creates_nothing(runtime, home):
    assert runtime.load_policy() is None
    assert runtime.status()["state"] == "unconfigured"
    assert not home.exists()


def test_private_connection_does_not_instruct_model_to_publish_a_profile():
    instructions = server.mcp.instructions
    assert "Connecting does not require publishing a profile" in instructions
    assert "require an explicit owner decision" in instructions


def test_configuration_requires_existing_identity(runtime, home, monkeypatch):
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:17404")
    with pytest.raises(InboxError):
        runtime.configure("session-a", [Keys().pubkey_hex])
    assert not identity.IDENTITY_FILE.exists()


def test_configuration_is_explicit_and_cannot_be_overwritten_accidentally(runtime, home, monkeypatch):
    keys, peer = identity.load_or_create_identity(), Keys()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:17404")
    runtime.configure("session-a", [peer.pubkey_hex], start_after=123)
    policy = runtime.load_policy()
    assert policy.recipient == keys.pubkey_hex
    assert policy.allowed_peers == frozenset({peer.pubkey_hex})
    assert policy.start_after == 123
    assert policy.relay == "ws://127.0.0.1:17404"
    with pytest.raises(InboxError):
        runtime.configure("session-a", [])
    assert runtime.load_policy() == policy


@pytest.mark.parametrize("change", [{"allowed_peers": ["*"]}, {"enabled": "yes"}, {"notify_per_hour": 0}, {"unexpected": True}, {"consumer": "other/session"}])
def test_malformed_policy_fails_closed(runtime, home, monkeypatch, change):
    identity.load_or_create_identity()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:17404")
    runtime.configure("session-a", [Keys().pubkey_hex])
    path = home / "inbox-policy.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(change)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(InboxError):
        runtime.load_policy()


async def test_default_private_read_and_send_do_not_touch_network(home, monkeypatch):
    def forbidden():
        pytest.fail("unconfigured private access must not open relay")
    monkeypatch.setattr(server, "_make_agent", forbidden)
    server._last_unreachable = None
    result = await server.a4a_read_private()
    assert "not configured" in result.lower() or "closed" in result.lower()
    result = await server.a4a_send_private(Keys().pubkey_hex, "do not send")
    assert "not authorized" in result.lower() or "closed" in result.lower()


async def test_default_file_and_connection_tools_are_also_closed(home, monkeypatch):
    def forbidden():
        pytest.fail("unconfigured private path must not open relay")
    monkeypatch.setattr(server, "_make_agent", forbidden)
    server._last_unreachable = None
    peer = Keys().pubkey_hex
    calls = [(server.a4a_send_file, (peer, "missing-blob", "https://files.example/blob")),
             (server.a4a_open_file, ("missing-blob", "missing-output")),
             (server.a4a_request_connection, (peer,)),
             (server.a4a_accept_connection, (peer,)),
             (server.a4a_get_connection_requests, ())]
    for function, args in calls:
        result = await function(*args)
        assert "closed" in result.lower(), function.__name__
    assert not home.exists()


async def test_unknown_sender_file_is_not_opened(runtime, home, monkeypatch, tmp_path):
    me, friend, stranger = identity.load_or_create_identity(), Keys(), Keys()
    blob, key = files.encrypt_file(b"unauthorized file")
    blob_path, output = tmp_path / "blob", tmp_path / "output"
    blob_path.write_bytes(blob)
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        runtime.configure("session-a", [friend.pubkey_hex])
        async with Agent([relay.url], keys=stranger) as author:
            await author.send_file(me.pubkey_hex, url="https://files.example/blob",
                                   sha256=files.sha256_hex(blob), key=key)
        result = await server.a4a_open_file(str(blob_path), str(output))
    assert "No incoming file reference" in result
    assert not output.exists()


async def test_legacy_read_hides_unknown_sender_and_shows_exact_ids(runtime, home, monkeypatch):
    me, friend, stranger = identity.load_or_create_identity(), Keys(), Keys()
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        runtime.configure("session-a", [friend.pubkey_hex])
        async with Agent([relay.url], keys=friend) as author:
            inner_id = await author.send_private_message(me.pubkey_hex, "approved content")
        async with Agent([relay.url], keys=stranger) as author:
            await author.send_private_message(me.pubkey_hex, "DO-NOT-SHOW-OUTSIDER")
        output = await server.a4a_read_private()
        assert "approved content" in output
        assert "DO-NOT-SHOW-OUTSIDER" not in output
        assert inner_id in output and "outer_id=" in output


def test_queue_claim_and_completion_are_separate(runtime, home, monkeypatch):
    me, peer = identity.load_or_create_identity(), Keys()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:17404")
    runtime.configure("session-a", [peer.pubkey_hex])
    with runtime.open_runtime() as (policy, agent, store):
        inner = Event(kind=types.KIND_PRIVATE_RUMOR, tags=[["p", me.pubkey_hex], ["d", "one"]], content="allowed but untrusted")
        inner.sign(peer)
        store.accept(agent, giftwrap.wrap(inner, me.pubkey_hex, peer), policy.allowed_peers)
    message = runtime.claim()
    assert message["state"] == "processing"
    assert "UNTRUSTED" in message["message"]["content"]
    assert runtime.claim()["message"] is None
    runtime.complete(message["message"]["seq"], message["message"]["lease_token"], "processed")
    assert runtime.status()["counts"]["processed"] == 1


async def test_mcp_completion_publishes_wrapped_network_ack(runtime, home, monkeypatch):
    me, peer = identity.load_or_create_identity(), Keys()
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        runtime.configure("session-a", [peer.pubkey_hex])
        async with Agent([relay.url], keys=peer) as sender:
            receipt = await sender.send_private_message_receipt(
                me.pubkey_hex, "process this", delivery_id="managed-ack")
            outer = Event(**next(event for event in relay.events
                                 if event["id"] == receipt["outer_id"]))
            with runtime.open_runtime() as (policy, agent, store):
                assert store.accept(agent, outer, policy.allowed_peers) == "stored"

            claimed = await server.a4a_inbox_next()
            message = claimed["message"]
            completed = await server.a4a_inbox_complete(
                message["seq"], message["lease_token"], "processed")

            assert completed == {
                "state": "processed",
                "seq": message["seq"],
                "network_ack_sent": True,
                "network_ack_state": "sent",
            }
            [ack] = await sender.get_acks(
                receipt["delivery_id"], from_pubkey=me.pubkey_hex)
            assert ack["status"] == "processed"
            assert ack["acked_event_id"] == receipt["inner_id"]


async def test_mcp_completion_retries_only_pending_ack_after_network_failure(
        runtime, home, monkeypatch):
    me, peer = identity.load_or_create_identity(), Keys()
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        runtime.configure("session-a", [peer.pubkey_hex])
        async with Agent([relay.url], keys=peer) as sender:
            receipt = await sender.send_private_message_receipt(
                me.pubkey_hex, "process once", delivery_id="managed-ack-retry")
            outer = Event(**next(event for event in relay.events
                                 if event["id"] == receipt["outer_id"]))
            with runtime.open_runtime() as (policy, agent, store):
                assert store.accept(agent, outer, policy.allowed_peers) == "stored"

            message = (await server.a4a_inbox_next())["message"]
            relay.reject_next_handshakes(1)
            first = await server.a4a_inbox_complete(
                message["seq"], message["lease_token"], "processed")
            assert first["network_ack_sent"] is False
            assert first["network_ack_state"] == "pending"
            pending_counts = runtime.status()["counts"]
            assert pending_counts["processed"] == 1
            assert pending_counts["ack_pending"] == 1
            assert (await server.a4a_inbox_next())["message"] is None

            second = await server.a4a_inbox_complete(
                message["seq"], message["lease_token"], "processed")
            assert second["network_ack_sent"] is True
            assert second["network_ack_state"] == "sent"
            sent_counts = runtime.status()["counts"]
            assert sent_counts["ack_pending"] == 0
            assert sent_counts["ack_sent"] == 1
            [ack] = await sender.get_acks(
                receipt["delivery_id"], from_pubkey=me.pubkey_hex)
            assert ack["status"] == "processed"


async def test_pending_completion_ack_recovers_without_old_lease_token(
        runtime, home, monkeypatch):
    me, peer = identity.load_or_create_identity(), Keys()
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        runtime.configure("session-a", [peer.pubkey_hex])
        async with Agent([relay.url], keys=peer) as sender:
            receipt = await sender.send_private_message_receipt(
                me.pubkey_hex, "survive a restart", delivery_id="managed-ack-crash")
            outer = Event(**next(event for event in relay.events
                                 if event["id"] == receipt["outer_id"]))
            with runtime.open_runtime() as (policy, agent, store):
                assert store.accept(agent, outer, policy.allowed_peers) == "stored"

            message = (await server.a4a_inbox_next())["message"]
            relay.reject_next_handshakes(1)
            first = await server.a4a_inbox_complete(
                message["seq"], message["lease_token"], "failed")
            assert first["network_ack_state"] == "pending"
            del message

            recovered = await runtime.flush_completion_acks()
            assert recovered == {"state": "sent", "sent": 1, "remaining": 0}
            counts = runtime.status()["counts"]
            assert counts["failed"] == 1
            assert counts["ack_pending"] == 0
            assert counts["ack_sent"] == 1
            [ack] = await sender.get_acks(
                receipt["delivery_id"], from_pubkey=me.pubkey_hex)
            assert ack["status"] == "failed"


@pytest.mark.parametrize("reference", MANAGED_FILE_CONTENTS,
                         ids=("raw", "json-string", "object-value", "array-value",
                              "object-key", "layers", "broken-object", "broken-array",
                              "prose-string", "truncated-string", "missing-left-quote",
                              "missing-both-quotes"))
async def test_managed_inbox_claim_redacts_file_reference_before_model_output(
        runtime, home, monkeypatch, reference):
    me, peer = identity.load_or_create_identity(), Keys()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:17404")
    runtime.configure("session-a", [peer.pubkey_hex])
    with runtime.open_runtime() as (policy, agent, store):
        inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                      tags=[["p", me.pubkey_hex], ["d", "file-claim"]],
                      content=reference).sign(peer)
        store.accept(agent, giftwrap.wrap(inner, me.pubkey_hex, peer), policy.allowed_peers)

    output = await server.a4a_inbox_next()
    encoded = json.dumps(output, ensure_ascii=False).casefold().encode("utf-8")
    assert "Receiving files through MCP is not supported".casefold().encode("utf-8") in encoded
    for secret in ("public-looking.example", "private-name.pdf", "c" * 64, "b" * 64):
        assert secret.casefold().encode("utf-8") not in encoded
    for instruction in ("\u0441\u043A\u0430\u0447", "download", "curl", "fetch"):
        assert instruction.encode("utf-8") not in encoded


def test_runtime_exposes_explicit_bound_unknown_reconciliation(runtime, home, monkeypatch):
    me, peer = identity.load_or_create_identity(), Keys()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:17404")
    runtime.configure("session-a", [peer.pubkey_hex])
    with runtime.open_runtime() as (policy, agent, store):
        inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                      tags=[["p", me.pubkey_hex], ["d", "runtime-reconcile"]],
                      content="finished before lease loss", created_at=1).sign(peer)
        store.accept(agent, giftwrap.wrap(inner, me.pubkey_hex, peer, now=2),
                     policy.allowed_peers, now=2)
        claimed = store.claim(agent, policy.consumer, policy.allowed_peers,
                              now=3, lease_seconds=1)
        store.status(now=5)

    with pytest.raises(InboxError, match="reconciliation"):
        runtime.reconcile(claimed["seq"], "f" * 64, "processed")
    result = runtime.reconcile(claimed["seq"], inner.id, "processed")
    assert result == {"state": "processed", "resolution": "processed",
                      "seq": claimed["seq"], "inner_id": inner.id,
                      "network_ack_sent": False}
    assert runtime.status()["counts"]["unknown"] == 0


def test_runtime_retry_rechecks_current_allowed_peer(runtime, home, monkeypatch):
    me, peer = identity.load_or_create_identity(), Keys()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:17404")
    runtime.configure("session-a", [peer.pubkey_hex], start_after=0)
    with runtime.open_runtime() as (stale_policy, agent, store):
        inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                      tags=[["p", me.pubkey_hex], ["d", "policy-reconcile"]],
                      content="uncertain effect", created_at=1).sign(peer)
        store.accept(agent, giftwrap.wrap(inner, me.pubkey_hex, peer, now=2),
                     stale_policy.allowed_peers, now=2)
        claimed = store.claim(agent, stale_policy.consumer, stale_policy.allowed_peers,
                              now=3, lease_seconds=1)
        store.status(now=5)

        runtime.configure("session-a", [], start_after=0, replace=True)

        @contextlib.contextmanager
        def previously_opened_runtime():
            yield stale_policy, agent, store

        monkeypatch.setattr(runtime, "open_runtime", previously_opened_runtime)
        with pytest.raises(InboxError, match="current policy"):
            runtime.reconcile(claimed["seq"], inner.id, "retry")
        assert store.db.execute("SELECT state FROM messages").fetchone()[0] == "unknown"

        runtime.configure("session-a", [peer.pubkey_hex], start_after=0, replace=True)
        assert runtime.reconcile(claimed["seq"], inner.id, "retry")["state"] == "pending"


def test_relay_change_cannot_silently_use_policy_for_another_network(runtime, home, monkeypatch):
    identity.load_or_create_identity()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:17404")
    runtime.configure("session-a", [Keys().pubkey_hex])
    monkeypatch.setenv("A4A_RELAY", "wss://example.org")
    with pytest.raises(InboxError):
        runtime.status()


async def test_missing_configured_identity_cannot_be_regenerated_by_private_read(runtime, home, monkeypatch):
    identity.load_or_create_identity()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1")
    runtime.configure("session-a", [])
    identity.IDENTITY_FILE.unlink()
    server._last_unreachable = None
    result = await server.a4a_read_private()
    assert "identity" in result
    assert not identity.IDENTITY_FILE.exists()


async def test_new_inbox_tools_work_locally_when_relay_is_offline(runtime, home, monkeypatch):
    identity.load_or_create_identity()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1")
    runtime.configure("session-a", [])
    def forbidden():
        pytest.fail("local inbox tools must not connect to the relay")
    monkeypatch.setattr(server, "_make_agent", forbidden)
    result = await server.a4a_inbox_status()
    assert result["state"] == "configured"
    result = await server.a4a_inbox_next()
    assert result["state"] == "receiver_unavailable"
    with pytest.raises(InboxError):
        await server.a4a_inbox_complete(1, "not-a-token", "processed")


def test_unprotected_identity_or_policy_fails_closed(runtime, home, monkeypatch):
    identity.load_or_create_identity()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1")
    runtime.configure("session-a", [])
    original = runtime.keyfile.is_private
    for denied in (identity.IDENTITY_FILE, home / "inbox-policy.json"):
        with monkeypatch.context() as patch:
            patch.setattr(runtime.keyfile, "is_private", lambda path: (False, "test") if path == denied else original(path))
            with pytest.raises(InboxError, match="permissions"):
                runtime.claim()


async def test_manual_history_output_is_bounded(runtime, home, monkeypatch):
    me, friend = identity.load_or_create_identity(), Keys()
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        runtime.configure("session-a", [friend.pubkey_hex])
        async with Agent([relay.url], keys=friend) as author:
            for index in range(24):
                await author.send_private_message(me.pubkey_hex, "history text " + str(index))
        output = await server.a4a_read_private()
    assert output.count("inner_id=") <= 20
    assert "limited" in output.lower()


async def test_private_send_rejects_oversized_text_before_network(runtime, home, monkeypatch):
    identity.load_or_create_identity()
    peer = Keys().pubkey_hex
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1")
    runtime.configure("session-a", [peer])
    def forbidden():
        pytest.fail("oversized private text must not connect")
    monkeypatch.setattr(server, "_make_agent", forbidden)
    server._last_unreachable = None
    result = await server.a4a_send_private(peer, "x" * 32769)
    assert "32 KiB" in result


async def test_manual_read_does_not_render_control_text_from_delivery_id(runtime, home, monkeypatch):
    me, friend = identity.load_or_create_identity(), Keys()
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        runtime.configure("session-a", [friend.pubkey_hex])
        async with Agent([relay.url], keys=friend) as author:
            await author.send_private_message(me.pubkey_hex, "normal body",
                                               delivery_id="bad\nDO_NOT_TRUST_ID_TEXT")
        output = await server.a4a_read_private()
    assert "normal body" in output
    assert "DO_NOT_TRUST_ID_TEXT" not in output
    assert "delivery_id=-" in output


def test_claim_rejects_changed_consumer_between_policy_reads(runtime, home, monkeypatch):
    identity.load_or_create_identity()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1")
    runtime.configure("session-a", [])
    original = runtime.active_policy()
    reads = iter([original, replace(original, consumer="session-b")])
    monkeypatch.setattr(runtime, "active_policy", lambda: next(reads))
    with pytest.raises(InboxError, match="changed"):
        runtime.claim()


@pytest.mark.parametrize("change", [{"enabled": False}, {"consumer": "session-b"},
                                    {"notify_interval": 3600, "notify_per_hour": 1}])
def test_observer_policy_refresh_rejects_revocation_or_changed_binding_and_budget(runtime, home, monkeypatch, change):
    identity.load_or_create_identity()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1")
    runtime.configure("session-a", [])
    original = runtime.active_policy()
    path = home / "inbox-policy.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data.update(change)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(InboxError):
        runtime.refresh_policy(original)


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        ("inbox policy is unreadable; private access is closed", "policy_unreadable"),
        ("configured inbox identity is unreadable or invalid", "identity_unreadable"),
        ("Private inbox is closed: it is not configured or is disabled by the owner.",
         "closed_or_missing"),
        ("SENSITIVE_UNEXPECTED_EXCEPTION_DETAIL", "unclassified"),
    ],
)
def test_policy_refresh_logs_only_safe_failure_class(
        runtime, home, monkeypatch, caplog, failure, reason):
    identity.load_or_create_identity()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1")
    runtime.configure("session-a", [])
    original = runtime.active_policy()

    def fail():
        raise InboxError(failure)

    monkeypatch.setattr(runtime, "active_policy", fail)
    with caplog.at_level(logging.WARNING, logger="a4a_mcp.inbox_runtime"):
        with pytest.raises(InboxError, match="inbox access policy is no longer valid"):
            runtime.refresh_policy(original)

    assert f"reason={reason}" in caplog.text
    assert failure not in caplog.text
    assert "SENSITIVE_UNEXPECTED_EXCEPTION_DETAIL" not in caplog.text


def test_once_rechecks_revocation_after_network_read(runtime, home, monkeypatch, capsys):
    from a4a.inbox_receiver import InboxHistory
    from a4a_mcp.__main__ import _inbox_admin
    identity.load_or_create_identity()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1")
    runtime.configure("session-a", [])
    async def revoke_during_read(self, cursor):
        path = home / "inbox-policy.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["enabled"] = False
        path.write_text(json.dumps(data), encoding="utf-8")
        return []
    monkeypatch.setattr(InboxHistory, "page", revoke_during_read)
    monkeypatch.setattr(runtime.InboxStore, "notice", lambda *a, **kw: pytest.fail("notice after revocation"))
    with pytest.raises(SystemExit, match="policy"):
        _inbox_admin(["inbox-watch", "--once"])
    assert not capsys.readouterr().out


def test_cli_release_returns_the_letter_for_a_later_claim(runtime, home, monkeypatch, capsys):
    """A bridge that could not hand a letter on returns it without a person."""
    from a4a_mcp.__main__ import _inbox_admin
    me, peer = identity.load_or_create_identity(), Keys()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:17404")
    runtime.configure("session-a", [peer.pubkey_hex])
    with runtime.open_runtime() as (policy, agent, store):
        inner = Event(kind=types.KIND_PRIVATE_RUMOR, tags=[["p", me.pubkey_hex], ["d", "one"]],
                      content="hub was down")
        inner.sign(peer)
        store.accept(agent, giftwrap.wrap(inner, me.pubkey_hex, peer), policy.allowed_peers)
    first = runtime.claim()["message"]
    _inbox_admin(["inbox-release", "--seq", str(first["seq"]),
                  "--lease-token", first["lease_token"]])
    assert json.loads(capsys.readouterr().out)["state"] == "pending"
    again = runtime.claim()["message"]
    assert again["seq"] == first["seq"] and again["lease_token"] != first["lease_token"]
    assert runtime.status()["counts"]["ack_sent"] == 0


def test_claim_tells_about_letters_left_unknown_by_an_expired_lease(runtime, home, monkeypatch):
    """26.09.2026: a lease expired, the letter went to unknown and inbox-next never
    mentioned it again. The next claim must say that letters wait for reconciliation."""
    import time as _time
    me, peer = identity.load_or_create_identity(), Keys()
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:17404")
    runtime.configure("session-a", [peer.pubkey_hex])
    with runtime.open_runtime() as (policy, agent, store):
        inner = Event(kind=types.KIND_PRIVATE_RUMOR, tags=[["p", me.pubkey_hex], ["d", "one"]],
                      content="lost tail")
        inner.sign(peer)
        store.accept(agent, giftwrap.wrap(inner, me.pubkey_hex, peer), policy.allowed_peers)
        store.claim(agent, policy.consumer, policy.allowed_peers, now=_time.time() - 600,
                    lease_seconds=1)
    result = runtime.claim()
    assert result["message"] is None
    assert result["unknown_waiting"] == 1
    assert "inbox-unknown" in result["hint"] and "inbox-reconcile" in result["hint"]
