"""Model-free recovery runner: synthetic inboxes, credentials and host responses."""
import asyncio
import contextlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from a4a import keyfile
from a4a.inbox import InboxError, InboxPolicyChanged

from test_wake_journal import mailbox, add, BINDING, ENDPOINT, RELAY
from test_host_signal import only_test_owned_sockets
from a4a_mcp.host_signal import Outcome, SignalError
from a4a_mcp.wake_journal import WakeJournal, WakeBlocked, journal_status
from a4a_mcp.wake_runtime import WakeRunner, read_token_file, run_wake
from a4a_mcp import wake_runtime


TOKEN = "synthetic-wake-only-token"


class Host:
    def __init__(self):
        self.seen = {}
        self.sends = self.queries = 0
        self.lose_ack = False

    async def send(self, signal, **kwargs):
        assert kwargs["token"] == TOKEN
        self.sends += 1
        self.seen[signal.signal_id] = signal
        return Outcome("unknown", "timeout") if self.lose_ack else Outcome("accepted", "queued")

    async def query(self, signal, **kwargs):
        assert kwargs["token"] == TOKEN
        self.queries += 1
        if signal.signal_id in self.seen:
            assert self.seen[signal.signal_id] == signal
            return Outcome("retained", "known")
        return Outcome("absent", "not_found")


def runner(box, clock, host, **options):
    return WakeRunner(box[-1], lambda: box[3], lambda: TOKEN,
                      send=host.send, query=host.query, clock=lambda: clock[0],
                      interval=10, per_hour=12, **options)


async def test_empty_inbox_never_reads_token_or_calls_host(mailbox):
    host, clock = Host(), [10]
    worker = runner(mailbox, clock, host)
    worker.token_loader = lambda: pytest.fail("empty inbox must not load credential")
    for value in (10, 100, 10000):
        clock[0] = value
        await worker.tick()
    assert host.sends == host.queries == 0


async def test_lost_ack_is_queried_not_sent_again(mailbox):
    add(mailbox)
    host, clock = Host(), [10]
    host.lose_ack = True
    worker = runner(mailbox, clock, host)
    await worker.tick()
    clock[0] = 50
    await worker.tick()
    assert host.sends == host.queries == 1
    assert journal_status(mailbox[0], now=50)["state"] == "retained"
    assert mailbox[0].status(now=50)["pending"] == 1


async def test_host_restart_recovers_unchanged_work_without_new_identity(mailbox):
    add(mailbox)
    host, clock = Host(), [10]
    worker = runner(mailbox, clock, host)
    await worker.tick()
    signal_id = next(iter(host.seen))
    host.seen.clear()
    clock[0] = 50
    await worker.tick()
    assert host.sends == 1 and host.queries == 1
    clock[0] = 51
    await worker.tick()
    assert host.sends == 2 and list(host.seen) == [signal_id]


async def test_receiver_reopen_recovers_unknown_from_disk(mailbox):
    from a4a.inbox import InboxStore
    add(mailbox)
    host, clock = Host(), [10]
    host.lose_ack = True
    await runner(mailbox, clock, host).tick()
    directory, recipient = mailbox[0].path.parent, mailbox[1].pubkey
    mailbox[0].db.close()
    with InboxStore(directory, recipient, BINDING.consumer) as reopened:
        journal = WakeJournal(reopened, BINDING, ENDPOINT, RELAY)
        clock[0] = 50
        box = (reopened, mailbox[1], mailbox[2], mailbox[3], journal)
        await runner(box, clock, host).tick()
        assert host.sends == host.queries == 1
        assert journal_status(reopened, now=50)["state"] == "retained"


async def test_revocation_during_credential_read_prevents_io(mailbox):
    add(mailbox)
    host, clock = Host(), [10]
    worker = runner(mailbox, clock, host)

    def token():
        mailbox[3].clear()
        return TOKEN

    worker.token_loader = token
    await worker.tick()
    assert host.sends == host.queries == 0


async def test_policy_invalidated_before_io_stops_loudly(mailbox):
    add(mailbox)
    host, clock = Host(), [10]
    worker = runner(mailbox, clock, host)
    count = 0

    def peers():
        nonlocal count
        count += 1
        if count > 1:
            raise InboxPolicyChanged("synthetic invalidation")
        return mailbox[3]

    worker.allowed_senders = peers
    with pytest.raises(InboxError):
        await worker.tick()
    assert host.sends == host.queries == 0


@pytest.mark.parametrize("failure", ["credential", "transport", "reject"])
async def test_configuration_failures_are_persisted_and_not_hidden(mailbox, failure):
    add(mailbox)
    host, clock = Host(), [10]
    worker = runner(mailbox, clock, host)
    if failure == "credential":
        worker.token_loader = lambda: (_ for _ in ()).throw(ValueError(TOKEN))
    elif failure == "transport":
        async def fail(*args, **kwargs):
            raise SignalError(TOKEN)
        worker.send = fail
    else:
        async def reject(*args, **kwargs):
            return Outcome("rejected", "not_authorized")
        worker.send = reject
    with pytest.raises(WakeBlocked) as exc:
        await worker.tick()
    assert TOKEN not in str(exc.value)
    assert journal_status(mailbox[0], now=10)["state"] == "failed"
    clock[0] = 100
    with pytest.raises(WakeBlocked):
        await worker.tick()


async def test_cancellation_leaves_unknown_for_recovery(mailbox):
    add(mailbox)
    host, clock = Host(), [10]
    worker = runner(mailbox, clock, host)
    started = asyncio.Event()

    async def send(*args, **kwargs):
        started.set()
        await asyncio.sleep(10)

    worker.send = send
    task = asyncio.create_task(worker.tick())
    await asyncio.wait_for(started.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    clock[0] = 50
    await runner(mailbox, clock, host).tick()
    assert host.sends == 0 and host.queries == 1


def private_token(tmp_path, data=TOKEN):
    path = tmp_path / "wake-token"
    path.write_bytes(data.encode("utf-8"))
    assert keyfile.harden_and_check(path, force=True)[0]
    return path


@pytest.mark.parametrize("ending", ["", "\n", "\r\n"])
def test_private_token_file_is_read_without_modification(tmp_path, ending):
    path = private_token(tmp_path, TOKEN + ending)
    before = path.read_bytes()
    assert read_token_file(path) == TOKEN
    assert path.read_bytes() == before


@pytest.mark.parametrize("data", ["", "a b", "a\nb", " x", "x" * 4097, "\u043D\u0435 \u0442\u043E\u043A\u0435\u043D"])
def test_invalid_token_file_fails_redacted(tmp_path, data):
    path = private_token(tmp_path, data)
    with pytest.raises(InboxError, match="credential"):
        read_token_file(path)


def test_shared_token_file_is_rejected_not_silently_hardened(tmp_path, monkeypatch):
    path = private_token(tmp_path)
    monkeypatch.setattr(keyfile, "is_private", lambda _: (False, "synthetic"))
    with pytest.raises(InboxError):
        read_token_file(path)


def test_unsafe_token_permissions_fail_before_open(tmp_path, monkeypatch):
    path = private_token(tmp_path)
    monkeypatch.setattr(keyfile, "is_private", lambda _: (False, "synthetic"))
    monkeypatch.setattr(os, "open", lambda *_args, **_kwargs:
                        pytest.fail("unsafe credential must not be opened"))
    with pytest.raises(InboxError, match="credential"):
        read_token_file(path)


def test_token_privacy_is_rechecked_after_read(tmp_path, monkeypatch):
    path = private_token(tmp_path)
    results = iter(((True, None), (False, "changed")))
    monkeypatch.setattr(keyfile, "is_private", lambda _: next(results))
    with pytest.raises(InboxError, match="credential"):
        read_token_file(path)


def test_hardlinked_token_file_is_rejected(tmp_path):
    path = private_token(tmp_path)
    os.link(path, tmp_path / "alias")
    with pytest.raises(InboxError):
        read_token_file(path)


def test_hardlink_rejection_does_not_depend_on_permission_helper(tmp_path, monkeypatch):
    path = private_token(tmp_path)
    os.link(path, tmp_path / "alias-independent")
    monkeypatch.setattr(keyfile, "is_private", lambda _: (True, None))
    with pytest.raises(InboxError, match="credential"):
        read_token_file(path)


def test_open_descriptor_metadata_is_validated_independently(tmp_path, monkeypatch):
    path = private_token(tmp_path)
    actual = path.lstat()
    opened = SimpleNamespace(st_mode=actual.st_mode, st_nlink=2, st_file_attributes=0,
                             st_ino=actual.st_ino, st_dev=actual.st_dev)
    monkeypatch.setattr(wake_runtime.os, "fstat", lambda _fd: opened)
    monkeypatch.setattr(keyfile, "is_private", lambda _: (True, None))
    with pytest.raises(InboxError, match="credential"):
        read_token_file(path)


@pytest.mark.parametrize("path", ["relative-token", "C:/not-present-a4a-test/token"])
def test_missing_or_relative_token_fails_redacted(path):
    with pytest.raises(InboxError):
        read_token_file(path)


@pytest.mark.parametrize("options", [
    {"once": 1}, {"forever": 1}, {"resume": 1}, {"once": True, "forever": True},
])
async def test_run_wake_rejects_invalid_lifetime_flags_before_credentials(monkeypatch, options):
    monkeypatch.setattr(wake_runtime, "read_token_file",
                        lambda _path: pytest.fail("invalid lifetime reached credential"))
    with pytest.raises(InboxError, match="lifetime"):
        await run_wake("project", "session", "unused", **options)


@pytest.mark.parametrize("duration", [True, 0, 86401, 1.0, "60"])
async def test_run_wake_rejects_invalid_duration_before_credentials(monkeypatch, duration):
    monkeypatch.setattr(wake_runtime, "read_token_file",
                        lambda _path: pytest.fail("invalid duration reached credential"))
    with pytest.raises(InboxError, match="duration"):
        await run_wake("project", "session", "unused", duration=duration)


@pytest.mark.parametrize("endpoint", [None, "ws://localhost:9876/",
                                       "ws://127.0.0.1:0/", "ws://127.0.0.1:65536/"])
async def test_run_wake_rejects_invalid_endpoint_before_credentials(monkeypatch, endpoint):
    monkeypatch.setattr(wake_runtime, "read_token_file",
                        lambda _path: pytest.fail("invalid endpoint reached credential"))
    with pytest.raises(InboxError, match="numeric IPv4 loopback"):
        await run_wake("project", "session", "unused", endpoint=endpoint)


async def test_unrelated_timeout_is_not_mistaken_for_runner_deadline(monkeypatch):
    policy = SimpleNamespace(start_after=0, allowed_peers=set(), consumer="test-consumer",
                             relay=RELAY, notify_interval=10, notify_per_hour=12,
                             ack_on_receipt=False)

    @contextlib.contextmanager
    def runtime():
        yield policy, object(), object()

    class Receiver:
        def __init__(self, *_args, **_kwargs):
            pass

        async def run_ticks(self, *_args, **_kwargs):
            raise TimeoutError("unrelated synthetic timeout")

    monkeypatch.setattr(wake_runtime, "read_token_file", lambda _path: TOKEN)
    monkeypatch.setattr(wake_runtime.inbox_runtime, "open_runtime", runtime)
    monkeypatch.setattr(wake_runtime, "InboxReceiver", Receiver)
    with pytest.raises(TimeoutError, match="unrelated synthetic timeout"):
        await run_wake("project", "session", "unused", duration=60)


async def test_run_once_owns_receive_and_wake_without_new_model_or_stdout(mailbox, tmp_path, monkeypatch, capsys):
    from a4a.inbox_receiver import InboxReceiver
    add(mailbox)
    policy = SimpleNamespace(start_after=0, allowed_peers=mailbox[3], consumer=BINDING.consumer,
                             relay=RELAY, notify_interval=10, notify_per_hour=12,
                             ack_on_receipt=False)

    @contextlib.contextmanager
    def runtime():
        yield policy, mailbox[1], mailbox[0]

    async def sync(receiver):
        receiver.store.set_health("ready")
        return 0

    async def stream(receiver):
        await asyncio.sleep(10)

    host = Host()
    monkeypatch.setattr(wake_runtime.inbox_runtime, "open_runtime", runtime)
    monkeypatch.setattr(wake_runtime.inbox_runtime, "refresh_policy", lambda _: policy)
    monkeypatch.setattr(InboxReceiver, "_sync_once", sync)
    monkeypatch.setattr(InboxReceiver, "_stream_hints", stream)
    monkeypatch.setattr(wake_runtime, "send_signal", host.send)
    monkeypatch.setattr(wake_runtime, "query_signal", host.query)
    result = await run_wake(BINDING.project_id, BINDING.target_session_id,
                           private_token(tmp_path), endpoint=ENDPOINT, once=True)
    assert result["state"] == "retained"
    assert host.sends == 1
    assert mailbox[0].health()["state"] == "stopped"
    assert capsys.readouterr().out == ""
