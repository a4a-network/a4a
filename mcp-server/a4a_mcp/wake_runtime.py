"""Model-free receiver attachment with durable, explicitly scoped host hints."""
import asyncio
import os
from pathlib import Path
import stat
import time

from a4a import keyfile
from a4a.inbox import InboxError, InboxPolicyChanged
from a4a.inbox_receiver import InboxReceiver, authorized_sender_keys

from . import inbox_runtime
from .host_signal import Binding, Outcome, SignalError, send_signal, query_signal, _TOKEN, _ENDPOINT
from .wake_journal import WakeJournal, WakeBlocked, journal_status


def read_token_file(value):
    """Read an explicit private regular file, without changing its permissions."""
    from .owner_admin import _safe_path
    fd = None
    try:
        path = _safe_path(Path(value))
        before = path.lstat()
        if before.st_size > 4098 or not keyfile.is_private(path)[0]:
            raise ValueError()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or getattr(opened, "st_file_attributes", 0) & 0x400
                or not os.path.samestat(before, opened)):
            raise ValueError()
        raw = os.read(fd, 4099)
        _safe_path(path)
        if not os.path.samestat(opened, path.lstat()) or not keyfile.is_private(path)[0]:
            raise ValueError()
        token = raw.decode("ascii")
        if token.endswith("\r\n"):
            token = token[:-2]
        elif token.endswith("\n"):
            token = token[:-1]
        if _TOKEN.fullmatch(token) is None:
            raise ValueError()
        return token
    except (OSError, ValueError, TypeError):
        raise InboxError("host wake credential unavailable or unsafe; use an explicit private token file") from None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                raise InboxError("host wake credential file could not be closed") from None


class WakeRunner:
    def __init__(self, journal, allowed_senders, token_loader, *, interval=60, per_hour=12,
                 send=None, query=None, clock=time.time):
        self.journal = journal
        self.allowed_senders, self.token_loader = allowed_senders, token_loader
        self.interval, self.per_hour = interval, per_hour
        self.send, self.query = send or send_signal, query or query_signal
        self.clock = clock

    def _fail(self, attempt, reason):
        self.journal.finish(attempt, Outcome("rejected", reason), now=self.clock())
        raise WakeBlocked("host wake blocked; inspect inbox-status and resume only after correction") from None

    async def tick(self):
        """Called only while holding the inbox receiver lock. Never invokes a model."""
        attempt = self.journal.begin(self.allowed_senders(), now=self.clock(),
                                     interval=self.interval, per_hour=self.per_hour)
        if attempt is None:
            return
        try:
            token = self.token_loader()
        except Exception:
            self._fail(attempt, "credential_unavailable")
        try:
            current = self.journal.current(attempt, self.allowed_senders(), now=self.clock())
        except InboxPolicyChanged:
            self._fail(attempt, "policy_changed")
        if not current:
            return
        operation = self.send if attempt.action == "send" else self.query
        try:
            outcome = await operation(attempt.signal, token=token, endpoint=self.journal.endpoint,
                before_send=lambda: self.journal.current(
                    attempt, self.allowed_senders(), now=self.clock()))
        except SignalError:
            self._fail(attempt, "transport_configuration")
        except Exception:
            outcome = Outcome("unknown", "transport_failed")
        if outcome == Outcome("not_sent", "preflight_failed"):
            self._fail(attempt, "preflight_failed")
        self.journal.finish(attempt, outcome, now=self.clock())
        if journal_status(self.journal.store, now=self.clock())["state"] == "failed":
            raise WakeBlocked("host rejected wake; inspect inbox-status and resume only after correction")


async def run_wake(project_id, target_session_id, token_file, *, endpoint="ws://127.0.0.1:9876/",
                   once=False, duration=3600, forever=False, resume=False):
    """Explicit local runner; no service installation or host credential issuance."""
    if type(once) is not bool or type(forever) is not bool or type(resume) is not bool or (once and forever):
        raise InboxError("invalid host wake lifetime")
    if type(duration) is not int or not 1 <= duration <= 86400:
        raise InboxError("host wake duration must be 1..86400 seconds")
    match = _ENDPOINT.fullmatch(endpoint) if type(endpoint) is str else None
    if not match or int(match[1]) > 65535:
        raise InboxError("host wake requires numeric IPv4 loopback")
    # Fail before opening a profile/receiver when a credential file isn't usable.
    read_token_file(token_file)
    with inbox_runtime.open_runtime() as (policy, agent, store):
        binding = Binding(project_id, target_session_id, policy.consumer)
        receiver = InboxReceiver(agent, store,
            lambda: inbox_runtime.refresh_policy(policy).allowed_peers, start_after=policy.start_after,
            ack_on_receipt=policy.ack_on_receipt,
            allowed_owners=lambda: getattr(inbox_runtime.refresh_policy(policy),
                                            "allowed_owners", frozenset()))
        worker = None
        owner_agents = frozenset()
        owner_snapshot = getattr(policy, "allowed_owners", frozenset())

        def current_senders():
            current = inbox_runtime.refresh_policy(policy)
            if getattr(current, "allowed_owners", frozenset()) != owner_snapshot:
                raise InboxPolicyChanged("owner trust changed during host wake; retry the tick")
            return current.allowed_peers | owner_agents

        async def tick():
            nonlocal worker, owner_agents, owner_snapshot
            current = inbox_runtime.refresh_policy(policy)
            owners = getattr(current, "allowed_owners", frozenset())
            permitted = await authorized_sender_keys(
                agent, current.allowed_peers, owners,
                store.pending_sender_keys())
            owner_agents = frozenset(permitted - current.allowed_peers)
            owner_snapshot = owners
            if worker is None:
                # Initialization and explicit resume happen under run_ticks' OS lock.
                journal = WakeJournal(store, binding, endpoint, policy.relay)
                if resume:
                    journal.resume()
                worker = WakeRunner(journal,
                    current_senders,
                    lambda: read_token_file(token_file),
                    interval=policy.notify_interval, per_hour=policy.notify_per_hour)
            await worker.tick()

        deadline = asyncio.timeout(None if forever else duration)
        try:
            async with deadline:
                await receiver.run_ticks(tick, once=once)
        except TimeoutError:
            if not deadline.expired():
                raise
            # Cancellation during a socket exchange leaves its committed unknown
            # record for a status query on restart, never an automatic action replay.
            pass
        return journal_status(store)
