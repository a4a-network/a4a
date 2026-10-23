"""One durable, coalesced host hint in the existing private inbox database."""
from dataclasses import asdict, dataclass
import json
import secrets
import time

from a4a.inbox import InboxError
from a4a.inbox_receiver import InboxHistory

from .host_signal import Binding, Outcome, PreparedSignal, prepare_signal, _ENDPOINT


_STATES = {"idle", "prepared", "unknown", "retained", "failed"}
_REASONS = {"not_authorized", "unknown_pair", "unsupported_version", "invalid_signal",
            "signal_id_conflict", "no_work", "host_blocked", "access_denied",
            "credential_unavailable", "transport_configuration", "policy_changed", "preflight_failed"}
_TRANSPORT = {"timeout", "transport_failed", "invalid_response"}


class WakeBlocked(InboxError):
    """Persistent rejection; correction and explicit local resume are required."""


def _time(value=None):
    value = time.time() if value is None else value
    if type(value) not in (int, float) or not 0 <= value <= 2**53 - 1:
        raise InboxError("invalid host wake clock")
    return value


def journal_status(store, *, now=None):
    if not store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='host_wake'").fetchone():
        return {"state": "unconfigured", "host_wake": "unverified"}
    row = store.db.execute("SELECT state,reason,updated,due FROM host_wake WHERE singleton=1").fetchone()
    if row is None or row["state"] not in _STATES:
        raise InboxError("invalid host wake journal")
    return {"state": row["state"], "reason": row["reason"], "checked_at": row["updated"],
            "next_check_at": row["due"], "stale": _time(now) - row["updated"] > 90,
            "host_wake": "unverified"}


@dataclass(frozen=True)
class Attempt:
    action: str
    signal: PreparedSignal
    ticket: str


class WakeJournal:
    """Called by one OS-locked receiver; SQL tickets additionally fence stale ACKs.

    Prepared attempts contain no message bodies or host credentials. A host ACK
    never finishes an inbox item. Host queries reconcile hints, not agent actions.
    """

    def __init__(self, store, binding, endpoint, relay):
        if type(binding) is not Binding or binding.consumer != store.consumer:
            raise InboxError("host wake binding differs from inbox consumer")
        match = _ENDPOINT.fullmatch(endpoint) if type(endpoint) is str else None
        if not match or int(match[1]) > 65535:
            raise InboxError("host wake requires numeric IPv4 loopback")
        InboxHistory(relay, store.recipient)
        self.store, self.binding = store, binding
        self.endpoint = endpoint
        encoded = json.dumps({"version": 1, "recipient": store.recipient, "relay": relay,
                              "endpoint": endpoint, **asdict(binding)}, sort_keys=True)
        with store._transaction():
            prior = store.db.execute("SELECT value FROM metadata WHERE key='host_wake_binding'").fetchone()
            if prior is not None and prior[0] != encoded:
                raise InboxError("host wake binding changed; explicit migration is required")
            store.db.execute("INSERT OR IGNORE INTO metadata VALUES ('host_wake_binding',?)", (encoded,))
            store.db.execute("""CREATE TABLE IF NOT EXISTS host_wake (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                fingerprint TEXT, notice TEXT, signal_id TEXT,
                state TEXT NOT NULL, reason TEXT NOT NULL,
                due REAL NOT NULL, failures INTEGER NOT NULL,
                ticket TEXT, action TEXT, updated REAL NOT NULL)""")
            store.db.execute("""INSERT OR IGNORE INTO host_wake
                VALUES (1,NULL,NULL,NULL,'idle','empty',0,0,NULL,NULL,0)""")

    def _row(self):
        row = self.store.db.execute("SELECT * FROM host_wake WHERE singleton=1").fetchone()
        if row is None or row["state"] not in _STATES:
            raise InboxError("invalid host wake journal")
        return row

    def _observe(self, allowed, now):
        row = self._row()
        if now < row["updated"]:
            raise InboxError("host wake clock moved backwards; check local clock")
        if row["state"] == "failed":
            raise WakeBlocked("host wake is blocked; inspect inbox-status and resume after correction")
        snapshot = self.store._work_snapshot(allowed, now)
        if snapshot["fingerprint"] != row["fingerprint"]:
            if snapshot["fingerprint"] is None:
                self.store.db.execute("""UPDATE host_wake SET fingerprint=NULL,notice=NULL,
                    signal_id=NULL,state='idle',reason='empty',due=0,failures=0,
                    ticket=NULL,action=NULL,updated=? WHERE singleton=1""", (now,))
            else:
                signal = prepare_signal(snapshot["notice"], self.binding)
                self.store.db.execute("""UPDATE host_wake SET fingerprint=?,notice=?,signal_id=?,
                    state='prepared',reason='new_work',due=0,failures=0,ticket=NULL,
                    action=NULL,updated=? WHERE singleton=1""",
                    (snapshot["fingerprint"], json.dumps(snapshot["notice"], sort_keys=True),
                     signal.signal_id, now))
        else:
            self.store.db.execute("UPDATE host_wake SET updated=? WHERE singleton=1", (now,))
        return self._row()

    def begin(self, allowed, *, now=None, interval=60, per_hour=12):
        """Reserve one send/query transactionally, then allow the caller to do I/O."""
        now = _time(now)
        if type(interval) is not int or not 10 <= interval <= 3600:
            raise InboxError("invalid host wake interval")
        if type(per_hour) is not int or not 1 <= per_hour <= 60:
            raise InboxError("invalid host wake budget")
        with self.store._transaction():
            row = self._observe(allowed, now)
            if row["state"] == "idle" or now < row["due"]:
                return None
            action = "send" if row["state"] == "prepared" else "query"
            try:
                signal = prepare_signal(json.loads(row["notice"]), self.binding,
                                        signal_id=row["signal_id"])
            except (ValueError, TypeError):
                raise InboxError("invalid host wake journal metadata") from None
            if action == "send" and not self.store._reserve_wake(now, interval, per_hour):
                return None
            ticket = secrets.token_hex(16)
            # Crash or cancellation after this commit is unknown, including when
            # the process dies before it actually writes to the socket.
            self.store.db.execute("""UPDATE host_wake SET state='unknown',reason='in_flight',
                ticket=?,action=?,due=?,updated=? WHERE singleton=1""", (ticket, action, now + 30, now))
            return Attempt(action, signal, ticket)

    def current(self, attempt, allowed, *, now=None):
        """Recheck eligibility immediately before I/O (after credential/policy I/O)."""
        with self.store._transaction():
            row = self._observe(allowed, _time(now))
            return row["signal_id"] == attempt.signal.signal_id and row["ticket"] == attempt.ticket

    def finish(self, attempt, outcome, *, now=None):
        now = _time(now)
        with self.store._transaction():
            row = self._row()
            if row["signal_id"] != attempt.signal.signal_id or row["ticket"] != attempt.ticket:
                return False
            if now < row["updated"]:
                raise InboxError("host wake clock moved backwards; check local clock")
            state, reason, failures, due = "unknown", "invalid_response", min(row["failures"] + 1, 8), now
            if type(outcome) is Outcome:
                if ((attempt.action == "send" and (outcome.status, outcome.reason) in (
                        ("accepted", "queued"), ("deferred", "busy"), ("duplicate", "already_seen")))
                        or (attempt.action == "query" and (outcome.status, outcome.reason) == ("retained", "known"))):
                    state, reason, failures, due = "retained", outcome.reason, 0, now + 30
                elif attempt.action == "query" and (outcome.status, outcome.reason) == ("absent", "not_found"):
                    state, reason, failures = "prepared", "host_absent", 0
                elif outcome.status == "rejected" and outcome.reason in _REASONS:
                    state, reason = "failed", outcome.reason
                elif outcome.status in ("not_sent", "unknown") and outcome.reason in _TRANSPORT:
                    state = "prepared" if attempt.action == "send" and outcome.status == "not_sent" else "unknown"
                    reason = outcome.reason
            if state in ("unknown", "prepared") and failures:
                due = now + min(300, 5 * 2**min(failures - 1, 6))
            self.store.db.execute("""UPDATE host_wake SET state=?,reason=?,failures=?,due=?,
                ticket=NULL,action=NULL,updated=? WHERE singleton=1""", (state, reason, failures, due, now))
            return True

    def resume(self, *, now=None):
        """Explicit local operator action; changes no route, policy or authority."""
        with self.store._transaction():
            if self._row()["state"] != "failed":
                raise InboxError("host wake has no rejected attempt to resume")
            self.store.db.execute("""UPDATE host_wake SET state='unknown',reason='operator_resume',
                due=0,failures=0,ticket=NULL,action=NULL,updated=? WHERE singleton=1""", (_time(now),))
