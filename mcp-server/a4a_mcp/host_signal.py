"""Candidate one-shot host signal, not an installed receiver or MCP channel.

Only locally authorized inbox metadata belongs here. A host ACK is not evidence
of model wake or mail processing. The caller owns persistence and reconciliation.
"""

import asyncio
import importlib.metadata
import inspect
import json
import logging
import re
import secrets
import socket
from dataclasses import dataclass

from .channel import ChannelAdapterError, _notification_params


_TYPE = "mcp:a4a_inbox_signal"
_QUERY_TYPE = "mcp:a4a_signal_status"
_CAPABILITIES_TYPE = "mcp:a4a_wake_capabilities"
_MAX_COUNTER = 2**63 - 1
_MAX_FRAME = 4096
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}", re.ASCII)
_CONSUMER = re.compile(r"[A-Za-z0-9_.:-]{1,96}", re.ASCII)
_SIGNAL_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_CLIENT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.ASCII)
_ENDPOINT = re.compile(r"ws://127\.0\.0\.1:([1-9][0-9]{0,4})/", re.ASCII)
_TOKEN = re.compile(r"[!-~]{1,4096}", re.ASCII)
_REJECTED = frozenset(("not_authorized", "unknown_pair", "unsupported_version",
                       "invalid_signal", "signal_id_conflict", "no_work", "host_blocked"))
_SUCCESS = {"accepted": "queued", "deferred": "busy", "duplicate": "already_seen"}
_QUERY_SUCCESS = {"retained": "known", "absent": "not_found"}
_RESPONSE_FIELDS = frozenset(("type", "requestId", "version", "signalId",
                              "success", "status", "reasonCode"))
_DENIAL_FIELDS = frozenset(("type", "requestId", "success", "error"))
_CAPABILITY_MODES = frozenset(("inbox", "dialogue"))
_CAPABILITY_WAKE_LEVELS = frozenset(("connected", "idle", "cold-start", "assisted"))


class SignalError(ValueError):
    """Payload-free local contract/configuration error, before network access."""


def _matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _request_id(value):
    if type(value) is not int or not 1 <= value <= 2**31 - 1:
        raise SignalError("A4A signal: invalid request ID")


@dataclass(frozen=True)
class Binding:
    project_id: str
    target_session_id: str
    consumer: str

    def __post_init__(self):
        if not (_matches(_ID, self.project_id) and _matches(_ID, self.target_session_id)
                and _matches(_CONSUMER, self.consumer)):
            raise SignalError("A4A signal: invalid local binding")


@dataclass(frozen=True)
class PreparedSignal:
    binding: Binding
    signal_id: str
    mode: str
    pending: int
    seq_hint: int
    needs_reconciliation: int
    outgoing_prepared: int

    def __post_init__(self):
        if type(self.binding) is not Binding or not _matches(_SIGNAL_ID, self.signal_id):
            raise SignalError("A4A signal: invalid prepared identity")
        if type(self.mode) is not str or self.mode not in ("inbox", "dialogue"):
            raise SignalError("A4A signal: invalid mode")
        for value in (self.pending, self.seq_hint, self.needs_reconciliation, self.outgoing_prepared):
            if type(value) is not int or not 0 <= value <= _MAX_COUNTER:
                raise SignalError("A4A signal: invalid counter")
        if self.mode == "inbox" and (self.needs_reconciliation or self.outgoing_prepared):
            raise SignalError("A4A signal: managed counters require dialogue mode")

    @property
    def has_work(self):
        return bool(self.pending or self.needs_reconciliation or self.outgoing_prepared)

    def request(self, request_id):
        _request_id(request_id)
        return {
            "type": _TYPE, "requestId": request_id, "version": "1",
            "projectId": self.binding.project_id,
            "targetSessionId": self.binding.target_session_id,
            "consumer": self.binding.consumer, "signalId": self.signal_id, "mode": self.mode,
            "counters": {"pending": str(self.pending), "seqHint": str(self.seq_hint),
                         "needsReconciliation": str(self.needs_reconciliation),
                         "outgoingPrepared": str(self.outgoing_prepared)},
        }


def prepare_signal(notice, binding, *, signal_id=None):
    """Freeze one validated attempt; retain this object for any explicit retry."""
    if type(binding) is not Binding:
        raise SignalError("A4A signal: invalid local binding")
    try:
        _notification_params(notice)
    except ChannelAdapterError:
        raise SignalError("A4A signal: invalid local notice") from None
    if notice["consumer"] != binding.consumer:
        raise SignalError("A4A signal: consumer does not match local binding")
    return PreparedSignal(
        binding, secrets.token_hex(16) if signal_id is None else signal_id,
        "dialogue" if "needs_reconciliation" in notice else "inbox",
        notice["pending"], notice["seq_hint"],
        notice.get("needs_reconciliation", 0), notice.get("outgoing_prepared", 0),
    )


@dataclass(frozen=True)
class Outcome:
    status: str
    reason: str


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _read_object(frame):
    if type(frame) is not str or len(frame) > _MAX_FRAME or len(frame.encode("utf-8")) > _MAX_FRAME:
        raise ValueError("invalid frame")
    data = json.loads(frame, object_pairs_hook=_unique_object)
    if type(data) is not dict:
        raise ValueError("invalid object")
    return data


def _is_welcome(frame):
    try:
        data = _read_object(frame)
        return (data.keys() == {"type", "clientId", "message"}
                and data["type"] == "welcome"
                and data["message"] == "Connected to V2coder"
                and _matches(_CLIENT_ID, data["clientId"]))
    except (ValueError, TypeError, RecursionError):
        return False


def parse_response(frame, signal, request_id):
    """Untrusted ACK parser. Invalid/mismatched data cannot prove rejection."""
    return _parse_response(frame, signal, request_id, _TYPE + ":response", _SUCCESS)


def parse_query_response(frame, signal, request_id):
    """Parse only a status-query ACK; invalid data cannot prove absence."""
    return _parse_response(frame, signal, request_id, _QUERY_TYPE + ":response", _QUERY_SUCCESS)


def _parse_response(frame, signal, request_id, response_type, success_pairs):
    _request_id(request_id)
    invalid = Outcome("unknown", "invalid_response")
    try:
        data = _read_object(frame)
        if data.get("type") != response_type:
            return invalid
        if type(data.get("requestId")) is not int or data["requestId"] != request_id:
            return invalid
        if (data.keys() == _DENIAL_FIELDS and data["success"] is False
                and type(data["error"]) is str):
            return Outcome("rejected", "access_denied")
        if data.keys() != _RESPONSE_FIELDS:
            return invalid
        if data["version"] != "1" or data["signalId"] != signal.signal_id:
            return invalid
        status, reason = data["status"], data["reasonCode"]
        if type(status) is not str or type(reason) is not str:
            return invalid
        if data["success"] is True and status in success_pairs and reason == success_pairs[status]:
            return Outcome(status, reason)
        if data["success"] is False and status == "rejected" and reason in _REJECTED:
            return Outcome(status, reason)
    except (ValueError, TypeError, RecursionError):
        pass
    return invalid


def _connect_factory():
    # This optional, uninstalled adapter has only been transport-tested on 13.1.
    # Do not let a library upgrade silently enable proxies or credential redirects.
    if importlib.metadata.version("websockets") != "13.1":
        raise SignalError("A4A signal: untested transport version; require websockets 13.1")
    from websockets.asyncio.client import connect
    return connect


async def send_signal(signal, *, token, endpoint="ws://127.0.0.1:9876/", request_id=1, timeout=5.0,
                      before_send=None):
    """At most one bounded attempt. No retries, model calls or identity/config I/O.

    Cancellation propagates; once called, the caller must treat an interrupted
    attempt as unknown and reconcile before resubmission. No durable ACK here.
    """
    return await _exchange_signal(signal, token=token, endpoint=endpoint,
                                  request_id=request_id, timeout=timeout,
                                  command_type=_TYPE, response_parser=parse_response,
                                  before_send=before_send)


async def query_signal(signal, *, token, endpoint="ws://127.0.0.1:9876/", request_id=1, timeout=5.0,
                       before_send=None):
    """Candidate exact-body status lookup, only while the prepared signal has work.

    No wake, model call or fallback submission, even if the host lacks support.
    Unknown responses never prove absence. Cancellation propagates to the caller.
    """
    return await _exchange_signal(signal, token=token, endpoint=endpoint,
                                  request_id=request_id, timeout=timeout,
                                  command_type=_QUERY_TYPE, response_parser=parse_query_response,
                                  before_send=before_send)


async def _exchange_signal(signal, *, token, endpoint, request_id, timeout,
                           command_type, response_parser, before_send):
    if type(signal) is not PreparedSignal:
        raise SignalError("A4A signal: expected a prepared signal")
    request = signal.request(request_id)
    request["type"] = command_type
    match = _ENDPOINT.fullmatch(endpoint) if type(endpoint) is str else None
    if match is None or int(match[1]) > 65535:
        raise SignalError("A4A signal: endpoint must be numeric IPv4 loopback")
    if not _matches(_TOKEN, token):
        raise SignalError("A4A signal: explicit header credential required")
    if type(timeout) not in (float, int) or not 0 < timeout <= 30:
        raise SignalError("A4A signal: timeout must be finite, positive and at most 30 seconds")
    if before_send is not None and (not callable(before_send) or inspect.iscoroutinefunction(before_send)):
        raise SignalError("A4A signal: preflight must be a synchronous callable")
    if not signal.has_work:
        return Outcome("no_work", "empty")
    connect = _connect_factory()
    logger = logging.Logger("a4a.signal.transport", level=logging.CRITICAL + 1)
    logger.disabled = True
    logger.propagate = False
    sock = None
    websocket = None
    started = False
    outcome = None
    try:
        async with asyncio.timeout(timeout) as deadline:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            # Numeric address: no DNS/proxy. A supplied socket also prevents
            # all redirect following in the tested websockets implementation.
            await asyncio.get_running_loop().sock_connect(sock, ("127.0.0.1", int(match[1])))
            websocket = await connect(
                endpoint, sock=sock, additional_headers={"X-V2coder-Token": token},
                compression=None, user_agent_header=None, ping_interval=None,
                open_timeout=timeout, close_timeout=min(timeout, 1),
                max_size=_MAX_FRAME, max_queue=1, logger=logger,
            )
            # The handshake yields: policy or work may change while it is pending.
            # No await separates this final eligibility check from the first send.
            if before_send is not None:
                try:
                    decision = before_send()
                    if inspect.isawaitable(decision):
                        if inspect.iscoroutine(decision):
                            decision.close()
                        raise ValueError()
                except Exception:
                    return Outcome("not_sent", "preflight_failed")
                if decision is not True:
                    return Outcome("not_sent", "superseded")
            # A synchronous ACL/SQLite check can outlast the async timeout before
            # its cancellation callback gets a turn on the event loop.
            if asyncio.get_running_loop().time() >= deadline.when():
                return Outcome("not_sent", "timeout")
            started = True
            await websocket.send(json.dumps(request, separators=(",", ":")))
            frame = await websocket.recv()
            if _is_welcome(frame):
                frame = await websocket.recv()
            outcome = response_parser(frame, signal, request_id)
            await websocket.close()
    except TimeoutError:
        if outcome is None:
            outcome = Outcome("unknown" if started else "not_sent", "timeout")
    except Exception:
        if outcome is None:
            outcome = Outcome("unknown" if started else "not_sent", "transport_failed")
    finally:
        # Cleanup must not hide cancellation or overwrite an already received ACK.
        try:
            if websocket is not None:
                websocket.transport.abort()
        except Exception:
            pass
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass
    return outcome


@dataclass(frozen=True)
class WakeCapabilities:
    status: str
    reason: str
    modes: tuple[str, ...] = ()
    status_query: bool = False
    wake_levels: tuple[str, ...] = ()


def parse_capabilities_response(frame, request_id):
    """Parse a Host Wake Contract v1 capabilities negotiation response."""
    _request_id(request_id)
    invalid = WakeCapabilities("unknown", "invalid_response")
    response_type = _CAPABILITIES_TYPE + ":response"
    try:
        data = _read_object(frame)
        if data.get("type") != response_type:
            return invalid
        if type(data.get("requestId")) is not int or data["requestId"] != request_id:
            return invalid
        if (data.keys() == _DENIAL_FIELDS and data["success"] is False
                and type(data["error"]) is str):
            return WakeCapabilities("rejected", "access_denied")
        if (data.keys() == {"type", "requestId", "version", "success", "status", "reasonCode"}
                and data["version"] == "1"
                and data["success"] is False
                and data["status"] == "rejected"
                and type(data["reasonCode"]) is str
                and data["reasonCode"] in _REJECTED):
            return WakeCapabilities("rejected", data["reasonCode"])
        if data.keys() != {"type", "requestId", "version", "success", "capabilities"}:
            return invalid
        if data["version"] != "1" or data["success"] is not True:
            return invalid
        caps = data["capabilities"]
        if type(caps) is not dict or caps.keys() != {"modes", "statusQuery", "wakeLevels"}:
            return invalid
        modes = caps["modes"]
        status_query = caps["statusQuery"]
        wake_levels = caps["wakeLevels"]
        if (type(modes) is not list or not modes or len(modes) > 4
                or any(type(m) is not str or m not in _CAPABILITY_MODES for m in modes)
                or len(set(modes)) != len(modes)):
            return invalid
        if type(status_query) is not bool:
            return invalid
        if (type(wake_levels) is not list or not wake_levels or len(wake_levels) > 4
                or any(type(w) is not str or w not in _CAPABILITY_WAKE_LEVELS for w in wake_levels)
                or len(set(wake_levels)) != len(wake_levels)):
            return invalid
        return WakeCapabilities(
            "supported",
            "ok",
            modes=tuple(modes),
            status_query=status_query,
            wake_levels=tuple(wake_levels),
        )
    except (ValueError, TypeError, RecursionError):
        return invalid


async def query_capabilities(*, token, endpoint="ws://127.0.0.1:9876/", request_id=1, timeout=5.0):
    """Negotiate Host Wake Contract v1 capabilities over numeric IPv4 loopback."""
    _request_id(request_id)
    match = _ENDPOINT.fullmatch(endpoint) if type(endpoint) is str else None
    if match is None or int(match[1]) > 65535:
        raise SignalError("A4A signal: endpoint must be numeric IPv4 loopback")
    if not _matches(_TOKEN, token):
        raise SignalError("A4A signal: explicit header credential required")
    if type(timeout) not in (float, int) or not 0 < timeout <= 30:
        raise SignalError("A4A signal: timeout must be finite, positive and at most 30 seconds")
    request = {"type": _CAPABILITIES_TYPE, "requestId": request_id, "version": "1"}
    connect = _connect_factory()
    logger = logging.Logger("a4a.signal.transport", level=logging.CRITICAL + 1)
    logger.disabled = True
    logger.propagate = False
    sock = None
    websocket = None
    started = False
    outcome = None
    try:
        async with asyncio.timeout(timeout):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            await asyncio.get_running_loop().sock_connect(sock, ("127.0.0.1", int(match[1])))
            websocket = await connect(
                endpoint, sock=sock, additional_headers={"X-V2coder-Token": token},
                compression=None, user_agent_header=None, ping_interval=None,
                open_timeout=timeout, close_timeout=min(timeout, 1),
                max_size=_MAX_FRAME, max_queue=1, logger=logger,
            )
            started = True
            await websocket.send(json.dumps(request, separators=(",", ":")))
            frame = await websocket.recv()
            if _is_welcome(frame):
                frame = await websocket.recv()
            outcome = parse_capabilities_response(frame, request_id)
            await websocket.close()
    except TimeoutError:
        if outcome is None:
            outcome = WakeCapabilities("unknown" if started else "not_sent", "timeout")
    except Exception:
        if outcome is None:
            outcome = WakeCapabilities("unknown" if started else "not_sent", "transport_failed")
    finally:
        try:
            if websocket is not None:
                websocket.transport.abort()
        except Exception:
            pass
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass
    return outcome


class ReferenceHarnessConsumer:
    """Reference Host Wake Contract v1 harness consumer and state machine.

    Validates route bindings and wake-only tokens, enforces the closed metadata
    schema, retains/coalesces signals when busy, answers status queries without
    triggering duplicate turns, and correlates model turns with signalId.
    """

    def __init__(
        self,
        *,
        routes: dict[tuple[str, str, str], str] | None = None,
        modes: tuple[str, ...] = ("inbox", "dialogue"),
        wake_levels: tuple[str, ...] = ("connected", "idle"),
        status_query: bool = True,
        busy: bool = False,
        host_blocked: bool = False,
    ):
        self.routes: dict[tuple[str, str, str], str] = dict(routes or {})
        self.modes = tuple(modes)
        self.wake_levels = tuple(wake_levels)
        self.status_query = bool(status_query)
        self.busy = bool(busy)
        self.host_blocked = bool(host_blocked)
        self.retained_signals: dict[str, dict] = {}
        self.turn_queue: list[str] = []
        self.completed_turns: list[dict] = []
        self.requests_log: list[str] = []

    def register_route(self, binding: Binding, token: str) -> None:
        if type(binding) is not Binding or not _matches(_TOKEN, token):
            raise SignalError("invalid route registration")
        self.routes[(binding.project_id, binding.target_session_id, binding.consumer)] = token

    def clear_state_on_restart(self) -> None:
        """Simulate a harness restart where in-memory retained signal state is lost."""
        self.retained_signals.clear()
        self.turn_queue.clear()

    def _validate_signal_body(self, data: dict) -> tuple[str | None, dict | None]:
        expected_keys = {
            "type", "requestId", "version", "projectId", "targetSessionId",
            "consumer", "signalId", "mode", "counters",
        }
        if data.keys() != expected_keys:
            return "invalid_signal", None
        if data.get("version") != "1":
            return "unsupported_version", None
        if not (
            _matches(_ID, data.get("projectId"))
            and _matches(_ID, data.get("targetSessionId"))
            and _matches(_CONSUMER, data.get("consumer"))
            and _matches(_SIGNAL_ID, data.get("signalId"))
        ):
            return "invalid_signal", None
        mode = data.get("mode")
        if type(mode) is not str or mode not in self.modes:
            return "invalid_signal", None
        counters = data.get("counters")
        if type(counters) is not dict or counters.keys() != {
            "pending", "seqHint", "needsReconciliation", "outgoingPrepared"
        }:
            return "invalid_signal", None
        parsed_counters = {}
        for k, v in counters.items():
            if type(v) is not str or not re.fullmatch(r"0|[1-9][0-9]{0,18}", v):
                return "invalid_signal", None
            iv = int(v)
            if not 0 <= iv <= _MAX_COUNTER:
                return "invalid_signal", None
            parsed_counters[k] = iv
        if mode == "inbox" and (
            parsed_counters["needsReconciliation"] or parsed_counters["outgoingPrepared"]
        ):
            return "invalid_signal", None
        if not (
            parsed_counters["pending"]
            or parsed_counters["needsReconciliation"]
            or parsed_counters["outgoingPrepared"]
        ):
            return "no_work", None
        canonical = {
            k: v for k, v in data.items() if k not in ("type", "requestId")
        }
        return None, canonical

    def handle_frame(self, raw_frame: str, *, header_token: str | None) -> dict:
        """Process one incoming JSON frame and return the response JSON dict."""
        try:
            data = _read_object(raw_frame)
        except Exception:
            return {
                "type": _TYPE + ":response",
                "requestId": 1,
                "version": "1",
                "signalId": "0" * 32,
                "success": False,
                "status": "rejected",
                "reasonCode": "invalid_signal",
            }
        req_type = data.get("type")
        req_id = data.get("requestId") if type(data.get("requestId")) is int else 1
        self.requests_log.append(str(req_type))

        if req_type == _CAPABILITIES_TYPE:
            if not header_token or header_token not in self.routes.values():
                return {
                    "type": _CAPABILITIES_TYPE + ":response",
                    "requestId": req_id,
                    "version": "1",
                    "success": False,
                    "status": "rejected",
                    "reasonCode": "not_authorized",
                }
            if data.keys() != {"type", "requestId", "version"}:
                return {
                    "type": _CAPABILITIES_TYPE + ":response",
                    "requestId": req_id,
                    "version": "1",
                    "success": False,
                    "status": "rejected",
                    "reasonCode": "invalid_signal",
                }
            if data.get("version") != "1":
                return {
                    "type": _CAPABILITIES_TYPE + ":response",
                    "requestId": req_id,
                    "version": "1",
                    "success": False,
                    "status": "rejected",
                    "reasonCode": "unsupported_version",
                }
            return {
                "type": _CAPABILITIES_TYPE + ":response",
                "requestId": req_id,
                "version": "1",
                "success": True,
                "capabilities": {
                    "modes": list(self.modes),
                    "statusQuery": self.status_query,
                    "wakeLevels": list(self.wake_levels),
                },
            }

        resp_type = (
            _QUERY_TYPE + ":response"
            if req_type == _QUERY_TYPE
            else _TYPE + ":response"
        )
        sig_id = data.get("signalId") if _matches(_SIGNAL_ID, data.get("signalId")) else "0" * 32

        if req_type not in (_TYPE, _QUERY_TYPE):
            return {
                "type": resp_type,
                "requestId": req_id,
                "version": "1",
                "signalId": sig_id,
                "success": False,
                "status": "rejected",
                "reasonCode": "invalid_signal",
            }

        err_code, canonical = self._validate_signal_body(data)
        if err_code is not None:
            return {
                "type": resp_type,
                "requestId": req_id,
                "version": "1",
                "signalId": sig_id,
                "success": False,
                "status": "rejected",
                "reasonCode": err_code,
            }

        route_key = (
            data["projectId"],
            data["targetSessionId"],
            data["consumer"],
        )
        if not header_token or header_token not in self.routes.values():
            return {
                "type": resp_type,
                "requestId": req_id,
                "version": "1",
                "signalId": sig_id,
                "success": False,
                "status": "rejected",
                "reasonCode": "not_authorized",
            }
        expected_token = self.routes.get(route_key)
        if expected_token is None:
            return {
                "type": resp_type,
                "requestId": req_id,
                "version": "1",
                "signalId": sig_id,
                "success": False,
                "status": "rejected",
                "reasonCode": "unknown_pair",
            }
        if expected_token != header_token:
            return {
                "type": resp_type,
                "requestId": req_id,
                "version": "1",
                "signalId": sig_id,
                "success": False,
                "status": "rejected",
                "reasonCode": "not_authorized",
            }
        if self.host_blocked:
            return {
                "type": resp_type,
                "requestId": req_id,
                "version": "1",
                "signalId": sig_id,
                "success": False,
                "status": "rejected",
                "reasonCode": "host_blocked",
            }

        if req_type == _QUERY_TYPE:
            existing = self.retained_signals.get(sig_id)
            if existing is None:
                return {
                    "type": resp_type,
                    "requestId": req_id,
                    "version": "1",
                    "signalId": sig_id,
                    "success": True,
                    "status": "absent",
                    "reasonCode": "not_found",
                }
            if existing != canonical:
                return {
                    "type": resp_type,
                    "requestId": req_id,
                    "version": "1",
                    "signalId": sig_id,
                    "success": False,
                    "status": "rejected",
                    "reasonCode": "signal_id_conflict",
                }
            return {
                "type": resp_type,
                "requestId": req_id,
                "version": "1",
                "signalId": sig_id,
                "success": True,
                "status": "retained",
                "reasonCode": "known",
            }

        # _TYPE ("mcp:a4a_inbox_signal")
        existing = self.retained_signals.get(sig_id)
        if existing is not None:
            if existing != canonical:
                return {
                    "type": resp_type,
                    "requestId": req_id,
                    "version": "1",
                    "signalId": sig_id,
                    "success": False,
                    "status": "rejected",
                    "reasonCode": "signal_id_conflict",
                }
            return {
                "type": resp_type,
                "requestId": req_id,
                "version": "1",
                "signalId": sig_id,
                "success": True,
                "status": "duplicate",
                "reasonCode": "already_seen",
            }

        self.retained_signals[sig_id] = canonical
        if self.busy:
            return {
                "type": resp_type,
                "requestId": req_id,
                "version": "1",
                "signalId": sig_id,
                "success": True,
                "status": "deferred",
                "reasonCode": "busy",
            }
        self.turn_queue.append(sig_id)
        return {
            "type": resp_type,
            "requestId": req_id,
            "version": "1",
            "signalId": sig_id,
            "success": True,
            "status": "accepted",
            "reasonCode": "queued",
        }

    def execute_next_turn(self, drain_callback) -> dict | None:
        """Execute one queued model turn against the local inbox and record correlation."""
        if self.busy:
            return None
        if not self.turn_queue:
            # Check if a deferred signal is retained and not yet completed
            completed_ids = {t["signalId"] for t in self.completed_turns}
            for sid in self.retained_signals:
                if sid not in completed_ids:
                    self.turn_queue.append(sid)
                    break
        if not self.turn_queue:
            return None
        sig_id = self.turn_queue.pop(0)
        sig_body = self.retained_signals.get(sig_id, {})
        disposition = drain_callback(sig_id, sig_body)
        receipt = {
            "signalId": sig_id,
            "consumer": sig_body.get("consumer"),
            "mode": sig_body.get("mode"),
            "disposition": disposition,
        }
        self.completed_turns.append(receipt)
        return receipt


class ReferenceWakeAdapter:
    """Reference loopback WebSocket server implementing Host Wake Contract v1."""

    def __init__(
        self,
        consumer: ReferenceHarnessConsumer,
        *,
        port: int = 0,
        send_welcome: bool = True,
    ):
        self.consumer = consumer
        self.port = port
        self.send_welcome = send_welcome
        self.drop_next_ack = False
        self._server = None

    @property
    def endpoint(self) -> str:
        return f"ws://127.0.0.1:{self.port}/"

    async def _handle_ws(self, ws):
        if self.send_welcome:
            await ws.send(
                json.dumps(
                    {
                        "type": "welcome",
                        "clientId": "01234567-89ab-cdef-0123-456789abcdef",
                        "message": "Connected to V2coder",
                    },
                    separators=(",", ":"),
                )
            )
        raw = await ws.recv()
        header_token = None
        if getattr(ws, "request", None) is not None and getattr(ws.request, "headers", None) is not None:
            header_token = ws.request.headers.get("X-V2coder-Token")
        response = self.consumer.handle_frame(raw, header_token=header_token)
        if self.drop_next_ack and response.get("type") == _TYPE + ":response":
            self.drop_next_ack = False
            return
        await ws.send(json.dumps(response, separators=(",", ":")))

    async def start(self) -> "ReferenceWakeAdapter":
        if importlib.metadata.version("websockets") != "13.1":
            raise SignalError("A4A signal: untested transport version; require websockets 13.1")
        from websockets.asyncio.server import serve
        self._server = await serve(self._handle_ws, "127.0.0.1", self.port, reuse_address=True)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def restart(self, *, clear_memory: bool = True) -> None:
        bound_port = self.port
        await self.close()
        if clear_memory:
            self.consumer.clear_state_on_restart()
        self.port = bound_port
        await self.start()

    async def __aenter__(self) -> "ReferenceWakeAdapter":
        return await self.start()

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

