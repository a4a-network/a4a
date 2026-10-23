"""Run-wide network boundary: tests must not reach outside or contact foreign services.

This implements the isolation contract proposed by independent review and **states its
limits honestly** in the scope section below.

WHY. Twice in one day a test run reached PRODUCTION while looking normal: one relay-address
substitution affected only the first item in a list, and another request reached an
unrelated listener on the same port. Both were found accidentally. A test that silently
escapes is more dangerous than a failing one because it verifies the wrong system and may
pass through somebody else's success.

DESIGN. Allow only addresses registered by A FIXTURE IN THIS RUN after binding a listener.
Reject everything else, including loopback: a listener on 127.0.0.1 does not prove it is
ours. Rejected attempts accumulate and fail the run even when product code catches the
exception; catching a refusal does not erase the attempt.

Cover exits by LAYER: transport object, event loop, and socket. Connections include
`socket.connect`, `connect_ex`, `loop.create_connection`, and both `loop.sock_connect`
implementations. Datagrams include `socket.sendto`, `loop.sock_sendto`,
`loop.create_datagram_endpoint`, and `transport.sendto`. Name resolution includes
`getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `gethostbyaddr`, and `getnameinfo`.

This inventory required three review rounds. Initially only `socket.connect` was patched,
although the asyncio-based SDK does not use that path. Then `loop.sock_sendto` remained,
then `transport.sendto`. Every gap was reproduced by its own test before repair.

Declare intent instead of bypassing the boundary:

* `allow(host, port)` means a fixture bound this address;
* `unreachable(host, port)` means refusal is the test subject, so emulate the kernel and
  do not count the attempt as a violation;
* `no_network(reason)` asserts zero network activity, including allowed endpoints.

There is no exception for "some other protection." A former `product_must_refuse_name`
exception confused a test-file audit hook with product protection and failed to record
resolver attempts that raised `gaierror`. Registered audit hooks should be tested with a
synthetic `sys.audit(...)` event, which performs no I/O.

No general bypass exists intentionally: eventually it would be used to "make tests pass,"
rendering the boundary meaningless.
"""
from __future__ import annotations

import contextlib
import contextvars
import errno
import itertools
import socket
import threading

#: Addresses bound by fixtures in THIS run. Empty until first registration.
_allowed: set[tuple[str, int]] = set()
#: APPEND-ONLY log of `(number, host, port)`. The first version removed the tail when
#: leaving `expect_blocked`, including completed connections to allowed addresses, so a
#: no-network assertion passed after real TCP traffic. Mark entries; never erase them.
_attempts: list[tuple[int, str, int]] = []
#: Rejected attempts: `(number, host, port, expectation owner)`. Only the expect_blocked
#: context active when the attempt occurred may mark it expected.
_blocked: list[tuple[int, str, int, int | None]] = []
#: Attempt numbers declared expected by the context that owned them.
_expected: set[int] = set()
_counter = itertools.count(1)
#: Active expectation stack, isolated per thread and asyncio task. New threads start with
#: empty context; tasks created inside a declaration inherit it as continuations.
_expectation = contextvars.ContextVar("a4a_network_guard_expectation", default=())
#: Addresses explicitly declared to have no listener.
_unreachable: set[tuple[str, int]] = set()

_pair_state = threading.local()
_installed = False
_original_connect = None
_original_connect_ex = None
_original_socketpair = None
_original_getaddrinfo = None
_original_sendto = None
_original_create_connection = None
_original_create_datagram = None
_original_sock_connect: dict = {}
_original_sock_sendto: dict = {}
_original_transport_sendto: dict = {}
_original_names: dict = {}


class NetworkBoundary(AssertionError):
    """Connection attempt outside addresses bound by this run's fixtures."""


def allow(host: str, port: int) -> None:
    """Register an address bound by a fixture. Call only AFTER bind succeeds."""
    _allowed.add((host, int(port)))


def unreachable(host: str, port: int) -> None:
    """Declare an address dead and refuse it exactly as the OS would.

    Tests of dead-node behavior must not rely on a port happening to be unused. If another
    service claims it, the test would silently communicate with a foreign service.
    Declared-dead addresses raise `ConnectionRefusedError`, exercising production error
    handling without counting the expected refusal as a boundary violation.
    """
    _unreachable.add((host, int(port)))


def forget(host: str, port: int) -> None:
    """Remove registration so a previous run's port cannot authorize a new one.

    A stale registry could permit a foreign service that later acquired the same port.
    """
    _allowed.discard((host, int(port)))
    _unreachable.discard((host, int(port)))


class expect_blocked:
    """Context where a boundary rejection is EXPECTED by a negative test.

    Expectation never allows the connection. It only prevents the rejected attempt from
    failing the run at teardown; allowing it would test real network behavior in disguise.
    """

    def __enter__(self):
        self._id = next(_counter)
        self._token = _expectation.set(_expectation.get() + (self._id,))
        return self

    def __exit__(self, *exc):
        _expectation.reset(self._token)
        # Mark only denials that occurred INSIDE this declaration, using its identity
        # rather than log position. The old tail deletion erased real allowed connections
        # and swallowed denials from neighboring threads. Sequence numbers keep the log
        # append-only; context establishes ownership.
        for number, _host, _port, owner in _blocked:
            if owner == self._id:
                _expected.add(number)
        return False


def _record(host, port) -> int:
    """Append an attempt to the log and return its sequence number."""
    number = next(_counter)
    _attempts.append((number, host, port))
    return number


#: Denial observers for child processes that may be terminated before a final report.
#: They receive each denial immediately and can persist it before process exit.
_denial_sinks: list = []


def on_denial(callback) -> None:
    """Subscribe an observer to every boundary denial."""
    _denial_sinks.append(callback)


def _record_denial(host, port) -> None:
    number = _record(host, port)
    stack = _expectation.get()
    _blocked.append((number, host, port, stack[-1] if stack else None))
    for sink in _denial_sinks:
        try:
            sink(host, port)
        except Exception:      # noqa: BLE001 - observer failure cannot cancel denial
            pass


def _refuse_dead(host, port):
    _expected.add(_record(host, port))
    return ConnectionRefusedError(
        errno.ECONNREFUSED,
        f"address declared unreachable in this run: {host}:{port}")


@contextlib.contextmanager
def no_network(reason: str):
    """Assert that a block performed NO network activity to any address.

    Eight files once carried separate socket.connect patches that guarded only one of four
    exits. This assertion counts ALL attempts, including allowed fixtures.
    """
    mark = next(_counter)
    try:
        yield
    finally:
        made = [(host, port) for number, host, port in _attempts
                if number > mark and number not in _expected]
        assert not made, f"{reason}: network attempts occurred: {sorted(set(made))}"


def _check(address) -> None:
    if getattr(_pair_state, "active", False):
        return                      # socketpair is an in-process channel, not a network.
    if not isinstance(address, tuple) or len(address) < 2:
        return                      # Unix sockets and other address spaces.
    key = (address[0], address[1])
    if key in _unreachable:
        raise _refuse_dead(*key)
    if key in _allowed:
        _record(*key)
        return
    _record_denial(*key)
    raise NetworkBoundary(
        f"connection outside test boundary: {key}. Only addresses bound by fixtures in "
        f"this run are allowed; a loopback listener does not prove ownership. Integration "
        f"requires explicit address selection, not a matching port number.")


_LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "", None}


def _is_loopback_name(host) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "ignore")
    return host in _LOOPBACK_NAMES


def _check_endpoint(host, port, kind="connection") -> None:
    """Check BEFORE any I/O. Loopback alone grants no permission."""
    if isinstance(host, bytes):
        host = host.decode("ascii", "ignore")
    try:
        port = int(port)
    except (TypeError, ValueError):
        # The old `return` allowed service-name or missing ports without inspection.
        # Fail closed on ambiguous input; a permissive boundary is not a boundary.
        _record_denial(str(host), 0)
        raise NetworkBoundary(
            f"{kind} outside test boundary: {host}:{port!r}; port number is unrecognized, "
            f"so address ownership cannot be established.")
    candidates = {host, "127.0.0.1" if _is_loopback_name(host) else host}
    for candidate in candidates:
        if (candidate, port) in _unreachable:
            raise _refuse_dead(candidate, port)
    for candidate in candidates:
        if (candidate, port) in _allowed:
            _record(host, port)
            return
    _record_denial(host, port)
    raise NetworkBoundary(
        f"{kind} outside test boundary: {host}:{port}. Only addresses bound by fixtures "
        f"in this run are allowed; a loopback listener does not prove ownership.")


def install() -> None:
    """Install the boundary on EVERY exit path, not only synchronous sockets.

    The first version patched `socket.socket.connect` only. Independent review showed
    Windows asyncio uses Proactor/IOCP without calling it, so the asyncio-based SDK bypassed
    the boundary and `unexpected()` recorded nothing. A real connection to an unregistered
    listener reproduced the gap.

    Patch paths the PRODUCT uses, not the first path that comes to mind. Reject before I/O
    for synchronous sockets, asynchronous connections, datagrams, and name resolution.
    """
    global _installed, _original_connect, _original_connect_ex, _original_socketpair
    global _original_getaddrinfo, _original_sendto, _original_create_connection
    global _original_create_datagram, _original_sock_connect, _original_names
    if _installed:
        return
    import asyncio.base_events
    import asyncio.proactor_events
    import asyncio.selector_events

    _original_connect = socket.socket.connect
    _original_connect_ex = socket.socket.connect_ex
    _original_socketpair = socket.socketpair
    _original_getaddrinfo = socket.getaddrinfo
    _original_sendto = socket.socket.sendto
    _original_create_connection = asyncio.base_events.BaseEventLoop.create_connection
    _original_create_datagram = asyncio.base_events.BaseEventLoop.create_datagram_endpoint

    def connect(sock, address):
        _check(address)
        return _original_connect(sock, address)

    def connect_ex(sock, address):
        _check(address)
        return _original_connect_ex(sock, address)

    def sendto(sock, data, *args):
        # Datagrams need no connection, so inspect destination or UDP remains an open exit.
        address = args[-1] if args else None
        if isinstance(address, tuple) and len(address) >= 2:
            _check_endpoint(address[0], address[1], "datagram")
        return _original_sendto(sock, data, *args)

    def _guarded_sock_sendto(original):
        # Low-level event-loop datagram path bypassing both create_datagram_endpoint and
        # socket.sendto. Review escaped through this exact door.
        async def sock_sendto(self, sock, data, address):
            if isinstance(address, tuple) and len(address) >= 2:
                _check_endpoint(address[0], address[1], "datagram")
            return await original(self, sock, data, address)
        return sock_sendto

    def _guarded_transport_sendto(original):
        """Guard the high-level datagram transport object's own method.

        Datagrams exposed three doors that were found one by one: `socket.sendto`, then
        `loop.sock_sendto`, then public `transport.sendto`. Inventory entry points by layer
        (transport, event loop, socket) rather than memory.
        """
        def sendto(self, data, addr=None):
            if isinstance(addr, tuple) and len(addr) >= 2:
                _check_endpoint(addr[0], addr[1], "datagram")
            return original(self, data, addr)
        return sendto

    def _guarded_name_lookup(name, original, host_index=0):
        """Guard other resolver entry points such as `gethostbyname`.

        Patching only `getaddrinfo` is insufficient; sibling functions reach resolvers by
        their own paths and are equally visible to the network operator.
        """
        def lookup(*args, **kwargs):
            host = args[host_index] if len(args) > host_index else None
            if not _is_loopback_name(host) and not any(h == host for h, _ in _allowed):
                _record_denial(str(host), 0)
                raise NetworkBoundary(
                    f"name resolution outside test boundary via {name}: {host}. External "
                    f"names are forbidden because their resolution leaves the process.")
            return original(*args, **kwargs)
        return lookup

    def getaddrinfo(host, port, *args, **kwargs):
        # Name resolution is network output visible to the resolver operator.
        if not _is_loopback_name(host) and not any(h == host for h, _ in _allowed):
            _record_denial(str(host), port or 0)
            raise NetworkBoundary(
                f"name resolution outside test boundary: {host}. External names are "
                f"forbidden because their resolution leaves the process.")
        if not _is_loopback_name(host):
            _record(str(host), port or 0)
        return _original_getaddrinfo(host, port, *args, **kwargs)

    async def create_connection(self, protocol_factory, host=None, port=None, **kwargs):
        if host is not None:
            _check_endpoint(host, port, "asynchronous connection")
        return await _original_create_connection(self, protocol_factory, host, port, **kwargs)

    async def create_datagram_endpoint(self, protocol_factory, *args, **kwargs):
        remote = kwargs.get("remote_addr")
        if isinstance(remote, tuple) and len(remote) >= 2:
            _check_endpoint(remote[0], remote[1], "datagram endpoint")
        return await _original_create_datagram(self, protocol_factory, *args, **kwargs)

    def _guarded_sock_connect(original):
        # Low-level asyncio entry bypassing create_connection. Libraries owning their own
        # sockets use it; without this patch Proactor escapes again.
        async def sock_connect(self, sock, address):
            _check(address)
            return await original(self, sock, address)
        return sock_connect

    def socketpair(*args, **kwargs):
        _pair_state.active = True
        try:
            return _original_socketpair(*args, **kwargs)
        finally:
            _pair_state.active = False

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.socket.sendto = sendto
    socket.getaddrinfo = getaddrinfo
    socket.socketpair = socketpair
    asyncio.base_events.BaseEventLoop.create_connection = create_connection
    asyncio.base_events.BaseEventLoop.create_datagram_endpoint = create_datagram_endpoint
    for loop_class in (asyncio.proactor_events.BaseProactorEventLoop,
                       asyncio.selector_events.BaseSelectorEventLoop):
        _original_sock_connect[loop_class] = loop_class.sock_connect
        loop_class.sock_connect = _guarded_sock_connect(loop_class.sock_connect)
        if hasattr(loop_class, "sock_sendto"):
            _original_sock_sendto[loop_class] = loop_class.sock_sendto
            loop_class.sock_sendto = _guarded_sock_sendto(loop_class.sock_sendto)
    for transport_class in (asyncio.proactor_events._ProactorDatagramTransport,
                            asyncio.selector_events._SelectorDatagramTransport):
        _original_transport_sendto[transport_class] = transport_class.sendto
        transport_class.sendto = _guarded_transport_sendto(transport_class.sendto)
    for name in ("gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo"):
        original = getattr(socket, name, None)
        if original is None:
            continue
        _original_names[name] = original
        setattr(socket, name, _guarded_name_lookup(name, original))
    _installed = True


def unexpected() -> list[tuple[str, int]]:
    """Return boundary violations not declared expected by their owning context."""
    return [(host, port) for number, host, port, _owner in _blocked if number not in _expected]


# SCOPE is explicit because silence would read as a promise of total isolation.
#
# ENFORCED: every connection from THIS process, including product code and import-time
# activity when installed before product imports.
#
# ENFORCED for Python children launched through `guarded_child`: the boundary installs in
# the child before product imports, confirms readiness by handshake, and receives only
# addresses already allowed by the parent.
#
# NOT ENFORCED for arbitrary executables. curl, another interpreter, or binaries inherit
# environment but not in-memory patches. Process-local code cannot solve that, while tests
# must not change host firewall settings. Such launches require separate isolation and are
# never silently claimed as protected.
SCOPE = {
    "sync sockets": "enforced",
    "asyncio connections": "enforced (Proactor included)",
    "datagrams": "enforced",
    "name resolution": "enforced",
    "imports": "enforced when installed before product import",
    "ambient configuration": "enforced; see tests/ambient.py",
    "guarded python children": "enforced; see tests/guarded_child.py",
    "subprocesses": "not enforced for arbitrary executables; see module docstring",
}
