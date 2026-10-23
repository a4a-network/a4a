"""Test the run-wide boundary itself across every exit path used by the product.

The first boundary patched only `socket.connect` and appeared healthy: green suite, zero
violations. Independent review showed Windows asyncio uses Proactor without calling that
method, so the product's actual path bypassed the guard. A real connection to an
unregistered listener reproduced the problem with zero recorded attempts.

The testing method was wrong: it exercised the guard through the same entry point it
patched and missed three others. These regression tests use an independent probe for every
path and a positive control against false refusal, since a boundary rejecting everything
would otherwise appear healthy too.
"""
import asyncio
import socket
import threading

import network_guard
import pytest


@pytest.fixture
def listener():
    """Listener unknown to the boundary; every connection to it must be rejected."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    yield port
    network_guard.forget("127.0.0.1", port)
    server.close()


async def test_asyncio_connection_is_refused_and_recorded(listener):
    """Exercise the SDK's path, which bypassed the first boundary implementation."""
    mark = len(network_guard._blocked)
    with network_guard.expect_blocked():
        with pytest.raises(AssertionError, match="outside test boundary"):
            await asyncio.open_connection("127.0.0.1", listener)
    recorded = [(host, port) for _n, host, port, _owner in network_guard._blocked[mark:]]
    assert ("127.0.0.1", listener) in recorded, (
        "attempt not recorded; silent refusal is no better than silent network escape")


async def test_registered_address_is_allowed_and_forgetting_restores_refusal(listener):
    """Positive control: a boundary rejecting everything is equally useless.

    `forget` must also restore refusal. A registry surviving into the next run could allow
    a foreign service that happened to acquire the same port, which looks like success.
    """
    network_guard.allow("127.0.0.1", listener)
    _, writer = await asyncio.open_connection("127.0.0.1", listener)
    writer.close()

    network_guard.forget("127.0.0.1", listener)
    with network_guard.expect_blocked():
        with pytest.raises(AssertionError, match="outside test boundary"):
            await asyncio.open_connection("127.0.0.1", listener)


def test_sync_connection_is_refused(listener):
    with network_guard.expect_blocked():
        with pytest.raises(AssertionError, match="outside test boundary"):
            socket.socket().connect(("127.0.0.1", listener))


def test_datagram_is_refused(listener):
    """UDP sends without connecting, so an unchecked destination is an open exit."""
    with network_guard.expect_blocked():
        with pytest.raises(AssertionError, match="outside test boundary"):
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", listener))


def test_name_resolution_is_refused():
    """Name resolution is visible to a network operator and therefore leaves the run."""
    with network_guard.expect_blocked():
        with pytest.raises(AssertionError, match="outside test boundary"):
            socket.getaddrinfo("relay.example.invalid", 443)


async def test_low_level_sock_connect_is_refused(listener):
    """`loop.sock_connect` bypasses `create_connection`; probe it independently."""
    loop = asyncio.get_running_loop()
    sock = socket.socket()
    sock.setblocking(False)
    try:
        with network_guard.expect_blocked():
            with pytest.raises(AssertionError, match="outside test boundary"):
                await loop.sock_connect(sock, ("127.0.0.1", listener))
    finally:
        sock.close()


def test_unparseable_port_is_refused_rather_than_waved_through():
    """Fail closed: allowing ambiguous input creates the same boundary hole."""
    with network_guard.expect_blocked():
        with pytest.raises(AssertionError, match="unrecognized"):
            network_guard._check_endpoint("127.0.0.1", "https")


async def test_address_declared_dead_refuses_like_the_kernel():
    """A declared-dead address must look like an ordinary kernel network refusal.

    Otherwise product error handling takes a different branch from production: it catches
    `OSError`, not a guard assertion.
    """
    network_guard.unreachable("127.0.0.1", 7)
    try:
        with pytest.raises(ConnectionRefusedError):
            await asyncio.open_connection("127.0.0.1", 7)
        with pytest.raises(ConnectionRefusedError):
            socket.socket().connect(("127.0.0.1", 7))
    finally:
        network_guard.forget("127.0.0.1", 7)
    assert ("127.0.0.1", 7) not in network_guard.unexpected(), (
        "a declared-dead address must not count as a boundary violation")


async def test_low_level_datagram_is_refused(listener):
    """`loop.sock_sendto` bypasses both datagram-endpoint creation and socket sendto.

    Review escaped here after the first repair closed three other doors. Inventory entry
    points rather than patching whichever one comes to mind.
    """
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        with network_guard.expect_blocked():
            with pytest.raises(AssertionError, match="outside test boundary"):
                await loop.sock_sendto(sock, b"x", ("127.0.0.1", listener))
    finally:
        sock.close()


@pytest.mark.parametrize("call", [
    lambda: socket.gethostbyname("relay.example.invalid"),
    lambda: socket.gethostbyname_ex("relay.example.invalid"),
    lambda: socket.gethostbyaddr("203.0.113.7"),
    lambda: socket.getnameinfo(("203.0.113.7", 0), 0),
], ids=["gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo"])
def test_every_resolver_entry_point_is_refused(call):
    """Patching only `getaddrinfo` is insufficient; resolvers expose several entries."""
    with network_guard.expect_blocked():
        with pytest.raises(AssertionError, match="outside test boundary"):
            call()


async def test_expected_denials_do_not_erase_a_real_connection(listener):
    """The append-only log must retain real connections inside expected-denial blocks.

    The old implementation removed the log tail on exit, so a no-network assertion passed
    after real TCP exchange inside `expect_blocked`.
    """
    network_guard.allow("127.0.0.1", listener)
    with pytest.raises(AssertionError, match="network attempts occurred"):
        with network_guard.no_network("control: test declared no network"):
            with network_guard.expect_blocked():
                _, writer = await asyncio.open_connection("127.0.0.1", listener)
                writer.close()


def test_an_expected_denial_alone_does_not_break_the_no_network_claim():
    """An expected rejected attempt alone must not invalidate a no-network claim."""
    with network_guard.no_network("boundary test may attempt and expect refusal"):
        with network_guard.expect_blocked():
            with pytest.raises(AssertionError):
                socket.socket().connect(("192.0.2.1", 443))


async def test_datagram_transport_object_is_refused(listener):
    """Probe the third datagram door: the transport object's own method.

    Three rounds found `socket.sendto`, `loop.sock_sendto`, and `transport.sendto` one at
    a time. This exercises the high-level path used after create_datagram_endpoint.
    """
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0))
    try:
        with network_guard.expect_blocked():
            with pytest.raises(AssertionError, match="outside test boundary"):
                transport.sendto(b"x", ("127.0.0.1", listener))
        network_guard.allow("127.0.0.1", listener)
        transport.sendto(b"x", ("127.0.0.1", listener))      # False-refusal control.
    finally:
        transport.close()


def test_an_expectation_does_not_swallow_a_denial_from_another_thread():
    """An expectation belongs to its context, not a range of log entries.

    The old code marked EVERY later denial expected. A simultaneous violation in another
    thread disappeared from the result, despite an incorrect claim that this was impossible.
    """
    outside = []

    def elsewhere():
        try:
            socket.socket().connect(("192.0.2.99", 443))
        except AssertionError as denial:
            outside.append(denial)

    mark = len(network_guard.unexpected())
    written = len(network_guard._blocked)
    with network_guard.expect_blocked():
        with pytest.raises(AssertionError):
            socket.socket().connect(("192.0.2.1", 443))
        worker = threading.Thread(target=elsewhere)
        worker.start()
        worker.join()

    assert outside, "neighboring thread received no denial; test proved nothing"
    left = network_guard.unexpected()[mark:]
    assert ("192.0.2.99", 443) in left, "foreign violation swallowed by another context"
    assert ("192.0.2.1", 443) not in left, "owned expected denial was not consumed"

    # Clean up EXACTLY the record created here by sequence number, not address. The first
    # version marked every historical match and could suppress unrelated violations.
    created = [number for number, host, port, _owner in network_guard._blocked[written:]
               if (host, port) == ("192.0.2.99", 443)]
    assert len(created) == 1, f"test created {len(created)} records instead of one"
    network_guard._expected.add(created[0])


def test_scope_names_its_own_limits():
    """Scope states its limits explicitly; silence would read as a promise."""
    assert network_guard.SCOPE["subprocesses"].startswith("not enforced")
    for door in ("sync sockets", "asyncio connections", "datagrams", "name resolution"):
        assert network_guard.SCOPE[door].startswith("enforced"), door
