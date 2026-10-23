"""Explicit unbounded CLI is an ordinary process, never an idle model timer."""
import asyncio
import socket
import sys

import pytest


@pytest.fixture
def cli(monkeypatch, tmp_path):
    monkeypatch.setenv("A4A_HOME", str(tmp_path / "unused"))
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1/never")
    monkeypatch.setenv("A4A_MANDATE_AUTO", "0")
    # asyncio on Windows needs its own local socketpair before blocking sockets.
    loop = asyncio.new_event_loop()
    def blocked(*args, **kwargs):
        raise AssertionError("watch CLI tests prohibit network and MCP fallback")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    from a4a_mcp import __main__ as entry, inbox_runtime
    entry._load_server()  # Ambient settings and socket guards are already set.
    monkeypatch.setattr(entry.mcp, "run", blocked)
    monkeypatch.setattr(entry.asyncio, "run", loop.run_until_complete)
    try:
        yield entry, inbox_runtime
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


@pytest.mark.parametrize("arguments,expected", [([], 3600), (["--duration", "42"], 42), (["--forever"], None)])
def test_watch_lifetime_and_idle_stdout(cli, monkeypatch, capsys, arguments, expected):
    entry, runtime = cli
    timeouts, closed = [], []
    actual_timeout = asyncio.timeout
    def timeout(value):
        timeouts.append(value)
        return actual_timeout(value)
    async def source():
        try:
            await asyncio.sleep(0)
            raise asyncio.CancelledError
            yield  # async iterator with no work
        finally:
            closed.append(True)
    monkeypatch.setattr(asyncio, "timeout", timeout)
    monkeypatch.setattr(runtime, "notices", source)
    monkeypatch.setattr(sys, "argv", ["a4a_mcp", "inbox-watch", *arguments])
    with pytest.raises(asyncio.CancelledError):
        entry.cli_main()
    assert timeouts == [expected]
    assert closed == [True]
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("arguments", [
    ["--once", "--duration", "1"], ["--once", "--forever"],
    ["--duration", "1", "--forever"], ["--duration", "0"], ["--duration", "86401"],
])
def test_invalid_watch_modes_never_open_runtime(cli, monkeypatch, capsys, arguments):
    entry, runtime = cli
    def forbidden():
        pytest.fail("invalid mode opened an inbox")
    monkeypatch.setattr(runtime, "open_runtime", forbidden)
    monkeypatch.setattr(sys, "argv", ["a4a_mcp", "inbox-watch", *arguments])
    with pytest.raises(SystemExit):
        entry.cli_main()
    assert capsys.readouterr().out == ""
