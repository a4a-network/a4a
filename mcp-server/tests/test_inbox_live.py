"""Opt-in actual relay + actual channel subprocess, isolated from working inboxes.

Build the local relay first. A4A_RUN_LOCAL_INBOX_CHECK=1 creates and removes only
its own loopback Docker container. No existing relay URL or user identity is used.
"""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import socket
import subprocess
import sys
import time
import uuid

import pytest

from urllib.parse import urlsplit

import guarded_child
from a4a import Agent, Keys
from mcp.client.stdio import get_default_environment

ROOT = Path(__file__).resolve().parents[2]


def guarded(home, url, args, extra=None):
    """Launch behind the suite boundary and explicitly grant the live relay address.

    This integration suite uses a real node selected through explicit `--integration`
    consent. The parent allows that address and passes it to the child. Without this,
    the child could access arbitrary network destinations instead of only the approved
    relay.
    """
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "wss" else 80)
    argv, env, ready = guarded_child.module_command(
        args, home=str(home), relay=url,
        allow=[(parts.hostname, port)],
        env={"A4A_MANDATE_AUTO": "0", "A4A_PUBLIC_TEXT": "deny",
             "A4A_MCP_TRANSPORT": "stdio", "A4A_MCP_CHANNEL": "",
             "PYTHONDONTWRITEBYTECODE": "1", **(extra or {})})
    return argv, {**get_default_environment(), **env}, ready


async def cli(home, url, *args):
    argv, env, ready = guarded(home, url, ["-m", "a4a_mcp", *args])
    result = await asyncio.to_thread(subprocess.run, argv, env=env,  # unguarded-launch: argv comes from module_command
        capture_output=True, text=True, encoding="utf-8", timeout=20)
    ready.note_exit(result.returncode)
    ready.check()
    assert result.returncode == 0, result.stderr
    return result.stdout


class Channel:
    #: One-time launch handshake. `None` means this channel was not started through
    #: `start()`: `test_quiet_channel_runtime` creates the process with its own isolated
    #: loader and socket audit hook. Requiring this handshake from another loader would
    #: either break it or erase the distinction between two protection mechanisms.
    ready = None

    async def start(self, home, url):
        # Set the channel through launch preparation, not by overlaying the final
        # environment. The child loader assigns product values after sanitization, so
        # an outer change cannot reach it. The first version prepared twice and then
        # overlaid the channel, causing the child to start without it.
        argv, env, self.ready = guarded(home, url, ["-m", "a4a_mcp"],
                                        extra={"A4A_MCP_CHANNEL": "claude"})
        self.process = await asyncio.create_subprocess_exec(  # unguarded-launch: argv comes from module_command
            *argv, env=env,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        # Confirm readiness before the first request. Otherwise broken preparation
        # becomes visible only after communicating with an unverified process.
        self.ready.wait(timeout=30)
        # The boundary reads the exit status itself after the test has awaited the child.
        self.ready.attach(self.process)
        self.errors = asyncio.create_task(self.process.stderr.read())
        self.number = 1
        await self.send("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                      "clientInfo": {"name": "inbox-acceptance", "version": "1"}}, 1)
        result = await self.receive()
        assert result["result"]["capabilities"]["experimental"] == {"claude/channel": {}}
        await self.send("notifications/initialized", {})
        return self

    async def send(self, method, params, number=None):
        packet = {"jsonrpc": "2.0", "method": method, "params": params}
        if number is not None:
            packet["id"] = number
        self.process.stdin.write((json.dumps(packet) + "\n").encode())
        await self.process.stdin.drain()

    async def receive(self, timeout=20):
        line = await asyncio.wait_for(self.process.stdout.readline(), timeout)
        assert line, "channel ended without the expected frame"
        return json.loads(line)

    async def call(self, name, **args):
        self.number += 1
        await self.send("tools/call", {"name": name, "arguments": args}, self.number)
        packet = await self.receive()
        assert packet.get("id") == self.number, packet
        result = packet["result"]
        assert not result.get("isError"), result
        return json.loads(next(item["text"] for item in result["content"] if item["type"] == "text"))

    async def close(self):
        if self.process.returncode is None:
            self.process.stdin.close()
            try:
                await asyncio.wait_for(self.process.wait(), 10)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()
                pytest.fail("channel did not stop after EOF")
        errors = await self.errors
        if self.ready is not None:
            self.ready.check()
        assert self.process.returncode == 0, errors.decode("utf-8", "replace")
        assert b"INBOX_LIVE_SECRET" not in errors


async def cursor_reached(home, event_id):
    started = time.monotonic()
    deadline = started + 60
    health = None
    while time.monotonic() < deadline:
        with sqlite3.connect(home / "inbox" / "inbox.sqlite3") as db:
            row = db.execute("SELECT event_id FROM cursors").fetchone()
            health = db.execute("SELECT value FROM metadata WHERE key='receiver'").fetchone()
        if row and row[0] == event_id:
            print(f"durable cursor reached after {time.monotonic() - started:.2f}s")
            return
        await asyncio.sleep(0.1)
    pytest.fail(f"receiver did not durably advance within 60s; cursor={row}; health={health}")


async def receiver_ready(channel):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        status = await channel.call("a4a_inbox_status")
        if status["receiver"]["state"] == "ready" and not status["receiver"]["stale"]:
            return
        await asyncio.sleep(0.1)
    pytest.fail(f"receiver did not complete initial history sync: {status['receiver']}")


async def test_inbox_on_disposable_relay(tmp_path):
    if os.environ.get("A4A_RUN_LOCAL_INBOX_CHECK") != "1":
        pytest.skip("explicit local Docker inbox acceptance only")
    spec = importlib.util.spec_from_file_location("inbox_local_runner", ROOT / "scripts/local-relay-safety-check.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    name = "a4a-inbox-check-" + uuid.uuid4().hex[:12]
    # Docker may choose a different ephemeral host port on restart. Pin a free
    # loopback port; if another process wins the race, Docker must fail to bind.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    created, channel = False, None
    try:
        await asyncio.to_thread(runner.docker, "create", "--pull", "never", "--name", name,
            "--memory", "256m", "--cpus", "2", "-p", f"127.0.0.1:{port}:8080",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", "a4a-relay-target:/build:ro", "-v", f"{ROOT / 'relay/config.toml'}:/check.toml:ro",
            "--entrypoint", "/build/debug/nostr-rs-relay", "a4a-relay-builder",
            "--config", "/check.toml", "--db", "/tmp")
        created = True
        await asyncio.to_thread(runner.docker, "start", name)
        address = await asyncio.to_thread(runner.docker, "port", name, "8080/tcp")
        assert re.fullmatch(r"127\.0\.0\.1:\d+", address)
        url, base = "ws://" + address, "http://" + address
        await asyncio.to_thread(runner.wait_ready, base)
        home, friend, stranger = tmp_path / "receiver", Keys(), Keys()
        text = await cli(home, url, "address")
        recipient = re.search(r"pubkey \(hex\): ([0-9a-f]{64})", text).group(1)
        await cli(home, url, "inbox-configure", "--consumer", "acceptance", "--allow-peer", friend.pubkey_hex,
                  "--start-after", "0")
        policy_path = home / "inbox-policy.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy.update(notify_interval=10, notify_per_hour=60)
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        channel = Channel()
        await channel.start(home, url)
        await receiver_ready(channel)
        async with Agent([url], keys=stranger) as sender:
            blocked = await sender.send_private_message_receipt(recipient, "INBOX_LIVE_SECRET_OUTSIDER")
        await cursor_reached(home, blocked["outer_id"])
        status = await channel.call("a4a_inbox_status")
        assert status["counts"]["total"] == 0
        async with Agent([url], keys=friend) as sender:
            first = await sender.send_private_message_receipt(recipient, "INBOX_LIVE_SECRET_ONE", delivery_id="one")
        hint = await channel.receive(timeout=60)
        assert hint["method"] == "notifications/claude/channel"
        assert hint["params"]["meta"] == {"consumer": "acceptance", "pending": "1", "seq_hint": "1"}
        assert "INBOX_LIVE_SECRET" not in json.dumps(hint)
        message = (await channel.call("a4a_inbox_next"))["message"]
        assert message["inner_id"] == first["inner_id"] and message["outer_id"] == first["outer_id"]
        assert "INBOX_LIVE_SECRET_ONE" in message["content"] and "UNTRUSTED" in message["content"]
        done = await channel.call("a4a_inbox_complete", seq=message["seq"], lease_token=message["lease_token"], status="processed")
        assert done["network_ack_sent"] is True
        assert done["network_ack_state"] == "sent"
        async with Agent([url], keys=friend) as sender:
            retry = await sender.send_private_message_receipt(recipient, "INBOX_LIVE_SECRET_ONE", delivery_id="one")
        assert retry["outer_id"] != first["outer_id"]
        await cursor_reached(home, retry["outer_id"])
        status = await channel.call("a4a_inbox_status")
        assert status["counts"]["total"] == status["counts"]["processed"] == 1
        await channel.close()
        channel = None
        async with Agent([url], keys=friend) as sender:
            offline = await sender.send_private_message_receipt(recipient, "INBOX_LIVE_SECRET_OFFLINE", delivery_id="two")
        await asyncio.to_thread(runner.docker, "restart", name)
        assert await asyncio.to_thread(runner.docker, "port", name, "8080/tcp") == address
        await asyncio.to_thread(runner.wait_ready, base)
        channel = Channel()
        await channel.start(home, url)
        hint = await channel.receive(timeout=45)
        assert hint["method"] == "notifications/claude/channel" and "INBOX_LIVE_SECRET" not in json.dumps(hint)
        message = (await channel.call("a4a_inbox_next"))["message"]
        assert message["inner_id"] == offline["inner_id"] and message["outer_id"] == offline["outer_id"]
        assert "INBOX_LIVE_SECRET_OFFLINE" in message["content"]
        await channel.call("a4a_inbox_complete", seq=message["seq"], lease_token=message["lease_token"], status="processed")
        status = await channel.call("a4a_inbox_status")
        assert status["counts"]["total"] == status["counts"]["processed"] == 2
        await channel.close()
        channel = None
        for path in (home / "inbox").iterdir():
            if path.is_file():
                assert b"INBOX_LIVE_SECRET" not in path.read_bytes()
        print("PASS actual relay -> encrypted SQLite -> metadata-only channel -> real tools/call; restart, duplicate and outsider checks")
    finally:
        try:
            if channel is not None:
                await channel.close()
        finally:
            if created:
                await asyncio.to_thread(runner.docker, "rm", "-f", name)
