"""Real A4A stdio tools and durable receiver, with all network blocked in child."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_channel_adapter import SOCKET_GUARD
from test_inbox_live import Channel


ROOT = Path(__file__).resolve().parents[2]
SECRET = "QUIET_RUNTIME_PRIVATE_BODY"


@pytest.mark.parametrize("kind", ["incoming", "prepared", "unknown"])
@pytest.mark.requires_channel
async def test_real_runtime_notification_opens_persisted_dialogue(tmp_path, kind):
    home = tmp_path / "synthetic-profile"
    env = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "SYSTEMDRIVE") if key in os.environ}
    env.update(A4A_HOME=str(home), A4A_RELAY="ws://127.0.0.1:1/never",
               A4A_MANDATE_AUTO="0", A4A_MCP_CHANNEL="claude", A4A_MCP_TRANSPORT="stdio",
               A4A_PUBLIC_TEXT="deny", PYTHONIOENCODING="utf-8",
               HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    # There are two test directories: this suite's and the shared location containing
    # `network_guard` and `guarded_child`. This loader intentionally keeps its own socket
    # audit hook and isolated `-I` launch. It still needs the shared module path;
    # otherwise importing the neighboring file terminates the child before its first frame.
    bootstrap = (SOCKET_GUARD + "\nimport runpy; sys.path[:0] = sys.argv[1:3]; "
                 "sys.argv = sys.argv[3:]; runpy.run_path(sys.argv[0], run_name='__main__')")
    channel = Channel()
    channel.process = await asyncio.create_subprocess_exec(
        sys.executable, "-I", "-X", "utf8", "-B", "-c", bootstrap,
        str(Path(__file__).parent), str(ROOT / "sdk-python" / "tests"),
        str(Path(__file__).resolve()), "--child", kind,
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    channel.errors = asyncio.create_task(channel.process.stderr.read())
    channel.number = 1
    try:
        await channel.send("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                          "clientInfo": {"name": "quiet-test", "version": "1"}}, 1)
        response = await channel.receive()
        assert response["result"]["capabilities"]["experimental"] == {"claude/channel": {}}
        assert "In owner-enabled dialogue mode" in response["result"]["instructions"]
        await channel.send("notifications/initialized", {})
        hint = await channel.receive()
        assert hint["method"] == "notifications/claude/channel"
        assert "a4a_dialogue_open" in hint["params"]["content"]
        assert SECRET not in json.dumps(hint)
        assert hint["params"]["meta"] == {
            "consumer": "runtime-test", "pending": str(int(kind == "incoming")),
            "seq_hint": str(int(kind == "incoming")),
            "needs_reconciliation": str(int(kind == "unknown")),
            "outgoing_prepared": str(int(kind == "prepared"))}
        status = await channel.call("a4a_inbox_status")
        assert status["notifications"] == {
            "adapter": "claude_channel", "state": "listening",
            "scope": "current_process", "host_wake": "unverified",
        }
        assert SECRET not in json.dumps(status)
        # Production registry and actual history, not a stub tool returning a label.
        opened = await channel.call("a4a_dialogue_open")
        item = opened["history"]["items"][0]
        assert SECRET in item["content"]
        assert item["state"] == ("processing" if kind == "incoming" else kind)
        assert opened["lease"]["token"]
        channel.number += 1
        await channel.send("tools/call", {"name": "a4a_inbox_next", "arguments": {}}, channel.number)
        legacy = await channel.receive()
        assert legacy["id"] == channel.number
        assert legacy["result"]["isError"] is True
        # MCP 2.x masks exception details; the wire contract is a tool error.
        assert "a4a_inbox_next" in json.dumps(legacy)
        # No unsolicited second frame while the same work remains leased.
        with pytest.raises(TimeoutError):
            await channel.receive(timeout=.15)
    finally:
        await channel.close()
    assert SECRET.encode() not in await channel.errors
    assert not (home / "owner.json").exists()


def child_main(kind):
    sys.path[:0] = [str(ROOT / "sdk-python"), str(ROOT / "mcp-server")]
    from a4a import Agent, Keys, giftwrap, types
    from a4a.event import Event
    from a4a.dialogue import DialogueStore
    from a4a.inbox_receiver import InboxReceiver, InboxHistory
    from a4a_mcp import identity, inbox_runtime
    from a4a_mcp.__main__ import cli_main
    keys, peer = identity.load_or_create_identity(), Keys()
    inbox_runtime.configure("runtime-test", [peer.pubkey_hex], start_after=0)
    agent = Agent([os.environ["A4A_RELAY"]], keys=keys)
    with DialogueStore(identity.IDENTITY_DIR / "inbox", keys.pubkey_hex, "runtime-test") as store:
        store.activate()
        if kind == "incoming":
            inner = Event(kind=types.KIND_PRIVATE_RUMOR, tags=[["p", keys.pubkey_hex]], content=SECRET).sign(peer)
            store.accept(agent, giftwrap.wrap(inner, keys.pubkey_hex, peer), {peer.pubkey_hex})
        else:
            lease = store.acquire(peer.pubkey_hex, "previous", {peer.pubkey_hex}, now=1, lease_seconds=1)
            store.prepare_send(agent, lease["token"], "previous", {peer.pubkey_hex}, "op", SECRET, now=1)
            store.db.execute("UPDATE dialogue_outbox SET state=?", (kind,))
    async def empty_history(self, cursor):
        return []
    async def no_stream(self):
        await asyncio.Event().wait()
    InboxHistory.page = empty_history
    InboxReceiver._stream_hints = no_stream
    sys.argv = ["a4a_mcp"]
    cli_main()


if __name__ == "__main__":
    child_main(sys.argv[2])
