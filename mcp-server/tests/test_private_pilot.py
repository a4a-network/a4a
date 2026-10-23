"""Local messaging rehearsal through separate MCP processes.

This uses real MCP/stdio and cryptography, but not Codex/Claude windows or LLM calls.
The ordinary test uses FakeRelay; a separate run uses a temporary Docker relay.
"""
import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

import ambient
import guarded_child
import network_guard
import pytest
import websockets
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client

from a4a import Keys, giftwrap, nip44
from a4a.event import Event
from a4a.relay import RelayClient
from fake_relay import FakeRelay


ROOT = Path(__file__).resolve().parents[2]
# The name lives in `ambient` because that module decides to keep it; the runner that
# owns the value and this test must not drift apart on its spelling.
PILOT_RELAY_ENV = ambient.PRIVATE_PILOT_RELAY


def _local_relay(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "ws" or parsed.hostname != "127.0.0.1"
            or parsed.port is None or parsed.port == 0
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("private pilot requires an explicit ws://127.0.0.1:<port> relay")
    return url


def _guarded(url, home, args):
    """Start the real server/CLI with the test boundary already installed.

    This used to be a bare launch with a custom environment. Monkeypatches live in parent
    memory and do not reach the child, so those interpreters accessed the network without a
    boundary. The fixture-owned node is now explicitly allowed for the child and every
    unrelated endpoint is removed.
    """
    relay = _local_relay(url)
    argv, env, ready = guarded_child.module_command(
        args, home=str(home), relay=relay,
        allow=[("127.0.0.1", int(urlsplit(relay).port))],
        source_roots=[ROOT / "sdk-python", ROOT / "mcp-server"],
        env={"A4A_MANDATE_AUTO": "0", "A4A_MANDATE_DAYS": "1",
             "A4A_PUBLIC_TEXT": "deny", "A4A_MCP_TRANSPORT": "stdio",
             "PYTHONDONTWRITEBYTECODE": "1"})
    return argv, {**get_default_environment(), **env}, ready


@asynccontextmanager
async def _peer(home, url):
    argv, env, ready = _guarded(url, home, ["-m", "a4a_mcp"])
    params = StdioServerParameters(command=argv[0], args=argv[1:], env=env,
                                   cwd=ROOT / "mcp-server")

    # Capture the real stdio-child exit code. A third-party library owns the process, and
    # without this hook the boundary knows nothing about its outcome. A reviewer showed that
    # the fallback marker alone is insufficient because it shares the storage that failed.
    # There is one explicit seam, so hook it narrowly rather than replacing the whole client.
    import mcp.client.stdio as stdio_module
    original_spawn = stdio_module._create_platform_compatible_process

    async def capture(*args, **kwargs):
        process = await original_spawn(*args, **kwargs)
        # Attach ONLY our child using its one-time secret. This hook is global while sessions
        # may nest. Without the check, an outer hook captured the inner process and overwrote
        # its own result with the inner result. A reviewer reproduced this with real nesting:
        # the broken child exited 6, the boundary saw 0, and the parent passed.
        spawned = kwargs.get("env")
        if spawned is None and len(args) >= 3:
            spawned = args[2]
        if spawned and spawned.get("A4A_CHILD_TOKEN") == ready.token:
            ready.attach(process)
        return process

    stdio_module._create_platform_compatible_process = capture
    try:
        async with stdio_client(params) as (reader, writer):
            # Before the first request, the child handshake must complete; otherwise we may be
            # talking to a process whose setup failed entirely.
            await asyncio.to_thread(ready.wait, None, 30)
            async with ClientSession(reader, writer) as session:
                info = await session.initialize()
                assert info.model_dump(by_alias=True)["serverInfo"]["version"], "MCP must identify the tested server version"
                yield session
    finally:
        stdio_module._create_platform_compatible_process = original_spawn


async def _call(session, name, **arguments):
    result = await session.call_tool(name, arguments)
    assert not result.model_dump(by_alias=True).get("isError", False), f"MCP tool failed: {name}"
    return "\n".join(item.text for item in result.content if item.type == "text")


async def _address(session):
    text = await _call(session, "a4a_my_address")
    found = re.search(r"pubkey \(hex\): ([0-9a-f]{64})", text)
    assert found, "a4a_my_address must identify its public key"
    return found.group(1)


async def _issue_mandate(home, url):
    argv, env, ready = _guarded(url, home, ["-m", "a4a_mcp", "issue-mandate"])
    completed = await asyncio.to_thread(
        subprocess.run, argv, cwd=ROOT / "mcp-server", env=env, capture_output=True,  # unguarded-launch: argv comes from module_command
        text=True, encoding="utf-8", timeout=30, check=False)
    ready.note_exit(completed.returncode)
    ready.check()
    assert completed.returncode == 0, "owner mandate command failed"
    assert "Mandate issued" in completed.stdout


async def _configure_inbox(home, url, consumer, recipient, peer):
    argv, env, ready = _guarded(url, home, [
        "-m", "a4a_mcp", "inbox-configure", "--consumer", consumer,
        "--allow-peer", peer, "--start-after", "0"])
    completed = await asyncio.to_thread(
        subprocess.run, argv, cwd=ROOT / "mcp-server", env=env, capture_output=True,  # unguarded-launch: argv comes from module_command
        text=True, encoding="utf-8", timeout=30, check=False)
    ready.note_exit(completed.returncode)
    ready.check()
    assert completed.returncode == 0, "temporary inbox configuration failed"
    assert json.loads(completed.stdout) == {
        "state": "configured", "consumer": consumer, "recipient": recipient,
        "allowed_peers": [peer], "allowed_owners": [], "relay": url, "start_after": 0,
        "ack_on_receipt": False,
    }


def _receipt(text):
    assert "relay_accepted" in text, text
    found = re.search(
        r"\binner_id=([0-9a-f]{64}) outer_id=([0-9a-f]{64}) delivery_id=([0-9a-f]{32})\b",
        text)
    assert found, "private receipt must identify both events and the logical delivery"
    return found.groups()


async def _wire_messages(url):
    async with RelayClient(url) as relay:
        return await relay.query({"kinds": [1059]})


@asynccontextmanager
async def _recording_relay(url):
    upstream_url = _local_relay(url)
    frames = []

    async def proxy(client):
        async with websockets.connect(upstream_url) as upstream:
            async def outbound():
                async for frame in client:
                    frames.append(frame)
                    await upstream.send(frame)

            async def inbound():
                async for frame in upstream:
                    await client.send(frame)

            tasks = [asyncio.create_task(outbound()), asyncio.create_task(inbound())]
            try:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

    async with websockets.serve(proxy, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        # This test started the recording proxy, so allow it through the test boundary.
        network_guard.allow("127.0.0.1", port)
        try:
            yield f"ws://127.0.0.1:{port}", frames
        finally:
            network_guard.forget("127.0.0.1", port)


async def _roundtrip(home, url):
    async with _recording_relay(url) as (observed_url, frames):
        await _exchange(home, observed_url, frames)
    packets = [json.loads(frame) for frame in frames]
    wire = json.dumps(packets, ensure_ascii=False)
    assert "PRIVATE_PILOT_REQUEST" not in wire and "PRIVATE_PILOT_REPLY" not in wire, "plaintext reached the relay"
    events = [p[1] for p in packets if p[0] == "EVENT"]
    assert len(events) == 4, "unexpected publication attempt"
    envelopes = [e for e in events if e["kind"] == 1059]
    mandates = [e for e in events if e["kind"] == 31000]
    assert len(envelopes) == 2 and len(mandates) == 2, "unexpected publication kind"
    # Each owner creates one mandate. Reuse on this exact node neither signs new
    # authorization nor redundantly republishes an already present mandate.
    originals = {e["id"]: e for e in mandates}
    assert len(originals) == 2
    assert all(e == originals[e["id"]] for e in mandates)
    assert all(sum(e["id"] == identifier for e in mandates) == 1 for identifier in originals)


async def _exchange(home, url, frames):
    home_a, home_b, home_c = (home / name for name in ("developer-a", "developer-b", "outsider"))
    request = "PRIVATE_PILOT_REQUEST: \u0441\u043E\u0433\u043B\u0430\u0441\u0443\u0435\u043C \u0442\u0435\u0441\u0442\u043E\u0432\u044B\u0439 \u0438\u043D\u0442\u0435\u0440\u0444\u0435\u0439\u0441, \u0432\u0435\u0440\u0441\u0438\u044F 1"
    reply = "PRIVATE_PILOT_REPLY: \u0442\u0435\u0441\u0442\u043E\u0432\u044B\u0439 \u0438\u043D\u0442\u0435\u0440\u0444\u0435\u0439\u0441 \u043F\u0440\u043E\u0432\u0435\u0440\u0435\u043D, \u0440\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442 \u0441\u043E\u0432\u043C\u0435\u0441\u0442\u0438\u043C"

    async with _peer(home_a, url) as sender:
        address_a = await _address(sender)
        async with _peer(home_b, url) as recipient:
            address_b = await _address(recipient)
            assert address_a != address_b, "different developers must not share an identity"
            await _configure_inbox(home_a, url, "pilot-a", address_a, address_b)
            await _configure_inbox(home_b, url, "pilot-b", address_b, address_a)
            assert "no incoming private messages" in await _call(
                recipient, "a4a_read_private"
            )

        # The recipient is offline: relay acceptance must not depend on a live MCP session.
        refused = await _call(sender, "a4a_send_private", to_pubkey=address_b, text=request)
        assert "delegation" in refused and "issue-mandate" in refused
        assert not await _wire_messages(url), "denied send must not publish a private envelope"
        assert not any(json.loads(frame)[0] == "EVENT" for frame in frames), "denied send attempted publication"
        await _issue_mandate(home_a, url)
        await _issue_mandate(home_b, url)
        sent = await _call(sender, "a4a_send_private", to_pubkey=address_b, text=request)
        request_receipt = _receipt(sent)
        assert address_b in sent

        async with _peer(home_b, url) as recipient:
            assert await _address(recipient) == address_b, "restart must preserve the address"
            inbox = await _call(recipient, "a4a_read_private")
            assert request in inbox and address_a in inbox
            assert f"inner_id={request_receipt[0]}" in inbox
            assert "UNTRUSTED DATA" in inbox, "peer content must remain untrusted input"
            sent_back = await _call(recipient, "a4a_send_private", to_pubkey=address_a, text=reply)
            reply_receipt = _receipt(sent_back)
            assert address_a in sent_back
            returned = await _call(sender, "a4a_read_private")
            assert reply in returned and address_b in returned
            assert f"inner_id={reply_receipt[0]}" in returned

            # This is the documented boundary of the current MCP, NOT one-time task processing.
            repeated = await _call(recipient, "a4a_read_private")
            assert request in repeated, "this API reads history, not a durable new-message queue"

    async with _peer(home_c, url) as outsider:
        address_c = await _address(outsider)
        assert address_c not in (address_a, address_b)
        # Exercise a real read, not a closed-policy refusal, with unrelated keys.
        await _configure_inbox(home_c, url, "pilot-outsider", address_c, address_a)
        assert "no incoming private messages" in await _call(
            outsider, "a4a_read_private"
        )

    envelopes = await _wire_messages(url)
    assert len(envelopes) == 2, "reading and restarting must not publish duplicate messages"
    assert {e.tag_value("p") for e in envelopes} == {address_a, address_b}
    recipients = {
        address: Keys(json.loads((directory / "identity.json").read_text(encoding="utf-8"))["privkey_hex"])
        for address, directory in ((address_a, home_a), (address_b, home_b))
    }
    outsider_keys = Keys()
    for envelope in envelopes:
        assert envelope.verify()
        assert envelope.pubkey not in (address_a, address_b)
        with pytest.raises(giftwrap.GiftWrapError):
            giftwrap.unwrap(envelope, outsider_keys)
        # The address check above never reaches cryptography; verify the ciphertext below.
        correct = recipients[envelope.tag_value("p")]
        inner = giftwrap.unwrap(envelope, correct)
        assert inner.content == (request if correct.pubkey_hex == address_b else reply)
        receipt = request_receipt if correct.pubkey_hex == address_b else reply_receipt
        assert (inner.id, envelope.id, inner.tag_value("d")) == receipt
        with pytest.raises(nip44.Nip44Error, match="MAC"):
            nip44.decrypt(envelope.content, outsider_keys.privkey_hex, envelope.pubkey)
    # Search beyond envelopes: an accidental public copy would also be a leak.
    async with RelayClient(url) as relay:
        all_events = await relay.query({"limit": 100})
    wire = json.dumps([event.model_dump() for event in all_events], ensure_ascii=False)
    assert request not in wire and reply not in wire
    assert len([e for e in all_events if e.kind == 31000]) == 2
    assert {e.kind for e in all_events} == {31000, 1059}


async def test_private_pilot_over_real_stdio_processes(tmp_path):
    async with FakeRelay() as relay:
        async with asyncio.timeout(90):
            await _roundtrip(tmp_path, relay.url)


async def test_private_pilot_without_mandate_env_uses_safe_default(tmp_path, monkeypatch):
    """Without explicit `A4A_MANDATE_AUTO`, the safe default applies instead of silent issuance."""
    original = _guarded

    def guarded(url, home, args):
        argv, env, ready = original(url, home, args)
        # The child receives this variable through `A4A_CHILD_EXTRA`; remove it there rather
        # than from the completed environment, where it is already absent.
        extra = json.loads(env["A4A_CHILD_EXTRA"])
        extra.pop("A4A_MANDATE_AUTO", None)
        return argv, {**env, "A4A_CHILD_EXTRA": json.dumps(extra)}, ready

    monkeypatch.setattr(sys.modules[__name__], "_guarded", guarded)
    async with FakeRelay() as relay:
        async with asyncio.timeout(90):
            await _roundtrip(tmp_path, relay.url)


@pytest.mark.skipif(not os.environ.get(PILOT_RELAY_ENV), reason="requires the disposable local relay runner")
async def test_private_pilot_on_disposable_relay(tmp_path):
    """Rehearse against the throwaway node that the safety-check runner created.

    Two things must arrive for this node to run. The address comes from
    `A4A_LOCAL_PRIVATE_PILOT_RELAY`, which `ambient` keeps as a harness-owned name while
    still removing every other `A4A_*` value; a skip here means no runner asked for this
    test, and the runner treats that as failure. The destination then has to be declared
    to the test boundary, which refuses every endpoint until a caller names it; that
    declaration is made below, after `_local_relay` has refused every address that is not
    `ws://127.0.0.1:<port>`.
    """
    url = _local_relay(os.environ[PILOT_RELAY_ENV])
    print(f"LOCAL MCP PRIVATE PILOT: {url}; isolated test identities; no LLM sessions")
    # The runner created this node and confirmed it answers `/v1/health` before this
    # process started, and the validation above already refused anything but a loopback
    # endpoint: that is the ownership claim the boundary asks for. Without it the
    # recording proxy below is refused when it dials the node, and the pilot fails
    # against a relay that is up, which reads like a product defect.
    port = int(urlsplit(url).port)
    network_guard.allow("127.0.0.1", port)
    try:
        async with asyncio.timeout(90):
            await _roundtrip(tmp_path, url)
    finally:
        network_guard.forget("127.0.0.1", port)


@pytest.mark.parametrize("url", [
    "wss://eu1.a4a.network", "ws://localhost:8080", "ws://127.0.0.1",
    "ws://127.0.0.1:0", "ws://user@127.0.0.1:8080", "ws://127.0.0.1:8080/other",
    "ws://127.0.0.1:8080?relay=production", "ws://127.0.0.1:8080#fragment",
])
def test_private_pilot_rejects_nonlocal_or_ambiguous_targets(url):
    with pytest.raises(ValueError):
        _local_relay(url)


async def test_private_pilot_detects_rejected_plaintext_frames(tmp_path, monkeypatch):
    original = _issue_mandate
    injected = False

    async def leak(home, url):
        nonlocal injected
        await original(home, url)
        if not injected:
            injected = True
            event = Event(kind=1, content="PRIVATE_PILOT_REQUEST: \u0441\u043E\u0433\u043B\u0430\u0441\u0443\u0435\u043C \u0442\u0435\u0441\u0442\u043E\u0432\u044B\u0439 \u0438\u043D\u0442\u0435\u0440\u0444\u0435\u0439\u0441, \u0432\u0435\u0440\u0441\u0438\u044F 1").sign(Keys())
            packet = event.model_dump()
            packet["sig"] = "0" * 128
            async with websockets.connect(url) as socket:
                await socket.send(json.dumps(["EVENT", packet]))
                await socket.recv()

    monkeypatch.setattr(sys.modules[__name__], "_issue_mandate", leak)
    async with FakeRelay() as relay:
        async with asyncio.timeout(90):
            with pytest.raises(AssertionError, match="plaintext"):
                await _roundtrip(tmp_path, relay.url)


async def test_private_pilot_exercises_actual_decryption(tmp_path, monkeypatch):
    original = nip44.decrypt
    outcomes = []

    def decrypt(*args, **kwargs):
        try:
            result = original(*args, **kwargs)
        except nip44.Nip44Error:
            outcomes.append("failed")
            raise
        outcomes.append("passed")
        return result

    monkeypatch.setattr(nip44, "decrypt", decrypt)
    async with FakeRelay() as relay:
        async with asyncio.timeout(90):
            await _roundtrip(tmp_path, relay.url)
    assert outcomes.count("failed") == 2, "outsider must actually try both ciphertexts"
    assert outcomes.count("passed") >= 2, "the correct keys must decrypt as a positive control"

async def test_a_caught_denial_inside_the_stdio_child_fails_the_parent(tmp_path, monkeypatch):
    """A violation in an stdio child must reach the PARENT test rather than disappear.

    A reviewer demonstrated this in the same caller: the child caught a boundary denial,
    exited with code 4, and printed the list, while the parent test stayed green. The stdio
    client does not raise on a nonzero exit code, and the caller did not inspect it. An outcome
    nobody reads is not an outcome.

    The denial is injected into the REAL bootstrap and travels through the real `_peer`;
    a fake caller would prove only that the fake works.
    """
    injected = guarded_child._MODULE_BOOTSTRAP.replace(
        "import runpy",
        chr(10).join([
            "try:",
            "    import socket as _probe",
            "    _probe.socket().connect((\"192.0.2.13\", 443))",
            "except Exception:",
            "    pass",
            "import runpy",
        ]), 1)
    assert injected != guarded_child._MODULE_BOOTSTRAP, "injection did not apply"
    monkeypatch.setattr(guarded_child, "_MODULE_BOOTSTRAP", injected)

    async with FakeRelay() as relay:
        async with asyncio.timeout(90):
            async with _peer(tmp_path / "home", relay.url) as session:
                assert await _address(session), "session did not start, making the control vacuous"

    # The parent must learn about the violation, even if the child was terminated forcefully:
    # the record is written at denial time, not at exit.
    with pytest.raises(AssertionError, match="crossed the test-run boundary"):
        guarded_child.assert_all_clean()


async def test_a_clean_stdio_child_leaves_the_parent_green(tmp_path):
    """Positive control: the same path is clean without injection.

    Without this, "the parent fails" is indistinguishable from "the parent always fails."
    """
    async with FakeRelay() as relay:
        async with asyncio.timeout(90):
            async with _peer(tmp_path / "home", relay.url) as session:
                assert await _address(session)
    guarded_child.assert_all_clean()

async def test_a_broken_audit_in_the_stdio_child_is_caught_by_its_exit_status(tmp_path):
    """When the fallback marker cannot be written ANYWHERE, only the exit code saves the parent.

    A reviewer showed that two paths are insufficient when both share one storage system. Break
    both the audit record and marker write, and a parent unaware of process outcome declares the
    child clean. A third-party library owns the process, so its outcome must be captured where
    the process is created.

    This probe breaks BOTH paths: audit writes are rejected, as is opening the marker file. The
    marker must NOT appear; otherwise the test would validate it instead of the exit code.
    """
    injected = guarded_child._MODULE_BOOTSTRAP.replace(
        "import runpy",
        chr(10).join([
            "import builtins as _b",
            "_real_open = _b.open",
            "def _refuse_open(path, *a, **k):",
            "    if str(path).endswith('.broken'):",
            '        raise OSError("injected marker failure")',
            "    return _real_open(path, *a, **k)",
            "_b.open = _refuse_open",
            "def _refuse_write(fd, data):",
            '    raise OSError("injected audit-write failure")',
            "os.write = _refuse_write",
            "try:",
            "    import socket as _probe",
            '    _probe.socket().connect(("192.0.2.41", 443))',
            "except Exception:",
            "    pass",
            "import runpy",
        ]), 1)
    assert injected != guarded_child._MODULE_BOOTSTRAP, "injection did not apply"

    made = []
    original = guarded_child.module_command

    def remember(*args, **kwargs):
        argv, env, ready = original(*args, **kwargs)
        made.append(ready)
        return argv, env, ready

    original_bootstrap = guarded_child._MODULE_BOOTSTRAP
    guarded_child.module_command = remember
    guarded_child._MODULE_BOOTSTRAP = injected
    try:
        async with FakeRelay() as relay:
            with pytest.raises(BaseException):
                async with asyncio.timeout(90):
                    async with _peer(tmp_path / "home", relay.url) as session:
                        await _address(session)
    finally:
        guarded_child.module_command = original
        guarded_child._MODULE_BOOTSTRAP = original_bootstrap

    assert made, "launch did not occur, making the control vacuous"
    ready = made[-1]
    assert not ready.crossings(), "audit write succeeded, so the probe did not reproduce the failure"
    assert not ready.broken_flag.exists(), (
        "failure marker was written, so the control is testing it rather than the exit code")
    assert ready.exit_status() == ready.AUDIT_BROKEN, (
        f"stdio-child outcome did not reach the boundary: {ready.exit_status()}")
    with pytest.raises(AssertionError, match="violation audit"):
        ready.assert_clean()
    ready.acknowledge()

def _audit_breaking_bootstrap():
    """Bootstrap in which BOTH paths for reporting audit failure break."""
    return guarded_child._MODULE_BOOTSTRAP.replace(
        "import runpy",
        chr(10).join([
            "import builtins as _b",
            "_real_open = _b.open",
            "def _refuse_open(path, *a, **k):",
            "    if str(path).endswith('.broken'):",
            '        raise OSError("injected marker failure")',
            "    return _real_open(path, *a, **k)",
            "_b.open = _refuse_open",
            "def _refuse_write(fd, data):",
            '    raise OSError("injected audit-write failure")',
            "os.write = _refuse_write",
            # Delay the failure: the child must survive until its nested session starts. If it
            # dies immediately, nesting never occurs and the test covers early startup rather
            # than outcome substitution.
            "import threading as _t, time as _time",
            "def _later():",
            "    _time.sleep(4)",
            "    try:",
            '        import socket as _probe',
            '        _probe.socket().connect(("192.0.2.41", 443))',
            "    except Exception:",
            "        pass",
            "_t.Thread(target=_later, daemon=True).start()",
            "import runpy",
        ]), 1)


async def test_a_broken_peer_is_not_hidden_by_a_healthy_one_nested_inside_it(tmp_path):
    """A nested session must not replace the outer session's outcome.

    The third-party library makes the process hook global while our sessions may nest. In the
    first version, the outer hook captured the INNER session's process and overwrote its own
    result with it: the broken child exited 6, the boundary saw 0, and the parent passed. A
    reviewer reproduced this with real nesting.

    Only the OUTER child breaks here; the inner child is healthy, and the boundary must reject
    the outer child specifically.
    """
    made = []
    original = guarded_child.module_command

    def remember(*args, **kwargs):
        result = original(*args, **kwargs)
        made.append(result[2])
        return result

    guarded_child.module_command = remember
    original_bootstrap = guarded_child._MODULE_BOOTSTRAP
    try:
        async with FakeRelay() as relay:
            guarded_child._MODULE_BOOTSTRAP = _audit_breaking_bootstrap()
            with pytest.raises(BaseException):
                async with asyncio.timeout(120):
                    async with _peer(tmp_path / "a", relay.url) as outer:
                        guarded_child._MODULE_BOOTSTRAP = original_bootstrap
                        async with _peer(tmp_path / "b", relay.url) as inner:
                            assert await _address(inner), "nested session did not start"
                        await asyncio.sleep(6)          # let the outer child reach its failure
                        await _address(outer)
    finally:
        guarded_child.module_command = original
        guarded_child._MODULE_BOOTSTRAP = original_bootstrap

    assert len(made) >= 2, f"nesting did not occur; launches: {len(made)}"
    broken, healthy = made[0], made[1]
    assert broken.exit_status() == broken.AUDIT_BROKEN, (
        f"outer broken child's outcome was replaced: {broken.exit_status()}")
    assert healthy.exit_status() != healthy.AUDIT_BROKEN, (
        f"inner healthy child's outcome was corrupted: {healthy.exit_status()}")
    with pytest.raises(AssertionError, match="violation audit"):
        broken.assert_clean()
    for child in made:
        child.acknowledge()


async def test_two_healthy_nested_peers_leave_the_parent_green(tmp_path):
    """Positive nesting control: both children are healthy, so the parent remains clean."""
    made = []
    original = guarded_child.module_command

    def remember(*args, **kwargs):
        result = original(*args, **kwargs)
        made.append(result[2])
        return result

    guarded_child.module_command = remember
    try:
        async with FakeRelay() as relay:
            async with asyncio.timeout(120):
                async with _peer(tmp_path / "a", relay.url) as outer:
                    async with _peer(tmp_path / "b", relay.url) as inner:
                        assert await _address(inner) != await _address(outer)
    finally:
        guarded_child.module_command = original

    assert len(made) >= 2, "nesting did not occur"
    for child in made:
        child.assert_clean()
