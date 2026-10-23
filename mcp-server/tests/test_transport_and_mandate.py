"""Transport (stdio/HTTP) and manual mandates, based on 2026-09-05 integrator findings.

The host platform reaches one MCP gateway over HTTP and may never read the stdio record.
Tools are invoked by an agent rather than a human, so automatic mandate issuance with the
owner key is inappropriate there. These tests verify that both transports start and respond,
and that with `A4A_MANDATE_AUTO=0` a publishing tool returns the exact owner command instead
of silently issuing a mandate.
"""
import asyncio
import json
import contextlib
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import guarded_child
import pytest
from a4a import Agent, Keys

from a4a_mcp import identity, server
from fake_relay import FakeRelay
from tool_call import call_text

MCP_PY = sys.executable  # unguarded-launch: definition, not a launch
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")


async def test_manual_mandate_is_copied_to_added_node_without_owner_key_use(mcp_home, monkeypatch):
    keys = identity.load_or_create_identity()
    owner = identity.load_or_create_owner_identity()
    monkeypatch.setenv("A4A_MANDATE_AUTO", "0")
    async with FakeRelay() as home, FakeRelay() as discovery:
        async with Agent([home.url], keys=keys) as agent:
            original_id = await agent.ensure_registered(owner, "bot")
        original = next(e for e in home.events if e["id"] == original_id)
        monkeypatch.setenv("A4A_RELAY", home.url + "," + discovery.url)
        def forbidden_owner_key():
            raise AssertionError("republishing must not use the owner private key")
        monkeypatch.setattr(server, "load_or_create_owner_identity", forbidden_owner_key)
        async with server._mandated() as agent:
            assert agent.delegation_id == original_id
        assert [e for e in discovery.events if e["kind"] == 31000] == [original]


@pytest.mark.parametrize("negative", ["revoked", "superseded"])
async def test_manual_mandate_reuse_does_not_spread_invalid_authority(mcp_home, monkeypatch, negative):
    from a4a.delegation import create_delegation, create_revocation
    keys = identity.load_or_create_identity()
    owner = identity.load_or_create_owner_identity()
    now = int(time.time())
    mandate = create_delegation(owner, keys.pubkey_hex, "Synthetic", now+86400, created_at=now-10)
    newer = (create_revocation(owner, mandate) if negative == "revoked" else
             create_delegation(owner, keys.pubkey_hex, "Replacement", now+1800, created_at=now-5))
    async with FakeRelay() as home, FakeRelay() as fresh:
        home.events.extend([mandate.model_dump(), newer.model_dump()])
        def forbidden_owner_key():
            raise AssertionError("lookup must not reauthorize with the owner private key")
        monkeypatch.setattr(server, "load_or_create_owner_identity", forbidden_owner_key)
        async with Agent([home.url, fresh.url], keys=keys) as agent:
            before = list(home.events)
            assert await server._find_existing_mandate(agent, republish=True) is None
            assert home.events == before and not fresh.events


def _post(url: str, payload: dict, timeout: float = 10) -> tuple[int, str]:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _spawn(env_extra: dict, args: list[str] | None = None, allow=()) -> subprocess.Popen:  # unguarded-launch: annotation, not a launch
    """Start the real entry point with the test boundary already installed.

    This used to call bare `Popen`: monkeypatches live in the parent process and do not reach
    the child, so the interpreter accessed the network without any boundary and inherited the
    entire poisoned environment. The caller validates the child handshake; silently accepting
    output from an unverified process is forbidden.
    """
    home = env_extra.pop("A4A_HOME", "")
    relay = env_extra.pop("A4A_RELAY", "")
    argv, env, ready = guarded_child.module_command(
        ["-m", "a4a_mcp", *(args or [])], home=home, relay=relay, env=env_extra, allow=allow)
    proc = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=subprocess.PIPE,  # unguarded-launch: argv comes from module_command
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # The boundary needs the child outcome; the caller has already waited for it by assertion time.
    ready.attach(proc)
    # Wait for confirmation HERE instead of handing the secret to the caller. The previous
    # version stored it on the process object, but no caller read it, so broken setup passed
    # silently. A check that can be forgotten must be performed here, not delegated.
    try:
        ready.wait(proc, timeout=30)
    except BaseException:
        proc.kill()
        proc.communicate(timeout=10)
        raise
    return proc


def _build_streamable_app(srv, restore: list):
    """Build the app on BOTH major `mcp` versions using the same approach as the product.

    In 2.x, transport settings are public `streamable_http_app` arguments. In 1.x, they are
    absent there and the same fields live in `mcp.settings`. Checking only that settings exist
    is insufficient: 2.x HAS a settings object, but it lacks the 1.x fields, and assignment
    fails with `ValueError: Settings object has no field stateless_http`. The baseline-version
    run failed exactly this way while this code checked only for `None`.

    The version is detected by exception, not version number: 2.x does not expose one, as
    already documented in `__main__._run_http`.

    Every change is recorded in `restore` for rollback. Mutating the module-level settings
    object survives the test and would otherwise leak into neighboring tests.
    """
    options = {"streamable_http_path": "/mcp", "json_response": True, "stateless_http": True}

    # The session manager is single-use: `run()` is allowed once per instance, so a second
    # startup in the same process fails while launching the app.
    previous_manager = getattr(srv.mcp, "_session_manager", None)
    srv.mcp._session_manager = None
    restore.append(lambda: setattr(srv.mcp, "_session_manager", previous_manager))

    try:
        return srv.mcp.streamable_http_app(**options)                     # mcp 2.x
    except TypeError:
        pass
    settings = getattr(srv.mcp, "settings", None)
    missing = [key for key in options if not hasattr(settings, key)]
    if settings is None or missing:
        raise AssertionError(
            "this `mcp` package accepts transport settings neither as "
            f"`streamable_http_app` arguments nor as settings fields (missing: {missing or 'settings object'})")
    for key, value in options.items():
        previous = getattr(settings, key)
        restore.append(lambda k=key, v=previous: setattr(settings, k, v))
        setattr(settings, key, value)
    return srv.mcp.streamable_http_app()                                  # mcp 1.x


@contextlib.asynccontextmanager
async def _owned_http_app(tmp_path):
    """Run HTTP on a socket bound BY the test and never released for an instant.

    This is the fourth revision; the previous three were rejected for good reason.

    The first proved ownership by port number. A reviewer substituted a dead child and an
    unrelated stub, and the test passed after making four requests to somebody else's service.

    The second proved ownership with the `a4a_my_address` tool response. That is a public app
    request: asking it requires contacting a service not yet established as ours, and the call
    may create identity state in that foreign service.

    The third chose a port in the child and passed a note with a one-time secret. The note was
    genuine, but a window remained between releasing the holder socket and binding the server.
    I claimed the window "degraded to failure." That claim was WRONG, and a reviewer
    demonstrated it live: while the child imports slowly, it remains alive, a foreign process
    already owns the port, the note is genuine, and the parent sends a request to the foreign
    listener. The child dies only AFTER the traffic.

    This construction has no window: the socket is bound in this process and passed into the
    server without ever being released. Readiness uses the server's own state, not a network
    probe.

    Cleanup also covers SETUP failure. This is not future-proofing: on the baseline `mcp`
    version, app configuration genuinely failed and left an address allowed because registration
    occurred before `try`. Every acquired resource is released by the same block as the others.
    """
    import network_guard
    import uvicorn
    from a4a_mcp import server as srv

    holder = port = server = task = None
    restore: list = []
    try:
        holder = socket.socket()
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            holder.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        holder.bind(("127.0.0.1", 0))
        holder.listen(64)
        port = holder.getsockname()[1]
        network_guard.allow("127.0.0.1", port)

        app = _build_streamable_app(srv, restore)
        server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
        task = asyncio.create_task(server.serve(sockets=[holder]))

        for _ in range(600):
            if server.started or task.done():
                break
            await asyncio.sleep(0.05)
        if task.done():
            task.result()
            raise AssertionError("server exited before it began serving")
        assert server.started, "server did not start within the allotted time"
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        if server is not None:
            server.should_exit = True
        if task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=20)
            except BaseException:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        for undo in reversed(restore):
            undo()
        if port is not None:
            network_guard.forget("127.0.0.1", port)
        if holder is not None:
            holder.close()


async def _apost(url: str, payload: dict) -> tuple[int, str]:
    return await asyncio.to_thread(_post, url, payload)


async def test_http_transport_serves_tools_over_one_post(tmp_path, mcp_home):
    """Primary integrator path: one HTTP request without a session or SSE."""
    async with _owned_http_app(tmp_path) as url:
        # Live on 2026-09-04: three independent sessionless POST requests—initialize,
        # tools/list, and tools/call—all returned 200. This is the path for a gateway that
        # retains no session and parses no SSE, so the test requires it rather than "200 or 400".
        status, body = await _apost(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                          "params": {"protocolVersion": "2024-11-05",
                                                     "capabilities": {},
                                                     "clientInfo": {"name": "test", "version": "0"}}})
        assert status == 200 and '"result"' in body and '"a4a"' in body, (status, body[:300])
        status, body = await _apost(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert status == 200 and "a4a_my_address" in body, (status, body[:300])
        status, body = await _apost(url, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                          "params": {"name": "a4a_my_address", "arguments": {}}})
        assert status == 200 and "apub" in body, (status, body[:300])


async def test_the_test_owned_socket_is_released_only_after_the_run(tmp_path, mcp_home):
    """Harness control: the address is allowed for the run and removed afterward.

    Leaving the port in the registry would let the next test contact whoever acquires it after
    us, and that request could appear successful.
    """
    import network_guard

    before = set(network_guard._allowed)
    async with _owned_http_app(tmp_path) as url:
        opened = set(network_guard._allowed) - before
        assert opened, "server address was not registered with the boundary"
    assert set(network_guard._allowed) == before


async def test_setup_failure_leaves_no_address_allowed(tmp_path, monkeypatch):
    """A SETUP failure must not leave an allowed address behind.

    This is not future-proofing: on the baseline `mcp` version, app setup genuinely failed
    (`Settings object has no field stateless_http`), while address registration preceded
    `try`, leaving the port allowed for the rest of the run.
    """
    import network_guard

    def explode(srv, restore):
        raise ValueError("Settings object has no field stateless_http")

    monkeypatch.setattr(sys.modules[__name__], "_build_streamable_app", explode)
    before = set(network_guard._allowed)
    with pytest.raises(ValueError):
        async with _owned_http_app(tmp_path):
            pass
    assert set(network_guard._allowed) == before, (
        "address remained allowed after setup failure")


def _read_lines_within(proc, deadline: float, needle: str) -> str:
    """Read process stderr with a REAL time limit.

    `readline()` blocks until a line arrives and ignores an outer clock check: a loop such as
    `while time.monotonic() < deadline: proc.stderr.readline()` hangs forever when the process
    is silent. A limit that cannot take effect is a comment, not a limit. Reading therefore
    happens in a separate thread, and this function waits on the thread.
    """
    found = []

    def pump():
        for raw in iter(proc.stderr.readline, b""):
            line = raw.decode("utf-8", "replace")
            found.append(line)
            if needle in line:
                return

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    while time.monotonic() < deadline:
        if any(needle in line for line in found):
            return next(line for line in found if needle in line)
        if not reader.is_alive():
            break
        reader.join(timeout=0.2)
    return ""


def test_command_line_reports_the_selected_transport(tmp_path):
    """Validate the real entry point through its OWN channel, not the network.

    The exact claim proved by the line is explicit: it is printed BEFORE server startup, so it
    proves transport SELECTION rather than readiness to listen. This test once claimed both,
    while proving the latter not at all. The neighboring test validates serving readiness on a
    socket that it owns.

    The pipe belongs to us by construction: this test creates it and nobody else can see it.
    An ephemeral port is requested, and no traffic is sent to it.
    """
    proc = _spawn({"A4A_MCP_TRANSPORT": "http", "A4A_MCP_PORT": "0",
                   "A4A_MCP_HOST": "127.0.0.1", "A4A_HOME": str(tmp_path / "home"),
                   "A4A_RELAY": "ws://127.0.0.1:1/never"})
    try:
        line = _read_lines_within(proc, time.monotonic() + 30, "streamable-http")
        assert line, f"entry point did not report transport selection; exit code {proc.poll()}"
    finally:
        proc.terminate()
        proc.wait(timeout=15)


def test_a_silent_live_process_ends_in_refusal_not_in_waiting(tmp_path):
    """A silent live process must time out instead of hanging.

    This is exactly the case the previous pipe reader could not survive: the process is alive,
    no line arrives, and `readline()` waits forever.
    """
    proc = subprocess.Popen(  # unguarded-launch: sleeping stub, not product code
        [MCP_PY, "-c", "import time; time.sleep(120)"],  # unguarded-launch: sleeping stub
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    started = time.monotonic()
    try:
        assert _read_lines_within(proc, started + 2, "streamable-http") == ""
        assert time.monotonic() - started < 20, "reader waited instead of giving up"
    finally:
        proc.kill()
        proc.communicate(timeout=10)


def test_stdio_transport_still_answers_initialize(tmp_path):
    proc = _spawn({"A4A_HOME": str(tmp_path / "home"), "A4A_RELAY": "ws://127.0.0.1:1/never"})
    try:
        req = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                          "clientInfo": {"name": "test", "version": "0"}}}
        proc.stdin.write((json.dumps(req) + "\n").encode())
        proc.stdin.flush()
        line = proc.stdout.readline().decode("utf-8", "replace")
        assert '"result"' in line and "a4a" in line.lower(), line[:300]
    finally:
        proc.terminate()
        proc.wait(timeout=15)


def test_unknown_transport_fails_loudly(tmp_path):
    proc = _spawn({"A4A_MCP_TRANSPORT": "carrier-pigeon", "A4A_HOME": str(tmp_path / "h")})
    out, err = proc.communicate(timeout=30)
    assert proc.returncode != 0
    assert "carrier-pigeon" in err.decode("utf-8", "replace")


@pytest.mark.parametrize("mode", [None, "0", "false", "no", "off", "", "  "])
async def test_manual_mandate_answers_with_the_owner_command(mcp_home, monkeypatch, caplog, mode):
    """With A4A_MANDATE_AUTO=0, publishing names the owner command instead of issuing a mandate."""
    if mode is None:
        monkeypatch.delenv("A4A_MANDATE_AUTO", raising=False)
    else:
        monkeypatch.setenv("A4A_MANDATE_AUTO", mode)
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        for _ in range(2):
            out = await call_text(server.mcp, "a4a_publish_profile",
                                  {"capabilities": ["x"], "category": "development"})
            assert "delegation" in out and "-m a4a_mcp issue-mandate" in out
            assert sys.executable in out  # unguarded-launch: text comparison, not a launch
            assert "A4A_HOME" in out and "A4A_RELAY" in out
            assert "Notify the owner" in out and "Do not repeat" in out
        assert [e["kind"] for e in relay.events] == [], "no events, including a mandate"
        refusals = [r for r in caplog.records if "kind=mandate-missing" in r.message]
        assert len(refusals) == 2, "every refusal is visible rather than suppressed as a duplicate"
        # Read-only tools work without a mandate.
        assert "No agreements" in await call_text(server.mcp, "a4a_get_agreements", {})


async def test_manual_mandate_uses_an_existing_delegation(mcp_home, monkeypatch):
    """A mandate issued by the owner in advance is reused without issuing another."""
    monkeypatch.setenv("A4A_MANDATE_AUTO", "0")
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        keys = identity.load_or_create_identity()
        owner = identity.load_or_create_owner_identity()
        async with Agent([relay.url], keys) as agent:          # issued by the owner in advance
            deleg_id = await agent.ensure_registered(owner, "issued by owner", days=30)
        out = await call_text(server.mcp, "a4a_publish_profile",
                              {"capabilities": ["x"], "category": "development"})
        assert "Profile published" in out
        published = [e for e in relay.events if e["kind"] == 31001]
        assert len(published) == 1
        assert [t[1] for t in published[0]["tags"] if t[0] == "delegation"] == [deleg_id]
        mandates = [e for e in relay.events if e["kind"] == 31000]
        assert mandates and all(e == mandates[0] for e in mandates), "only the exact existing mandate may be republished"
        assert {e["id"] for e in mandates} == {deleg_id}, "no second mandate was issued"


@pytest.mark.parametrize("mode", ["1", "true", "yes", "on", " TRUE "])
async def test_auto_mandate_requires_explicit_opt_in(mcp_home, monkeypatch, mode):
    monkeypatch.setenv("A4A_MANDATE_AUTO", mode)
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        out = await call_text(server.mcp, "a4a_publish_profile",
                              {"capabilities": ["x"], "category": "development"})
    assert "Profile published" in out
    mandates = [e for e in relay.events if e["kind"] == 31000]
    assert mandates and all(e == mandates[0] for e in mandates)
    assert len([e for e in relay.events if e["kind"] == 31001]) == 1
    assert {e["kind"] for e in relay.events} == {31000, 31001}


@pytest.mark.parametrize("mode", ["flase", "enabled", "2"])
def test_unknown_mandate_mode_fails_closed(monkeypatch, mode):
    monkeypatch.setenv("A4A_MANDATE_AUTO", mode)
    with pytest.raises(ValueError, match="A4A_MANDATE_AUTO"):
        server._mandate_auto()


@pytest.mark.parametrize("reason", ["delegation revoked by its owner", "delegation required",
                                   "delegation not found", "expired delegation"])
def test_delegation_refusal_never_promises_silent_renewal(monkeypatch, reason):
    from a4a.relay import RelayError
    monkeypatch.delenv("A4A_MANDATE_AUTO", raising=False)
    out = server._explain_relay_refusal(RelayError(reason))
    assert reason in out and "owner" in out and "Do not repeat" in out
    assert "will issue" not in out


def test_issue_mandate_command_publishes_one_delegation(tmp_path):
    """`python -m a4a_mcp issue-mandate` is the exact command named in the refusal."""
    async def run_relay():
        async with FakeRelay() as relay:
            # This fixture started the node, so its address must be ALLOWED for the child.
            # Previously the child reached the network without a boundary, leaving nothing to allow.
            port = int(relay.url.rsplit(":", 1)[1])
            proc = _spawn({"A4A_HOME": str(tmp_path / "home"), "A4A_RELAY": relay.url,
                           "A4A_MANDATE_DAYS": "7"}, ["issue-mandate"],
                          allow=[("127.0.0.1", port)])
            out, err = await asyncio.get_running_loop().run_in_executor(
                None, lambda: proc.communicate(timeout=60))
            return out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), list(relay.events)
    out, err, events = asyncio.run(run_relay())
    assert "Mandate issued" in out and "7 days" in out, out + err
    assert [e["kind"] for e in events] == [31000]


def test_server_instructions_rank_the_tools_and_name_only_real_ones():
    """The model uses tools in the order it is given.

    Integrator finding from 2026-09-05: 25 of 30 skills went unused because nothing defined
    their invocation order. The server description therefore gives a path from request to
    review; this guard keeps it nonempty and prevents it from naming nonexistent tools.
    """
    import re
    text = server.mcp.instructions or ""
    named = set(re.findall(r"a4a_\w+", text))
    real = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert named - real == set(), f"instructions name nonexistent tools: {named - real}"
    for must in ("a4a_publish_intent", "a4a_get_offers", "a4a_make_agreement",
                 "a4a_cosign_agreement", "a4a_send_task", "a4a_publish_review",
                 "a4a_check_authority", "a4a_encrypt_file"):
        assert must in named, f"{must} is absent from the path, so the model will not know when to call it"
    assert "NEW ID" in text, "the instructions do not say that countersigning changes the deal ID"
    assert "untrusted input" in text


def test_server_reports_its_version_on_both_mcp_majors():
    """`initialize` must name the build version so a foreign cluster can report it.

    When investigating a mismatch, the first integrator question is "which build is deployed?"
    The only answer visible to the host is `serverInfo.version`; an empty value left no answer.

    This check supports both major `mcp` versions: in 1.x the field lives on an internal object,
    while in 2.x it is a read-only property set by the constructor. The first patch handled only
    the 1.x path and broke package import entirely on 2.x—exactly the clean-environment install
    where a newcomer gets the latest major version.
    """
    from a4a_mcp import server

    version = getattr(server.mcp, "version", None)
    if not version:
        inner = getattr(server.mcp, "_mcp_server", None)
        version = getattr(inner, "version", None)
    assert version, "server does not report its version in initialize"
    assert version[0].isdigit(), f"value does not resemble a version: {version!r}"


# ── Command-line path controls ────────────────────────────────────────────────
# The HTTP server harness no longer needs fake-child controls: it starts no child and never
# releases the port, so there is nothing to substitute. Controls for the former harness (dead
# child, foreign note, startup failure, and silent live child) disappeared with it. This is not
# lost coverage; the behavior being covered no longer exists. Command-line startup controls
# remain because that path is observed through its own channel.


def test_command_line_start_fails_loudly_when_the_process_dies(tmp_path):
    """Startup death is a loud failure, not an empty wait for a line.

    A deliberately invalid transport forces the process to die. The harness must notice instead
    of waiting for a message that will never arrive.
    """
    proc = _spawn({"A4A_MCP_TRANSPORT": "does-not-exist", "A4A_HOME": str(tmp_path / "home"),
                   "A4A_RELAY": "ws://127.0.0.1:1/never"})
    try:
        assert proc.wait(timeout=30) != 0, "an invalid transport must not start"
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=10)
