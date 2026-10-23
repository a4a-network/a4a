"""The disposable-relay address must reach the pilot test without disarming the guard.

`scripts/local-relay-safety-check.py` starts a throwaway relay, waits for `/v1/health`,
and then runs ONE test against it:
`test_private_pilot.py::test_private_pilot_on_disposable_relay`. The address travels in
`A4A_LOCAL_PRIVATE_PILOT_RELAY`, which `ambient.sanitize()` keeps as a harness-owned name
while still removing every other `A4A_*` value.

Before the guard kept that one name, the pilot skipped, pytest printed
"EXTERNAL SETTINGS REMOVED: A4A_LOCAL_PRIVATE_PILOT_RELAY", and the runner failed with
"private pilot requires one executed passing test". `test_the_address_reaches_the_node`
fails on that behavior: it runs the real node in a child interpreter and requires a
clean PASSED result, not a skip - and not a pass whose session died at the test
boundary, which is what a supplied address that is never declared looks like. The other
tests cover the rest of the contract: the guard gained no exemption list, and a
harness-owned value still never reaches a child process.

Each case runs the node the way the runner does, so what is proved here is the runner's
own invocation and not a convenient variant. The child is awaited rather than blocked on:
a relay owned by this test must keep serving while that child connects to it.
"""
import asyncio
import os
import sys
from pathlib import Path

import ambient
from fake_relay import FakeRelay


ROOT = Path(__file__).resolve().parents[2]
MCP_SERVER = ROOT / "mcp-server"
PILOT_NODE = "tests/test_private_pilot.py::test_private_pilot_on_disposable_relay"
# The name is owned by `ambient`, which decides to keep it; spelling it again here would
# let the guard and this check drift apart.
PILOT_RELAY_ENV = ambient.PRIVATE_PILOT_RELAY


async def _pilot_run(ambient_values: dict[str, str] | None = None) -> tuple[int, str, str]:
    """Run the real pilot node in a child interpreter; return `(returncode, stdout, stderr)`.

    `A4A_*` and `PYTEST_*` variables are dropped from the inherited environment, so every
    case states its outside settings explicitly instead of inheriting this process's. The
    command mirrors the runner's: an isolated interpreter, no ambient toolkit autoload,
    one node.
    """
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(("A4A_", "PYTEST_"))}
    environment.update(ambient_values or {})
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [sys.executable, "-X", "utf8", "-B", "-m", "pytest", "-q", "-o",
               "addopts=", "-p", "no:cacheprovider", PILOT_NODE]
    # The child is itself a pytest run: its own conftest installs the boundary before any
    # product import, so wrapping it here would test the wrapper, not the runner's call.
    process = await asyncio.create_subprocess_exec(  # unguarded-launch: see note above
        *command, cwd=MCP_SERVER, env=environment, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
    return (process.returncode, stdout.decode("utf-8", "replace"),
            stderr.decode("utf-8", "replace"))


async def test_the_address_reaches_the_node():
    """The runner's own invocation must end in a PASSED pilot, with a clean boundary.

    The node is a relay this test binds, so the child completes a real rehearsal. The pass
    is required to be a clean one: a child whose test passed and whose SESSION then failed
    at the boundary exits non-zero, and asserting only on the word "passed" would hide a
    pilot that never really reached the node.
    """
    async with FakeRelay() as relay:
        code, stdout, stderr = await _pilot_run({PILOT_RELAY_ENV: relay.url})
    assert code == 0, stdout + stderr
    assert "1 passed" in stdout, stdout + stderr
    assert "NETWORK BOUNDARY" not in stdout, stdout + stderr
    assert "skipped" not in stdout, stdout + stderr


async def test_the_node_is_skipped_when_no_runner_supplied_an_address():
    """Without a runner there is no node, and a skip is the honest result."""
    code, stdout, stderr = await _pilot_run()
    assert code == 0, stdout + stderr
    assert "1 skipped" in stdout, stdout + stderr


async def test_only_the_harness_owned_name_survives_the_guard():
    """Negative control: the guard keeps ONE name and still removes the rest.

    Both the pilot address and ordinary product settings are supplied. The address must be
    delivered - the node runs and refuses a non-loopback address instead of skipping - while
    `A4A_RELAY`, `A4A_HOME` and `A4A_AGENT_HOME` must be reported as removed, exactly as
    before. A growing exemption list would show up here as a missing reported line.
    """
    code, stdout, stderr = await _pilot_run({
        PILOT_RELAY_ENV: "wss://relay.example.invalid",
        "A4A_RELAY": "wss://relay.example.invalid",
        "A4A_HOME": str(ROOT / "home-that-must-not-be-used"),
        "A4A_AGENT_HOME": str(ROOT / "agent-home-that-must-not-be-used"),
    })
    assert "EXTERNAL SETTINGS REMOVED" in stdout, stdout + stderr
    for name in ("A4A_RELAY", "A4A_HOME", "A4A_AGENT_HOME"):
        assert f"\n  {name}" in stdout, stdout + stderr
    reported = stdout.split("EXTERNAL SETTINGS REMOVED", 1)[1]
    assert PILOT_RELAY_ENV not in reported, stdout + stderr
    assert "skipped" not in stdout, stdout + stderr
    assert "private pilot requires an explicit" in stdout, stdout + stderr
