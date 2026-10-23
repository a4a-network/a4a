"""Shared MCP server test harness.

`FakeRelay` lives in the SDK tests and is reused here unchanged. Starting a real relay to test
thin wrappers is unnecessary, while mocking `Agent` would test the mock instead of the code.
Import the file as a module rather than a package: both the SDK and this project have `tests`
directories, which would collide as package names.
"""
import sys
from pathlib import Path

_SDK_TESTS = Path(__file__).resolve().parents[2] / "sdk-python" / "tests"
if str(_SDK_TESTS) not in sys.path:
    sys.path.insert(0, str(_SDK_TESTS))

# Use the same network boundary as the SDK and install it here as well: the server tool suite
# runs separately and would otherwise have no boundary at all. Install it BEFORE collection
# and product import so a connection made during import cannot bypass it.
import ambient  # noqa: E402 — only after inserting the path

# Sanitize FIRST and before product import: some values are read at import time
# (`identity.IDENTITY_DIR` is computed from `A4A_HOME` once), so removing the variable later
# changes nothing. See `ambient` for details and boundaries.
_REMOVED_AMBIENT = ambient.sanitize()

import guarded_child  # noqa: E402 — only after inserting the path
import network_guard  # noqa: E402 — only after inserting the path

network_guard.install()

# Canonical non-responsive suite endpoint: ws://127.0.0.1:1 and neighboring low ports appear
# where a connection must be impossible. Explicitly mark them unreachable in EVERY suite, not
# just one. While the declaration existed only in the SDK, the same addresses looked like
# violations elsewhere; nothing exposed this because only unguarded child processes tried them.
for _dead_port in (1, 2, 9):
    network_guard.unreachable("127.0.0.1", _dead_port)



# Gate positive tests for optional adapters.
#
# Two adapters are verified against exact transport versions and refuse to run on others. Base
# dependencies intentionally use broad ranges, so an ordinary install gets recent versions and
# tests requiring a WORKING adapter have nothing to observe. Without gating, an outsider sees
# 32 failures from unused capabilities and concludes that the package is broken.
#
# ONLY positive checks are skipped. Tests guarding version refusal itself always run: they
# replace the version and do not need a working adapter. Otherwise gating would erase the proof
# that the protection exists.
import importlib.metadata

import pytest

#: Versions against which the adapters are verified. These match the `channel` and
#: `host-signal` installation profiles in pyproject.toml. A mismatch would mean that a profile
#: installed exactly as documented still skips its own tests.
_CHANNEL_VERSIONS = ("1.28.1", "2.1.1")
_SIGNAL_VERSION = "13.1"


def _installed(package):
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


def pytest_collection_modifyitems(config, items):
    mcp_version = _installed("mcp")
    ws_version = _installed("websockets")
    gates = {
        "requires_channel": (
            mcp_version in _CHANNEL_VERSIONS,
            f"installation profile `channel` required (mcp {' or '.join(_CHANNEL_VERSIONS)}); "
            f"installed: {mcp_version}. This is an unavailable capability, not a failure: "
            f"the adapter deliberately refuses unverified versions."),
        "requires_host_signal": (
            ws_version == _SIGNAL_VERSION,
            f"installation profile `host-signal` required (websockets {_SIGNAL_VERSION}); "
            f"installed: {ws_version}. This is an unavailable capability, not a failure."),
    }
    for name, (available, reason) in gates.items():
        if available:
            continue
        skip = pytest.mark.skip(reason=reason)
        for item in items:
            if item.get_closest_marker(name):
                item.add_marker(skip)


def pytest_sessionfinish(session, exitstatus):
    """Same obligation as the SDK: crossing the boundary fails the run.

    This is duplicated rather than inherited because the suites run separately and one
    conftest does not participate in another suite's run.
    """
    attempts = network_guard.unexpected()
    if not attempts:
        return
    session.exitstatus = 1


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if _REMOVED_AMBIENT:
        terminalreporter.section("EXTERNAL SETTINGS REMOVED", bold=True)
        terminalreporter.line(
            "The run proceeded WITHOUT these environment values because they change the "
            "destination or storage and must not silently affect the result:")
        for name in sorted(_REMOVED_AMBIENT):
            terminalreporter.line(f"  {name}")

    """Report boundary violations in a separate NORMAL summary section, not an exception.

    This used to raise `pytest.UsageError`. It did fail the run, but also truncated the terminal
    report: the failed-test list never appeared, making a run with twenty failures look like one
    boundary line. A guard that hides what it guards is worse than no guard.
    """
    attempts = network_guard.unexpected()
    if not attempts:
        return
    terminalreporter.section("NETWORK BOUNDARY", red=True, bold=True)
    terminalreporter.line(
        "The run reached beyond endpoints started by its fixtures. Only those endpoints are "
        "allowed. If an address is intentionally needed, start it from a fixture or mark the "
        "attempt as expected with network_guard.expect_blocked.")
    for host, port in sorted(set(attempts)):
        terminalreporter.line(f"  {host}:{port}")


@pytest.fixture(autouse=True)
def _guarded_children_stayed_inside():
    """Automatically verify that no launched child crossed the boundary.

    A reviewer showed that callers forget checks delegated to them: an stdio child exited 4
    and recorded a violation while the parent test stayed green because the stdio client does
    not raise on nonzero exit. The boundary therefore lives here, at every test teardown, not
    in the author's memory.
    """
    yield
    guarded_child.assert_all_clean()
