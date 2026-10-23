"""Reuse shared SDK test helpers and the suite boundary instead of copying them.

`FakeRelay` lives in the SDK tests and now registers its port with the shared network
boundary. This suite previously added only the SDK package directory to its import path,
not the tests directory, so full collection failed with
`ModuleNotFoundError: network_guard`. SDK and MCP runs could not reveal the problem
because their collection paths differ.

The rule encoded here is that changing a shared test module affects every suite that
reuses it, not only the suite that motivated the change. Four suites reuse this code.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for path in (_ROOT / "sdk-python", _ROOT / "sdk-python" / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import ambient  # noqa: E402 - must follow the path insertion

# Sanitize first, before importing product code. Some values are read at import time
# (`identity.IDENTITY_DIR` is derived from `A4A_HOME` once), so removing an environment
# variable afterward is too late. See `ambient` for details and scope.
_REMOVED_AMBIENT = ambient.sanitize()

import pytest  # noqa: E402

import guarded_child  # noqa: E402 - must follow the path insertion
import network_guard  # noqa: E402 - must follow the path insertion

# Install before collection and product imports.
network_guard.install()

# Canonical unreachable endpoints use ws://127.0.0.1:1 and neighboring low ports.
# Declare them explicitly unreachable in every suite. When this exception existed only
# in the SDK suite, identical addresses elsewhere looked like violations; unguarded
# child processes made the discrepancy invisible.
for _dead_port in (1, 2, 9):
    network_guard.unreachable("127.0.0.1", _dead_port)



def pytest_sessionfinish(session, exitstatus):
    if network_guard.unexpected():
        session.exitstatus = 1


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if _REMOVED_AMBIENT:
        terminalreporter.section("AMBIENT SETTINGS REMOVED", bold=True)
        terminalreporter.line(
            "The suite ran without these environment values because they change the "
            "destination or storage and must not silently influence results:")
        for name in sorted(_REMOVED_AMBIENT):
            terminalreporter.line(f"  {name}")

    attempts = network_guard.unexpected()
    if not attempts:
        return
    terminalreporter.section("NETWORK BOUNDARY", red=True, bold=True)
    terminalreporter.line(
        "The suite attempted to reach addresses outside its fixtures. Only fixture "
        "addresses are allowed; if an address is intentional, provide it through a "
        "fixture or mark the blocked attempt with network_guard.expect_blocked.")
    for host, port in sorted(set(attempts)):
        terminalreporter.line(f"  {host}:{port}")


@pytest.fixture(autouse=True)
def _guarded_children_stayed_inside():
    """Automatically verify that spawned child processes stayed inside the boundary.

    A reviewer showed that callers forget checks assigned to them: a stdio child could
    exit with code 4 and record a violation while the parent test stayed green because
    the stdio client did not surface the nonzero status. The boundary therefore runs
    automatically at each test teardown rather than relying on author memory.
    """
    yield
    guarded_child.assert_all_clean()
