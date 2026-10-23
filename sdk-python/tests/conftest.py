"""Test-run boundaries: reachable destinations and explicit consent.

Two controls preserve the honesty of test results.

**Integration tests require explicit consent, not inference.** The `integration`
marker existed in `pyproject.toml` without enforcement, so thirteen tests failed with
`ConnectionRefusedError` when no live relay was present. Familiar noise to maintainers
looks like thirteen red failures and a broken project to outsiders, instead of the
honest statement that a live relay is required. The first fix PROBED the port to infer
availability. The network boundary correctly treated that probe as a violation: a
listener is not consent to test it and may be an unrelated service that reused the
port. Integration tests now require `--integration`.

**Install the network boundary before collection and product imports.** Otherwise a
connection made at import time would bypass it. `network_guard` documents both the
mechanism and its scope.
"""
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest

# The tests directory is not yet on the import path when pytest loads conftest.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ambient  # noqa: E402 - only after adding the path

# Sanitize FIRST and before product imports. Some values are read during import
# (`identity.IDENTITY_DIR` is derived from `A4A_HOME` once), so removing a variable
# afterwards changes nothing. See `ambient` for details and scope.
_REMOVED_AMBIENT = ambient.sanitize()

import guarded_child  # noqa: E402 - only after adding the path
import network_guard  # noqa: E402 - only after adding the path

# Install the boundary BEFORE collection and product imports so import-time
# connections cannot bypass it.
network_guard.install()

# The suite's canonical non-responsive endpoint, ws://127.0.0.1:1 and adjacent low
# ports, appears in 19 files. Declare them unreachable explicitly. Previously tests
# relied on nobody listening there. That happens to be true on our machine, but if
# another service claimed a port, dozens of tests would silently talk to it as though
# it were our relay.
for _dead_port in (1, 2, 9):
    network_guard.unreachable("127.0.0.1", _dead_port)

#: Integration-test endpoint matching `docker compose up -d`.
INTEGRATION_RELAY = "ws://localhost:8080"


def pytest_addoption(parser):
    parser.addoption("--integration", action="store_true", default=False,
                     help=f"run integration tests against {INTEGRATION_RELAY}; "
                          f"this is EXPLICIT consent to test the service already running there")


def pytest_collection_modifyitems(config, items):
    """Run integration tests only with explicit consent.

    The first version inferred consent through a PROBE: connect to the port and run
    tests if something answered. The network boundary correctly flagged the probe.
    A listener is not consent to test it; it may be an unrelated service that reused
    the port, and we would send it events while treating it as ours.

    Use a flag instead of inference. Without it, skip; with it, register the endpoint
    as an intentional destination.
    """
    if not config.getoption("--integration"):
        skip = pytest.mark.skip(reason=(
            f"integration tests require a live relay at {INTEGRATION_RELAY} and "
            f"EXPLICIT consent: run `docker compose up -d` and add `--integration`. "
            f"This is not a product failure."))
        for item in items:
            if item.get_closest_marker("integration"):
                item.add_marker(skip)
        return
    parts = urlsplit(INTEGRATION_RELAY)
    port = parts.port or (443 if parts.scheme == "wss" else 80)
    for host in {parts.hostname or "localhost", "127.0.0.1", "::1"}:
        network_guard.allow(host, port)


def pytest_sessionfinish(session, exitstatus):
    """Fail the run if anything attempted to cross the network boundary.

    Failure is mandatory EVEN when the test itself passed. Product code may catch a
    denial and continue, making a green run mean "we attempted external access but
    did not mind." The attempt still must be visible.

    Expected attempts inside negative `network_guard.expect_blocked` checks do not
    appear here because denial is their explicit subject.
    """
    attempts = network_guard.unexpected()
    if not attempts:
        return
    session.exitstatus = 1


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if _REMOVED_AMBIENT:
        terminalreporter.section("AMBIENT SETTINGS REMOVED", bold=True)
        terminalreporter.line(
            "The run proceeded WITHOUT these environment values. They change the "
            "destination or storage and must not silently affect results:")
        for name in sorted(_REMOVED_AMBIENT):
            terminalreporter.line(f"  {name}")

    """Report boundary violations in the NORMAL summary, not as an exception.

    This used to raise `pytest.UsageError`. It failed the run but interrupted terminal
    reporting: failed-test details never appeared, so twenty failures looked like one
    boundary line. A guard that hides what it protects is worse than no guard.
    """
    attempts = network_guard.unexpected()
    if not attempts:
        return
    terminalreporter.section("NETWORK BOUNDARY", red=True, bold=True)
    terminalreporter.line(
        "The run attempted endpoints outside those created by its fixtures. Only "
        "fixture-owned endpoints are allowed. If an address is intentional, create "
        "it through a fixture or declare the attempt with network_guard.expect_blocked.")
    for host, port in sorted(set(attempts)):
        terminalreporter.line(f"  {host}:{port}")


@pytest.fixture(autouse=True)
def _guarded_children_stayed_inside():
    """Automatically verify that no launched child crossed the boundary.

    Review showed that callers forget checks assigned to them: a stdio child had exit
    code 4 and a violation record while the parent test stayed green because the stdio
    client did not raise on a nonzero code. Enforce the boundary during every test's
    teardown rather than relying on author memory.
    """
    yield
    guarded_child.assert_all_clean()
