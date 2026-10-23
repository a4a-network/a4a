"""Network boundary for the notary test suite.

The suite originally had no boundary even though the notary naturally talks to public
OpenTimestamps calendars. It could silently contact a third-party calendar and pass
because that service worked, or fail because the service was unavailable. External
state is the worst possible dependency for a suite deciding whether timestamps are
valid.

This suite shares `sdk-python/tests/network_guard.py` with the other suites rather than
creating a third implementation. Two copies had already diverged and allowed async
connections through.
"""
import sys
from pathlib import Path

_SDK_TESTS = Path(__file__).resolve().parents[2] / "sdk-python" / "tests"
if str(_SDK_TESTS) not in sys.path:
    sys.path.insert(0, str(_SDK_TESTS))

import ambient  # noqa: E402 - must follow the path insertion

# Sanitize first, before importing product code. Some values are read at import time
# (`identity.IDENTITY_DIR` is derived from `A4A_HOME` once), so removing an environment
# variable afterward is too late. See `ambient` for details and scope.
_REMOVED_AMBIENT = ambient.sanitize()

import pytest  # noqa: E402

import guarded_child  # noqa: E402 - must follow the path insertion
import network_guard  # noqa: E402 - must follow the path insertion

# Install before collection and product imports so import-time connections cannot escape.
network_guard.install()

# Canonical unreachable endpoints use ws://127.0.0.1:1 and neighboring low ports.
# Declare them explicitly unreachable in every suite. When this exception existed only
# in the SDK suite, identical addresses elsewhere looked like violations; unguarded
# child processes made the discrepancy invisible.
for _dead_port in (1, 2, 9):
    network_guard.unreachable("127.0.0.1", _dead_port)


LOCAL_HISTORY_RELAY = "ws://127.0.0.1:8080"


def pytest_addoption(parser):
    parser.addoption(
        "--local-history-check", action="store_true", default=False,
        help="explicit consent for the safety runner's disposable relay namespace")
    parser.addoption(
        "--local-history-relay", default=LOCAL_HISTORY_RELAY, choices=[LOCAL_HISTORY_RELAY],
        help="the relay endpoint inside that runner-owned container namespace")


@pytest.fixture
def local_history_relay(request):
    if not request.config.getoption("--local-history-check"):
        pytest.skip("local history requires the disposable safety runner and --local-history-check")
    # The runner starts and checks this relay before sharing its container network
    # namespace. A loopback listener alone never opts the test in.
    url = request.config.getoption("--local-history-relay")
    network_guard.allow("127.0.0.1", 8080)
    try:
        yield url
    finally:
        network_guard.forget("127.0.0.1", 8080)



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
        "The notary suite attempted to reach addresses outside its fixtures. "
        "OpenTimestamps calendars are third-party services; contacting them makes "
        "the test result depend on external state.")
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
