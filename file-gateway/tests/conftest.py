"""Network boundary for the file-gateway suite.

The gateway's only legitimate network peer is its configured S3 endpoint. Tests
use an in-process stand-in, so any real connection is a failure even when product
code catches it.
"""
import sys
from pathlib import Path

_SDK_TESTS = Path(__file__).resolve().parents[2] / "sdk-python" / "tests"
if str(_SDK_TESTS) not in sys.path:
    sys.path.insert(0, str(_SDK_TESTS))

import ambient  # noqa: E402 - must follow the path insertion

_REMOVED_AMBIENT = ambient.sanitize()

import pytest  # noqa: E402

import guarded_child  # noqa: E402 - must follow the path insertion
import network_guard  # noqa: E402 - must follow the path insertion

network_guard.install()

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
        "The file-gateway suite attempted to reach addresses outside its fixtures.")
    for host, port in sorted(set(attempts)):
        terminalreporter.line(f"  {host}:{port}")


@pytest.fixture(autouse=True)
def _guarded_children_stayed_inside():
    yield
    guarded_child.assert_all_clean()
