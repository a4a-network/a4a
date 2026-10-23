"""Probe module for child-process launch tests; this is not product code.

It tests the launch wrapper without depending on whether a tool server is installed.
It does exactly what `PROBE_ACTION` requests and nothing more: writes a marker, attempts
a connection, or exits with the requested status.
"""
import os
import socket
import sys


def main() -> None:
    action = os.environ.get("PROBE_ACTION", "mark")
    marker = os.environ.get("PROBE_MARKER")
    if marker:
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("body executed")

    # Corrupting the audit write is the exact probe that broke the first revision in
    # review: a denial occurs but cannot be recorded. Break it AFTER setup so auditing
    # starts successfully and the test covers a mid-run failure rather than startup.
    broken = os.environ.get("PROBE_BREAK_AUDIT")
    if broken == "error":
        def _refuse(fd, data):
            raise OSError("audit write refused")
        os.write = _refuse
    elif broken == "zero":
        os.write = lambda fd, data: 0

    if action == "connect":
        # Catch the denial deliberately to verify that a denial handled by product code
        # still appears in the child's outcome instead of remaining private to it.
        try:
            socket.socket().connect((os.environ["PROBE_HOST"], int(os.environ["PROBE_PORT"])))
            print("PROBE connected")
        except Exception as error:
            print("PROBE caught " + type(error).__name__)
    if os.environ.get("PROBE_HOLD"):
        # Stay alive so the parent can terminate us forcibly. Exit-time reporting is
        # lost on forced termination, but a record written at denial time survives.
        import time
        time.sleep(120)

    if action == "exit":
        sys.exit(int(os.environ.get("PROBE_CODE", "0")))
    else:
        print("PROBE done")


if __name__ == "__main__":
    main()
