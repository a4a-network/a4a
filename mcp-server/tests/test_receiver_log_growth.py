"""Prevent polling from growing a long-lived receiver log (2026-09-08).

Observed locally, `receiver-codex.stderr.log` grew to 1.1 MiB in 17 hours: every poll
wrote `HTTP Request: GET .../v1/inbox?recipient=<key>&after=...`, and the handler wrapped
each entry over several lines (1,745 requests became 13,960 lines). That is roughly
1.5 MiB per day on an empty channel with no rotation, or 45 MiB per month until disk
exhaustion makes the issue visible.

This is a second-day defect because the first hour looks fine. The test therefore
checks logger configuration directly instead of inspecting a file by eye. It also
stops writing the recipient address and cursor in clear text on every poll. They are
not local secrets, but there is no reason to retain them.

Use WARNING rather than disabling logging so transport failures remain visible.

SCOPE, clarified in review on 2026-09-09: this reduces volume on a healthy channel. It
does not cap file size. During prolonged relay unavailability, a WARNING per attempt
still grows indefinitely. Rotation is separate work and these tests do not cover it.
"""
import logging

from a4a_mcp.__main__ import _quiet_poll_logs

NOISY = ("httpx", "httpcore")


def test_polling_libraries_are_quieted_to_warning():
    for name in NOISY:
        logging.getLogger(name).setLevel(logging.INFO)
    _quiet_poll_logs()
    for name in NOISY:
        assert logging.getLogger(name).level == logging.WARNING, \
            f"{name} will continue writing one line per poll"


def test_errors_still_pass(caplog):
    """Quieter must not mean silent; transport errors still need to surface."""
    _quiet_poll_logs()
    logger = logging.getLogger("httpx")
    with caplog.at_level(logging.WARNING, logger="httpx"):
        logger.info("HTTP Request: GET /v1/inbox?recipient=deadbeef")
        logger.warning("connection refused")
    assert "connection refused" in caplog.text
    assert "recipient=deadbeef" not in caplog.text


def test_quieting_does_not_touch_the_root_logger():
    """Quiet only named libraries; the root logger belongs to the host."""
    root = logging.getLogger()
    before = root.level
    _quiet_poll_logs()
    assert root.level == before
