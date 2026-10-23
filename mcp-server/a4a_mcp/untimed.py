"""Network rule 1 for free text: a count in a letter should say when it was taken.

"50 letters" read an hour later as "55" made a false discrepancy on 26.09.2026. Tools
enforce the rule by tests; for free text only the recipient can see a violation, in its
own mailbox, so this module gives it a heuristic count. It flags, it never refuses.
The heuristic is documented in docs/integration/network-rules.md, rule 1.
"""
from __future__ import annotations

import re

_FRAME_START = "[UNTRUSTED DATA FROM THE A4A NETWORK"
_FRAME_END = "[END OF UNTRUSTED DATA]"

#: A taken-at mark anywhere in the letter makes its counts timed.
_MOMENT = re.compile(
    '\u0441\u043d\u044f\u0442\u043e\\s+\\d{1,2}\\.\\d{2}'                      # Russian taken-at label followed by a date
    '|(?<![\\w])\u043d\u0430\\s+(?:\\d{1,2}\\.\\d{2}(?:\\.\\d{4})?\\s+)?\\d{1,2}:\\d{2}'   # Russian as-of label, with optional date
    r"|\bas_of\b|\bchecked_at\b"                  # tool output
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}",             # ISO time
    re.IGNORECASE)

#: What looks like a number but is not a count: ids, keys, dates, times, versions.
_NOT_COUNTS = re.compile(
    r"\b[0-9a-f]*[a-f][0-9a-f]*\b"                # hex ids with at least one letter
    r"|\b[0-9a-f]{16,}\b"                         # long hex ids even without letters
    r"|\d{4}-\d{2}-\d{2}(?:T[\d:.]+)?"            # ISO dates
    r"|\b\d{1,2}\.\d{2}(?:\.\d{2,4})?\b"          # 26.09, 26.09.2026
    r"|\b\d{1,2}:\d{2}(?::\d{2})?\b"              # 07:20
    r"|\b\d+(?:\.\d+){2,}\b"                       # versions 2.0.934
    # Measured on a live mailbox 26.09.2026: 80 of 100 letters flagged, mostly by these.
    r"|^\s*\d+[.)](?=\s)"                         # list markers «1. …»
    r"|\(\d+\)"                                   # enumerations «(1)»
    r"|\b\d+\s+(?:passed|failed|skipped|errors?|deselected)\b"  # test results: tied to a commit
    r"|\bSHA-\d+\b|\bNIP-\d+\b|\bkind[- ]?\d+\b"   # algorithm and protocol names
    '|\\b\\d[\\d,]*\\s*(?:bytes|\u0431\u0430\u0439\u0442|KB|MB|GB|\u041a\u0411|\u041c\u0411|\u0413\u0411|KiB|MiB)\\b'  # sizes: tied to content
    # Measured on three mailboxes 26.09.2026 (65-90% flagged): thresholds and durations
    # are constants, not measurements that go stale.
    '|\\b\\d+\\s*(?:\u0441\u0435\u043a\\w*|\u043c\u0438\u043d\\w*|\u0447\u0430\u0441\\w*|\u0447|\u0441\u0443\u0442\\w*|\u0434\u043d\\w*|\u0434\u043d\u044f|\u043d\u0435\u0434\u0435\u043b\\w*|\u043c\u0435\u0441\\w*|s|sec\\w*|min\\w*|h|hours?|days?|weeks?)\\b'
    r"|=\s*\d+(?:\.\d+)?"                          # assignments «k = 5»
    r"|№\s*\d+",                                   # numbers of things «№34»
    re.IGNORECASE | re.MULTILINE)

_NUMBER = re.compile(r"\b\d+\b")


def _body(text: str) -> str:
    return "\n".join(line for line in text.splitlines()
                     if not line.startswith(_FRAME_START) and line != _FRAME_END)


# Recognize Russian taken-at, as-of and sending-time labels (27.09, letter 278).
# The sending-time phrase is a mark too, the approximation word may precede the time, and UTC
# is converted instead of being read as local time. Seconds may follow the minutes (27.09, letter
# 302: "07:12:30 UTC" hid its UTC suffix and a three-hour lead showed as six minutes).
_STATED = re.compile('(?:\u0441\u043d\u044f\u0442\u043e|\u043d\u0430|\u0432\u0440\u0435\u043c\u044f \u043e\u0442\u043f\u0440\u0430\u0432\u043a\u0438\\s*[\u2014\u2013-]?)\\s+(?:\u043e\u043a\u043e\u043b\u043e\\s+)?'
                     '(?:(\\d{1,2})\\.(\\d{2})(?:\\.(\\d{4}))?\\s+)?(?:\u043e\u043a\u043e\u043b\u043e\\s+)?(\\d{1,2}):(\\d{2})(?::\\d{2})?(\\s*UTC)?',
                     re.IGNORECASE)


def stated_minus_sent(text: str, signed_at: float) -> int | None:
    """Minutes between the header's stated taken-at mark and the letter's own signed send time.

    The truth of a time in free text cannot be checked against the text, but it can against
    the envelope (representative, 26.09): a positive value is a stamp LATER than the letter
    itself; hours apart is the "23:53 of the wrong day" class. None when there is no mark.
    Times are local to the host environment."""
    import datetime
    # Only the letter's own header counts (27.09, letter 306): a forwarded quote below carries
    # someone else's mark. Header = first three non-empty lines after the declared-length line.
    # No length line - no header - no own mark (letter 310): by form, not by position.
    lines = [line for line in _body(text).splitlines() if line.strip()]
    if not lines or not lines[0].startswith('[\u043d\u0438\u0436\u0435 '):
        return None
    found = _STATED.search("\n".join(lines[1:4]))
    if found is None:
        return None
    day, month, year, hour, minute, utc = found.groups()
    # A UTC mark is compared with the signing time in UTC; any other mark in local time.
    sent = (datetime.datetime.fromtimestamp(signed_at, datetime.timezone.utc).replace(tzinfo=None)
            if utc else datetime.datetime.fromtimestamp(signed_at))
    try:
        stated = sent.replace(year=int(year) if year else sent.year,
                              month=int(month) if month else sent.month,
                              day=int(day) if day else sent.day,
                              hour=int(hour), minute=int(minute), second=0, microsecond=0)
    except ValueError:
        return None
    return int((stated - sent.replace(second=0, microsecond=0)).total_seconds() // 60)


def numbers_without_time(text: str) -> bool:
    """True when the letter carries a count but no moment it was taken."""
    body = _body(text)
    if _MOMENT.search(body):
        return False
    return bool(_NUMBER.search(_NOT_COUNTS.sub(" ", body)))
