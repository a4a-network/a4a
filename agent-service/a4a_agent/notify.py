"""Escalate requests to the owner through Telegram.

The owner reads these messages directly, so ordering matters: verifiable facts
come first, followed by third-party text inside an explicit untrusted-data frame
so that it cannot be mistaken for an instruction.
"""
from a4a.sanitize import wrap_untrusted

_API = "https://api.telegram.org/bot{token}/sendMessage"
# Telegram rejects messages longer than 4,096 characters. Without truncation, a
# request containing a long introduction would fail on every delivery attempt,
# and the owner would see neither the request nor the failure (review 2026-08-28, A9).
_TELEGRAM_LIMIT = 4096
_TRUNCATED = "\n…(sender text truncated)"


def format_escalation(pubkey: str, intro: str, reasons: tuple[str, ...]) -> str:
    head = f"Contact request from {pubkey[:12]}…"
    facts = "\n".join(f"  ✓ {r}" for r in reasons) if reasons else "  (no verifiable facts)"
    prefix = f"{head}\n{facts}\n\n"
    # Truncate ONLY third-party text. Verifiable facts must remain intact because
    # they are the reason the owner reads the message. Calculate the available
    # space using the actual size of an empty untrusted-data frame.
    overhead = len(prefix) + len(wrap_untrusted("", source=pubkey[:12])) + len(_TRUNCATED)
    room = _TELEGRAM_LIMIT - overhead
    if room > 0 and len(intro) > room:
        intro = intro[:room] + _TRUNCATED
    return f"{prefix}{wrap_untrusted(intro, source=pubkey[:12])}"


def send(token: str, chat_id: str, text: str, poster=None) -> bool:
    """Send a notification; tests inject ``poster`` to avoid network access."""
    if poster is None:
        import httpx

        def poster(url, json):  # noqa: F811 - local default avoids importing httpx in tests
            return httpx.post(url, json=json, timeout=15)
    try:
        r = poster(_API.format(token=token), {"chat_id": chat_id, "text": text})
        return getattr(r, "status_code", 0) == 200
    except Exception:
        return False  # Notifications are non-critical and must not crash the service.
