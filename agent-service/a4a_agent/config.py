"""Service configuration loaded from environment variables."""
import os
from dataclasses import dataclass, field

from .policy import Policy


@dataclass
class Config:
    relays: tuple[str, ...] = ("wss://eu1.a4a.network",)
    telegram_token: str = ""
    telegram_chat_id: str = ""
    policy: Policy = field(default_factory=Policy)
    # Scripted-response limit for ONE sender per cycle. Design section 3 requires a
    # local per-sender limit because the relay only has a global messages_per_sec=100.
    # Without this limit, one key can make us publish an event for every question.
    max_replies_per_sender: int = 3
    # Scripted-response ceiling for the ENTIRE stream per window. Free keys bypass a
    # per-sender limit, allowing a spammer to make us publish for every question
    # (review A12, 2026-08-28). The global ceiling bounds cost across all keys.
    max_replies_total: int = 60
    # Inbox-read window in days. Without it, every poll downloads ALL addressed history,
    # so service cost grows with incoming junk and we pay instead of the spammer (audit
    # L1, 2026-08-28). Tradeoff: mail older than the window is not processed after a
    # prolonged outage.
    inbox_window_days: int = 7
    # Reply-rate window in seconds. Streaming has no polling cycles, so "responses per
    # cycle" becomes "responses per time window."
    reply_window_seconds: int = 60
    # Pause before restoring a subscription after relay disconnect. Zero retries
    # immediately in tests. The SDK gives up after three reconnection attempts, so the
    # service must keep the long-lived subscription alive.
    reconnect_delay_seconds: float = 5.0


def _num(name: str, default, cast):
    """Parse a numeric environment value with an actionable error.

    `A4A_MIN_REVIEWS=three` used to raise a bare ValueError without identifying the
    variable (review A18, 2026-08-28).
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = cast(raw)
    except ValueError:
        raise ValueError(f"{name}: expected a number, got {raw!r}") from None
    if value < 0:
        raise ValueError(f"{name}: negative value {value} is not meaningful")
    return value


def from_env() -> Config:
    issuers = tuple(i for i in os.environ.get("A4A_TRUSTED_ISSUERS", "").split(",") if i)
    return Config(
        relays=tuple(r for r in os.environ.get(
            "A4A_RELAYS", "wss://eu1.a4a.network").split(",") if r),
        telegram_token=os.environ.get("A4A_TELEGRAM_TOKEN", ""),
        telegram_chat_id=os.environ.get("A4A_TELEGRAM_CHAT_ID", ""),
        policy=Policy(
            trusted_issuers=issuers,
            min_trust=_num("A4A_MIN_TRUST", 0.0, float),
            min_reviews=_num("A4A_MIN_REVIEWS", 0, int),
        ),
        max_replies_per_sender=_num("A4A_MAX_REPLIES_PER_SENDER", 3, int),
        max_replies_total=_num("A4A_MAX_REPLIES_TOTAL", 60, int),
        inbox_window_days=_num("A4A_INBOX_WINDOW_DAYS", 7, int),
        reply_window_seconds=_num("A4A_REPLY_WINDOW_SECONDS", 60, int),
        reconnect_delay_seconds=_num("A4A_RECONNECT_DELAY_SECONDS", 5.0, float),
    )
