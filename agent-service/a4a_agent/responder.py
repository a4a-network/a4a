"""Scripted responses to common questions.

No model is involved: keywords select a fixed answer, and network text cannot
alter that answer. Prompt injection is therefore ineffective by construction.

PLAN DEVIATION (2026-08-28): the plan proposed replying with ``pip install
a4a-mcp``. Neither ``a4a-mcp`` nor ``a4a-sdk`` exists on PyPI (verified as 404).
The project agent is the network's public front door and must not distribute a
broken installation command. Restore the command only after package publication.
"""
import re

_ANSWERS: tuple[tuple[tuple[str, ...], str], ...] = (
    # Russian phrases are intentional multilingual input aliases; responses and
    # implementation remain English for the public service surface.
    (("\u0447\u0442\u043E \u0442\u0430\u043A\u043E\u0435 a4a", "what is a4a", "\u043F\u0440\u043E \u0447\u0442\u043E", "\u0447\u0435\u043C \u0437\u0430\u043D\u0438\u043C\u0430\u0435\u0442\u0435\u0441\u044C"),
     "A4A is an open communication protocol for personal AI agents. Agents owned "
     "by different people can discover each other and act for their owners. It "
     "uses signed JSON events over WebSocket relays, with signed agreements, reviews, and verifiable "
     "reputation."),
    (("\u043F\u043E\u0434\u043A\u043B\u044E\u0447", "connect", "\u043A\u0430\u043A \u043D\u0430\u0447\u0430\u0442\u044C", "get started", "quickstart"),
     "Connect an agent by installing the A4A MCP server from the project "
     "repository (there is no PyPI package yet). See "
     "docs/onboarding/connect-your-agent.md. Public network relay: "
     "wss://eu1.a4a.network"),
    (("\u0441\u043F\u0435\u0446", "\u0441\u043F\u0435\u043A\u0430", "spec", "\u043F\u0440\u043E\u0442\u043E\u043A\u043E\u043B", "kind"),
     "The protocol specification and complete event-kind registry are in "
     "docs/spec/a4a-protocol-v0.4.md in the project repository."),
    (("\u0440\u0435\u043B\u0435\u0439", "relay", "\u0430\u0434\u0440\u0435\u0441 \u0441\u0435\u0442\u0438"),
     "Public relay: wss://eu1.a4a.network"),
)


def _normalize(text: str) -> str:
    """Lowercase text, replace punctuation with spaces, and collapse whitespace.

    Collapsing is required so a query containing duplicate spaces still matches a
    single-space keyword. Python's ``\\w`` also includes Cyrillic characters.
    """
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", text.lower())).strip()


def answer(text: str) -> str | None:
    """Return a scripted answer, or ``None`` when the question is unknown."""
    normalized = _normalize(text)
    for keys, response in _ANSWERS:
        if any(_normalize(k) in normalized for k in keys):
            return response
    return None
