"""A4A signed HTTP authentication (kind 27235), the same checks the relay uses for a signed proof.

There is no second signature scheme. The event is a normal kind 27235 A4A event
verified by ``Event.verify``. It is bound to this process's configured origin, the
request target, the method, and — when the method has a body — the sha256 of that
body. The accepted clock skew is the relay's one-minute window.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit

from pydantic import ValidationError

from a4a.event import Event

KIND_HTTP_AUTH = 27235
AUTH_WINDOW_SECONDS = 60
_MAX_HEADER = 16 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")


class AuthError(Exception):
    """The request did not prove a key. ``message`` is safe to return to the caller."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def canonical_url(url: str) -> str:
    """Normalize an absolute URL the way the request binding compares it.

    Default ports and host case must not make two spellings of one request verify
    as different requests. A fragment, userinfo, or non-HTTP scheme never matches.
    """
    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise AuthError("Authorization u tag is not an absolute URL")
    if parts.username or parts.password or parts.fragment:
        raise AuthError("Authorization event is not bound to this request")
    host = parts.hostname.lower()
    port = parts.port
    if (parts.scheme, port) in {("http", 80), ("https", 443)}:
        port = None
    bracketed = f"[{host}]" if ":" in host else host
    netloc = bracketed if port is None else f"{bracketed}:{port}"
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit((parts.scheme, netloc, path, parts.query, ""))


def _tag_values(event: Event, name: str) -> list[str]:
    return event.tag_values(name)


def authenticate(header: object, *, method: str, url: str, body: bytes,
                 now: int, require_payload: bool, check_payload: bool = True) -> str:
    """Return the proven pubkey or raise ``AuthError`` with a fixed English reason."""
    if not isinstance(header, str) or not header:
        raise AuthError("a signed Authorization header is required")
    if len(header) > _MAX_HEADER:
        raise AuthError("Authorization header is too large")
    if header.startswith(("A4A ", "a4a ")):
        encoded = header[4:].strip()
    elif header.startswith(("Nostr ", "nostr ")):
        encoded = header[6:].strip()
    else:
        raise AuthError("Authorization must use the Nostr scheme")
    try:
        decoded = base64.b64decode(encoded, validate=True)
        data = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthError("Authorization payload is not base64") from exc
    if not isinstance(data, dict):
        raise AuthError("Authorization payload is not an event")
    # Reject non-integers before the event model coerces them. A boolean is an int
    # subclass, so the exact type is the check that matters.
    if type(data.get("kind")) is not int or data.get("kind") != KIND_HTTP_AUTH:
        raise AuthError("Authorization event has the wrong kind")
    if type(data.get("created_at")) is not int:
        raise AuthError("Authorization event is outside the accepted time window")
    try:
        event = Event.model_validate(data)
    except ValidationError as exc:
        raise AuthError("Authorization payload is not an event") from exc
    if not event.verify():
        raise AuthError("Authorization event signature is invalid")
    if abs(int(now) - event.created_at) > AUTH_WINDOW_SECONDS:
        raise AuthError("Authorization event is outside the accepted time window")
    urls = _tag_values(event, "u")
    if len(urls) != 1:
        raise AuthError("Authorization event must contain exactly one u tag")
    try:
        supplied = canonical_url(urls[0])
        expected = canonical_url(url)
    except AuthError:
        raise
    if supplied != expected:
        raise AuthError("Authorization event is not bound to this request")
    methods = _tag_values(event, "method")
    if len(methods) != 1 or methods[0].casefold() != method.casefold():
        raise AuthError(f"Authorization event is not bound to {method.upper()}")
    payloads = _tag_values(event, "payload")
    if require_payload:
        # An unread oversized body still has to carry one well-formed payload tag.
        # The hash is compared only when this process actually has the bytes.
        if len(payloads) != 1 or not _SHA256.fullmatch(payloads[0]):
            raise AuthError("Authorization event must contain exactly one payload tag")
        if check_payload and payloads[0] != hashlib.sha256(body).hexdigest():
            raise AuthError("Authorization payload does not match the request body")
    elif payloads:
        raise AuthError("Authorization event must not contain a payload tag")
    return event.pubkey
