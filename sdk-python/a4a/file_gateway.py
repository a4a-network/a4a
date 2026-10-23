"""Client for an A4A file gateway: upload ciphertext for one recipient, fetch it as them.

The gateway keeps client-encrypted blobs in object storage and hands each one only to
the recipient named at upload. Every request carries a NIP-98 event (kind 27235) bound
to the URL, the method and, for an upload, the sha256 of the body.

A file reference in a letter names a gateway URL, but that address is never fetched as
given: `gateway_blob` accepts it only when its origin is one of the caller's own
configured gateways and the path names the same sha256 as the reference. Anything else
is somebody else's address, and following it would let a sender make the recipient
reach into its own network.
"""
from __future__ import annotations

import base64
import hashlib
import time
from urllib.parse import urlsplit

import httpx

from .event import Event, is_canonical_pubkey
from .keys import Keys

KIND_HTTP_AUTH = 27235
_TIMEOUT = 60.0


class FileGatewayError(RuntimeError):
    """The gateway refused or failed. `status` is the HTTP status, 0 when none arrived."""

    def __init__(self, status: int, message: str):
        super().__init__(f"file gateway: {status} {message}")
        self.status = status
        self.message = message


def _origin(url: str) -> str:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise FileGatewayError(0, "gateway address is malformed") from exc
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise FileGatewayError(0, "gateway address must be an absolute http or https origin")
    host = parts.hostname.lower()
    if (parts.scheme, port) in {("http", 80), ("https", 443)}:
        port = None
    bracketed = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{bracketed if port is None else f'{bracketed}:{port}'}"


def auth_header(keys: Keys, method: str, url: str, body: bytes | None = None, *,
                now: int | None = None) -> str:
    """Return the `Authorization` value proving `keys` for exactly this request."""
    tags = [["u", url], ["method", method.upper()]]
    if body is not None:
        tags.append(["payload", hashlib.sha256(body).hexdigest()])
    event = Event(kind=KIND_HTTP_AUTH, content="", tags=tags,
                  created_at=int(time.time()) if now is None else int(now))
    event.sign(keys)
    token = base64.standard_b64encode(event.model_dump_json().encode("utf-8"))
    return "Nostr " + token.decode("ascii")


def blob_url(origin: str, sha256: str) -> str:
    return f"{_origin(origin)}/v1/blobs/{sha256}"


def gateway_blob(ref: dict, allowed_origins) -> str | None:
    """Return the blob's sha256 if `ref` points at one of OUR gateways, else None."""
    url, digest = ref.get("url"), ref.get("sha256")
    if not isinstance(url, str) or not isinstance(digest, str):
        return None
    try:
        origin = _origin(url)
        allowed = {_origin(item) for item in allowed_origins}
    except FileGatewayError:
        return None
    parts = urlsplit(url)
    if origin not in allowed or parts.query or parts.fragment:
        return None
    if parts.path != f"/v1/blobs/{digest}":
        return None
    return digest


def _client(client: httpx.AsyncClient | None) -> tuple[httpx.AsyncClient, bool]:
    if client is not None:
        return client, False
    # No proxy from the environment and no redirects: the request goes to the gateway
    # the caller named, or nowhere.
    return httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=_TIMEOUT), True


async def _request(method: str, url: str, keys: Keys, body: bytes | None,
                   client: httpx.AsyncClient | None, now: int | None) -> httpx.Response:
    session, owned = _client(client)
    headers = {"Authorization": auth_header(keys, method, url, body, now=now)}
    try:
        response = await session.request(method, url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        raise FileGatewayError(0, f"gateway unreachable: {type(exc).__name__}") from exc
    finally:
        if owned:
            await session.aclose()
    if response.status_code >= 400:
        text = response.text.strip()[:200] or "no reason given"
        raise FileGatewayError(response.status_code, text)
    return response


async def upload(origin: str, keys: Keys, recipient: str, blob: bytes, *,
                 client: httpx.AsyncClient | None = None, now: int | None = None) -> dict:
    """Store `blob` (already encrypted) for `recipient`; return the gateway's record."""
    if not is_canonical_pubkey(recipient):
        raise FileGatewayError(0, "recipient must be a lowercase hex public key")
    url = f"{_origin(origin)}/v1/blobs?recipient={recipient}"
    response = await _request("PUT", url, keys, bytes(blob), client, now)
    return response.json()


async def fetch(origin: str, keys: Keys, sha256: str, *,
                client: httpx.AsyncClient | None = None, now: int | None = None) -> bytes:
    """Download a blob addressed to `keys` and check that it is the one named."""
    response = await _request("GET", blob_url(origin, sha256), keys, None, client, now)
    data = response.content
    if hashlib.sha256(data).hexdigest() != sha256:
        raise FileGatewayError(response.status_code, "downloaded bytes do not match the blob name")
    return data


async def status(origin: str, keys: Keys, sha256: str, *,
                 client: httpx.AsyncClient | None = None, now: int | None = None) -> dict:
    """Return `stored`, `fetched`, `expired_unfetched` or `expired_fetched` with details."""
    response = await _request("GET", blob_url(origin, sha256) + "/status", keys, None,
                              client, now)
    return response.json()
