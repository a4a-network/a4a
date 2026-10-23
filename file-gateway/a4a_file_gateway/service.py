"""HTTP API for ciphertext blobs. No request URL is fetched."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl

from a4a.event import is_canonical_pubkey

from .auth import AuthError, authenticate
from .blobs import BlobStoreError, S3BlobStore, client_for
from .config import Settings
from .store import BlobRecord, MetadataStore, StoreError

log = logging.getLogger("a4a.file_gateway")

RECIPIENT_ONLY = "only the recipient may fetch this blob"
STATUS_ONLY = "only the sender or the recipient may read this blob status"
SENDER_NOT_ALLOWED = "sender is not allowed to upload"
QUOTA_EXCEEDED = "daily upload quota exceeded"
DAY_SECONDS = 24 * 60 * 60


class GatewayError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    content_type: str

    @staticmethod
    def text(status: int, message: str) -> Response:
        raw = message.encode("ascii")
        if raw.decode("ascii") != message or "\n" in message or message != message.strip():
            raise RuntimeError("response text must be one English line")
        return Response(status, raw, "text/plain; charset=utf-8")

    @staticmethod
    def json_body(status: int, payload: dict) -> Response:
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return Response(status, raw, "application/json")

    @staticmethod
    def octets(payload: bytes) -> Response:
        return Response(200, payload, "application/octet-stream")


def load_body(method: str, content_length: str | None, reader, max_bytes: int) -> tuple[bytes, bool]:
    """Return ``(body, payload_unverified)``.

    A declared length above the limit is not read. The caller still authenticates
    the header, then refuses the upload. Reading the extra byte would only turn a
    size limit into a memory limit.
    """
    if method == "GET":
        if content_length not in (None, "0"):
            raise GatewayError(400, "GET body is not allowed")
        return b"", False
    if content_length is None:
        raise GatewayError(400, "Content-Length is required")
    if (not content_length.isascii() or not content_length.isdigit()
            or len(content_length) > 12 or content_length != str(int(content_length))):
        raise GatewayError(400, "Content-Length is not an integer")
    declared = int(content_length)
    if declared > max_bytes:
        return b"", True
    body = reader(declared)
    if len(body) != declared:
        raise GatewayError(400, "request body ended early")
    return body, False


def _status_name(record: BlobRecord, now: int) -> str:
    expired = now >= record.expires_at
    fetched = record.fetched_at is not None
    if expired and fetched:
        return "expired_fetched"
    if expired:
        return "expired_unfetched"
    if fetched:
        return "fetched"
    return "stored"


def _public_record(record: BlobRecord, now: int) -> dict:
    return {
        "sha256": record.sha256,
        "status": _status_name(record, now),
        "size": record.size,
        "sender": record.sender,
        "recipient": record.recipient,
        "uploaded_at": record.uploaded_at,
        "expires_at": record.expires_at,
        "fetched_at": record.fetched_at,
        "fetched_by": record.fetched_by,
    }


class FileGateway:
    def __init__(self, settings: Settings, store: MetadataStore, blobs: S3BlobStore, clock):
        self.settings = settings
        self.store = store
        self.blobs = blobs
        self.clock = clock

    def close(self) -> None:
        self.store.close()

    def handle(self, method: str, target: str, headers, body: bytes,
               *, payload_unverified: bool = False) -> Response:
        try:
            return self._handle(method.upper(), target, headers, body, payload_unverified)
        except GatewayError as exc:
            return Response.text(exc.status, exc.message)
        except AuthError as exc:
            return Response.text(401, exc.message)
        except BlobStoreError:
            log.exception("object storage failed")
            return Response.text(503, "object storage is unavailable")
        except StoreError:
            log.exception("metadata store failed")
            return Response.text(503, "metadata store is unavailable")

    def _now(self) -> int:
        return int(self.clock())

    def _split(self, target: str) -> tuple[str, str]:
        if not isinstance(target, str) or not target.startswith("/") or target.startswith("//"):
            raise GatewayError(400, "request target must be an origin-form path")
        if "#" in target or "\\" in target or "://" in target:
            raise GatewayError(400, "request target must be an origin-form path")
        path, separator, query = target.partition("?")
        if separator and query == "":
            raise GatewayError(400, "request query is not valid")
        return path, query

    def _prove(self, method: str, target: str, headers, body: bytes,
               payload_unverified: bool) -> str:
        path, query = self._split(target)
        header = None if headers is None else headers.get("Authorization")
        return authenticate(
            header, method=method, url=self.settings.request_url(path, query),
            body=body, now=self._now(), require_payload=method == "PUT",
            check_payload=not payload_unverified)

    def _handle(self, method: str, target: str, headers, body: bytes,
                payload_unverified: bool) -> Response:
        if method not in {"GET", "PUT"}:
            self._prove(method, target, headers, body, payload_unverified)
            raise GatewayError(405, "method not allowed")
        if payload_unverified or len(body) > self.settings.max_bytes:
            self._prove(method, target, headers, body, payload_unverified or len(body) > self.settings.max_bytes)
            raise GatewayError(413, "blob exceeds the size limit")
        pubkey = self._prove(method, target, headers, body, False)
        path, query = self._split(target)
        parts = [part for part in path.split("/") if part]
        if parts == ["v1", "blobs"] and method == "PUT":
            return self._put(pubkey, query, body)
        if (len(parts) == 3 and parts[0] == "v1" and parts[1] == "blobs"
                and method == "GET"):
            self._reject_query(query)
            return self._get(pubkey, parts[2])
        if (len(parts) == 4 and parts[:2] == ["v1", "blobs"] and parts[3] == "status"
                and method == "GET"):
            self._reject_query(query)
            return self._status(pubkey, parts[2])
        if parts[:2] == ["v1", "blobs"]:
            raise GatewayError(405, "method not allowed")
        raise GatewayError(404, "not found")

    def _reject_query(self, query: str) -> None:
        if query:
            raise GatewayError(400, "this request does not accept a query")

    def _recipient(self, query: str) -> str:
        try:
            pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, separator="&")
        except ValueError as exc:
            raise GatewayError(400, "request query is not valid") from exc
        if [name for name, _value in pairs] != ["recipient"]:
            raise GatewayError(400, "upload requires exactly one recipient parameter")
        recipient = pairs[0][1]
        if not is_canonical_pubkey(recipient):
            raise GatewayError(400, "recipient must be a lowercase hex public key")
        return recipient

    def _digest_name(self, name: str) -> str:
        if len(name) != 64 or any(character not in "0123456789abcdef" for character in name):
            raise GatewayError(400, "blob name must be a lowercase sha256 hex digest")
        return name

    def _reap(self, record: BlobRecord, now: int) -> str:
        status = _status_name(record, now)
        if status.startswith("expired"):
            self.blobs.delete(record.sha256)
        return status

    def _allowed_senders(self) -> frozenset[str]:
        """Read the operator's sender list on every upload, so adding a key needs no restart.

        One malformed line makes the whole list unusable: a typo must not silently drop
        or admit a key. Blank lines and lines starting with '#' are comments.
        """
        try:
            text = self.settings.allowed_senders_file.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as exc:
            log.error("sender list is unreadable: %s", type(exc).__name__)
            raise GatewayError(503, "sender list is unavailable") from exc
        keys = set()
        for line in text.splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            if not is_canonical_pubkey(entry):
                log.error("sender list has a malformed line")
                raise GatewayError(503, "sender list is unavailable")
            keys.add(entry)
        return frozenset(keys)

    def _put(self, sender: str, query: str, body: bytes) -> Response:
        recipient = self._recipient(query)
        if sender not in self._allowed_senders():
            raise GatewayError(403, SENDER_NOT_ALLOWED)
        digest = hashlib.sha256(body).hexdigest()
        now = self._now()
        record = BlobRecord(
            sha256=digest, sender=sender, recipient=recipient, size=len(body),
            uploaded_at=now, expires_at=now + self.settings.ttl_seconds)
        outcome, stored = self.store.reserve_upload(
            record, now, now - DAY_SECONDS, self.settings.sender_daily_bytes)
        if outcome == "quota":
            raise GatewayError(429, QUOTA_EXCEEDED)
        if outcome == "conflict":
            raise GatewayError(409, "blob is already recorded")
        try:
            # A failed write must not leave a row that says the blob is stored.
            if outcome == "created" or not self.blobs.contains(stored.sha256):
                self.blobs.put(stored.sha256, body)
            stored = self.store.finish_upload(stored, self._now())
        except BlobStoreError:
            if outcome == "created":
                self.store.cancel_upload(stored)
            raise
        status = 201 if outcome == "created" else 200
        return Response.json_body(status, _public_record(stored, now))

    def _get(self, pubkey: str, name: str) -> Response:
        digest = self._digest_name(name)
        record = self.store.get(digest)
        if record is None:
            raise GatewayError(404, "blob not found")
        if pubkey != record.recipient:
            raise GatewayError(403, RECIPIENT_ONLY)
        if not record.ready and self._now() < record.expires_at:
            raise GatewayError(503, "blob upload is incomplete")
        now = self._now()
        if self._reap(record, now).startswith("expired"):
            raise GatewayError(410, "blob expired")
        data = self.blobs.get(digest)
        if data is None or hashlib.sha256(data).hexdigest() != digest:
            raise GatewayError(502, "stored blob does not match its name")
        updated = self.store.mark_fetched(digest, pubkey, now)
        if updated is None:
            raise GatewayError(404, "blob not found")
        return Response.octets(data)

    def _status(self, pubkey: str, name: str) -> Response:
        digest = self._digest_name(name)
        record = self.store.get(digest)
        if record is None:
            raise GatewayError(404, "blob not found")
        if pubkey not in {record.sender, record.recipient}:
            raise GatewayError(403, STATUS_ONLY)
        if not record.ready and self._now() < record.expires_at:
            raise GatewayError(503, "blob upload is incomplete")
        now = self._now()
        self._reap(record, now)
        current = self.store.get(digest)
        if current is None:
            raise GatewayError(404, "blob not found")
        return Response.json_body(200, _public_record(current, now))


def build_gateway(env, *, clock=None, s3_client=None) -> FileGateway:
    settings = Settings.from_env(env)
    store = MetadataStore(settings.home)
    client = client_for(settings) if s3_client is None else s3_client
    return FileGateway(settings, store, S3BlobStore(client, settings.bucket),
                       clock or time.time)


class GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._dispatch()

    def do_PUT(self):
        self._dispatch()

    def log_message(self, fmt, *args):
        log.info("http " + fmt, *args)

    def _dispatch(self):
        gateway: FileGateway = self.server.gateway  # type: ignore[attr-defined]
        unverified = False
        try:
            values = self.headers.get_all("Content-Length") or []
            if len(values) > 1:
                raise GatewayError(400, "Content-Length must appear once")
            length = values[0] if values else None
            body, unverified = load_body(self.command, length, self.rfile.read,
                                          gateway.settings.max_bytes)
            response = gateway.handle(self.command, self.path, self.headers, body,
                                      payload_unverified=unverified)
        except GatewayError as exc:
            response = Response.text(exc.status, exc.message)
        except Exception:
            log.exception("file gateway request failed")
            response = Response.text(500, "file gateway failed")
        if unverified:
            self.close_connection = True
        self._write(response)

    def _write(self, response: Response):
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(response.body)


def serve(gateway: FileGateway) -> int:
    server = ThreadingHTTPServer((gateway.settings.bind_host, gateway.settings.bind_port),
                                 GatewayHandler)
    server.gateway = gateway  # type: ignore[attr-defined]
    log.info("file gateway listening on %s:%s", gateway.settings.bind_host, gateway.settings.bind_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("file gateway stopped")
    finally:
        server.server_close()
        gateway.close()
    return 0
