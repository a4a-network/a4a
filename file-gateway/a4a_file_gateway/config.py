"""Process configuration. Endpoints and credentials come from the environment only."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping
from urllib.parse import urlsplit, urlunsplit


class ConfigError(RuntimeError):
    """The process cannot start. The message names the variable, never its value."""


DEFAULT_MAX_BYTES = 25 * 1024 * 1024
#: The owner chose 30 days on 24.09.2026: a letter is not always read at once.
DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60
#: Per sender, over the last 24 hours. Rented storage is paid for; one key must not fill it.
DEFAULT_SENDER_DAILY_BYTES = 200 * 1024 * 1024
MAX_CONFIGURABLE_DAILY_BYTES = 64 * 1024 * 1024 * 1024
#: The body is buffered in memory, so a typo must not accept an unbounded upload.
MAX_CONFIGURABLE_BYTES = 512 * 1024 * 1024
MAX_CONFIGURABLE_TTL_SECONDS = 10 * 365 * 24 * 60 * 60
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_REGION = re.compile(r"[a-z0-9-]{1,32}")


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "")
    if not value or any(character.isspace() for character in value):
        raise ConfigError(f"{name} must be a single non-empty token")
    return value


def _origin(value: str, name: str) -> str:
    """Return scheme://host[:port] or refuse a URL that is not an origin.

    A path, query, fragment, or embedded secret would let one setting smuggle a
    different request target than the one callers sign.
    """
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ConfigError(f"{name} must be an absolute http or https origin")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfigError(f"{name} must not contain credentials, a query, or a fragment")
    if parts.path not in {"", "/"}:
        raise ConfigError(f"{name} must not include a path")
    host = parts.hostname.lower()
    port = parts.port
    if (parts.scheme, port) in {("http", 80), ("https", 443)}:
        port = None
    bracketed = f"[{host}]" if ":" in host else host
    netloc = bracketed if port is None else f"{bracketed}:{port}"
    return urlunsplit((parts.scheme, netloc, "", "", ""))


def _positive_int(env: Mapping[str, str], name: str, default: int, ceiling: int) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    if not raw.isascii() or not raw.isdigit() or raw != str(int(raw)):
        raise ConfigError(f"{name} must be a canonical positive integer")
    value = int(raw)
    if not 1 <= value <= ceiling:
        raise ConfigError(f"{name} must be from 1 to {ceiling}")
    return value


def _bind(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if separator != ":" or not host or not port.isascii() or not port.isdigit():
        raise ConfigError("A4A_FILE_GATEWAY_BIND must be host:port")
    number = int(port)
    if not 1 <= number <= 65535 or port != str(number):
        raise ConfigError("A4A_FILE_GATEWAY_BIND must be host:port")
    return host, number


@dataclass(frozen=True)
class Settings:
    home: Path
    public_origin: str
    endpoint: str
    bucket: str
    access_key: str
    secret_key: str
    region: str
    max_bytes: int
    ttl_seconds: int
    allowed_senders_file: Path
    sender_daily_bytes: int
    bind_host: str
    bind_port: int

    def request_url(self, path: str, query: str) -> str:
        if not path.startswith("/") or path.startswith("//"):
            raise ConfigError("request path is not origin-form")
        target = path if not query else f"{path}?{query}"
        return self.public_origin + target

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Settings:
        bucket = _required(env, "A4A_FILE_GATEWAY_S3_BUCKET")
        if not _BUCKET.fullmatch(bucket):
            raise ConfigError("A4A_FILE_GATEWAY_S3_BUCKET must be a DNS-style bucket name")
        region = env.get("A4A_FILE_GATEWAY_S3_REGION", "us-east-1")
        if not _REGION.fullmatch(region):
            raise ConfigError("A4A_FILE_GATEWAY_S3_REGION must be a short region token")
        access_key = _required(env, "A4A_FILE_GATEWAY_S3_ACCESS_KEY")
        secret_key = _required(env, "A4A_FILE_GATEWAY_S3_SECRET_KEY")
        if len(access_key) > 128 or len(secret_key) > 256:
            raise ConfigError("S3 credentials are longer than the accepted token length")
        bind_host, bind_port = _bind(env.get("A4A_FILE_GATEWAY_BIND", "127.0.0.1:8787"))
        return cls(
            home=Path(_required(env, "A4A_FILE_GATEWAY_HOME")),
            public_origin=_origin(_required(env, "A4A_FILE_GATEWAY_PUBLIC_URL"),
                                   "A4A_FILE_GATEWAY_PUBLIC_URL"),
            endpoint=_origin(_required(env, "A4A_FILE_GATEWAY_S3_ENDPOINT"),
                             "A4A_FILE_GATEWAY_S3_ENDPOINT"),
            bucket=bucket,
            access_key=access_key,
            secret_key=secret_key,
            region=region,
            max_bytes=_positive_int(env, "A4A_FILE_GATEWAY_MAX_BYTES",
                                    DEFAULT_MAX_BYTES, MAX_CONFIGURABLE_BYTES),
            ttl_seconds=_positive_int(env, "A4A_FILE_GATEWAY_TTL_SECONDS",
                                      DEFAULT_TTL_SECONDS, MAX_CONFIGURABLE_TTL_SECONDS),
            allowed_senders_file=Path(_required(env, "A4A_FILE_GATEWAY_ALLOWED_SENDERS_FILE")),
            sender_daily_bytes=_positive_int(env, "A4A_FILE_GATEWAY_SENDER_DAILY_BYTES",
                                             DEFAULT_SENDER_DAILY_BYTES,
                                             MAX_CONFIGURABLE_DAILY_BYTES),
            bind_host=bind_host,
            bind_port=bind_port,
        )
