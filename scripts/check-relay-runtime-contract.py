#!/usr/bin/env python3
"""Verify the operator-visible contract of a running relay on loopback only."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


MAX_JSON_BYTES = 1024 * 1024
MAX_METRICS_BYTES = 5 * 1024 * 1024
REQUIRED_METRICS = {
    "nostr_cmd_event_total": "counter",
    "nostr_cmd_req_total": "counter",
    "nostr_connections_active": "gauge",
    "nostr_connections_total": "counter",
    "nostr_db_connections": "gauge",
    "nostr_events_write_seconds": "histogram",
}


class ContractError(RuntimeError):
    """The live relay does not expose the promised safe runtime contract."""


def validate_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ContractError("base URL must be a plain loopback HTTP origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
        port = parsed.port
    except ValueError as exc:
        raise ContractError("base URL must contain a literal loopback IP and valid port") from exc
    if not address.is_loopback or port is None or port <= 0:
        raise ContractError("base URL must contain a literal loopback IP and explicit port")
    return value.rstrip("/")


def fetch(base_url: str, path: str, *, accept: str, limit: int) -> tuple[str, bytes]:
    request = urllib.request.Request(base_url + path, headers={"Accept": accept})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=5) as response:
            content_type = response.headers.get_content_type()
            payload = response.read(limit + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise ContractError(f"relay request failed for {path}: {exc}") from exc
    if len(payload) > limit:
        raise ContractError(f"relay response exceeds {limit} bytes: {path}")
    return content_type, payload


def parse_json(payload: bytes, *, endpoint: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"{endpoint} did not return valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{endpoint} JSON root must be an object")
    return value


def expected_kinds(config_path: Path) -> list[int]:
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
        values = config["a4a"]["required_for_kinds"]
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise ContractError(f"could not read a4a.required_for_kinds from {config_path}: {exc}") from exc
    if (
        not isinstance(values, list)
        or not values
        or any(not isinstance(value, int) or isinstance(value, bool) for value in values)
        or len(values) != len(set(values))
    ):
        raise ContractError("configured a4a.required_for_kinds must be unique nonempty integers")
    return values


def expected_inbox_auth(config_path: Path) -> bool:
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
        value = config["a4a"].get("inbox_auth", False)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise ContractError(f"could not read a4a.inbox_auth from {config_path}: {exc}") from exc
    if not isinstance(value, bool):
        raise ContractError("configured a4a.inbox_auth must be a boolean")
    return value


def validate_nip11(
    document: dict[str, Any], configured_kinds: list[int], configured_inbox_auth: bool,
) -> str:
    nips = document.get("supported_nips")
    limitation = document.get("limitation")
    a4a = document.get("a4a")
    version = document.get("version")
    if not isinstance(nips, list) or 11 not in nips:
        raise ContractError("NIP-11 response does not advertise NIP-11")
    if not isinstance(limitation, dict) or limitation.get("restricted_writes") is not True:
        raise ContractError("NIP-11 response does not advertise restricted writes")
    if not isinstance(a4a, dict):
        raise ContractError("NIP-11 response has no A4A capability object")
    if a4a.get("protocol") != "0.4" or a4a.get("multi_char_tag_filters") is not True:
        raise ContractError("NIP-11 response has stale A4A protocol capabilities")
    if a4a.get("delegation_required_for_kinds") != configured_kinds:
        raise ContractError("NIP-11 delegation kinds differ from the running configuration")
    if a4a.get("inbox_auth") is not configured_inbox_auth:
        raise ContractError("NIP-11 inbox authentication differs from the running configuration")
    if not isinstance(version, str) or not version:
        raise ContractError("NIP-11 response has no product version")
    return version


def validate_health(document: dict[str, Any], nip11_version: str) -> None:
    if document.get("status") != "ok":
        raise ContractError("health endpoint is not healthy")
    relay_version = document.get("version")
    a4a_version = document.get("a4a_version")
    schema_version = document.get("schema_version")
    if not isinstance(relay_version, str) or not relay_version:
        raise ContractError("health endpoint has no upstream relay version")
    if not isinstance(a4a_version, str) or not nip11_version.startswith(a4a_version + " "):
        raise ContractError("health and NIP-11 A4A versions differ")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or schema_version <= 0:
        raise ContractError("health endpoint has no positive schema version")


def validate_metrics(payload: bytes) -> None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("metrics endpoint is not UTF-8 text") from exc
    missing = []
    for metric, metric_type in REQUIRED_METRICS.items():
        sample = metric + "_bucket" if metric_type == "histogram" else metric
        if (
            f"# TYPE {metric} {metric_type}" not in text
            or re.search(rf"(?m)^{re.escape(sample)}(?:\{{|\s)", text) is None
        ):
            missing.append(metric)
    if missing:
        raise ContractError("metrics endpoint misses required series: " + ", ".join(missing))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--config", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
        base_url = validate_base_url(args.base_url)
        kinds = expected_kinds(args.config)
        inbox_auth = expected_inbox_auth(args.config)
        nip_type, nip_raw = fetch(
            base_url, "/", accept="application/nostr+json", limit=MAX_JSON_BYTES,
        )
        if nip_type not in ("application/json", "application/nostr+json"):
            raise ContractError(f"NIP-11 endpoint returned unexpected content type: {nip_type}")
        nip_version = validate_nip11(
            parse_json(nip_raw, endpoint="NIP-11"), kinds, inbox_auth,
        )
        health_type, health_raw = fetch(
            base_url, "/v1/health", accept="application/json", limit=MAX_JSON_BYTES,
        )
        if health_type != "application/json":
            raise ContractError(f"health endpoint returned unexpected content type: {health_type}")
        validate_health(parse_json(health_raw, endpoint="health"), nip_version)
        metrics_type, metrics_raw = fetch(
            base_url, "/metrics", accept="text/plain", limit=MAX_METRICS_BYTES,
        )
        if metrics_type != "text/plain":
            raise ContractError(f"metrics endpoint returned unexpected content type: {metrics_type}")
        validate_metrics(metrics_raw)
        print(
            f"relay runtime contract passed: {nip_version}; "
            f"{len(kinds)} protected kinds; {len(REQUIRED_METRICS)} required metrics"
        )
        return 0
    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
