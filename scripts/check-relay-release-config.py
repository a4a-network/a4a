#!/usr/bin/env python3
"""Fail when a shipped relay profile silently drops a production safety bound."""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parent.parent
REAL_ROOT = ROOT
RUNNABLE = (ROOT / "relay" / "config.toml", ROOT / "relay" / "config.prod.toml")
EXAMPLE = ROOT / "relay" / "config.toml.example"


def runnable_profiles(root: pathlib.Path = ROOT) -> tuple[pathlib.Path, ...]:
    """Public exports declare their shipped profiles; private trees require both."""
    marker = root / "A4A-SOURCE.json"
    if not marker.exists():
        if root == REAL_ROOT and not (root / "relay/config.prod.toml").exists():
            return (root / "relay/config.toml",)
        return (root / "relay/config.toml", root / "relay/config.prod.toml")
    manifest = json.loads(marker.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != "a4a-public-source-v1":
        raise ValueError("unsupported public source manifest")
    files = {item["path"]: item for item in manifest["files"]}
    if "relay/config.prod.toml" in files or (root / "relay/config.prod.toml").exists():
        raise ValueError("public source must exclude the private production profile")
    for name in ("relay/config.toml", "relay/config.toml.example"):
        item = files[name]
        raw = (root / name).read_bytes()
        if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("public profile differs from its source manifest: " + name)
    return (root / "relay/config.toml",)


def _positive(table: dict, key: str, errors: list[str], *, maximum: int | None = None):
    value = table.get(key)
    if type(value) is not int or value <= 0 or (maximum is not None and value > maximum):
        suffix = f" and <= {maximum}" if maximum is not None else ""
        errors.append(f"{key} must be an integer > 0{suffix}, got {value!r}")


def validate_profile(name: str, data: dict, *, runnable: bool) -> list[str]:
    errors: list[str] = []
    network = data.get("network") if isinstance(data.get("network"), dict) else {}
    limits = data.get("limits") if isinstance(data.get("limits"), dict) else {}
    database = data.get("database") if isinstance(data.get("database"), dict) else {}
    options = data.get("options") if isinstance(data.get("options"), dict) else {}
    a4a = data.get("a4a") if isinstance(data.get("a4a"), dict) else {}
    retention = data.get("retention") if isinstance(data.get("retention"), dict) else {}

    if not isinstance(network.get("address"), str) or not network["address"].strip():
        errors.append("network.address must be explicit")
    _positive(limits, "messages_per_sec", errors)
    _positive(limits, "subscriptions_per_min", errors)
    _positive(limits, "max_event_bytes", errors, maximum=1024 * 1024)
    _positive(limits, "max_ws_message_bytes", errors, maximum=1024 * 1024)
    _positive(limits, "max_ws_frame_bytes", errors, maximum=1024 * 1024)

    if not runnable:
        if network.get("address") not in {"127.0.0.1", "::1", "localhost"}:
            errors.append("example profile must default to loopback; public bind is explicit")
        return [f"{name}: {error}" for error in errors]

    if database.get("in_memory") is True:
        errors.append("database.in_memory must not be enabled in a runnable profile")
    if not isinstance(database.get("data_directory"), str) or not database["data_directory"].strip():
        errors.append("database.data_directory must be explicit")
    _positive(options, "reject_future_seconds", errors, maximum=3600)
    _positive(retention, "max_events_per_author", errors)
    _positive(retention, "max_db_bytes", errors)
    kinds = retention.get("kind_persist_days")
    if not isinstance(kinds, dict) or not kinds:
        errors.append("retention.kind_persist_days must be a nonempty table")
    elif any(type(kind) not in (str, int) or type(days) is not int or days <= 0
             for kind, days in kinds.items()):
        errors.append("retention.kind_persist_days entries must have positive integer days")

    if a4a.get("enabled") is not True:
        errors.append("a4a.enabled must be true in shipped runnable profiles")
    if a4a.get("rest_enabled") is not True:
        errors.append("a4a.rest_enabled must be true in shipped runnable profiles")
    required = a4a.get("required_for_kinds")
    if not isinstance(required, list) or not required or any(type(kind) is not int for kind in required):
        errors.append("a4a.required_for_kinds must be a nonempty integer list")

    return [f"{name}: {error}" for error in errors]


def _load(path: pathlib.Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    errors: list[str] = []
    try:
        profiles = runnable_profiles(ROOT)
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        print("RELAY RELEASE CONFIG REFUSED: invalid public profile declaration:", type(exc).__name__)
        return 1
    for path in profiles:
        try:
            data = _load(path)
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"{path.relative_to(ROOT)}: unreadable TOML: {type(exc).__name__}")
            continue
        errors.extend(validate_profile(path.relative_to(ROOT).as_posix(), data, runnable=True))
    try:
        example = _load(EXAMPLE)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"{EXAMPLE.relative_to(ROOT)}: unreadable TOML: {type(exc).__name__}")
    else:
        errors.extend(validate_profile(EXAMPLE.relative_to(ROOT).as_posix(), example,
                                       runnable=False))

    if errors:
        print("RELAY RELEASE CONFIG REFUSED")
        for error in errors:
            print("  " + error)
        return 1
    print(f"RELAY RELEASE CONFIG OK: {len(profiles)} runnable profiles + safe example")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
