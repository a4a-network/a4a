"""Negative controls for shipped relay release profiles."""
import copy
import importlib.util
import hashlib
import json
import pathlib
import tomllib

import pytest


ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
spec = importlib.util.spec_from_file_location(
    "relay_release_config", ROOT / "scripts" / "check-relay-release-config.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def _profile():
    return {
        "network": {"address": "0.0.0.0", "port": 8080},
        "database": {"data_directory": "/data", "in_memory": False},
        "limits": {
            "messages_per_sec": 100,
            "subscriptions_per_min": 10,
            "max_event_bytes": 131072,
            "max_ws_message_bytes": 131072,
            "max_ws_frame_bytes": 131072,
        },
        "options": {"reject_future_seconds": 900},
        "retention": {
            "max_events_per_author": 5000,
            "max_db_bytes": 4 * 1024**3,
            "kind_persist_days": {"31002": 30},
        },
        "a4a": {
            "enabled": True,
            "rest_enabled": True,
            "required_for_kinds": [31002],
        },
    }


@pytest.mark.parametrize("section,key,bad", [
    ("network", "address", ""),
    ("limits", "messages_per_sec", 0),
    ("limits", "subscriptions_per_min", None),
    ("limits", "max_event_bytes", 0),
    ("limits", "max_ws_message_bytes", 2 * 1024**2),
    ("limits", "max_ws_frame_bytes", 0),
    ("database", "data_directory", ""),
    ("database", "in_memory", True),
    ("options", "reject_future_seconds", 0),
    ("retention", "max_events_per_author", 0),
    ("retention", "max_db_bytes", None),
    ("retention", "kind_persist_days", {}),
    ("a4a", "enabled", False),
    ("a4a", "rest_enabled", False),
    ("a4a", "required_for_kinds", []),
])
def test_each_missing_release_bound_is_refused(section, key, bad):
    data = copy.deepcopy(_profile())
    data[section][key] = bad
    assert guard.validate_profile("synthetic", data, runnable=True)


def test_complete_release_profile_and_loopback_example_pass():
    assert guard.validate_profile("synthetic", _profile(), runnable=True) == []
    example = _profile()
    example["network"]["address"] = "127.0.0.1"
    assert guard.validate_profile("example", example, runnable=False) == []
    example["network"]["address"] = "0.0.0.0"
    assert any("loopback" in error
               for error in guard.validate_profile("example", example, runnable=False))


def test_shipped_profiles_parse_and_pass():
    for path in guard.runnable_profiles(ROOT):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        assert guard.validate_profile(path.name, data, runnable=True) == []
    assert guard.main() == 0


def _public_profiles(root):
    (root / "relay").mkdir()
    files = []
    for name in ("config.toml", "config.toml.example"):
        raw = (ROOT / "relay" / name).read_bytes()
        (root / "relay" / name).write_bytes(raw)
        files.append({"path": "relay/" + name, "size": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()})
    marker = {"schema": "a4a-public-source-v1", "files": files}
    (root / "A4A-SOURCE.json").write_text(json.dumps(marker), encoding="utf-8")
    return marker


def test_public_profiles_are_bound_to_declared_bytes(tmp_path):
    _public_profiles(tmp_path)
    assert guard.runnable_profiles(tmp_path) == (tmp_path / "relay/config.toml",)
    with (tmp_path / "relay/config.toml").open("ab") as stream:
        stream.write(b"\n# Changed after export\n")
    with pytest.raises(ValueError, match="differs"):
        guard.runnable_profiles(tmp_path)


def test_missing_private_production_profile_is_still_required(tmp_path, monkeypatch):
    assert guard.runnable_profiles(tmp_path) == (
        tmp_path / "relay/config.toml", tmp_path / "relay/config.prod.toml")
    (tmp_path / "relay").mkdir()
    for name in ("config.toml", "config.toml.example"):
        (tmp_path / "relay" / name).write_bytes((ROOT / "relay" / name).read_bytes())
    monkeypatch.setattr(guard, "ROOT", tmp_path)
    monkeypatch.setattr(guard, "EXAMPLE", tmp_path / "relay/config.toml.example")
    assert guard.main() == 1


def test_public_manifest_cannot_declare_private_profile(tmp_path):
    marker = _public_profiles(tmp_path)
    marker["files"].append({"path": "relay/config.prod.toml"})
    (tmp_path / "A4A-SOURCE.json").write_text(json.dumps(marker), encoding="utf-8")
    with pytest.raises(ValueError, match="exclude"):
        guard.runnable_profiles(tmp_path)
