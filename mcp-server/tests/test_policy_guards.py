"""Self-contained negative controls for the build-time publication policy."""
import importlib
import importlib.util
import json
from pathlib import Path

import pytest


def _policy():
    return importlib.import_module("a4a_mcp.policy")


def test_policy_module_imports_when_the_optional_build_file_is_absent():
    path = Path(__file__).resolve().parents[1] / "a4a_mcp" / "policy.py"
    spec = importlib.util.spec_from_file_location("isolated_policy_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.BUILD_POLICY == {}


def test_build_policy_must_be_a_json_object(tmp_path):
    policy = _policy()
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(["deny"]), encoding="utf-8")
    with pytest.raises(RuntimeError, match="JSON"):
        policy._read_policy(path)


def test_build_policy_rejects_an_unknown_mode(tmp_path):
    policy = _policy()
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"public_text": "maybe"}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="public_text"):
        policy._read_policy(path)


def test_missing_environment_override_is_distinct_from_allow(monkeypatch):
    policy = _policy()
    monkeypatch.delenv("A4A_PUBLIC_TEXT", raising=False)
    assert policy._env_mode() is None


def test_environment_override_rejects_an_unknown_mode(monkeypatch):
    policy = _policy()
    monkeypatch.setenv("A4A_PUBLIC_TEXT", "maybe")
    with pytest.raises(ValueError, match="A4A_PUBLIC_TEXT"):
        policy._env_mode()


def test_locked_build_deny_cannot_be_relaxed(monkeypatch):
    policy = _policy()
    monkeypatch.setattr(policy, "BUILD_POLICY", {"public_text": "deny", "locked": True})
    monkeypatch.setenv("A4A_PUBLIC_TEXT", "allow")
    assert policy.public_text_mode() == "deny"


def test_environment_deny_applies_when_the_build_is_not_locked(monkeypatch):
    policy = _policy()
    monkeypatch.setattr(policy, "BUILD_POLICY", {})
    monkeypatch.setenv("A4A_PUBLIC_TEXT", "deny")
    assert policy.public_text_mode() == "deny"


def test_source_names_a_locked_build_policy(monkeypatch):
    policy = _policy()
    monkeypatch.setattr(policy, "BUILD_POLICY", {"public_text": "deny", "locked": True})
    monkeypatch.setenv("A4A_PUBLIC_TEXT", "allow")
    assert "build" in policy.source()


def test_source_names_an_environment_policy(monkeypatch):
    policy = _policy()
    monkeypatch.setattr(policy, "BUILD_POLICY", {})
    monkeypatch.setenv("A4A_PUBLIC_TEXT", "deny")
    assert "A4A_PUBLIC_TEXT" in policy.source()
