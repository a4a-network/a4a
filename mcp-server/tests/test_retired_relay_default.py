"""Fresh configuration must not rely on an intentionally retired DNS alias."""
import json

from a4a_mcp import identity, server
from a4a_mcp.__main__ import DEFAULT_PUBLIC_RELAYS


def test_unconfigured_tools_use_current_default_without_creating_identity(tmp_path, monkeypatch):
    home = tmp_path / "unused-home"
    monkeypatch.delenv("A4A_RELAY", raising=False)
    monkeypatch.setattr(identity, "IDENTITY_DIR", home)

    assert server._relay_url() == DEFAULT_PUBLIC_RELAYS[0]
    assert server._relay_urls() == [DEFAULT_PUBLIC_RELAYS[0]]
    assert not home.exists()


def test_explicit_private_relay_set_keeps_its_order(tmp_path, monkeypatch):
    home = tmp_path / "unused-home"
    relays = ["ws://127.0.0.1:18401", "ws://127.0.0.1:18402"]
    monkeypatch.setattr(identity, "IDENTITY_DIR", home)
    monkeypatch.setenv("A4A_RELAY", ",".join(relays))

    assert server._relay_url() == relays[0]
    assert server._relay_urls() == relays
    assert not home.exists()


def test_saved_legacy_policy_is_respected_without_silent_migration(tmp_path, monkeypatch):
    monkeypatch.delenv("A4A_RELAY", raising=False)
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path)
    relays = ["wss://relay.a4a.network", "wss://eu1.a4a.network"]
    policy = tmp_path / "inbox-policy.json"
    original = json.dumps({"relay": relays[0], "relays": relays}).encode()
    policy.write_bytes(original)

    assert server._relay_url() == relays[0]
    assert server._relay_urls() == relays
    assert policy.read_bytes() == original


def test_policy_three_active_relays_override_legacy_seven_relay_env(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path)
    active = [
        "wss://ru1.a4a.network",
        "wss://ru2.a4a.network",
        "wss://eu1.a4a.network",
    ]
    seven = [
        "wss://ru1.a4a.network",
        "wss://ru2.a4a.network",
        "wss://eu1.a4a.network",
        "wss://eu2.a4a.network",
        "wss://us1.a4a.network",
        "wss://us2.a4a.network",
        "wss://sg1.a4a.network",
    ]
    policy = tmp_path / "inbox-policy.json"
    policy.write_text(json.dumps({"relay": active[0], "relays": active}), encoding="utf-8")
    monkeypatch.setenv("A4A_RELAY", ",".join(seven))

    assert server._relay_url() == active[0]
    assert server._relay_urls() == active

    # Also verify that a legacy env var still containing retired kz1/relay.a4a.network
    # is overridden by the 3-relay official inbox-policy.json pool:
    monkeypatch.setenv("A4A_RELAY", "wss://ru1.a4a.network,wss://kz1.a4a.network")
    assert server._relay_url() == active[0]
    assert server._relay_urls() == active


