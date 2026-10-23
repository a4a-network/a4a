"""The mailbox opt-in for `received` ACKs: explicit, and absent in older policy files."""
import json

import pytest

from a4a_mcp import identity, inbox_runtime


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:9")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    identity.load_or_create_identity()
    return tmp_path / ".a4a" / "inbox-policy.json"


def test_receipt_acks_are_off_unless_configured(home):
    policy = inbox_runtime.configure("c", ["a" * 64], start_after=0)
    assert policy.ack_on_receipt is False


def test_configure_can_turn_receipt_acks_on(home):
    policy = inbox_runtime.configure("c", ["a" * 64], start_after=0, ack_on_receipt=True)
    assert policy.ack_on_receipt is True
    assert inbox_runtime.load_policy().ack_on_receipt is True


def test_policy_written_before_the_option_still_loads(home):
    inbox_runtime.configure("c", ["a" * 64], start_after=0)
    data = json.loads(home.read_text(encoding="utf-8"))
    data.pop("ack_on_receipt")
    home.write_text(json.dumps(data), encoding="utf-8")
    assert inbox_runtime.load_policy().ack_on_receipt is False


def test_non_boolean_option_is_refused(home):
    inbox_runtime.configure("c", ["a" * 64], start_after=0)
    data = json.loads(home.read_text(encoding="utf-8"))
    data["ack_on_receipt"] = "yes"
    home.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(Exception):
        inbox_runtime.load_policy()
