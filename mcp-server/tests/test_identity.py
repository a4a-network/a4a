"""Test MCP server local identity storage and key reuse."""
import json

import pytest

from a4a_mcp import identity


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Provide an isolated identity directory.

    Patch module attributes rather than the environment because `A4A_HOME` is read at
    import time and changing it afterward has no effect.
    """
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    return tmp_path / ".a4a" / "identity.json"


def test_creates_identity_file(home):
    keys = identity.load_or_create_identity()
    assert home.exists()
    saved = json.loads(home.read_text(encoding="utf-8"))
    assert saved["privkey_hex"] == keys.privkey_hex
    assert saved["pubkey_hex"] == keys.pubkey_hex


def test_identity_is_stable_between_calls(home):
    """Keep user identity stable so a second call does not create a new key.

    Otherwise the agent address would change and peers could not contact it again.
    """
    first = identity.load_or_create_identity()
    second = identity.load_or_create_identity()
    assert first.privkey_hex == second.privkey_hex


def test_corrupted_identity_fails_loudly(home):
    """Fail clearly on corruption instead of silently generating a new key.

    Replacement would lose the address and all reputation attached to it.
    """
    home.parent.mkdir(parents=True)
    home.write_text(json.dumps({"pubkey_hex": "corrupted"}), encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt identity file"):
        identity.load_or_create_identity()


def test_key_file_not_world_readable(home):
    """Require mode 0600 for private-key files on POSIX.

    Windows has no equivalent chmod semantics; its profile directory provides the
    relevant access boundary.
    """
    import os
    import stat
    identity.load_or_create_identity()
    if os.name == "posix":
        mode = stat.S_IMODE(home.stat().st_mode)
        assert mode == 0o600, oct(mode)
