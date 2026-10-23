"""Project-agent identity tests: its key persists unchanged in a file."""
import json
import os

from a4a_agent import identity


def test_creates_identity_file_when_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_AGENT_HOME", str(tmp_path / "home"))
    keys = identity.load_or_create_identity()
    assert len(keys.pubkey_hex) == 64
    assert identity.identity_path().exists()


def test_reuses_existing_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_AGENT_HOME", str(tmp_path / "home"))
    first = identity.load_or_create_identity()
    second = identity.load_or_create_identity()
    assert first.privkey_hex == second.privkey_hex, (
        "the agent key must remain stable across starts"
    )


def test_identity_file_is_not_world_readable(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_AGENT_HOME", str(tmp_path / "home"))
    identity.load_or_create_identity()
    mode = identity.identity_path().stat().st_mode & 0o077
    if os.name == "posix":
        assert mode == 0, "the private key is readable by the group or everyone"


def test_identity_file_contains_only_the_key(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_AGENT_HOME", str(tmp_path / "home"))
    keys = identity.load_or_create_identity()
    data = json.loads(identity.identity_path().read_text(encoding="utf-8"))
    assert data == {"privkey": keys.privkey_hex}


def test_identity_home_is_separate_from_mcp_server(tmp_path, monkeypatch):
    """The default directory must differ from the MCP server's ``~/.a4a``.

    These are distinct network agents; mixing identities would lose one address.
    """
    monkeypatch.delenv("A4A_AGENT_HOME", raising=False)
    assert identity.identity_dir().name != ".a4a"


def test_corrupted_key_file_fails_with_clear_message(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_AGENT_HOME", str(tmp_path / "home"))
    home = identity.identity_path()
    """A19: report empty or partially written key files clearly.

    Silently generating a replacement would lose the address and reputation; a
    raw ``KeyError`` or ``JSONDecodeError`` is not actionable either.
    """
    import pytest
    home.parent.mkdir(parents=True, exist_ok=True)
    for junk in ("", "{}", "not json"):
        home.write_text(junk, encoding="utf-8")
        with pytest.raises(ValueError, match="corrupt key file"):
            identity.load_or_create_identity()


def test_key_file_written_atomically(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_AGENT_HOME", str(tmp_path / "home"))
    """A19: atomic replacement prevents a fatal partially written key file."""
    import os
    seen = []
    real_replace = os.replace

    def spy(src, dst):
        seen.append((str(src), str(dst)))
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy)
    identity.load_or_create_identity()
    assert seen, "the key was not written atomically (no temporary-file replacement)"


# --- Owner key (2026-08-29) ------------------------------------------------------

def test_owner_key_is_separate_from_the_agent_key(tmp_path, monkeypatch):
    """A separate owner key can revoke a compromised worker key safely."""
    monkeypatch.setenv("A4A_AGENT_HOME", str(tmp_path / "home"))
    agent = identity.load_or_create_identity()
    owner = identity.load_or_create_owner_identity()
    assert owner.privkey_hex != agent.privkey_hex
    assert identity.load_or_create_owner_identity().privkey_hex == owner.privkey_hex


def test_owner_key_does_not_change_the_agent_address(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_AGENT_HOME", str(tmp_path / "home"))
    before = identity.load_or_create_identity().pubkey_hex
    identity.load_or_create_owner_identity()
    assert identity.load_or_create_identity().pubkey_hex == before
