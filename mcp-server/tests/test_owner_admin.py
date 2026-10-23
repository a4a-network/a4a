"""Owner migration tests use synthetic keys and temporary profiles only."""
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest
from a4a import keyfile
from a4a.keys import Keys

from a4a_mcp import identity

PASSWORD = "test-only passphrase for synthetic keys"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    from a4a import Agent
    monkeypatch.setenv("A4A_RELAY", "ws://127.0.0.1:1/never")
    async def forbidden(self):
        raise AssertionError("owner-admin tests must not open any relay connection")
    monkeypatch.setattr(Agent, "__aenter__", forbidden)


@pytest.fixture
def profile(tmp_path, monkeypatch):
    home = tmp_path / "profile"
    home.mkdir()
    monkeypatch.setattr(identity, "IDENTITY_DIR", home)
    monkeypatch.setattr(identity, "IDENTITY_FILE", home / "identity.json")
    agent = identity.load_or_create_identity()
    owner = identity.load_or_create_owner_identity()
    data = json.loads(identity.IDENTITY_FILE.read_text())
    data["custom"] = {"keep": True}
    identity.IDENTITY_FILE.write_text(json.dumps(data))
    return agent, owner, tmp_path / "owner-vault.json"


def test_separate_preserves_identity_and_removes_owner_secret(profile):
    from a4a_mcp.owner_admin import separate_owner, unlock_owner
    agent, owner, destination = profile
    result = separate_owner(destination, PASSWORD)
    assert result == owner.pubkey_hex
    data = json.loads(identity.IDENTITY_FILE.read_text())
    assert data["privkey_hex"] == agent.privkey_hex
    assert data["pubkey_hex"] == agent.pubkey_hex
    assert data["owner_pubkey_hex"] == owner.pubkey_hex
    assert data["custom"] == {"keep": True}
    assert identity.OWNER_FIELD not in data
    assert owner.privkey_hex not in destination.read_text()
    assert unlock_owner(destination, PASSWORD).pubkey_hex == owner.pubkey_hex
    assert keyfile.is_private(destination)[0]
    assert keyfile.is_private(identity.IDENTITY_FILE)[0]
    with pytest.raises(ValueError, match="external"):
        identity.load_or_create_owner_identity()


def test_profile_rejects_invalid_agent_secret_before_key_construction(profile, monkeypatch):
    from a4a_mcp import owner_admin
    data = json.loads(identity.IDENTITY_FILE.read_text())
    data["privkey_hex"] = "short"
    identity.IDENTITY_FILE.write_text(json.dumps(data))
    monkeypatch.setattr(owner_admin, "Keys",
                        lambda _value: pytest.fail("invalid agent secret reached key constructor"))
    with pytest.raises(ValueError, match="invalid agent identity"):
        owner_admin._profile()


def test_profile_rejects_mismatched_agent_public_key(profile):
    from a4a_mcp import owner_admin
    data = json.loads(identity.IDENTITY_FILE.read_text())
    data["pubkey_hex"] = Keys().pubkey_hex
    identity.IDENTITY_FILE.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="invalid agent identity"):
        owner_admin._profile()


def test_existing_destination_is_never_overwritten(profile):
    from a4a_mcp.owner_admin import separate_owner
    _, _, destination = profile
    destination.write_text("unrelated existing file")
    original = identity.IDENTITY_FILE.read_bytes()
    with pytest.raises(ValueError, match="exists"):
        separate_owner(destination, PASSWORD)
    assert destination.read_text() == "unrelated existing file"
    assert identity.IDENTITY_FILE.read_bytes() == original


@pytest.mark.parametrize("inside", [True, False])
def test_unsafe_destination_refused(profile, inside):
    from a4a_mcp.owner_admin import separate_owner
    destination = identity.IDENTITY_DIR / "owner.json" if inside else Path("relative.json")
    original = identity.IDENTITY_FILE.read_bytes()
    with pytest.raises(ValueError):
        separate_owner(destination, PASSWORD)
    assert identity.IDENTITY_FILE.read_bytes() == original


def test_permission_failure_keeps_original(profile, monkeypatch):
    from a4a_mcp.owner_admin import separate_owner
    _, _, destination = profile
    original = identity.IDENTITY_FILE.read_bytes()
    monkeypatch.setattr(keyfile, "harden_and_check", lambda *a, **kw: (False, "test"))
    with pytest.raises(ValueError, match="permissions"):
        separate_owner(destination, PASSWORD)
    assert identity.IDENTITY_FILE.read_bytes() == original


def test_write_rechecks_private_permissions_after_flush(tmp_path, monkeypatch):
    from a4a_mcp import owner_admin
    path = tmp_path / "owner.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    monkeypatch.setattr(owner_admin.keyfile, "harden_and_check",
                        lambda *_args, **_kwargs: (True, None))
    monkeypatch.setattr(owner_admin.keyfile, "is_private", lambda _path: (False, "changed"))
    with pytest.raises(ValueError, match="permissions changed"):
        owner_admin._write_fd(fd, path, {"synthetic": True})


def test_replace_failure_leaves_recoverable_vault(profile, monkeypatch):
    from a4a_mcp import owner_admin
    _, owner, destination = profile
    original = identity.IDENTITY_FILE.read_bytes()
    monkeypatch.setattr(owner_admin.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("test")))
    with pytest.raises(ValueError):
        owner_admin.separate_owner(destination, PASSWORD)
    assert identity.IDENTITY_FILE.read_bytes() == original
    assert owner_admin.unlock_owner(destination, PASSWORD).pubkey_hex == owner.pubkey_hex


def test_wrong_password_and_wrong_owner_are_rejected(profile):
    from a4a_mcp.owner_admin import separate_owner, unlock_owner
    _, _, destination = profile
    separate_owner(destination, PASSWORD)
    original = identity.IDENTITY_FILE.read_bytes()
    with pytest.raises(ValueError):
        unlock_owner(destination, "wrong password")
    data = json.loads(original)
    data["owner_pubkey_hex"] = Keys().pubkey_hex
    identity.IDENTITY_FILE.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="binding"):
        unlock_owner(destination, PASSWORD)


def test_separate_never_initializes_missing_profile(tmp_path, monkeypatch):
    from a4a_mcp.owner_admin import separate_owner
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / "missing")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / "missing" / "identity.json")
    with pytest.raises(ValueError):
        separate_owner(tmp_path / "owner.json", PASSWORD)
    assert not identity.IDENTITY_FILE.exists()


def test_password_prompt_refuses_noninteractive_input(monkeypatch):
    from a4a_mcp import owner_admin
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(owner_admin.getpass, "getpass",
                        lambda *_args: pytest.fail("noninteractive input reached getpass"))
    with pytest.raises(ValueError, match="terminal"):
        owner_admin.prompt_password(confirm=True)


def test_safe_path_rejects_symlink_metadata(monkeypatch, tmp_path):
    from a4a_mcp import owner_admin
    target = tmp_path / "owner.json"
    target.write_text("{}")
    original = Path.lstat
    fake = SimpleNamespace(st_mode=stat.S_IFLNK, st_nlink=1, st_file_attributes=0)
    monkeypatch.setattr(Path, "lstat", lambda self: fake if self == target else original(self))
    with pytest.raises(ValueError, match="links and reparse"):
        owner_admin._safe_path(target)


def test_safe_path_rejects_multiply_linked_target_metadata(monkeypatch, tmp_path):
    from a4a_mcp import owner_admin
    target = tmp_path / "owner.json"
    target.write_text("{}")
    actual = target.lstat()
    fake = SimpleNamespace(st_mode=actual.st_mode, st_nlink=2, st_file_attributes=0)
    original = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda self: fake if self == target else original(self))
    with pytest.raises(ValueError, match="regular, unlinked"):
        owner_admin._safe_path(target)


def test_read_rejects_duplicate_json_fields(tmp_path):
    from a4a_mcp import owner_admin
    path = tmp_path / "duplicate.json"
    path.write_text('{"version":1,"version":2}')
    with pytest.raises(ValueError, match="invalid identity or vault JSON"):
        owner_admin._read(path, 1024)


def test_read_rejects_oversize_before_json_decode(tmp_path, monkeypatch):
    from a4a_mcp import owner_admin
    path = tmp_path / "oversize.json"
    path.write_bytes(b"x" * 11)
    monkeypatch.setattr(owner_admin.json, "loads",
                        lambda *_args, **_kwargs: pytest.fail("oversize input reached JSON"))
    with pytest.raises(ValueError, match="size limit"):
        owner_admin._read(path, 10)


def test_read_requires_a_json_object(tmp_path):
    from a4a_mcp import owner_admin
    path = tmp_path / "array.json"
    path.write_text("[]")
    with pytest.raises(ValueError, match="invalid identity or vault JSON"):
        owner_admin._read(path, 1024)


def test_password_prompt_requires_matching_confirmation(monkeypatch):
    from a4a_mcp import owner_admin
    monkeypatch.setattr(owner_admin.sys.stdin, "isatty", lambda: True)
    answers = iter([PASSWORD, "different password"])
    monkeypatch.setattr(owner_admin.getpass, "getpass", lambda *a: next(answers))
    with pytest.raises(ValueError, match="match"):
        owner_admin.prompt_password(confirm=True)


def test_concurrent_identity_writer_cannot_enter(profile):
    from a4a_mcp.profile_lock import profile_lock
    original = identity.IDENTITY_FILE.read_bytes()
    with profile_lock(identity.IDENTITY_DIR):
        with pytest.raises(ValueError, match="busy"):
            identity.load_or_create_owner_identity()
    assert identity.IDENTITY_FILE.read_bytes() == original


def test_cli_separate_is_explicit_and_does_not_publish(profile, monkeypatch, capsys):
    from a4a_mcp import __main__, owner_admin
    import sys
    _, owner, destination = profile
    monkeypatch.setattr(owner_admin, "prompt_password", lambda **kw: PASSWORD)
    monkeypatch.setattr(sys, "argv", ["a4a_mcp", "owner-separate", "--owner-file", str(destination)])
    __main__.cli_main()
    assert owner.pubkey_hex in capsys.readouterr().out
    assert identity.OWNER_FIELD not in json.loads(identity.IDENTITY_FILE.read_text())


def test_cli_issue_uses_vault_without_legacy_owner_loader(profile, monkeypatch, capsys):
    from a4a_mcp import __main__, owner_admin
    from a4a import Agent
    import sys
    agent, owner, destination = profile
    owner_admin.separate_owner(destination, PASSWORD)
    monkeypatch.setattr(owner_admin, "prompt_password", lambda **kw: PASSWORD)
    def forbidden():
        raise AssertionError("legacy owner loader invoked")
    monkeypatch.setattr(identity, "load_or_create_owner_identity", forbidden)
    seen = []
    async def enter(self):
        return self
    async def leave(self, *args):
        pass
    async def register(self, signing_owner, **kwargs):
        seen.append((self.pubkey, signing_owner.pubkey_hex, kwargs["days"]))
        return "test-mandate-id"
    monkeypatch.setattr(Agent, "__aenter__", enter)
    monkeypatch.setattr(Agent, "__aexit__", leave)
    monkeypatch.setattr(Agent, "ensure_registered", register)
    monkeypatch.setattr(sys, "argv", ["a4a_mcp", "issue-mandate", "--owner-file", str(destination), "--days", "1"])
    __main__.cli_main()
    output = capsys.readouterr().out
    assert seen == [(agent.pubkey_hex, owner.pubkey_hex, 1)]
    assert "test-mandate-id" in output
    assert owner.privkey_hex not in output
    assert PASSWORD not in output


def test_cli_bad_arguments_do_not_create_identity(tmp_path, monkeypatch, capsys):
    from a4a_mcp import __main__
    import sys
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / "missing")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / "missing" / "identity.json")
    monkeypatch.setattr(sys, "argv", ["a4a_mcp", "issue-mandate", "--password", "not-accepted"])
    with pytest.raises(SystemExit):
        __main__.cli_main()
    assert not identity.IDENTITY_FILE.exists()
    assert "not-accepted" not in capsys.readouterr().err


def test_failed_readback_never_removes_source_key(profile, monkeypatch):
    from a4a_mcp import owner_admin
    _, _, destination = profile
    original = identity.IDENTITY_FILE.read_bytes()
    def reject(*args):
        raise ValueError("test authentication failure")
    monkeypatch.setattr(owner_admin, "open_owner_key", reject)
    with pytest.raises(ValueError, match="authentication"):
        owner_admin.separate_owner(destination, PASSWORD)
    assert identity.IDENTITY_FILE.read_bytes() == original


def test_noncooperating_writer_is_not_overwritten(profile, monkeypatch):
    from a4a_mcp import owner_admin
    _, _, destination = profile
    changed = json.loads(identity.IDENTITY_FILE.read_text())
    changed["custom"]["concurrent"] = True
    original_open = owner_admin.open_owner_key
    def open_and_change(*args):
        identity.IDENTITY_FILE.write_text(json.dumps(changed))
        return original_open(*args)
    monkeypatch.setattr(owner_admin, "open_owner_key", open_and_change)
    with pytest.raises(ValueError, match="changed"):
        owner_admin.separate_owner(destination, PASSWORD)
    assert json.loads(identity.IDENTITY_FILE.read_text()) == changed
    assert not list(identity.IDENTITY_DIR.glob(".identity-*.tmp"))


def test_mismatched_legacy_owner_binding_is_not_exported(profile):
    from a4a_mcp.owner_admin import separate_owner
    _, _, destination = profile
    data = json.loads(identity.IDENTITY_FILE.read_text())
    data["owner_pubkey_hex"] = Keys().pubkey_hex
    identity.IDENTITY_FILE.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="binding"):
        separate_owner(destination, PASSWORD)
    assert not destination.exists()


def test_invalid_owner_secret_fails_before_key_construction(profile, monkeypatch):
    from a4a_mcp import owner_admin
    _, _, destination = profile
    data = json.loads(identity.IDENTITY_FILE.read_text())
    invalid = "short"
    data[identity.OWNER_FIELD] = invalid
    identity.IDENTITY_FILE.write_text(json.dumps(data))
    real_keys = owner_admin.Keys

    def checked(value):
        if value == invalid:
            pytest.fail("invalid owner secret reached key constructor")
        return real_keys(value)

    monkeypatch.setattr(owner_admin, "Keys", checked)
    with pytest.raises(ValueError, match="distinct existing agent/owner"):
        owner_admin.separate_owner(destination, PASSWORD)
    assert not destination.exists()


def test_agent_and_owner_must_be_distinct(profile):
    from a4a_mcp import owner_admin
    agent, _, destination = profile
    data = json.loads(identity.IDENTITY_FILE.read_text())
    data[identity.OWNER_FIELD] = agent.privkey_hex
    data["owner_pubkey_hex"] = agent.pubkey_hex
    identity.IDENTITY_FILE.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="distinct existing agent/owner"):
        owner_admin.separate_owner(destination, PASSWORD)
    assert not destination.exists()


def test_insecure_password_fallback_is_refused(monkeypatch):
    from a4a_mcp import owner_admin
    import warnings
    monkeypatch.setattr(owner_admin.sys.stdin, "isatty", lambda: True)
    def fallback(*args):
        warnings.warn("echo would be enabled", owner_admin.getpass.GetPassWarning)
        raise AssertionError("must not reach plaintext fallback")
    monkeypatch.setattr(owner_admin.getpass, "getpass", fallback)
    with pytest.raises(ValueError, match="secure password"):
        owner_admin.prompt_password()


@pytest.mark.parametrize("path", ["", " ", "\t"])
def test_explicit_empty_vault_path_never_falls_back_to_legacy(tmp_path, monkeypatch, path):
    from a4a_mcp import __main__, owner_admin
    import sys
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / "missing")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / "missing" / "identity.json")
    def forbidden(*args, **kwargs):
        raise AssertionError("empty vault path must fail before identity access or password input")
    monkeypatch.setattr(identity, "load_or_create_identity", forbidden)
    monkeypatch.setattr(identity, "load_or_create_owner_identity", forbidden)
    monkeypatch.setattr(owner_admin, "prompt_password", forbidden)
    monkeypatch.setattr(sys, "argv", ["a4a_mcp", "issue-mandate", "--owner-file", path])
    with pytest.raises(SystemExit, match="empty"):
        __main__.cli_main()
    assert not identity.IDENTITY_FILE.exists()
