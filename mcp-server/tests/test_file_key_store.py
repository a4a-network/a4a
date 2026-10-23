"""Fail-closed local storage for file encryption keys."""
import json
import os
from unittest.mock import Mock

import pytest

from a4a import files
from a4a_mcp import identity, inbox_runtime, server


@pytest.fixture
def home(tmp_path, monkeypatch):
    root = tmp_path / "profile"
    monkeypatch.setattr(identity, "IDENTITY_DIR", root)
    monkeypatch.setattr(identity, "IDENTITY_FILE", root / "identity.json")
    return root


@pytest.mark.parametrize("payload", [b"{broken", b"null", b"[]", b'"text"'])
def test_malformed_store_is_not_treated_as_empty_or_overwritten(home, payload):
    home.mkdir()
    path = identity._file_keys_path()
    path.write_bytes(payload)

    with pytest.raises(identity.FileKeyStoreError, match="file-keys.json"):
        identity.store_file_key("a" * 64, "new-secret", size=1, name="new")
    assert path.read_bytes() == payload
    assert not list(home.glob(".file-keys-*.tmp"))


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_linked_store_is_rejected_without_changing_target(home, tmp_path, kind):
    home.mkdir()
    path = identity._file_keys_path()
    target = tmp_path / "outside.json"
    target.write_text(json.dumps({"outside": "secret"}), encoding="utf-8")
    before = target.read_bytes()
    try:
        if kind == "symlink":
            path.symlink_to(target)
        else:
            path.hardlink_to(target)
    except OSError as exc:
        pytest.skip(f"filesystem does not support {kind}: {exc}")

    with pytest.raises(identity.FileKeyStoreError, match="linked|regular"):
        identity.peek_file_key("a" * 64)
    assert target.read_bytes() == before


def test_failed_hardening_preserves_existing_store(home, monkeypatch):
    identity.store_file_key("a" * 64, "first", size=1, name="one")
    path = identity._file_keys_path()
    before = path.read_bytes()
    original = identity.keyfile.harden_and_check

    def fail_temporary(candidate, *args, **kwargs):
        if str(candidate).endswith(".tmp"):
            return False, "synthetic hardening failure"
        return original(candidate, *args, **kwargs)

    monkeypatch.setattr(identity.keyfile, "harden_and_check", fail_temporary)
    with pytest.raises(identity.FileKeyStoreError, match="permissions could not be secured"):
        identity.store_file_key("b" * 64, "second", size=2, name="two")
    assert path.read_bytes() == before
    assert not list(home.glob(".file-keys-*.tmp"))


def test_oversized_store_is_rejected_before_permissions_or_json(home, monkeypatch):
    home.mkdir()
    path = identity._file_keys_path()
    path.write_bytes(b"{" + b" " * identity._MAX_FILE_KEYS_BYTES)
    monkeypatch.setattr(identity.keyfile, "is_private",
                        lambda _path: pytest.fail("oversized store reached permissions"))

    with pytest.raises(identity.FileKeyStoreError, match="too large"):
        identity.peek_file_key("a" * 64)


def test_store_with_unrepairable_permissions_fails_closed(home, monkeypatch):
    identity.store_file_key("a" * 64, "first", size=1, name="one")
    path = identity._file_keys_path()
    before = path.read_bytes()
    monkeypatch.setattr(identity.keyfile, "is_private", lambda _path: (False, "synthetic"))
    monkeypatch.setattr(identity.keyfile, "harden_and_check",
                        lambda *_args, **_kwargs: (False, "synthetic"))

    with pytest.raises(identity.FileKeyStoreError, match="permissions are not private"):
        identity.peek_file_key("a" * 64)
    assert path.read_bytes() == before


def test_store_changed_between_path_check_and_open_is_rejected(home, monkeypatch):
    identity.store_file_key("a" * 64, "first", size=1, name="one")
    path = identity._file_keys_path()
    before = path.read_bytes()
    actual = path.stat()
    opened = Mock(st_mode=actual.st_mode, st_nlink=1,
                  st_dev=actual.st_dev, st_ino=actual.st_ino + 1,
                  st_file_attributes=0)
    monkeypatch.setattr(identity.os, "fstat", lambda _fd: opened)

    with pytest.raises(identity.FileKeyStoreError, match="changed while opening"):
        identity.peek_file_key("a" * 64)
    assert path.read_bytes() == before


def test_store_appearing_before_publish_is_not_overwritten(home, monkeypatch):
    path = identity._file_keys_path()
    external = b'{"external":"writer"}'
    fsync = os.fsync

    def appears(fd):
        fsync(fd)
        if not path.exists():
            path.write_bytes(external)

    monkeypatch.setattr(identity.os, "fsync", appears)
    with pytest.raises(identity.FileKeyStoreError, match="changed before publication"):
        identity.store_file_key("a" * 64, "first", size=1, name="one")
    assert path.read_bytes() == external
    assert not list(home.glob(".file-keys-*.tmp"))


async def test_send_reports_unreadable_store_instead_of_missing_key(
        home, tmp_path, monkeypatch):
    blob_path = tmp_path / "payload.a4a"
    blob_path.write_bytes(b"encrypted-looking blob")
    monkeypatch.setattr(inbox_runtime, "require_legacy_send", lambda _peer: None)
    monkeypatch.setattr(identity, "peek_file_key",
                        lambda _sha: (_ for _ in ()).throw(
                            identity.FileKeyStoreError("synthetic unreadable store")))
    server._last_unreachable = None

    output = await server.a4a_send_file(
        "a" * 64, str(blob_path), "https://example.org/payload")
    assert "local file-key storage failed" in output
    assert "Do not report the file as sent" in output
    assert "not found" not in output.lower()


async def test_encrypt_reports_key_store_failure_and_forbids_using_blob(
        home, tmp_path, monkeypatch):
    source = tmp_path / "payload.txt"
    source.write_bytes(b"private payload")
    monkeypatch.setattr(identity, "store_file_key",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(
                            identity.FileKeyStoreError("synthetic unreadable store")))

    output = await server.a4a_encrypt_file(str(source))
    blob_path = source.with_name(source.name + ".a4a")
    assert blob_path.exists()
    assert "key was not stored" in output
    assert "Do not upload or send" in output
    assert files.sha256_hex(blob_path.read_bytes()) not in output
