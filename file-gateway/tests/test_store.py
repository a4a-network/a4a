"""Metadata file protection. These checks fail if the database is created loosely."""
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from a4a import keyfile

from a4a_file_gateway import store as store_module
from a4a_file_gateway.store import MetadataStore, StoreError


def test_logon_grant_cleanup_only_targets_exact_logon_sid(monkeypatch, tmp_path):
    calls = []

    def remove(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(store_module.subprocess, "run", remove)
    path = tmp_path / "metadata.sqlite3"
    assert store_module._remove_new_file_logon_grant(
        path, "extraneous SID in DACL: S-1-5-5-0-123")
    assert calls[0][0] == ["icacls", str(path), "/remove:g", "*S-1-5-5-0-123"]
    assert not store_module._remove_new_file_logon_grant(
        path, "extraneous SID in DACL: S-1-5-21-123")
    assert len(calls) == 1


def test_metadata_database_is_created_private(tmp_path):
    store = MetadataStore(tmp_path / "home")
    try:
        assert store.path.is_file()
        assert not store.path.is_symlink()
        assert keyfile.is_private(store.path)[0]
        if os.name != "nt":
            assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    finally:
        store.close()


def test_existing_database_with_foreign_acl_is_not_silently_rewritten(
        tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    database = home / "metadata.sqlite3"
    database.write_bytes(b"")
    harden = keyfile.harden_and_check

    def simulated_acl(path, *, force=False):
        if Path(path) == database:
            return False, "extraneous SID in DACL: S-1-5-5-0-123"
        return harden(path, force=force)

    def must_not_remove(*_args):
        pytest.fail("pre-existing ACL must not be rewritten automatically")

    monkeypatch.setattr(store_module.keyfile, "harden_and_check", simulated_acl)
    monkeypatch.setattr(store_module, "_remove_new_file_logon_grant", must_not_remove)
    with pytest.raises(StoreError, match="cannot protect metadata database"):
        MetadataStore(home)


def test_metadata_database_rejects_a_symlink(tmp_path, monkeypatch):
    home = tmp_path / "home"
    database = home / "metadata.sqlite3"
    original = Path.is_symlink

    def pretend(self):
        if self == database:
            return True
        return original(self)

    monkeypatch.setattr(Path, "is_symlink", pretend)
    with pytest.raises(StoreError, match="metadata database must not be a symlink"):
        MetadataStore(home)


def test_the_store_serves_requests_from_other_threads(tmp_path):
    """ThreadingHTTPServer handles each request in its own thread.

    25.09.2026, first live upload: "SQLite objects created in a thread can only be used in
    that same thread" - every request failed with 503. Calls into the store are serialized
    by its lock, so the connection may be shared across threads.
    """
    import threading
    store = MetadataStore(tmp_path / "home")
    errors = []

    def use():
        try:
            store.get("0" * 64)
        except Exception as exc:  # noqa: BLE001 - the test reports what happened
            errors.append(exc)

    try:
        worker = threading.Thread(target=use)
        worker.start()
        worker.join()
    finally:
        store.close()
    assert errors == []
