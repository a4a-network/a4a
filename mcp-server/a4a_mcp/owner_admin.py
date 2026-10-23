"""Explicit, interactive owner-key separation; never invoked by an MCP tool."""
import getpass
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unicodedata
import warnings

from a4a import keyfile
from a4a.keys import Keys

from . import identity
from .owner_vault import open_owner_key, seal_owner_key
from .profile_lock import profile_lock


def prompt_password(*, confirm=False):
    if not sys.stdin.isatty():
        raise ValueError("owner password requires an interactive terminal; no stdin/env/argv password input")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            password = getpass.getpass("Owner vault passphrase: ")
            if confirm:
                second = getpass.getpass("Repeat passphrase: ")
                if unicodedata.normalize("NFKC", password) != unicodedata.normalize("NFKC", second):
                    raise ValueError("passphrases do not match")
        except (getpass.GetPassWarning, EOFError):
            raise ValueError("secure password input unavailable; use an interactive terminal") from None
    return password


def _safe_path(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("owner file requires an absolute path without '..'")
    for part in (*reversed(path.parents), path):
        try:
            info = part.lstat()
        except FileNotFoundError:
            if part == path:
                continue
            raise ValueError("owner file parent directory must already exist") from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("links and reparse points are not allowed for owner operations")
        if part == path and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise ValueError("owner operation requires a regular, unlinked file")
    return path


def _vault_path(path):
    path = _safe_path(path)
    if path.resolve().is_relative_to(identity.IDENTITY_DIR.resolve()):
        raise ValueError("owner file must be outside A4A_HOME")
    return path


def _private(path):
    if not keyfile.harden_and_check(path, force=True)[0]:
        raise ValueError("cannot establish private file permissions; source identity is unchanged")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _read(path, limit):
    _safe_path(path)
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("owner file exceeds size limit")
    try:
        data = json.loads(raw, object_pairs_hook=_pairs)
        if not isinstance(data, dict):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ValueError("invalid identity or vault JSON") from None
    return data, raw


def _profile():
    data, raw = _read(identity.IDENTITY_FILE, 1024 * 1024)
    try:
        secret = data["privkey_hex"]
        if not isinstance(secret, str) or len(secret) != 64:
            raise ValueError()
        agent = Keys(secret)
        if data.get("pubkey_hex") != agent.pubkey_hex:
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        raise ValueError("invalid agent identity; no key was generated") from None
    return data, raw


def _sync_directory(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _write_fd(fd, path, data):
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        # Harden the empty file before any private material reaches it on Windows.
        _private(path)
        json.dump(data, stream, indent=2, allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
    if not keyfile.is_private(path)[0]:
        raise ValueError("file permissions changed during owner operation")


def separate_owner(destination, password):
    """Vault first, verified read-back second, atomic working-profile replacement last.

    Stop older MCP processes before use: they do not participate in the new lock.
    On an interrupted attempt keep the vault and retry with a NEW destination.
    """
    destination = _vault_path(destination)
    _safe_path(identity.IDENTITY_FILE)
    temporary = None
    try:
        with profile_lock(identity.IDENTITY_DIR):
            data, original = _profile()
            _private(identity.IDENTITY_FILE)
            if destination.exists():
                raise ValueError("owner file already exists; choose a new destination, never overwrite a backup")
            try:
                secret = data[identity.OWNER_FIELD]
                if not isinstance(secret, str) or len(secret) != 64:
                    raise ValueError()
                owner = Keys(secret)
                if data.get("owner_pubkey_hex") != owner.pubkey_hex:
                    raise ValueError()
                if data["pubkey_hex"] == owner.pubkey_hex:
                    raise ValueError()
            except (KeyError, ValueError, TypeError):
                raise ValueError("separation requires distinct existing agent/owner keys with a valid public binding") from None
            payload = seal_owner_key(owner, password)
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            _write_fd(fd, destination, payload)
            reread, _ = _read(destination, 4096)
            if open_owner_key(reread, password).pubkey_hex != owner.pubkey_hex:
                raise ValueError("owner vault verification failed; source identity is unchanged")
            _sync_directory(destination.parent)
            del data[identity.OWNER_FIELD]
            fd, name = tempfile.mkstemp(prefix=".identity-", suffix=".tmp", dir=identity.IDENTITY_DIR)
            temporary = Path(name)
            _write_fd(fd, temporary, data)
            # Also detect old/noncooperating writers before replacing the source.
            if _read(identity.IDENTITY_FILE, 1024 * 1024)[1] != original:
                raise ValueError("identity changed during separation; source was not replaced")
            os.replace(temporary, identity.IDENTITY_FILE)
            temporary = None
            _sync_directory(identity.IDENTITY_DIR)
            return owner.pubkey_hex
    except OSError:
        raise ValueError("owner operation failed; keep any created vault and check the source before retrying") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def unlock_owner(path, password):
    """Unlock only a vault matching this existing working profile's public owner."""
    path = _vault_path(path)
    try:
        data, _ = _profile()
        payload, _ = _read(path, 4096)
        _private(path)
        owner = open_owner_key(payload, password)
        if data.get("owner_pubkey_hex") != owner.pubkey_hex:
            raise ValueError("owner vault does not match the profile's public binding")
        return owner
    except OSError:
        raise ValueError("cannot read owner vault or existing identity; no key was generated") from None
