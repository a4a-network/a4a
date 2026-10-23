"""Store the local identity used by the A4A MCP server.

The legacy model keeps TWO keys in one file: owner and agent. Explicit
owner-separate mode moves the owner's secret to an encrypted external file while
retaining the public binding.

The original MVP used one self-owned agent key and no delegation. A compromised
worker key could not be revoked because it was also the identity. Changing the
address, and losing all reputation and connections, was the only recovery.

A separate owner key splits the long-lived identity from the worker key. The owner
signs an agent mandate (kind 31000) and is otherwise unused; a compromised worker
key can be revoked with kind 31007 without replacing the identity.

This is independent of legal identity: kind 31021 attests the owner's key but does
not determine whether the key exists.

During migration, the existing agent key remains UNCHANGED. Replacing it would
change the address and lose reputation. The owner key is added alongside it.

No MCP tool ever logs or returns a private key.
"""
import json
import logging
import os
import stat
import tempfile
from pathlib import Path

from a4a import keyfile
from a4a.keys import Keys
from .profile_lock import profile_lock

log = logging.getLogger(__name__)

IDENTITY_DIR = Path(os.environ.get("A4A_HOME", str(Path.home() / ".a4a")))
IDENTITY_FILE = IDENTITY_DIR / "identity.json"


def _restrict_permissions(path: Path) -> None:
    """Restrict private-key file access and VERIFY the resulting protection.

    This used to be best-effort ``os.chmod`` with swallowed errors. Windows chmod
    affects only the read-only attribute, not access control, and raises no error.
    The file therefore remained exposed while documentation promised mode 0600;
    a 2026-08-30 measurement found mode 0666 on the working machine.

    Protection now uses chmod on POSIX and icacls on Windows, verifies the result,
    and reports failure loudly. Do not terminate solely because hardening failed:
    an agent without its key is useless, while one with an exposed key still runs.
    Never fail silently, however.
    """
    ok, detail = keyfile.harden_and_check(path)
    if not ok:
        log.warning(
            "KEY FILE IS NOT PROTECTED: %s. The private key is the agent: losing "
            "it loses the address and reputation; exposing it loses control. "
            "Restrict access manually",
            detail,
        )


def load_or_create_identity() -> Keys:
    """Load/create the working agent under the cooperating local writer lock."""
    with profile_lock(IDENTITY_DIR):
        return _load_or_create_identity()


def _identity_stat():
    """Reject linked/nonregular targets before reading or changing permissions."""
    try:
        info = IDENTITY_FILE.lstat()
    except FileNotFoundError:
        return None
    _check_identity_stat(info)
    return info


def _check_identity_stat(info) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise ValueError("identity.json is linked or not a regular file; access is closed")


def _read_identity(*, harden: bool = False) -> dict | None:
    info = _identity_stat()
    if info is None:
        return None
    fd = os.open(IDENTITY_FILE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        opened = os.fstat(stream.fileno())
        _check_identity_stat(opened)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("identity.json changed while opening; access is closed")
        if harden:
            _restrict_permissions(IDENTITY_FILE)
        data = json.load(stream)
        if not isinstance(data, dict):
            raise ValueError("invalid identity.json: expected a JSON object; no key was generated")
        return data


def _refuse_identity_regeneration() -> None:
    # Only inspect existence: damaged/disabled policies and dangling links still
    # indicate an existing profile. Never parse or modify surviving inbox state.
    for path in (IDENTITY_DIR / "inbox-policy.json",
                 IDENTITY_DIR / "inbox" / "inbox.sqlite3"):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise ValueError(
            "identity.json is missing but persisted inbox state exists; "
            "restore the original identity.json before continuing; "
            "no replacement identity was written"
        )


def _write_identity(data: dict, *, create: bool = False) -> None:
    """Publish a complete private file; caller must hold the profile lock."""
    fd, name = tempfile.mkstemp(prefix=".identity-", suffix=".tmp", dir=IDENTITY_DIR)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            # Verify the empty file before writing secrets; do not expose diagnostics.
            try:
                secured, _ = keyfile.harden_and_check(temporary)
            except Exception:
                secured = False
            if not secured:
                raise ValueError(
                    "identity.json permissions could not be secured; no identity was written"
                ) from None
            json.dump(data, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        existing = _identity_stat()
        if create:
            if existing is not None:
                raise ValueError("identity.json appeared during creation; retry without replacing it")
            _refuse_identity_regeneration()
        os.replace(temporary, IDENTITY_FILE)
        if os.name != "nt":
            directory_fd = os.open(IDENTITY_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _load_or_create_identity() -> Keys:
    """Load ``~/.a4a/identity.json`` or generate and persist a new ``Keys``.

    File format: ``{"privkey_hex": "...", "pubkey_hex": "..."}``.
    ``pubkey_hex`` exists for human inspection and debugging; ``privkey_hex`` is
    authoritative and always derives the public key during loading.
    """
    data = _read_identity(harden=True)
    if data is not None:
        privkey_hex = data.get("privkey_hex")
        if not privkey_hex:
            raise ValueError(f"corrupt identity file: {IDENTITY_FILE} (privkey_hex is missing)")
        return Keys(privkey_hex)

    _refuse_identity_regeneration()
    keys = Keys()
    # mode=0o700 applies on POSIX and is harmlessly ignored on Windows.
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {"privkey_hex": keys.privkey_hex, "pubkey_hex": keys.pubkey_hex}
    _write_identity(payload, create=True)
    return keys


def identity_path() -> Path:
    return IDENTITY_FILE


# --- File keys -------------------------------------------------------------------
#
# The encrypted-file key lives HERE between ``a4a_encrypt_file`` and
# ``a4a_send_file``, never in model context. Encryption is meant to expose the key
# only to the recipient, not to the host transcript or logs. This store uses the
# identity-file pattern: mode 0600 at creation, atomic replacement, and verified
# permissions (finding 42). Successful sending deletes the entry. Consequently, a
# blob can be sent only from the machine where it was encrypted.

def _file_keys_path() -> Path:
    return IDENTITY_DIR / "file-keys.json"


class FileKeyStoreError(ValueError):
    """The local file-key store was not read or changed as requested."""


_MAX_FILE_KEYS_BYTES = 4 * 1024 * 1024


def _file_keys_stat(path: Path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise FileKeyStoreError(
            "file-keys.json is linked or not a regular file; access is closed")
    if info.st_size > _MAX_FILE_KEYS_BYTES:
        raise FileKeyStoreError("file-keys.json is too large; access is closed")
    return info


def _read_file_keys() -> dict:
    path = _file_keys_path()
    info = _file_keys_stat(path)
    if info is None:
        return {}
    private, _ = keyfile.is_private(path)
    if not private:
        try:
            private, _ = keyfile.harden_and_check(path)
        except Exception:
            private = False
        if not private:
            raise FileKeyStoreError(
                "file-keys.json permissions are not private; access is closed") from None
        # Hardening is a path operation. Re-establish the object identity before open.
        info = _file_keys_stat(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or getattr(opened, "st_file_attributes", 0) & 0x400
                    or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
                raise FileKeyStoreError(
                    "file-keys.json changed while opening; access is closed")
            data = json.load(stream)
    except FileKeyStoreError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise FileKeyStoreError(
            "file-keys.json is unreadable; no file keys were changed") from exc
    if not isinstance(data, dict):
        raise FileKeyStoreError(
            "file-keys.json must contain a JSON object; no file keys were changed")
    return data


def _write_file_keys(data: dict) -> None:
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = _file_keys_path()
    before = _file_keys_stat(path)
    fd, name = tempfile.mkstemp(prefix=".file-keys-", suffix=".tmp", dir=IDENTITY_DIR)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            try:
                secured, _ = keyfile.harden_and_check(temporary)
            except Exception:
                secured = False
            if not secured:
                raise FileKeyStoreError(
                    "file-keys.json permissions could not be secured; no file keys were changed"
                ) from None
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        current = _file_keys_stat(path)
        if ((before is None) != (current is None)
                or (before is not None and
                    (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino))):
            raise FileKeyStoreError(
                "file-keys.json changed before publication; no file keys were changed")
        os.replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(IDENTITY_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def store_file_key(blob_sha256: str, key: str, *, size: int, name: str) -> None:
    """Store a blob key by the SHA-256 value included in its reference."""
    with profile_lock(IDENTITY_DIR):
        data = _read_file_keys()
        data[blob_sha256] = {"key": key, "size": size, "name": name}
        _write_file_keys(data)


def peek_file_key(blob_sha256: str) -> dict | None:
    return _read_file_keys().get(blob_sha256)


def pop_file_key(blob_sha256: str) -> None:
    with profile_lock(IDENTITY_DIR):
        data = _read_file_keys()
        if blob_sha256 in data:
            del data[blob_sha256]
            _write_file_keys(data)


OWNER_FIELD = "owner_privkey_hex"


def owner_public_key() -> str | None:
    """Read the configured public owner binding without loading an owner Keys."""
    from a4a.event import is_canonical_pubkey

    data = _read_identity()
    if data is None:
        return None
    value = data.get("owner_pubkey_hex")
    if value is None:
        return None
    if not isinstance(value, str) or not is_canonical_pubkey(value):
        raise ValueError("invalid public owner binding")
    return value


def load_or_create_owner_identity() -> Keys:
    """Legacy owner access; an external owner binding must never be replaced."""
    with profile_lock(IDENTITY_DIR):
        return _load_or_create_owner_identity()


def _load_or_create_owner_identity() -> Keys:
    """Load the OWNER key used primarily to sign the agent mandate.

    It resides beside the agent key in the same file. The existing agent key remains
    untouched because changing its address would lose all associated reputation and
    connections.
    """
    data = _read_identity()
    if data is not None:
        existing = data.get(OWNER_FIELD)
        if existing:
            return Keys(existing)
        if "owner_pubkey_hex" in data:
            raise ValueError("owner key is external; use issue-mandate --owner-file from the owner terminal")
    else:
        # Create the agent key first; it creates the identity file with it.
        _load_or_create_identity()
        data = _read_identity()

    owner = Keys()
    data[OWNER_FIELD] = owner.privkey_hex
    data["owner_pubkey_hex"] = owner.pubkey_hex
    _write_identity(data)
    return owner
