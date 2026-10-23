"""Project-agent identity: a private key stored in a mode-0600 file.

``A4A_AGENT_HOME`` selects a directory intentionally separate from the MCP
server's ``~/.a4a`` directory. They are distinct network agents and must not
share identities.

Read the environment variable on every call rather than at import time so tests
and launches with a different directory do not depend on import order.
"""
import json
import logging
import os
import stat
from pathlib import Path

from a4a import keyfile
from a4a.keys import Keys


log = logging.getLogger(__name__)


def identity_dir() -> Path:
    return Path(os.environ.get("A4A_AGENT_HOME", str(Path.home() / ".a4a-project-agent")))


def identity_path() -> Path:
    return identity_dir() / "identity.json"


def _protect(path: Path) -> None:
    """Restrict access to the key file and VERIFY the resulting permissions.

    This used to call ``os.chmod`` and swallow exceptions. On Windows, chmod only
    changes the read-only attribute and does not restrict access, yet raises no
    exception. The file therefore remained exposed while documentation promised
    mode 0600. A 2026-08-30 measurement found mode 0666 on the working machine.

    Do not terminate solely because hardening failed: an agent without its key is
    useless, while one with an exposed key can still operate. Never fail silently,
    however, or the protection would exist only in a comment.
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
    """Load the agent key, or create and persist a new one.

    A corrupt file is an error, not permission to generate a new key. A new key
    means a new address and loss of all reputation and connections tied to the
    previous one. Fail with an actionable message (review 2026-08-28, A19).
    """
    path = identity_path()
    if path.exists():
        # Check existing files too: an older version may have applied only
        # best-effort protection, or the file may have moved from another machine.
        _protect(path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            privkey = data["privkey"]
        except (ValueError, KeyError, TypeError) as e:
            raise ValueError(
                f"corrupt key file: {path} ({e}). A new key must not be generated "
                f"because it would create a different agent address. Restore the "
                f"file from a backup."
            ) from e
        return Keys(privkey)
    identity_dir().mkdir(parents=True, exist_ok=True)
    keys = Keys()
    # Write to a temporary file and replace atomically. A direct write can leave an
    # empty file if the process stops mid-write, breaking every subsequent start.
    # Apply mode 0600 at creation so the key is never briefly world-readable.
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"privkey": keys.privkey_hex}, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _protect(path)
    return keys


OWNER_FIELD = "owner_privkey"


def load_or_create_owner_identity() -> Keys:
    """Load the project agent OWNER key used primarily to sign its mandate.

    Previously the agent owned itself, so a compromised worker key could not be
    revoked: it was also the identity, leaving address rotation and loss of
    reputation and connections as the only recovery. A separate owner key splits
    the long-lived identity from the worker key (2026-08-29).

    It is stored beside the agent key in the same file. The agent key is NOT
    changed: preventing that address loss is the reason for this separation.
    """
    path = identity_path()
    data: dict = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as e:
            raise ValueError(f"corrupt key file: {path} ({e})") from e
        existing = data.get(OWNER_FIELD)
        if existing:
            return Keys(existing)
    else:
        load_or_create_identity()
        data = json.loads(path.read_text(encoding="utf-8"))

    owner = Keys()
    data[OWNER_FIELD] = owner.privkey_hex
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _protect(path)
    return owner
