"""SQLite metadata for one blob. The ciphertext itself never enters this file."""
from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from a4a import keyfile
from a4a.event import is_canonical_pubkey


class StoreError(RuntimeError):
    """Metadata could not be recorded. Callers must not report success."""


_LOGON_GRANT = re.compile(r"extraneous SID in DACL: (S-1-5-5-[0-9]+-[0-9]+)")


def _remove_new_file_logon_grant(path: Path, detail: str) -> bool:
    """Tighten one newly created empty DB file; never rewrite an existing ACL.

    Some Windows tokens create files with an explicit logon-session RX grant even
    under a private parent. `keyfile.harden_and_check` correctly refuses that
    grant. Remove only this exact SID before SQLite writes any metadata, then let
    the full independent ACL check decide whether the file is safe.
    """
    match = _LOGON_GRANT.fullmatch(detail)
    if match is None:
        return False
    try:
        result = subprocess.run(
            ["icacls", str(path), "/remove:g", f"*{match.group(1)}"],
            capture_output=True, text=True, errors="replace")
    except OSError:
        return False
    return result.returncode == 0


@dataclass(frozen=True)
class BlobRecord:
    sha256: str
    sender: str
    recipient: str
    size: int
    uploaded_at: int
    expires_at: int
    fetched_at: int | None = None
    fetched_by: str | None = None
    ready: bool = True
    upload_token: str = ""


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise StoreError("metadata directory must not be a symlink")
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise StoreError("cannot create metadata directory") from exc
    if os.name == "nt":
        ok, _detail = keyfile.harden_and_check(path, force=True)
    else:
        os.chmod(path, 0o700)
        ok, _detail = keyfile.is_private(path)
    if not ok:
        raise StoreError("cannot protect metadata directory")


def _row(row: sqlite3.Row) -> BlobRecord:
    return BlobRecord(
        sha256=row["sha256"],
        sender=row["sender"],
        recipient=row["recipient"],
        size=int(row["size"]),
        uploaded_at=int(row["uploaded_at"]),
        expires_at=int(row["expires_at"]),
        fetched_at=None if row["fetched_at"] is None else int(row["fetched_at"]),
        fetched_by=row["fetched_by"],
        ready=bool(row["ready"]),
        upload_token=row["upload_token"],
    )


class MetadataStore:
    """One private database file. Opening it follows the delivery-journal rules."""

    def __init__(self, directory: Path | str):
        directory = Path(directory)
        _private_directory(directory)
        self.path = directory / "metadata.sqlite3"
        if self.path.is_symlink():
            raise StoreError("metadata database must not be a symlink")
        created = False
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
            created = True
        ok, detail = keyfile.harden_and_check(self.path, force=True)
        if not ok and created and os.name == "nt" and _remove_new_file_logon_grant(self.path, detail):
            ok, detail = keyfile.harden_and_check(self.path, force=True)
        if not ok:
            raise StoreError("cannot protect metadata database")
        if not self.path.is_file():
            raise StoreError("metadata database must be a regular file")
        self._lock = threading.Lock()
        # One connection shared across request threads; every use goes through self._lock.
        self.db = sqlite3.connect(self.path, timeout=5, isolation_level=None,
                                  check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        try:
            # DELETE, not WAL: a WAL file would be a second copy of the metadata
            # outside the file whose permissions were just restricted.
            mode = self.db.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            if str(mode).lower() != "delete":
                raise StoreError("metadata database journal must stay inside the database file")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("""CREATE TABLE IF NOT EXISTS blobs (
                sha256 TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                size INTEGER NOT NULL,
                uploaded_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                fetched_at INTEGER,
                fetched_by TEXT
            )""")
            # Old rows were written as completed uploads. Migrate under the same
            # database lock used for admission, including across service processes.
            with self._transaction():
                columns = {row[1] for row in self.db.execute("PRAGMA table_info(blobs)")}
                if "ready" not in columns:
                    self.db.execute("ALTER TABLE blobs ADD COLUMN ready INTEGER NOT NULL DEFAULT 1")
                if "upload_token" not in columns:
                    self.db.execute("ALTER TABLE blobs ADD COLUMN upload_token TEXT NOT NULL DEFAULT ''")
        except BaseException:
            self.db.close()
            raise

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def _transaction(self):
        with self._lock:
            try:
                self.db.execute("BEGIN IMMEDIATE")
                yield
                self.db.execute("COMMIT")
            except BaseException as exc:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                if isinstance(exc, sqlite3.Error):
                    raise StoreError("metadata database operation failed") from exc
                raise

    def get(self, sha256: str) -> BlobRecord | None:
        with self._transaction():
            row = self.db.execute("SELECT * FROM blobs WHERE sha256=?", (sha256,)).fetchone()
        return None if row is None else _row(row)

    def insert_or_conflict(self, record: BlobRecord, now: int) -> tuple[str, BlobRecord]:
        """Insert ``record`` or return ``exists`` / ``conflict`` for the current row.

        ``exists`` means the same sender and recipient still have an unexpired row.
        Anything else that already occupies the digest is ``conflict`` and is left
        unchanged, including an expired row.
        """
        if not is_canonical_pubkey(record.sender) or not is_canonical_pubkey(record.recipient):
            raise StoreError("blob parties must be lowercase hex public keys")
        with self._transaction():
            current = self.db.execute(
                "SELECT * FROM blobs WHERE sha256=?", (record.sha256,)).fetchone()
            if current is not None:
                existing = _row(current)
                same = (existing.sender == record.sender
                        and existing.recipient == record.recipient
                        and existing.expires_at > now)
                return ("exists" if same else "conflict"), existing
            self.db.execute(
                "INSERT INTO blobs (sha256, sender, recipient, size, uploaded_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (record.sha256, record.sender, record.recipient, record.size,
                 record.uploaded_at, record.expires_at))
            return "created", record

    def reserve_upload(self, record: BlobRecord, now: int, since: int,
                       quota: int) -> tuple[str, BlobRecord]:
        """Admit one upload atomically; live unfinished reservations stay charged.

        Idempotent retries do not add bytes and may finish an interrupted upload.
        The generation token prevents an old failed writer from deleting or
        completing a later reservation for the same digest.
        """
        if not is_canonical_pubkey(record.sender) or not is_canonical_pubkey(record.recipient):
            raise StoreError("blob parties must be lowercase hex public keys")
        with self._transaction():
            current = self.db.execute("SELECT * FROM blobs WHERE sha256=?",
                                      (record.sha256,)).fetchone()
            if current is not None:
                existing = _row(current)
                same = (existing.sender == record.sender
                        and existing.recipient == record.recipient
                        and existing.expires_at > now)
                return ("exists" if same else "conflict"), existing
            used = self.db.execute(
                "SELECT COALESCE(SUM(size), 0) FROM blobs "
                "WHERE sender=? AND (uploaded_at>? OR (ready=0 AND expires_at>?))",
                (record.sender, since, now)).fetchone()[0]
            if int(used) + record.size > quota:
                return "quota", record
            token = uuid.uuid4().hex
            self.db.execute(
                "INSERT INTO blobs (sha256,sender,recipient,size,uploaded_at,expires_at,ready,upload_token) "
                "VALUES (?,?,?,?,?,?,0,?)",
                (record.sha256, record.sender, record.recipient, record.size,
                 record.uploaded_at, record.expires_at, token))
            return "created", _row(self.db.execute(
                "SELECT * FROM blobs WHERE sha256=?", (record.sha256,)).fetchone())

    def finish_upload(self, record: BlobRecord, now: int) -> BlobRecord:
        with self._transaction():
            current = self.db.execute(
                "SELECT * FROM blobs WHERE sha256=? AND upload_token=?",
                (record.sha256, record.upload_token)).fetchone()
            if current is None:
                raise StoreError("upload reservation no longer exists")
            if int(current["expires_at"]) <= now:
                raise StoreError("upload reservation expired")
            self.db.execute("UPDATE blobs SET ready=1 WHERE sha256=? AND upload_token=?",
                            (record.sha256, record.upload_token))
            return _row(self.db.execute(
                "SELECT * FROM blobs WHERE sha256=? AND upload_token=?",
                (record.sha256, record.upload_token)).fetchone())

    def cancel_upload(self, record: BlobRecord) -> None:
        """Release only this unfinished generation, never a completed duplicate."""
        with self._transaction():
            self.db.execute("DELETE FROM blobs WHERE sha256=? AND upload_token=? AND ready=0",
                            (record.sha256, record.upload_token))

    def bytes_uploaded_since(self, sender: str, since: int) -> int:
        with self._transaction():
            row = self.db.execute(
                "SELECT COALESCE(SUM(size), 0) FROM blobs WHERE sender=? AND uploaded_at>?",
                (sender, since)).fetchone()
        return int(row[0])

    def delete(self, sha256: str) -> None:
        with self._transaction():
            self.db.execute("DELETE FROM blobs WHERE sha256=?", (sha256,))

    def mark_fetched(self, sha256: str, fetched_by: str, when: int) -> BlobRecord | None:
        """Record the first fetch. A later fetch does not move the original timestamp."""
        if not is_canonical_pubkey(fetched_by):
            raise StoreError("fetched_by must be a lowercase hex public key")
        with self._transaction():
            self.db.execute(
                "UPDATE blobs SET fetched_at=?, fetched_by=? "
                "WHERE sha256=? AND fetched_at IS NULL",
                (when, fetched_by, sha256))
            row = self.db.execute("SELECT * FROM blobs WHERE sha256=?", (sha256,)).fetchone()
        return None if row is None else _row(row)
