"""OS-held receiver ownership for one private local inbox, not a distributed lease."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import os
from pathlib import Path
import stat
import sys

from .inbox import InboxError


__all__ = ["InboxReceiverBusy", "receiver_lock"]


class InboxReceiverBusy(InboxError):
    """Another receiver owns this inbox; do not overwrite its health state."""


def _check_regular(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise InboxError("unsafe inbox receiver lock file") from None


def _check_identity(path, fd, before=None):
    opened = os.fstat(fd)
    current = path.lstat()
    _check_regular(opened)
    _check_regular(current)
    if (not os.path.samestat(opened, current)
            or (before is not None and not os.path.samestat(opened, before))):
        raise InboxError("inbox receiver lock file changed") from None


def _acquire(fd):
    try:
        if os.name == "nt":
            import msvcrt
            # Byte-range locks may extend beyond EOF; never write or truncate.
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if (error.errno in (errno.EACCES, errno.EAGAIN)
                or (os.name == "nt" and error.errno == errno.EDEADLK)):
            raise InboxReceiverBusy("inbox receiver is already running") from None
        raise


def _release(fd, locked):
    try:
        if locked:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextmanager
def receiver_lock(directory):
    """Fail immediately if another receiver owns this inbox directory.

    InboxStore must already have made the directory private. Enter before any
    network or health work, and handle InboxReceiverBusy without changing health.
    The persistent .receiver.lock file is never removed: deleting it could let
    another process lock a different inode while an existing owner still runs.
    The OS releases ownership on process death; no stale PID recovery is needed.
    """
    fd = None
    locked = False
    try:
        try:
            path = Path(directory) / ".receiver.lock"
            try:
                before = path.lstat()
            except FileNotFoundError:
                before = None
            if before is not None:
                _check_regular(before)
            # NONBLOCK also avoids hanging if a FIFO replaces the path at open.
            flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
            fd = os.open(path, flags, 0o600)
            _check_identity(path, fd, before)
            _acquire(fd)
            locked = True
            _check_identity(path, fd)
        except (OSError, ValueError, TypeError):
            raise InboxError("cannot acquire inbox receiver lock") from None
        yield
    finally:
        if fd is not None:
            error_in_flight = sys.exc_info()[0] is not None
            try:
                _release(fd, locked)
            except OSError:
                if not error_in_flight:
                    raise InboxError("cannot release inbox receiver lock") from None
