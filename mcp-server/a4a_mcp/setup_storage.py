"""Private installer state and checked paths; never erase identities or backups."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from a4a import keyfile


def secure_new_empty(path, *, directory=False):
    """Set an exact private DACL only on our newly created, empty object.

    Windows CRT temporary files can carry an explicit logon-session ACE. Never
    broaden the SDK allowlist or remove permissions from existing owner files.
    """
    if os.name != 'nt':
        os.chmod(path, 0o700 if directory else 0o600)
        return
    checked_path(path)
    empty = path.is_dir() and not any(path.iterdir()) if directory else read_regular(path) == b''
    if not empty:
        raise ValueError('only a new empty object may receive this DACL')
    import ctypes
    from ctypes import wintypes
    advapi, kernel = keyfile._windows_api()
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
    convert.restype = wintypes.BOOL
    apply = advapi.SetFileSecurityW
    apply.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    apply.restype = wintypes.BOOL
    descriptor = ctypes.c_void_p()
    inheritance = 'OICI' if directory else ''
    sddl = 'D:P(A;' + inheritance + ';FA;;;' + keyfile._windows_current_sid() + ')'
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
        if not apply(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


def checked_path(value):
    path = Path(value).expanduser()
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('an absolute path without parent traversal is required')
    if str(path).replace('\\', '/').startswith('//'):
        raise ValueError('network paths are not supported')
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('linked paths are not supported')
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('reparse points are not supported')
    return path


def persistent_path(value):
    """Keep runtime and private backups outside any checkout and known uv cache."""
    path = checked_path(value)
    if any((parent / '.git').exists() for parent in (path, *path.parents)):
        raise ValueError('persistent private state must be outside every Git checkout')
    cache_roots = [Path.home() / '.cache/uv', Path.home() / 'Library/Caches/uv']
    local = os.environ.get('LOCALAPPDATA')
    if local:
        cache_roots.append(Path(local) / 'uv/cache')
    for key in ('UV_CACHE_DIR', 'XDG_CACHE_HOME'):
        if os.environ.get(key):
            cache_roots.append(Path(os.environ[key]) / 'uv' if key == 'XDG_CACHE_HOME' else Path(os.environ[key]))
    if any(path.is_relative_to(root) for root in cache_roots if root.is_absolute()):
        raise ValueError('persistent private state must be outside the uv cache')
    return path


def private_directory(value):
    path = checked_path(value)
    if not path.exists():
        path.mkdir(parents=True, mode=0o700)
        secure_new_empty(path, directory=True)
        ok, detail = keyfile.is_private(path)
    else:
        if not path.is_dir():
            raise ValueError('installer state is not a directory')
        ok, detail = keyfile.is_private(path)
    if not ok:
        raise ValueError('installer directory is not private: ' + detail)
    if os.name != 'nt' and path.stat().st_uid != os.geteuid():
        raise ValueError('installer state belongs to another user')
    return path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(value, limit=2 * 1024 * 1024):
    return _read_in_checked_directory(checked_path(value), limit)


def _read_in_checked_directory(path, limit):
    """Bounded file read after the caller validated its containing directory."""
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit
            or getattr(info, 'st_file_attributes', 0) & 0x400):
        raise ValueError('file is not a bounded regular single-link file')
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        if ((opened.st_dev, opened.st_ino, opened.st_nlink) != (info.st_dev, info.st_ino, 1)
                or opened.st_size != info.st_size):
            raise ValueError('file changed during the checked open')
        # Allocate for the actual file, not the maximum wheel-size allowance.
        data = stream.read(info.st_size + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != info.st_size or after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns):
            raise ValueError('file changed during the checked read')
    if len(data) > limit:
        raise ValueError('file grew beyond its size limit')
    return data


def atomic_private_write(value, data):
    path = checked_path(value)
    fd, name = tempfile.mkstemp(prefix='.a4a-', dir=path.parent)
    temporary = Path(name)
    try:
        # Check protection before writing potentially secret configuration bytes.
        secure_new_empty(temporary)
        ok, detail = keyfile.is_private(temporary)
        if not ok:
            raise ValueError('temporary file cannot be protected: ' + detail)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        checked_path(path)
        os.replace(temporary, path)
    finally:
        if fd is not None:
            os.close(fd)
        # Failed writes are retained for inspection, never remove user data.


def write_json(path, document):
    atomic_private_write(path, (json.dumps(document, ensure_ascii=True, indent=2) + '\n').encode())


def child_environment(extra=None):
    # Do not inherit an existing personal mailbox or Python/installer overrides.
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(('A4A_', 'PYTHON', 'PIP_', 'UV_'))}
    env.update(extra or {})
    return env
