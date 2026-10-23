"""Private-key file creation, hardening, and hardening VERIFICATION.

An agent proves its identity with its private key alone. Losing the key costs the
owner the address, reputation, and every relationship; disclosing it costs control
of the agent. The file is therefore created with restricted access and, more
importantly, the result is VERIFIED.

Why verification is separate from enforcement: a 2026-08-30 check on a working
machine found that a project agent's key file had mode 666. The code duly called
`os.chmod(0o600)`, but on Windows that does not control access (Python maps chmod
only to the read-only attribute). The exception was swallowed, nobody noticed, and
onboarding still claimed “0600 permissions.” The same failure is possible on POSIX
with a filesystem that does not implement permissions, such as FAT or some network
mounts: chmod can succeed without changing anything.

The user profile directory already excludes other ordinary users on both systems,
so this was not an exposed-key emergency. The point is that a promised protection
must either exist or be reported as absent. Silent failure is worse than either.
"""
import ctypes
import errno
import os
import stat
import subprocess
import sys
import tempfile
from ctypes import wintypes
from functools import lru_cache
from pathlib import Path

#: Principals allowed to access a key on Windows: the process user and system
#: accounts that can already read anything on the machine.
#:
#: This is deliberately an ALLOWLIST. A denylist ("Everyone", localized variants,
#: and so on) is structurally unreliable: the principal may have another name in a
#: different locale or domain, silently allowing an exposed file. An allowlist
#: fails safely by reporting any unfamiliar principal as extraneous.
_WINDOWS_ALLOWED_SIDS = frozenset({"S-1-5-18", "S-1-5-32-544"})  # SYSTEM, Administrators


def windows_extra_principals(icacls_output: str, user: str) -> list[str]:
    """Provide legacy text diagnostics, NOT an ACL security check.

    `user` must be a full DOMAIN\\Name; a short name does not establish identity.
    Even an empty result does not prove protection because text does not describe
    the entire DACL structure. Security decisions require `is_private`, which
    checks actual SIDs.
    """
    # Include localized Windows principal names for legacy text diagnostics. Unicode
    # escapes keep locale-specific display text out of otherwise English source.
    allowed = {r"NT AUTHORITY\SYSTEM",
               "NT AUTHORITY\\\u0441\u0438\u0441\u0442\u0435\u043c\u0430",
               r"BUILTIN\Administrators",
               "BUILTIN\\\u0410\u0434\u043c\u0438\u043d\u0438\u0441\u0442\u0440\u0430\u0442\u043e\u0440\u044b"}
    if "\\" in user:
        allowed.add(user)
    allowed = {name.casefold() for name in allowed}
    extra = []
    found = False
    for line in icacls_output.splitlines():
        line = line.strip()
        if ":(" not in line:
            continue
        found = True
        left = line.rsplit(":(", 1)[0]
        if any(left.casefold() == name or left.casefold().endswith(" " + name)
               for name in allowed):
            continue
        extra.append(left.rsplit("\\", 1)[-1].strip() or "unknown principal")
    return extra if found else ["unrecognized ACL"]


class _AceHeader(ctypes.Structure):
    _fields_ = [("kind", wintypes.BYTE), ("flags", wintypes.BYTE), ("size", wintypes.WORD)]


class _AclSize(ctypes.Structure):
    _fields_ = [("count", wintypes.DWORD), ("used", wintypes.DWORD), ("free", wintypes.DWORD)]


@lru_cache(maxsize=1)
def _windows_api():
    """Lazy WinAPI bindings: no subprocesses or optional packages for ACL reads."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    out_pointer = ctypes.POINTER(pointer)
    out_dword = ctypes.POINTER(wintypes.DWORD)
    out_bool = ctypes.POINTER(wintypes.BOOL)
    signatures = {
        "OpenProcessToken": ([wintypes.HANDLE, wintypes.DWORD, out_pointer], wintypes.BOOL),
        "GetTokenInformation": ([wintypes.HANDLE, ctypes.c_int, pointer,
                                  wintypes.DWORD, out_dword], wintypes.BOOL),
        "GetNamedSecurityInfoW": ([wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                                   out_pointer, out_pointer, out_pointer, out_pointer,
                                   out_pointer], wintypes.DWORD),
        "GetSecurityDescriptorDacl": ([pointer, out_bool, out_pointer, out_bool], wintypes.BOOL),
        "GetAclInformation": ([pointer, pointer, wintypes.DWORD, ctypes.c_int], wintypes.BOOL),
        "GetAce": ([pointer, wintypes.DWORD, out_pointer], wintypes.BOOL),
        "IsValidSecurityDescriptor": ([pointer], wintypes.BOOL),
        "IsValidAcl": ([pointer], wintypes.BOOL),
        "IsValidSid": ([pointer], wintypes.BOOL),
        "GetLengthSid": ([pointer], wintypes.DWORD),
        "ConvertSidToStringSidW": ([pointer, out_pointer], wintypes.BOOL),
    }
    for name, (args, result) in signatures.items():
        function = getattr(advapi, name)
        function.argtypes, function.restype = args, result
    kernel.GetCurrentProcess.argtypes, kernel.GetCurrentProcess.restype = [], wintypes.HANDLE
    kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [wintypes.HANDLE], wintypes.BOOL
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [pointer], pointer
    return advapi, kernel


def _windows_sid_string(sid) -> str:
    advapi, kernel = _windows_api()
    if not sid or not advapi.IsValidSid(sid):
        raise OSError("invalid or missing SID")
    text = ctypes.c_void_p()
    if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.wstring_at(text)
    finally:
        kernel.LocalFree(text)


def _windows_current_sid() -> str:
    """Actual process-token user, never an environment variable or display name."""
    advapi, kernel = _windows_api()
    token = ctypes.c_void_p()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        # TOKEN_QUERY, TokenUser; the first call obtains the variable buffer size.
        if (advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
                or ctypes.get_last_error() != 122 or needed.value < ctypes.sizeof(ctypes.c_void_p)):
            raise OSError("cannot determine token user buffer size")
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        # TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first member is PSID.
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        return _windows_sid_string(sid)
    finally:
        kernel.CloseHandle(token)


def _windows_acl(path: Path) -> tuple[str, list[tuple[int, int, int, str]]]:
    """Return owner SID and structured (type, flags, mask, SID) ACEs, or fail closed."""
    advapi, kernel = _windows_api()
    descriptor, owner, dacl = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    # SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION.
    error = advapi.GetNamedSecurityInfoW(str(path), 1, 0x0005, ctypes.byref(owner), None,
                                        ctypes.byref(dacl), None, ctypes.byref(descriptor))
    try:
        if error:
            raise ctypes.WinError(error)
        if not descriptor or not advapi.IsValidSecurityDescriptor(descriptor):
            raise OSError("invalid security descriptor")
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        if not advapi.GetSecurityDescriptorDacl(
                descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not present.value or not dacl:
            raise OSError("missing or NULL DACL permits unrestricted access")
        if not advapi.IsValidAcl(dacl):
            raise OSError("invalid DACL")
        info = _AclSize()
        if not advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise ctypes.WinError(ctypes.get_last_error())
        entries = []
        for index in range(info.count):
            ace = ctypes.c_void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)) or not ace:
                raise OSError("cannot read DACL entry")
            header = ctypes.cast(ace, ctypes.POINTER(_AceHeader)).contents
            # Only ordinary allow/deny ACEs have this layout. Object/callback ACEs
            # and unrecognized flags must not be interpreted as ordinary grants.
            if header.kind not in (0, 1) or header.flags & ~0x1F or header.size < 16:
                raise OSError("unsupported DACL entry")
            mask = wintypes.DWORD.from_address(ace.value + 4).value
            sid = ctypes.c_void_p(ace.value + 8)
            if not advapi.IsValidSid(sid) or advapi.GetLengthSid(sid) > header.size - 8:
                raise OSError("invalid DACL entry SID")
            entries.append((header.kind, header.flags, mask, _windows_sid_string(sid)))
        return _windows_sid_string(owner), entries
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)


def _harden(path: Path) -> None:
    """Restrict access, raising an exception if enforcement fails."""
    if sys.platform == "win32":
        user_sid = _windows_current_sid()
        # /inheritance:r removes inherited permissions so directory groups do not
        # remain; /grant:r replaces permissions for the current SID. Foreign
        # explicit ACEs remain, and the subsequent check must detect and reject them.
        res = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{user_sid}:F"],
            capture_output=True, text=True, errors="replace",
        )
        if res.returncode != 0:
            raise OSError(f"icacls could not restrict access: {res.stderr.strip()[:200]}")
    else:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


@lru_cache(maxsize=1)
def _darwin_api():
    """System ACL ABI; macOS extended ACLs are independent of BSD mode bits."""
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    pointer = ctypes.c_void_p
    declarations = {
        'acl_get_fd_np': ([ctypes.c_int, ctypes.c_int], pointer),
        'acl_valid': ([pointer], ctypes.c_int),
        'acl_get_entry': ([pointer, ctypes.c_int, ctypes.POINTER(pointer)], ctypes.c_int),
        'acl_get_tag_type': ([pointer, ctypes.POINTER(ctypes.c_int)], ctypes.c_int),
        'acl_get_qualifier': ([pointer], pointer),
        'acl_free': ([pointer], ctypes.c_int),
        'mbr_uid_to_uuid': ([ctypes.c_uint32, ctypes.POINTER(ctypes.c_ubyte)], ctypes.c_int),
    }
    for name, (arguments, result) in declarations.items():
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    return library


def _darwin_verify_acl(fd: int, uid: int) -> None:
    """Inspect a held descriptor; permit only owner ALLOWs and known DENYs."""
    api = _darwin_api()
    ctypes.set_errno(0)
    acl = api.acl_get_fd_np(fd, 0x100)  # ACL_TYPE_EXTENDED.
    if not acl:
        error = ctypes.get_errno()
        # Apple statx_np/filesec report NOACL as ENOENT even for a valid fd.
        # The caller already checked its held file type, owner and BSD mode.
        if error == errno.ENOENT:
            return
        raise OSError(error, 'could not retrieve macOS extended ACL')
    try:
        if api.acl_valid(acl) != 0:
            raise OSError('invalid macOS ACL object')
        owner_uuid = None
        for index in range(129):
            entry = ctypes.c_void_p()
            ctypes.set_errno(0)
            result = api.acl_get_entry(acl, 0 if index == 0 else -1, ctypes.byref(entry))
            if result == -1 and ctypes.get_errno() == errno.EINVAL:
                return  # Darwin's end-of-list convention; not Linux's return1.
            if result != 0 or not entry.value or index == 128:
                raise OSError('unreadable or oversized macOS ACL')
            tag = ctypes.c_int()
            if api.acl_get_tag_type(entry, ctypes.byref(tag)) != 0 or tag.value not in (1, 2):
                raise OSError('unknown macOS ACL entry type')
            qualifier = api.acl_get_qualifier(entry)
            if not qualifier:
                raise OSError('missing macOS ACL principal')
            try:
                if tag.value == 1:  # ACL_EXTENDED_ALLOW.
                    if owner_uuid is None:
                        value = (ctypes.c_ubyte * 16)()
                        error = api.mbr_uid_to_uuid(uid, value)
                        if error != 0:
                            raise OSError(error, 'could not resolve macOS owner UUID')
                        owner_uuid = bytes(value)
                    if ctypes.string_at(qualifier, 16) != owner_uuid:
                        raise OSError('macOS ACL grants access to another principal')
            finally:
                if api.acl_free(qualifier) != 0:
                    raise OSError('could not release macOS ACL principal')
    finally:
        if api.acl_free(acl) != 0:
            raise OSError('could not release macOS ACL')


def _darwin_permissions(path: Path, *, storage_parent=False) -> None:
    before = path.lstat()
    forbidden = 0o022 if storage_parent else 0o077
    if (not (stat.S_ISREG(before.st_mode) or stat.S_ISDIR(before.st_mode))
            or before.st_uid != os.geteuid() or before.st_mode & forbidden
            or (stat.S_ISREG(before.st_mode) and before.st_nlink != 1)
            or (storage_parent and not stat.S_ISDIR(before.st_mode))):
        raise OSError('macOS key storage must be an owned private regular file or directory')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    signature = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_mode,
                              info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    try:
        if signature(os.fstat(fd)) != signature(before):
            raise OSError('macOS key storage changed during open')
        _darwin_verify_acl(fd, before.st_uid)
        if signature(os.fstat(fd)) != signature(before) or signature(path.lstat()) != signature(before):
            raise OSError('macOS key storage changed during ACL verification')
    finally:
        os.close(fd)


def is_private(path) -> tuple[bool, str]:
    """Return `(is_file_private, explanation)`.

    A missing file is NOT considered protected. Otherwise, the check would pass in
    the most alarming case: when the key does not exist at all.
    """
    path = Path(path)
    if not path.exists():
        return False, f"file does not exist: {path}"
    if sys.platform == "win32":
        try:
            user_sid = _windows_current_sid()
            if not user_sid:
                raise OSError("unknown token user SID")
            owner, entries = _windows_acl(path)
            allowed = _WINDOWS_ALLOWED_SIDS | {user_sid}
            if owner not in allowed:
                return False, f"owner SID is not allowed: {owner}"
            for kind, flags, mask, sid in entries:
                if kind not in (0, 1) or flags & ~0x1F or not sid:
                    raise OSError("unknown DACL entry")
                # OWNER RIGHTS grants apply only to the descriptor's actual
                # owner, which was checked above. Modern Windows Python uses
                # this SID for mkdir(mode=0o700); it is not another account.
                # Never add it to the unconditional principal allowlist.
                effective_sid = owner if sid == "S-1-3-4" else sid
                if effective_sid not in allowed:
                    return False, f"extraneous SID in DACL: {sid}"
        except (OSError, ValueError, TypeError) as e:
            return False, f"could not verify permissions: {e}"
        return True, "DACL is restricted to the current user SID, SYSTEM, and Administrators"
    if sys.platform == 'darwin':
        try:
            _darwin_permissions(path)
        except (OSError, ValueError, TypeError, AttributeError) as error:
            return False, f'could not verify macOS permissions: {error}'
        return True, 'BSD permissions and macOS ACL are restricted to the current user'
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        return False, f"mode {mode:o} permits access by users other than the owner: {path}"
    return True, f"mode {mode:o}"


#: Successful hardening of a particular file version, not just a path name.
#:
#: On Windows, enforcing permissions launches `icacls` as a separate process. The
#: key file is read on every MCP tool invocation; without a cache the test suite
#: became seven times slower (1.2 to 8.5 seconds). Atomic replacement creates a
#: different file, potentially with different ACLs. Metadata detects replacement
#: but not every ACL change. The cache skips only repeated enforcement; current ACLs
#: and ownership are verified on every call.
_Fingerprint = tuple[int, int, int, int, int, int]
_checked: dict[str, tuple[_Fingerprint, tuple[bool, str]]] = {}


def _fingerprint(path: Path) -> _Fingerprint:
    info = path.stat()
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def harden_and_check(path, force: bool = False) -> tuple[bool, str]:
    """Enforce and immediately verify protection without raising exceptions.

    `force=True` bypasses the process cache, as required by tests and immediately
    after writing a file.
    """
    path = Path(path)
    key = None
    try:
        key = str(path.resolve())
        fingerprint = _fingerprint(path)
        cached = _checked.get(key)
        if not force and cached is not None and cached[0] == fingerprint:
            result = is_private(path)
            if not result[0]:
                _checked.pop(key, None)
            return result
        _checked.pop(key, None)
        _harden(path)
        result = is_private(path)
        if result[0]:
            _checked[key] = (_fingerprint(path), result)
    except Exception as e:  # noqa: BLE001 - report the cause to the caller.
        if key is not None:
            _checked.pop(key, None)
        result = (False, f"could not restrict or verify access: {e}")
    return result


def write_private(path, text: str) -> tuple[bool, str]:
    """Atomically write a secret and restrict the file to authorized principals.

    Atomicity prevents a process terminated during the write from leaving a
    truncated key file that fails to parse on every subsequent start. Permissions
    are applied AT CREATION through the `os.open` mode, not after writing; otherwise
    there would be a window in which the key is on disk but still exposed.

    Return the protection-check result; the caller must inspect it.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if sys.platform == 'darwin':
        try:
            # A directory-only ACL can grant delete_child without inheriting
            # an entry onto the new key file. Refuse that mutation authority.
            _darwin_permissions(path.parent, storage_parent=True)
        except (OSError, ValueError, TypeError, AttributeError) as error:
            return False, f'could not verify macOS key storage parent: {error}'
    # Inherited macOS ACLs can grant read access despite creation mode0600.
    # Verify an exclusive empty file before any secret bytes touch the disk.
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', suffix='.tmp', dir=path.parent)
    tmp = Path(name)
    temporary_cache_key = None
    try:
        temporary_cache_key = str(tmp.resolve())
        ok, detail = harden_and_check(tmp, force=True)
        _checked.pop(temporary_cache_key, None)
        opened, named = os.fstat(fd), tmp.lstat()
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
            ok, detail = False, 'exclusive key temporary file changed before writing'
        if not ok:
            # Retain the empty diagnostic artifact; preserve the previous key.
            return False, detail
        stream = os.fdopen(fd, "w", encoding="utf-8")
        fd = None  # Ownership transferred to the stream.
        with stream as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
            opened, named = os.fstat(f.fileno()), tmp.lstat()
            if (not stat.S_ISREG(named.st_mode) or opened.st_nlink != 1
                    or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
                raise OSError('key temporary file changed before replacement')
    finally:
        # Preserve a private partial artifact on failure; never damage the old
        # key. Temporary names must not accumulate in the enforcement cache.
        if temporary_cache_key is not None:
            _checked.pop(temporary_cache_key, None)
        if fd is not None:
            os.close(fd)
    os.replace(tmp, path)
    return harden_and_check(path, force=True)
