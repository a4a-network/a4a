"""Private-key file protection is enforced AND VERIFIED.

A 2026-08-30 check on a working machine found
`~/.a4a-project-agent/identity.json` at mode 666. The code duly called
`os.chmod(0o600)`, but on Windows that does not control access because Python maps
chmod only to the read-only attribute. The exception was swallowed, nobody noticed,
and onboarding still claimed that the key file was created with mode 0600.

Tests must verify the RESULT rather than the intent. The same failure occurs on
POSIX when a filesystem without permissions, such as FAT or some network mounts,
silently accepts chmod without changing anything.
"""
import csv
import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from a4a import keyfile


def test_written_key_file_is_private(tmp_path):
    """The main path writes a key file that excludes unauthorized principals."""
    path = tmp_path / "identity.json"
    keyfile.write_private(path, '{"privkey_hex": "00"}')
    assert path.read_text(encoding="utf-8") == '{"privkey_hex": "00"}'
    ok, detail = keyfile.is_private(path)
    assert ok, detail


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes do not control Windows ACLs")
def test_group_and_world_access_is_reported_on_posix(tmp_path):
    """A file with broad permissions must be reported as exposed.

    Without this check, “protection” exists only in a comment: chmod may fail to
    enforce the mode without the caller learning about it.
    """
    path = tmp_path / "identity.json"
    keyfile.write_private(path, "x")
    os.chmod(path, 0o644)
    ok, detail = keyfile.is_private(path)
    assert not ok
    assert "644" in detail or "access" in detail or "permission" in detail.lower()


def test_hardening_reports_failure_instead_of_pretending(tmp_path, monkeypatch):
    """The caller must LEARN when protection cannot be enforced.

    Silent failure is the worst outcome: documentation says “0600,” while the file
    on disk is exposed and nobody ever notices.
    """
    path = tmp_path / "identity.json"
    path.write_text("x", encoding="utf-8")

    def _fail(*a, **kw):
        raise OSError("filesystem does not support permissions")

    monkeypatch.setattr(keyfile, "_harden", _fail)
    ok, detail = keyfile.harden_and_check(path, force=True)
    assert not ok
    assert "does not support permissions" in detail or "could not" in detail


def test_missing_file_is_not_reported_as_private(tmp_path):
    """A missing file is not “protected,” especially when the key is simply gone."""
    ok, detail = keyfile.is_private(tmp_path / "does-not-exist.json")
    assert not ok, detail
    assert "does not exist" in detail


@pytest.fixture
def hardening_spy(monkeypatch):
    spy = Mock(wraps=keyfile._harden)
    monkeypatch.setattr(keyfile, "_harden", spy)
    return spy


def test_unchanged_file_reuses_cached_check(tmp_path, hardening_spy, monkeypatch):
    path = tmp_path / "identity.json"
    path.write_text("test", encoding="utf-8")
    verification = Mock(wraps=keyfile.is_private)
    monkeypatch.setattr(keyfile, "is_private", verification)
    assert keyfile.harden_and_check(path)[0]
    assert keyfile.harden_and_check(path)[0]
    assert hardening_spy.call_count == 1
    assert verification.call_count == 2
    assert keyfile.harden_and_check(path, force=True)[0]
    assert hardening_spy.call_count == 2
    assert verification.call_count == 3


def test_atomic_replacement_requires_new_check(tmp_path, hardening_spy):
    path = tmp_path / "identity.json"
    path.write_text("test", encoding="utf-8")
    assert keyfile.harden_and_check(path)[0]
    before = path.stat()
    replacement = tmp_path / "replacement.json"
    replacement.write_text("test", encoding="utf-8")
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    os.replace(replacement, path)

    assert keyfile.harden_and_check(path)[0]
    assert hardening_spy.call_count == 2
    assert keyfile.is_private(path)[0]


def test_deleted_file_does_not_reuse_cached_success(tmp_path):
    path = tmp_path / "identity.json"
    path.write_text("test", encoding="utf-8")
    assert keyfile.harden_and_check(path)[0]
    path.unlink()
    assert not keyfile.harden_and_check(path)[0]


def test_failed_check_is_retried(tmp_path, monkeypatch):
    path = tmp_path / "identity.json"
    path.write_text("test", encoding="utf-8")
    with monkeypatch.context() as patch:
        patch.setattr(keyfile, "_harden", Mock(side_effect=OSError("temporary failure")))
        assert not keyfile.harden_and_check(path)[0]
    assert keyfile.harden_and_check(path)[0]


def test_permission_read_failure_is_reported(tmp_path, monkeypatch):
    path = tmp_path / "identity.json"
    path.write_text("test", encoding="utf-8")
    monkeypatch.setattr(keyfile, "is_private", Mock(side_effect=OSError("cannot read ACL")))
    ok, detail = keyfile.harden_and_check(path)
    assert not ok
    assert "cannot read ACL" in detail


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
def test_changed_mode_requires_new_check(tmp_path, hardening_spy):
    path = tmp_path / "identity.json"
    path.write_text("test", encoding="utf-8")
    assert keyfile.harden_and_check(path)[0]
    os.chmod(path, 0o644)
    assert keyfile.harden_and_check(path)[0]
    assert hardening_spy.call_count == 2
    assert path.stat().st_mode & 0o777 == 0o600


# --- Windows permission parsing, exercised on every platform --------------------

REAL_ICACLS = (
    r"C:\Users\alice\.a4a\identity.json WORKSTATION\alice:(F)" + "\n"
    "\nSuccessfully processed 1 files; Failed processing 0 files\n")

INHERITED_ICACLS = (
    r"C:\Users\alice\.a4a\identity.json NT AUTHORITY\SYSTEM:(I)(F)" + "\n"
    r"                                    BUILTIN\Administrators:(I)(F)" + "\n"
    r"                                    WORKSTATION\alice:(I)(F)" + "\n"
    r"                                    BUILTIN\Users:(I)(RX)" + "\n")

LOCALIZED_KEY = "\u043A\u043B\u044E\u0447"
LOCALIZED_USERS = "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0438"
LOCALIZED_ICACLS = (
    rf"C:\{LOCALIZED_KEY}.json WORKSTATION\alice:(F)" + "\n"
    rf"              BUILTIN\{LOCALIZED_USERS}:(RX)" + "\n")


def test_only_owner_and_system_accounts_are_accepted():
    assert keyfile.windows_extra_principals(REAL_ICACLS, r"WORKSTATION\alice") == []


def test_inherited_group_access_is_caught():
    """Inherited Users-group access is exactly what hardening must remove."""
    extra = keyfile.windows_extra_principals(INHERITED_ICACLS, r"WORKSTATION\alice")
    assert extra == ["Users"], extra


def test_localized_group_name_is_caught_too():
    """The check must not depend on the system language.

    This is why a name denylist fails: the Users group has a localized name on
    Russian Windows, and every variant cannot be known in advance. An allowlist
    fails safely.
    """
    extra = keyfile.windows_extra_principals(LOCALIZED_ICACLS, r"WORKSTATION\alice")
    assert extra == [LOCALIZED_USERS], extra


@pytest.mark.parametrize("user", ["User", r"MACHINE\User"])
def test_text_acl_cannot_trust_a_short_username_collision(user):
    text = r"C:\synthetic.txt OTHERDOMAIN\User:(F)"
    assert keyfile.windows_extra_principals(text, user)


@pytest.mark.parametrize("name", ["SYSTEM", "Administrators", "TrustedInstaller"])
def test_text_acl_cannot_trust_a_system_account_name_from_another_domain(name):
    assert keyfile.windows_extra_principals(
        rf"C:\synthetic.txt OTHERDOMAIN\{name}:(F)", r"MACHINE\User")


@pytest.mark.parametrize("text", ["", "Successfully processed 1 files", "unrecognized ACL"])
def test_unrecognized_text_acl_fails_closed(text):
    assert keyfile.windows_extra_principals(text, r"MACHINE\User")


WINDOWS = pytest.mark.skipif(sys.platform != "win32", reason="native Windows ACL test")
USER_SID = "S-1-5-21-100-200-300-1001"
OTHER_SID = "S-1-5-21-400-500-600-1001"


@pytest.fixture
def structured_acl(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.txt"
    path.write_text("synthetic non-secret payload", encoding="utf-8")
    monkeypatch.setattr(keyfile, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(keyfile, "_windows_current_sid", lambda: USER_SID, raising=False)
    # The hostile textual view claims the same short account name for another SID.
    monkeypatch.setenv("USERNAME", "User")
    monkeypatch.setattr(keyfile.subprocess, "run", Mock(return_value=subprocess.CompletedProcess(
        [], 0, rf"{path} OTHERDOMAIN\User:(F)", "")))
    return path


@pytest.mark.parametrize("change", ["foreign_ace", "owner", "null", "unreadable"])
def test_cached_hardening_rechecks_acl_with_same_fingerprint(
        structured_acl, hardening_spy, monkeypatch, change):
    path = structured_acl
    fingerprint = keyfile._fingerprint(path)
    monkeypatch.setattr(keyfile, "_fingerprint", lambda path: fingerprint)
    safe_acl = (USER_SID, [(0, 0, 0x1F01FF, USER_SID)])
    acl = Mock(return_value=safe_acl)
    monkeypatch.setattr(keyfile, "_windows_acl", acl)
    assert keyfile.harden_and_check(path)[0]

    if change == "foreign_ace":
        acl.return_value = (USER_SID, safe_acl[1] + [(0, 0, 0x120089, OTHER_SID)])
    elif change == "owner":
        acl.return_value = (OTHER_SID, safe_acl[1])
    elif change == "null":
        acl.return_value = (USER_SID, None)
    else:
        acl.side_effect = OSError("unreadable DACL")

    ok, detail = keyfile.harden_and_check(path)
    assert not ok, detail
    assert hardening_spy.call_count == 1
    assert acl.call_count == 2
    assert str(path.resolve()) not in keyfile._checked

    acl.side_effect = None
    acl.return_value = safe_acl
    assert keyfile.harden_and_check(path)[0]
    assert hardening_spy.call_count == 2


@pytest.mark.parametrize("sid", [OTHER_SID, "S-1-1-0", "S-1-5-32-545"])
def test_security_decision_compares_full_sids(structured_acl, monkeypatch, sid):
    monkeypatch.setattr(keyfile, "_windows_acl", lambda path: (
        USER_SID, [(0, 0, 0x1F01FF, USER_SID), (0, 0, 0x120089, sid)]), raising=False)
    ok, detail = keyfile.is_private(structured_acl)
    assert not ok, detail
    assert sid in detail


def test_security_decision_allows_only_current_system_and_admin_sids(structured_acl, monkeypatch):
    monkeypatch.setattr(keyfile, "_windows_acl", lambda path: (USER_SID, [
        (0, 3, 0x1F01FF, USER_SID), (0, 16, 0x1F01FF, "S-1-5-18"),
        (0, 0, 0x1F01FF, "S-1-5-32-544")]), raising=False)
    assert keyfile.is_private(structured_acl)[0]
    keyfile.subprocess.run.assert_not_called()  # unguarded-launch: subprocess is mocked here


@pytest.mark.parametrize("acl", [None, (USER_SID, None),
                                  (OTHER_SID, [(0, 0, 1, USER_SID)]),
                                  (USER_SID, [(9, 0, 1, USER_SID)]),
                                  (USER_SID, [(0, 128, 1, USER_SID)]),
                                  (USER_SID, [(0, 0, 1, "")])])
def test_null_or_unknown_structured_acl_fails_closed(structured_acl, monkeypatch, acl):
    monkeypatch.setattr(keyfile, "_windows_acl", lambda path: acl, raising=False)
    assert not keyfile.is_private(structured_acl)[0]


def test_unreadable_acl_fails_closed(structured_acl, monkeypatch):
    monkeypatch.setattr(keyfile, "_windows_acl", Mock(side_effect=OSError("unreadable DACL")),
                        raising=False)
    ok, detail = keyfile.is_private(structured_acl)
    assert not ok
    assert "unreadable DACL" in detail


def test_unknown_token_identity_fails_closed(structured_acl, monkeypatch):
    monkeypatch.setattr(keyfile, "_windows_current_sid", Mock(side_effect=OSError("no token")))
    assert not keyfile.is_private(structured_acl)[0]


def test_hardening_grants_actual_sid_not_environment_username(structured_acl, monkeypatch):
    monkeypatch.setenv("USERNAME", "OTHERDOMAIN\\User")
    keyfile._harden(structured_acl)
    command = keyfile.subprocess.run.call_args.args[0]  # unguarded-launch: subprocess is mocked
    assert f"*{USER_SID}:F" in command
    assert not any("OTHERDOMAIN" in arg for arg in command)


def test_hardening_rejects_nonzero_icacls_exit(structured_acl, monkeypatch):
    monkeypatch.setattr(keyfile.subprocess, "run", Mock(return_value=subprocess.CompletedProcess(
        [], 5, "", "access denied")))
    with pytest.raises(OSError, match="icacls.*access denied"):
        keyfile._harden(structured_acl)


def test_empty_current_sid_is_rejected_fail_closed(structured_acl, monkeypatch):
    monkeypatch.setattr(keyfile, "_windows_current_sid", lambda: "")
    ok, detail = keyfile.is_private(structured_acl)
    assert not ok
    assert "unknown token user SID" in detail


def test_posix_group_access_guard_is_exercised_on_windows_too(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.txt"
    path.write_text("x", encoding="utf-8")
    monkeypatch.setattr(keyfile, "sys", SimpleNamespace(platform="linux"))
    real_stat = keyfile.os.stat

    def open_mode(target, *args, **kwargs):
        info = real_stat(target, *args, **kwargs)
        return SimpleNamespace(st_mode=(info.st_mode & ~0o777) | 0o644)

    monkeypatch.setattr(keyfile.os, "stat", open_mode)
    ok, detail = keyfile.is_private(path)
    assert not ok
    assert "mode 644" in detail


def _fake_acl_api(mode):
    """Minimal in-memory WinAPI surface for fail-closed ACL parser branches."""
    ace_buffer = ctypes.create_string_buffer(16)
    header = keyfile._AceHeader.from_buffer(ace_buffer)
    header.kind, header.flags, header.size = 0, 0, 16
    valid_descriptor = Mock(return_value=mode != "descriptor")

    def named(path, object_type, flags, owner, group, dacl, sacl, descriptor):
        if mode == "named-error":
            return 5
        descriptor._obj.value = 1
        owner._obj.value = 2
        return 0

    def descriptor_dacl(descriptor, present, dacl, defaulted):
        present._obj.value = mode != "null-dacl"
        if mode != "null-dacl":
            dacl._obj.value = 3
        return True

    def acl_info(dacl, info, size, kind):
        info._obj.count = 1
        return True

    def get_ace(dacl, index, ace):
        ace._obj.value = ctypes.addressof(ace_buffer)
        return True

    advapi = SimpleNamespace(
        GetNamedSecurityInfoW=named,
        IsValidSecurityDescriptor=valid_descriptor,
        GetSecurityDescriptorDacl=descriptor_dacl,
        IsValidAcl=Mock(return_value=mode != "invalid-acl"),
        GetAclInformation=acl_info,
        GetAce=get_ace,
        IsValidSid=Mock(return_value=False),
        GetLengthSid=Mock(return_value=100),
        ConvertSidToStringSidW=Mock(return_value=False),
    )
    kernel = SimpleNamespace(LocalFree=Mock())
    return advapi, kernel, valid_descriptor


def test_windows_sid_string_rejects_missing_or_invalid_pointer(monkeypatch):
    advapi, kernel, _ = _fake_acl_api("invalid-sid")
    monkeypatch.setattr(keyfile, "_windows_api", lambda: (advapi, kernel))
    with pytest.raises(OSError, match="invalid or missing SID"):
        keyfile._windows_sid_string(None)


def test_windows_acl_stops_at_native_lookup_error(monkeypatch):
    advapi, kernel, descriptor_check = _fake_acl_api("named-error")
    monkeypatch.setattr(keyfile, "_windows_api", lambda: (advapi, kernel))
    if not hasattr(ctypes, "WinError"):
        # The native constructor exists only on Windows; keep exercising this
        # fail-closed branch on Linux with the rest of the simulated native API.
        def win_error(code):
            error = OSError(code, "synthetic Windows native error")
            error.winerror = code
            return error
        monkeypatch.setattr(ctypes, "WinError", win_error, raising=False)
    with pytest.raises(OSError) as caught:
        keyfile._windows_acl("synthetic")
    assert getattr(caught.value, "winerror", None) == 5
    descriptor_check.assert_not_called()


@pytest.mark.parametrize("mode, message", [
    ("descriptor", "invalid security descriptor"),
    ("null-dacl", "missing or NULL DACL"),
    ("invalid-acl", "^invalid DACL$"),
    ("invalid-sid", "invalid DACL entry SID"),
])
def test_windows_acl_rejects_each_invalid_native_structure(monkeypatch, mode, message):
    advapi, kernel, _ = _fake_acl_api(mode)
    monkeypatch.setattr(keyfile, "_windows_api", lambda: (advapi, kernel))
    with pytest.raises(OSError, match=message):
        keyfile._windows_acl("synthetic")


@pytest.fixture
def native_identity():
    result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],  # unguarded-launch: OS identity helper
                            capture_output=True, text=True, errors="replace", check=True)
    name, sid = next(csv.reader(result.stdout.strip().splitlines()))
    assert sid.startswith("S-1-")
    return name, sid


def _set_test_dacl(path, sddl):
    """Set only a synthetic temp object's DACL; never change its owner."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(pointer), ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [pointer, ctypes.POINTER(wintypes.BOOL),
                                                ctypes.POINTER(pointer), ctypes.POINTER(wintypes.BOOL)]
    advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                                           pointer, pointer, pointer, pointer]
    advapi.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer
    descriptor, dacl = pointer(), pointer()
    present, defaulted = wintypes.BOOL(), wintypes.BOOL()
    assert advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None), ctypes.WinError(ctypes.get_last_error())
    try:
        assert advapi.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted))
        assert present.value
        error = advapi.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, dacl, None)
        assert error == 0, ctypes.WinError(error)
    finally:
        kernel.LocalFree(descriptor)


@WINDOWS
def test_native_sid_matches_token_even_when_environment_lies(native_identity, monkeypatch):
    _, sid = native_identity
    monkeypatch.setenv("USERNAME", "OTHERDOMAIN\\User")
    monkeypatch.setenv("USER", "not-the-token-user")
    assert keyfile._windows_current_sid() == sid


@WINDOWS
def test_native_explicit_foreign_ace_survives_hardening_and_is_rejected(
        tmp_path, native_identity, monkeypatch):
    name, sid = native_identity
    path = tmp_path / "synthetic.txt"
    path.write_text("not a key", encoding="utf-8")
    assert keyfile.harden_and_check(path)[0]
    assert str(path.resolve()) in keyfile._checked
    _set_test_dacl(path, f"D:P(A;;FA;;;{sid})(A;;FR;;;{OTHER_SID})")
    actual_run = subprocess.run  # unguarded-launch: save the original before mocking
    short_name = name.rsplit("\\", 1)[-1]

    def misleading_text(command, **kwargs):
        if command[0] == "icacls" and len(command) == 2:
            return subprocess.CompletedProcess(command, 0,
                rf"{path} OTHERDOMAIN\{short_name}:(R)", "")
        return actual_run(command, **kwargs)

    monkeypatch.setattr(keyfile.subprocess, "run", misleading_text)
    ok, detail = keyfile.harden_and_check(path, force=True)
    assert not ok, detail
    owner, entries = keyfile._windows_acl(path)
    assert any(ace[3] == OTHER_SID for ace in entries)
    assert str(path.resolve()) not in keyfile._checked
    _set_test_dacl(path, f"D:P(A;;FA;;;{sid})")
    assert keyfile.harden_and_check(path)[0]


@WINDOWS
def test_native_cached_hardening_rejects_new_explicit_ace(
        tmp_path, native_identity, hardening_spy, monkeypatch):
    _, sid = native_identity
    path = tmp_path / "synthetic.txt"
    path.write_text("not a key", encoding="utf-8")
    assert keyfile.harden_and_check(path)[0]
    fingerprint = keyfile._fingerprint(path)
    # ACL-only changes need not change the stat metadata used by the cache.
    monkeypatch.setattr(keyfile, "_fingerprint", lambda path: fingerprint)
    try:
        _set_test_dacl(path, f"D:P(A;;FA;;;{sid})(A;;FR;;;{OTHER_SID})")
        ok, detail = keyfile.harden_and_check(path)
        assert not ok, detail
        assert OTHER_SID in detail
        assert hardening_spy.call_count == 1
        assert str(path.resolve()) not in keyfile._checked
    finally:
        _set_test_dacl(path, f"D:P(A;;FA;;;{sid})")


@WINDOWS
def test_native_null_dacl_is_not_private(tmp_path, native_identity):
    _, sid = native_identity
    path = tmp_path / "synthetic.txt"
    path.write_text("not a key", encoding="utf-8")
    try:
        _set_test_dacl(path, "D:NO_ACCESS_CONTROL")
        assert not keyfile.is_private(path)[0]
    finally:
        _set_test_dacl(path, f"D:P(A;;FA;;;{sid})")


@WINDOWS
@pytest.mark.parametrize("entry", [
    "(OA;;FR;00000000-0000-0000-0000-000000000001;;{sid})",
    '(XA;;FR;;;{sid};(@User.Title == "VP"))',
], ids=["object", "callback"])
def test_native_unsupported_ace_types_fail_closed(tmp_path, native_identity, entry):
    _, sid = native_identity
    path = tmp_path / "synthetic.txt"
    path.write_text("not a key", encoding="utf-8")
    try:
        _set_test_dacl(path, f"D:P(A;;FA;;;{sid})" + entry.format(sid=sid))
        with pytest.raises(OSError, match="unsupported DACL entry"):
            keyfile._windows_acl(path)
        assert not keyfile.is_private(path)[0]
    finally:
        _set_test_dacl(path, f"D:P(A;;FA;;;{sid})")


@WINDOWS
def test_native_verification_needs_no_subprocess(tmp_path, native_identity, monkeypatch):
    _, sid = native_identity
    path = tmp_path / "synthetic.txt"
    path.write_text("not a key", encoding="utf-8")
    _set_test_dacl(path, f"D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)")
    with monkeypatch.context() as patch:
        patch.setattr(keyfile.subprocess, "run", Mock(side_effect=AssertionError("no shell reads")))
        for _ in range(20):
            assert keyfile.is_private(path)[0]


@WINDOWS
def test_native_directory_acl_still_supports_inbox_child_inheritance(tmp_path, native_identity):
    name, sid = native_identity
    directory = tmp_path / "private-inbox"
    directory.mkdir()
    assert keyfile.harden_and_check(directory, force=True)[0]
    subprocess.run(["icacls", str(directory), "/grant:r", f"{name}:(OI)(CI)F"],  # unguarded-launch: OS ACL helper
                   capture_output=True, text=True, errors="replace", check=True)
    assert keyfile.is_private(directory)[0]
    child = directory / "synthetic.sqlite3"
    child.write_bytes(b"synthetic database placeholder")
    assert keyfile.is_private(child)[0]
    _, entries = keyfile._windows_acl(child)
    assert any(ace[3] == sid and ace[1] & 0x10 for ace in entries)


@pytest.mark.parametrize("owner", [USER_SID, "S-1-5-18", "S-1-5-32-544", OTHER_SID])
def test_owner_rights_resolves_only_to_the_checked_owner(tmp_path, monkeypatch, owner):
    path = tmp_path / "synthetic.txt"
    path.write_text("not a key")
    monkeypatch.setattr(keyfile.sys, "platform", "win32")
    monkeypatch.setattr(keyfile, "_windows_current_sid", lambda: USER_SID)
    monkeypatch.setattr(keyfile, "_windows_acl", lambda path: (owner, [
        (0, 0, 0x1F01FF, USER_SID), (0, 3, 0x1F01FF, "S-1-3-4")]))
    ok, detail = keyfile.is_private(path)
    assert ok == (owner != OTHER_SID), detail
    assert "S-1-3-4" not in keyfile._WINDOWS_ALLOWED_SIDS


def test_owner_rights_does_not_hide_an_unrelated_grant(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.txt"
    path.write_text("not a key")
    monkeypatch.setattr(keyfile.sys, "platform", "win32")
    monkeypatch.setattr(keyfile, "_windows_current_sid", lambda: USER_SID)
    monkeypatch.setattr(keyfile, "_windows_acl", lambda path: (USER_SID, [
        (0, 3, 0x1F01FF, "S-1-3-4"), (0, 0, 0x120089, OTHER_SID)]))
    ok, detail = keyfile.is_private(path)
    assert not ok and OTHER_SID in detail


@WINDOWS
def test_native_owner_rights_directory_is_private_and_foreign_grants_still_fail(
        tmp_path, native_identity):
    _, sid = native_identity
    directory = tmp_path / "owner-rights-inbox"
    directory.mkdir(mode=0o700)
    # Exercise OWNER RIGHTS on older test interpreters too, with the actual
    # descriptor owner left unchanged. New Python emits the same SID itself.
    _set_test_dacl(directory, f"D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;S-1-3-4)")
    assert keyfile.harden_and_check(directory, force=True)[0]
    from a4a.inbox import _private_directory
    _private_directory(directory)
    child = directory / "synthetic.txt"
    child.write_text("not a key")
    assert keyfile.is_private(child)[0]
    try:
        _set_test_dacl(directory, f"D:P(A;;FA;;;{sid})(A;;FA;;;S-1-3-4)(A;;FR;;;{OTHER_SID})")
        assert not keyfile.harden_and_check(directory, force=True)[0]
    finally:
        _set_test_dacl(directory, f"D:P(A;OICI;FA;;;{sid})")
