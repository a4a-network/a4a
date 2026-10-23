"""Darwin ACL contracts and platform-native secret-before-permission negatives."""
import ctypes
import errno
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from a4a import keyfile


class ACL:
    """Explicit Apple ABI fixture, never advertised as a native Mac test."""
    def __init__(self, entries=(), *, missing=None, iteration=None, uuid_error=0):
        self.entries = entries
        self.missing, self.iteration, self.uuid_error = missing, iteration, uuid_error
        self.index = 0
        self.freed = []
        self.uuid_calls = 0
        self.buffers = [ctypes.create_string_buffer(principal, 16) for _, principal in entries]

    def acl_get_fd_np(self, fd, kind):
        assert fd == 7 and kind == 0x100
        if self.missing is not None:
            ctypes.set_errno(self.missing)
            return None
        return 1

    def acl_valid(self, acl):
        assert acl == 1
        return 0

    def acl_get_entry(self, acl, position, output):
        assert position == (0 if self.index == 0 else -1)
        if self.iteration is not None:
            result, error = self.iteration
            ctypes.set_errno(error)
            return result
        if self.index == len(self.entries):
            ctypes.set_errno(errno.EINVAL)
            return -1
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = 100 + self.index
        self.index += 1
        return 0

    def acl_get_tag_type(self, entry, output):
        index = entry.value - 100
        ctypes.cast(output, ctypes.POINTER(ctypes.c_int)).contents.value = self.entries[index][0]
        return 0

    def acl_get_qualifier(self, entry):
        return ctypes.addressof(self.buffers[entry.value - 100])

    def acl_free(self, value):
        self.freed.append(value)
        return 0

    def mbr_uid_to_uuid(self, uid, output):
        assert uid == 501
        self.uuid_calls += 1
        output[:] = b'o' * 16
        return self.uuid_error


def inspect(monkeypatch, api):
    monkeypatch.setattr(keyfile, '_darwin_api', lambda: api)
    return keyfile._darwin_verify_acl(7, 501)


def test_apple_no_acl_on_valid_fd_is_enoent(monkeypatch):
    api = ACL(missing=errno.ENOENT)
    assert inspect(monkeypatch, api) is None
    assert api.freed == []


@pytest.mark.parametrize('error', [0, errno.EACCES, errno.EBADF, errno.ENOTSUP])
def test_other_acl_read_errors_fail_closed(monkeypatch, error):
    with pytest.raises(OSError, match='retrieve'):
        inspect(monkeypatch, ACL(missing=error))


@pytest.mark.parametrize('entries', [(), ((2, b'f'*16),), ((1, b'o'*16),),
                                   ((2, b'f'*16), (1, b'o'*16))])
def test_empty_deny_and_owner_allow_acl(monkeypatch, entries):
    api = ACL(entries)
    assert inspect(monkeypatch, api) is None
    assert len(api.freed) == 1 + len(entries)
    assert api.freed[-1] == 1
    assert api.uuid_calls == int(any(tag == 1 for tag, _ in entries))


def test_foreign_allow_rejected_and_native_allocations_freed(monkeypatch):
    api = ACL(((1, b'f'*16),))
    with pytest.raises(OSError, match='another principal'):
        inspect(monkeypatch, api)
    assert len(api.freed) == 2 and api.freed[-1] == 1


@pytest.mark.parametrize('result,error', [(1, 0), (-1, errno.EIO), (-1, 0)])
def test_non_darwin_iteration_conventions_fail(monkeypatch, result, error):
    api = ACL(iteration=(result, error))
    with pytest.raises(OSError, match='unreadable'):
        inspect(monkeypatch, api)
    assert api.freed == [1]


def test_unknown_tag_and_owner_lookup_error_fail(monkeypatch):
    api = ACL(((17, b'o'*16),))
    with pytest.raises(OSError, match='entry type'):
        inspect(monkeypatch, api)
    assert api.freed == [1]
    api = ACL(((1, b'o'*16),), uuid_error=errno.ENOENT)
    with pytest.raises(OSError, match='owner UUID'):
        inspect(monkeypatch, api)
    assert len(api.freed) == 2


def test_acl_entry_count_is_bounded(monkeypatch):
    exact = ACL(tuple((2, b'f'*16) for _ in range(128)))
    assert inspect(monkeypatch, exact) is None
    assert len(exact.freed) == 129
    api = ACL(tuple((2, b'f'*16) for _ in range(129)))
    with pytest.raises(OSError, match='oversized'):
        inspect(monkeypatch, api)
    assert len(api.freed) == 129  # 128 qualifiers and the ACL itself.


def test_acl_read_invalid_object_null_qualifier_and_release_failures(monkeypatch):
    api = ACL()
    api.acl_valid = lambda _: -1
    with pytest.raises(OSError, match='invalid'):
        inspect(monkeypatch, api)
    assert api.freed == [1]
    api = ACL(((1, b'o'*16),))
    api.acl_get_qualifier = lambda _: None
    with pytest.raises(OSError, match='principal'):
        inspect(monkeypatch, api)
    assert api.freed == [1]
    api = ACL(((2, b'f'*16),))
    def release(value):
        api.freed.append(value)
        return -1 if value != 1 else 0
    api.acl_free = release
    with pytest.raises(OSError, match='release'):
        inspect(monkeypatch, api)
    assert len(api.freed) == 2 and api.freed[-1] == 1


def test_descriptor_link_count_change_is_refused_and_descriptor_closed(monkeypatch):
    before = SimpleNamespace(st_dev=1, st_ino=2, st_uid=501, st_mode=0o100600,
        st_nlink=1, st_size=0, st_mtime_ns=4, st_ctime_ns=5)
    after = SimpleNamespace(**{**vars(before), 'st_nlink': 2})
    states = iter((before, after))
    closed = []
    monkeypatch.setattr(keyfile, 'os', SimpleNamespace(geteuid=lambda:501,
        open=lambda *_:7, fstat=lambda _:next(states), close=closed.append,
        O_RDONLY=0, O_NOFOLLOW=1, O_NONBLOCK=2))
    monkeypatch.setattr(keyfile, '_darwin_verify_acl', lambda *_:None)
    with pytest.raises(OSError, match='changed during ACL'):
        keyfile._darwin_permissions(SimpleNamespace(lstat=lambda:before))
    assert closed == [7]


def test_failed_empty_file_check_preserves_old_key_without_secret_write(tmp_path, monkeypatch):
    target = tmp_path/'identity.json'
    target.write_text('old synthetic key', encoding='utf-8')
    seen = []
    def reject(path, force=False):
        assert force and Path(path).read_bytes() == b''
        seen.append(Path(path))
        return False, 'foreign inherited ACL'
    monkeypatch.setattr(keyfile, 'harden_and_check', reject)
    assert keyfile.write_private(target, 'new synthetic secret') == (False, 'foreign inherited ACL')
    assert target.read_text() == 'old synthetic key'
    assert len(seen) == 1 and seen[0].read_bytes() == b''


def test_predictable_old_temporary_hardlink_is_not_followed(tmp_path):
    outside = tmp_path/'outside-sentinel'
    outside.write_bytes(b'preserve me')
    target = tmp_path/'identity.json'
    os.link(outside, tmp_path/'identity.json.tmp')
    ok, reason = keyfile.write_private(target, 'synthetic secret')
    assert ok, reason
    assert outside.read_bytes() == b'preserve me'
    assert target.read_text() == 'synthetic secret'


def test_parent_acl_refusal_happens_before_any_temporary_file(tmp_path, monkeypatch):
    target = tmp_path/'identity.json'
    monkeypatch.setattr(keyfile, 'sys', SimpleNamespace(platform='darwin'))
    def reject(path, *, storage_parent=False):
        assert path == tmp_path and storage_parent
        raise OSError('foreign directory mutation ACL')
    monkeypatch.setattr(keyfile, '_darwin_permissions', reject)
    ok, reason = keyfile.write_private(target, 'synthetic secret')
    assert not ok and 'directory mutation' in reason
    assert not target.exists() and list(tmp_path.iterdir()) == []


@pytest.mark.skipif(sys.platform != 'darwin', reason='native Apple extended ACL required')
def test_native_foreign_read_allow_defeats_mode600_and_is_rejected(tmp_path):
    target = tmp_path/'synthetic-key.json'
    target.write_text('synthetic fixture', encoding='utf-8')
    os.chmod(target, 0o600)
    subprocess.run(['/bin/chmod', '+a', 'everyone allow read', str(target)], check=True, timeout=10)  # unguarded-launch: local chmod on a synthetic temp fixture; no relay/client access.
    assert target.stat().st_mode & 0o777 == 0o600
    ok, reason = keyfile.is_private(target)
    assert not ok and 'another principal' in reason


@pytest.mark.skipif(sys.platform != 'darwin', reason='native Apple inheritable ACL required')
def test_native_inherited_acl_refuses_secret_before_disk_write(tmp_path):
    directory = tmp_path/'storage'
    directory.mkdir(mode=0o700)
    subprocess.run(['/bin/chmod', '+a', 'everyone allow read,file_inherit,directory_inherit', str(directory)], check=True, timeout=10)  # unguarded-launch: local chmod on a synthetic temp fixture; no relay/client access.
    target = directory/'identity.json'
    ok, reason = keyfile.write_private(target, 'must never reach the disk')
    assert not ok and 'macOS' in reason
    assert not target.exists()
    assert all(b'must never reach the disk' not in p.read_bytes() for p in directory.iterdir() if p.is_file())


@pytest.mark.skipif(sys.platform != 'darwin', reason='native Apple key-temp ACL required')
def test_native_empty_temporary_file_acl_is_checked_before_secret_write(tmp_path, monkeypatch):
    original = keyfile.tempfile.mkstemp
    def inherited_acl(*args, **kwargs):
        fd, name = original(*args, **kwargs)
        subprocess.run(['/bin/chmod', '+a', 'everyone allow read', name], check=True, timeout=10)  # unguarded-launch: inject ACL only onto an owned empty native fixture; no secret is present.
        return fd, name
    monkeypatch.setattr(keyfile.tempfile, 'mkstemp', inherited_acl)
    target = tmp_path/'identity.json'
    ok, reason = keyfile.write_private(target, 'synthetic secret must stay in memory')
    assert not ok and 'macOS' in reason
    assert not target.exists()
    artifacts = list(tmp_path.glob('.identity.json-*.tmp'))
    assert len(artifacts) == 1 and artifacts[0].read_bytes() == b''


@pytest.mark.skipif(sys.platform != 'darwin', reason='native Apple cache ACL-only mutation required')
def test_native_acl_only_mutation_is_rechecked_even_with_cached_fingerprint(tmp_path, monkeypatch):
    target = tmp_path/'identity.json'
    assert keyfile.write_private(target, 'synthetic cache fixture')[0]
    stamp = keyfile._fingerprint(target)
    subprocess.run(['/bin/chmod', '+a', 'everyone allow read', str(target)], check=True, timeout=10)  # unguarded-launch: mutate only a synthetic native key fixture ACL, never owner data.
    assert target.stat().st_mode & 0o777 == 0o600
    monkeypatch.setattr(keyfile, '_fingerprint', lambda _:stamp)
    ok, reason = keyfile.harden_and_check(target)
    assert not ok and 'macOS' in reason
