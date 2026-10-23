"""Synthetic lock tests; run this file directly for a socket-guarded pytest run."""
import errno
import importlib
import importlib.util
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
from contextlib import contextmanager
from types import SimpleNamespace


def _socket_guard(event, args):
    if event.startswith("socket."):
        raise AssertionError("inbox lock tests forbid sockets and DNS")


if __name__ == "__main__":
    sys.addaudithook(_socket_guard)

import network_guard
import pytest


LOCK_NAME = ".receiver.lock"
SDK = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_network():
    """These tests must remain fully offline, and the complete boundary is enforced.

    A local `socket.connect` stub previously guarded only one of four paths: async
    connections, datagrams, and name resolution bypassed the assertion. The suite once
    had eight such copies; one boundary now protects the entire run.
    """
    with network_guard.no_network("inbox lock tests forbid sockets and DNS"):
        yield


def _api():
    assert importlib.util.find_spec("a4a.inbox_lock") is not None, "receiver lock is missing"
    return importlib.import_module("a4a.inbox_lock")


def _child(directory, action):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.Popen(
        [sys.executable, "-X", "utf8", "-B", str(Path(__file__).resolve()),
         "--lock-child", str(directory), action],
        cwd=SDK, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )


def _probe(directory, expected):
    child = _child(directory, "probe")
    try:
        stdout, stderr = child.communicate(timeout=5)
        assert child.returncode == 0, stderr
        assert stdout.strip() == expected, (stdout, stderr)
        assert stderr == ""
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)


@contextmanager
def _holder(directory):
    child = _child(directory, "hold")
    try:
        # A reader thread bounds startup without sockets or polling sleeps.
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as pool:
            line = pool.submit(child.stdout.readline)
            try:
                assert line.result(timeout=5).strip() == "held"
            except BaseException:
                child.kill()
                raise
        yield child
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)


def _record_opens(api, monkeypatch):
    original = api.os.open
    descriptors = []

    def opened(*args, **kwargs):
        fd = original(*args, **kwargs)
        descriptors.append(fd)
        return fd

    monkeypatch.setattr(api.os, "open", opened)
    return descriptors


def _assert_closed(descriptors):
    assert descriptors
    for fd in descriptors:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF


def _changed_stat(info, **changes):
    values = {name: getattr(info, name) for name in (
        "st_mode", "st_nlink", "st_dev", "st_ino", "st_size")}
    values["st_file_attributes"] = getattr(info, "st_file_attributes", 0)
    return SimpleNamespace(**(values | changes))


def test_socket_guard_is_active_before_lock_import():
    """The network boundary is active before the receiver lock is imported.

    The test previously guarded a local stub in this file. It now guards the shared
    run boundary, which can only be tested by ATTEMPTING network access, so the
    attempts are declared as expected. The declaration does not permit a connection:
    it is still rejected, and that rejection is the subject of the test.
    """
    with network_guard.expect_blocked():
        with pytest.raises(AssertionError, match="outside test boundary"):
            socket.create_connection(("never.invalid", 443))
        with pytest.raises(AssertionError, match="outside test boundary"):
            socket.getaddrinfo("never.invalid", 443)


def test_persistent_lock_file_is_reused_without_truncating(tmp_path):
    api = _api()
    with api.receiver_lock(str(tmp_path)):
        path = tmp_path / LOCK_NAME
        assert path.is_file()
    before = path.stat()
    path.write_bytes(b"synthetic existing marker")
    with api.receiver_lock(tmp_path):
        assert os.path.samestat(before, path.stat())
    assert path.read_bytes() == b"synthetic existing marker"
    assert list(tmp_path.iterdir()) == [path]
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_same_process_contention_fails_before_context_body(tmp_path):
    api = _api()
    from a4a.inbox import InboxError
    assert issubclass(api.InboxReceiverBusy, InboxError)
    assert "InboxReceiverBusy" in api.__all__
    with api.receiver_lock(tmp_path):
        with pytest.raises(api.InboxReceiverBusy, match="receiver.*already running") as error:
            with api.receiver_lock(tmp_path):
                pytest.fail("competing receiver reached network/health work")
        assert str(tmp_path) not in str(error.value)
        assert error.value.__suppress_context__
        _probe(tmp_path, "busy")
    _probe(tmp_path, "acquired")


def test_child_cannot_enter_same_profile_but_can_enter_another(tmp_path):
    api = _api()
    first, second = tmp_path / "profile-a", tmp_path / "profile-b"
    first.mkdir()
    second.mkdir()
    with api.receiver_lock(first):
        _probe(first, "busy")
        _probe(second, "acquired")
    _probe(first, "acquired")


@pytest.mark.parametrize("exit_kind", ["normal", "abrupt", "killed"])
def test_child_ownership_is_released_on_exit(tmp_path, exit_kind):
    api = _api()
    with _holder(tmp_path) as child:
        with pytest.raises(api.InboxReceiverBusy):
            with api.receiver_lock(tmp_path):
                pytest.fail("child did not own lock")
        before = (tmp_path / LOCK_NAME).stat()
        if exit_kind == "killed":
            child.kill()
        else:
            child.stdin.write(exit_kind + "\n")
            child.stdin.flush()
        child.wait(timeout=5)
        if exit_kind != "killed":
            assert child.returncode == (23 if exit_kind == "abrupt" else 0)
    with api.receiver_lock(tmp_path):
        assert os.path.samestat(before, (tmp_path / LOCK_NAME).stat())


@pytest.mark.parametrize("exception_type", [ValueError, OSError, KeyboardInterrupt])
def test_body_exception_is_preserved_and_lock_released(tmp_path, exception_type):
    api = _api()
    error = exception_type("synthetic body failure")
    with pytest.raises(exception_type) as caught:
        with api.receiver_lock(tmp_path):
            raise error
    assert caught.value is error
    _probe(tmp_path, "acquired")


def test_missing_directory_is_not_created_and_error_is_sanitized(tmp_path):
    api = _api()
    missing = tmp_path / "sensitive-profile"
    with pytest.raises(api.InboxError) as error:
        with api.receiver_lock(missing):
            pytest.fail("missing inbox accepted")
    assert not missing.exists()
    assert "sensitive-profile" not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.parametrize("kind", ["directory", "hardlink", "symlink", "dangling-symlink", "fifo"])
def test_unsafe_lock_targets_are_rejected_unchanged(tmp_path, kind):
    api = _api()
    target, path = tmp_path / "target", tmp_path / LOCK_NAME
    target.write_bytes(b"do not change")
    if kind == "directory":
        path.mkdir()
    elif kind == "hardlink":
        os.link(target, path)
    elif kind in ("symlink", "dangling-symlink"):
        try:
            path.symlink_to(target if kind == "symlink" else tmp_path / "absent")
        except OSError as error:
            if os.name == "nt" and error.winerror == 1314:
                pytest.skip("Windows symlink privilege unavailable")
            raise
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("POSIX FIFO test")
        os.mkfifo(path)
    before = path.lstat()
    with pytest.raises(api.InboxError, match="unsafe.*lock"):
        with api.receiver_lock(tmp_path):
            pytest.fail("unsafe lock target accepted")
    assert os.path.samestat(before, path.lstat())
    assert target.read_bytes() == b"do not change"


@pytest.mark.parametrize("source", ["path", "descriptor"])
@pytest.mark.parametrize("change", [
    {"st_file_attributes": 0x400}, {"st_nlink": 2},
    {"st_mode": stat.S_IFIFO | 0o600}, {"st_mode": stat.S_IFLNK | 0o600},
])
def test_unsafe_metadata_is_rejected_on_path_and_descriptor(tmp_path, monkeypatch, source, change):
    api = _api()
    path = tmp_path / LOCK_NAME
    path.touch()
    descriptors = _record_opens(api, monkeypatch)
    with monkeypatch.context() as patch:
        if source == "path":
            original = Path.lstat
            patch.setattr(Path, "lstat", lambda self: _changed_stat(original(self), **change))
        else:
            original = api.os.fstat
            patch.setattr(api.os, "fstat", lambda fd: _changed_stat(original(fd), **change))
        with pytest.raises(api.InboxError, match="unsafe.*lock"):
            with api.receiver_lock(tmp_path):
                pytest.fail("unsafe metadata accepted")
    if descriptors:
        _assert_closed(descriptors)
    _probe(tmp_path, "acquired")


def test_opened_descriptor_must_match_lock_path(tmp_path, monkeypatch):
    api = _api()
    other = tmp_path / "other"
    other.write_bytes(b"untouched")
    (tmp_path / LOCK_NAME).touch()
    original = api.os.open
    descriptors = []
    with monkeypatch.context() as patch:
        def wrong_file(path, flags, mode=0o777):
            fd = original(other, os.O_RDWR)
            descriptors.append(fd)
            return fd
        patch.setattr(api.os, "open", wrong_file)
        with pytest.raises(api.InboxError, match="lock.*changed"):
            with api.receiver_lock(tmp_path):
                pytest.fail("descriptor/path mismatch accepted")
    _assert_closed(descriptors)
    assert other.read_bytes() == b"untouched"
    _probe(tmp_path, "acquired")


def test_lock_path_is_revalidated_after_acquisition(tmp_path, monkeypatch):
    api = _api()
    path = tmp_path / LOCK_NAME
    path.touch()
    original = Path.lstat
    calls = 0
    descriptors = _record_opens(api, monkeypatch)
    with monkeypatch.context() as patch:
        def replaced(self):
            nonlocal calls
            calls += 1
            info = original(self)
            return _changed_stat(info, st_ino=info.st_ino + 1) if calls >= 3 else info
        patch.setattr(Path, "lstat", replaced)
        with pytest.raises(api.InboxError, match="lock.*changed"):
            with api.receiver_lock(tmp_path):
                pytest.fail("lock path changed during acquisition")
    assert calls >= 3
    _assert_closed(descriptors)
    _probe(tmp_path, "acquired")


@pytest.mark.parametrize("failure_at", [2, 3])
def test_path_disappearing_during_acquisition_closes_descriptor(tmp_path, monkeypatch, failure_at):
    api = _api()
    (tmp_path / LOCK_NAME).touch()
    descriptors = _record_opens(api, monkeypatch)
    original = Path.lstat
    calls = 0
    with monkeypatch.context() as patch:
        def missing(self):
            nonlocal calls
            calls += 1
            if calls == failure_at:
                raise FileNotFoundError(errno.ENOENT, "SENSITIVE PATH", str(self))
            return original(self)
        patch.setattr(Path, "lstat", missing)
        with pytest.raises(api.InboxError) as error:
            with api.receiver_lock(tmp_path):
                pytest.fail("missing lock path accepted")
    assert "SENSITIVE" not in str(error.value)
    assert error.value.__suppress_context__
    _assert_closed(descriptors)
    _probe(tmp_path, "acquired")


def test_descriptor_is_not_inheritable(tmp_path, monkeypatch):
    api = _api()
    descriptors = _record_opens(api, monkeypatch)
    with api.receiver_lock(tmp_path):
        assert descriptors
        assert not os.get_inheritable(descriptors[0])
    _assert_closed(descriptors)


def _native_lock(monkeypatch, replacement):
    if os.name == "nt":
        import msvcrt
        monkeypatch.setattr(msvcrt, "locking", replacement)
    else:
        import fcntl
        monkeypatch.setattr(fcntl, "flock", replacement)


def test_noncontention_lock_failure_is_sanitized_and_closes_descriptor(tmp_path, monkeypatch):
    api = _api()
    descriptors = _record_opens(api, monkeypatch)
    with monkeypatch.context() as patch:
        def broken(*args):
            raise OSError(errno.EIO, "SENSITIVE OS ERROR", str(tmp_path))
        _native_lock(patch, broken)
        with pytest.raises(api.InboxError) as error:
            with api.receiver_lock(tmp_path):
                pytest.fail("failed OS lock accepted")
    assert not isinstance(error.value, api.InboxReceiverBusy)
    assert "SENSITIVE" not in str(error.value)
    assert str(tmp_path) not in str(error.value)
    assert error.value.__suppress_context__
    _assert_closed(descriptors)
    _probe(tmp_path, "acquired")


@pytest.mark.parametrize("body_fails", [False, True])
def test_unlock_failure_still_closes_and_does_not_mask_body(tmp_path, monkeypatch, body_fails):
    api = _api()
    descriptors = _record_opens(api, monkeypatch)
    body_error = KeyboardInterrupt("synthetic cancellation")
    with monkeypatch.context() as patch:
        with pytest.raises(KeyboardInterrupt if body_fails else api.InboxError) as error:
            with api.receiver_lock(tmp_path):
                def broken(*args):
                    raise OSError(errno.EIO, "SENSITIVE UNLOCK ERROR")
                _native_lock(patch, broken)
                if body_fails:
                    raise body_error
    if body_fails:
        assert error.value is body_error
    else:
        assert "SENSITIVE" not in str(error.value)
        assert error.value.__suppress_context__
    _assert_closed(descriptors)
    _probe(tmp_path, "acquired")


@pytest.mark.parametrize("body_fails", [False, True])
def test_close_failure_is_sanitized_without_retry_or_masking_body(tmp_path, monkeypatch, body_fails):
    api = _api()
    original = os.close
    closed = []
    body_error = ValueError("synthetic body failure")
    with monkeypatch.context() as patch:
        def close_then_fail(fd):
            original(fd)
            closed.append(fd)
            raise OSError(errno.EIO, "SENSITIVE CLOSE ERROR")
        with pytest.raises(ValueError if body_fails else api.InboxError) as error:
            with api.receiver_lock(tmp_path):
                patch.setattr(api.os, "close", close_then_fail)
                if body_fails:
                    raise body_error
    assert len(closed) == 1
    if body_fails:
        assert error.value is body_error
    else:
        assert "SENSITIVE" not in str(error.value)
        assert error.value.__suppress_context__
    _assert_closed(closed)
    _probe(tmp_path, "acquired")


@pytest.mark.parametrize("platform", ["nt", "posix"])
def test_platform_calls_use_nonblocking_exclusive_lock_and_matching_unlock(monkeypatch, platform):
    api = _api()
    calls = []
    native_os = SimpleNamespace(
        name=platform, SEEK_SET=os.SEEK_SET,
        lseek=lambda *args: calls.append(("seek", *args)),
        close=lambda fd: calls.append(("close", fd)),
    )
    monkeypatch.setattr(api, "os", native_os)
    if platform == "nt":
        native = SimpleNamespace(
            LK_NBLCK=2, LK_UNLCK=0,
            locking=lambda *args: calls.append(("lock", *args)),
        )
        monkeypatch.setitem(sys.modules, "msvcrt", native)
        expected = [("seek", 42, 0, os.SEEK_SET), ("lock", 42, native.LK_NBLCK, 1),
                    ("seek", 42, 0, os.SEEK_SET), ("lock", 42, native.LK_UNLCK, 1)]
    else:
        native = SimpleNamespace(
            LOCK_EX=2, LOCK_NB=4, LOCK_UN=8,
            flock=lambda *args: calls.append(("lock", *args)),
        )
        monkeypatch.setitem(sys.modules, "fcntl", native)
        expected = [("lock", 42, native.LOCK_EX | native.LOCK_NB),
                    ("lock", 42, native.LOCK_UN)]
    api._acquire(42)
    api._release(42, True)
    assert calls == expected + [("close", 42)]


def _child_main(directory, action):
    sys.path.insert(0, str(SDK))
    from a4a.inbox_lock import InboxReceiverBusy, receiver_lock
    try:
        with receiver_lock(directory):
            if action == "probe":
                print("acquired", flush=True)
            else:
                print("held", flush=True)
                if sys.stdin.readline().strip() == "abrupt":
                    os._exit(23)
    except InboxReceiverBusy:
        print("busy", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--lock-child":
        _child_main(sys.argv[2], sys.argv[3])
    else:
        os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        sys.path.insert(0, str(SDK))
        raise SystemExit(pytest.main([
            "-q", "-o", "addopts=", "-p", "no:cacheprovider", "-p", "pytest_asyncio.plugin",
            str(Path(__file__).resolve()), *sys.argv[1:],
        ]))
