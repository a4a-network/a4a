"""Synthetic continuity regressions; executable as a guarded pytest runner."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import traceback
from unittest.mock import Mock


# Install before importing pytest or A4A, including in every child interpreter.
_SOCKET_GUARD = r'''
import ipaddress
import sys

def _loopback_only(event, args):
    if event in {"socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg"}:
        address = args[-1]
        if not isinstance(address, tuple):
            return  # Local Unix sockets have no network destination.
        host = address[0]
    elif event in {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"}:
        host = args[0]
    else:
        return
    if host in {"localhost", b"localhost"}:
        return
    if isinstance(host, bytes):
        host = host.decode("ascii")
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise AssertionError("non-loopback socket access forbidden by identity tests")

sys.addaudithook(_loopback_only)
'''
exec(_SOCKET_GUARD)

_ROOT = Path(__file__).resolve().parents[2]


def _isolated_environment(home):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("A4A_")}
    env.update({
        "A4A_HOME": str(home),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "A4A_RELAY": "ws://127.0.0.1:1",
        "A4A_MANDATE_AUTO": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONPATH": os.pathsep.join((str(_ROOT / "mcp-server"),
                                      str(_ROOT / "sdk-python"))),
    })
    return env


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="a4a-identity-tests-") as directory:
        environment = _isolated_environment(Path(directory))
        for name in list(os.environ):
            if name.startswith("A4A_"):
                del os.environ[name]
        os.environ.update(environment)
        sys.path[:0] = environment["PYTHONPATH"].split(os.pathsep)
        import pytest

        arguments = sys.argv[1:] or [str(Path(__file__).resolve())]
        raise SystemExit(pytest.main([
            "-p", "pytest_asyncio.plugin", "-p", "no:cacheprovider",
            "--basetemp", str(Path(directory) / "pytest"), *arguments,
        ]))

import pytest


@pytest.fixture(autouse=True)
def profile(tmp_path, monkeypatch):
    home = tmp_path / "profile"
    home.mkdir()
    for name in list(os.environ):
        if name.startswith("A4A_"):
            monkeypatch.delenv(name)
    for name, value in _isolated_environment(home).items():
        if name.startswith("A4A_") or name in {"HOME", "USERPROFILE"}:
            monkeypatch.setenv(name, value)
    from a4a_mcp import identity

    monkeypatch.setattr(identity, "IDENTITY_DIR", home)
    monkeypatch.setattr(identity, "IDENTITY_FILE", home / "identity.json")
    return identity


def _child(home, snippet, *args):
    return subprocess.Popen(
        [sys.executable, "-B", "-c", _SOCKET_GUARD + snippet, *map(str, args)],
        cwd=_ROOT, env=_isolated_environment(home),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


def _stop(children):
    for child in children:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)


def test_socket_guard_is_active():
    import socket

    import network_guard

    # A synthetic event invokes ALL registered audit hooks without resolving a name, so no
    # packet leaves the process. This validates both hook logic and hook registration.
    #
    # This once called real `getaddrinfo` inside a wrapper that allowed the call "for product
    # protection." The wrapper was invalid twice over: the protection was a hook in this same
    # file rather than product code, and a resolver `gaierror` prevented the attempt from being
    # recorded even after it reached the resolver.
    # The event shape is REAL, measured on CPython 3.11.9: five arguments
    # `(host, port, family, type, protocol)`. A synthetic two-argument call with host bytes
    # could bypass a hook that inspects length or type. A reviewer correctly noted that
    # "a dry event is strictly better" is false as a general claim. It tests hook logic and
    # registration, but neither proves the real call path nor guarantees reaching every hook:
    # the first hook that raises stops propagation.
    with pytest.raises(AssertionError, match="non-loopback"):
        sys.audit("socket.getaddrinfo", "never.invalid", 443, 0, 0, 0)
    # The TEST-RUN BOUNDARY rejects the connection, not the local audit hook. It wraps `connect`
    # and fires before the hook inside the system call. The name-resolution check above still
    # reaches the hook and is what this test guards.
    #
    # Mark the attempt expected: a negative control may VERIFY denial, but the connection still
    # must not occur.
    import network_guard
    with socket.socket() as connection:
        with network_guard.expect_blocked():
            with pytest.raises(AssertionError, match="outside test boundary"):
                connection.connect(("192.0.2.1", 443))


_SURVIVORS = [("inbox-policy.json",), ("inbox/inbox.sqlite3",),
              ("inbox-policy.json", "inbox/inbox.sqlite3")]


@pytest.mark.parametrize("survivors", _SURVIVORS)
@pytest.mark.parametrize("entry", ["agent", "owner", "my_address"])
async def test_missing_identity_with_inbox_state_fails_closed(profile, monkeypatch, survivors, entry):
    from a4a_mcp import server

    profile.load_or_create_identity()
    saved = {}
    for relative in survivors:
        path = profile.IDENTITY_DIR / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic persisted state, intentionally not parsed")
        saved[path] = path.read_bytes()
    profile.IDENTITY_FILE.unlink()

    def forbid_keys(*args, **kwargs):
        pytest.fail("lost identity must be refused before generating any Keys")

    monkeypatch.setattr(profile, "Keys", forbid_keys)
    with pytest.raises(ValueError, match=r"identity.*missing.*inbox.*restore"):
        if entry == "my_address":
            await server.a4a_my_address()
        elif entry == "owner":
            profile.load_or_create_owner_identity()
        else:
            profile.load_or_create_identity()
    assert not profile.IDENTITY_FILE.exists()
    assert all(path.read_bytes() == contents for path, contents in saved.items())
    assert not list(profile.IDENTITY_DIR.glob("*.tmp"))


@pytest.mark.parametrize("payload", [b"null", b"[]", b'"invalid"', b"42"])
@pytest.mark.parametrize("entry", ["agent", "owner", "public_owner"])
def test_nonobject_identity_is_not_treated_as_missing(profile, monkeypatch, payload, entry):
    profile.IDENTITY_FILE.write_bytes(payload)

    def forbid_keys(*args, **kwargs):
        pytest.fail("malformed identity must not generate or load any Keys")

    monkeypatch.setattr(profile, "Keys", forbid_keys)
    operation = {"agent": profile.load_or_create_identity,
                 "owner": profile.load_or_create_owner_identity,
                 "public_owner": profile.owner_public_key}[entry]
    with pytest.raises(ValueError, match="identity.*JSON object"):
        operation()
    assert profile.IDENTITY_FILE.read_bytes() == payload
    assert not list(profile.IDENTITY_DIR.glob("*.tmp"))


def test_public_owner_lookup_without_identity_returns_absence(profile):
    """An unused profile has no owner binding; absence is not a read failure."""
    assert not profile.IDENTITY_FILE.exists()
    assert profile.owner_public_key() is None
    assert not profile.IDENTITY_FILE.exists()


@pytest.mark.parametrize("value", [1, [], "00", "A" * 64])
def test_public_owner_lookup_rejects_noncanonical_binding(profile, value):
    from a4a import Keys

    agent = Keys()
    payload = {
        "privkey_hex": agent.privkey_hex,
        "pubkey_hex": agent.pubkey_hex,
        "owner_pubkey_hex": value,
    }
    profile.IDENTITY_FILE.write_text(json.dumps(payload), encoding="utf-8")
    before = profile.IDENTITY_FILE.read_bytes()

    with pytest.raises(ValueError, match="invalid public owner binding"):
        profile.owner_public_key()
    assert profile.IDENTITY_FILE.read_bytes() == before


def test_identity_changed_between_path_check_and_open_is_rejected(profile, monkeypatch):
    """The descriptor must still name the exact inode inspected before opening."""
    keys = profile.load_or_create_identity()
    before = profile.IDENTITY_FILE.read_bytes()
    actual = profile.IDENTITY_FILE.stat()
    opened = Mock(st_mode=actual.st_mode, st_nlink=1,
                  st_dev=actual.st_dev, st_ino=actual.st_ino + 1,
                  st_file_attributes=0)
    monkeypatch.setattr(profile.os, "fstat", lambda _fd: opened)

    with pytest.raises(ValueError, match="changed while opening"):
        profile.load_or_create_identity()
    assert profile.IDENTITY_FILE.read_bytes() == before
    assert json.loads(before)["pubkey_hex"] == keys.pubkey_hex


@pytest.mark.parametrize("owner_mode", ["none", "colocated", "external"])
async def test_bootstrap_keeps_existing_identity_and_owner_binding(profile, monkeypatch, owner_mode):
    from a4a import Keys
    from a4a_mcp import server

    agent, owner = Keys(), Keys()
    data = {"privkey_hex": agent.privkey_hex, "pubkey_hex": agent.pubkey_hex}
    if owner_mode != "none":
        data["owner_pubkey_hex"] = owner.pubkey_hex
    if owner_mode == "colocated":
        data[profile.OWNER_FIELD] = owner.privkey_hex
    profile.IDENTITY_FILE.write_text(json.dumps(data), encoding="utf-8")
    (profile.IDENTITY_DIR / "inbox-policy.json").write_bytes(b"persisted policy")
    before = profile.IDENTITY_FILE.read_bytes()

    def agent_only(secret=None):
        assert secret == agent.privkey_hex, "bootstrap generated or loaded owner Keys"
        return Keys(secret)

    def forbid_owner():
        pytest.fail("ordinary address lookup must not load the owner secret")

    monkeypatch.setattr(profile, "Keys", agent_only)
    monkeypatch.setattr(server, "load_or_create_owner_identity", forbid_owner)
    assert profile.load_or_create_identity().pubkey_hex == agent.pubkey_hex
    assert agent.pubkey_hex in await server.a4a_my_address()
    assert profile.owner_public_key() == (owner.pubkey_hex if owner_mode != "none" else None)
    assert profile.IDENTITY_FILE.read_bytes() == before


@pytest.mark.parametrize("link_kind", ["hardlink", "symlink", "dangling", "directory"])
@pytest.mark.parametrize("entry", ["agent", "owner", "public_owner"])
def test_linked_or_nonregular_identity_is_rejected(profile, tmp_path, entry, link_kind):
    from a4a import Keys

    outside = tmp_path / "outside.json"
    agent, owner = Keys(), Keys()
    before = json.dumps({"privkey_hex": agent.privkey_hex,
                         "owner_privkey_hex": owner.privkey_hex,
                         "owner_pubkey_hex": owner.pubkey_hex}).encode()
    if link_kind != "dangling":
        outside.write_bytes(before)
    try:
        if link_kind == "hardlink":
            os.link(outside, profile.IDENTITY_FILE)
        elif link_kind == "directory":
            profile.IDENTITY_FILE.mkdir()
        else:
            profile.IDENTITY_FILE.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"filesystem does not support {link_kind}: {exc}")
    operation = {"agent": profile.load_or_create_identity,
                 "owner": profile.load_or_create_owner_identity,
                 "public_owner": profile.owner_public_key}[entry]
    with pytest.raises(ValueError, match=r"identity.*(linked|regular|unsafe)"):
        operation()
    if link_kind == "dangling":
        assert not outside.exists()
        assert profile.IDENTITY_FILE.is_symlink()
    else:
        assert outside.read_bytes() == before


def test_creation_flushes_and_syncs_private_temporary_before_publish(profile, monkeypatch):
    from a4a import keyfile
    from a4a_mcp.profile_lock import profile_lock

    fsync, replace = os.fsync, os.replace
    observed = []

    def synced(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            assert not profile.IDENTITY_FILE.exists()
            candidates = list(profile.IDENTITY_DIR.glob("*.tmp"))
            assert len(candidates) == 1
            data = json.loads(candidates[0].read_text(encoding="utf-8"))
            assert data["privkey_hex"] and data["pubkey_hex"]
            assert keyfile.is_private(candidates[0])[0]
            observed.append("file-sync")
        fsync(fd)

    def published(source, destination):
        assert Path(source).parent == profile.IDENTITY_DIR
        assert Path(destination) == profile.IDENTITY_FILE
        assert observed == ["file-sync"]
        with pytest.raises(ValueError, match="busy"):
            with profile_lock(profile.IDENTITY_DIR):
                pytest.fail("publication did not hold the OS profile lock")
        replace(source, destination)
        observed.append("publish")

    monkeypatch.setattr(os, "fsync", synced)
    monkeypatch.setattr(os, "replace", published)
    keys = profile.load_or_create_identity()
    assert observed == ["file-sync", "publish"]
    assert json.loads(profile.IDENTITY_FILE.read_text())["pubkey_hex"] == keys.pubkey_hex
    assert keyfile.is_private(profile.IDENTITY_FILE)[0]
    assert not list(profile.IDENTITY_DIR.glob("*.tmp"))


@pytest.mark.parametrize("failure", ["serialize", "fsync", "publish"])
def test_failed_creation_leaves_no_partial_identity(profile, monkeypatch, failure):
    def fail(*args, **kwargs):
        if failure == "serialize":
            stream = args[1]
            stream.write('{"privkey_hex": "partial')
            stream.flush()
        raise OSError("injected creation failure")

    with monkeypatch.context() as patch:
        if failure == "serialize":
            patch.setattr(json, "dump", fail)
        else:
            patch.setattr(os, "fsync" if failure == "fsync" else "replace", fail)
        with pytest.raises(OSError, match="injected creation failure"):
            profile.load_or_create_identity()
    assert not profile.IDENTITY_FILE.exists()
    assert not list(profile.IDENTITY_DIR.glob("*.tmp"))
    keys = profile.load_or_create_identity()
    assert profile.load_or_create_identity().pubkey_hex == keys.pubkey_hex


@pytest.mark.parametrize("failure", ["false", "os_error", "runtime_error", "timeout"])
@pytest.mark.parametrize("entry", ["bootstrap", "owner_update"])
def test_hardening_failure_aborts_identity_write(profile, monkeypatch, caplog, failure, entry):
    from a4a import Keys, keyfile

    before = None
    if entry == "owner_update":
        profile.load_or_create_identity()
        before = profile.IDENTITY_FILE.read_bytes()
    new_keys = Keys()
    sensitive_detail = f"synthetic hardening failure: {new_keys.privkey_hex}"
    attempts = []
    serialize = Mock(wraps=json.dump)
    publish = Mock(wraps=os.replace)

    def fail_hardening(path):
        path = Path(path)
        assert path.parent == profile.IDENTITY_DIR
        assert path.suffix == ".tmp"
        assert path.read_bytes() == b""
        attempts.append(path)
        if failure == "os_error":
            raise OSError(sensitive_detail)
        if failure == "runtime_error":
            raise RuntimeError(sensitive_detail)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(sensitive_detail, 1, output=sensitive_detail)
        return False, sensitive_detail

    operation = (profile.load_or_create_identity if entry == "bootstrap"
                 else profile.load_or_create_owner_identity)
    with monkeypatch.context() as patch:
        patch.setattr(profile, "Keys", lambda: new_keys)
        patch.setattr(keyfile, "harden_and_check", fail_hardening)
        patch.setattr(json, "dump", serialize)
        patch.setattr(os, "replace", publish)
        with pytest.raises(ValueError, match="identity.*permissions") as caught:
            operation()

    assert len(attempts) == 1
    serialize.assert_not_called()
    publish.assert_not_called()
    assert all(not path.exists() for path in attempts)
    assert not list(profile.IDENTITY_DIR.glob("*.tmp"))
    if before is None:
        assert not profile.IDENTITY_FILE.exists()
    else:
        assert profile.IDENTITY_FILE.read_bytes() == before
    diagnostics = caplog.text + "".join(traceback.format_exception(caught.value))
    assert new_keys.privkey_hex not in diagnostics
    assert sensitive_detail not in diagnostics
    assert all(new_keys.privkey_hex.encode() not in path.read_bytes()
               for path in profile.IDENTITY_DIR.iterdir() if path.is_file())

    # A transient failure must release the file and lock so a clean retry succeeds.
    recovered = operation()
    assert operation().pubkey_hex == recovered.pubkey_hex
    if before is not None:
        assert profile.load_or_create_identity().privkey_hex == json.loads(before)["privkey_hex"]
    assert not list(profile.IDENTITY_DIR.glob("*.tmp"))


def test_existing_identity_read_keeps_best_effort_hardening(profile, monkeypatch, caplog):
    from a4a import keyfile

    keys = profile.load_or_create_identity()
    before = profile.IDENTITY_FILE.read_bytes()
    monkeypatch.setattr(keyfile, "harden_and_check", lambda path: (False, "synthetic ACL failure"))
    assert profile.load_or_create_identity().pubkey_hex == keys.pubkey_hex
    assert profile.IDENTITY_FILE.read_bytes() == before
    assert "synthetic ACL failure" in caplog.text
    assert not list(profile.IDENTITY_DIR.glob("*.tmp"))


@pytest.mark.parametrize("appearing", ["identity.json", "inbox-policy.json", "inbox/inbox.sqlite3"])
def test_creation_does_not_overwrite_state_appearing_before_publish(profile, monkeypatch, appearing):
    destination = profile.IDENTITY_DIR / appearing
    contents = b"synthetic state from another local writer"
    fsync = os.fsync

    def state_appears(fd):
        fsync(fd)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(contents)

    monkeypatch.setattr(os, "fsync", state_appears)
    with pytest.raises(ValueError, match="identity.*(appeared|restore)"):
        profile.load_or_create_identity()
    assert destination.read_bytes() == contents
    if appearing != "identity.json":
        assert not profile.IDENTITY_FILE.exists()
    assert not list(profile.IDENTITY_DIR.glob("*.tmp"))


@pytest.mark.parametrize("failure", ["serialize", "fsync", "publish"])
def test_failed_owner_creation_preserves_agent_file(profile, monkeypatch, failure):
    agent = profile.load_or_create_identity()
    before = profile.IDENTITY_FILE.read_bytes()

    def fail(*args, **kwargs):
        if failure == "serialize":
            args[1].write('{"partial":')
            args[1].flush()
        raise OSError("injected owner creation failure")

    with monkeypatch.context() as patch:
        if failure == "serialize":
            patch.setattr(json, "dump", fail)
        else:
            patch.setattr(os, "fsync" if failure == "fsync" else "replace", fail)
        with pytest.raises(OSError, match="injected owner creation failure"):
            profile.load_or_create_owner_identity()
    assert profile.IDENTITY_FILE.read_bytes() == before
    assert profile.load_or_create_identity().pubkey_hex == agent.pubkey_hex
    assert not list(profile.IDENTITY_DIR.glob("*.tmp"))


def test_process_crash_before_publish_leaves_no_partial_identity(profile):
    child = _child(profile.IDENTITY_DIR, r'''
import os
from a4a_mcp import identity

def crash(fd):
    os._exit(73)

identity.os.fsync = crash
identity.load_or_create_identity()
''')
    try:
        _, error = child.communicate(timeout=30)
        assert child.returncode == 73, error
    finally:
        _stop([child])
    assert not profile.IDENTITY_FILE.exists()
    leftovers = {path: path.read_bytes() for path in profile.IDENTITY_DIR.glob("*.tmp")}
    assert leftovers
    keys = profile.load_or_create_identity()
    assert profile.load_or_create_identity().pubkey_hex == keys.pubkey_hex
    assert all(path.read_bytes() == before for path, before in leftovers.items())


def test_concurrent_bootstraps_share_one_identity_under_os_lock(profile):
    from a4a_mcp.profile_lock import profile_lock

    children = []
    markers = [profile.IDENTITY_DIR / f"busy-{index}" for index in range(3)]
    snippet = r'''
import json
from pathlib import Path
import sys
import time
from a4a_mcp import identity

deadline = time.monotonic() + 30
while True:
    try:
        keys = identity.load_or_create_identity()
        print(json.dumps({"pubkey": keys.pubkey_hex}), flush=True)
        break
    except ValueError as exc:
        if "identity is busy" not in str(exc) or time.monotonic() >= deadline:
            raise
        Path(sys.argv[1]).touch()
        time.sleep(0.02)
'''
    try:
        with profile_lock(profile.IDENTITY_DIR):
            for marker in markers:
                children.append(_child(profile.IDENTITY_DIR, snippet, marker))
            deadline = time.monotonic() + 20
            while not all(marker.exists() for marker in markers):
                assert all(child.poll() is None for child in children)
                assert time.monotonic() < deadline, "children did not contend on the OS lock"
                time.sleep(0.02)
            assert not profile.IDENTITY_FILE.exists()
        public_keys = []
        for child in children:
            output, error = child.communicate(timeout=30)
            assert child.returncode == 0, error
            public_keys.append(json.loads(output)["pubkey"])
        assert len(set(public_keys)) == 1
        assert profile.load_or_create_identity().pubkey_hex == public_keys[0]
        assert json.loads(profile.IDENTITY_FILE.read_text())["pubkey_hex"] == public_keys[0]
    finally:
        _stop(children)
