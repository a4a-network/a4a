"""Fail-closed runtime preparation without mutating the test interpreter."""

import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "prepare_python_runtime", ROOT / "scripts/prepare-python-runtime.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def distribution(name, version="1.0", requires=()):
    return SimpleNamespace(metadata={"Name": name}, version=version, requires=list(requires))


def test_snapshot_excludes_only_installers_and_keeps_runtime_metadata():
    result = MODULE.runtime_snapshot([
        distribution("pip"), distribution("setuptools"), distribution("wheel"),
        distribution("A4A_SDK", requires=["example>=1"]), distribution("example", "2.0"),
    ])
    assert result == {"a4a-sdk": {"version": "1.0", "requires": ["example>=1"]},
                      "example": {"version": "2.0", "requires": []}}


@pytest.mark.parametrize("installer", ["pip", "setuptools", "wheel"])
def test_active_installer_dependency_is_rejected(installer):
    with pytest.raises(RuntimeError, match="runtime installer dependency"):
        MODULE.runtime_snapshot([distribution("app", requires=[installer + ">=1"]),
                                 distribution(installer)])


def test_unselected_development_extra_does_not_require_an_installer():
    assert MODULE.runtime_snapshot([
        distribution("app", requires=['setuptools; extra == "dev"']),
    ])["app"]["version"] == "1.0"


def test_requested_extra_activates_its_transitive_installer_edge():
    with pytest.raises(RuntimeError, match="runtime installer dependency"):
        MODULE.runtime_snapshot([
            distribution("dependency", requires=['setuptools; extra == "build"']),
            distribution("app", requires=["dependency[build]"]),
        ])


def test_environment_markers_are_evaluated_not_stripped():
    assert MODULE.runtime_snapshot([
        distribution("app", requires=['pip; python_version < "1"']),
    ])["app"]["requires"] == ['pip; python_version < "1"']


@pytest.mark.parametrize("requires, dependencies, message", [
    (["missing>=1"], [], "missing runtime dependency"),
    (["example>=2"], [distribution("example", "1.0")], "incompatible runtime dependency"),
])
def test_incomplete_or_incompatible_graph_is_rejected(requires, dependencies, message):
    with pytest.raises(RuntimeError, match=message):
        MODULE.runtime_snapshot([distribution("app", requires=requires), *dependencies])


def test_normalized_duplicate_distribution_is_rejected():
    with pytest.raises(RuntimeError, match="duplicate installed distribution"):
        MODULE.runtime_snapshot([distribution("my_pkg"), distribution("my-pkg")])


def test_cyclic_runtime_dependency_graph_terminates():
    result = MODULE.runtime_snapshot([
        distribution("first", requires=["second[use]"]),
        distribution("second", requires=['first[use]; extra == "use"']),
    ])
    assert set(result) == {"first", "second"}


def test_missing_explicit_build_opt_in_prevents_all_mutation(monkeypatch):
    monkeypatch.delenv("A4A_PREPARE_CONTAINER_RUNTIME", raising=False)
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *a, **kw: pytest.fail("no subprocess expected"))
    monkeypatch.setattr(MODULE.shutil, "rmtree", lambda *a, **kw: pytest.fail("no deletion expected"))
    with pytest.raises(RuntimeError, match="explicit root Linux"):
        MODULE.prepare()


def test_dependency_failure_precedes_uninstall_or_bootstrap_removal(monkeypatch):
    monkeypatch.setattr(MODULE, "require_container_stage", lambda: None)
    monkeypatch.setattr(MODULE.metadata, "distributions", lambda: [
        distribution("pip"), distribution("app", requires=["setuptools"]),
    ])
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *a, **kw: pytest.fail("no uninstall expected"))
    monkeypatch.setattr(MODULE.shutil, "rmtree", lambda *a, **kw: pytest.fail("no deletion expected"))
    with pytest.raises(RuntimeError, match="runtime installer dependency"):
        MODULE.prepare()


def test_linked_bootstrap_directory_is_rejected_before_deletion(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "STDLIB", tmp_path)
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == tmp_path / "ensurepip")
    monkeypatch.setattr(MODULE.shutil, "rmtree", lambda *a, **kw: pytest.fail("no deletion expected"))
    with pytest.raises(RuntimeError, match="unexpected ensurepip"):
        MODULE.remove_ensurepip()


def test_missing_bootstrap_directory_is_not_silently_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(MODULE, "STDLIB", tmp_path)
    with pytest.raises(RuntimeError, match="unexpected ensurepip"):
        MODULE.remove_ensurepip()


def privilege_filesystem(monkeypatch, mode=0o6751):
    """Model Linux descriptor operations; never chmod the Windows test filesystem."""
    state = {"mode": stat.S_IFREG | mode, "content": b"unchanged executable\x00bytes",
             "opened": [], "closed": [], "walks": 0, "position": 0,
             "chmods": [], "inode": 17, "directory_mode": stat.S_IFDIR | 0o755}

    def info(file_mode, inode=17):
        return SimpleNamespace(st_mode=file_mode, st_dev=1, st_ino=inode,
                               st_uid=0, st_gid=42, st_size=len(state["content"]),
                               st_mtime_ns=123456)

    def walk(root, *, topdown, onerror, follow_symlinks):
        assert root == "/" and topdown and not follow_symlinks
        state["walks"] += 1
        directories = ["dev", "proc", "sys"]
        yield "/", directories, ["command", "plain", "link", "device"], 31
        assert directories == [], "pseudo-filesystem mounts must be pruned"

    def lstat(name, *, dir_fd, follow_symlinks):
        assert dir_fd == 31 and not follow_symlinks
        return info({"command": state["mode"], "plain": stat.S_IFREG | 0o644,
                     "link": stat.S_IFLNK | 0o777, "device": stat.S_IFCHR | 0o666}[name])

    def open_file(name, flags, *, dir_fd):
        assert name == "command" and dir_fd == 31 and flags == 7
        state["opened"].append(name)
        return 100

    def fstat(descriptor):
        return info(state["directory_mode"] if descriptor == 31 else state["mode"],
                    31 if descriptor == 31 else state["inode"])

    def chmod(descriptor, new_mode):
        assert descriptor in (31, 100)
        state["chmods"].append(new_mode)
        if descriptor == 31:
            state["directory_mode"] = stat.S_IFDIR | new_mode
        else:
            state["mode"] = stat.S_IFREG | new_mode

    def seek(descriptor, offset, origin):
        assert descriptor == 100 and offset == origin == 0
        state["position"] = 0

    def read(descriptor, size):
        assert descriptor == 100
        chunk = state["content"][state["position"]:state["position"] + size]
        state["position"] += len(chunk)
        return chunk

    fake_os = SimpleNamespace(fwalk=walk, stat=lstat, open=open_file, fstat=fstat,
                              fchmod=chmod, close=state["closed"].append,
                              lseek=seek, read=read, O_RDONLY=1, O_NOFOLLOW=2,
                              O_NONBLOCK=4, SEEK_SET=0)
    monkeypatch.setattr(MODULE, "require_container_stage", lambda: None)
    monkeypatch.setattr(MODULE, "os", fake_os)
    return state


@pytest.mark.parametrize("mode", [0o4755, 0o2755, 0o6751, 0o7751])
def test_privilege_removal_preserves_bytes_owners_and_all_other_mode_bits(monkeypatch, mode):
    state = privilege_filesystem(monkeypatch, mode)
    result = MODULE.remove_privilege_bits()
    assert state["chmods"] == [mode & ~0o6000]
    assert state["opened"] == ["command"] and state["closed"] == [100]
    assert state["walks"] == 2
    assert result["regular_files_checked"] == 2
    assert result["remaining_privileged_files"] == []
    assert result["excluded_mount_trees"] == ["/dev", "/proc", "/sys"]
    record, = result["changed_files"]
    assert record == {"path": "/command", "before_mode": oct(mode),
                      "after_mode": oct(mode & ~0o6000), "uid": 0, "gid": 42,
                      "size": len(state["content"]),
                      "sha256": MODULE.hashlib.sha256(state["content"]).hexdigest()}


def test_nonprivileged_files_and_links_are_not_opened_or_changed(monkeypatch):
    state = privilege_filesystem(monkeypatch, 0o1755)
    result = MODULE.remove_privilege_bits()
    assert result["changed_files"] == []
    assert state["chmods"] == state["opened"] == state["closed"] == []


def test_privilege_removal_requires_stage_guard_before_traversal(monkeypatch):
    monkeypatch.delenv("A4A_PREPARE_CONTAINER_RUNTIME", raising=False)
    monkeypatch.setattr(MODULE.os, "fwalk", lambda *a, **kw: pytest.fail("no traversal expected"),
                        raising=False)
    with pytest.raises(RuntimeError, match="explicit root Linux"):
        MODULE.remove_privilege_bits()


def test_replaced_inode_is_rejected_without_chmod(monkeypatch):
    state = privilege_filesystem(monkeypatch)
    state["inode"] = 99
    with pytest.raises(RuntimeError, match="changed file identity"):
        MODULE.remove_privilege_bits()
    assert state["chmods"] == [] and state["closed"] == [100]


def test_privileged_directory_preserves_other_permissions_owner_and_children(monkeypatch):
    state = privilege_filesystem(monkeypatch, 0o755)
    state["directory_mode"] |= 0o2000
    result = MODULE.remove_privilege_bits()
    assert state["chmods"] == [0o755] and not state["opened"]
    assert result["regular_files_checked"] == 2
    assert result["changed_directories"] == [
        {"path": "/", "before_mode": "0o2755", "after_mode": "0o755", "uid": 0, "gid": 42}
    ]


def test_directory_mode_change_must_be_verified(monkeypatch):
    state = privilege_filesystem(monkeypatch)
    state["directory_mode"] |= 0o2000
    monkeypatch.setattr(MODULE.os, "fchmod", lambda *args: None)
    with pytest.raises(RuntimeError, match="directory changed during privilege removal"):
        MODULE.remove_privilege_bits()
    assert state["opened"] == state["chmods"] == []


def test_traversal_error_is_not_silently_ignored(monkeypatch):
    privilege_filesystem(monkeypatch)

    def inaccessible(*args, **kwargs):
        kwargs["onerror"](PermissionError("unreadable image directory"))
        yield

    monkeypatch.setattr(MODULE.os, "fwalk", inaccessible)
    with pytest.raises(PermissionError, match="unreadable image directory"):
        MODULE.remove_privilege_bits()


def test_chmod_failure_aborts_preparation_and_closes_descriptor(monkeypatch):
    state = privilege_filesystem(monkeypatch)

    def denied(*args):
        raise PermissionError("mode change denied")

    monkeypatch.setattr(MODULE.os, "fchmod", denied)
    with pytest.raises(PermissionError, match="mode change denied"):
        MODULE.remove_privilege_bits()
    assert state["closed"] == [100]


def test_changed_file_bytes_abort_preparation(monkeypatch):
    state = privilege_filesystem(monkeypatch)
    chmod = MODULE.os.fchmod

    def changed(descriptor, mode):
        chmod(descriptor, mode)
        state["content"] = b"X" + state["content"][1:]

    monkeypatch.setattr(MODULE.os, "fchmod", changed)
    with pytest.raises(RuntimeError, match="file changed during privilege removal"):
        MODULE.remove_privilege_bits()
    assert state["closed"] == [100]


def test_remaining_privilege_bit_aborts_preparation(monkeypatch):
    state = privilege_filesystem(monkeypatch)
    monkeypatch.setattr(MODULE.os, "fchmod", lambda *args: None)
    with pytest.raises(RuntimeError, match="file changed during privilege removal"):
        MODULE.remove_privilege_bits()
    assert state["closed"] == [100]


def test_fresh_verification_detects_new_privileged_file(monkeypatch):
    state = privilege_filesystem(monkeypatch)
    walk = MODULE.os.fwalk

    def race(*args, **kwargs):
        if state["walks"]:
            state["mode"] |= 0o4000
        yield from walk(*args, **kwargs)

    monkeypatch.setattr(MODULE.os, "fwalk", race)
    with pytest.raises(RuntimeError, match="privilege bits remain"):
        MODULE.remove_privilege_bits()
    assert state["walks"] == 2


def test_link_replacement_is_not_followed_on_open(monkeypatch):
    state = privilege_filesystem(monkeypatch)

    def linked(name, flags, *, dir_fd):
        assert flags & MODULE.os.O_NOFOLLOW
        raise OSError("symbolic link replaced file")

    monkeypatch.setattr(MODULE.os, "open", linked)
    with pytest.raises(OSError, match="symbolic link"):
        MODULE.remove_privilege_bits()
    assert state["chmods"] == state["closed"] == []


def test_privileged_special_file_fails_closed(monkeypatch):
    privilege_filesystem(monkeypatch, 0o755)
    lstat = MODULE.os.stat

    def privileged(name, **kwargs):
        info = lstat(name, **kwargs)
        if name == "device":
            info.st_mode |= 0o4000
        return info

    monkeypatch.setattr(MODULE.os, "stat", privileged)
    with pytest.raises(RuntimeError, match="privileged nonregular"):
        MODULE.remove_privilege_bits()


def test_changed_owner_fails_closed(monkeypatch):
    state = privilege_filesystem(monkeypatch)
    fstat = MODULE.os.fstat

    def owner_changed(descriptor):
        info = fstat(descriptor)
        if descriptor == 100 and state["chmods"]:
            info.st_uid = 10001
        return info

    monkeypatch.setattr(MODULE.os, "fstat", owner_changed)
    with pytest.raises(RuntimeError, match="file changed during privilege removal"):
        MODULE.remove_privilege_bits()
    assert state["closed"] == [100]


def test_successful_preparation_includes_verified_privilege_record(monkeypatch):
    calls = []
    proof = {"changed_files": [], "regular_files_checked": 9,
             "remaining_privileged_files": [], "excluded_mount_trees": ["/dev", "/proc", "/sys"]}
    monkeypatch.setattr(MODULE, "require_container_stage", lambda: None)
    monkeypatch.setattr(MODULE.metadata, "distributions", lambda: [distribution("pip")])
    monkeypatch.setattr(MODULE, "runtime_snapshot", lambda distributions: {})
    monkeypatch.setattr(MODULE, "remove_ensurepip", lambda: calls.append("bootstrap"))

    def run(command, **kwargs):
        calls.append("probe" if "-c" in command else "pip")
        return SimpleNamespace(stdout='{"distributions": {}, "modules": {"pip": false}, "scripts": []}')

    def remove():
        calls.append("privileges")
        return proof

    monkeypatch.setattr(MODULE.subprocess, "run", run)
    monkeypatch.setattr(MODULE, "remove_privilege_bits", remove)
    assert MODULE.prepare()["privilege_removal"] == proof
    assert calls == ["pip", "pip", "bootstrap", "probe", "privileges"]
