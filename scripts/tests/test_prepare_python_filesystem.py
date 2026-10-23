"""Exercise namespace, native dependency and complete-prefix selection boundaries."""
import importlib.util
from pathlib import Path
import struct

import pytest

SPEC = importlib.util.spec_from_file_location(
    "prepare_python_filesystem", Path(__file__).parents[1] / "prepare-python-filesystem.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def elf():
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, 62)
    struct.pack_into("<HH", data, 54, 56, 0)
    return bytes(data)


def object_file():
    data = bytearray(128)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", data, 16, 1, 62)
    struct.pack_into("<Q", data, 40, 64)
    struct.pack_into("<HH", data, 58, 64, 1)
    return data


@pytest.mark.parametrize("mutation", ["executable", "type", "sections", "other_path"])
def test_only_valid_nonexecutable_cpython_object_is_exempt_from_program_headers(mutation):
    data, path, mode = object_file(), MODULE.BUILD_OBJECT, 0o644
    assert MODULE.dependencies(path, data, {"mode": mode}) == ([], None, [])
    if mutation == "executable":
        mode = 0o755
    elif mutation == "type":
        struct.pack_into("<H", data, 16, 3)
    elif mutation == "sections":
        struct.pack_into("<Q", data, 40, 127)
    else:
        path = "/usr/local/lib/unexpected.o"
    with pytest.raises(MODULE.Error):
        MODULE.dependencies(path, data, {"mode": mode})


def test_no_new_missing_native_edge_is_allowed(monkeypatch):
    tree = {MODULE.OPTIONAL_TK: {"mode": 0o644}, "/usr/local/lib/new.so": {"mode": 0o644}}
    payload = {path: elf() for path in tree}
    monkeypatch.setattr(MODULE, "dependencies", lambda *args: (["libtk8.6.so"], None, []))
    _, _, missing = MODULE.native_closure(tree, payload, {MODULE.OPTIONAL_TK}, MODULE.OPTIONAL_EDGES)
    assert missing == [{"from": MODULE.OPTIONAL_TK, "needed": "libtk8.6.so"}]
    with pytest.raises(MODULE.Error, match="missing selected ELF"):
        MODULE.native_closure(tree, payload, set(tree), MODULE.OPTIONAL_EDGES)
    with pytest.raises(MODULE.Error, match="missing selected ELF"):
        MODULE.native_closure(tree, payload, {MODULE.OPTIONAL_TK})


def test_link_closure_keeps_image_alias_and_rejects_dangling_target():
    tree = {"/usr/local/link": {"kind": "symlink", "target": "/usr/share/runtime/data"},
            "/usr/share/runtime/data": {"kind": "file"}, "/usr/share/runtime": {"kind": "directory"}}
    selected = {"/usr/local/link"}
    MODULE.close_paths(tree, selected)
    assert selected == set(tree)
    tree.pop("/usr/share/runtime/data")
    with pytest.raises(MODULE.Error, match="dangling"):
        MODULE.close_paths(tree, {"/usr/local/link"})


@pytest.fixture
def source(tmp_path, monkeypatch):
    root = tmp_path / "source"
    files = {"/var/lib/dpkg/status": b"Package: leaf\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\n\n",
             "/var/lib/dpkg/info/leaf.list": b"/bin/sh\n/usr/sbin/ldconfig\n/usr/share/doc/leaf/copyright\n",
             "/bin/sh": elf(), "/usr/sbin/ldconfig": elf(), "/usr/local/bin/python3.11": elf(),
             "/usr/local/lib/python3.11/site-packages/example/data.txt": b"package data",
             "/usr/local/lib/python3.11/site-packages/example-1.dist-info/LICENSE": b"license",
             "/usr/share/doc/leaf/copyright": b"copyright", "/usr/share/unneeded/tool": b"tool"}
    for path, data in files.items():
        physical = root / path.lstrip("/")
        physical.parent.mkdir(parents=True, exist_ok=True)
        physical.write_bytes(data)
    monkeypatch.setattr(MODULE, "ROOT_PACKAGES", ("leaf",))
    return root, files


@pytest.mark.parametrize("name", ["pycryptodomex-3.23.0-native-NOTICES.txt",
                                  "pycryptodomex-LICENSE-libtom.txt", "CC0-1.0.txt"])
def test_native_source_notices_survive_runtime_selection(source, name):
    root, _ = source
    expected = (Path(__file__).parents[2] / "notary/licenses" / name).read_bytes()
    destination = root / "app/licenses" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(expected)
    _, selected, payload = MODULE.select(root, MODULE.runtime.scan_tree(root))
    path = "/app/licenses/" + name
    assert path in selected
    assert payload[path] == expected


def test_all_prefix_bytes_and_complete_selected_package_paths_are_retained(source):
    root, files = source
    tree = MODULE.runtime.scan_tree(root)
    manifest, selected, payload = MODULE.select(root, tree)
    assert {row["Package"] for row in manifest["installed_packages"]} == {"leaf"}
    assert all(payload[path] == data for path, data in files.items() if path.startswith("/usr/local/"))
    assert payload["/bin/sh"] == files["/bin/sh"]
    assert "/usr/share/unneeded/tool" not in selected
    assert manifest["whole_usr_local_retained"] is True
    assert {row["path"] for row in manifest["files"]} == set(selected)


def test_unowned_native_dependency_is_rejected(source, monkeypatch):
    root, _ = source
    missing = root / "usr/lib/unowned.so"
    missing.parent.mkdir(parents=True)
    missing.write_bytes(elf())
    original = MODULE.dependencies
    monkeypatch.setattr(MODULE, "dependencies", lambda path, data, node:
        (["/usr/lib/unowned.so"], None, []) if path == "/usr/local/bin/python3.11" else original(path, data, node))
    with pytest.raises(MODULE.Error, match="no Debian package owner"):
        MODULE.select(root, MODULE.runtime.scan_tree(root))


@pytest.mark.parametrize("condition", ["host", "existing_output", "no_guard"])
def test_stage_guard_does_not_create_or_modify_output(source, tmp_path, monkeypatch, condition):
    root, _ = source
    output = tmp_path / "prepared"
    monkeypatch.setattr(MODULE, "SOURCE", root)
    monkeypatch.setattr(MODULE, "PREPARED", output)
    monkeypatch.setattr(MODULE.sys, "platform", "linux")
    monkeypatch.setattr(MODULE.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setenv("A4A_PREPARE_PYTHON_FILESYSTEM", "1")
    if condition == "host":
        monkeypatch.setattr(MODULE.sys, "platform", "win32")
    elif condition == "existing_output":
        output.mkdir()
        (output / "untouched").write_bytes(b"keep")
    else:
        monkeypatch.delenv("A4A_PREPARE_PYTHON_FILESYSTEM")
    with pytest.raises(MODULE.Error, match="isolated"):
        MODULE.prepare()
    if condition == "existing_output":
        assert list(output.iterdir()) == [output / "untouched"]
        assert (output / "untouched").read_bytes() == b"keep"
    else:
        assert not output.exists()
