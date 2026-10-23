#!/usr/bin/env python3
"""Copy a declared Python runtime from an already prepared, authenticated stage.

Keep all CPython/application/distribution files and complete source-present Debian
package payloads. Never purge the input, resolve image links through the host, or
silently omit a new native dependency. This is not a general-purpose Debian image.
"""
from __future__ import annotations

from collections import deque
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import struct
import sys

_spec = importlib.util.spec_from_file_location(
    "a4a_runtime_selection", Path(__file__).with_name("prepare-relay-runtime.py"))
runtime = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runtime)
Error = runtime.RuntimePreparationError
SOURCE = Path("/runtime")
PREPARED = Path("/prepared")
PREFIXES = ("/usr/local", "/app", "/keys", "/data", "/home",
            "/usr/share/licenses", "/etc/terminfo", "/usr/share/terminfo", "/lib/terminfo")
ROOT_PACKAGES = ("ca-certificates", "dash", "libc-bin", "libc6", "ncurses-base", "tzdata")
MANIFEST_PATH = "/usr/local/share/a4a-python-runtime-selection/manifest.json"
BUILD_OBJECT = "/usr/local/lib/python3.11/config-3.11-x86_64-linux-gnu/python.o"
OPTIONAL_TK = "/usr/local/lib/python3.11/lib-dynload/_tkinter.cpython-311-x86_64-linux-gnu.so"
OPTIONAL_EDGES = {(OPTIONAL_TK, "libtk8.6.so"), (OPTIONAL_TK, "libtcl8.6.so")}


def inside(path, prefix):
    return path == prefix or path.startswith(prefix + "/")


def dependencies(path, data, node):
    if path == BUILD_OBJECT:
        if (len(data) < 64 or data[:6] != b"\x7fELF\x02\x01"
                or struct.unpack_from("<HH", data, 16) != (1, 62)
                or struct.unpack_from("<HH", data, 54) != (0, 0)
                or node["mode"] & 0o111):
            raise Error("invalid retained nonexecutable CPython build object")
        offset = struct.unpack_from("<Q", data, 40)[0]
        size, count = struct.unpack_from("<HH", data, 58)
        if size != 64 or not count or offset + size * count > len(data):
            raise Error("invalid CPython build object section headers")
        return [], None, []
    return runtime.elf_dependencies(data)


def target(tree, payload, path, name, search):
    directories = [part.replace("${ORIGIN}", posixpath.dirname(path)).replace(
        "$ORIGIN", posixpath.dirname(path)) for value in search for part in value.split(":")]
    directories += ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/usr/local/lib",
                    "/lib64", "/lib", "/usr/lib"]
    candidates = [name] if name.startswith("/") else [directory + "/" + name for directory in directories]
    return next((runtime.resolve(tree, candidate) for candidate in candidates
                 if payload.get(runtime.resolve(tree, candidate), b"")[:4] == b"\x7fELF"), None)


def native_closure(tree, payload, roots, allowed_missing=()):
    pending, visited, edges, missing = deque(sorted(roots)), set(), [], []
    while pending:
        path = pending.popleft()
        if path in visited:
            continue
        visited.add(path)
        needed, interpreter, search = dependencies(path, payload[path], tree[path])
        for name in needed + ([interpreter] if interpreter else []):
            resolved = target(tree, payload, path, name, search)
            if resolved is None:
                if (path, name) not in allowed_missing:
                    raise Error("missing selected ELF dependency: " + path + ": " + name)
                missing.append({"from": path, "needed": name})
            else:
                edges.append({"from": path, "needed": name, "resolved": resolved})
                pending.append(resolved)
    return visited, edges, missing


def close_paths(tree, selected):
    pending = deque(sorted(selected))
    while pending:
        path = pending.popleft()
        additions = []
        if tree[path]["kind"] == "symlink":
            resolved = runtime.resolve(tree, path)
            if resolved not in tree:
                raise Error("dangling selected image symlink: " + path)
            additions.append(resolved)
        parent = posixpath.dirname(path)
        while parent and parent != "/":
            if parent in tree:
                additions.append(parent)
            parent = posixpath.dirname(parent)
        for addition in additions:
            if addition not in selected:
                selected.add(addition)
                pending.append(addition)


def select(root, tree, *, compare=runtime.satisfies):
    status = runtime.read_file(root, tree, "/var/lib/dpkg/status")
    paragraphs = runtime.control_paragraphs(status)
    packages = runtime.installed_packages(paragraphs)
    owners, native = {}, {}
    for path, node in sorted(tree.items()):
        if node["kind"] != "file":
            continue
        if path.startswith("/var/lib/dpkg/info/") and path.endswith(".list"):
            names = [name for name in packages if runtime.info_belongs(posixpath.basename(path), name)]
            if len(names) != 1:
                raise Error("ambiguous installed package file list")
            for listed in runtime.read_file(root, tree, path).decode("utf-8").splitlines():
                owners.setdefault(runtime.resolve(tree, listed), set()).add(names[0])
        # Use the namespace-safe bounded reader even for the initial magic.
        data = runtime.read_file(root, tree, path)
        if data[:4] == b"\x7fELF":
            native[path] = data
    roots = {path for path in native if inside(path, "/usr/local")}
    for path in ("/bin/sh", "/usr/sbin/ldconfig"):
        resolved = runtime.resolve(tree, path)
        if resolved not in native:
            raise Error("required Python runtime executable is absent: " + path)
        roots.add(resolved)
    if "/usr/local/bin/python3.11" not in roots:
        raise Error("CPython 3.11 ELF is absent")
    reached, _, baseline_missing = native_closure(tree, native, roots, OPTIONAL_EDGES)
    package_roots = set(ROOT_PACKAGES)
    for path in reached:
        if not inside(path, "/usr/local"):
            if not owners.get(path):
                raise Error("native dependency has no Debian package owner: " + path)
            package_roots.update(owners[path])
    chosen, choices = runtime.package_closure(packages, sorted(package_roots), compare=compare)
    selected, missing = runtime.select_paths(root, tree, chosen)
    selected.update(path for path in tree if any(inside(path, prefix) for prefix in PREFIXES))
    close_paths(tree, selected)
    if MANIFEST_PATH in tree or posixpath.dirname(MANIFEST_PATH) in tree:
        raise Error("source already contains Python selection metadata")
    payload, total = {}, 0
    for path in sorted(selected):
        node = tree[path]
        if node["kind"] == "special" or node["mode"] & 0o6000:
            raise Error("special or privileged selected node")
        if node["kind"] == "file":
            payload[path] = runtime.read_file(root, tree, path)
            total += len(payload[path])
    if total > runtime.MAX_PAYLOAD:
        raise Error("Python runtime payload exceeds the bound")
    payload["/var/lib/dpkg/status"] = ("\n\n".join(raw for fields, raw in paragraphs
        if fields.get("Package") in chosen) + "\n\n").encode()
    selected_tree = {path: tree[path] for path in selected}
    elf_roots = {path for path, data in payload.items() if data[:4] == b"\x7fELF"}
    _, edges, unresolved = native_closure(selected_tree, payload, elf_roots,
                                         {(r["from"], r["needed"]) for r in baseline_missing})
    if sorted(unresolved, key=str) != sorted(baseline_missing, key=str):
        raise Error("optional native module baseline changed")
    records = [{"path": path, **{key: value for key, value in tree[path].items() if key != "size"},
                "size": len(payload[path]) if path in payload else 0,
                "sha256": hashlib.sha256(payload[path]).hexdigest() if path in payload else None}
               for path in sorted(selected)]
    actual = "".join(f"{name}\t{fields['Version']}\t{fields['Architecture']}\n"
                     for name, fields in sorted(packages.items())).encode()
    manifest = {"schema": "a4a-selected-python-runtime-v1", "root_packages": sorted(package_roots),
                "installed_packages": [packages[name] for name in sorted(chosen)],
                "dependency_choices": choices, "source_inventory_sha256": hashlib.sha256(actual).hexdigest(),
                "source_missing_package_paths": missing, "elf_edges": edges,
                "unchanged_baseline_unresolved": unresolved, "whole_usr_local_retained": True,
                "retained_nonexecutable_build_objects": [{"path": BUILD_OBJECT, "elf_type": "ET_REL",
                    "executable": False, "sha256": hashlib.sha256(payload[BUILD_OBJECT]).hexdigest()}]
                    if BUILD_OBJECT in payload else [],
                "files": records,
                "scope": "Complete source-present selected packages, all CPython/apps/distributions and explicit dynamic data; not general-purpose Debian."}
    return manifest, selected_tree, payload


def require_stage():
    if (sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0
            or sys.version_info[:2] != (3, 11)
            or os.environ.get("A4A_PREPARE_PYTHON_FILESYSTEM") != "1"
            or SOURCE.is_symlink() or not SOURCE.is_dir()
            or PREPARED.exists() or PREPARED.is_symlink()):
        raise Error("requires a new isolated root Linux Python 3.11 preparation stage")


def prepare():
    require_stage()
    tree = runtime.scan_tree(SOURCE)
    for path in tree:
        if inside(path, "/usr/local/lib/python3.11/ensurepip") or any(
            inside(path, "/usr/local/lib/python3.11/site-packages/" + name)
            for name in ("pip", "setuptools", "wheel")):
            raise Error("input Python installer preparation is incomplete")
    manifest, selected, payload = select(SOURCE, tree)
    rootfs = PREPARED / "rootfs"
    rootfs.mkdir(parents=True, exist_ok=False)
    directories = sorted((path for path in selected if selected[path]["kind"] == "directory"),
                         key=lambda path: (path.count("/"), path))
    for path in directories:
        if path != "/":
            (rootfs / path.lstrip("/")).mkdir(exist_ok=True)
    for path, data in sorted(payload.items()):
        destination = rootfs / path.lstrip("/")
        with destination.open("xb") as stream:
            stream.write(data)
        os.chown(destination, selected[path]["uid"], selected[path]["gid"])
        destination.chmod(selected[path]["mode"])
        os.utime(destination, (0, 0))
    # Generate metadata before links: an absolute image link cannot redirect it
    # into the collector filesystem. Reject a link at any metadata ancestor.
    for parent in Path(MANIFEST_PATH).parents:
        if selected.get(parent.as_posix(), {}).get("kind") == "symlink":
            raise Error("selection metadata has a symlink ancestor")
    metadata = rootfs / MANIFEST_PATH.lstrip("/")
    metadata.parent.mkdir(parents=True, exist_ok=False)
    metadata.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    metadata.chmod(0o444)
    os.utime(metadata, (0, 0))
    os.utime(metadata.parent, (0, 0))
    for path in sorted(selected):
        if selected[path]["kind"] == "symlink":
            destination = rootfs / path.lstrip("/")
            os.symlink(selected[path]["target"], destination)
            os.lchown(destination, selected[path]["uid"], selected[path]["gid"])
            os.utime(destination, (0, 0), follow_symlinks=False)
    for path in reversed(directories):
        destination = rootfs / path.lstrip("/")
        os.chown(destination, selected[path]["uid"], selected[path]["gid"])
        destination.chmod(selected[path]["mode"])
        os.utime(destination, (0, 0))
    receipt = {"schema": "a4a-python-filesystem-preparation-v1",
               "manifest_sha256": hashlib.sha256(metadata.read_bytes()).hexdigest(),
               "package_count": len(manifest["installed_packages"]),
               "file_count": len(manifest["files"]), "release_approved": False}
    (PREPARED / "preparation.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


if __name__ == "__main__":
    try:
        if len(sys.argv) != 1:
            raise Error("no arguments are accepted")
        print(json.dumps(prepare(), sort_keys=True))
    except (Error, OSError, ValueError, KeyError, struct.error) as error:
        print("Python filesystem preparation failed: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error
