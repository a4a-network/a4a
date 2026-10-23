#!/usr/bin/env python3
"""Select source-present Debian payload after authenticated image installation.

Run only in the isolated runtime preparation build stage. This copies selected
files into a new rootfs; it never purges packages or deletes the source tree.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import struct
import subprocess
import sys


SOURCE = Path("/runtime")
PREPARED = Path("/prepared")
KIT = Path("/verified/runtime")
ROOT_PACKAGES = ("ca-certificates", "dash", "libc-bin", "libc6", "libgcc-s1", "tzdata")
MAX_FILE = 32 * 1024 * 1024
MAX_PAYLOAD = 256 * 1024 * 1024


class RuntimePreparationError(RuntimeError):
    pass


def image_path(value: str) -> str:
    if not value or "\x00" in value or "\n" in value:
        raise RuntimePreparationError("invalid image path")
    return posixpath.normpath("/" + value.lstrip("/"))


def scan_tree(root: Path) -> dict:
    """Inspect physical paths without following image symlinks into the host."""
    if root.is_symlink() or not root.is_dir():
        raise RuntimePreparationError("source root is not a plain directory")
    tree = {}
    pending = [root]
    while pending:
        path = pending.pop()
        info = path.lstat()
        relative = "/" + path.relative_to(root).as_posix()
        relative = image_path(relative)
        kind = ("directory" if stat.S_ISDIR(info.st_mode) else
                "symlink" if stat.S_ISLNK(info.st_mode) else
                "file" if stat.S_ISREG(info.st_mode) else "special")
        tree[relative] = {"kind": kind, "size": info.st_size, "mode": stat.S_IMODE(info.st_mode),
                          "uid": info.st_uid, "gid": info.st_gid}
        if kind == "symlink":
            tree[relative]["target"] = os.readlink(path)
        elif kind == "directory":
            pending.extend(sorted(path.iterdir(), reverse=True))
        if len(tree) > 100000:
            raise RuntimePreparationError("source tree exceeds the bound")
    return tree


def resolve(tree: dict, value: str) -> str:
    path = image_path(value)
    for _ in range(40):
        parts = path.strip("/").split("/")
        for index in range(len(parts)):
            prefix = "/" + "/".join(parts[:index + 1])
            node = tree.get(prefix, {})
            if node.get("kind") == "symlink":
                target = node["target"]
                if not target.startswith("/"):
                    target = posixpath.dirname(prefix) + "/" + target
                path = image_path(target + "/" + "/".join(parts[index + 1:]))
                break
        else:
            return path
    raise RuntimePreparationError("image symlink cycle")


def read_file(root: Path, tree: dict, path: str, *, limit: int = MAX_FILE) -> bytes:
    path = resolve(tree, path)
    node = tree.get(path, {})
    if node.get("kind") != "file" or node["size"] > limit:
        raise RuntimePreparationError("missing, special or oversized image file: " + path)
    physical = root / path.lstrip("/")
    # Canonical image paths have no physical symlink ancestor; never resolve an
    # absolute image link with Path.resolve(), which would enter the build host.
    for parent in physical.parents:
        if parent == root:
            break
        if parent.is_symlink():
            raise RuntimePreparationError("physical symlink ancestor")
    descriptor = os.open(physical, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise RuntimePreparationError("image file changed type")
        data = stream.read(limit + 1)
    if len(data) != node["size"] or len(data) > limit:
        raise RuntimePreparationError("image file changed size")
    return data


def control_paragraphs(data: bytes) -> list[tuple[dict, str]]:
    result = []
    for paragraph in data.decode("utf-8").strip().split("\n\n"):
        fields, previous = {}, None
        for line in paragraph.splitlines():
            if line[:1].isspace():
                if previous is None:
                    raise RuntimePreparationError("orphan control continuation")
                fields[previous] += " " + line.strip()
            else:
                if ":" not in line:
                    raise RuntimePreparationError("invalid control field")
                key, value = line.split(":", 1)
                if key in fields:
                    raise RuntimePreparationError("duplicate control field")
                fields[key], previous = value.strip(), key
        result.append((fields, paragraph))
    return result


def installed_packages(paragraphs: list) -> dict:
    packages = {}
    for fields, _ in paragraphs:
        if fields.get("Status") != "install ok installed":
            continue
        name = fields.get("Package", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", name) or name in packages:
            raise RuntimePreparationError("invalid or duplicate installed package")
        if fields.get("Architecture") not in ("amd64", "all") or not fields.get("Version"):
            raise RuntimePreparationError("unsupported installed package coordinate")
        packages[name] = fields
    return packages


def satisfies(installed: str, operator: str | None, wanted: str | None) -> bool:
    if operator is None:
        return True
    if installed is None:
        return False
    operation = {"=": "eq", ">=": "ge", "<=": "le", ">>": "gt", "<<": "lt"}[operator]
    # Compare strings using the trusted collector's dpkg, not a Trixie binary
    # copied into a Bookworm verifier with a different libc ABI.
    result = subprocess.run(["/usr/bin/dpkg", "--compare-versions", installed, operation, wanted],
                            capture_output=True, timeout=10, check=False)
    if result.returncode not in (0, 1):
        raise RuntimePreparationError("Debian version comparison failed")
    return result.returncode == 0


def package_closure(packages: dict, roots=ROOT_PACKAGES, *, compare=satisfies) -> tuple[set, list]:
    providers = {}
    for name, fields in sorted(packages.items()):
        for provided in fields.get("Provides", "").split(","):
            if not provided.strip():
                continue
            match = re.fullmatch(r"\s*([a-z0-9][a-z0-9+.-]*)(?:\s*\(=\s*([^()\s]+)\))?\s*", provided)
            if not match:
                raise RuntimePreparationError("unsupported virtual package expression")
            providers.setdefault(match[1], []).append((name, match[2]))
    selected, choices = set(), []
    pending = deque(sorted(roots))
    while pending:
        package = pending.popleft()
        if package in selected:
            continue
        if package not in packages:
            raise RuntimePreparationError("missing required package: " + package)
        selected.add(package)
        for relationship in ("Depends", "Pre-Depends"):
            for expression in packages[package].get(relationship, "").split(","):
                if not expression.strip():
                    continue
                chosen = None
                for alternative in expression.split("|"):
                    match = re.fullmatch(r"\s*([a-z0-9][a-z0-9+.-]*)(?::(?:any|native|amd64))?"
                                         r"(?:\s*\((=|>=|<=|>>|<<)\s*([^()\s]+)\))?\s*", alternative)
                    if not match:
                        raise RuntimePreparationError("unsupported dependency expression")
                    candidates = []
                    if match[1] in packages:
                        candidates.append((match[1], packages[match[1]]["Version"]))
                    candidates.extend(providers.get(match[1], []))
                    for candidate, version in candidates:
                        if compare(version, match[2], match[3]):
                            chosen = candidate
                            break
                    if chosen:
                        break
                if chosen is None:
                    raise RuntimePreparationError("unsatisfied dependency: " + expression)
                choices.append({"package": package, "relationship": relationship,
                                "expression": expression.strip(), "selected": chosen})
                pending.append(chosen)
    return selected, choices


def info_belongs(filename: str, package: str) -> bool:
    stem = filename.rsplit(".", 1)[0].split(":", 1)[0]
    return stem == package


def select_paths(root: Path, tree: dict, packages: set) -> tuple[set, list]:
    selected, missing, listed_packages = set(), [], set()
    for path in sorted(tree):
        if path.startswith("/var/lib/dpkg/info/"):
            matches = [name for name in sorted(packages) if info_belongs(posixpath.basename(path), name)]
            if matches:
                selected.add(path)
                if path.endswith(".list"):
                    if len(matches) != 1:
                        raise RuntimePreparationError("ambiguous package file list")
                    listed_packages.add(matches[0])
                    for listed in read_file(root, tree, path).decode("utf-8").splitlines():
                        raw, canonical = image_path(listed), resolve(tree, listed)
                        if raw in tree:
                            selected.add(raw)
                        if canonical in tree:
                            selected.add(canonical)
                        else:
                            missing.append({"package": matches[0], "path": listed})
    if listed_packages != packages:
        raise RuntimePreparationError("missing selected package file list")
    for path in tree:
        if (path.startswith("/usr/share/common-licenses/")
                or (path.startswith("/usr/share/doc/") and posixpath.basename(path) == "copyright")
                or path.startswith("/etc/ssl/certs/") or path.startswith("/usr/share/ca-certificates/")
                or path.startswith("/usr/src/app/") or path.startswith("/etc/ld.so.conf.d/")):
            selected.add(path)
    for path in ("/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/gai.conf", "/etc/host.conf",
                 "/etc/localtime", "/etc/timezone", "/etc/ld.so.conf", "/etc/os-release",
                 "/usr/lib/os-release", "/etc/debian_version", "/tmp", "/bin", "/sbin", "/lib", "/lib64"):
        if path in tree:
            selected.add(path)
    selected.add("/var/lib/dpkg/status")
    pending = deque(sorted(selected))
    while pending:
        path = pending.popleft()
        additions = []
        if tree.get(path, {}).get("kind") == "symlink":
            target = resolve(tree, path)
            if target not in tree:
                raise RuntimePreparationError("dangling selected image symlink: " + path)
            additions.append(target)
        parent = posixpath.dirname(path)
        while parent and parent != "/":
            if parent in tree:
                additions.append(parent)
            parent = posixpath.dirname(parent)
        for addition in additions:
            if addition not in selected:
                selected.add(addition)
                pending.append(addition)
    return selected, missing


def elf_dependencies(data: bytes) -> tuple[list, str | None, list]:
    if data[:4] != b"\x7fELF":
        return [], None, []
    if len(data) < 64 or data[4:6] != b"\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 62:
        raise RuntimePreparationError("unsupported runtime ELF architecture")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size != 56 or offset + size * count > len(data):
        raise RuntimePreparationError("invalid runtime ELF program headers")
    headers = [struct.unpack_from("<IIQQQQQQ", data, offset + index * size) for index in range(count)]
    if any(h[2] + h[5] > len(data) for h in headers):
        raise RuntimePreparationError("runtime ELF segment outside file")
    loads = [header for header in headers if header[0] == 1]
    interpreter = next((data[h[2]:h[2] + h[5]].split(b"\0")[0].decode("utf-8")
                        for h in headers if h[0] == 3), None)
    entries = []
    for header in headers:
        if header[0] == 2:
            for position in range(header[2], header[2] + header[5], 16):
                tag, value = struct.unpack_from("<qQ", data, position)
                if tag == 0:
                    break
                entries.append((tag, value))
    address = next((value for tag, value in entries if tag == 5), None)
    def string(value):
        if address is None:
            raise RuntimePreparationError("missing ELF string table")
        location = address + value
        header = next((h for h in loads if h[3] <= location < h[3] + h[5]), None)
        if header is None:
            raise RuntimePreparationError("ELF string outside load segment")
        position = header[2] + location - header[3]
        return data[position:data.index(b"\0", position)].decode("utf-8")
    return ([string(value) for tag, value in entries if tag == 1], interpreter,
            [string(value) for tag, value in entries if tag in (15, 29)])


def validate_elf_closure(tree: dict, payload: dict) -> list:
    edges = []
    for path, data in sorted(payload.items()):
        needed, interpreter, search = elf_dependencies(data)
        for name in needed + ([interpreter] if interpreter else []):
            directories = [directory.replace("${ORIGIN}", posixpath.dirname(path)).replace(
                "$ORIGIN", posixpath.dirname(path)) for value in search for directory in value.split(":")]
            directories += ["/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/usr/local/lib", "/lib64", "/lib", "/usr/lib"]
            candidates = [name] if name.startswith("/") else [directory + "/" + name for directory in directories]
            target = next((resolve(tree, candidate) for candidate in candidates
                           if payload.get(resolve(tree, candidate), b"")[:4] == b"\x7fELF"), None)
            if target is None:
                raise RuntimePreparationError("missing selected ELF dependency: " + path + ": " + name)
            edges.append({"from": path, "needed": name, "resolved": target})
    if payload.get("/usr/src/app/nostr-rs-relay", b"")[:4] != b"\x7fELF":
        raise RuntimePreparationError("relay ELF absent")
    return edges


def require_stage(nonce: str) -> dict:
    if (sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0
            or os.environ.get("A4A_PREPARE_RELAY_RUNTIME") != "1"
            or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or SOURCE.is_symlink() or PREPARED.exists() or PREPARED.is_symlink()):
        raise RuntimePreparationError("requires a new isolated root Linux runtime preparation stage")
    tree = scan_tree(SOURCE)
    trusted = (KIT / "verification.json").read_bytes()
    if read_file(SOURCE, tree, "/usr/local/share/a4a-debian-install/verification.json") != trusted:
        raise RuntimePreparationError("source installation receipt differs from verified kit")
    proof = json.loads(trusted)
    if proof.get("build_nonce") != nonce:
        raise RuntimePreparationError("source installation belongs to a different build nonce")
    deadline = datetime.fromisoformat(proof["installation_deadline_utc"].replace("Z", "+00:00"))
    if deadline.tzinfo is None or datetime.now(timezone.utc) >= deadline:
        raise RuntimePreparationError("source installation deadline expired")
    if read_file(SOURCE, tree, "/usr/local/share/a4a-debian-install/result.txt").decode().strip() != "exact-inventory-and-health-checked":
        raise RuntimePreparationError("source installation did not complete")
    return proof


def prepare(nonce: str) -> dict:
    proof = require_stage(nonce)
    tree = scan_tree(SOURCE)
    status = read_file(SOURCE, tree, "/var/lib/dpkg/status")
    paragraphs = control_paragraphs(status)
    packages = installed_packages(paragraphs)
    actual = "".join(f"{name}\t{fields['Version']}\t{fields['Architecture']}\n"
                     for name, fields in sorted(packages.items())).encode()
    trusted_inventory = (KIT / "after.expected.tsv").read_bytes()
    if actual != trusted_inventory or read_file(SOURCE, tree, "/usr/local/share/a4a-debian-install/after.tsv") != actual:
        raise RuntimePreparationError("source status inventory differs from authenticated installation")
    chosen, choices = package_closure(packages)
    paths, missing = select_paths(SOURCE, tree, chosen)
    selected_tree = {path: tree[path] for path in paths}
    payload, total = {}, 0
    for path in sorted(paths):
        node = tree[path]
        if node["kind"] == "special" or node["mode"] & 0o6000:
            raise RuntimePreparationError("special or privileged selected node")
        if node["kind"] == "file":
            payload[path] = read_file(SOURCE, tree, path)
            total += len(payload[path])
    if total > MAX_PAYLOAD:
        raise RuntimePreparationError("runtime payload exceeds the bound")
    payload["/var/lib/dpkg/status"] = ("\n\n".join(raw for fields, raw in paragraphs
                                                 if fields.get("Package") in chosen) + "\n\n").encode()
    edges = validate_elf_closure(selected_tree, payload)
    records = [{"path": path, **{key: value for key, value in tree[path].items() if key != "size"},
                "size": len(payload[path]) if path in payload else 0,
                "sha256": hashlib.sha256(payload[path]).hexdigest() if path in payload else None}
               for path in sorted(paths)]
    manifest = {"schema": "a4a-selected-relay-runtime-v1", "root_packages": list(ROOT_PACKAGES),
                "installed_packages": [packages[name] for name in sorted(chosen)], "dependency_choices": choices,
                "source_inventory_sha256": hashlib.sha256(actual).hexdigest(),
                "source_lock_policy_sha256": proof["lock_policy_sha256"], "source_missing_package_paths": missing,
                "elf_edges": edges, "files": records,
                "scope": "Source-present selected package payload and explicit dependencies; not a general-purpose Debian installation."}
    # Validate everything before making the new output. Files/directories precede
    # symlinks so absolute image links cannot redirect a collector write.
    rootfs = PREPARED / "rootfs"
    rootfs.mkdir(parents=True, exist_ok=False)
    directories = sorted((path for path in paths if tree[path]["kind"] == "directory"),
                         key=lambda path: (path.count("/"), path))
    for path in directories:
        if path != "/":
            (rootfs / path.lstrip("/")).mkdir(exist_ok=True)
    for path, data in sorted(payload.items()):
        destination = rootfs / path.lstrip("/")
        with destination.open("xb") as output:
            output.write(data)
        os.chown(destination, tree[path]["uid"], tree[path]["gid"])
        destination.chmod(tree[path]["mode"])
        os.utime(destination, (0, 0))
    for path in sorted(paths):
        if tree[path]["kind"] == "symlink":
            destination = rootfs / path.lstrip("/")
            os.symlink(tree[path]["target"], destination)
            os.lchown(destination, tree[path]["uid"], tree[path]["gid"])
            os.utime(destination, (0, 0), follow_symlinks=False)
    metadata = rootfs / "usr/local/share/a4a-runtime-selection"
    metadata.mkdir(parents=True, exist_ok=False)
    metadata.chmod(0o755)
    with (metadata / "manifest.json").open("x", encoding="utf-8", newline="\n") as output:
        json.dump(manifest, output, indent=2, sort_keys=True)
        output.write("\n")
    (metadata / "manifest.json").chmod(0o444)
    os.utime(metadata / "manifest.json", (0, 0))
    os.utime(metadata, (0, 0))
    for path in reversed(directories):
        destination = rootfs / path.lstrip("/")
        os.chown(destination, tree[path]["uid"], tree[path]["gid"])
        destination.chmod(tree[path]["mode"])
        os.utime(destination, (0, 0))
    receipt = {"build_nonce": nonce, "installation_deadline_utc": proof["installation_deadline_utc"],
               "manifest_sha256": hashlib.sha256((metadata / "manifest.json").read_bytes()).hexdigest(),
               "observed_utc": datetime.now(timezone.utc).isoformat()}
    (PREPARED / "preparation.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


def main():
    if len(sys.argv) != 2:
        raise RuntimePreparationError("one fresh build nonce is required")
    print(json.dumps(prepare(sys.argv[1]), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (RuntimePreparationError, OSError, ValueError, KeyError, struct.error) as error:
        print("Relay runtime preparation failed: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error
