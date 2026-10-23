#!/usr/bin/env python3
"""Remove installers and filesystem privilege bits in an isolated image stage.

The final Docker stage copies this prepared filesystem, rather than inheriting
Python's installer-bearing layers. Never run this on a host or a user environment.
"""

from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import sysconfig


INSTALLERS = frozenset({"pip", "setuptools", "wheel"})
PREFIX = Path("/usr/local")
STDLIB = PREFIX / "lib/python3.11"
PRIVILEGE_BITS = stat.S_ISUID | stat.S_ISGID
EXCLUDED_MOUNT_TREES = ("/dev", "/proc", "/sys")
PROBE = r'''
import importlib.metadata as metadata
import importlib.util
import json
from pathlib import Path
import sys

def canonical(name):
    import re
    return re.sub(r"[-_.]+", "-", name).lower()

distributions = {}
for distribution in metadata.distributions():
    name = canonical(distribution.metadata["Name"])
    if name in distributions:
        raise RuntimeError("duplicate installed distribution: " + name)
    distributions[name] = {"version": distribution.version,
                           "requires": sorted(distribution.requires or [])}
modules = {name: importlib.util.find_spec(name) is not None for name in
           ("pip", "setuptools", "wheel", "pkg_resources", "_distutils_hack", "ensurepip")}
scripts = sorted(path.name for pattern in ("pip*", "easy_install*", "wheel")
                 for path in (Path(sys.prefix) / "bin").glob(pattern))
print(json.dumps({"distributions": distributions, "modules": modules, "scripts": scripts}))
'''


def require_container_stage() -> None:
    """Fail before mutation unless explicitly invoked in the expected build stage."""
    if (
        sys.platform != "linux"
        or sys.version_info[:2] != (3, 11)
        or Path(sys.prefix) != PREFIX
        or Path(sysconfig.get_path("stdlib")) != STDLIB
        or getattr(os, "geteuid", lambda: -1)() != 0
        or os.environ.get("A4A_PREPARE_CONTAINER_RUNTIME") != "1"
    ):
        raise RuntimeError("requires the explicit root Linux/Python 3.11 container preparation stage")


def runtime_snapshot(distributions) -> dict:
    """Check active metadata edges, including extras requested by another dependency."""
    # Use the already hash-checked installer only before removing it. No new
    # dependency is added to the final runtime just to perform this build check.
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.utils import canonicalize_name

    installed = {}
    for distribution in distributions:
        name = canonicalize_name(distribution.metadata["Name"])
        if name in installed:
            raise RuntimeError(f"duplicate installed distribution: {name}")
        installed[name] = distribution
    runtime = {name: distribution for name, distribution in installed.items()
               if name not in INSTALLERS}
    extras = {name: set() for name in runtime}
    changed = True
    while changed:
        changed = False
        for name, distribution in runtime.items():
            for raw in distribution.requires or []:
                requirement = Requirement(raw)
                if requirement.marker is not None and not any(
                    requirement.marker.evaluate({"extra": extra})
                    for extra in {"", *extras[name]}
                ):
                    continue
                dependency = canonicalize_name(requirement.name)
                if dependency in INSTALLERS:
                    raise RuntimeError(f"runtime installer dependency: {name}: {raw}")
                if dependency not in runtime:
                    raise RuntimeError(f"missing runtime dependency: {name}: {raw}")
                version = runtime[dependency].version
                if version not in requirement.specifier:
                    raise RuntimeError(f"incompatible runtime dependency: {name}: {raw}: {version}")
                added = requirement.extras - extras[dependency]
                if added:
                    extras[dependency].update(added)
                    changed = True
    return {name: {"version": distribution.version,
                   "requires": sorted(distribution.requires or [])}
            for name, distribution in sorted(runtime.items())}


def remove_ensurepip() -> None:
    path = STDLIB / "ensurepip"
    if path.is_symlink() or path.resolve() != path or not path.is_dir():
        raise RuntimeError("unexpected ensurepip directory in the preparation stage")
    # This fixed, validated path is in the disposable image stage, never on the host.
    shutil.rmtree(path)


def regular_image_files(changed_directories: list | None = None):
    """Walk persistent image paths using directory descriptors, never symlinks."""
    if changed_directories is not None:
        require_container_stage()

    def fail(error):
        raise error

    for directory, directories, files, descriptor in os.fwalk(
        "/", topdown=True, onerror=fail, follow_symlinks=False
    ):
        if directory == "/":
            # Build mounts are not copied into the final scratch image. Do not
            # enter the build host's device, process or kernel pseudo-filesystems.
            directories[:] = [name for name in directories
                              if "/" + name not in EXCLUDED_MOUNT_TREES]
        before = os.fstat(descriptor)
        if before.st_mode & PRIVILEGE_BITS:
            if changed_directories is None:
                raise RuntimeError(f"privilege bits remain on directory: {directory}")
            mode = stat.S_IMODE(before.st_mode) & ~PRIVILEGE_BITS
            os.fchmod(descriptor, mode)
            after = os.fstat(descriptor)
            if (stat.S_IMODE(after.st_mode) != mode
                or (after.st_dev, after.st_ino, after.st_uid, after.st_gid,
                    after.st_size, after.st_mtime_ns)
                != (before.st_dev, before.st_ino, before.st_uid, before.st_gid,
                    before.st_size, before.st_mtime_ns)):
                raise RuntimeError(f"directory changed during privilege removal: {directory}")
            changed_directories.append({"path": directory, "before_mode": oct(stat.S_IMODE(before.st_mode)),
                                        "after_mode": oct(mode), "uid": after.st_uid, "gid": after.st_gid})
        for name in files:
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            path = directory.rstrip("/") + "/" + name
            if stat.S_ISREG(info.st_mode):
                yield path, name, descriptor, info
            elif not stat.S_ISLNK(info.st_mode) and info.st_mode & PRIVILEGE_BITS:
                raise RuntimeError(f"unexpected privileged nonregular entry: {path}")


def descriptor_sha256(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def remove_privilege_bits() -> dict:
    """Clear only SUID/SGID on files and directories; fail on verification errors."""
    require_container_stage()
    changed = []
    changed_directories = []
    for path, name, directory_descriptor, observed in regular_image_files(changed_directories):
        if not observed.st_mode & PRIVILEGE_BITS:
            continue
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory_descriptor)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode)
                or (before.st_dev, before.st_ino, before.st_mode)
                != (observed.st_dev, observed.st_ino, observed.st_mode)):
                raise RuntimeError(f"changed file identity before privilege removal: {path}")
            before_hash = descriptor_sha256(descriptor)
            mode = stat.S_IMODE(before.st_mode) & ~PRIVILEGE_BITS
            os.fchmod(descriptor, mode)
            after = os.fstat(descriptor)
            if (stat.S_IMODE(after.st_mode) != mode
                or (after.st_dev, after.st_ino, after.st_uid, after.st_gid,
                    after.st_size, after.st_mtime_ns)
                != (before.st_dev, before.st_ino, before.st_uid, before.st_gid,
                    before.st_size, before.st_mtime_ns)
                or descriptor_sha256(descriptor) != before_hash):
                raise RuntimeError(f"file changed during privilege removal: {path}")
            changed.append({"path": path, "before_mode": oct(stat.S_IMODE(before.st_mode)),
                            "after_mode": oct(mode), "uid": after.st_uid, "gid": after.st_gid,
                            "size": after.st_size, "sha256": before_hash})
        finally:
            os.close(descriptor)
    checked = 0
    remaining = []
    for path, _, _, info in regular_image_files():
        checked += 1
        if info.st_mode & PRIVILEGE_BITS:
            remaining.append(path)
    if remaining:
        raise RuntimeError(f"privilege bits remain after fresh traversal: {remaining}")
    return {"changed_files": sorted(changed, key=lambda item: item["path"]),
            "changed_directories": sorted(changed_directories, key=lambda item: item["path"]),
            "regular_files_checked": checked, "remaining_privileged_files": remaining,
            "excluded_mount_trees": list(EXCLUDED_MOUNT_TREES)}


def prepare() -> dict:
    require_container_stage()
    distributions = list(metadata.distributions())
    expected = runtime_snapshot(distributions)
    tools = sorted({distribution.metadata["Name"].lower() for distribution in distributions}
                   & INSTALLERS)
    if "pip" not in tools:
        raise RuntimeError("hash-checked installer is absent before preparation")
    subprocess.run([sys.executable, "-I", "-B", "-m", "pip", "check"], check=True)
    subprocess.run([sys.executable, "-I", "-B", "-m", "pip", "uninstall", "--yes", *tools],
                   check=True)
    remove_ensurepip()
    result = subprocess.run([sys.executable, "-I", "-B", "-c", PROBE],
                            check=True, capture_output=True, text=True)
    actual = json.loads(result.stdout)
    if actual["distributions"] != expected:
        raise RuntimeError("runtime metadata changed while removing installers")
    if any(actual["modules"].values()) or actual["scripts"]:
        raise RuntimeError(f"installer/bootstrap payload remains: {actual}")
    privilege_removal = remove_privilege_bits()
    return {"schema": "a4a-python-runtime-preparation-v1", "python": sys.version,
            "removed_installers": tools, "removed_bootstrap": "ensurepip",
            "runtime_distributions": actual["distributions"],
            "fresh_interpreter_modules": actual["modules"], "installer_scripts": actual["scripts"],
            "privilege_removal": privilege_removal}


def main() -> int:
    try:
        record = prepare()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Runtime preparation failed: {error}", file=sys.stderr)
        return 1
    print("A4A_RUNTIME_PREPARATION=" + json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
