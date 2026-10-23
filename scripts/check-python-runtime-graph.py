#!/usr/bin/env python3
"""Inspect a prepared image read-only; verify its metadata on the CI host.

Snapshot mode uses only the standard library, so neither packaging nor installers
are added to the runtime. Verification uses the host's hash-checked packaging
library and the image's marker environment, including dependency-requested extras.
"""

from __future__ import annotations

import argparse
import importlib.metadata as metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import sys


INSTALLERS = frozenset({"pip", "setuptools", "wheel"})
BOOTSTRAP_MODULES = (*sorted(INSTALLERS), "pkg_resources", "_distutils_hack", "ensurepip")
CRYPTO_LICENSES = ("LICENSE", "LICENSE.APACHE", "LICENSE.BSD")
# The pinned official Python base carries this distribution independently of
# application requirements. Its exact version is also in the hashed build lock.
BASE_RUNTIME_NAMES = frozenset({"packaging"})


def snapshot():
    distributions = {}
    for distribution in metadata.distributions():
        name = re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower()
        if name in distributions:
            raise RuntimeError(f"duplicate installed distribution: {name}")
        distributions[name] = {"version": distribution.version,
                               "requires": sorted(distribution.requires or [])}
    crypto = metadata.distribution("cryptography")
    files = crypto.files or []
    licenses = {
        name: any(path.as_posix().endswith(".dist-info/licenses/" + name)
                  and Path(crypto.locate_file(path)).is_file()
                  and Path(crypto.locate_file(path)).stat().st_size > 0 for path in files)
        for name in CRYPTO_LICENSES
    }
    implementation = sys.implementation.version
    implementation_version = ".".join(str(value) for value in implementation[:3])
    if implementation.releaselevel != "final":
        implementation_version += implementation.releaselevel[0] + str(implementation.serial)
    return {
        "distributions": distributions,
        "modules": {name: importlib.util.find_spec(name) is not None for name in BOOTSTRAP_MODULES},
        "crypto_licenses": licenses,
        "environment": {
            "implementation_name": sys.implementation.name,
            "implementation_version": implementation_version,
            "os_name": os.name, "platform_machine": platform.machine(),
            "platform_release": platform.release(), "platform_system": platform.system(),
            "platform_version": platform.version(),
            "python_full_version": platform.python_version(),
            "platform_python_implementation": platform.python_implementation(),
            "python_version": ".".join(platform.python_version_tuple()[:2]),
            "sys_platform": sys.platform,
        },
    }


def verify(data, locked, base_locked=None):
    from packaging.markers import default_environment
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    environment = data["environment"]
    if set(environment) != set(default_environment()) or not all(
        isinstance(value, str) for value in environment.values()
    ):
        raise RuntimeError("incomplete image marker environment")
    runtime = data["distributions"]
    if not runtime or any(name != canonicalize_name(name) for name in runtime):
        raise RuntimeError("invalid runtime distribution names")
    if INSTALLERS & runtime.keys():
        raise RuntimeError("installer distribution retained")
    if set(data["modules"]) != set(BOOTSTRAP_MODULES) or any(data["modules"].values()):
        raise RuntimeError("installer/bootstrap module retained or probe incomplete")
    if set(data["crypto_licenses"]) != set(CRYPTO_LICENSES) or not all(
        data["crypto_licenses"].values()
    ):
        raise RuntimeError("missing cryptography license material")
    base_locked = base_locked or {}
    base_pins = {name: base_locked[name] for name in BASE_RUNTIME_NAMES & runtime.keys()
                 if name not in locked and name in base_locked}
    for name, version in {**base_pins, **locked}.items():
        if name not in runtime or runtime[name]["version"] != version:
            raise RuntimeError(f"runtime differs from lock: {name}=={version}")
    unexpected = runtime.keys() - locked.keys() - base_pins.keys() - {"a4a-sdk", "a4a-mcp", "a4a-notary"}
    if unexpected:
        raise RuntimeError(f"unlocked runtime distributions: {sorted(unexpected)}")
    extras = {name: set() for name in runtime}
    changed = True
    while changed:
        changed = False
        for name, distribution in runtime.items():
            for raw in distribution["requires"]:
                requirement = Requirement(raw)
                if requirement.marker is not None and not any(
                    requirement.marker.evaluate({**environment, "extra": extra})
                    for extra in {"", *extras[name]}
                ):
                    continue
                dependency = canonicalize_name(requirement.name)
                if dependency not in runtime:
                    raise RuntimeError(f"missing runtime dependency: {name}: {raw}")
                if runtime[dependency]["version"] not in requirement.specifier:
                    raise RuntimeError(f"incompatible runtime dependency: {name}: {raw}")
                added = requirement.extras - extras[dependency]
                if added:
                    extras[dependency].update(added)
                    changed = True
    return {"runtime_distributions": len(runtime), "locked_distributions": len(locked),
            "base_distributions": base_pins,
            "installers_absent": True, "crypto_licenses_present": True}


def read_lock(path):
    pins = re.findall(r"(?m)^([A-Za-z0-9_.-]+)==([^\s\\]+) \\\n", path.read_text("utf-8"))
    if not pins:
        raise RuntimeError("empty runtime lock")
    normalized = [(re.sub(r"[-_.]+", "-", name).lower(), version) for name, version in pins]
    if len(dict(normalized)) != len(normalized):
        raise RuntimeError("duplicate runtime lock pin")
    return dict(normalized)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--snapshot", action="store_true")
    mode.add_argument("--verify", type=Path)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--base-lock", type=Path)
    args = parser.parse_args()
    if args.snapshot:
        if args.lock or args.base_lock:
            parser.error("lock arguments belong to verification mode")
        result = snapshot()
    else:
        if not args.lock:
            parser.error("verification requires --lock")
        result = verify(json.loads(args.verify.read_text("utf-8")), read_lock(args.lock),
                        read_lock(args.base_lock) if args.base_lock else None)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
