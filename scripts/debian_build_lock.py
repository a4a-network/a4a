"""Verify a portable, offline relay Debian input bundle without installing it.

The lock is trusted build policy, not a signed authority statement. Its image
and inventory bindings must be checked against the actual installation image.
Use an immutable bundle and verifier environment, and bound CPU/memory/temp
space externally. A receipt does not keep mutable files safe for later use.
This schema supports explicitly pinned amd64 stage images and their exact suites.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

from debian_install_replay import _inventory
from debian_lock_contract import (
    LockContractError, _FIELDS, _HASH, _locked, validate_closure, verify_package_stream,
)
from debian_release_auth import validate_signed_repository


SCHEMA = "a4a-relay-debian-build-lock-v1"
# Original v1 pins remain readable for retained evidence. STAGE_PROFILES binds
# each permitted image to its suites; the committed lock selects active inputs.
BASE_IMAGES = {
    "builder": "docker.io/library/rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e",
    "runtime": "docker.io/library/debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251",
}
SUITES = {"bookworm", "bookworm-updates", "bookworm-security"}
TRIXIE_RUNTIME = (
    "docker.io/library/debian:trixie-slim@sha256:"
    "7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c"
)
STAGE_PROFILES = {
    "builder": {BASE_IMAGES["builder"]: frozenset(SUITES)},
    "runtime": {
        BASE_IMAGES["runtime"]: frozenset(SUITES),
        TRIXIE_RUNTIME: frozenset({"trixie", "trixie-updates", "trixie-security"}),
    },
}
_MAX_LOCK = 1024 * 1024
_MAX_BUNDLE = 384 * 1024 * 1024
_MAX_PACKAGE_TOTAL = 64 * 1024 * 1024
_PORTABLE_PATH = re.compile(r"[A-Za-z0-9_+./~\-]+\Z")


def _fields(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise LockContractError(f"unexpected or missing {label} fields")


def _descriptor(value, maximum, paths):
    _fields(value, {"path", "size", "sha256"}, "file descriptor")
    path = value["path"]
    if (not isinstance(path, str) or len(path) > 512 or not _PORTABLE_PATH.fullmatch(path)
            or any(part in ("", ".", "..") for part in path.split("/"))):
        raise LockContractError("nonportable bundle path")
    if path in paths:
        raise LockContractError("reused bundle path")
    paths.add(path)
    if (type(value["size"]) is not int or not 0 < value["size"] <= maximum
            or not isinstance(value["sha256"], str) or not _HASH.fullmatch(value["sha256"])):
        raise LockContractError("invalid file descriptor size or SHA256")
    return value["size"]


def validate_lock(manifest):
    """Reject unknown fields, unsupported pins and unbounded/ambiguous layouts."""
    _fields(manifest, {"schema", "architecture", "keyring_sha256", "stages"}, "lock")
    if manifest["schema"] != SCHEMA or manifest["architecture"] != "amd64":
        raise LockContractError("unsupported lock schema or architecture")
    ring = manifest["keyring_sha256"]
    if not isinstance(ring, str) or not _HASH.fullmatch(ring):
        raise LockContractError("invalid archive keyring SHA256")
    _fields(manifest["stages"], BASE_IMAGES, "stage set")
    paths, total, package_total = set(), 0, 0
    for name, stage in manifest["stages"].items():
        _fields(stage, {"base_image", "base_inventory", "repositories", "resolved_requests", "packages"}, "stage")
        if not isinstance(stage["base_image"], str) or stage["base_image"] not in STAGE_PROFILES[name]:
            raise LockContractError("unsupported or changed base image pin")
        allowed_suites = STAGE_PROFILES[name][stage["base_image"]]
        total += _descriptor(stage["base_inventory"], 8 * 1024 * 1024, paths)
        repos = stage["repositories"]
        if not isinstance(repos, list) or len(repos) != 3:
            raise LockContractError("exactly three repository bundles are required")
        suites = set()
        for repo in repos:
            _fields(repo, {"suite", "inrelease", "index"}, "repository")
            suite = repo["suite"]
            if not isinstance(suite, str) or suite not in allowed_suites or suite in suites:
                raise LockContractError("unsupported or duplicate repository suite")
            suites.add(suite)
            total += _descriptor(repo["inrelease"], 2 * 1024 * 1024, paths)
            total += _descriptor(repo["index"], 128 * 1024 * 1024, paths)
        packages = stage["packages"]
        if not isinstance(packages, list) or not 1 <= len(packages) <= 64:
            raise LockContractError("invalid or oversized stage package set")
        records = []
        for package in packages:
            _fields(package, {"suite", "record", "file"}, "package")
            if not isinstance(package["suite"], str) or package["suite"] not in suites:
                raise LockContractError("package refers to unsupported repository")
            record = package["record"]
            _fields(record, _FIELDS, "package record")
            _locked([record])
            if record["Architecture"] not in ("amd64", "all"):
                raise LockContractError("package architecture differs from lock")
            total += _descriptor(package["file"], _MAX_PACKAGE_TOTAL, paths)
            package_total += package["file"]["size"]
            if (str(package["file"]["size"]) != record["Size"]
                    or package["file"]["sha256"] != record["SHA256"]):
                raise LockContractError("package file descriptor differs from package record")
            records.append(record)
        validate_closure(records, stage["resolved_requests"])
    if total > _MAX_BUNDLE or package_total > _MAX_PACKAGE_TOTAL:
        raise LockContractError("bundle exceeds aggregate byte limit")
    return manifest


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LockContractError("duplicate JSON field")
        result[key] = value
    return result


def load_lock(payload):
    """Parse bounded UTF-8 JSON, rejecting duplicate keys and nonfinite values."""
    if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_LOCK:
        raise LockContractError("invalid or oversized lock JSON")
    def reject_constant(value):
        raise LockContractError("nonfinite JSON value")
    try:
        result = json.loads(payload.decode("utf-8"), object_pairs_hook=_object, parse_constant=reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise LockContractError("invalid lock JSON") from exc
    return validate_lock(result)


def _path(root, binding):
    path = root
    try:
        for component in binding["path"].split("/"):
            path /= component
            if path.is_symlink():
                raise LockContractError("symlink in bundle path")
        if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size != binding["size"]:
            raise LockContractError("bundle file type or size mismatch")
    except OSError as exc:
        raise LockContractError("bundle file unavailable") from exc
    return path


def _read(root, binding):
    try:
        with _path(root, binding).open("rb") as source:
            raw = source.read(binding["size"] + 1)
    except OSError as exc:
        raise LockContractError("bundle read failed") from exc
    if len(raw) != binding["size"] or hashlib.sha256(raw).hexdigest() != binding["sha256"]:
        raise LockContractError("bundle file size or SHA256 mismatch")
    return raw


def verify_bundle(manifest, directory, *, now):
    """Compose signatures, current freshness, closure and bytes for both stages.

    No downloads, commands from the lock, install, extraction or image mutation.
    Base inventory is validated as data, not measured from an actual base here.
    Only the CLI chooses actual UTC; explicit time is for deterministic tests.
    """
    validate_lock(manifest)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise LockContractError("now requires timezone")
    try:
        root = Path(directory).resolve(strict=True)
    except OSError as exc:
        raise LockContractError("bundle root unavailable") from exc
    if not root.is_dir():
        raise LockContractError("bundle root is not a directory")
    results = {}
    for name, stage in manifest["stages"].items():
        try:
            inventory = _inventory(_read(root, stage["base_inventory"]).decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise LockContractError("invalid UTF-8 inventory") from exc
        if any(architecture not in ("amd64", "all") for _, architecture in inventory):
            raise LockContractError("base inventory architecture differs from lock")
        repos = []
        for repo in stage["repositories"]:
            records = [p["record"] for p in stage["packages"] if p["suite"] == repo["suite"]]
            proof = validate_signed_repository(_read(root, repo["inrelease"]), _read(root, repo["index"]),
                                               records, suite=repo["suite"], architecture="amd64", now=now)
            if proof["keyring_sha256"] != manifest["keyring_sha256"]:
                raise LockContractError("archive keyring differs from lock")
            repos.append({"suite": repo["suite"], **proof})
        for package in stage["packages"]:
            try:
                with _path(root, package["file"]).open("rb") as source:
                    verify_package_stream(package["record"], source)
            except OSError as exc:
                raise LockContractError("package file unavailable") from exc
        results[name] = {"base_image": stage["base_image"], "base_package_count": len(inventory),
                         "base_inventory_measured_from_image": False,
                         "package_count": len(stage["packages"]), "repositories": repos}
    return {"schema": "a4a-relay-debian-bundle-receipt-v1", "checked_at_utc": now.isoformat(),
            "signature_verified": True, "package_bytes_verified": True, "packages_installed": False,
            "keyring_sha256": manifest["keyring_sha256"], "stages": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("bundle", type=Path)
    options = parser.parse_args()
    try:
        with options.lock.open("rb") as source:
            raw = source.read(_MAX_LOCK + 1)
        proof = verify_bundle(load_lock(raw), options.bundle, now=datetime.now(timezone.utc))
        proof["lock_sha256"] = hashlib.sha256(raw).hexdigest()
    except (LockContractError, OSError) as exc:
        print(f"Debian bundle verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(proof, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
