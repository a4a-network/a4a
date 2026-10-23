"""Bundle tests stub cryptography; native signed replay is separate evidence."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import debian_build_lock as lock
import debian_release_auth as auth

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)
RING = "c" * 64
TRIXIE_RUNTIME = (
    "docker.io/library/debian:trixie-slim@sha256:"
    "7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c"
)


def descriptor(path, payload):
    return {"path": path, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    files = {}
    stages = {}
    for stage, image in lock.BASE_IMAGES.items():
        base = b"base\t1\tamd64\n"
        base_path = f"{stage}/base.tsv"
        files[base_path] = base
        record = {"Package": "tool", "Version": "2", "Architecture": "amd64",
                  "Filename": "pool/main/t/tool/tool.deb", "Size": "3",
                  "SHA256": hashlib.sha256(b"deb").hexdigest()}
        index = ("\n".join(f"{key}: {value}" for key, value in record.items()) + "\n\n").encode()
        repos = []
        for suite in sorted(lock.SUITES):
            release = (f"Codename: {suite}\nArchitectures: amd64\nDate: Thu, 01 Oct 2026 00:00:00 UTC\n"
                       "Valid-Until: Thu, 08 Oct 2026 00:00:00 UTC\nSHA256:\n"
                       f" {hashlib.sha256(index).hexdigest()} {len(index)} main/binary-amd64/Packages\n").encode()
            release_path, index_path = f"{stage}/{suite}/InRelease", f"{stage}/{suite}/Packages"
            files[release_path], files[index_path] = release, index
            repos.append({"suite": suite, "inrelease": descriptor(release_path, release),
                          "index": descriptor(index_path, index)})
        package_path = f"{stage}/packages/tool.deb"
        files[package_path] = b"deb"
        stages[stage] = {"base_image": image, "base_inventory": descriptor(base_path, base),
                         "repositories": repos, "resolved_requests": ["tool=2"],
                         "packages": [{"suite": "bookworm", "record": record,
                                       "file": descriptor(package_path, b"deb")}]}
    manifest = {"schema": lock.SCHEMA, "architecture": "amd64", "keyring_sha256": RING,
                "stages": stages}
    for name, payload in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    monkeypatch.setattr(auth, "authenticate_inrelease", lambda raw: {
        "release_payload": raw, "signature_verified": True, "signers": ["A" * 40],
        "keyring_sha256": RING})
    return manifest, tmp_path


def check(bundle):
    manifest, root = bundle
    return lock.verify_bundle(manifest, root, now=NOW)


def test_complete_bundle_is_checked_without_installation(bundle):
    proof = check(bundle)
    assert proof["signature_verified"] is True
    assert proof["package_bytes_verified"] is True
    assert proof["packages_installed"] is False
    assert proof["stages"]["builder"]["package_count"] == 1
    assert proof["stages"]["runtime"]["base_package_count"] == 1
    assert len(proof["stages"]["builder"]["repositories"]) == 3


def test_json_round_trip_is_valid(bundle):
    manifest, _ = bundle
    assert lock.load_lock(json.dumps(manifest).encode()) == manifest


@pytest.mark.parametrize("raw", [b"{}", b"[]", b'{"schema":1,"schema":2}', b'{"schema":NaN}',
                                 b"\xff", b"{", b"x" * (1024 * 1024 + 1)],
                         ids=["empty-object", "array", "duplicate", "nonfinite", "encoding", "truncated", "oversized"])
def test_invalid_json_is_rejected(raw):
    with pytest.raises(lock.LockContractError):
        lock.load_lock(raw)


@pytest.mark.parametrize("where,key,value", [
    ("top", "architecture", "arm64"), ("top", "schema", "unknown"),
    ("top", "keyring_sha256", "not a hash"), ("top", "disable_expiry", True),
    ("stage", "base_image", "debian:latest"), ("stage", "shell", "ignored"),
    ("file", "path", "../escape"), ("file", "path", "/abs"),
    ("file", "path", "C:/drive"), ("file", "path", "a\\b"),
    ("file", "path", "a//b"), ("file", "path", "a/./b"),
    ("file", "path", "a b"), ("file", "size", True),
    ("file", "size", 0), ("file", "size", 1024 * 1024 * 1024),
    ("file", "sha256", "A" * 64), ("file", "mode", "ignore"),
])
def test_unknown_fields_bad_pins_and_nonportable_paths_are_rejected(bundle, where, key, value):
    manifest, _ = bundle
    target = {"top": manifest, "stage": manifest["stages"]["builder"],
              "file": manifest["stages"]["builder"]["base_inventory"]}[where]
    target[key] = value
    with pytest.raises(lock.LockContractError):
        check(bundle)


@pytest.mark.parametrize("change", ["missing-stage", "extra-stage", "missing-repo", "duplicate-repo",
                                    "wrong-request", "duplicate-package", "wrong-file-hash",
                                    "wrong-package-suite", "reused-path"])
def test_incomplete_or_ambiguous_sets_are_rejected(bundle, change):
    manifest, _ = bundle
    stage = manifest["stages"]["builder"]
    if change == "missing-stage":
        del manifest["stages"]["runtime"]
    elif change == "extra-stage":
        manifest["stages"]["third"] = deepcopy(stage)
    elif change == "missing-repo":
        stage["repositories"].pop()
    elif change == "duplicate-repo":
        stage["repositories"][1] = deepcopy(stage["repositories"][0])
    elif change == "wrong-request":
        stage["resolved_requests"] = ["tool=3"]
    elif change == "duplicate-package":
        stage["packages"].append(deepcopy(stage["packages"][0]))
    elif change == "wrong-file-hash":
        stage["packages"][0]["file"]["sha256"] = "a" * 64
    elif change == "wrong-package-suite":
        stage["packages"][0]["suite"] = "bullseye"
    else:
        stage["repositories"][1]["index"] = deepcopy(stage["repositories"][0]["index"])
    with pytest.raises(lock.LockContractError):
        check(bundle)


@pytest.mark.parametrize("target", ["inventory", "index", "inrelease", "package"])
def test_changed_bundle_file_is_rejected(bundle, target):
    manifest, root = bundle
    stage = manifest["stages"]["builder"]
    binding = {"inventory": stage["base_inventory"], "index": stage["repositories"][0]["index"],
               "inrelease": stage["repositories"][0]["inrelease"],
               "package": stage["packages"][0]["file"]}[target]
    path = root / binding["path"]
    raw = path.read_bytes()
    path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    with pytest.raises(lock.LockContractError):
        check(bundle)


def test_actual_expiry_is_not_replaced_by_lock_creation_time(bundle):
    manifest, root = bundle
    with pytest.raises(lock.LockContractError, match="expired"):
        lock.verify_bundle(manifest, root, now=datetime(2026, 10, 8, tzinfo=timezone.utc))


def test_different_keyring_is_rejected(bundle):
    bundle[0]["keyring_sha256"] = "d" * 64
    with pytest.raises(lock.LockContractError, match="keyring"):
        check(bundle)


def test_signature_failure_stops_before_package_verification(bundle, monkeypatch):
    def fail(payload):
        raise lock.LockContractError("gpgv rejected signature")
    monkeypatch.setattr(auth, "authenticate_inrelease", fail)
    with pytest.raises(lock.LockContractError, match="gpgv"):
        check(bundle)


def test_naive_time_is_rejected(bundle):
    with pytest.raises(lock.LockContractError):
        lock.verify_bundle(*bundle, now=datetime(2026, 10, 2))


def test_missing_and_directory_files_are_rejected(bundle):
    manifest, root = bundle
    path = root / manifest["stages"]["builder"]["base_inventory"]["path"]
    path.unlink()
    with pytest.raises(lock.LockContractError):
        check(bundle)
    path.mkdir()
    with pytest.raises(lock.LockContractError):
        check(bundle)


def test_symlink_components_are_rejected(bundle):
    manifest, root = bundle
    target = root / "builder/base.tsv"
    replacement = root / "other.tsv"
    replacement.write_bytes(target.read_bytes())
    target.unlink()
    try:
        target.symlink_to(replacement)
    except OSError:
        pytest.skip("symlink creation unavailable; native Linux probe required")
    with pytest.raises(lock.LockContractError, match="symlink"):
        check(bundle)


def test_missing_bundle_root_is_rejected(bundle):
    manifest, root = bundle
    with pytest.raises(lock.LockContractError, match="root"):
        lock.verify_bundle(manifest, root / "missing", now=NOW)


def test_aggregate_limits_are_checked_before_reads(bundle):
    manifest, _ = bundle
    for stage in manifest["stages"].values():
        for repository in stage["repositories"]:
            repository["index"]["size"] = 128 * 1024 * 1024
    with pytest.raises(lock.LockContractError, match="aggregate"):
        check(bundle)


def test_lock_base_pins_match_the_actual_dockerfile():
    relay = Path(__file__).resolve().parents[2] / "relay"
    manifest = lock.load_lock((relay / "debian/lock.json").read_bytes())
    dockerfile = (relay / "Dockerfile").read_text(encoding="utf-8")
    assert all(f"FROM {stage['base_image']}" in dockerfile for stage in manifest["stages"].values())


def test_cli_does_not_accept_historical_time_or_bypass_flags(bundle, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["debian_build_lock.py", "lock.json", "bundle", "--now", "2026-10-02"])
    with pytest.raises(SystemExit) as rejected:
        lock.main()
    assert rejected.value.code == 2


def trixie_runtime(bundle):
    """Synthetic repositories test the complete contract, not native signatures."""
    manifest, root = bundle
    runtime = manifest["stages"]["runtime"]
    runtime["base_image"] = TRIXIE_RUNTIME
    for repo in runtime["repositories"]:
        repo["suite"] = repo["suite"].replace("bookworm", "trixie")
        path = root / repo["inrelease"]["path"]
        raw = path.read_bytes().replace(b"bookworm", b"trixie")
        path.write_bytes(raw)
        repo["inrelease"] = descriptor(repo["inrelease"]["path"], raw)
    for package in runtime["packages"]:
        package["suite"] = "trixie"
    return manifest, root


def test_pinned_trixie_runtime_and_bookworm_builder_are_verified_together(bundle):
    proof = lock.verify_bundle(*trixie_runtime(bundle), now=NOW)
    assert proof["signature_verified"] is True
    assert proof["packages_installed"] is False
    assert proof["stages"]["runtime"]["base_image"] == TRIXIE_RUNTIME
    assert {repo["suite"] for repo in proof["stages"]["runtime"]["repositories"]} == {
        "trixie", "trixie-updates", "trixie-security"
    }
    assert {repo["suite"] for repo in proof["stages"]["builder"]["repositories"]} == lock.SUITES


@pytest.mark.parametrize("stage", ["builder", "runtime"])
def test_a_stage_cannot_mix_suites_from_two_debian_releases(bundle, stage):
    manifest, _ = trixie_runtime(bundle)
    repo = manifest["stages"][stage]["repositories"][0]
    repo["suite"] = repo["suite"].replace("bookworm", "trixie") if stage == "builder" else repo["suite"].replace("trixie", "bookworm")
    with pytest.raises(lock.LockContractError, match="suite"):
        lock.validate_lock(manifest)


def test_bookworm_runtime_pin_does_not_authorize_trixie_repositories(bundle):
    manifest, _ = trixie_runtime(bundle)
    manifest["stages"]["runtime"]["base_image"] = lock.BASE_IMAGES["runtime"]
    with pytest.raises(lock.LockContractError, match="suite"):
        lock.validate_lock(manifest)
