#!/usr/bin/env python3
"""Create and verify a portable, offline A4A release-evidence package.

The package joins the artifact inventory, wheels, SBOMs, locked release inputs,
and corresponding source into one hash-indexed directory and deterministic tarball.
It neither signs nor publishes the result. Image bytes are not exported; immutable
image IDs are checked against the local Docker store while the package is built.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
BUILD_ROOT = ROOT / "build"
DEFAULT_POLICY = ROOT / "scripts" / "release-evidence-policy.json"
DEFAULT_OUTPUT = BUILD_ROOT / "release-evidence"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024


class EvidenceError(RuntimeError):
    """Release evidence is incomplete, stale, unsafe, or internally inconsistent."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path, label: str) -> tuple[bytes, Any]:
    try:
        raw = path.read_bytes()
        return raw, json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid {label} {path}: {exc}") from exc


def safe_relative(value: str, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise EvidenceError(f"invalid {label}: {value!r}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
        or path.as_posix() != value
    ):
        raise EvidenceError(f"unsafe {label}: {value!r}")
    return path


def repository_path(value: str, *, label: str) -> Path:
    relative = safe_relative(value, label=label)
    path = ROOT.joinpath(*relative.parts)
    resolved = path.resolve()
    if ROOT.resolve() not in resolved.parents:
        raise EvidenceError(f"{label} escapes the repository: {value!r}")
    return path


def ordinary_file(path: Path, *, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"{label} is missing or not an ordinary file: {path}")


def run_git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    if result.returncode:
        raise EvidenceError(result.stderr.strip() or f"git {arguments!r} failed")
    return result.stdout.rstrip("\r\n")


def git_state() -> dict[str, Any]:
    commit = run_git("rev-parse", "HEAD").strip()
    changed = sorted(line[3:] for line in run_git("status", "--porcelain").splitlines())
    if changed:
        raise EvidenceError("refusing release evidence from a dirty worktree: " + ", ".join(changed))
    return {"commit": commit, "dirty": False, "changed_paths": []}


def load_policy(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw, policy = read_json(path, "release evidence policy")
    if not isinstance(policy, dict) or policy.get("schema") != "a4a-release-evidence-policy-v1":
        raise EvidenceError("release evidence policy has an unsupported schema")
    for key in (
        "release_inventory",
        "source_bundle",
        "public_source",
        "public_source_archive",
        "wheel_directory",
    ):
        safe_relative(policy.get(key), label=key)
    for key in ("tracked_release_inputs", "post_inventory_non_runtime_paths"):
        values = policy.get(key)
        if not isinstance(values, list) or not values:
            raise EvidenceError(f"release evidence policy has no {key}")
        normalized = [safe_relative(value, label=key).as_posix() for value in values]
        if len(set(normalized)) != len(normalized):
            raise EvidenceError(f"release evidence policy has duplicate {key}")
        policy[key] = normalized
    if "supplemental_notices" in policy:
        safe_relative(policy["supplemental_notices"], label="supplemental notices")
    return raw, policy


def load_notice_verifier():
    script = Path(__file__).with_name("release_notices.py")
    spec = importlib.util.spec_from_file_location("a4a_release_notices", script)
    if spec is None or spec.loader is None:
        raise EvidenceError("notice verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_post_inventory_changes(inventory_commit: str, head: str, allowed: list[str]) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{40}", inventory_commit):
        raise EvidenceError("release inventory has an invalid Git commit")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", inventory_commit, head], cwd=ROOT, timeout=30,
    )
    if ancestor.returncode != 0:
        raise EvidenceError("release inventory commit is not an ancestor of the evidence commit")
    changed = sorted(
        line for line in run_git("diff", "--name-only", f"{inventory_commit}..{head}").splitlines()
        if line
    )
    unexpected = sorted(set(changed) - set(allowed))
    if unexpected:
        raise EvidenceError(
            "runtime-relevant paths changed after the artifact inventory: " + ", ".join(unexpected)
        )
    return changed


def inventory_members(inventory_dir: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    expected: dict[str, str] = {}
    images = manifest.get("images")
    if not isinstance(images, dict) or set(images) != {"mcp", "notary", "relay"}:
        raise EvidenceError("release inventory must describe exactly mcp, notary, and relay images")
    for name, image in images.items():
        if not isinstance(image, dict):
            raise EvidenceError(f"invalid release inventory image: {name}")
        filename = safe_relative(image.get("sbom"), label=f"{name} SBOM").as_posix()
        digest = image.get("sbom_sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise EvidenceError(f"invalid {name} SBOM hash")
        expected[filename] = digest
    relay = manifest.get("relay_rust")
    if not isinstance(relay, dict):
        raise EvidenceError("release inventory has no relay Rust metadata")
    metadata = safe_relative(relay.get("metadata"), label="relay metadata").as_posix()
    metadata_sha = relay.get("metadata_sha256")
    if not isinstance(metadata_sha, str) or not SHA256_RE.fullmatch(metadata_sha):
        raise EvidenceError("release inventory has an invalid relay metadata hash")
    expected[metadata] = metadata_sha

    actual = {path.name for path in inventory_dir.iterdir()}
    required = {"manifest.json", *expected}
    if actual != required:
        raise EvidenceError(
            f"release inventory file set differs: missing={sorted(required - actual)}, "
            f"unexpected={sorted(actual - required)}"
        )
    members = []
    for filename, digest in sorted(expected.items()):
        path = inventory_dir / filename
        ordinary_file(path, label="release inventory member")
        actual_digest = sha256_file(path)
        if actual_digest != digest:
            raise EvidenceError(f"release inventory member hash mismatch: {filename}")
        members.append({"filename": filename, "sha256": digest, "size": path.stat().st_size})
    return members


def wheel_members(wheel_dir: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    wheels = manifest.get("wheels")
    if not isinstance(wheels, list) or len(wheels) != 4:
        raise EvidenceError("release inventory must describe exactly four wheels")
    expected: dict[str, dict[str, Any]] = {}
    for wheel in wheels:
        if not isinstance(wheel, dict):
            raise EvidenceError("invalid wheel inventory entry")
        filename = safe_relative(wheel.get("filename"), label="wheel filename").as_posix()
        digest = wheel.get("sha256")
        size = wheel.get("size")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise EvidenceError(f"invalid wheel hash: {filename}")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise EvidenceError(f"invalid wheel size: {filename}")
        if filename in expected:
            raise EvidenceError(f"duplicate wheel: {filename}")
        expected[filename] = wheel
    actual = {path.name for path in wheel_dir.iterdir()}
    if actual != set(expected):
        raise EvidenceError(
            f"wheel file set differs: missing={sorted(set(expected) - actual)}, "
            f"unexpected={sorted(actual - set(expected))}"
        )
    for filename, wheel in expected.items():
        path = wheel_dir / filename
        ordinary_file(path, label="wheel")
        if path.stat().st_size != wheel["size"] or sha256_file(path) != wheel["sha256"]:
            raise EvidenceError(f"wheel bytes differ from release inventory: {filename}")
    return [dict(expected[name]) for name in sorted(expected)]


def load_source_verifier():
    script = ROOT / "scripts" / "build-license-source-bundle.py"
    spec = importlib.util.spec_from_file_location("a4a_source_bundle_verifier", script)
    if spec is None or spec.loader is None:
        raise EvidenceError("could not load the corresponding-source verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_source_bundle(
    source_dir: Path,
    inventory_raw: bytes,
    inventory: dict[str, Any],
    head: str,
) -> dict[str, Any]:
    try:
        source = load_source_verifier().verify_bundle(source_dir)
    except Exception as exc:
        raise EvidenceError(f"corresponding-source verification failed: {exc}") from exc
    if source.get("git") != {"commit": head, "dirty": False, "changed_paths": []}:
        raise EvidenceError("corresponding-source bundle is stale or was built from a dirty worktree")
    binding = source.get("release_inventory")
    if not isinstance(binding, dict) or binding.get("sha256") != sha256_bytes(inventory_raw):
        raise EvidenceError("corresponding-source bundle targets another release inventory")
    image_ids = {name: item["image_id"] for name, item in inventory["images"].items()}
    if binding.get("images") != image_ids:
        raise EvidenceError("corresponding-source bundle targets different image IDs")
    return source


def load_public_source_verifier():
    script = ROOT / "scripts" / "build-public-source-archive.py"
    spec = importlib.util.spec_from_file_location("a4a_public_source_verifier", script)
    if spec is None or spec.loader is None:
        raise EvidenceError("could not load the public-source verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_public_source(directory: Path, archive: Path, head: str) -> dict[str, Any]:
    try:
        verifier = load_public_source_verifier()
        unpacked = verifier.verify_directory(directory)
        packed = verifier.verify_archive(archive)
    except Exception as exc:
        raise EvidenceError(f"public-source verification failed: {exc}") from exc
    if unpacked != packed:
        raise EvidenceError("public-source directory and archive describe different snapshots")
    if unpacked.get("git_commit") != head:
        raise EvidenceError("public-source artifact targets another Git commit")
    checksum = archive.with_name(archive.name + ".sha256")
    ordinary_file(checksum, label="public-source archive checksum")
    expected_line = f"{sha256_file(archive)}  {archive.name}\n".encode("ascii")
    if checksum.read_bytes() != expected_line:
        raise EvidenceError("public-source archive checksum sidecar is missing or stale")
    return unpacked


def docker_image_bindings(inventory: dict[str, Any]) -> list[dict[str, str]]:
    context = inventory.get("docker_context")
    if context is not None and (not isinstance(context, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", context)):
        raise EvidenceError("inventory has an invalid Docker context")
    docker = ["docker", *(["--context", context] if context is not None else [])]
    bindings = []
    candidates = [
        (name, data) for name, data in sorted(inventory["images"].items())
    ]
    candidates.append(("relay-builder", inventory["relay_rust"]["builder_image"]))
    for name, data in candidates:
        reference = data.get("reference")
        expected = data.get("image_id")
        if not isinstance(reference, str) or not isinstance(expected, str) or not expected.startswith("sha256:"):
            raise EvidenceError(f"invalid Docker image identity for {name}")
        result = subprocess.run(
            [*docker, "image", "inspect", reference, "--format", "{{.Id}}"],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
        if result.returncode:
            raise EvidenceError(f"Docker image is unavailable for {name}: {reference}")
        actual = result.stdout.strip()
        if actual != expected:
            raise EvidenceError(
                f"Docker tag drift for {name}: expected {expected}, got {actual}"
            )
        bindings.append({"name": name, "reference": reference, "image_id": expected})
    return bindings


def validate_output(path: Path) -> Path:
    resolved = path.resolve()
    build = BUILD_ROOT.resolve()
    if resolved == build or build not in resolved.parents:
        raise EvidenceError(f"output must be a child of {build}: {resolved}")
    return resolved


def copy_file(source: Path, destination: Path) -> None:
    ordinary_file(source, label="evidence input")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def copy_tree(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise EvidenceError(f"evidence directory is missing or unsafe: {source}")
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise EvidenceError(f"evidence directory contains a symlink: {path}")
        if path.is_file():
            copy_file(path, destination / path.relative_to(source))
        elif not path.is_dir():
            raise EvidenceError(f"evidence directory contains a special file: {path}")


def embed_policy(staging: Path, policy_path: Path, policy_raw: bytes) -> dict[str, str]:
    """Retain the selected policy independently of the tracked-input template."""
    ordinary_file(policy_path, label="release-evidence policy")
    try:
        relative = policy_path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise EvidenceError("release-evidence policy must be inside the repository") from exc
    safe_relative(relative, label="release-evidence policy")
    digest = sha256_bytes(policy_raw)
    if sha256_file(policy_path) != digest:
        raise EvidenceError("release-evidence policy changed after it was read")
    destination = staging / "release-inputs" / Path(relative)
    if destination.exists() or destination.is_symlink():
        ordinary_file(destination, label="embedded release-evidence policy")
        if destination.read_bytes() != policy_raw:
            raise EvidenceError("embedded release-evidence policy differs from the selected policy")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as handle:
            handle.write(policy_raw)
    return {"path": relative, "sha256": digest}


def indexed_files(root: Path) -> list[dict[str, Any]]:
    result = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise EvidenceError(f"evidence output contains a symlink: {path}")
        if path.is_file() and path != root / "manifest.json":
            result.append({
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            })
        elif not path.is_dir() and not path.is_file():
            raise EvidenceError(f"evidence output contains a special file: {path}")
    return result


def index_text(manifest_summary: dict[str, Any]) -> bytes:
    lines = [
        "# A4A release evidence",
        "",
        "This package joins the exact release inventory, four wheels, SPDX SBOMs,",
        "relay Cargo metadata, locked build inputs, and corresponding source.",
        "Supplemental notices can include saved runtime images and additional",
        "corresponding source. It is local evidence, not a signature, legal advice,",
        "or publication approval.",
        "",
        f"- Evidence Git commit: `{manifest_summary['git_commit']}`",
        f"- Artifact inventory Git commit: `{manifest_summary['inventory_commit']}`",
        f"- Immutable runtime image IDs checked locally: {manifest_summary['image_count']}",
        f"- Wheels: {manifest_summary['wheel_count']}",
        f"- Corresponding-source artifacts: {manifest_summary['source_count']}",
        f"- Public source files: {manifest_summary['public_source_count']}",
        "",
        "Verify the directory offline with:",
        "",
        "```console",
        "python scripts/build-release-evidence.py --verify build/release-evidence",
        "```",
        "",
        "Verify the deterministic archive without extracting it with:",
        "",
        "```console",
        "python scripts/build-release-evidence.py --verify-archive build/release-evidence.tar.gz",
        "```",
        "",
    ]
    return "\n".join(lines).encode()


def quarantine_generated(path: Path, reason: str) -> None:
    helper = load_source_verifier()
    helper.BUILD_ROOT = BUILD_ROOT
    try:
        helper.quarantine_directory(path, reason)
    except helper.SourceBundleError as exc:
        raise EvidenceError(str(exc)) from exc


def replace_directory(staging: Path, output: Path) -> None:
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise EvidenceError(f"unsafe output path: {output}")
    helper = load_source_verifier()
    helper.BUILD_ROOT = BUILD_ROOT
    try:
        helper.replace_directory(staging, output)
    except helper.SourceBundleError as exc:
        raise EvidenceError(str(exc)) from exc


def deterministic_archive(directory: Path, archive: Path) -> str:
    archive = validate_output(archive)
    temporary = archive.with_name(archive.name + ".tmp")
    if temporary.exists():
        quarantine_generated(temporary, "previous incomplete release-evidence archive")
    root_name = directory.name
    with temporary.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as tar:
                paths = [
                    directory,
                    *sorted(
                        directory.rglob("*"),
                        key=lambda path: path.relative_to(directory).as_posix(),
                    ),
                ]
                for path in paths:
                    relative = Path(root_name) / path.relative_to(directory)
                    info = tarfile.TarInfo(relative.as_posix())
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    if path.is_dir():
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        tar.addfile(info)
                    else:
                        ordinary_file(path, label="archive input")
                        info.size = path.stat().st_size
                        info.mode = 0o644
                        with path.open("rb") as handle:
                            tar.addfile(info, handle)
    if archive.exists():
        quarantine_generated(archive, "replaced release-evidence archive")
    os.replace(temporary, archive)
    digest = sha256_file(archive)
    checksum = archive.with_name(archive.name + ".sha256")
    if checksum.exists():
        quarantine_generated(checksum, "replaced release-evidence checksum")
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii", newline="\n")
    return digest


def build_evidence(policy_path: Path, output: Path, archive: Path) -> tuple[dict[str, Any], str]:
    output = validate_output(output)
    policy_raw, policy = load_policy(policy_path)
    state = git_state()
    inventory_path = repository_path(policy["release_inventory"], label="release inventory")
    inventory_dir = inventory_path.parent
    inventory_raw, inventory = read_json(inventory_path, "release inventory")
    if not isinstance(inventory, dict) or inventory.get("schema") != "a4a-release-inventory-v1":
        raise EvidenceError("release inventory has an unsupported schema")
    if (inventory.get("git") or {}).get("dirty") is not False:
        raise EvidenceError("release inventory was built from a dirty worktree")
    inventory_commit = inventory["git"].get("commit")
    changed_after_inventory = validate_post_inventory_changes(
        inventory_commit, state["commit"], policy["post_inventory_non_runtime_paths"]
    )
    inventory_files = inventory_members(inventory_dir, inventory)
    wheel_dir = repository_path(policy["wheel_directory"], label="wheel directory")
    wheels = wheel_members(wheel_dir, inventory)
    source_dir = repository_path(policy["source_bundle"], label="source bundle")
    source = validate_source_bundle(source_dir, inventory_raw, inventory, state["commit"])
    public_source_dir = repository_path(policy["public_source"], label="public source")
    public_source_archive = repository_path(
        policy["public_source_archive"], label="public source archive"
    )
    public_source = validate_public_source(
        public_source_dir, public_source_archive, state["commit"]
    )
    images = docker_image_bindings(inventory)

    tracked = []
    for relative in policy["tracked_release_inputs"]:
        path = repository_path(relative, label="tracked release input")
        ordinary_file(path, label="tracked release input")
        tracked.append({"path": relative, "sha256": sha256_file(path), "size": path.stat().st_size})

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=output.name + ".", dir=output.parent))
    try:
        copy_tree(inventory_dir, staging / "inventory")
        notice_snapshot = None
        if "supplemental_notices" in policy:
            notices = load_notice_verifier()
            materials = repository_path(policy["supplemental_notices"], label="supplemental notices")
            try:
                notice_snapshot = notices.build_snapshot(materials, staging / "supplemental-notices", inventory_raw, state)
            except notices.NoticeError as exc:
                raise EvidenceError("supplemental notice verification failed: " + str(exc)) from exc
        copy_tree(wheel_dir, staging / "wheels")
        copy_tree(source_dir, staging / "corresponding-source")
        copy_file(
            public_source_dir / "A4A-SOURCE.json",
            staging / "public-source" / "A4A-SOURCE.json",
        )
        copy_file(
            public_source_archive,
            staging / "public-source" / public_source_archive.name,
        )
        public_checksum = public_source_archive.with_name(public_source_archive.name + ".sha256")
        copy_file(
            public_checksum,
            staging / "public-source" / public_checksum.name,
        )
        for item in tracked:
            copy_file(ROOT / Path(item["path"]), staging / "release-inputs" / Path(item["path"]))
        selected_policy = embed_policy(staging, policy_path, policy_raw)
        summary = {
            "git_commit": state["commit"],
            "inventory_commit": inventory_commit,
            "image_count": len(images),
            "wheel_count": len(wheels),
            "source_count": source["artifact_count"],
            "public_source_count": public_source["file_count"],
        }
        (staging / "INDEX.md").write_bytes(index_text(summary))
        manifest = {
            "schema": "a4a-release-evidence-v1",
            "git": state,
            "policy": selected_policy,
            "release_inventory": {
                "git_commit": inventory_commit,
                "sha256": sha256_bytes(inventory_raw),
                "members": inventory_files,
            },
            "post_inventory_changed_paths": changed_after_inventory,
            "docker_images": images,
            "wheels": wheels,
            "corresponding_source": {
                "manifest_sha256": sha256_file(source_dir / "manifest.json"),
                "artifact_count": source["artifact_count"],
                "total_source_bytes": source["total_source_bytes"],
            },
            "public_source": {
                "git_commit": public_source["git_commit"],
                "snapshot_id": public_source["snapshot_id"],
                "file_count": public_source["file_count"],
                "total_source_bytes": public_source["total_bytes"],
                "archive": public_source_archive.name,
                "archive_sha256": sha256_file(public_source_archive),
                "archive_size": public_source_archive.stat().st_size,
            },
            "tracked_release_inputs": tracked,
        }
        if notice_snapshot is not None:
            manifest["supplemental_notices"] = {
                "manifest_sha256": sha256_file(staging / "supplemental-notices/manifest.json"),
                "file_count": notice_snapshot["file_count"],
                "coverage": notice_snapshot["coverage"],
            }
        manifest["files"] = indexed_files(staging)
        manifest["file_count"] = len(manifest["files"])
        manifest["total_bytes"] = sum(item["size"] for item in manifest["files"])
        (staging / "manifest.json").write_bytes(canonical_json(manifest))
        verify_directory(staging)
        replace_directory(staging, output)
        archive_digest = deterministic_archive(output, archive)
        verify_archive(archive)
        return manifest, archive_digest
    except Exception:
        if staging.exists():
            quarantine_generated(staging, "release-evidence build failed; retained for diagnosis")
        raise


def expected_directories(files: set[str]) -> set[str]:
    result: set[str] = set()
    for filename in files:
        parent = PurePosixPath(filename).parent
        while parent != PurePosixPath("."):
            result.add(parent.as_posix())
            parent = parent.parent
    return result


def validate_file_index(
    manifest: dict[str, Any],
    read: Any,
    actual_names: set[str],
    actual_directories: set[str],
) -> None:
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise EvidenceError("evidence manifest contains no files")
    expected = {"manifest.json"}
    total = 0
    for item in files:
        if not isinstance(item, dict):
            raise EvidenceError("evidence manifest has invalid file metadata")
        relative = safe_relative(item.get("path"), label="evidence file").as_posix()
        digest = item.get("sha256")
        size = item.get("size")
        if relative in expected:
            raise EvidenceError(f"duplicate evidence file: {relative}")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise EvidenceError(f"invalid evidence hash: {relative}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise EvidenceError(f"invalid evidence size: {relative}")
        content = read(relative)
        if len(content) != size or sha256_bytes(content) != digest:
            raise EvidenceError(f"evidence file differs from manifest: {relative}")
        expected.add(relative)
        total += size
    if actual_names != expected:
        raise EvidenceError(
            f"evidence file set differs: missing={sorted(expected - actual_names)}, "
            f"unexpected={sorted(actual_names - expected)}"
        )
    required_directories = expected_directories(expected)
    if actual_directories != required_directories:
        raise EvidenceError(
            f"evidence directory set differs: missing={sorted(required_directories - actual_directories)}, "
            f"unexpected={sorted(actual_directories - required_directories)}"
        )
    if manifest.get("file_count") != len(files) or manifest.get("total_bytes") != total:
        raise EvidenceError("evidence aggregate count or size differs from manifest")


def validate_nested_bindings(manifest: dict[str, Any], read: Any) -> None:
    """Cross-check copied manifests and artifacts, not only the outer file index."""
    try:
        inventory_raw = read("inventory/manifest.json")
        inventory = json.loads(inventory_raw)
        inventory_meta = manifest["release_inventory"]
        if sha256_bytes(inventory_raw) != inventory_meta["sha256"]:
            raise EvidenceError("embedded release inventory hash differs from the binding")
        if inventory["git"]["commit"] != inventory_meta["git_commit"]:
            raise EvidenceError("embedded release inventory commit differs from the binding")
        for item in inventory_meta["members"]:
            content = read("inventory/" + item["filename"])
            if len(content) != item["size"] or sha256_bytes(content) != item["sha256"]:
                raise EvidenceError(f"embedded inventory member differs: {item['filename']}")

        for wheel in manifest["wheels"]:
            content = read("wheels/" + wheel["filename"])
            if len(content) != wheel["size"] or sha256_bytes(content) != wheel["sha256"]:
                raise EvidenceError(f"embedded wheel differs: {wheel['filename']}")

        source_raw = read("corresponding-source/manifest.json")
        source = json.loads(source_raw)
        source_meta = manifest["corresponding_source"]
        if sha256_bytes(source_raw) != source_meta["manifest_sha256"]:
            raise EvidenceError("embedded corresponding-source manifest hash differs")
        if (
            source["artifact_count"] != source_meta["artifact_count"]
            or source["total_source_bytes"] != source_meta["total_source_bytes"]
        ):
            raise EvidenceError("embedded corresponding-source aggregates differ")

        public_raw = read("public-source/A4A-SOURCE.json")
        public_record = json.loads(public_raw)
        load_public_source_verifier().validate_record(public_record)
        public_meta = manifest["public_source"]
        for field in ("git_commit", "snapshot_id", "file_count"):
            if public_record[field] != public_meta[field]:
                raise EvidenceError(f"embedded public-source {field} differs from the binding")
        if public_record["total_bytes"] != public_meta["total_source_bytes"]:
            raise EvidenceError("embedded public-source byte count differs from the binding")
        archive_name = public_meta["archive"]
        safe_relative(archive_name, label="embedded public-source archive")
        archive_bytes = read("public-source/" + archive_name)
        if (
            len(archive_bytes) != public_meta["archive_size"]
            or sha256_bytes(archive_bytes) != public_meta["archive_sha256"]
        ):
            raise EvidenceError("embedded public-source archive differs from the binding")
        checksum = read("public-source/" + archive_name + ".sha256")
        expected_checksum = f"{public_meta['archive_sha256']}  {archive_name}\n".encode("ascii")
        if checksum != expected_checksum:
            raise EvidenceError("embedded public-source checksum sidecar differs")

        policy = manifest["policy"]
        policy_bytes = read("release-inputs/" + policy["path"])
        if sha256_bytes(policy_bytes) != policy["sha256"]:
            raise EvidenceError("embedded release-evidence policy differs from the binding")
        selected_policy = json.loads(policy_bytes)
        if not isinstance(selected_policy, dict):
            raise EvidenceError("embedded selected policy is not an object")
        notice_paths = {item["path"].removeprefix("supplemental-notices/") for item in manifest.get("files", [])
                        if item["path"].startswith("supplemental-notices/")}
        if ("supplemental_notices" in selected_policy) != ("supplemental_notices" in manifest):
            raise EvidenceError("supplemental notice binding differs from selected policy")
        if "supplemental_notices" in manifest:
            notices = load_notice_verifier()
            binding = manifest["supplemental_notices"]
            if sha256_bytes(read("supplemental-notices/manifest.json")) != binding["manifest_sha256"]:
                raise EvidenceError("supplemental notice manifest hash differs")
            try:
                snapshot = notices.verify_snapshot(lambda name: read("supplemental-notices/" + name),
                                                   inventory_raw, notice_paths - {"manifest.json"}, manifest["git"]["commit"])
            except notices.NoticeError as exc:
                raise EvidenceError("embedded supplemental notices failed: " + str(exc)) from exc
            if snapshot["file_count"] != binding["file_count"] or snapshot["coverage"] != binding["coverage"]:
                raise EvidenceError("supplemental notice coverage differs from binding")
            owned = [p for p in public_record["files"] if p["path"] == "relay/LICENSE"]
            if len(owned) != 1 or owned[0]["sha256"] != snapshot["coverage"]["owned_source_notice_sha256"]:
                raise EvidenceError("relay source notice differs from public export")
        elif notice_paths:
            raise EvidenceError("unexpected supplemental notice files")
        for item in manifest["tracked_release_inputs"]:
            content = read("release-inputs/" + item["path"])
            if len(content) != item["size"] or sha256_bytes(content) != item["sha256"]:
                raise EvidenceError(f"embedded tracked release input differs: {item['path']}")
    except KeyError as exc:
        raise EvidenceError(f"release evidence lacks a required nested binding: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"embedded evidence manifest is invalid JSON: {exc}") from exc


def verify_directory(directory: Path) -> dict[str, Any]:
    directory = directory.resolve()
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceError(f"evidence directory is missing or unsafe: {directory}")
    raw, manifest = read_json(directory / "manifest.json", "release evidence manifest")
    if not raw or not isinstance(manifest, dict) or manifest.get("schema") != "a4a-release-evidence-v1":
        raise EvidenceError("release evidence manifest has an unsupported schema")
    actual = set()
    actual_directories = set()
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise EvidenceError(f"evidence directory contains a symlink: {path}")
        if path.is_file():
            actual.add(path.relative_to(directory).as_posix())
        elif path.is_dir():
            actual_directories.add(path.relative_to(directory).as_posix())
        else:
            raise EvidenceError(f"evidence directory contains a special file: {path}")
    validate_file_index(
        manifest,
        lambda name: (directory / Path(name)).read_bytes(),
        actual,
        actual_directories,
    )
    validate_nested_bindings(manifest, lambda name: (directory / Path(name)).read_bytes())
    return manifest


def verify_archive(archive: Path) -> dict[str, Any]:
    ordinary_file(archive, label="release evidence archive")
    with tarfile.open(archive, mode="r:gz") as tar:
        members = tar.getmembers()
        if not members:
            raise EvidenceError("release evidence archive is empty")
        first = safe_relative(members[0].name, label="archive root")
        if len(first.parts) != 1 or not members[0].isdir():
            raise EvidenceError("archive must begin with one top-level directory")
        root = first.parts[0]
        names: set[str] = set()
        directories: set[str] = set()
        files: dict[str, bytes] = {}
        seen_members: set[str] = set()
        previous = ""
        declared_bytes = 0
        for member in members:
            name = member.name
            if name < previous:
                raise EvidenceError("archive members are not sorted")
            previous = name
            path = safe_relative(name, label="archive member")
            if name in seen_members:
                raise EvidenceError(f"duplicate archive member: {name}")
            seen_members.add(name)
            if not path.parts or path.parts[0] != root:
                raise EvidenceError(f"archive member is outside the expected root: {name}")
            if member.mtime != 0 or member.uid != 0 or member.gid != 0:
                raise EvidenceError(f"archive member has non-deterministic metadata: {name}")
            expected_mode = 0o644 if member.isfile() else 0o755
            if member.mode != expected_mode or member.uname or member.gname:
                raise EvidenceError(f"archive member has non-canonical metadata: {name}")
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise EvidenceError(f"archive member has an unsafe type: {name}")
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            if member.isfile():
                if not relative or relative in names:
                    raise EvidenceError(f"duplicate archive file: {name}")
                declared_bytes += member.size
                if declared_bytes > MAX_ARCHIVE_BYTES:
                    raise EvidenceError("archive exceeds the verification size limit")
                handle = tar.extractfile(member)
                if handle is None:
                    raise EvidenceError(f"could not read archive member: {name}")
                content = handle.read()
                if len(content) != member.size:
                    raise EvidenceError(f"truncated archive member: {name}")
                files[relative] = content
                names.add(relative)
            elif relative != ".":
                directories.add(relative)
        raw = files.get("manifest.json")
        if raw is None:
            raise EvidenceError("archive contains no evidence manifest")
        try:
            manifest = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"archive manifest is invalid: {exc}") from exc
        if not isinstance(manifest, dict) or manifest.get("schema") != "a4a-release-evidence-v1":
            raise EvidenceError("archive manifest has an unsupported schema")
        validate_file_index(manifest, lambda name: files[name], names, directories)
        validate_nested_bindings(manifest, lambda name: files[name])
        return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--archive", type=Path, default=BUILD_ROOT / "release-evidence.tar.gz")
    parser.add_argument("--verify", type=Path, help="verify an unpacked evidence directory offline")
    parser.add_argument("--verify-archive", type=Path, help="verify a deterministic evidence archive without extraction")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.verify and args.verify_archive:
            raise EvidenceError("choose only one verification mode")
        if args.verify:
            manifest = verify_directory(args.verify)
            print(f"offline directory verification passed: {manifest['file_count']} files")
            return 0
        if args.verify_archive:
            manifest = verify_archive(args.verify_archive)
            print(f"offline archive verification passed: {manifest['file_count']} files")
            return 0
        manifest, digest = build_evidence(args.policy, args.output, args.archive)
        print(
            f"wrote release evidence: {manifest['file_count']} files, {manifest['total_bytes']} bytes; "
            f"archive SHA-256 {digest}"
        )
        return 0
    except (EvidenceError, OSError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
