#!/usr/bin/env python3
"""Generate an artifact-bound release inventory without publishing anything.

The final relay image contains a statically linked Rust binary. Image scanners can see
the Debian packages around it but older scanners do not recover its Cargo dependency
graph. This command therefore records two independently checkable views:

* SPDX 2.2 SBOMs of every retained layer of each final image;
* target-filtered ``cargo metadata --locked --offline`` from the exact relay builder.

Python wheels are inspected directly. The command writes into a temporary sibling and
only replaces the requested output after every input and generated document validates.
"""

from __future__ import annotations

import argparse
from email.parser import BytesParser
from email.policy import default
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import tarfile
from typing import Any
import zipfile
import uuid


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGES = {
    "relay": "a4a-relay:release-check",
    "mcp": "a4a-mcp:release-check",
    "notary": "a4a-notary:release-check",
}
EXPECTED_WHEELS = {"a4a-mcp", "a4a-notary", "a4a-project-agent", "a4a-sdk"}
EXPECTED_IMAGE_PACKAGES = {
    "mcp": {"a4a-mcp", "a4a-sdk"},
    "notary": {"a4a-notary", "a4a-sdk", "opentimestamps"},
    # cargo metadata validates the statically linked application and its Rust graph.
    "relay": set(),
}
LINUX_TARGET = "x86_64-unknown-linux-gnu"
LICENSE_REVIEW_PATH = ROOT / "scripts" / "release-license-review.json"


class InventoryError(RuntimeError):
    """An input is absent, ambiguous, or cannot support a complete inventory."""


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def run(command: list[str], *, cwd: Path = ROOT) -> bytes:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        timeout=300,
    )
    if result.returncode:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        detail = stderr or stdout or f"exit code {result.returncode}"
        raise InventoryError(f"command failed: {command!r}: {detail}")
    return result.stdout


def parse_json(raw: bytes, *, source: str) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"{source} did not produce valid UTF-8 JSON: {exc}") from exc


def docker_command(arguments: list[str], *, context: str | None = None) -> list[str]:
    if context is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", context):
        raise InventoryError("Docker context must be an explicit nonempty context name")
    return ["docker", *(["--context", context] if context is not None else []), *arguments]


def load_public_source_verifier():
    path = ROOT / "scripts/build-public-source-archive.py"
    spec = importlib.util.spec_from_file_location("inventory_public_source", path)
    if spec is None or spec.loader is None:
        raise InventoryError("cannot load the public source verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verified_public_source(path: Path | None, *, expected_commit: str | None = None) -> dict:
    if path is None:
        raise InventoryError("requires a verified public source export, never the private worktree")
    verifier = load_public_source_verifier()
    try:
        record = verifier.verify_directory(path.resolve())
    except (verifier.PublicSourceError, OSError) as error:
        raise InventoryError(f"invalid public source export: {error}") from error
    if expected_commit is not None and record["git_commit"] != expected_commit:
        raise InventoryError("public source export targets a different Git commit")
    return record


def image_sbom(reference: str, *, docker_context: str | None = None) -> bytes:
    return run(docker_command(["sbom", reference, "--layers", "all", "--format", "spdx-json", "--quiet"],
                              context=docker_context))


def image_identity(reference: str, *, docker_context: str | None = None) -> dict[str, Any]:
    data = parse_json(
        run(docker_command(["image", "inspect", reference], context=docker_context)),
        source=f"docker inspect {reference}",
    )
    if not isinstance(data, list) or len(data) != 1:
        count = len(data) if isinstance(data, list) else "an invalid"
        raise InventoryError(
            f"docker inspect returned {count} records for {reference}"
        )
    image = data[0]
    image_id = image.get("Id")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise InventoryError(f"image {reference} has no immutable sha256 identity")
    config = image.get("Config") or {}
    return {
        "reference": reference,
        "image_id": image_id,
        "repo_digests": sorted(image.get("RepoDigests") or []),
        "runtime_user": config.get("User") or "root",
    }


def validate_spdx(
    document: Any, *, image: str, required_packages: set[str] | None = None,
) -> dict[str, int]:
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.2":
        raise InventoryError(f"{image} SBOM is not an SPDX 2.2 document")
    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        raise InventoryError(f"{image} SBOM contains no packages")
    missing_names = sum(not isinstance(item, dict) or not item.get("name") for item in packages)
    if missing_names:
        raise InventoryError(f"{image} SBOM has {missing_names} unnamed packages")
    names = {package["name"].lower().replace("_", "-") for package in packages}
    missing_required = sorted((required_packages or set()) - names)
    if missing_required:
        raise InventoryError(f"{image} SBOM misses required packages: {missing_required}")
    unknown_licenses = sum(
        package.get("licenseConcluded") in (None, "NOASSERTION")
        and package.get("licenseDeclared") in (None, "NOASSERTION")
        for package in packages
    )
    return {"package_count": len(packages), "unknown_license_count": unknown_licenses}


def normalized_package_name(value: str) -> str:
    return value.lower().replace("_", "-")


def unknown_spdx_packages(document: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """Return packages for which the scanner made no license assertion."""
    unknown: dict[tuple[str, str], dict[str, Any]] = {}
    for package in document["packages"]:
        if not (
            package.get("licenseConcluded") in (None, "NOASSERTION")
            and package.get("licenseDeclared") in (None, "NOASSERTION")
        ):
            continue
        name = package.get("name")
        version = package.get("versionInfo")
        if not isinstance(name, str) or not isinstance(version, str) or not version:
            raise InventoryError("NOASSERTION package lacks an exact name or version")
        key = (normalized_package_name(name), version)
        if key in unknown:
            raise InventoryError(f"duplicate NOASSERTION package in SBOM: {key}")
        unknown[key] = package
    return unknown


def load_license_review(path: Path = LICENSE_REVIEW_PATH) -> tuple[bytes, dict[str, dict]]:
    """Load and strictly expand artifact-specific reviews by image and package."""
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"invalid license review registry {path}: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema") != "a4a-license-review-v1":
        raise InventoryError("license review registry has an unsupported schema")
    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        raise InventoryError("license review registry contains no packages")

    expanded: dict[str, dict] = {name: {} for name in DEFAULT_IMAGES}
    sha_pattern = re.compile(r"[0-9a-f]{64}")
    for index, item in enumerate(packages):
        if not isinstance(item, dict):
            raise InventoryError(f"license review entry {index} is not an object")
        images = item.get("images")
        name = item.get("name")
        version = item.get("version")
        expression = item.get("license_expression")
        evidence_path = item.get("evidence_path")
        evidence_sha256 = item.get("evidence_sha256")
        source_url = item.get("source_url")
        notes = item.get("distribution_notes")
        if not isinstance(images, list) or not images or any(
            image not in DEFAULT_IMAGES for image in images
        ):
            raise InventoryError(f"license review entry {index} has invalid images")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise InventoryError(f"license review entry {index} lacks package identity")
        if not isinstance(expression, str) or not expression or "NOASSERTION" in expression:
            raise InventoryError(f"license review entry {index} has no license conclusion")
        if not isinstance(evidence_path, str) or not evidence_path.startswith("/"):
            raise InventoryError(f"license review entry {index} has no absolute evidence path")
        if ".." in PurePosixPath(evidence_path).parts:
            raise InventoryError(f"license review entry {index} has an unsafe evidence path")
        if not isinstance(evidence_sha256, str) or not sha_pattern.fullmatch(evidence_sha256):
            raise InventoryError(f"license review entry {index} has an invalid evidence hash")
        if not isinstance(source_url, str) or not source_url.startswith("https://"):
            raise InventoryError(f"license review entry {index} has no HTTPS source URL")
        if not isinstance(notes, list) or not notes or any(
            not isinstance(note, str) or not note for note in notes
        ):
            raise InventoryError(f"license review entry {index} has no distribution notes")

        key = (normalized_package_name(name), version)
        conclusion = {
            "name": name,
            "version": version,
            "license_expression": expression,
            "evidence_path": evidence_path,
            "evidence_sha256": evidence_sha256,
            "source_url": source_url,
            "distribution_notes": notes,
        }
        for image in images:
            if key in expanded[image]:
                raise InventoryError(f"duplicate license review for {image} {key}")
            expanded[image][key] = conclusion
    return raw, expanded


def verify_license_review(
    image: str,
    reference: str,
    document: dict[str, Any],
    reviews: dict[str, dict],
    *, docker_context: str | None = None,
) -> list[dict[str, Any]]:
    """Require an exact, artifact-hashed review for every scanner NOASSERTION."""
    unknown = unknown_spdx_packages(document)
    expected = reviews.get(image, {})
    missing = sorted(set(unknown) - set(expected))
    stale = sorted(set(expected) - set(unknown))
    if missing:
        raise InventoryError(f"{image} has unreviewed NOASSERTION packages: {missing}")
    if stale:
        raise InventoryError(f"{image} has stale license reviews: {stale}")

    verified = []
    for key in sorted(unknown):
        conclusion = expected[key]
        evidence = copy_image_file(reference, conclusion["evidence_path"], docker_context=docker_context)
        actual_sha256 = sha256_bytes(evidence)
        if actual_sha256 != conclusion["evidence_sha256"]:
            raise InventoryError(
                f"{image} license evidence changed for {key}: "
                f"expected {conclusion['evidence_sha256']}, got {actual_sha256}"
            )
        verified.append(dict(conclusion))
    return verified


def copy_image_file(reference: str, path: str, *, docker_context: str | None = None) -> bytes:
    """Read a bounded notice from a stopped carrier, without runtime utilities."""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", reference):
        raise InventoryError("notice carrier requires an immutable image ID")
    if not path.startswith("/") or ".." in PurePosixPath(path).parts or "\\" in path:
        raise InventoryError("unsafe notice carrier path")
    name = "a4a-inventory-notice-" + uuid.uuid4().hex
    run(docker_command(["create", "--name", name, "--pull", "never", "--network", "none",
                        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                        "--memory", "128m", "--cpus", "1", "--pids-limit", "64", reference], context=docker_context))
    # Retain the never-started carrier for diagnosis. No image process executes.
    raw = run(docker_command(["cp", "-L", name + ":" + path, "-"], context=docker_context))
    if len(raw) > 2 * 1024 * 1024:
        raise InventoryError("notice carrier archive exceeds the bound")
    try:
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            members = archive.getmembers()
            if (len(members) != 1 or not members[0].isfile() or members[0].size > 1024 * 1024
                    or PurePosixPath(members[0].name).name != PurePosixPath(path).name
                    or PurePosixPath(members[0].name).is_absolute() or ".." in PurePosixPath(members[0].name).parts):
                raise InventoryError("notice carrier did not return one bounded regular file")
            return archive.extractfile(members[0]).read()
    except tarfile.TarError as error:
        raise InventoryError("invalid notice carrier archive") from error


def wheel_inventory(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.suffix != ".whl":
        raise InventoryError(f"wheel does not exist: {path}")
    raw = path.read_bytes()
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_paths = [
                name for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_paths) != 1:
                raise InventoryError(f"wheel {path.name} has {len(metadata_paths)} METADATA files")
            metadata = BytesParser(policy=default).parsebytes(archive.read(metadata_paths[0]))
            license_files = sorted(
                name for name in archive.namelist()
                if ".dist-info/licenses/" in name
            )
    except zipfile.BadZipFile as exc:
        raise InventoryError(f"invalid wheel: {path}") from exc

    name = metadata.get("Name")
    version = metadata.get("Version")
    if not name or not version:
        raise InventoryError(f"wheel {path.name} has incomplete package identity")
    license_value = metadata.get("License-Expression") or metadata.get("License")
    if not license_value:
        raise InventoryError(f"wheel {path.name} has no license metadata")
    if not license_files:
        raise InventoryError(f"wheel {path.name} carries no license file")
    return {
        "filename": path.name,
        "name": name,
        "version": version,
        "sha256": sha256_bytes(raw),
        "size": len(raw),
        "license": license_value,
        "license_files": license_files,
        "requires_dist": sorted(metadata.get_all("Requires-Dist") or []),
        "requires_python": metadata.get("Requires-Python"),
    }


def validate_wheels(paths: list[Path]) -> list[dict[str, Any]]:
    wheels = sorted((wheel_inventory(path) for path in paths), key=lambda item: item["name"])
    names = {item["name"].lower().replace("_", "-") for item in wheels}
    if names != EXPECTED_WHEELS or len(wheels) != len(EXPECTED_WHEELS):
        missing = sorted(EXPECTED_WHEELS - names)
        extra = sorted(names - EXPECTED_WHEELS)
        raise InventoryError(f"wheel set mismatch; missing={missing}, extra={extra}")
    return wheels


def relay_cargo_metadata(
    builder_image: str, *, public_source: Path | None = None, docker_context: str | None = None,
) -> dict[str, Any]:
    verified_public_source(public_source)
    assert public_source is not None
    command = docker_command([
        "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m", "--cpus", "2",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m,mode=1777",
        "--env", "CARGO_TARGET_DIR=/tmp/target",
        "--mount", f"type=bind,source={public_source.resolve()},target=/src,readonly",
        "--workdir", "/src/relay", builder_image,
        "cargo", "metadata", "--locked", "--offline", "--format-version", "1",
        "--filter-platform", LINUX_TARGET,
    ], context=docker_context)
    data = parse_json(run(command), source="target-filtered cargo metadata")
    packages = data.get("packages") if isinstance(data, dict) else None
    nodes = (data.get("resolve") or {}).get("nodes") if isinstance(data, dict) else None
    if not isinstance(packages, list) or not packages or not isinstance(nodes, list):
        raise InventoryError("cargo metadata omitted packages or the resolved graph")
    package_ids = {package.get("id") for package in packages}
    node_ids = {node.get("id") for node in nodes}
    if None in package_ids or package_ids != node_ids:
        raise InventoryError("cargo package set does not match the resolved Linux graph")
    missing_license = sorted(
        package.get("name", "<unnamed>")
        for package in packages
        if not package.get("license")
    )
    if missing_license:
        raise InventoryError(f"Rust packages without license expressions: {missing_license}")
    roots = [package for package in packages if package.get("name") == "nostr-rs-relay"]
    if len(roots) != 1:
        raise InventoryError(f"expected one nostr-rs-relay root, found {len(roots)}")
    return data


def git_state(*, allow_dirty: bool) -> dict[str, Any]:
    head = run(["git", "rev-parse", "HEAD"]).decode("ascii").strip()
    status = run(["git", "status", "--porcelain=v1", "--untracked-files=all"]).decode(
        "utf-8", errors="replace"
    ).splitlines()
    if status and not allow_dirty:
        raise InventoryError(
            "working tree is dirty; commit the exact candidate or pass --allow-dirty "
            "for a diagnostic inventory that cannot serve as release evidence"
        )
    return {"commit": head, "dirty": bool(status), "changed_paths": status}


def write_inventory(
    output: Path,
    *,
    images: dict[str, str],
    wheels: list[Path],
    relay_builder_image: str,
    allow_dirty: bool = False,
    public_source: Path | None = None,
    docker_context: str | None = None,
) -> dict[str, Any]:
    resolved_output = output.resolve()
    build_root = (ROOT / "build").resolve()
    if resolved_output == build_root or build_root not in resolved_output.parents:
        raise InventoryError(f"output must be a child of {build_root}")
    if output.exists() or output.is_symlink():
        raise InventoryError(f"output already exists; preserve old evidence and choose a new path: {output}")
    if docker_context is None:
        raise InventoryError("requires an explicit Docker context for release inventory generation")
    if set(images) != set(DEFAULT_IMAGES):
        raise InventoryError("inventory requires exactly mcp, notary and relay images")
    docker_command([], context=docker_context)
    state = git_state(allow_dirty=allow_dirty)
    source_record = verified_public_source(public_source, expected_commit=state["commit"])
    output.parent.mkdir(parents=True, exist_ok=True)
    review_raw, reviews = load_license_review()

    with tempfile.TemporaryDirectory(prefix=f".{output.name}-", dir=output.parent) as temporary:
        staging = Path(temporary)
        manifest: dict[str, Any] = {
            "schema": "a4a-release-inventory-v1",
            "git": state,
            "docker_context": docker_context,
            "public_source": {key: source_record[key] for key in ("git_commit", "snapshot_id", "file_count")},
            "images": {},
            "wheels": validate_wheels(wheels),
            "relay_rust": {},
            "license_review": {
                "registry": str(LICENSE_REVIEW_PATH.relative_to(ROOT)).replace("\\", "/"),
                "registry_sha256": sha256_bytes(review_raw),
                "images": {},
            },
        }

        for name, reference in sorted(images.items()):
            identity = image_identity(reference, docker_context=docker_context)
            raw = image_sbom(identity["image_id"], docker_context=docker_context)
            document = parse_json(raw, source=f"docker sbom {reference}")
            summary = validate_spdx(
                document,
                image=reference,
                required_packages=EXPECTED_IMAGE_PACKAGES[name],
            )
            reviewed = verify_license_review(name, identity["image_id"], document, reviews,
                                             docker_context=docker_context)
            filename = f"{name}.spdx.json"
            content = canonical_json(document)
            (staging / filename).write_bytes(content)
            manifest["images"][name] = {
                **identity,
                **summary,
                "reviewed_unknown_license_count": len(reviewed),
                "unreviewed_unknown_license_count": summary["unknown_license_count"] - len(reviewed),
                "sbom": filename,
                "sbom_sha256": sha256_bytes(content),
                "sbom_scope": "all-layers",
            }
            manifest["license_review"]["images"][name] = reviewed

        builder_identity = image_identity(relay_builder_image, docker_context=docker_context)
        cargo = relay_cargo_metadata(builder_identity["image_id"], public_source=public_source,
                                    docker_context=docker_context)
        cargo_content = canonical_json(cargo)
        cargo_filename = "relay-cargo-metadata.json"
        (staging / cargo_filename).write_bytes(cargo_content)
        manifest["relay_rust"] = {
            "builder_image": builder_identity,
            "target": LINUX_TARGET,
            "package_count": len(cargo["packages"]),
            "resolved_node_count": len(cargo["resolve"]["nodes"]),
            "metadata": cargo_filename,
            "metadata_sha256": sha256_bytes(cargo_content),
        }

        manifest_content = canonical_json(manifest)
        (staging / "manifest.json").write_bytes(manifest_content)
        if git_state(allow_dirty=allow_dirty) != state or verified_public_source(
            public_source, expected_commit=state["commit"]
        ) != source_record:
            raise InventoryError("Git or public source changed during inventory generation")
        for reference in [*images.values(), relay_builder_image]:
            expected = builder_identity if reference == relay_builder_image else next(
                item for item in manifest["images"].values() if item["reference"] == reference
            )
            if image_identity(reference, docker_context=docker_context)["image_id"] != expected["image_id"]:
                raise InventoryError(f"image reference changed during inventory generation: {reference}")
        if output.exists() or output.is_symlink():
            raise InventoryError("output appeared during inventory generation; refusing to replace it")
        Path(temporary).rename(output)
        return manifest


def image_arguments(values: list[str]) -> dict[str, str]:
    images = dict(DEFAULT_IMAGES)
    for value in values:
        if "=" not in value:
            raise InventoryError(f"--image expects NAME=REFERENCE, got {value!r}")
        name, reference = value.split("=", 1)
        if name not in DEFAULT_IMAGES or not reference:
            raise InventoryError(f"unknown or empty image assignment: {value!r}")
        images[name] = reference
    return images


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/release-inventory")
    parser.add_argument("--wheel", type=Path, action="append", required=True)
    parser.add_argument("--image", action="append", default=[], metavar="NAME=REFERENCE")
    parser.add_argument("--relay-builder-image", default="a4a-relay-sbom-builder:release-check")
    parser.add_argument("--public-source", type=Path, required=True, help="verified clean public export at HEAD")
    parser.add_argument("--docker-context", required=True, help="explicit local Docker context to inspect")
    parser.add_argument(
        "--allow-dirty", action="store_true",
        help="allow a diagnostic inventory and record every dirty path",
    )
    args = parser.parse_args(argv)
    try:
        manifest = write_inventory(
            args.output,
            images=image_arguments(args.image),
            wheels=args.wheel,
            relay_builder_image=args.relay_builder_image,
            allow_dirty=args.allow_dirty,
            public_source=args.public_source,
            docker_context=args.docker_context,
        )
    except InventoryError as exc:
        parser.exit(1, f"release inventory failed: {exc}\n")
    print(f"Release inventory: {args.output.resolve()}")
    print(f"Commit: {manifest['git']['commit']} (dirty={manifest['git']['dirty']})")
    print(f"Wheels: {len(manifest['wheels'])}")
    print(f"Images: {len(manifest['images'])}")
    reviewed = sum(
        image["reviewed_unknown_license_count"] for image in manifest["images"].values()
    )
    print(f"Scanner NOASSERTION packages reviewed: {reviewed}")
    print(f"Relay Rust packages: {manifest['relay_rust']['package_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
