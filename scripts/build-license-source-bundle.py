#!/usr/bin/env python3
"""Build and verify the release images' corresponding-source bundle.

The bundle is a local release artifact. Building it does not publish, upload, or
authorize distribution of anything. The registry is intentionally exact and fails
closed when the artifact-bound license review gains, loses, or changes a copyleft
package. Verification reads only the completed bundle and needs no network access.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any
import urllib.error
import urllib.request
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent.parent
BUILD_ROOT = ROOT / "build"
DEFAULT_DEFINITION = ROOT / "scripts" / "release-source-bundle.json"
DEFAULT_LICENSE_REVIEW = ROOT / "scripts" / "release-license-review.json"
DEFAULT_INVENTORY = BUILD_ROOT / "release-inventory" / "manifest.json"
DEFAULT_OUTPUT = BUILD_ROOT / "license-source-bundle"
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class SourceBundleError(RuntimeError):
    """A source input is incomplete, stale, unsafe, or corrupt."""


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


def read_json(path: Path, *, label: str) -> tuple[bytes, Any]:
    try:
        raw = path.read_bytes()
        return raw, json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceBundleError(f"invalid {label} {path}: {exc}") from exc


def normalized_name(value: str) -> str:
    return value.lower().replace("_", "-")


def coverage_key(item: dict[str, Any]) -> tuple[str, str, str]:
    image = item.get("image")
    name = item.get("name")
    version = item.get("version")
    if not all(isinstance(value, str) and value for value in (image, name, version)):
        raise SourceBundleError(f"invalid coverage identity: {item!r}")
    return image, normalized_name(name), version


def copyleft_coverage(review: Any) -> tuple[set[tuple[str, str, str]], dict[tuple[str, str, str], dict[str, Any]]]:
    if not isinstance(review, dict) or review.get("schema") != "a4a-license-review-v1":
        raise SourceBundleError("license review has an unsupported schema")
    packages = review.get("packages")
    if not isinstance(packages, list) or not packages:
        raise SourceBundleError("license review contains no packages")
    required: set[tuple[str, str, str]] = set()
    details: dict[tuple[str, str, str], dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise SourceBundleError("license review package is not an object")
        expression = package.get("license_expression")
        images = package.get("images")
        if not isinstance(expression, str) or not isinstance(images, list):
            raise SourceBundleError("license review package lacks license expression or images")
        if "GPL-" not in expression:
            continue
        for image in images:
            identity = coverage_key({
                "image": image,
                "name": package.get("name"),
                "version": package.get("version"),
            })
            if identity in required:
                raise SourceBundleError(f"duplicate copyleft review identity: {identity}")
            required.add(identity)
            details[identity] = package
    if not required:
        raise SourceBundleError("license review contains no copyleft packages")
    return required, details


def validate_definition(definition: Any, required: set[tuple[str, str, str]]) -> list[dict[str, Any]]:
    if not isinstance(definition, dict) or definition.get("schema") != "a4a-release-source-bundle-v1":
        raise SourceBundleError("source bundle definition has an unsupported schema")
    groups = definition.get("groups")
    if not isinstance(groups, list) or not groups:
        raise SourceBundleError("source bundle definition contains no groups")

    covered: set[tuple[str, str, str]] = set()
    inventory_bound: set[tuple[str, str, str]] = set()
    filenames: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, group in enumerate(groups):
        if not isinstance(group, dict):
            raise SourceBundleError(f"source group {index} is not an object")
        component = group.get("component")
        source_version = group.get("source_version")
        notes = group.get("notes")
        covers = group.get("covers")
        artifacts = group.get("artifacts")
        if not all(isinstance(value, str) and value for value in (component, source_version, notes)):
            raise SourceBundleError(f"source group {index} lacks descriptive metadata")
        if not isinstance(covers, list) or not covers:
            raise SourceBundleError(f"source group {index} has no coverage")
        if not isinstance(artifacts, list) or not artifacts:
            raise SourceBundleError(f"source group {index} has no artifacts")

        group_coverage = []
        for item in covers:
            if not isinstance(item, dict):
                raise SourceBundleError(f"source group {index} has invalid coverage")
            identity = coverage_key(item)
            if identity in covered:
                raise SourceBundleError(f"duplicate source coverage: {identity}")
            covered.add(identity)
            group_coverage.append({"image": identity[0], "name": identity[1], "version": identity[2]})

        group_artifacts = []
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise SourceBundleError(f"source group {index} has invalid artifact metadata")
            filename = artifact.get("filename")
            url = artifact.get("url")
            digest = artifact.get("sha256")
            size = artifact.get("size")
            if not isinstance(filename, str) or not filename or Path(filename).name != filename:
                raise SourceBundleError(f"unsafe source filename: {filename!r}")
            if filename in filenames:
                raise SourceBundleError(f"duplicate source filename: {filename}")
            filenames.add(filename)
            if not isinstance(url, str) or not url.startswith("https://"):
                raise SourceBundleError(f"source artifact has no HTTPS URL: {filename}")
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                raise SourceBundleError(f"source artifact has invalid SHA-256: {filename}")
            if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
                raise SourceBundleError(f"source artifact has invalid size: {filename}")
            group_artifacts.append({
                "filename": filename,
                "url": url,
                "sha256": digest,
                "size": size,
            })
        validated.append({
            "component": component,
            "source_version": source_version,
            "notes": notes,
            "covers": sorted(group_coverage, key=lambda item: (item["image"], item["name"], item["version"])),
            "artifacts": group_artifacts,
        })

        if "inventory_bindings" in group:
            bindings = group["inventory_bindings"]
            if not isinstance(bindings, list) or not bindings:
                raise SourceBundleError("inventory bindings must be nonempty")
            bound = set()
            checked = []
            for binding in bindings:
                if not isinstance(binding, dict):
                    raise SourceBundleError("invalid inventory binding")
                identity = coverage_key(binding)
                if identity in bound:
                    raise SourceBundleError("duplicate inventory binding")
                if identity in required:
                    raise SourceBundleError("inventory binding overlaps a required unknown-license review")
                bound.add(identity)
                if not all(isinstance(binding.get(field), str) and binding[field]
                           for field in ("image_id", "sbom_sha256", "sbom_license", "purl", "notice_path", "notice_sha256", "review_scope")):
                    raise SourceBundleError("incomplete inventory binding")
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", binding["image_id"]) or not all(
                    SHA256_RE.fullmatch(binding[field]) for field in ("sbom_sha256", "notice_sha256")
                ):
                    raise SourceBundleError("invalid inventory binding hash")
                if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", identity[0]) or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", identity[1]):
                    raise SourceBundleError("unsafe inventory binding identity")
                notice_path = PurePosixPath(binding["notice_path"])
                if (not binding["notice_path"].startswith("/usr/share/doc/") or ".." in notice_path.parts
                        or "\\" in binding["notice_path"] or notice_path.name != "copyright"):
                    raise SourceBundleError("unsafe installed notice path")
                size = binding.get("notice_size")
                if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
                    raise SourceBundleError("invalid installed notice size")
                if binding["sbom_license"] in {"NOASSERTION", "NONE"} or "GPL-" not in binding["sbom_license"]:
                    raise SourceBundleError("inventory binding needs a known copyleft expression")
                checked.append({**binding, "image": identity[0], "name": identity[1], "version": identity[2]})
            if bound != {coverage_key(item) for item in group_coverage}:
                raise SourceBundleError("inventory bindings differ from group coverage")
            inventory_bound.update(bound)
            validated[-1]["inventory_bindings"] = checked

    missing = sorted(required - covered)
    stale = sorted(covered - (required | inventory_bound))
    if missing:
        raise SourceBundleError(f"copyleft packages lack source coverage: {missing}")
    if stale:
        raise SourceBundleError(f"source definition has stale coverage: {stale}")
    return validated


def validate_inventory_bindings(groups: list[dict[str, Any]], inventory: Any,
                                sboms: dict[str, bytes]) -> None:
    if not isinstance(inventory, dict) or inventory.get("git", {}).get("dirty") is not False:
        raise SourceBundleError("inventory bindings need a clean recorded inventory")
    for group in groups:
        for binding in group.get("inventory_bindings", []):
            image = inventory.get("images", {}).get(binding["image"])
            raw = sboms.get(binding["image"])
            if not isinstance(image, dict) or image.get("image_id") != binding["image_id"]:
                raise SourceBundleError("bound image ID differs from inventory")
            if raw is None or sha256_bytes(raw) != binding["sbom_sha256"] or image.get("sbom_sha256") != binding["sbom_sha256"]:
                raise SourceBundleError("bound SBOM differs from inventory")
            try:
                document = json.loads(raw)
                packages = document["packages"]
                candidates = [p for p in packages if normalized_name(p.get("name", "")) == binding["name"]
                              and p.get("versionInfo") == binding["version"]]
                if len(candidates) != 1 or candidates[0].get("licenseDeclared") != binding["sbom_license"]:
                    raise SourceBundleError("bound package identity/license is missing, ambiguous or changed")
                purls = [ref.get("referenceLocator") for ref in candidates[0].get("externalRefs", [])
                         if ref.get("referenceType") == "purl"]
                if purls != [binding["purl"]]:
                    raise SourceBundleError("bound package PURL differs")
                parsed = urlsplit(binding["purl"])
                expected_path = "deb/debian/" + binding["name"] + "@" + binding["version"]
                # PURL qualifiers are URI components, not HTML form data: Syft's
                # literal '+' in a Debian version must remain '+'. A source-name
                # qualifier omits the version when it equals the binary version.
                source_coordinate = [unquote(part.partition("=")[2])
                                     for part in parsed.query.split("&")
                                     if unquote(part.partition("=")[0]) == "upstream"]
                if not source_coordinate:
                    source_coordinate = [binding["name"] + "@" + binding["version"]]
                else:
                    source_coordinate = [value if "@" in value else value + "@" + binding["version"]
                                         for value in source_coordinate]
                if parsed.scheme != "pkg" or parsed.path != expected_path or source_coordinate != [group["component"] + "@" + group["source_version"]]:
                    raise SourceBundleError("bound binary-to-source coordinate differs")
            except (KeyError, TypeError, AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SourceBundleError("invalid bound SBOM") from exc


def bound_evidence_names(groups: list[dict[str, Any]]) -> set[str]:
    names = set()
    for group in groups:
        for binding in group.get("inventory_bindings", []):
            names.update({"inventory.json", binding["image"] + ".spdx.json",
                          "notices/" + binding["image"] + "/" + binding["name"] + ".copyright"})
    return names


def ordinary_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or any(parent.is_symlink() for parent in path.parents):
        raise SourceBundleError(f"evidence must be an ordinary file: {path}")
    if path.stat().st_size > 32 * 1024 * 1024:
        raise SourceBundleError("evidence file is oversized")
    return path.read_bytes()


def prepare_inventory_evidence(groups: list[dict[str, Any]], inventory: Any,
                               inventory_raw: bytes, inventory_dir: Path,
                               notice_root: Path | None, destination: Path) -> dict:
    expected = bound_evidence_names(groups)
    if not expected:
        return {}
    if notice_root is None:
        raise SourceBundleError("inventory-bound groups require --notice-root")
    contents = {"inventory.json": inventory_raw}
    sboms = {}
    for group in groups:
        for binding in group.get("inventory_bindings", []):
            image = binding["image"]
            filename = inventory.get("images", {}).get(image, {}).get("sbom")
            if not isinstance(filename, str) or PurePosixPath(filename).name != filename or "\\" in filename:
                raise SourceBundleError("unsafe bound SBOM filename")
            sboms[image] = ordinary_bytes(inventory_dir / filename)
            contents[image + ".spdx.json"] = sboms[image]
            notice = ordinary_bytes(notice_root / image / binding["notice_path"].lstrip("/"))
            if len(notice) != binding["notice_size"] or sha256_bytes(notice) != binding["notice_sha256"]:
                raise SourceBundleError("bound installed notice differs")
            contents["notices/" + image + "/" + binding["name"] + ".copyright"] = notice
    validate_inventory_bindings(groups, inventory, sboms)
    if set(contents) != expected:
        raise SourceBundleError("bound evidence set differs")
    for relative, raw in contents.items():
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return {name: {"sha256": sha256_bytes(raw), "size": len(raw)} for name, raw in contents.items()}


def verify_inventory_evidence(groups: list[dict[str, Any]], manifest: dict, bundle: Path) -> None:
    required = {coverage_key(item) for group in groups if "inventory_bindings" not in group
                for item in group.get("covers", [])}
    checked = validate_definition({"schema": "a4a-release-source-bundle-v1", "groups": groups}, required)
    expected = bound_evidence_names(checked)
    if not expected:
        if manifest.get("schema") != "a4a-corresponding-source-bundle-v1" or "inventory_evidence" in manifest:
            raise SourceBundleError("unexpected inventory evidence/schema")
        return
    if manifest.get("schema") != "a4a-corresponding-source-bundle-v2":
        raise SourceBundleError("inventory-bound groups require the v2 evidence schema")
    index = manifest.get("inventory_evidence")
    if not isinstance(index, dict) or set(index) != expected:
        raise SourceBundleError("inventory evidence index differs")
    directory = bundle / "inventory-evidence"
    expected_dirs = {str(parent) for name in expected for parent in PurePosixPath(name).parents
                     if str(parent) != "."}
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob("*")}
    if actual != expected | expected_dirs:
        raise SourceBundleError("inventory evidence file set differs")
    contents = {}
    for name, meta in index.items():
        raw = ordinary_bytes(directory / name)
        if not isinstance(meta, dict) or meta.get("size") != len(raw) or meta.get("sha256") != sha256_bytes(raw):
            raise SourceBundleError("inventory evidence bytes differ")
        contents[name] = raw
    try:
        inventory = json.loads(contents["inventory.json"])
        image_ids = {name: data["image_id"] for name, data in inventory["images"].items()}
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise SourceBundleError("invalid embedded inventory") from exc
    binding = manifest.get("release_inventory", {})
    if binding.get("sha256") != sha256_bytes(contents["inventory.json"]) or binding.get("images") != image_ids:
        raise SourceBundleError("embedded inventory differs from bundle binding")
    sboms = {item["image"]: contents[item["image"] + ".spdx.json"] for group in checked
             for item in group.get("inventory_bindings", [])}
    validate_inventory_bindings(checked, inventory, sboms)
    for group in checked:
        for item in group.get("inventory_bindings", []):
            notice = contents["notices/" + item["image"] + "/" + item["name"] + ".copyright"]
            if len(notice) != item["notice_size"] or sha256_bytes(notice) != item["notice_sha256"]:
                raise SourceBundleError("embedded notice differs from inventory binding")


def inventory_identities(inventory: Any) -> dict[tuple[str, str, str], dict[str, Any]]:
    if not isinstance(inventory, dict):
        raise SourceBundleError("release inventory manifest is not an object")
    git = inventory.get("git")
    if not isinstance(git, dict) or git.get("dirty") is not False:
        raise SourceBundleError("release inventory was not generated from a clean worktree")
    images = ((inventory.get("license_review") or {}).get("images"))
    if not isinstance(images, dict):
        raise SourceBundleError("release inventory has no artifact-bound license review")
    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    for image, packages in images.items():
        if not isinstance(image, str) or not isinstance(packages, list):
            raise SourceBundleError("release inventory has invalid reviewed packages")
        for package in packages:
            if not isinstance(package, dict):
                raise SourceBundleError("release inventory review entry is invalid")
            identity = coverage_key({"image": image, **package})
            if identity in result:
                raise SourceBundleError(f"duplicate inventory review identity: {identity}")
            result[identity] = package
    return result


def validate_inventory(
    inventory: Any,
    inventory_raw: bytes,
    review_raw: bytes,
    review_details: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    recorded_review_sha = ((inventory.get("license_review") or {}).get("registry_sha256"))
    actual_review_sha = sha256_bytes(review_raw)
    if recorded_review_sha != actual_review_sha:
        raise SourceBundleError(
            "release inventory is stale: its license-review hash does not match the current registry"
        )
    identities = inventory_identities(inventory)
    for identity, review in review_details.items():
        candidate = identities.get(identity)
        if candidate is None:
            raise SourceBundleError(f"release inventory lacks reviewed package {identity}")
        for field in ("license_expression", "evidence_path", "evidence_sha256"):
            if candidate.get(field) != review.get(field):
                raise SourceBundleError(f"release inventory review differs for {identity}: {field}")
    if not inventory_raw:
        raise SourceBundleError("release inventory manifest is empty")


def verify_file(path: Path, artifact: dict[str, Any]) -> None:
    if path.is_symlink() or not path.is_file():
        raise SourceBundleError(f"source artifact is missing: {path}")
    size = path.stat().st_size
    if size != artifact["size"]:
        raise SourceBundleError(
            f"source artifact size mismatch for {artifact['filename']}: expected {artifact['size']}, got {size}"
        )
    digest = sha256_file(path)
    if digest != artifact["sha256"]:
        raise SourceBundleError(
            f"source artifact hash mismatch for {artifact['filename']}: expected {artifact['sha256']}, got {digest}"
        )


def acquire_artifact(artifact: dict[str, Any], destination: Path, cache: Path | None) -> None:
    cached = cache / artifact["filename"] if cache is not None else None
    if cached is not None and cached.is_file():
        verify_file(cached, artifact)
        shutil.copyfile(cached, destination)
        return
    request = urllib.request.Request(
        artifact["url"],
        headers={"User-Agent": "A4A-release-source-bundle/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
            if not response.geturl().startswith("https://"):
                raise SourceBundleError(
                    f"source download redirected outside HTTPS: {response.geturl()}"
                )
            remaining = artifact["size"] + 1
            while remaining:
                chunk = response.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                output.write(chunk)
                remaining -= len(chunk)
            if remaining == 0:
                raise SourceBundleError(
                    f"source download exceeded the registered size: {artifact['filename']}"
                )
    except (OSError, urllib.error.URLError) as exc:
        raise SourceBundleError(f"could not download {artifact['url']}: {exc}") from exc
    verify_file(destination, artifact)


def dsc_checksums(path: Path) -> dict[str, tuple[str, int]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SourceBundleError(f"could not read Debian source control file {path}: {exc}") from exc
    match = re.search(r"^Checksums-Sha256:\s*\n((?: [^\n]+\n)+)", text, re.MULTILINE)
    if match is None:
        raise SourceBundleError(f"Debian source control file has no Checksums-Sha256: {path.name}")
    result: dict[str, tuple[str, int]] = {}
    for line in match.group(1).splitlines():
        parts = line.split()
        if len(parts) != 3 or not SHA256_RE.fullmatch(parts[0]):
            raise SourceBundleError(f"invalid Checksums-Sha256 line in {path.name}: {line!r}")
        filename = parts[2]
        if Path(filename).name != filename:
            raise SourceBundleError(f"unsafe filename in {path.name}: {filename!r}")
        try:
            size = int(parts[1])
        except ValueError as exc:
            raise SourceBundleError(f"invalid size in {path.name}: {parts[1]!r}") from exc
        if filename in result:
            raise SourceBundleError(f"duplicate source member in {path.name}: {filename}")
        result[filename] = (parts[0], size)
    return result


def verify_dsc_groups(groups: list[dict[str, Any]], sources: Path) -> None:
    for group in groups:
        dsc = [artifact for artifact in group["artifacts"] if artifact["filename"].endswith(".dsc")]
        if not dsc:
            if group.get("inventory_bindings"):
                raise SourceBundleError("inventory-bound Debian source group requires a .dsc")
            continue
        if len(dsc) != 1:
            raise SourceBundleError(f"source group {group['component']} must have exactly one .dsc")
        expected = {
            artifact["filename"]: (artifact["sha256"], artifact["size"])
            for artifact in group["artifacts"]
            if not artifact["filename"].endswith(".dsc")
        }
        recorded = dsc_checksums(sources / dsc[0]["filename"])
        if group.get("inventory_bindings"):
            text = (sources / dsc[0]["filename"]).read_text(encoding="utf-8")
            for field, value in (("Source", group["component"]), ("Version", group["source_version"])):
                if re.findall(r"^" + field + r": (.+)$", text, re.MULTILINE) != [value]:
                    raise SourceBundleError("Debian .dsc source coordinate differs from inventory binding")
        if recorded != expected:
            raise SourceBundleError(
                f"Debian .dsc members differ from the source definition for {group['component']} "
                f"{group['source_version']}: recorded={recorded!r}, expected={expected!r}"
            )


def git_state(*, allow_dirty: bool) -> dict[str, Any]:
    def run_git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments], cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        if result.returncode:
            raise SourceBundleError(result.stderr.strip() or f"git {arguments!r} failed")
        return result.stdout.rstrip("\r\n")

    commit = run_git("rev-parse", "HEAD").strip()
    changed_paths = sorted(line[3:] for line in run_git("status", "--porcelain").splitlines())
    if changed_paths and not allow_dirty:
        raise SourceBundleError(
            "refusing a release source bundle from a dirty worktree: " + ", ".join(changed_paths)
        )
    return {"commit": commit, "dirty": bool(changed_paths), "changed_paths": changed_paths}


def validate_output_path(output: Path) -> Path:
    resolved = output.resolve()
    build = BUILD_ROOT.resolve()
    if resolved == build or build not in resolved.parents:
        raise SourceBundleError(f"output must be a child of {build}: {resolved}")
    return resolved


def notice_text(groups: list[dict[str, Any]]) -> str:
    lines = [
        "# Corresponding source bundle",
        "",
        "This local artifact contains the exact source archives mapped to the GPL/LGPL",
        "components identified by the artifact-bound review of the A4A release images.",
        "Its presence is not legal advice and does not authorize publication or distribution.",
        "",
        "Run `python scripts/build-license-source-bundle.py --verify <bundle-directory>`",
        "to verify every file offline against `manifest.json`.",
        "",
    ]
    for group in groups:
        lines.extend([
            f"## {group['component']} — {group['source_version']}",
            "",
            group["notes"],
            "",
            "Covered installed packages:",
            "",
        ])
        lines.extend(
            f"- `{item['image']}:{item['name']}=={item['version']}`"
            for item in group["covers"]
        )
        lines.extend(["", "Source files:", ""])
        lines.extend(
            f"- `{item['filename']}` — SHA-256 `{item['sha256']}` — {item['size']} bytes — {item['url']}"
            for item in group["artifacts"]
        )
        lines.append("")
    return "\n".join(lines)


def quarantine_directory(path: Path, reason: str) -> Path:
    original = validate_output_path(path)
    trash = validate_output_path(BUILD_ROOT / ".trash" / "source-bundles")
    if trash == original or trash in original.parents:
        raise SourceBundleError("cannot quarantine a quarantine directory")
    trash.mkdir(parents=True, exist_ok=True)
    batch = Path(tempfile.mkdtemp(prefix="retained-", dir=trash))
    relative = original.relative_to(BUILD_ROOT.resolve())
    retained = batch / "files" / relative
    retained.parent.mkdir(parents=True, exist_ok=True)
    (batch / "QUARANTINE.md").write_text(
        f"# Retained generated release artifact\n\n"
        f"Original: {original}\nRetained: {retained}\n"
        f"Date (UTC): {datetime.now(timezone.utc).isoformat()}\n"
        f"Actor: A4A corresponding-source builder\nReason: {reason}\n\n"
        f"Restore: move the retained artifact to the original path after preserving "
        f"any current output. Keep for at least one month; no automatic deletion.\n",
        encoding="utf-8",
    )
    original.rename(retained)
    return retained


def replace_directory(staging: Path, output: Path) -> None:
    staging = validate_output_path(staging)
    output = validate_output_path(output)
    if staging == output or staging in output.parents or output in staging.parents:
        raise SourceBundleError("staging and output directories must be disjoint")
    backup = None
    moved_old = False
    try:
        if output.exists():
            backup = quarantine_directory(output, "replaced by a verified source bundle")
            moved_old = True
        staging.rename(output)
    except OSError:
        if moved_old and not output.exists():
            backup.rename(output)
        raise


def build_bundle(
    *,
    definition_path: Path,
    review_path: Path,
    inventory_path: Path,
    output: Path,
    cache: Path | None,
    allow_dirty: bool,
    notice_root: Path | None = None,
) -> dict[str, Any]:
    output = validate_output_path(output)
    definition_raw, definition = read_json(definition_path, label="source bundle definition")
    review_raw, review = read_json(review_path, label="license review")
    inventory_raw, inventory = read_json(inventory_path, label="release inventory")
    required, review_details = copyleft_coverage(review)
    groups = validate_definition(definition, required)
    validate_inventory(inventory, inventory_raw, review_raw, review_details)
    current_git = git_state(allow_dirty=allow_dirty)

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=output.name + ".", dir=output.parent))
    try:
        evidence = prepare_inventory_evidence(groups, inventory, inventory_raw, inventory_path.parent,
                                             notice_root, staging / "inventory-evidence")
        sources = staging / "sources"
        sources.mkdir()
        for group in groups:
            for artifact in group["artifacts"]:
                destination = sources / artifact["filename"]
                acquire_artifact(artifact, destination, cache)
                verify_file(destination, artifact)
        verify_dsc_groups(groups, sources)

        notice = notice_text(groups).encode("utf-8")
        (staging / "NOTICE.md").write_bytes(notice)
        manifest = {
            "schema": "a4a-corresponding-source-bundle-v2" if evidence else "a4a-corresponding-source-bundle-v1",
            "git": current_git,
            "release_inventory": {
                "path": inventory_path.resolve().relative_to(ROOT.resolve()).as_posix(),
                "sha256": sha256_bytes(inventory_raw),
                "git_commit": inventory["git"]["commit"],
                "images": {
                    name: data["image_id"]
                    for name, data in sorted(inventory["images"].items())
                },
            },
            "license_review": {
                "path": review_path.resolve().relative_to(ROOT.resolve()).as_posix(),
                "sha256": sha256_bytes(review_raw),
            },
            "definition": {
                "path": definition_path.resolve().relative_to(ROOT.resolve()).as_posix(),
                "sha256": sha256_bytes(definition_raw),
            },
            "notice_sha256": sha256_bytes(notice),
            "groups": groups,
            "artifact_count": sum(len(group["artifacts"]) for group in groups),
            "total_source_bytes": sum(
                artifact["size"] for group in groups for artifact in group["artifacts"]
            ),
        }
        if evidence:
            manifest["inventory_evidence"] = evidence
        (staging / "manifest.json").write_bytes(canonical_json(manifest))
        verify_bundle(staging)
        replace_directory(staging, output)
        return manifest
    except Exception:
        if staging.exists():
            quarantine_directory(staging, "source-bundle build failed; retained for diagnosis")
        raise


def verify_bundle(bundle: Path) -> dict[str, Any]:
    bundle = bundle.resolve()
    raw, manifest = read_json(bundle / "manifest.json", label="source bundle manifest")
    if not raw or not isinstance(manifest, dict) or manifest.get("schema") not in {"a4a-corresponding-source-bundle-v1", "a4a-corresponding-source-bundle-v2"}:
        raise SourceBundleError("source bundle manifest has an unsupported schema")
    notice = bundle / "NOTICE.md"
    if not notice.is_file() or sha256_file(notice) != manifest.get("notice_sha256"):
        raise SourceBundleError("source bundle NOTICE.md is missing or changed")
    groups = manifest.get("groups")
    if not isinstance(groups, list) or not groups:
        raise SourceBundleError("source bundle manifest contains no groups")
    expected_files: set[str] = set()
    artifact_count = 0
    total_bytes = 0
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("artifacts"), list):
            raise SourceBundleError("source bundle manifest has invalid group metadata")
        for artifact in group["artifacts"]:
            if not isinstance(artifact, dict):
                raise SourceBundleError("source bundle manifest has invalid artifact metadata")
            filename = artifact.get("filename")
            if not isinstance(filename, str) or Path(filename).name != filename or filename in expected_files:
                raise SourceBundleError(f"source bundle manifest has unsafe or duplicate filename: {filename!r}")
            if not isinstance(artifact.get("sha256"), str) or not SHA256_RE.fullmatch(artifact["sha256"]):
                raise SourceBundleError(f"source bundle manifest has invalid hash for {filename}")
            if not isinstance(artifact.get("size"), int) or artifact["size"] <= 0:
                raise SourceBundleError(f"source bundle manifest has invalid size for {filename}")
            expected_files.add(filename)
            artifact_count += 1
            total_bytes += artifact["size"]
            verify_file(bundle / "sources" / filename, artifact)
    sources = bundle / "sources"
    if sources.is_symlink() or not sources.is_dir():
        raise SourceBundleError("source bundle has no ordinary sources directory")
    actual_entries = {path.name for path in sources.iterdir()}
    if actual_entries != expected_files:
        raise SourceBundleError(
            f"source bundle file set differs from manifest: missing={sorted(expected_files - actual_entries)}, "
            f"unexpected={sorted(actual_entries - expected_files)}"
        )
    verify_dsc_groups(groups, sources)
    if manifest.get("artifact_count") != artifact_count:
        raise SourceBundleError("source bundle artifact count differs from manifest")
    if manifest.get("total_source_bytes") != total_bytes:
        raise SourceBundleError("source bundle byte count differs from manifest")
    verify_inventory_evidence(groups, manifest, bundle)
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--definition", type=Path, default=DEFAULT_DEFINITION)
    parser.add_argument("--license-review", type=Path, default=DEFAULT_LICENSE_REVIEW)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--cache", type=Path, help="optional local source archive cache")
    parser.add_argument("--notice-root", type=Path, help="installed notices under IMAGE/usr/share/doc/... for inventory-bound groups")
    parser.add_argument("--allow-dirty", action="store_true", help="create a diagnostic bundle from a dirty worktree")
    parser.add_argument("--verify", type=Path, help="verify an existing bundle without network access")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.verify is not None:
            manifest = verify_bundle(args.verify)
            print(
                f"offline verification passed: {manifest['artifact_count']} source artifacts, "
                f"{manifest['total_source_bytes']} bytes"
            )
            return 0
        manifest = build_bundle(
            definition_path=args.definition,
            review_path=args.license_review,
            inventory_path=args.inventory,
            output=args.output,
            cache=args.cache.resolve() if args.cache else None,
            allow_dirty=args.allow_dirty,
            notice_root=args.notice_root,
        )
        qualifier = "diagnostic dirty-worktree" if manifest["git"]["dirty"] else "release"
        print(
            f"wrote {qualifier} source bundle to {args.output}: "
            f"{manifest['artifact_count']} artifacts, {manifest['total_source_bytes']} bytes"
        )
        return 0
    except (SourceBundleError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
