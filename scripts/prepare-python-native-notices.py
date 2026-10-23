#!/usr/bin/env python3
"""Prepare a v3 notice overlay from collected images and a verified source cache."""
import argparse
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile

from release_notices import NoticeError, absolute_file, safe, sha, validate_native_dependencies, validate_python


def prepare(base, collected, cache, output):
    if output.exists():
        raise NoticeError("output exists; retain it and choose a new directory")
    inventory_raw = (base / "inventory/manifest.json").read_bytes()
    inventory = json.loads(inventory_raw)
    source_paths, roots = {}, {}
    for path in sorted(cache.rglob("*")):
        if not path.is_file() or path.is_symlink() or not path.name.endswith((".crate", ".tar.gz", ".tar.xz")):
            continue
        if path.stat().st_size > 150 * 1024 * 1024:
            raise NoticeError("oversized source cache member")
        raw = path.read_bytes()
        source_paths[sha(raw)] = path
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tar:
            top = {PurePosixPath(m.name).parts[0] for m in tar.getmembers() if m.name}
            if len(top) == 1:
                roots.setdefault(next(iter(top)), []).append(path)
    output.mkdir(parents=True)
    records = {}
    for image in ("mcp", "notary"):
        directory = collected[image]
        record = json.loads((directory / ("python-" + image + ".json")).read_bytes())
        if record["image_id"] != inventory["images"][image]["image_id"] or record["inventory_sha256"] != sha(inventory_raw):
            raise NoticeError("collected Python inventory/image differs")
        sbom_raw = (base / "inventory" / safe(inventory["images"][image]["sbom"])).read_bytes()
        if sha(sbom_raw) != inventory["images"][image]["sbom_sha256"]:
            raise NoticeError("base inventory SBOM differs")
        validate_python(image, record, json.loads(sbom_raw), lambda p: (directory / safe(p)).read_bytes(), require_native=True)
        records[image] = record
        shutil.copyfile(directory / ("python-" + image + ".json"), output / ("python-" + image + ".json"))
        shutil.copytree(directory / "files" / image, output / "files" / image)
    evidence = {"schema": "a4a-python-native-dependencies-v1", "inventory_sha256": sha(inventory_raw),
                "images": {k: inventory["images"][k]["image_id"] for k in records}, "components": [],
                "without_sbom": [], "complete_link_closure_proven": False,
                "complete_legal_acceptance": False, "release_approved": False}
    copied, extracted = {}, {}

    def copy_archive(path):
        digest = sha(path.read_bytes())
        target = "native-dependencies/sources/" + digest + ".tar"
        if digest not in copied:
            destination = output / target
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            copied[digest] = target
        return target

    def extract_notices(path):
        digest = sha(path.read_bytes())
        if digest not in extracted:
            notices = []
            with tarfile.open(path, mode="r:*") as tar:
                for member in tar.getmembers():
                    parts = PurePosixPath(member.name).parts
                    if not member.isfile():
                        continue
                    if not (re.match(r"^(licen[sc]e|copying|copyright|notice|unlicense|authors)([._-]|$)", parts[-1], re.I)
                            or any(p.lower() in ("licenses", "licences") for p in parts[1:-1])):
                        continue
                    safe(member.name)
                    if member.size > 4 * 1024 * 1024:
                        raise NoticeError("oversized native notice")
                    raw = tar.extractfile(member).read()
                    target = "native-dependencies/notices/" + digest + "/" + safe(member.name)
                    destination = output / target
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(raw)
                    notices.append({"path": target, "member": member.name})
            extracted[digest] = notices
        return extracted[digest]

    for image, record in records.items():
        for package in record["packages"]:
            if package["native_files"] and not package["sbom_files"]:
                evidence["without_sbom"].append({"image": image, "name": package["name"], "version": package["version"],
                                                "native_files": package["native_files"], "state": "requires-file-level-review"})
            for sbom_path in package["sbom_files"]:
                raw = (output / absolute_file(image, sbom_path)).read_bytes()
                for component in json.loads(raw)["components"]:
                    item = {"image": image, "sbom": sbom_path, "sbom_sha256": sha(raw), "purl": component["purl"],
                            "name": component["name"], "version": component["version"], "licenses": component.get("licenses", [])}
                    if "download_url=file:" in component["purl"]:
                        item["distribution_notices"] = package["license_files"]
                    else:
                        checksums = [v["content"] for v in component.get("hashes", []) if v["alg"] == "SHA-256"]
                        if len(checksums) != 1 or checksums[0] not in source_paths:
                            raise NoticeError("missing exact source for nested component: " + component["purl"])
                        path = source_paths[checksums[0]]
                        item["source_archive"] = copy_archive(path)
                        item["notices"] = extract_notices(path)
                        if not item["notices"]:
                            with tarfile.open(path, mode="r:*") as tar:
                                info = json.loads(tar.extractfile(component["name"] + "-" + component["version"] + "/.cargo_vcs_info.json").read())
                            commit = info["git"]["sha1"]
                            matches = [p for root, paths in roots.items() if root.endswith("-" + commit) for p in paths]
                            if len(matches) != 1:
                                raise NoticeError("missing/ambiguous immutable repository notices: " + component["purl"])
                            repository = matches[0]
                            item["notice_repository"] = {"archive": copy_archive(repository), "sha256": sha(repository.read_bytes()), "commit": commit}
                            item["notices"] = extract_notices(repository)
                    evidence["components"].append(item)
    (output / "python-native-dependencies.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    materials = json.loads((base / "materials.json").read_bytes())
    materials["schema"] = "a4a-release-notice-materials-v3"
    (output / "materials.json").write_text(json.dumps(materials, indent=2) + "\n", encoding="utf-8")
    reader = lambda p: (output / safe(p)).read_bytes() if (output / safe(p)).is_file() else (base / safe(p)).read_bytes()
    coverage = validate_native_dependencies(records, inventory, inventory_raw, reader)
    (output / "native-coverage.json").write_text(json.dumps(coverage, indent=2) + "\n", encoding="utf-8")
    return coverage


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--materials", required=True, type=Path, help="Retained base materials; never modified")
    parser.add_argument("--mcp", required=True, type=Path, help="Fresh collector output")
    parser.add_argument("--notary", required=True, type=Path, help="Fresh collector output")
    parser.add_argument("--source-cache", required=True, type=Path, help="Archives; exact SBOM hashes are required")
    parser.add_argument("--output", required=True, type=Path, help="New overlay directory")
    args = parser.parse_args()
    result = prepare(args.materials, {"mcp": args.mcp, "notary": args.notary}, args.source_cache, args.output)
    print(json.dumps({k: v for k, v in result.items() if k != "without_sbom"} |
                     {"without_sbom_packages": len(result["without_sbom"]), "complete_legal_acceptance": False}))


if __name__ == "__main__":
    if sys.flags.optimize:
        raise SystemExit("Run without -O")
    main()
