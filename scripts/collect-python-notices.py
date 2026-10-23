#!/usr/bin/env python3
"""Collect Python licenses, RECORD-declared SBOMs and native hashes from an image."""
import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import sysconfig
import uuid


def collect_installed():
    """Read distribution files without importing application modules or writing."""
    files, packages = {}, []

    def add(path):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("missing or linked distribution evidence: " + str(path))
        raw = path.read_bytes()
        if len(raw) > 4 * 1024 * 1024:
            raise RuntimeError("oversized Python notice/metadata")
        files[path.as_posix()] = {"path": path.as_posix(), "size": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "base64": base64.b64encode(raw).decode()}

    for dist in importlib.metadata.distributions():
        metadata, notices, sboms, native = set(), set(), set(), []
        for entry in dist.files or []:
            path = Path(dist.locate_file(entry))
            # RECORD also lists launchers outside site-packages. Only paths
            # selected as evidence below are exported; never follow links.
            if path.is_symlink():
                raise RuntimeError("linked distribution file: " + str(path))
            if not path.is_file():
                if str(entry).endswith("/RECORD"):
                    raise RuntimeError("missing installed RECORD")
                continue
            value = path.as_posix()
            if path.name in ("METADATA", "RECORD", "WHEEL") and ".dist-info/" in value:
                add(path)
                metadata.add(value)
            elif ".dist-info/sboms/" in value:
                add(path)
                sboms.add(value)
            elif (re.match(r"^(?:licen[sc]e|copying|copyright|notice|unlicense)(?:$|[._-])", path.name, re.I)
                  or "/licenses/" in value):
                add(path)
                notices.add(value)
            with path.open("rb") as handle:
                magic = handle.read(4)
            if magic == b"\x7fELF":
                with path.open("rb") as handle:
                    digest = hashlib.file_digest(handle, "sha256").hexdigest()
                native.append({"path": value, "size": path.stat().st_size, "sha256": digest})
        parents = [Path(p).parent for p in metadata if p.endswith("/METADATA")]
        if len(parents) != 1 or not any(p.endswith("/RECORD") for p in metadata):
            raise RuntimeError("distribution lacks unambiguous METADATA/RECORD")
        for declared in dist.metadata.get_all("License-File", []):
            relative = PurePosixPath(declared)
            if relative.is_absolute() or ".." in relative.parts or "\\" in declared:
                raise RuntimeError("unsafe License-File")
            candidates = [parents[0] / declared, parents[0] / "licenses" / declared]
            found = [p for p in candidates if p.is_file()]
            if not found:
                raise RuntimeError("declared Python license is missing")
            for path in found:
                add(path)
                notices.add(path.as_posix())
        packages.append({"name": dist.metadata["Name"], "version": dist.version,
                         "license_expression": dist.metadata.get("License-Expression"),
                         "license_metadata": dist.metadata.get("License"),
                         "license_files": sorted(notices), "metadata_files": sorted(metadata),
                         "sbom_files": sorted(sboms), "native_files": sorted(native, key=lambda v: v["path"])})
    stdlib = Path(sysconfig.get_path("stdlib")) / "LICENSE.txt"
    add(stdlib)
    for path in sorted(Path("/app/licenses").glob("*")):
        if path.is_file():
            add(path)
    return {"schema": "a4a-python-notices-v2", "packages": packages,
            "python_version": sys.version, "stdlib_license": stdlib.as_posix(),
            "stdlib_license_present": True, "files": sorted(files.values(), key=lambda v: v["path"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--probe", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--image", choices=("mcp", "notary"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--docker-context", default="desktop-linux")
    args = parser.parse_args()
    if args.probe:
        if sys.platform != "linux":
            raise RuntimeError("the image probe requires Linux")
        print(json.dumps(collect_installed()))
        return
    if not args.inventory or not args.image or not args.output:
        parser.error("--inventory, --image and --output are required")
    if args.output.exists():
        parser.error("output already exists; retain it and choose a new directory")
    inventory_raw = args.inventory.read_bytes()
    inventory = json.loads(inventory_raw)
    image = inventory["images"][args.image]["image_id"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        parser.error("inventory must select an immutable image ID")
    name = "a4a-python-notices-" + uuid.uuid4().hex
    command = ["docker", "--context", args.docker_context, "run", "--pull", "never", "--name", name,
               "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--pids-limit", "64", "--memory", "384m", "-i", "--entrypoint", "python", image, "-B", "-", "--probe"]
    result = subprocess.run(command, input=Path(__file__).read_bytes(), capture_output=True, timeout=120)
    inspect_raw = subprocess.check_output(["docker", "--context", args.docker_context, "inspect", name], timeout=30)
    inspected = json.loads(inspect_raw)[0]
    args.output.mkdir(parents=True)
    (args.output / "collector-command.json").write_text(json.dumps(command, indent=2) + "\n", encoding="utf-8")
    (args.output / "collector-inspect.json").write_bytes(inspect_raw)
    (args.output / "collector-stderr.txt").write_bytes(result.stderr)
    if (result.returncode or inspected["State"]["Running"] or inspected["State"]["ExitCode"]
            or inspected["Config"]["Image"] != image):
        raise RuntimeError("image collection failed; diagnostics and stopped container retained: " + name)
    record = json.loads(result.stdout)
    for item in record["files"]:
        value = item["path"]
        path = PurePosixPath(value)
        if not path.is_absolute() or ".." in path.parts or "\\" in value:
            raise RuntimeError("unsafe collected path")
        raw = base64.b64decode(item.pop("base64"), validate=True)
        if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise RuntimeError("collected file differs")
        target = args.output / "files" / args.image / Path(*path.parts[1:])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    record.update(image_id=image, inventory_sha256=hashlib.sha256(inventory_raw).hexdigest())
    from release_notices import validate_python
    sbom_raw = (args.inventory.parent / inventory["images"][args.image]["sbom"]).read_bytes()
    if hashlib.sha256(sbom_raw).hexdigest() != inventory["images"][args.image]["sbom_sha256"]:
        raise RuntimeError("inventory SBOM differs")
    validate_python(args.image, record, json.loads(sbom_raw), lambda p: (args.output / p).read_bytes(), require_native=True)
    (args.output / ("python-" + args.image + ".json")).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"image": args.image, "packages": len(record["packages"]),
                      "sboms": sum(len(p["sbom_files"]) for p in record["packages"]),
                      "native_files": sum(len(p["native_files"]) for p in record["packages"]),
                      "container_retained": name, "complete_legal_acceptance": False}))


if __name__ == "__main__":
    if sys.flags.optimize:
        raise SystemExit("Run without -O")
    main()
