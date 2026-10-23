"""Portable notice evidence; collection is distinct from legal acceptance."""

from email.parser import BytesParser
import base64
import csv
import hashlib
import gzip
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tomllib

SCHEMA = "a4a-release-notice-snapshot-v1"

def safe(value):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise NoticeError("unsafe notice path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise NoticeError("unsafe notice path")
    return value

def absolute_file(family, value):
    if not isinstance(value, str) or not value.startswith("/"):
        raise NoticeError("notice origin is not an absolute image path")
    return safe("files/" + family + "/" + value.lstrip("/"))

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def document(read, path):
    try:
        return json.loads(read(safe(path)))
    except (ValueError, TypeError, OSError) as exc:
        raise NoticeError("invalid notice document: " + path) from exc

def verified_record_files(family, record, read):
    seen = set()
    for item in record["files"]:
        path = absolute_file(family, item["path"])
        if path in seen:
            raise NoticeError("duplicate collected notice file")
        seen.add(path)
        raw = read(path)
        if len(raw) != item["size"] or sha(raw) != item["sha256"]:
            raise NoticeError("collected notice bytes differ")
    return seen

def normalized(value):
    return re.sub(r"[-_.]+", "-", value).lower()

class NoticeError(RuntimeError):
    pass

def validate_python(image, record, sbom, read, *, require_native=False):
    native = record.get("schema") == "a4a-python-notices-v2"
    if require_native and not native:
        raise NoticeError("new Python notice evidence requires native/SBOM coverage")
    known_files = verified_record_files(image, record, read)
    expected = {(normalized(p["name"]), p["versionInfo"]) for p in sbom["packages"]
                if any(r.get("referenceType") == "purl" and r.get("referenceLocator", "").startswith("pkg:pypi/") for r in p.get("externalRefs", []))}
    seen = set()
    for package in record["packages"]:
        key = normalized(package["name"]), package["version"]
        if key in seen:
            raise NoticeError("duplicate Python distribution")
        seen.add(key)
        paths = [p for p in package["metadata_files"] if p.endswith("/METADATA")]
        if len(paths) != 1 or absolute_file(image, paths[0]) not in known_files:
            raise NoticeError("Python metadata is missing or ambiguous")
        metadata = BytesParser().parsebytes(read(absolute_file(image, paths[0])))
        if (normalized(metadata.get("Name", "")), metadata.get("Version")) != key:
            raise NoticeError("Python package metadata identity differs")
        if metadata.get("License-Expression") != package.get("license_expression") or metadata.get("License") != package.get("license_metadata"):
            raise NoticeError("Python license declaration differs")
        notices = package["license_files"]
        if not notices or any(absolute_file(image, p) not in known_files for p in notices):
            raise NoticeError("Python package lacks collected notices")
        parent = PurePosixPath(paths[0]).parent
        for declared in metadata.get_all("License-File", []):
            safe(declared)
            candidates = {str(parent / declared), str(parent / "licenses" / declared)}
            if not candidates.intersection(notices):
                raise NoticeError("declared Python license file is missing")
        if native:
            validate_python_record(image, package, parent, known_files, read)
    if seen != expected:
        raise NoticeError("Python notice identities differ from the exact SBOM")
    return len(seen)


def validate_python_record(image, package, parent, known_files, read):
    """Derive nested SBOM coverage from installed RECORD, not a declared count."""
    path = str(parent / "RECORD")
    if path not in package["metadata_files"] or absolute_file(image, path) not in known_files:
        raise NoticeError("Python native evidence lacks RECORD")
    entries = {}
    for row in csv.reader(io.StringIO(read(absolute_file(image, path)).decode())):
        if len(row) != 3 or row[0] in entries:
            raise NoticeError("invalid/duplicate Python RECORD entry")
        entries[row[0]] = row[1:]
    prefix = parent.name + "/sboms/"
    expected_sboms = {str(parent.parent / safe(p)) for p in entries if p.startswith(prefix)}
    sboms = package["sbom_files"]
    if len(sboms) != len(set(sboms)) or set(sboms) != expected_sboms:
        raise NoticeError("nested Python SBOM coverage differs from RECORD")
    native = package["native_files"]
    paths = [p["path"] for p in native]
    if len(paths) != len(set(paths)):
        raise NoticeError("duplicate Python native file")
    expected_libraries = {str(parent.parent / safe(p)) for p in entries
                          if re.search(r"\.so(?:\.[A-Za-z0-9_.-]+)?$", p)}
    if not expected_libraries.issubset(paths):
        raise NoticeError("Python shared library coverage differs from RECORD")
    for value in sboms + paths:
        absolute_file(image, value)
        try:
            relative = PurePosixPath(value).relative_to(parent.parent).as_posix()
        except ValueError as exc:
            raise NoticeError("native/SBOM path escapes distribution root") from exc
        if relative not in entries:
            raise NoticeError("native/SBOM file is absent from RECORD")
        digest, size = entries[relative]
        if value in sboms:
            if absolute_file(image, value) not in known_files:
                raise NoticeError("nested Python SBOM bytes are missing")
            raw = read(absolute_file(image, value))
            actual_hash, actual_size = sha(raw), len(raw)
            body = json.loads(raw)
            if body.get("bomFormat") != "CycloneDX" or not isinstance(body.get("components"), list):
                raise NoticeError("unsupported nested Python SBOM")
        else:
            item = next(v for v in native if v["path"] == value)
            actual_hash, actual_size = item["sha256"], item["size"]
        encoded = base64.urlsafe_b64encode(bytes.fromhex(actual_hash)).rstrip(b"=").decode()
        if digest != "sha256=" + encoded or size != str(actual_size):
            raise NoticeError("native/SBOM bytes differ from installed RECORD")

def index_materials(root):
    if root.is_symlink() or not root.is_dir():
        raise NoticeError("notice materials must be an ordinary directory")
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise NoticeError("notice materials contain a link or special file")
        if path.is_file():
            if path == root / "manifest.json":
                raise NoticeError("materials contain the reserved snapshot manifest")
            raw = path.read_bytes()
            if len(raw) > 150 * 1024 * 1024:
                raise NoticeError("notice material is oversized")
            files.append({"path": safe(path.relative_to(root).as_posix()), "sha256": sha(raw), "size": len(raw)})
    if not files:
        raise NoticeError("notice materials are empty")
    return files

def validate_rust(record, metadata, supplement, materials, read):
    known = verified_record_files("rust", record, read)
    known.update(verified_record_files("rust", supplement, read))
    key = lambda p: (p["name"], p["version"], p.get("source"))
    expected = {key(p): p for p in metadata["packages"]}
    seen = set()
    lock = tomllib.loads(read("files/rust/nostr-rs-relay/Cargo.lock").decode())["package"]
    fallback = {(p["name"], p["version"]): p for p in materials["fallback"]}
    supplemented = {(p["name"], p["version"]): p for p in supplement["packages"]}
    upstream = {(p["name"], p["version"]): p for p in document(read, "upstream-notices.json")["packages"]}
    pending = []
    fallback_used = set()
    for package in record["packages"]:
        identity = key(package)
        if identity in seen or identity not in expected:
            raise NoticeError("Rust package is duplicate or absent from metadata")
        seen.add(identity)
        original = expected[identity]
        if package["license"] != original.get("license") or package["manifest_path"] != original["manifest_path"]:
            raise NoticeError("Rust declaration differs from retained metadata")
        pair = identity[:2]
        actual_manifest = package["manifest_path"]
        if package.get("missing"):
            if package.get("source") is not None or pair not in supplemented:
                raise NoticeError("Rust manifest is missing")
            actual_manifest = supplemented[pair]["manifest_path"]
        parsed = tomllib.loads(read(absolute_file("rust", actual_manifest)).decode())["package"]
        if (parsed["name"], parsed["version"], parsed.get("license")) != (identity[0], identity[1], package["license"]):
            raise NoticeError("actual Cargo.toml identity/license differs")
        if package["license_files"]:
            if any(absolute_file("rust", p) not in known for p in package["license_files"]):
                raise NoticeError("Rust notice file is missing")
        elif package.get("source") is None:
            if not read(safe(materials["own_source_notice"])):
                raise NoticeError("owned relay source notice is missing")
        else:
            item = fallback.get(pair)
            if item is None or item["license"] != package["license"]:
                raise NoticeError("Rust fallback grant/source is missing")
            fallback_used.add(pair)
            archive = read(absolute_file("rust", item["archive_path"]))
            locked = [p for p in lock if key(p) == identity]
            if len(locked) != 1 or sha(archive) != locked[0].get("checksum") or sha(archive) != item["archive_sha256"]:
                raise NoticeError("Rust fallback archive differs from Cargo.lock")
            notices = item["notices"]
            if notices:
                if any(not read(safe(path)) for path in notices) or item["disposition"] != "exact-notice-files":
                    raise NoticeError("Rust fallback notice/disposition differs")
                with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
                    prefix = identity[0] + "-" + identity[1] + "/"
                    for path in notices:
                        if path.startswith("crate-notices/"):
                            member = prefix + path.split("/", 3)[3]
                            handle = tar.extractfile(member)
                            if handle is None or handle.read() != read(safe(path)):
                                raise NoticeError("notice differs from locked crate archive")
                        elif path.startswith("upstream/"):
                            provenance = upstream[pair]
                            vcs_path = supplemented[pair]["vcs_path"]
                            vcs_raw = read(absolute_file("rust", vcs_path))
                            handle = tar.extractfile(prefix + ".cargo_vcs_info.json")
                            if handle is None or handle.read() != vcs_raw:
                                raise NoticeError("upstream VCS provenance differs from locked archive")
                            commit = json.loads(vcs_raw)["git"]["sha1"]
                            origins = [p for p in provenance["files"] if p["path"] == path]
                            repository = supplemented[pair]["repository"].rstrip("/").removesuffix(".git")
                            expected_origin = "https://raw.githubusercontent.com/" + repository.split("https://github.com/", 1)[1] + "/" + commit + "/"
                            if (len(origins) != 1 or provenance["commit"] != commit
                                    or origins[0]["url"] != expected_origin + PurePosixPath(path).name
                                    or origins[0]["sha256"] != sha(read(safe(path))) or origins[0]["size"] != len(read(safe(path)))):
                                raise NoticeError("pinned upstream notice provenance differs")
                        else:
                            raise NoticeError("unexpected Rust fallback notice origin")
            elif package["license"] == "CC0-1.0":
                if item["disposition"] != "exact-archive-and-CC0-declaration":
                    raise NoticeError("CC0 evidence disposition differs")
            else:
                pending.append({"name": pair[0], "version": pair[1], "reason": "upstream-MIT-declaration-without-license-text"})
                if item["disposition"] != pending[-1]["reason"]:
                    raise NoticeError("unresolved grant was relabelled")
    if seen != set(expected) or fallback_used != set(fallback) or pending != materials["pending_notice_grants"]:
        raise NoticeError("Rust coverage or pending grants differ")
    return len(seen)

def validate_layers(record, sbom, inventory, read):
    if record.get("schema") == "a4a-selected-runtime-layer-evidence-v1":
        return validate_selected_runtime(record, sbom, inventory, read)
    base = document(read, "base-image.json")[0]
    relay = document(read, "relay-image.json")[0]
    prefix = base["RootFS"]["Layers"]
    if (base["Id"] != record["base_image_id"] or relay["Id"] != record["relay_image_id"]
            or relay["Id"] != inventory["images"]["relay"]["image_id"] or not prefix
            or relay["RootFS"]["Layers"][:len(prefix)] != prefix or record["matching_rootfs_prefix"] != prefix):
        raise NoticeError("retained layer prefix/image differs")
    known = verified_record_files("old-layer", record, read)
    raw = read("old-layer-packages.tsv")
    if sha(raw) != record["packages_tsv_sha256"]:
        raise NoticeError("retained layer source table differs")
    groups = document(read, "old-layer-sources.json")["groups"]
    group_ids = set()
    for group in groups:
        identity = group["component"], group["source_version"]
        if identity in group_ids:
            raise NoticeError("duplicate retained source group")
        group_ids.add(identity)
        artifacts = {a["filename"]: a for a in group["artifacts"]}
        if len(artifacts) != len(group["artifacts"]):
            raise NoticeError("duplicate retained source artifact")
        controls = []
        for name, item in artifacts.items():
            safe(name)
            content = read("sources/" + name)
            if len(content) != item["size"] or sha(content) != item["sha256"]:
                raise NoticeError("retained source artifact differs")
            if name.endswith(".dsc"):
                controls.append(content.decode())
        if len(controls) != 1:
            raise NoticeError("retained source needs one DSC")
        text = controls[0]
        if re.findall(r"^Source: ([^\r\n]+)", text, re.M) != [identity[0]] or re.findall(r"^Version: ([^\r\n]+)", text, re.M) != [identity[1]]:
            raise NoticeError("retained source DSC coordinate differs")
        section = re.search(r"(?m)^Checksums-Sha256:\r?\n((?: [^\r\n]+\r?\n)+)", text)
        if section is None:
            raise NoticeError("retained DSC lacks SHA256 members")
        members = {}
        for line in section[1].splitlines():
            digest, size, name = line.split()
            if name in members or name not in artifacts:
                raise NoticeError("retained DSC members differ")
            members[name] = digest, int(size)
            if (artifacts[name]["sha256"], artifacts[name]["size"]) != members[name]:
                raise NoticeError("retained DSC member binding differs")
        if set(members) != {n for n in artifacts if not n.endswith(".dsc")}:
            raise NoticeError("retained DSC member set differs")
    covered = set()
    used_groups = set()
    for line in raw.decode().splitlines():
        name, version, component, source_version = line.split("\t")
        if name in covered or (component, source_version) not in group_ids:
            raise NoticeError("retained-layer source coverage differs")
        covered.add(name)
        used_groups.add((component, source_version))
        candidates = [p for p in sbom["packages"] if p["name"] == name and p.get("versionInfo") == version]
        if len(candidates) != 1 or absolute_file("old-layer", "/usr/share/doc/" + name + "/copyright") not in known:
            raise NoticeError("retained-layer package/notice differs")
    if covered != {"libpcre2-8-0", "libssl3t64", "openssl-provider-legacy"} or used_groups != group_ids:
        raise NoticeError("retained-layer occurrence set differs")
    return len(covered)


def validate_selected_runtime(record, sbom, inventory, read, *, image="relay", python_notices=None, observations=None):
    """Check actual saved scratch payload rather than asserting a base prefix."""
    if image not in ("relay", "mcp", "notary"):
        raise NoticeError("unsupported selected runtime image")
    python = image != "relay"
    schema = "a4a-selected-python-runtime-layer-evidence-v1" if python else "a4a-selected-runtime-layer-evidence-v1"
    if record.get("schema") != schema:
        raise NoticeError("unsupported selected runtime evidence")
    image_id = inventory["images"][image]["image_id"]
    raw = read(safe(record["image_archive"]))
    if record["image_id" if python else "relay_image_id"] != image_id or sha(raw) != record["image_archive_sha256"]:
        raise NoticeError("selected runtime archive/image differs")
    nodes, occurrences = {}, []
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        legacy = json.load(archive.extractfile("manifest.json"))
        if len(legacy) != 1:
            raise NoticeError("selected runtime archive has multiple images")
        config_raw = archive.extractfile(legacy[0]["Config"]).read()
        config = json.loads(config_raw)
        if "index.json" in archive.getnames():
            descriptors = json.load(archive.extractfile("index.json"))["manifests"]
            descriptor, = [d for d in descriptors if d["digest"] == image_id]
            while True:
                content = archive.extractfile("blobs/sha256/" + descriptor["digest"].split(":")[1]).read()
                if "sha256:" + sha(content) != descriptor["digest"]:
                    raise NoticeError("selected runtime OCI descriptor differs")
                document = json.loads(content)
                if "manifests" not in document:
                    break
                descriptor, = [d for d in document["manifests"] if d.get("platform", {}).get("architecture") == "amd64"
                               and d.get("platform", {}).get("os") == "linux"]
            if document["config"]["digest"] != "sha256:" + sha(config_raw):
                raise NoticeError("selected runtime config differs")
        elif image_id != "sha256:" + sha(config_raw):
            raise NoticeError("selected runtime legacy config differs")
        if config["config"]["User"] != ("10001" if python else "appuser"):
            raise NoticeError("selected runtime user differs")
        layers = legacy[0]["Layers"]
        if len(layers) != len(config["rootfs"]["diff_ids"]):
            raise NoticeError("selected runtime layer count differs")
        for path, digest in zip(layers, config["rootfs"]["diff_ids"], strict=True):
            content = archive.extractfile(path).read()
            if content[:2] == b"\x1f\x8b":
                content = gzip.decompress(content)
            if "sha256:" + sha(content) != digest:
                raise NoticeError("selected runtime layer content differs")
            with tarfile.open(fileobj=io.BytesIO(content)) as payload:
                for member in payload:
                    name = member.name.removeprefix("./").rstrip("/")
                    if name in ("", "."):
                        continue
                    if (PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts or "\\" in name
                            or member.mode & 0o6000 or PurePosixPath(name).name.startswith(".wh.")
                            or not (member.isfile() or member.isdir() or member.issym())):
                        raise NoticeError("unsafe selected runtime layer node")
                    node = {"kind": "file" if member.isfile() else "directory" if member.isdir() else "symlink",
                            "uid": member.uid, "gid": member.gid, "mode": member.mode,
                            "target": member.linkname if member.issym() else None}
                    if member.isfile():
                        node["data"] = payload.extractfile(member).read()
                    nodes["/" + name] = node
                    if node["kind"] != "directory":
                        occurrences.append(("/" + name, node))
    manifest_path = "/usr/local/share/" + ("a4a-python-runtime-selection" if python else "a4a-runtime-selection") + "/manifest.json"
    manifest_raw = nodes[manifest_path]["data"]
    if sha(manifest_raw) != record["selection_manifest_sha256"]:
        raise NoticeError("selected runtime manifest differs")
    selection = json.loads(manifest_raw)
    if selection["schema"] != ("a4a-selected-python-runtime-v1" if python else "a4a-selected-relay-runtime-v1"):
        raise NoticeError("unsupported runtime selection")
    seen = set()
    for item in selection["files"]:
        path = item["path"]
        if path in seen:
            raise NoticeError("duplicate selected runtime path")
        seen.add(path)
        if path == "/":
            continue
        node = nodes[path]
        if any(item[key] != node[key] for key in ("kind", "uid", "gid", "mode")):
            raise NoticeError("selected runtime file metadata differs")
        if item["kind"] == "file" and (len(node["data"]) != item["size"] or sha(node["data"]) != item["sha256"]):
            raise NoticeError("selected runtime file bytes differ")
        if item["kind"] == "symlink" and node["target"] != item["target"]:
            raise NoticeError("selected runtime symlink differs")
    extra = {path for path, node in nodes.items() if node["kind"] != "directory"} - seen
    if extra != {manifest_path, "/etc/ld.so.cache"}:
        raise NoticeError("unindexed runtime payload")
    # Checking only the final merged tree would miss replaced payload in a lower
    # layer. Every distributed non-directory occurrence must match the index.
    indexed = {item["path"]: item for item in selection["files"]}
    for path, node in occurrences:
        if path == "/etc/ld.so.cache":
            continue
        if path == manifest_path:
            if node["data"] != manifest_raw:
                raise NoticeError("replaced runtime selection manifest")
            continue
        item = indexed.get(path)
        if item is None or any(item[key] != node[key] for key in ("kind", "uid", "gid", "mode")):
            raise NoticeError("unindexed or replaced lower-layer payload")
        if node["kind"] == "file" and (sha(node["data"]) != item["sha256"] or len(node["data"]) != item["size"]):
            raise NoticeError("replaced lower-layer file bytes")
        if node["kind"] == "symlink" and node["target"] != item["target"]:
            raise NoticeError("replaced lower-layer symlink")
    if python and selection.get("whole_usr_local_retained") is not True:
        raise NoticeError("Python prefix retention is not declared")
    if python_notices is not None:
        declared = {}
        for package in python_notices["packages"]:
            for item in package["native_files"]:
                if item["path"] in declared:
                    raise NoticeError("native file claimed by multiple distributions")
                declared[item["path"]] = (item["size"], item["sha256"])
        actual_native = {path: (len(node["data"]), sha(node["data"])) for path, node in nodes.items()
                         if "/site-packages/" in path and node["kind"] == "file" and node["data"].startswith(b"\x7fELF")}
        if declared != actual_native:
            raise NoticeError("Python native coverage differs from saved image payload")
        declared_sboms = {path for package in python_notices["packages"] for path in package["sbom_files"]}
        actual_sboms = {path for path, node in nodes.items()
                        if "/site-packages/" in path and ".dist-info/sboms/" in path and node["kind"] == "file"}
        if declared_sboms != actual_sboms:
            raise NoticeError("Python SBOM coverage differs from saved image payload")
        for item in python_notices["files"]:
            node = nodes.get(item["path"])
            if (node is None or node["kind"] != "file" or len(node["data"]) != item["size"]
                    or sha(node["data"]) != item["sha256"]
                    or node["data"] != read(absolute_file(image, item["path"]))):
                raise NoticeError("Python notice/metadata differs from saved image payload")
        for package in python_notices["packages"]:
            for path in package["sbom_files"]:
                if nodes[path]["data"] != read(absolute_file(image, path)):
                    raise NoticeError("nested SBOM differs from saved image payload")
    actual = {(p["Package"], p["Version"]) for p in selection["installed_packages"]}
    debian = {(p["name"], p["versionInfo"]) for p in sbom["packages"]
              if any(r.get("referenceType") == "purl" and r.get("referenceLocator", "").startswith("pkg:deb/debian/")
                     for r in p.get("externalRefs", []))}
    if actual != debian or len(actual) != len(selection["installed_packages"]):
        raise NoticeError("selected runtime package/SBOM coverage differs")
    if observations is not None:
        observations[image] = {"nodes": nodes, "selection": selection}
    return len(actual)

def cpython_source_lock():
    """Source pins reviewed for the exact selected official Python base."""
    return json.loads(Path(__file__).with_name("cpython-source-lock.json").read_bytes())


def validate_cpython_source(read, inventory_raw, inventory, observations):
    """Bind complete CPython/packaging sources to saved GPL-linked modules.

    Publisher provenance remains a publisher claim. This check does not assert
    an independently authenticated attestation or a bit-identical rebuild.
    """
    lock = cpython_source_lock()
    record = document(read, "cpython-source/manifest.json")
    if (record.get("schema") != "a4a-cpython-corresponding-source-v1"
            or record.get("inventory_sha256") != sha(inventory_raw)
            or record.get("base_reference") != lock["base_reference"]
            or record.get("platform") != lock["platform"]
            or record.get("python_version") != lock["python_version"]
            or record.get("independent_rebuild_proven") is not False
            or record.get("signature_authenticated") is not False):
        raise NoticeError("CPython source scope/base/inventory differs")
    images = {name: inventory["images"][name]["image_id"] for name in ("mcp", "notary")}
    if record.get("images") != images or set(observations) != set(images):
        raise NoticeError("CPython source image coverage differs")
    if record.get("artifacts") != lock["artifacts"]:
        raise NoticeError("CPython source artifacts differ from reviewed source pins")
    base = document(read, "cpython-source/base-binding.json")
    if (base.get("schema") != "a4a-cpython-base-file-measurement-v1"
            or any(base.get(key) != lock[key] for key in ("base_reference", "platform", "python_version"))):
        raise NoticeError("CPython measured base identity differs")
    base_files = {item["path"]: item for item in base["files"]}
    expected_base_paths = {item["path"] for item in lock["modules"]} | {
        "/usr/local/include/python3.11/patchlevel.h", "/usr/local/lib/python3.11/LICENSE.txt"}
    if len(base_files) != len(base["files"]) or set(base_files) != expected_base_paths:
        raise NoticeError("CPython measured base file coverage differs")
    archives = {}
    for item in lock["artifacts"]:
        raw = read("cpython-source/" + safe(item["filename"]))
        if len(raw) != item["size"] or sha(raw) != item["sha256"]:
            raise NoticeError("CPython source artifact bytes differ")
        contents = {}
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            for member in archive:
                name = safe(member.name.rstrip("/"))
                if (name in contents or member.size > 16 * 1024 * 1024
                        or member.mode & 0o6000 or not (member.isfile() or member.isdir())):
                    raise NoticeError("unsafe/duplicate CPython source archive member")
                contents[name] = archive.extractfile(member).read() if member.isfile() else None
        archives[item["filename"]] = contents
    source = archives[lock["source_archive"]]
    prefix = "Python-" + lock["python_version"] + "/"
    for name in ("LICENSE", "configure", "Makefile.pre.in", "Include/patchlevel.h",
                 "Modules/readline.c", "Modules/_gdbmmodule.c"):
        if not source.get(prefix + name):
            raise NoticeError("CPython source/build/licence member is missing")
    recipe = archives[lock["recipe_archive"]]
    recipe_prefix = "python-" + lock["recipe_commit"] + "/"
    dockerfile = recipe.get(recipe_prefix + lock["recipe_path"])
    licence = recipe.get(recipe_prefix + "LICENSE")
    if (not dockerfile or sha(dockerfile) != lock["dockerfile_sha256"]
            or not licence or sha(licence) != lock["recipe_license_sha256"]
            or read("cpython-source/Dockerfile") != dockerfile
            or read("cpython-source/docker-library-python.LICENSE") != licence):
        raise NoticeError("CPython build recipe/licence differs")
    source_pin = next(a for a in lock["artifacts"] if a["filename"] == lock["source_archive"])
    if (not re.search(rb"(?m)^ENV PYTHON_VERSION[ =]" + re.escape(lock["python_version"].encode()) + rb"$", dockerfile)
            or source_pin["sha256"].encode() not in dockerfile):
        raise NoticeError("CPython build recipe source coordinate differs")
    provenance = document(read, "cpython-source/registry-provenance.json")
    invocation = provenance["SLSA"]["invocation"]
    if (invocation["configSource"] != {"entryPoint": "Dockerfile", "uri":
            "https://github.com/docker-library/python.git#" + lock["recipe_commit"] + ":" + str(PurePosixPath(lock["recipe_path"]).parent)}
            or invocation["environment"].get("platform") != lock["platform"]
            or invocation["parameters"]["args"].get("context:debian:trixie-slim") != lock["debian_build_context"]):
        raise NoticeError("CPython publisher recipe/build context differs")
    expected = []
    for image in images:
        nodes, selection = observations[image]["nodes"], observations[image]["selection"]
        for path, item in base_files.items():
            node = nodes[path]
            if node["kind"] != "file" or len(node["data"]) != item["size"] or sha(node["data"]) != item["sha256"]:
                raise NoticeError("CPython runtime differs from measured base file")
        if nodes["/usr/local/include/python3.11/patchlevel.h"]["data"] != source[prefix + "Include/patchlevel.h"]:
            raise NoticeError("CPython runtime/source version header differs")
        if nodes["/usr/local/lib/python3.11/LICENSE.txt"]["data"] != source[prefix + "LICENSE"]:
            raise NoticeError("CPython runtime/source licence differs")
        paths = {p for p in nodes if re.fullmatch(
            r"/usr/local/lib/python3\.11/lib-dynload/(?:readline|_gdbm)\..*\.so", p)}
        if paths != {item["path"] for item in lock["modules"]}:
            raise NoticeError("CPython GPL-linked module set differs")
        for item in lock["modules"]:
            node = nodes[item["path"]]
            if node["kind"] != "file" or len(node["data"]) != item["size"] or sha(node["data"]) != item["sha256"]:
                raise NoticeError("CPython module differs from reviewed base module")
            edges = [e for e in selection["elf_edges"] if e["from"] == item["path"] and e["needed"] == item["needed"]]
            if len(edges) != 1 or nodes[edges[0]["resolved"]]["kind"] != "file":
                raise NoticeError("CPython GPL library edge differs")
            member = prefix + item["source_member"]
            expected.append({"image": image, **item, "source_member_sha256": sha(source[member]),
                             "resolved_library": edges[0]["resolved"]})
    if record.get("modules") != expected:
        raise NoticeError("CPython source/module bindings differ")
    return {"images": len(images), "files": len(expected), "archives": len(archives),
            "source_version": lock["python_version"]}

def validate_native_dependencies(records, inventory, inventory_raw, read):
    """Check every nested component's collected notice/source bindings.

    Upstream SBOM scope is retained conservatively, including excluded/build
    entries. Collection provenance is not actual linked closure or legal assent.
    """
    evidence = document(read, "python-native-dependencies.json")
    if (evidence["schema"] != "a4a-python-native-dependencies-v1"
            or evidence["inventory_sha256"] != sha(inventory_raw)
            or any(evidence[key] is not False for key in
                   ("complete_link_closure_proven", "complete_legal_acceptance", "release_approved"))):
        raise NoticeError("native dependency evidence scope/inventory differs")
    expected = {}
    unresolved = []
    if set(evidence["images"]) != set(records):
        raise NoticeError("native dependency image set differs")
    for image, record in records.items():
        if evidence["images"][image] != inventory["images"][image]["image_id"]:
            raise NoticeError("native dependency image differs")
        for package in record["packages"]:
            if package["native_files"] and not package["sbom_files"]:
                unresolved.append({"image": image, "name": package["name"], "version": package["version"],
                                   "native_files": package["native_files"], "state": "requires-file-level-review"})
            for path in package["sbom_files"]:
                raw = read(absolute_file(image, path))
                for component in json.loads(raw)["components"]:
                    key = image, path, component["purl"]
                    if key in expected:
                        raise NoticeError("duplicate nested SBOM component")
                    expected[key] = (component, sha(raw), package)
    if evidence["without_sbom"] != unresolved:
        raise NoticeError("native packages without SBOM are not explicitly accounted for")
    seen, archives, members = set(), {}, {}

    def archive(path):
        path = safe(path)
        if path not in archives:
            raw = read(path)
            if len(raw) > 150 * 1024 * 1024:
                raise NoticeError("oversized native source archive")
            archives[path] = raw
        return archives[path]

    def member(path, name):
        safe(name)
        key = path, name
        if key not in members:
            with tarfile.open(fileobj=io.BytesIO(archive(path)), mode="r:*") as tar:
                matches = [m for m in tar.getmembers() if m.name == name]
                if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 4 * 1024 * 1024:
                    raise NoticeError("missing/unsafe native source notice member")
                members[key] = tar.extractfile(matches[0]).read()
        return members[key]

    for item in evidence["components"]:
        key = item["image"], item["sbom"], item["purl"]
        if key in seen or key not in expected:
            raise NoticeError("unexpected/duplicate native notice component")
        seen.add(key)
        component, digest, package = expected[key]
        if (item["sbom_sha256"] != digest or item["name"] != component["name"]
                or item["version"] != component["version"] or item["licenses"] != component.get("licenses", [])):
            raise NoticeError("native component identity/license/SBOM differs")
        if "download_url=file:" in component["purl"]:
            if (item.get("distribution_notices") != package["license_files"]
                    or component.get("licenses") != [{"expression": package["license_expression"]}]):
                raise NoticeError("local native component grant differs from distribution")
            continue
        checksums = [v["content"] for v in component.get("hashes", []) if v["alg"] == "SHA-256"]
        source = item["source_archive"]
        if len(checksums) != 1 or sha(archive(source)) != checksums[0]:
            raise NoticeError("native source archive differs from nested SBOM")
        repository = item.get("notice_repository")
        notice_archive = source
        if repository:
            info = json.loads(member(source, component["name"] + "-" + component["version"] + "/.cargo_vcs_info.json"))
            commit = repository["commit"]
            notice_archive = repository["archive"]
            if (not re.fullmatch(r"[a-f0-9]{40}", commit) or info["git"]["sha1"] != commit
                    or sha(archive(notice_archive)) != repository["sha256"]):
                raise NoticeError("native repository notice provenance differs")
        if not item["notices"]:
            raise NoticeError("native component lacks collected grant/notice")
        for notice in item["notices"]:
            raw = read(safe(notice["path"]))
            if not raw or raw != member(notice_archive, notice["member"]):
                raise NoticeError("native notice differs from exact source")
            if repository and not PurePosixPath(notice["member"]).parts[0].endswith("-" + repository["commit"]):
                raise NoticeError("native repository archive root differs from commit")
    if seen != set(expected):
        raise NoticeError("native component notice coverage is incomplete")
    return {"sboms": sum(len(p["sbom_files"]) for r in records.values() for p in r["packages"]),
            "component_occurrences": len(seen),
            "native_files": sum(len(p["native_files"]) for r in records.values() for p in r["packages"]),
            "without_sbom": unresolved}


def validate_materials(read, inventory_raw, *, require_native=False):
    try:
        materials = document(read, "materials.json")
        if (materials["schema"] not in ("a4a-release-notice-materials-v1", "a4a-release-notice-materials-v2", "a4a-release-notice-materials-v3", "a4a-release-notice-materials-v4") or materials["inventory_sha256"] != sha(inventory_raw)
                or materials["complete_legal_acceptance"] is not False or materials["signature_authenticated"] is not False):
            raise NoticeError("notice scope/provenance differs")
        native = materials["schema"] in ("a4a-release-notice-materials-v3", "a4a-release-notice-materials-v4")
        if require_native and not native:
            raise NoticeError("new notice snapshots require v3 native component coverage")
        if read("inventory/manifest.json") != inventory_raw:
            raise NoticeError("notice inventory differs")
        inventory = json.loads(inventory_raw)
        sboms = {}
        for image, item in inventory["images"].items():
            raw = read("inventory/" + safe(item["sbom"]))
            if sha(raw) != item["sbom_sha256"]:
                raise NoticeError("notice SBOM differs")
            sboms[image] = json.loads(raw)
        counts, records, observations = {}, {}, {}
        for image in ("mcp", "notary"):
            record = document(read, "python-" + image + ".json")
            if record["image_id"] != inventory["images"][image]["image_id"] or record["inventory_sha256"] != sha(inventory_raw):
                raise NoticeError("Python notice image differs")
            counts[image] = validate_python(image, record, sboms[image], read, require_native=native)
            records[image] = record
            if not record["stdlib_license_present"] or not read(absolute_file(image, record["stdlib_license"])):
                raise NoticeError("Python runtime license is missing")
            if materials["schema"] in ("a4a-release-notice-materials-v2", "a4a-release-notice-materials-v3", "a4a-release-notice-materials-v4"):
                layer_record = document(read, "python-runtime-" + image + ".json")
                count = validate_selected_runtime(layer_record, sboms[image], inventory, read, image=image,
                                                  python_notices=record if native else None, observations=observations)
                counts.setdefault("python_runtime_packages", {})[image] = count
        if native:
            counts["python_native"] = validate_native_dependencies(records, inventory, inventory_raw, read)
        if materials["schema"] == "a4a-release-notice-materials-v4":
            counts["cpython_source"] = validate_cpython_source(read, inventory_raw, inventory, observations)
        elif require_native:
            raise NoticeError("new notice snapshots require v4 CPython corresponding source")
        rust_raw = read("inventory/" + safe(inventory["relay_rust"]["metadata"]))
        if sha(rust_raw) != inventory["relay_rust"]["metadata_sha256"]:
            raise NoticeError("notice Rust metadata differs")
        rust = document(read, "rust.json")
        if (rust["relay_image_id"] != inventory["images"]["relay"]["image_id"] or rust["metadata_sha256"] != sha(rust_raw)
                or rust["builder_image_id"] != inventory["relay_rust"]["builder_image"]["image_id"]):
            raise NoticeError("Rust notice binding differs")
        continuity = document(read, "builder-source-check.json")
        if (continuity["passed"] is not True or continuity["builder_image_id"] != rust["builder_image_id"]
                or continuity["binary_sha256"] != rust["binary_sha256"]
                or continuity["files"]["Cargo.lock"] != sha(read("files/rust/nostr-rs-relay/Cargo.lock"))):
            raise NoticeError("Rust build continuity differs")
        counts["rust"] = validate_rust(rust, json.loads(rust_raw), document(read, "rust-supplement.json"), materials, read)
        counts["retained_layers"] = validate_layers(document(read, "old-layer.json"), sboms["relay"], inventory, read)
        counts["pending_notice_grants"] = materials["pending_notice_grants"]
        counts["owned_source_notice_sha256"] = sha(read(safe(materials["own_source_notice"])))
        return counts
    except (KeyError, TypeError, ValueError, OSError, csv.Error, tarfile.TarError) as exc:
        raise NoticeError("invalid/incomplete notice evidence: " + str(exc)) from exc

def build_snapshot(materials, output, inventory_raw, git):
    index = index_materials(materials)
    counts = validate_materials(lambda p: (materials / safe(p)).read_bytes(), inventory_raw, require_native=True)
    output.mkdir()
    for item in index:
        destination = output / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(materials / item["path"], destination)
    snapshot = {"schema": SCHEMA, "git": git, "inventory_sha256": sha(inventory_raw),
                "files": index, "file_count": len(index), "coverage": counts,
                "complete_legal_acceptance": False, "release_approved": False}
    (output / "manifest.json").write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    verify_snapshot(lambda p: (output / safe(p)).read_bytes(), inventory_raw, {i["path"] for i in index}, git["commit"])
    return snapshot

def verify_snapshot(read, inventory_raw, actual_names, head):
    snapshot = document(read, "manifest.json")
    if (snapshot.get("schema") != SCHEMA or snapshot.get("git") != {"commit": head, "dirty": False, "changed_paths": []}
            or snapshot.get("inventory_sha256") != sha(inventory_raw) or snapshot.get("complete_legal_acceptance") is not False
            or snapshot.get("release_approved") is not False):
        raise NoticeError("notice snapshot binding/scope differs")
    seen = set()
    for item in snapshot["files"]:
        path = safe(item["path"])
        if path in seen:
            raise NoticeError("duplicate notice snapshot file")
        seen.add(path)
        raw = read(path)
        if len(raw) != item["size"] or sha(raw) != item["sha256"]:
            raise NoticeError("notice snapshot file differs")
    if seen != actual_names or snapshot["file_count"] != len(seen):
        raise NoticeError("notice snapshot file set differs")
    if snapshot["coverage"] != validate_materials(read, inventory_raw):
        raise NoticeError("notice snapshot coverage differs")
    return snapshot
