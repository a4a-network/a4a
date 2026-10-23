#!/usr/bin/env python3
"""Build a local relay image from authenticated Debian inputs using BuildKit.

Use --bundle for a retained portable bundle, or acquire the exact trusted lock
from fixed Debian origins using the committed exact signed Releases. Expired
metadata fails closed and needs an explicit lock refresh. This command never
pushes, publishes ports, mounts the host into containers, or prunes artifacts.
Build contexts/logs and any created acquisition containers are retained for
diagnosis. Failed BuildKit RUN filesystems are not exported by this command.
BuildKit RUN resource limits come from the existing builder configuration;
the guards on the stopped export carrier do not constrain the build itself.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

from debian_build_lock import _MAX_LOCK, _read, load_lock
from debian_lock_contract import LockContractError

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ("debian_acquire.py", "debian_build_lock.py", "debian_install_replay.py",
         "debian_lock_contract.py", "debian_release_auth.py", "debian_image_inputs.py", "debian_refresh.py",
         "prepare-relay-runtime.py")
FRESH_STAGES = "debian-verify,builder-inputs,runtime-inputs"


def _plain(path):
    path = Path(path).absolute()
    for component in (path, *path.parents):
        # Python 3.11 on Windows lacks Path.is_junction(). Reject any reparse
        # point there, including junctions through an ancestor directory.
        attributes = getattr(component.lstat(), "st_file_attributes", 0) if component.exists() else 0
        if component.is_symlink() or attributes & 0x400:
            raise LockContractError("linked build input or output")
    return path


def copy_input(source, destination):
    source = _plain(source)
    if not source.is_file() or source.stat().st_size > 32 * 1024 * 1024:
        raise LockContractError("missing, special or oversized source input")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as origin, destination.open("xb") as output:
        shutil.copyfileobj(origin, output)


def prepare_contexts(root, output):
    """Expose only needed relay code/policy and eight named build modules."""
    root, output = _plain(root), _plain(output)
    if output.exists():
        raise LockContractError("build destination already exists")
    output.mkdir(parents=True, exist_ok=False)
    with (root / "relay/debian/lock.json").open("rb") as source:
        manifest = load_lock(source.read(_MAX_LOCK + 1))
    relay, tools = output / "relay", output / "tools"
    for filename in ("Dockerfile", "Cargo.toml", "Cargo.lock", "build.rs", "debian/lock.json", "debian/policy.json"):
        copy_input(root / "relay" / filename, relay / filename)
    for name, stage in manifest["stages"].items():
        binding = stage["base_inventory"]
        if binding["path"] != f"{name}/base.tsv":
            raise LockContractError("unsupported inventory seed layout")
        _read(root / "relay/debian", binding)
        copy_input(root / "relay/debian" / binding["path"], relay / "debian" / binding["path"])
        for repository in stage["repositories"]:
            binding = repository["inrelease"]
            _read(root / "relay/debian", binding)
            copy_input(root / "relay/debian" / binding["path"], relay / "debian" / binding["path"])
    for directory, suffix in (("src", ".rs"), ("proto", ".proto")):
        origin = _plain(root / "relay" / directory)
        files = sorted(origin.rglob("*"))
        for path in files:
            _plain(path)
            if path.is_file():
                if path.suffix != suffix:
                    raise LockContractError("unexpected file in relay source tree")
                copy_input(path, relay / directory / path.relative_to(origin))
        if not any(p.is_file() for p in files):
            raise LockContractError("empty relay source tree")
    for filename in TOOLS:
        copy_input(root / "scripts" / filename, tools / filename)
    return manifest, relay, tools


def filter_bundle(manifest, source, destination):
    """Copy only bounded lock bindings; native signatures are checked in Docker."""
    source, destination = _plain(source), _plain(destination)
    if destination.exists():
        raise LockContractError("bundle destination already exists")
    destination.mkdir(parents=True, exist_ok=False)
    for stage in manifest["stages"].values():
        bindings = [stage["base_inventory"]]
        bindings += [binding for repo in stage["repositories"]
                     for binding in (repo["inrelease"], repo["index"])]
        bindings += [package["file"] for package in stage["packages"]]
        for binding in bindings:
            _plain(source / binding["path"])
            payload = _read(source, binding)
            path = destination / binding["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as handle:
                handle.write(payload)


def build_command(relay, tools, *, nonce, tag, target, bundle=None):
    command = ["docker", "buildx", "build", "--load", "--platform", "linux/amd64",
               "--progress", "plain", "--no-cache-filter", FRESH_STAGES + ",debian-acquire",
               "--build-context", f"debian-tools={tools}",
               "--build-arg", f"DEBIAN_BUILD_NONCE={nonce}",
               "--target", target, "--tag", tag]
    if bundle is not None:
        command += ["--build-context", f"debian-bundle={bundle}"]
    return command + [str(relay)]


def _run(command, output, label, *, timeout=900):
    with (output / f"{label}.log").open("xb") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        log_path = output / f"{label}.log"
        with log_path.open("rb") as failed_log:
            failed_log.seek(max(0, log_path.stat().st_size - 65536))
            tail = failed_log.read(65536).decode("utf-8", errors="replace")
        print(f"{label} log (last 64 KiB):\n{tail}", file=sys.stderr)
        raise LockContractError(f"{label} failed ({result.returncode}); see {output / (label + '.log')}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="new owned diagnostic directory")
    parser.add_argument("--tag", required=True, help="local image tag")
    parser.add_argument("--target", choices=("builder-inputs", "runtime-inputs", "builder", "runtime-tools", "runtime-prepare", "runtime"),
                        default="runtime")
    options = parser.parse_args()
    try:
        manifest, relay, tools = prepare_contexts(ROOT, options.output)
        output = options.output.absolute()
        nonce = uuid.uuid4().hex
        acquisition_tag = f"a4a-debian-acquire:{nonce}"
        source = options.bundle
        if source is None:
            print(f"Acquiring exact locked inputs; log: {output / 'acquire.log'}", flush=True)
            _run(build_command(relay, tools, nonce=nonce, tag=acquisition_tag,
                               target="debian-acquire"), output, "acquire")
            container = f"a4a-debian-acquire-{nonce}"
            _run(["docker", "create", "--name", container, "--network", "none", "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "1g",
                  "--cpus", "2", "--pids-limit", "64", acquisition_tag, "/bin/true"], output, "create")
            source = output / "acquired"
            _run(["docker", "cp", f"{container}:/acquired", str(source)], output, "export")
        bundle = output / "bundle"
        filter_bundle(manifest, source, bundle)
        command = build_command(relay, tools, nonce=nonce, tag=options.tag,
                                target=options.target, bundle=bundle)
        record = {"schema": "a4a-relay-image-build-attempt-v1", "build_nonce": nonce,
                  "target": options.target, "tag": options.tag, "command": command,
                  "source_files": {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                                   for context in (relay, tools) for p in sorted(context.rglob("*"))
                                   if p.is_file()}}
        (output / "attempt.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        print(f"Building {options.target}; log: {output / 'build.log'}", flush=True)
        _run(command, output, "build", timeout=2700)
        (output / "success.json").write_text(json.dumps({"build_nonce": nonce, "tag": options.tag,
                                                       "target": options.target}) + "\n")
    except (LockContractError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Relay image build failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
