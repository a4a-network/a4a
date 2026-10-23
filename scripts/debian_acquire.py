"""Acquire the exact relay Debian lock from fixed official HTTPS repositories.

Run the CLI in the pinned builder image with its immutable gpgv/archive ring,
an owned private output parent, bounded disk/memory and no concurrent writer.
Base inventories and optionally exact reviewed signed Releases are supplied
locally. This does not remeasure a base, resolve dependencies or install packages.
Changed/unavailable or expired inputs require a reviewed refreshed lock, never
an automatic fallback. Failed output is retained without acquisition.json.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import lzma
import os
from pathlib import Path
import signal
import stat
import sys
import time
import urllib.request

from debian_build_lock import _MAX_LOCK, _read, load_lock, validate_lock, verify_bundle
from debian_install_replay import _inventory
from debian_lock_contract import LockContractError, validate_release, validate_repository
import debian_release_auth as auth


ORIGINS = {
    "bookworm": "https://deb.debian.org/debian",
    "bookworm-updates": "https://deb.debian.org/debian",
    "bookworm-security": "https://security.debian.org/debian-security",
    "trixie": "https://deb.debian.org/debian",
    "trixie-updates": "https://deb.debian.org/debian",
    "trixie-security": "https://security.debian.org/debian-security",
}
_CHUNK = 65536
_SECONDS = 300
_MAX_COMPRESSED = 128 * 1024 * 1024
_MAX_NETWORK = 384 * 1024 * 1024
_RESERVED = {"lock.json", "acquisition.json", "acquisition.pending.json", "README.txt", "_transport"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LockContractError("repository redirect refused")


def _open(url, timeout):
    # Do not inherit proxy credentials or forward requests to another origin.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity",
                                                  "User-Agent": "A4A-Debian-lock/1"})
    return opener.open(request, timeout=timeout)


def _remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise LockContractError("acquisition deadline exceeded")
    return min(15, left)


def _fetch(url, binding, target, deadline):
    """Stream exact bytes with socket/deadline limits and no HTTP transforms.

    The CLI alarm also bounds slow response headers and blocked system calls.
    Library callers must impose an overall process timeout of their own.
    """
    if not any(url.startswith(origin + "/") for origin in set(ORIGINS.values())):
        raise LockContractError("unsupported repository origin")
    digest, total = hashlib.sha256(), 0
    try:
        with _open(url, timeout=_remaining(deadline)) as response:
            if (response.status != 200 or response.geturl() != url
                    or response.headers.get("Content-Encoding", "identity") != "identity"):
                raise LockContractError("repository response or encoding refused")
            length = response.headers.get("Content-Length")
            if length is not None and length != str(binding["size"]):
                raise LockContractError("download Content-Length differs from lock")
            with target.open("xb") as output:
                while True:
                    _remaining(deadline)
                    chunk = response.read1(min(_CHUNK, binding["size"] - total + 1))
                    _remaining(deadline)
                    if not isinstance(chunk, bytes) or len(chunk) > min(_CHUNK, binding["size"] - total + 1):
                        raise LockContractError("invalid download read")
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > binding["size"]:
                        raise LockContractError("download exceeds locked size")
                    digest.update(chunk)
                    output.write(chunk)
    except OSError as exc:
        raise LockContractError("repository download failed") from exc
    if total != binding["size"] or digest.hexdigest() != binding["sha256"]:
        raise LockContractError("download size or SHA256 differs from lock")
    return total


def _decompress(source, target, binding, deadline):
    """Accept one bounded XZ stream and the exact locked uncompressed bytes."""
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024 * 1024)
    digest, total = hashlib.sha256(), 0
    try:
        with source.open("rb") as compressed, target.open("xb") as output:
            while not decoder.eof:
                _remaining(deadline)
                chunk = compressed.read(_CHUNK) if decoder.needs_input else b""
                if decoder.needs_input and not chunk:
                    raise LockContractError("truncated compressed index")
                decoded = decoder.decompress(chunk, max_length=min(_CHUNK, binding["size"] - total + 1))
                total += len(decoded)
                if total > binding["size"]:
                    raise LockContractError("decompressed index exceeds locked size")
                output.write(decoded)
                digest.update(decoded)
            if decoder.unused_data or compressed.read(1):
                raise LockContractError("trailing or concatenated compressed index")
    except (OSError, lzma.LZMAError, EOFError) as exc:
        raise LockContractError("compressed index decoding failed") from exc
    if total != binding["size"] or digest.hexdigest() != binding["sha256"]:
        raise LockContractError("decompressed index size or SHA256 differs from lock")


def _plain_path(path):
    path = Path(path).absolute()
    for component in (path, *path.parents):
        if component.is_symlink():
            raise LockContractError("symlink in acquisition path")
        if component.exists():
            attributes = getattr(component.stat(), "st_file_attributes", 0)
            if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                raise LockContractError("reparse point in acquisition path")
    return path


def _target(root, binding):
    path = _plain_path(root / binding["path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def acquire_bundle(manifest, inventory_root, destination, *, now=None, release_root=None):
    """Acquire/authenticate all repositories before downloading any package.

    Explicit time is for library tests only. The CLI always uses actual UTC at
    each validation, including the final complete offline bundle verification.
    A success receipt is written last; partial failures are kept for inspection.
    """
    validate_lock(manifest)
    raw_lock = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    manifest = load_lock(raw_lock)
    if now is not None and (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None):
        raise LockContractError("now requires timezone")
    def current_time():
        return now if now is not None else datetime.now(timezone.utc)
    for stage in manifest["stages"].values():
        bindings = [stage["base_inventory"]]
        bindings += [r[k] for r in stage["repositories"] for k in ("inrelease", "index")]
        bindings += [p["file"] for p in stage["packages"]]
        if any(b["path"].split("/")[0] in _RESERVED for b in bindings):
            raise LockContractError("reserved acquisition path in manifest")
    output = _plain_path(destination)
    seed = _plain_path(inventory_root)
    releases = _plain_path(release_root) if release_root is not None else None
    if output.exists() or not output.parent.is_dir():
        raise LockContractError("destination exists or its parent is unavailable")
    inventories = {}
    for name, stage in manifest["stages"].items():
        raw = _read(seed, stage["base_inventory"])
        try:
            inventory = _inventory(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise LockContractError("invalid inventory encoding") from exc
        if any(architecture not in ("amd64", "all") for _, architecture in inventory):
            raise LockContractError("base inventory architecture differs from lock")
        inventories[name] = raw
    locked_releases = {}
    if releases is not None:
        # Review pins these bytes in the source tree. Never substitute another
        # response from the mutable InRelease URL when a local pin is missing.
        for stage in manifest["stages"].values():
            for repo in stage["repositories"]:
                binding = repo["inrelease"]
                locked_releases[binding["path"]] = _read(releases, binding)
    try:
        output.mkdir(mode=0o700)
        (output / "README.txt").write_text(
            "Owned acquisition output. A missing acquisition.json means incomplete/failed.\n"
            "Keep failed output; use a fresh destination for another attempt.\n"
            "Reverify immutable inputs before installation; no installation is certified here.\n",
            encoding="utf-8")
        (output / "lock.json").write_bytes(raw_lock)
        (output / "_transport").mkdir()
        deadline, network_bytes = time.monotonic() + _SECONDS, 0
        for name, stage in manifest["stages"].items():
            with _target(output, stage["base_inventory"]).open("xb") as inventory_file:
                inventory_file.write(inventories[name])
            for repo in stage["repositories"]:
                base = ORIGINS[repo["suite"]] + "/dists/" + repo["suite"]
                if network_bytes + repo["inrelease"]["size"] > _MAX_NETWORK:
                    raise LockContractError("aggregate network byte limit exceeded")
                if releases is None:
                    network_bytes += _fetch(base + "/InRelease", repo["inrelease"],
                                            _target(output, repo["inrelease"]), deadline)
                else:
                    with _target(output, repo["inrelease"]).open("xb") as release_file:
                        release_file.write(locked_releases[repo["inrelease"]["path"]])
                signed = _read(output, repo["inrelease"])
                authenticated = auth.authenticate_inrelease(signed)
                if authenticated["keyring_sha256"] != manifest["keyring_sha256"]:
                    raise LockContractError("archive keyring differs from lock")
                _, entries = validate_release(authenticated["release_payload"], suite=repo["suite"],
                                               architecture="amd64", now=current_time())
                index_name = "main/binary-amd64/Packages"
                if entries.get(index_name) != (repo["index"]["sha256"], repo["index"]["size"]):
                    raise LockContractError("signed index differs from locked descriptor")
                compressed = entries.get(index_name + ".xz")
                if compressed is None or not 0 < compressed[1] <= _MAX_COMPRESSED:
                    raise LockContractError("missing or oversized signed compressed index")
                if network_bytes + compressed[1] > _MAX_NETWORK:
                    raise LockContractError("aggregate network byte limit exceeded")
                transport = output / "_transport" / f"{name}-{repo['suite']}.xz"
                network_bytes += _fetch(base + "/main/binary-amd64/by-hash/SHA256/" + compressed[0],
                                        {"size": compressed[1], "sha256": compressed[0]}, transport, deadline)
                _decompress(transport, _target(output, repo["index"]), repo["index"], deadline)
                records = [p["record"] for p in stage["packages"] if p["suite"] == repo["suite"]]
                validate_repository(authenticated["release_payload"], _read(output, repo["index"]), records,
                                    suite=repo["suite"], architecture="amd64", now=current_time())
        for stage in manifest["stages"].values():
            for package in stage["packages"]:
                if network_bytes + package["file"]["size"] > _MAX_NETWORK:
                    raise LockContractError("aggregate network byte limit exceeded")
                url = ORIGINS[package["suite"]] + "/" + package["record"]["Filename"]
                network_bytes += _fetch(url, package["file"], _target(output, package["file"]), deadline)
        _remaining(deadline)
        proof = verify_bundle(manifest, output, now=current_time())
        _remaining(deadline)
        proof.update(schema="a4a-relay-debian-acquisition-receipt-v1", network_bytes=network_bytes,
                     lock_sha256=hashlib.sha256(raw_lock).hexdigest(),
                     origins=sorted(set(ORIGINS.values())), acquisition_deadline_seconds=_SECONDS,
                     release_source="locked-local" if releases is not None else "official-network")
        pending = output / "acquisition.pending.json"
        with pending.open("x", encoding="utf-8") as receipt:
            receipt.write(json.dumps(proof, indent=2, sort_keys=True) + "\n")
            receipt.flush()
            os.fsync(receipt.fileno())
        # Atomic no-overwrite publication. Keep the owned pending file as evidence;
        # an interrupted write cannot create a success-named partial receipt.
        os.link(pending, output / "acquisition.json")
        return proof
    except OSError as exc:
        raise LockContractError("acquisition file operation failed; partial output retained") from exc


def _alarm(signum, frame):
    raise LockContractError("acquisition process deadline exceeded")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("inventories", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--locked-releases", type=Path,
                        help="exact reviewed signed Releases; all hashes, signatures and freshness still required")
    options = parser.parse_args()
    try:
        if not hasattr(signal, "setitimer"):
            raise LockContractError("CLI requires Linux process deadline support")
        with options.lock.open("rb") as source:
            manifest = load_lock(source.read(_MAX_LOCK + 1))
        previous = signal.signal(signal.SIGALRM, _alarm)
        try:
            signal.setitimer(signal.ITIMER_REAL, _SECONDS)
            proof = acquire_bundle(manifest, options.inventories, options.destination,
                                   release_root=options.locked_releases)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    except (LockContractError, OSError) as exc:
        print(f"Debian acquisition failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(proof, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
