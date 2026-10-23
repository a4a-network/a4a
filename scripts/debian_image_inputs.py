"""Emit offline installation kits after native authentication of both stages.

The CLI uses actual UTC. Run in an immutable, resource-bounded Linux verifier;
its output must be mounted read-only into the matching pinned install images.
Only the supported build wrapper supplies a fresh nonce and bypasses RUN cache.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

from debian_build_lock import _MAX_LOCK, _read, load_lock, verify_bundle
from debian_install_replay import _inventory
from debian_lock_contract import LockContractError
from debian_refresh import load_policy, validate_policy, _utc


def _rows(inventory):
    return "".join(sorted(f"{name}\t{version}\t{arch}\n"
                          for (name, arch), version in inventory.items()))


def _installer(package_count):
    arguments = " ".join(f'"$KIT/packages/{i:03}.deb"' for i in range(package_count))
    return '''#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
export DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC
test "${A4A_DEBIAN_INSTALL:-}" = 1
test "$(id -u)" = 0
test "$(uname -s)" = Linux
KIT=/tmp/a4a-debian-kit
REPORT=/usr/local/share/a4a-debian-install
test ! -e "$REPORT"
mkdir -p "$REPORT"
dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n' > "$REPORT/before.raw.tsv"
sort "$REPORT/before.raw.tsv" > "$REPORT/before.tsv"
cmp "$KIT/before.expected.tsv" "$REPORT/before.tsv"
(cd "$KIT" && sha256sum -c files.sha256)
test "$(date -u +%s)" -lt "$(cat "$KIT/expires.unix")"
dpkg --install ''' + arguments + '''
dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n' > "$REPORT/after.raw.tsv"
sort "$REPORT/after.raw.tsv" > "$REPORT/after.tsv"
cmp "$KIT/after.expected.tsv" "$REPORT/after.tsv"
dpkg --audit > "$REPORT/dpkg-audit.txt"
test ! -s "$REPORT/dpkg-audit.txt"
apt-get check > "$REPORT/apt-check.txt" 2>&1
test "$(date -u +%s)" -lt "$(cat "$KIT/expires.unix")"
cp "$KIT/verification.json" "$REPORT/verification.json"
printf '%s\\n' 'exact-inventory-and-health-checked' > "$REPORT/result.txt"
'''


def emit_kits(manifest, bundle, output, *, nonce, now=None, policy=None):
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise LockContractError("invalid fresh build nonce")
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise LockContractError("kit destination already exists")
    current_time = (lambda: datetime.now(timezone.utc)) if now is None else (lambda: now)
    validate_policy(manifest, policy, now=current_time())
    proof = verify_bundle(manifest, bundle, now=current_time())
    validate_policy(manifest, policy, now=current_time())
    expiry = min([_utc(policy["usable_until_utc"])] + [
        _utc(repo["valid_until_utc"]) for stage in proof["stages"].values()
        for repo in stage["repositories"] if repo["valid_until_utc"] is not None])
    if current_time() >= expiry:
        raise LockContractError("authenticated install kit deadline expired")
    proof["installation_deadline_utc"] = expiry.isoformat()
    proof["refresh_policy"] = policy
    proof["build_nonce"] = nonce
    proof["lock_policy_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    root = Path(bundle).resolve(strict=True)
    # No output is created until every repository and package has passed.
    output.mkdir(parents=True, exist_ok=False)
    for name, stage in manifest["stages"].items():
        kit = output / name
        (kit / "packages").mkdir(parents=True)
        base = _inventory(_read(root, stage["base_inventory"]).decode("utf-8"))
        expected = dict(base)
        files = {}
        for i, package in enumerate(stage["packages"]):
            record = package["record"]
            expected[record["Package"], record["Architecture"]] = record["Version"]
            # Recheck the copy rather than relying on an earlier mutable read.
            files[f"packages/{i:03}.deb"] = _read(root, package["file"])
        files["before.expected.tsv"] = _rows(base).encode()
        files["after.expected.tsv"] = _rows(expected).encode()
        files["verification.json"] = (json.dumps(proof, sort_keys=True, indent=2) + "\n").encode()
        files["install.sh"] = _installer(len(stage["packages"])).encode()
        files["expires.unix"] = (str(int(expiry.timestamp())) + "\n").encode()
        for path, payload in files.items():
            with (kit / path).open("xb") as destination:
                destination.write(payload)
        hashes = "".join(f"{hashlib.sha256(payload).hexdigest()}  {path}\n"
                         for path, payload in sorted(files.items()))
        with (kit / "files.sha256").open("x", encoding="ascii", newline="\n") as destination:
            destination.write(hashes)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("nonce")
    options = parser.parse_args()
    try:
        with options.lock.open("rb") as source:
            manifest = load_lock(source.read(_MAX_LOCK + 1))
        emit_kits(manifest, options.bundle, options.output, nonce=options.nonce,
                  policy=load_policy(options.lock.parent / "policy.json"))
    except (LockContractError, OSError) as exc:
        print(f"Debian install kit verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
