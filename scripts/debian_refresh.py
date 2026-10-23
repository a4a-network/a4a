"""Explicit metadata-only candidate refresh for the fixed relay Debian lock.

Never changes package records, resolver inputs, image pins or inventory bindings.
New metadata must authenticate, remain current and retain every selected record.
The old signed Date is a rollback floor, not evidence of current validity.
Candidates require review before replacing committed build policy. Only the CLI
chooses actual UTC; explicit library time is reserved for deterministic tests.
"""
import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time

import debian_acquire as acquire
from debian_build_lock import _MAX_LOCK, _read, load_lock, validate_lock
from debian_install_replay import _inventory
from debian_lock_contract import (LockContractError, _date, _stanzas, _text,
                                  validate_release, validate_repository)

_WINDOW = timedelta(hours=24)
_POLICY_FIELDS = {"schema", "lock_sha256", "parent_lock_sha256", "observed_at_utc", "usable_until_utc"}
_RESERVED = acquire._RESERVED | {"policy.json", "policy.pending.json", "refresh.json"}


def lock_bytes(manifest):
    return (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()


def _utc(value):
    if not isinstance(value, str) or len(value) > 40:
        raise LockContractError("invalid policy UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise LockContractError("invalid policy UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0) or parsed.isoformat() != value:
        raise LockContractError("noncanonical policy UTC timestamp")
    return parsed


def validate_policy(manifest, policy, *, now):
    validate_lock(manifest)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise LockContractError("policy now requires timezone")
    if not isinstance(policy, dict) or set(policy) != _POLICY_FIELDS:
        raise LockContractError("missing or unexpected refresh policy fields")
    if (policy["schema"] != "a4a-debian-refresh-policy-v1"
            or policy["lock_sha256"] != hashlib.sha256(lock_bytes(manifest)).hexdigest()
            or not isinstance(policy["parent_lock_sha256"], str)
            or len(policy["parent_lock_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in policy["parent_lock_sha256"])):
        raise LockContractError("refresh policy identity or lock binding mismatch")
    observed, deadline = _utc(policy["observed_at_utc"]), _utc(policy["usable_until_utc"])
    if observed > now or deadline <= observed or deadline > observed + _WINDOW:
        raise LockContractError("refresh policy future date or invalid lifetime")
    if now >= deadline:
        raise LockContractError("refresh policy expired; explicit metadata refresh required")
    return True


def load_policy(path):
    from debian_build_lock import _object
    with Path(path).open("rb") as source:
        raw = source.read(8193)
    if not raw or len(raw) > 8192:
        raise LockContractError("invalid or oversized refresh policy")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise LockContractError("invalid refresh policy JSON") from exc


def _observe(url, target, deadline):
    """Bounded unknown-digest InRelease; authentication must precede its use."""
    if not any(url.startswith(origin + "/") for origin in set(acquire.ORIGINS.values())):
        raise LockContractError("unsupported refresh origin")
    maximum, total = 2 * 1024 * 1024, 0
    try:
        with acquire._open(url, timeout=acquire._remaining(deadline)) as response:
            if (response.status != 200 or response.geturl() != url
                    or response.headers.get("Content-Encoding", "identity") != "identity"):
                raise LockContractError("refresh response or encoding refused")
            length = response.headers.get("Content-Length")
            if length is not None and (not isinstance(length, str) or not length.isascii()
                    or not length.isdecimal() or len(length) > 10 or not 0 < int(length) <= maximum):
                raise LockContractError("oversized or invalid refresh Content-Length")
            with target.open("xb") as output:
                while True:
                    acquire._remaining(deadline)
                    chunk = response.read1(min(acquire._CHUNK, maximum - total + 1))
                    acquire._remaining(deadline)
                    if not isinstance(chunk, bytes) or len(chunk) > min(acquire._CHUNK, maximum - total + 1):
                        raise LockContractError("invalid refresh read")
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > maximum:
                        raise LockContractError("oversized observed InRelease")
                    output.write(chunk)
            if total == 0 or length is not None and int(length) != total:
                raise LockContractError("empty or truncated observed InRelease")
    except OSError as exc:
        raise LockContractError("refresh download failed") from exc
    return total


def refresh_candidate(manifest, previous_bundle, destination, *, now=None):
    validate_lock(manifest)
    current_time = (lambda: datetime.now(timezone.utc)) if now is None else (lambda: now)
    observed = current_time()
    if not isinstance(observed, datetime) or observed.tzinfo is None or observed.utcoffset() is None:
        raise LockContractError("refresh now requires timezone")
    observed = observed.astimezone(timezone.utc)
    output, previous = acquire._plain_path(destination), acquire._plain_path(previous_bundle)
    if output.exists() or not output.parent.is_dir():
        raise LockContractError("refresh destination exists or parent unavailable")
    candidate = deepcopy(manifest)
    floors, seeds = {}, {}
    # Authenticate the exact trusted old Release to obtain a monotonic floor.
    # Its historical expiry is not bypassed for installation: no old repository
    # or package acceptance is produced by this baseline-only operation.
    for name, stage in manifest["stages"].items():
        bindings = [stage["base_inventory"]] + [repo[key] for repo in stage["repositories"]
                                                for key in ("inrelease", "index")]
        bindings += [package["file"] for package in stage["packages"]]
        if any(binding["path"].split("/")[0] in _RESERVED for binding in bindings):
            raise LockContractError("reserved refresh output path")
        seeds[name] = _read(previous, stage["base_inventory"])
        _inventory(seeds[name].decode("utf-8"))
        for repo in stage["repositories"]:
            signed = acquire.auth.authenticate_inrelease(_read(previous, repo["inrelease"]))
            if signed["keyring_sha256"] != manifest["keyring_sha256"]:
                raise LockContractError("baseline archive keyring differs from lock")
            rows = list(_stanzas(_text(signed["release_payload"], "baseline Release", 2 * 1024 * 1024),
                                 "baseline Release"))
            if (len(rows) != 1 or rows[0].get("Codename") != repo["suite"]
                    or "amd64" not in rows[0].get("Architectures", "").split()):
                raise LockContractError("baseline Release identity mismatch")
            floors[name, repo["suite"]] = _date(rows[0].get("Date"), "baseline Date")
    output.mkdir(mode=0o700)
    (output / "_transport").mkdir()
    network, deadline, expiry = 0, time.monotonic() + acquire._SECONDS, observed + _WINDOW
    repository_proofs = []
    for name, stage in candidate["stages"].items():
        with acquire._target(output, stage["base_inventory"]).open("xb") as target:
            target.write(seeds[name])
        for repo in stage["repositories"]:
            if network + 2 * 1024 * 1024 > acquire._MAX_NETWORK:
                raise LockContractError("refresh aggregate network limit exceeded")
            origin = acquire.ORIGINS[repo["suite"]] + "/dists/" + repo["suite"]
            target = acquire._target(output, repo["inrelease"])
            network += _observe(origin + "/InRelease", target, deadline)
            raw = target.read_bytes()
            signed = acquire.auth.authenticate_inrelease(raw)
            if signed["keyring_sha256"] != manifest["keyring_sha256"]:
                raise LockContractError("observed archive keyring differs from lock")
            release, entries = validate_release(signed["release_payload"], suite=repo["suite"],
                                                architecture="amd64", now=current_time())
            issued = _date(release["Date"], "Date")
            if issued < floors[name, repo["suite"]]:
                raise LockContractError("authenticated Release Date rollback")
            index_name = "main/binary-amd64/Packages"
            plain, compressed = entries.get(index_name), entries.get(index_name + ".xz")
            if (plain is None or not 0 < plain[1] <= 128 * 1024 * 1024 or compressed is None
                    or not 0 < compressed[1] <= acquire._MAX_COMPRESSED):
                raise LockContractError("missing or oversized signed refresh index")
            if network + compressed[1] > acquire._MAX_NETWORK:
                raise LockContractError("refresh aggregate network limit exceeded")
            repo["inrelease"].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            repo["index"].update(size=plain[1], sha256=plain[0])
            transport = output / "_transport" / f"{name}-{repo['suite']}.xz"
            network += acquire._fetch(origin + "/main/binary-amd64/by-hash/SHA256/" + compressed[0],
                                      {"size": compressed[1], "sha256": compressed[0]}, transport, deadline)
            acquire._decompress(transport, acquire._target(output, repo["index"]), repo["index"], deadline)
            records = [p["record"] for p in stage["packages"] if p["suite"] == repo["suite"]]
            proof = validate_repository(signed["release_payload"], _read(output, repo["index"]), records,
                                        suite=repo["suite"], architecture="amd64", now=current_time())
            if "Valid-Until" in release:
                expiry = min(expiry, _date(release["Valid-Until"], "Valid-Until"))
            proof.update(signature_verified=True, keyring_sha256=signed["keyring_sha256"])
            repository_proofs.append({"stage": name, "suite": repo["suite"], "date": release["Date"],
                                      "valid_until": release.get("Valid-Until"), "signers": signed["signers"],
                                      **proof})
    validate_lock(candidate)
    policy = {"schema": "a4a-debian-refresh-policy-v1",
              "lock_sha256": hashlib.sha256(lock_bytes(candidate)).hexdigest(),
              "parent_lock_sha256": hashlib.sha256(lock_bytes(manifest)).hexdigest(),
              "observed_at_utc": observed.isoformat(), "usable_until_utc": expiry.isoformat()}
    validate_policy(candidate, policy, now=current_time())
    acquire._remaining(deadline)
    proof = {"schema": "a4a-debian-metadata-refresh-v1", "candidate_only": True,
             "packages_installed": False, "package_bytes_acquired": False, "network_bytes": network,
             "policy": policy, "repositories": repository_proofs}
    with (output / "lock.json").open("xb") as target:
        target.write(lock_bytes(candidate))
    with (output / "refresh.json").open("x") as target:
        json.dump(proof, target, sort_keys=True, indent=2)
        target.write("\n")
    pending = output / "policy.pending.json"
    with pending.open("x") as target:
        json.dump(policy, target, sort_keys=True, indent=2)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    os.link(pending, output / "policy.json")
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    candidate = actions.add_parser("candidate")
    candidate.add_argument("lock", type=Path)
    candidate.add_argument("previous_bundle", type=Path)
    candidate.add_argument("output", type=Path)
    check = actions.add_parser("check-policy")
    check.add_argument("lock", type=Path)
    check.add_argument("policy", type=Path)
    options = parser.parse_args()
    try:
        with options.lock.open("rb") as source:
            manifest = load_lock(source.read(_MAX_LOCK + 1))
        if options.action == "check-policy":
            validate_policy(manifest, load_policy(options.policy), now=datetime.now(timezone.utc))
        else:
            if not hasattr(signal, "setitimer"):
                raise LockContractError("refresh CLI requires Linux process deadline")
            previous = signal.signal(signal.SIGALRM, acquire._alarm)
            try:
                signal.setitimer(signal.ITIMER_REAL, acquire._SECONDS)
                refresh_candidate(manifest, options.previous_bundle, options.output)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)
    except (LockContractError, OSError, UnicodeDecodeError) as exc:
        print(f"Debian refresh failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
