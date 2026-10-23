"""Bounded, pure consistency checks for a future single-architecture Debian lock.

This is NOT a signature verifier, dependency solver, downloader, or freshness
policy for repositories without Valid-Until. The caller must authenticate the
Release payload with its trusted keyring, supply independently resolved package
requests, call the byte verifier on actual .deb bytes, and enforce its own
refresh policy. Do not
pass a raw clearsigned InRelease as a Release payload.
"""

from collections.abc import Mapping
from datetime import datetime
from email.utils import parsedate_to_datetime
import hashlib
import re


_FIELDS = ("Package", "Version", "Architecture", "Filename", "Size", "SHA256")
_SUITES = {"bookworm", "bookworm-updates", "bookworm-security",
           "trixie", "trixie-updates", "trixie-security"}
_ARCHITECTURES = {"amd64", "arm64"}
_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]+\Z")
_VERSION = re.compile(r"(?:[0-9]+:)?[0-9][A-Za-z0-9.+:~\-]*\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SIZE = re.compile(r"[1-9][0-9]{0,19}\Z")
_INDEX_SIZE = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")
_PATH = re.compile(r"pool/[A-Za-z0-9_+./~\-]+\.deb\Z")
_MAX_PACKAGES = 100_000
_MAX_LINE = 128 * 1024
_MAX_PACKAGE_BYTES = 128 * 1024 * 1024
_READ_SIZE = 65_536


class LockContractError(ValueError):
    """The proposed package lock contradicts repository or resolver evidence."""


def _text(payload, label, limit):
    if not isinstance(payload, bytes) or len(payload) > limit or not payload:
        raise LockContractError(f"invalid or oversized {label}")
    try:
        value = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LockContractError(f"invalid UTF-8 in {label}") from exc
    if any(ord(c) < 32 and c not in "\n\r\t" for c in value):
        raise LockContractError(f"control character in {label}")
    value = value.replace("\r\n", "\n")
    if "\r" in value:
        raise LockContractError(f"bare carriage return in {label}")
    return value


def _stanzas(text, label):
    """Parse Debian control fields, rejecting ambiguity instead of overwriting."""
    fields = {}
    previous = None
    count = 0
    stanza_size = 0
    for line in text.split("\n"):
        stanza_size += len(line)
        if len(line) > _MAX_LINE or stanza_size > 4 * 1024 * 1024:
            raise LockContractError(f"oversized field in {label}")
        if not line:
            if fields:
                count += 1
                if count > _MAX_PACKAGES:
                    raise LockContractError(f"too many stanzas in {label}")
                yield fields
            fields, previous, stanza_size = {}, None, 0
        elif line[0] in " \t":
            if previous is None:
                raise LockContractError(f"orphan continuation in {label}")
            fields[previous] += "\n" + line[1:]
        else:
            key, separator, value = line.partition(":")
            if not separator or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", key):
                raise LockContractError(f"malformed field in {label}")
            if key.lower() in {field.lower() for field in fields}:
                raise LockContractError(f"duplicate field {key} in {label}")
            if len(key) > 128 or len(fields) >= 128:
                raise LockContractError(f"too many or oversized field names in {label}")
            fields[key] = value.strip(" \t")
            previous = key
    if fields:
        if count >= _MAX_PACKAGES:
            raise LockContractError(f"too many stanzas in {label}")
        yield fields


def _date(value, label):
    try:
        result = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise LockContractError(f"invalid {label}") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise LockContractError(f"{label} requires timezone")
    return result


def _identity(record):
    if not isinstance(record, Mapping):
        raise LockContractError("package record must be a mapping")
    if any(not isinstance(record.get(field), str) for field in _FIELDS):
        raise LockContractError("missing or non-string package field")
    if any(len(record[field]) > 4096 for field in _FIELDS):
        raise LockContractError("oversized package field")
    if not _NAME.fullmatch(record["Package"]) or not _VERSION.fullmatch(record["Version"]):
        raise LockContractError("invalid package name or version")
    if record["Architecture"] not in _ARCHITECTURES | {"all"}:
        raise LockContractError("unsupported package architecture")
    filename = record["Filename"]
    if not _PATH.fullmatch(filename) or any(part in ("", ".", "..") for part in filename.split("/")):
        raise LockContractError("noncanonical package Filename")
    if not _SIZE.fullmatch(record["Size"]) or not _HASH.fullmatch(record["SHA256"]):
        raise LockContractError("invalid package Size or SHA256")
    return record["Package"], record["Version"], record["Architecture"]


def _locked(records):
    if not isinstance(records, (list, tuple)) or len(records) > _MAX_PACKAGES:
        raise LockContractError("invalid or oversized locked package list")
    result = {}
    names = set()
    for record in records:
        identity = _identity(record)
        if identity[0] in names:
            raise LockContractError("duplicate locked package name")
        names.add(identity[0])
        result[identity] = record
    return result


def validate_release(release_payload, *, suite, architecture, now):
    """Check authenticated Release identity, freshness and SHA256 entries.

    The caller must authenticate the payload first; this pure parser does not
    verify signatures. Acquisition uses it before fetching a large index.
    """
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise LockContractError("now requires timezone")
    if not isinstance(suite, str) or not isinstance(architecture, str) or suite not in _SUITES or architecture not in _ARCHITECTURES:
        raise LockContractError("unsupported suite or architecture")
    releases = list(_stanzas(_text(release_payload, "Release", 8 * 1024 * 1024), "Release"))
    if len(releases) != 1:
        raise LockContractError("Release must contain exactly one stanza")
    release = releases[0]
    if release.get("Codename") != suite:
        raise LockContractError("Release suite mismatch")
    if architecture not in release.get("Architectures", "").split():
        raise LockContractError("Release architecture mismatch")
    issued = _date(release.get("Date"), "Date")
    if issued > now:
        raise LockContractError("Release Date is in the future")
    expiry = release.get("Valid-Until")
    if expiry is None and suite.endswith("-security"):
        raise LockContractError("security Release requires Valid-Until")
    if expiry is not None:
        deadline = _date(expiry, "Valid-Until")
        if deadline <= issued:
            raise LockContractError("Valid-Until does not follow Date")
        if now >= deadline:
            raise LockContractError("Release expired")
    entries = {}
    for line in release.get("SHA256", "").splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 3 or not _HASH.fullmatch(parts[0]) or not _INDEX_SIZE.fullmatch(parts[1]):
            raise LockContractError("malformed Release SHA256 entry")
        digest, size, path = parts
        if path in entries:
            raise LockContractError("duplicate Release SHA256 path")
        entries[path] = digest, int(size)
    return release, entries


def validate_repository(release_payload, packages_index, locked_packages, *, suite, architecture, now):
    """Match selected lock records to one Release-bound uncompressed index.

    An empty selection is allowed, but still validates the Release and index.
    It says nothing about whether the complete installation closure is present.
    Multiarch locks and suites outside the explicit allowlist are not supported.
    """
    release, entries = validate_release(release_payload, suite=suite, architecture=architecture, now=now)
    expiry = release.get("Valid-Until")
    expected = entries.get(f"main/binary-{architecture}/Packages")
    index_text = _text(packages_index, "Packages index", 128 * 1024 * 1024)
    if expected != (hashlib.sha256(packages_index).hexdigest(), len(packages_index)):
        raise LockContractError("Packages index size or SHA256 mismatch")
    locked = _locked(locked_packages)
    seen = set()
    matched = set()
    for record in _stanzas(index_text, "Packages index"):
        identity = _identity(record)
        if identity[2] not in (architecture, "all"):
            raise LockContractError("Packages index architecture mismatch")
        if identity in seen:
            raise LockContractError("duplicate Packages index identity")
        seen.add(identity)
        if identity in locked:
            if any(record[field] != locked[identity][field] for field in _FIELDS):
                raise LockContractError("locked package fields differ from Packages index")
            matched.add(identity)
    if matched != set(locked):
        raise LockContractError("locked package absent from Packages index")
    return {"package_count": len(locked), "expiry_declared": expiry is not None,
            "valid_until_utc": _date(expiry, "Valid-Until").isoformat() if expiry is not None else None,
            "signature_verified": False, "package_bytes_verified": False}


def validate_closure(locked_packages, resolved_requests):
    """Compare a single-architecture lock to a separate resolver's exact set.

    This does not compute dependencies or prove the resolver's correctness.
    """
    locked = _locked(locked_packages)
    architectures = {identity[2] for identity in locked if identity[2] != "all"}
    if len(architectures) > 1:
        raise LockContractError("multiarch closure is unsupported")
    if not isinstance(resolved_requests, (list, tuple)) or len(resolved_requests) > _MAX_PACKAGES:
        raise LockContractError("invalid or oversized resolved requests")
    requests = set()
    names = set()
    for request in resolved_requests:
        if not isinstance(request, str) or len(request) > 4096:
            raise LockContractError("resolver request must be a bounded string")
        name, separator, version = request.partition("=")
        if not separator or not _NAME.fullmatch(name) or not _VERSION.fullmatch(version):
            raise LockContractError("invalid resolver package request")
        if name in names:
            raise LockContractError("duplicate resolver package name")
        names.add(name)
        requests.add(request)
    if requests != {f"{name}={version}" for name, version, _ in locked}:
        raise LockContractError("locked packages differ from resolved closure")
    return {"package_count": len(locked)}


def verify_package_stream(record, stream):
    """Hash a binary stream from its current position through EOF, boundedly.

    Metadata must be authenticated separately before this result is trusted.
    The caller owns the stream and must open its intended immutable file safely,
    start at offset zero, and enforce network/read timeouts when applicable.
    This function does not open paths, extract archives, install packages, close
    streams, or authenticate signatures. Verified bytes must not be replaced
    between this check and their use. A package over 128 MiB fails before reads.
    """
    _identity(record)
    size, expected_hash = int(record["Size"]), record["SHA256"]
    if size > _MAX_PACKAGE_BYTES:
        raise LockContractError("package exceeds byte-verification limit")
    read = getattr(stream, "read", None)
    if not callable(read):
        raise LockContractError("package stream must be readable")
    digest = hashlib.sha256()
    total = 0
    while True:
        requested = min(_READ_SIZE, size - total + 1)
        try:
            chunk = read(requested)
        except (OSError, ValueError) as exc:
            raise LockContractError("package stream read failed") from exc
        if not isinstance(chunk, bytes):
            raise LockContractError("package stream must return binary bytes")
        if len(chunk) > requested:
            raise LockContractError("package stream exceeded requested read size")
        if not chunk:
            break
        total += len(chunk)
        if total > size:
            raise LockContractError("package Size mismatch: extra bytes")
        digest.update(chunk)
    if total != size:
        raise LockContractError("package Size mismatch: truncated stream")
    if digest.hexdigest() != expected_hash:
        raise LockContractError("package SHA256 mismatch")
    return {"size": total, "sha256": expected_hash,
            "package_bytes_verified": True, "signature_verified": False}
