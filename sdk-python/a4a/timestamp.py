"""Trusted timestamps (§4.1 v0.4, option B): verify OpenTimestamps proofs.

What a timestamp proves: a notary (our relay or anyone else) places an event ID in a
tree whose root enters a Bitcoin block. A kind-1040 event (NIP-03) carries an `.ots`
proof: the operation chain from the ID to the root and the block height. By checking
the chain and matching the root to the block header, the reader obtains time T from
that header and proof that the ID was included. This establishes an upper bound on
when the data defining the ID existed relative to block inclusion, not the exact UTC
publication time. A Nostr signature is not part of the ID, so its creation time is
not proven. Two timestamps neither order events nor prove historical authority.
`created_at` remains author-declared; see specification §2.9.

The dependency-free `.ots` parser is practical because the format is small: magic,
varuint, a tree of sha1/ripemd160/sha256/append/prepend/reverse/hexlify operations,
and attestations with 8-byte tags. Requiring the library stack (`opentimestamps`,
LGPL3, plus `python-bitcoinlib`, whose metadata reports an UNKNOWN license, about
10 MB total) would burden clients unnecessarily, and its CLI does not start on
Windows because it looks for libssl. The parser is checked against the reference
`hello-world.txt.ots` from opentimestamps-client (block 358391) and a recent pending
calendar timestamp, both stored under `tests/data/`.

What is timestamped (format fixed on 2026-09-04): the proof digest is the event ID's
**raw 32 bytes**. NIP-03 says it “MUST prove the referenced e event id as its digest,”
and nostr-ots does the same. sha256(id) is explicitly rejected. Our node timestamps
only historical kinds (`NOTARISED_KINDS`), once per hour, and publishes kind 1040 only
after Bitcoin confirmation. Consequently, `pending` is rare for our notary and
normal for others.

Block headers come from Esplora (blockstream.info) by default, with an on-disk cache.
Only 80 bytes per block would suffice; we store its root and time. The endpoint is
replaceable, and tests use `StaticHeaders`. If the source is unavailable, the result
is `unverifiable` with the network reason: the proof is unverified, not disproven.
"""
import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from .event import Event

KIND_OTS_ATTESTATION = 1040

#: Kinds timestamped by our notary: historical records only, matching the relay's
#: PROTECTED_KINDS. Other kinds receive `absent (kind not notarised)`.
NOTARISED_KINDS = frozenset({31000, 31007, 31004, 31005, 31020, 31021})

_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
_MAJOR_VERSION = 1
_TAG_ATTESTATION = 0x00
_TAG_FORK = 0xFF
_CRYPT_OPS = {0x02: ("sha1", 20), 0x03: ("ripemd160", 20), 0x08: ("sha256", 32)}
_TAG_KECCAK = 0x67
_TAG_APPEND, _TAG_PREPEND, _TAG_REVERSE, _TAG_HEXLIFY = 0xF0, 0xF1, 0xF2, 0xF3
_ATT_BITCOIN = bytes.fromhex("0588960d73d71901")
_ATT_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
_ATT_TAG_SIZE = 8
_MAX_MSG = 4096
_MAX_PAYLOAD = 8192
_MAX_URI = 1000
_MAX_DEPTH = 256


class OtsError(ValueError):
    """The proof cannot be parsed or violates the format."""


@dataclass(frozen=True)
class Attestation:
    kind: Literal["bitcoin", "pending", "unknown"]
    msg: bytes                    # Message at this leaf; Bitcoin root in internal byte order.
    height: int | None = None
    uri: str = ""


@dataclass(frozen=True)
class OtsProof:
    digest_op: str
    digest: bytes
    attestations: tuple[Attestation, ...]


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise OtsError("truncated proof")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def byte(self) -> int:
        return self.bytes(1)[0]

    def varuint(self) -> int:
        value, shift = 0, 0
        while True:
            b = self.byte()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise OtsError("varuint exceeds 64 bits")

    def varbytes(self, max_len: int, min_len: int = 0) -> bytes:
        n = self.varuint()
        if n > max_len or n < min_len:
            raise OtsError(f"varbytes: length {n} is outside [{min_len}, {max_len}]")
        return self.bytes(n)

    def eof(self) -> bool:
        return self.pos >= len(self.data)


def _apply_op(tag: int, reader: _Reader, msg: bytes) -> bytes:
    if tag in _CRYPT_OPS:
        name, _ = _CRYPT_OPS[tag]
        return hashlib.new(name, msg).digest()
    if tag == _TAG_KECCAK:
        raise OtsError("keccak256 operation is not supported")
    if tag in (_TAG_APPEND, _TAG_PREPEND):
        arg = reader.varbytes(_MAX_MSG, min_len=1)
        out = msg + arg if tag == _TAG_APPEND else arg + msg
    elif tag == _TAG_REVERSE:
        if not msg:
            raise OtsError("cannot reverse an empty message")
        out = msg[::-1]
    elif tag == _TAG_HEXLIFY:
        if not msg:
            raise OtsError("cannot hexlify an empty message")
        out = msg.hex().encode("ascii")
    else:
        raise OtsError(f"unknown operation 0x{tag:02x}")
    if len(out) > _MAX_MSG:
        raise OtsError("message exceeds 4096 bytes")
    return out


def _read_attestation(reader: _Reader, msg: bytes) -> Attestation:
    tag = reader.bytes(_ATT_TAG_SIZE)
    payload = _Reader(reader.varbytes(_MAX_PAYLOAD))
    if tag == _ATT_BITCOIN:
        height = payload.varuint()
        if not payload.eof():
            raise OtsError("trailing bytes in Bitcoin attestation")
        return Attestation("bitcoin", msg, height=height)
    if tag == _ATT_PENDING:
        uri = payload.varbytes(_MAX_URI).decode("utf-8", "replace")
        if not payload.eof():
            raise OtsError("trailing bytes in calendar attestation")
        return Attestation("pending", msg, uri=uri)
    return Attestation("unknown", msg)


def _read_timestamp(reader: _Reader, msg: bytes, out: list[Attestation], depth: int) -> None:
    if depth <= 0:
        raise OtsError("proof tree exceeds depth 256")
    tag = reader.byte()
    while tag == _TAG_FORK:
        _read_branch(reader, reader.byte(), msg, out, depth)
        tag = reader.byte()
    _read_branch(reader, tag, msg, out, depth)


def _read_branch(reader: _Reader, tag: int, msg: bytes, out: list[Attestation], depth: int) -> None:
    if tag == _TAG_ATTESTATION:
        out.append(_read_attestation(reader, msg))
        return
    _read_timestamp(reader, _apply_op(tag, reader, msg), out, depth - 1)


def parse_ots(data: bytes) -> OtsProof:
    """Parse an `.ots` detached timestamp file, raising OtsError on any violation."""
    reader = _Reader(data)
    if reader.bytes(len(_MAGIC)) != _MAGIC:
        raise OtsError("not an OpenTimestamps file (magic is missing)")
    major = reader.varuint()
    if major != _MAJOR_VERSION:
        raise OtsError(f"format version {major} is not supported")
    op_tag = reader.byte()
    if op_tag not in _CRYPT_OPS:
        raise OtsError(f"unknown file hash operation 0x{op_tag:02x}")
    name, digest_len = _CRYPT_OPS[op_tag]
    digest = reader.bytes(digest_len)
    attestations: list[Attestation] = []
    _read_timestamp(reader, digest, attestations, _MAX_DEPTH)
    if not reader.eof():
        raise OtsError("trailing data after the proof")
    return OtsProof(name, digest, tuple(attestations))


# --- Block-header sources -------------------------------------------------------

class HeaderSourceError(Exception):
    """A block header was unavailable due to network, response, or cache failure."""


class HeaderSource(Protocol):
    def block(self, height: int) -> tuple[str, int]:
        """Return `(explorer-style merkle_root hex, Unix block time)`."""


class StaticHeaders:
    """Dictionary-backed headers for tests and fully offline verification."""

    def __init__(self, blocks: dict[int, tuple[str, int]]):
        self._blocks = dict(blocks)

    def block(self, height: int) -> tuple[str, int]:
        try:
            return self._blocks[height]
        except KeyError:
            raise HeaderSourceError(f"block header {height} is not in the set") from None


class CachedHeaders:
    """Disk cache for immutable headers, avoiding repeated network requests."""

    def __init__(self, path: Path | None = None):
        self.path = path or Path(os.environ.get("A4A_HOME", str(Path.home() / ".a4a"))) / "headers.json"
        self._data: dict[str, list] = {}
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self._data = loaded
        except (OSError, ValueError):
            pass

    def get(self, height: int) -> tuple[str, int] | None:
        entry = self._data.get(str(height))
        if (isinstance(entry, list) and len(entry) == 2 and isinstance(entry[0], str)
                and isinstance(entry[1], int)):
            return entry[0], entry[1]
        return None

    def put(self, height: int, merkle_root: str, block_time: int) -> None:
        self._data[str(height)] = [merkle_root, block_time]
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            pass  # The cache is an optimization, not a source of truth.


class EsploraHeaders:
    """Headers through the Esplora API (blockstream.info by default); two GETs per block."""

    def __init__(self, base_url: str = "https://blockstream.info/api", timeout: float = 10.0,
                 cache: CachedHeaders | None = None, _opener=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cache = cache
        self._opener = _opener or self._http_get

    def _http_get(self, url: str) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": "a4a-sdk"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return r.read().decode("utf-8")

    def block(self, height: int) -> tuple[str, int]:
        if self.cache is not None and (hit := self.cache.get(height)) is not None:
            return hit
        try:
            block_hash = self._opener(f"{self.base_url}/block-height/{height}").strip()
            if len(block_hash) != 64 or any(c not in "0123456789abcdef" for c in block_hash):
                raise HeaderSourceError(
                    f"Esplora returned an invalid block hash: {block_hash[:40]!r}")
            header = json.loads(self._opener(f"{self.base_url}/block/{block_hash}"))
            root, ts = header["merkle_root"], header["timestamp"]
            if not isinstance(root, str) or not isinstance(ts, int):
                raise HeaderSourceError(
                    "Esplora returned a header without merkle_root/timestamp")
        except HeaderSourceError:
            raise
        except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as e:
            raise HeaderSourceError(
                f"header source is unavailable: {type(e).__name__}: {e}") from e
        if self.cache is not None:
            self.cache.put(height, root, ts)
        return root, ts


# --- Timestamp verdict ---------------------------------------------------------

@dataclass(frozen=True)
class StampVerdict:
    """Describe what the timestamp proves; only `confirmed` supplies time T."""
    state: Literal["confirmed", "pending", "absent", "unverifiable"]
    block_height: int | None = None
    block_time: int | None = None
    detail: str = ""

    @property
    def confirmed(self) -> bool:
        return self.state == "confirmed"


def stamp_targets(stamp: Event) -> list[str]:
    """Return event IDs named by `e` tags (NIP-03: `["e", <id>, <relay>]`)."""
    return [t[1] for t in stamp.tags if len(t) >= 2 and t[0] == "e"]


def verify_stamp(stamp: Event, target_id: str, headers: HeaderSource) -> StampVerdict:
    """Verify a kind-1040 event for `target_id`.

    Check the format, digest equal to the ID, operation chain to the block, and root.
    Nothing is trusted implicitly: the notary signature is not a time source (the
    block supplies time), and the kind-1040 event is only a container. Any format
    defect produces `unverifiable` with a reason rather than an exception because
    the network-supplied timestamp is untrusted.
    """
    if stamp.kind != KIND_OTS_ATTESTATION:
        return StampVerdict("unverifiable", detail=f"event kind is {stamp.kind}, not 1040")
    if target_id not in stamp_targets(stamp):
        return StampVerdict(
            "unverifiable", detail="timestamp does not reference this event with an e tag")
    try:
        proof = parse_ots(base64.b64decode(stamp.content, validate=True))
    except (OtsError, ValueError) as e:
        return StampVerdict("unverifiable", detail=f"proof cannot be parsed: {e}")
    target = bytes.fromhex(target_id)
    if proof.digest != target:
        if proof.digest == hashlib.sha256(target).digest():
            return StampVerdict("unverifiable", detail=(
                "proof digest is sha256(id), but the protocol requires the raw 32-byte ID "
                "(NIP-03, A4A format dated 2026-09-04)"))
        return StampVerdict("unverifiable", detail="proof digest does not equal the event ID")
    bitcoin = [a for a in proof.attestations if a.kind == "bitcoin"]
    pending = [a for a in proof.attestations if a.kind == "pending"]
    if not bitcoin:
        if pending:
            return StampVerdict("pending", detail=(
                f"timestamp is waiting for a Bitcoin block (calendar {pending[0].uri}); "
                "retry in 1–3 hours"))
        return StampVerdict(
            "unverifiable", detail="proof contains neither Bitcoin nor calendar attestation")
    best: StampVerdict | None = None
    problems: list[str] = []
    for att in sorted(bitcoin, key=lambda a: a.height or 0):
        try:
            root, block_time = headers.block(att.height)
        except HeaderSourceError as e:
            problems.append(str(e))
            continue
        if att.msg[::-1].hex() != root.lower():
            problems.append(f"tree root does not match block {att.height} merkle_root")
            continue
        verdict = StampVerdict("confirmed", block_height=att.height, block_time=block_time,
                               detail=f"block {att.height}")
        if best is None or block_time < (best.block_time or 0):
            best = verdict
    if best is not None:
        return best
    return StampVerdict(
        "unverifiable", detail="; ".join(problems) or "block header was not obtained")


def block_time_of(verdict: StampVerdict) -> int | None:
    return verdict.block_time if verdict.confirmed else None


__all__ = [
    "KIND_OTS_ATTESTATION", "NOTARISED_KINDS", "OtsError", "OtsProof", "Attestation",
    "parse_ots", "HeaderSource", "HeaderSourceError", "StaticHeaders", "CachedHeaders",
    "EsploraHeaders", "StampVerdict", "verify_stamp", "stamp_targets", "block_time_of",
]
