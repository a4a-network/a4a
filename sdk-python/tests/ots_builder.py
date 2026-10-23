"""Build synthetic `.ots` fixtures with an independent format implementation.

Parsing in `a4a.timestamp` is checked against the reference library. This builder
supports arbitrary IDs and predetermined roots. Keeping two format implementations in
separate files ensures that any divergence becomes visible in the tests.
"""
import hashlib

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
ATT_BITCOIN = bytes.fromhex("0588960d73d71901")
ATT_PENDING = bytes.fromhex("83dfe30d2ef90c8e")


def varuint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def varbytes(b: bytes) -> bytes:
    return varuint(len(b)) + b


def attestation_bitcoin(height: int) -> bytes:
    return b"\x00" + ATT_BITCOIN + varbytes(varuint(height))


def attestation_pending(uri: str) -> bytes:
    return b"\x00" + ATT_PENDING + varbytes(varbytes(uri.encode()))


def build_ots(digest: bytes, *, height: int | None = None, salt: bytes = b"salt",
              pending_uri: str | None = None, extra_heights: tuple[int, ...] = (),
              prepend: bool = False) -> tuple[bytes, bytes]:
    """Build `.ots` for `digest`: append (or prepend) salt, SHA-256, attestations.

    Return `(file, root)`. With `prepend=True` and `salt`=<peer digest>, this creates
    the second leaf of the SAME two-leaf tree: sha256(salt || digest) equals the peer
    root where salt was appended. The root is the Bitcoin leaf message in INTERNAL
    byte order; the block header (Esplora) displays it reversed as `root[::-1].hex()`.
    """
    body = bytearray(MAGIC + varuint(1) + b"\x08" + digest)
    body += (b"\xf1" if prepend else b"\xf0") + varbytes(salt)
    body += b"\x08"                           # sha256
    root = hashlib.sha256((salt + digest) if prepend else (digest + salt)).digest()
    leaves: list[bytes] = []
    if pending_uri is not None:
        leaves.append(attestation_pending(pending_uri))
    for h in (height, *extra_heights):
        if h is not None:
            leaves.append(attestation_bitcoin(h))
    if not leaves:
        raise ValueError("at least one attestation is required")
    for leaf in leaves[:-1]:
        body += b"\xff" + leaf                # fork
    body += leaves[-1]
    return bytes(body), root


def display_root(root: bytes) -> str:
    return root[::-1].hex()
