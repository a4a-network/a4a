"""A4A event cryptography: event IDs (SHA-256) and Schnorr signatures (BIP-340)."""
import hashlib
import json

from coincurve import PrivateKey, PublicKeyXOnly


def compute_event_id(pubkey: str, created_at: int, kind: int,
                     tags: list[list[str]], content: str) -> str:
    """Return sha256 of canonical [0, pubkey, created_at, kind, tags, content]."""
    payload = json.dumps([0, pubkey, created_at, kind, tags, content],
                         separators=(",", ":"), ensure_ascii=False)
    # Keep this low-level hash helper total for escaped lone-surrogate fixtures.
    # It can hash those nonstandard bytes, and a signature over that hash can verify.
    # That does not make the strings valid A4A Unicode: Event.sign rejects them
    # and Event.verify returns False before computing the hash. Using surrogatepass
    # here avoids an encoding exception for callers inspecting malformed wire data.
    return hashlib.sha256(payload.encode("utf-8", "surrogatepass")).hexdigest()


def sign(event_id_hex: str, privkey_hex: str) -> str:
    """Return a 64-byte hex Schnorr signature over a 32-byte event id."""
    priv = PrivateKey(bytes.fromhex(privkey_hex))
    return priv.sign_schnorr(bytes.fromhex(event_id_hex)).hex()


_HEX = "0123456789abcdef"


def _canonical(value: str, length: int) -> bool:
    return len(value) == length and all(c in _HEX for c in value)


def verify(event_id_hex: str, sig_hex: str, pubkey_hex: str) -> bool:
    """Verify a Schnorr signature; malformed input returns False, never an exception.

    Argument shape is checked before cryptography. bytes.fromhex silently ignores
    whitespace, so without this guard one key had infinitely many valid spellings:
    signatures verified while string comparisons and dictionary keys saw different
    identities (2026-08-29 internal audit, F7). Event parsing rejects this earlier;
    this is the second boundary for callers that invoke crypto.verify directly.
    """
    if not (_canonical(pubkey_hex, 64) and _canonical(sig_hex, 128)
            and _canonical(event_id_hex, 64)):
        return False
    try:
        pub = PublicKeyXOnly(bytes.fromhex(pubkey_hex))
        return pub.verify(bytes.fromhex(sig_hex), bytes.fromhex(event_id_hex))
    except Exception:
        return False
