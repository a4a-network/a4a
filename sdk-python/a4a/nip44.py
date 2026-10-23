"""A4A E2EE v2 end-to-end encryption for event content.

Implements A4A E2EE v2: secp256k1 ECDH using the shared point's x-coordinate
WITHOUT additional hashing. This differs critically from `coincurve.PrivateKey.ecdh`,
which returns sha256(compressed_pubkey); here `PublicKey.multiply` computes the shared
point and its raw x-coordinate is used. HKDF extract/expand (HMAC-SHA256) derives the
conversation and per-message keys, followed by custom power-of-two padding, ChaCha20
(RFC 8439, counter=0), and HMAC-SHA256 over `nonce || ciphertext` (encrypt-then-MAC).
Payload format: base64(0x02 || nonce (32B) || ciphertext || mac (32B)).

Correctness is checked against the canonical E2EE v2 test vectors
(`nip44_vectors.json`, SHA-256 269ed0f6...5040); see tests/test_nip44.py.

Metadata privacy: E2EE v2 hides only event `content`. Without a sealed envelope, the relay and
every observer can still see that pubkey A contacted pubkey B through the author and
`p` tag. A4A Sealed Envelope is implemented separately in `a4a.giftwrap` and enabled by
default in `Agent.send_private_message(..., wrap=True)`. It hides the sender, while
recipient, envelope time, and envelope size remain visible.
"""
import base64
import hashlib
import hmac
import math
import os

from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

VERSION = 0x02

_MIN_PLAINTEXT_SIZE = 1
_MAX_PLAINTEXT_SIZE = 65535  # NIP-44 v2 plaintext MUST be 1..65535 bytes (u16 prefix).
_MIN_PAYLOAD_B64_LEN = 132
_MIN_PAYLOAD_BYTES = 99


class Nip44Error(Exception):
    """Payload is malformed, version is unsupported, or MAC verification failed."""


# --- ECDH and keys -------------------------------------------------------

def _conversation_key(privkey_hex: str, pubkey_hex: str) -> bytes:
    """conversation_key = HKDF-extract(salt="nip44-v2", IKM=shared_x).

    shared_x is the 32-byte x-coordinate of privkey * pubkey WITHOUT hashing.
    The BIP-340 x-only pubkey is expanded with even-parity prefix 0x02, the standard
    assumption used by Nostr/NIP-44 implementations.
    """
    try:
        priv = PrivateKey(bytes.fromhex(privkey_hex))
        pub_full = PublicKey(bytes.fromhex("02" + pubkey_hex))
        shared_point = pub_full.multiply(priv.secret)
        shared_x = shared_point.format(compressed=True)[1:]
    except Exception as e:
        raise Nip44Error(f"failed to compute ECDH: {e}") from e
    # HKDF extract with HMAC-SHA256: PRK = HMAC-Hash(salt, IKM).
    return hmac.new(b"nip44-v2", shared_x, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def _message_keys(conversation_key: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
    if len(conversation_key) != 32:
        raise Nip44Error("invalid conversation_key length")
    if len(nonce) != 32:
        raise Nip44Error("invalid nonce length")
    okm = _hkdf_expand(conversation_key, nonce, 76)
    return okm[0:32], okm[32:44], okm[44:76]


def _chacha20(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    # cryptography expects 16 bytes: 4-byte little-endian counter (0) + 12-byte nonce.
    full_nonce = b"\x00\x00\x00\x00" + nonce12
    encryptor = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None).encryptor()
    return encryptor.update(data) + encryptor.finalize()


# --- Padding -------------------------------------------------------------

def _calc_padded_len(unpadded_len: int) -> int:
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (math.floor(math.log2(unpadded_len - 1)) + 1)
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * ((unpadded_len - 1) // chunk + 1)


def _pad(plaintext: str) -> bytes:
    unpadded = plaintext.encode("utf-8")
    n = len(unpadded)
    if n < _MIN_PLAINTEXT_SIZE or n > _MAX_PLAINTEXT_SIZE:
        raise Nip44Error("invalid plaintext length")
    prefix = n.to_bytes(2, "big")
    suffix = b"\x00" * (_calc_padded_len(n) - n)
    return prefix + unpadded + suffix


def _unpad(padded: bytes) -> str:
    # There is intentionally no separate `len(padded) < 2` branch. A short buffer
    # yields unpadded_len == 0 or a length mismatch and the check below rejects it with
    # the same message. A 2026-08-29 mutation pass proved that the separate branch was
    # dead: removing it changed no input's behavior.
    unpadded_len = int.from_bytes(padded[0:2], "big")
    unpadded = padded[2:2 + unpadded_len]
    if (unpadded_len == 0 or len(unpadded) != unpadded_len
            or len(padded) != 2 + _calc_padded_len(unpadded_len)):
        raise Nip44Error("invalid padding")
    try:
        return unpadded.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Nip44Error(f"invalid UTF-8: {e}") from e


# --- MAC ---------------------------------------------------------------

def _hmac_aad(key: bytes, message: bytes, aad: bytes) -> bytes:
    if len(aad) != 32:
        raise Nip44Error("AAD (nonce) must be 32 bytes")
    return hmac.new(key, aad + message, hashlib.sha256).digest()


# --- Public API ----------------------------------------------------------

def _encrypt_with_nonce(plaintext: str, conv_key: bytes, nonce: bytes) -> str:
    """Encrypt plaintext with a prepared conversation key and explicit nonce.

    TESTS ONLY, for deterministic nonces from official NIP-44 vectors. This helper is
    not exported and must not be used by applications. Nonce reuse under a stream
    cipher such as ChaCha20 is catastrophic: it reveals the XOR of two plaintexts and
    permits forgery of the MAC-independent portion. Production nonces ALWAYS come from
    CSPRNG `os.urandom(32)`; see public `encrypt()`.
    """
    chacha_key, chacha_nonce, hmac_key = _message_keys(conv_key, nonce)
    padded = _pad(plaintext)
    ciphertext = _chacha20(chacha_key, chacha_nonce, padded)
    mac = _hmac_aad(hmac_key, ciphertext, nonce)
    return base64.b64encode(bytes([VERSION]) + nonce + ciphertext + mac).decode("ascii")


def encrypt(plaintext: str, sender_privkey_hex: str, recipient_pubkey_hex: str) -> str:
    """Encrypt plaintext for recipient_pubkey_hex and return a base64 NIP-44 v2 payload.

    The nonce ALWAYS comes from CSPRNG `os.urandom(32)`. The public API deliberately
    accepts no nonce parameter to prevent catastrophic reuse under ChaCha20; tests use
    `_encrypt_with_nonce` for deterministic official vectors.
    """
    conv_key = _conversation_key(sender_privkey_hex, recipient_pubkey_hex)
    nonce = os.urandom(32)
    return _encrypt_with_nonce(plaintext, conv_key, nonce)


def _decrypt_with_key(payload: str, conv_key: bytes) -> str:
    """Decrypt a NIP-44 v2 payload with a prepared conversation key.

    Used by public `decrypt()`, which first derives conv_key through ECDH, and by the
    official `invalid.decrypt` vectors, where each conversation key is supplied directly.
    """
    if not payload or payload[0] == "#":
        raise Nip44Error("unknown encryption version ('#' flag)")
    if len(payload) < _MIN_PAYLOAD_B64_LEN:
        raise Nip44Error("payload is too short")
    try:
        data = base64.b64decode(payload, validate=True)
    except Exception as e:
        raise Nip44Error(f"invalid base64: {e}") from e
    if len(data) < _MIN_PAYLOAD_BYTES:
        raise Nip44Error("decoded payload is too short")
    version = data[0]
    if version != VERSION:
        raise Nip44Error(f"unsupported encryption version: {version}")
    nonce = data[1:33]
    ciphertext = data[33:len(data) - 32]
    mac = data[len(data) - 32:]

    chacha_key, chacha_nonce, hmac_key = _message_keys(conv_key, nonce)
    calculated_mac = _hmac_aad(hmac_key, ciphertext, nonce)
    if not hmac.compare_digest(calculated_mac, mac):
        raise Nip44Error("MAC mismatch: message was forged or the key is wrong")
    padded_plaintext = _chacha20(chacha_key, chacha_nonce, ciphertext)
    return _unpad(padded_plaintext)


def decrypt(payload: str, recipient_privkey_hex: str, sender_pubkey_hex: str) -> str:
    """Decrypt a NIP-44 v2 payload supplied as UNTRUSTED input.

    Any malformed base64, version, length, MAC, padding, or UTF-8 raises a clean
    Nip44Error without crashing or hanging.
    """
    conv_key = _conversation_key(recipient_privkey_hex, sender_pubkey_hex)
    return _decrypt_with_key(payload, conv_key)
