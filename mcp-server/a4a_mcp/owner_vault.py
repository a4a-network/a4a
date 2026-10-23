"""Password-encrypted owner keys, independent of profile storage.

Version 1 has exactly: version, algorithm, owner_pubkey, salt, nonce, ciphertext.
Binary fields use canonical standard base64. AAD is the ASCII encoding of the
version/algorithm/owner_pubkey JSON object with sorted keys and compact separators.
Scrypt parameters are fixed by the version, never supplied by the payload.

No profile, filesystem, environment, or network access is performed. Callers own
storage permissions and interactive password input. Python objects and crypto
backends may retain secret copies; guaranteed memory zeroization is not provided.
"""

import base64
import hmac
import json
import re
import secrets
import unicodedata

import a4a
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

__all__ = ["OwnerVaultError", "seal_owner_key", "open_owner_key"]

_VERSION = 1
_ALGORITHM = "scrypt-aes256gcm"
_FIELDS = frozenset({
    "version", "algorithm", "owner_pubkey", "salt", "nonce", "ciphertext",
})
_BINARY_SIZES = {"salt": 16, "nonce": 12, "ciphertext": 48}
_HEX_KEY = re.compile(r"[0-9a-f]{64}")
_MAX_PASSWORD_BYTES = 1024
_MIN_SEAL_CHARACTERS = 16
_AUTH_ERROR = "Owner vault authentication failed."


class OwnerVaultError(ValueError):
    """An owner vault or its credentials cannot be used."""


def _password_bytes(password: str, *, sealing: bool) -> bytes:
    if type(password) is not str:
        raise OwnerVaultError("Invalid owner vault password.")
    normalized = unicodedata.normalize("NFKC", password)
    if not 0 < len(normalized) <= _MAX_PASSWORD_BYTES:
        raise OwnerVaultError("Invalid owner vault password.")
    if sealing and len(normalized) < _MIN_SEAL_CHARACTERS:
        raise OwnerVaultError(
            "Owner vault password requires at least 16 normalized characters.")
    try:
        encoded = normalized.encode("utf-8")
    except UnicodeError:
        raise OwnerVaultError("Invalid owner vault password.") from None
    if len(encoded) > _MAX_PASSWORD_BYTES:
        raise OwnerVaultError("Invalid owner vault password.")
    return encoded


def _canonical_key(value: str) -> bool:
    return (type(value) is str and len(value) == 64
            and _HEX_KEY.fullmatch(value) is not None)


def _key_material(keys: a4a.Keys) -> tuple[bytes, str]:
    if not isinstance(keys, a4a.Keys):
        raise OwnerVaultError("Invalid owner key.")
    try:
        private_hex = keys.privkey_hex
        public_hex = keys.pubkey_hex
        if not _canonical_key(private_hex) or not _canonical_key(public_hex):
            raise ValueError
        checked = a4a.Keys(private_hex)
        if not hmac.compare_digest(checked.pubkey_hex, public_hex):
            raise ValueError
        return bytes.fromhex(private_hex), public_hex
    except Exception:
        # SDK/backend exceptions must not become secret-bearing diagnostics.
        raise OwnerVaultError("Invalid owner key.") from None


def _parse_payload(payload: dict) -> tuple[dict, dict[str, bytes]]:
    if type(payload) is not dict or len(payload) != len(_FIELDS):
        raise OwnerVaultError("Invalid owner vault payload.")
    if any(type(field) is not str for field in payload) or set(payload) != _FIELDS:
        raise OwnerVaultError("Invalid owner vault payload.")
    payload = payload.copy()
    if type(payload["version"]) is not int or payload["version"] != _VERSION:
        raise OwnerVaultError("Unsupported owner vault version.")
    if type(payload["algorithm"]) is not str or payload["algorithm"] != _ALGORITHM:
        raise OwnerVaultError("Unsupported owner vault algorithm.")
    if not _canonical_key(payload["owner_pubkey"]):
        raise OwnerVaultError("Invalid owner vault payload.")

    # Check every encoded size before decoding anything or allocating KDF state.
    for field, size in _BINARY_SIZES.items():
        value = payload[field]
        if type(value) is not str or len(value) != 4 * ((size + 2) // 3):
            raise OwnerVaultError("Invalid owner vault payload.")
    decoded = {}
    for field, size in _BINARY_SIZES.items():
        value = payload[field]
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError:
            raise OwnerVaultError("Invalid owner vault payload.") from None
        if len(raw) != size or base64.b64encode(raw).decode("ascii") != value:
            raise OwnerVaultError("Invalid owner vault payload.")
        decoded[field] = raw
    return payload, decoded


def _aad(payload: dict) -> bytes:
    metadata = {field: payload[field] for field in (
        "version", "algorithm", "owner_pubkey")}
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("ascii")


def _derive_key(password: bytes, salt: bytes) -> bytes:
    try:
        return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password)
    except Exception:
        raise OwnerVaultError("Owner vault key derivation failed.") from None


def seal_owner_key(keys: a4a.Keys, password: str) -> dict:
    """Seal a validated owner key using fresh CSPRNG salt and nonce.

    Passwords are NFKC-normalized, require at least 16 normalized characters for
    new vaults, and must encode to at most 1024 UTF-8 bytes after normalization.
    """
    password_bytes = _password_bytes(password, sealing=True)
    private_key, owner_pubkey = _key_material(keys)
    payload = {
        "version": _VERSION,
        "algorithm": _ALGORITHM,
        "owner_pubkey": owner_pubkey,
    }
    try:
        salt = secrets.token_bytes(_BINARY_SIZES["salt"])
        nonce = secrets.token_bytes(_BINARY_SIZES["nonce"])
    except Exception:
        raise OwnerVaultError("Owner vault randomness unavailable.") from None
    encryption_key = _derive_key(password_bytes, salt)
    try:
        ciphertext = AESGCM(encryption_key).encrypt(nonce, private_key, _aad(payload))
    except Exception:
        raise OwnerVaultError("Owner vault encryption failed.") from None
    payload.update({
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    })
    return payload


def open_owner_key(payload: dict, password: str) -> a4a.Keys:
    """Authenticate and open a strictly validated version-1 owner vault.

    Unlock permits any nonempty normalized password within the 1024-byte bound,
    including legacy short passwords. Invalid credentials, tampering, invalid
    decrypted keys, and owner-binding failures share one authentication error.
    """
    payload, decoded = _parse_payload(payload)
    password_bytes = _password_bytes(password, sealing=False)
    encryption_key = _derive_key(password_bytes, decoded["salt"])
    try:
        private_key = AESGCM(encryption_key).decrypt(
            decoded["nonce"], decoded["ciphertext"], _aad(payload))
        if len(private_key) != 32:
            raise ValueError
        keys = a4a.Keys(private_key.hex())
        if not hmac.compare_digest(keys.pubkey_hex, payload["owner_pubkey"]):
            raise ValueError
    except Exception:
        raise OwnerVaultError(_AUTH_ERROR) from None
    return keys
