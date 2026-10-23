"""Agent and user key pairs: secp256k1 with A4A Bech32 asec/apub encoding."""
import secrets

import bech32
from coincurve import PrivateKey


class Keys:
    """A secp256k1 key pair; generate a new pair when no key is supplied."""

    def __init__(self, privkey_hex: str | None = None):
        if privkey_hex is None:
            privkey_hex = secrets.token_hex(32)
        self._priv = PrivateKey(bytes.fromhex(privkey_hex))

    @property
    def privkey_hex(self) -> str:
        return self._priv.secret.hex()

    @property
    def pubkey_hex(self) -> str:
        # BIP-340 x-only key: discard the parity byte from the compressed key.
        return self._priv.public_key.format(compressed=True)[1:].hex()

    @property
    def asec(self) -> str:
        return self._encode_bech32("asec", self._priv.secret)

    @property
    def apub(self) -> str:
        return self._encode_bech32("apub", bytes.fromhex(self.pubkey_hex))

    @property
    def nsec(self) -> str:
        return self.asec

    @property
    def npub(self) -> str:
        return self.apub

    @classmethod
    def from_asec(cls, asec: str) -> "Keys":
        prefix, data = cls._decode_bech32(asec)
        if prefix != "asec":
            raise ValueError(f"expected asec, got prefix {prefix!r}")
        if len(data) != 32:
            raise ValueError(f"expected a 32-byte key, got {len(data)} bytes")
        return cls(data.hex())

    @classmethod
    def from_nsec(cls, asec: str) -> "Keys":
        return cls.from_asec(asec)

    @classmethod
    def decode_apub(cls, apub: str) -> str:
        prefix, data = cls._decode_bech32(apub)
        if prefix != "apub":
            raise ValueError(f"expected apub, got prefix {prefix!r}")
        if len(data) != 32:
            raise ValueError(f"expected a 32-byte key, got {len(data)} bytes")
        return data.hex()

    @classmethod
    def decode_npub(cls, apub: str) -> str:
        return cls.decode_apub(apub)

    @classmethod
    def encode_apub(cls, pubkey_hex: str) -> str:
        raw = bytes.fromhex(cls.normalize_pubkey(pubkey_hex))
        if len(raw) != 32:
            raise ValueError(f"expected a 32-byte key, got {len(raw)} bytes")
        return cls._encode_bech32("apub", raw)

    @classmethod
    def normalize_pubkey(cls, value: str) -> str:
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("apub1"):
                try:
                    return cls.decode_apub(trimmed)
                except ValueError:
                    return value
        return value

    @staticmethod
    def _encode_bech32(prefix: str, data: bytes) -> str:
        return bech32.bech32_encode(prefix, bech32.convertbits(data, 8, 5))

    @staticmethod
    def _decode_bech32(encoded: str) -> tuple[str, bytes]:
        prefix, data5 = bech32.bech32_decode(encoded)
        if prefix is None:
            raise ValueError("invalid bech32 string")
        data8 = bech32.convertbits(data5, 5, 8, False)
        if data8 is None:
            raise ValueError("invalid bech32 padding")
        return prefix, bytes(data8)
