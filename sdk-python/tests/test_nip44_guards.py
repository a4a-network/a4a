"""Malformed NIP-44 ciphertext parsing guards missed by the original suite.

A 2026-08-29 mutation pass disabled every `if …: raise` guard in `nip44.py` and
ran the full suite; seven mutations survived. Official NIP-44 vectors cover valid
cases and some invalid ones, but not key, nonce, and AAD lengths or payload boundaries.

This is a security boundary, not pedantry: payloads arrive from unknown network peers.
Without length checks, a slice such as `data[1:33]` silently returns short data and the
code computes a MAC over garbage instead of failing deterministically.
"""
import base64

import pytest
from a4a import nip44
from a4a.keys import Keys


def _conv_key() -> bytes:
    a, b = Keys(), Keys()
    return nip44._conversation_key(a.privkey_hex, b.pubkey_hex)


# --- Key-material lengths ------------------------------------------------

def test_message_keys_reject_short_conversation_key():
    """conversation_key is always the 32-byte ECDH+HKDF output."""
    with pytest.raises(nip44.Nip44Error, match="conversation_key"):
        nip44._message_keys(b"\x01" * 31, b"\x02" * 32)


def test_message_keys_reject_short_nonce():
    """A truncated foreign payload must not feed a short nonce into HKDF."""
    with pytest.raises(nip44.Nip44Error, match="nonce"):
        nip44._message_keys(b"\x01" * 32, b"\x02" * 16)


def test_hmac_aad_rejects_wrong_aad_length():
    """AAD is the same nonce, so a length mismatch means parsing drifted."""
    with pytest.raises(nip44.Nip44Error, match="AAD"):
        nip44._hmac_aad(b"\x01" * 32, b"message", b"\x02" * 16)


# --- Padding parsing -----------------------------------------------------

def test_unpad_rejects_too_short_buffer():
    """A buffer shorter than its two-byte length prefix must be rejected.

    The common branch (`unpadded_len == 0` or a length mismatch) performs this check.
    A separate early branch was removed after mutation showed it changed no input.
    """
    with pytest.raises(nip44.Nip44Error, match="padding"):
        nip44._unpad(b"\x01")


# --- Payload boundaries --------------------------------------------------

def test_decrypt_rejects_unpadded_marker():
    """A `#` prefix is reserved for unsupported unpadded NIP-44 payloads."""
    with pytest.raises(nip44.Nip44Error, match="#"):
        nip44._decrypt_with_key("#" + "A" * 200, _conv_key())


def test_decrypt_rejects_too_short_payload():
    with pytest.raises(nip44.Nip44Error, match="payload is too short"):
        nip44._decrypt_with_key("A" * 40, _conv_key())


def test_decrypt_rejects_payload_that_is_long_in_base64_but_short_in_bytes():
    """The post-decode check does not duplicate the encoded-string length check.

    132 base64 characters normally yield 99 bytes, but `==` padding yields only 97.
    An encoded string can therefore pass the first check while remaining too short;
    without the second check parsing would slice beyond the actual fields.
    """
    payload = base64.b64encode(b"\x02" * 97).decode()
    assert len(payload) >= 132 and len(base64.b64decode(payload)) < 99
    with pytest.raises(nip44.Nip44Error, match="decoded payload is too short"):
        nip44._decrypt_with_key(payload, _conv_key())
