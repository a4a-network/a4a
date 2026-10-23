import pytest
import bech32
from a4a.keys import Keys

VECTOR_PRIV = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"
VECTOR_ASEC = "asec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqv8rc7v"
VECTOR_PUB = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
VECTOR_APUB = "apub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8q7cwsvs"


def test_pubkey_derivation_known_vector():
    # privkey = 1 -> pubkey = x-coordinate of the base point G
    keys = Keys("00" * 31 + "01")
    assert keys.pubkey_hex == "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def test_asec_apub_encoding_vectors():
    keys = Keys(VECTOR_PRIV)
    assert keys.asec == VECTOR_ASEC
    assert keys.apub == VECTOR_APUB


def test_apub_encoding_vector():
    apub = Keys._encode_bech32("apub", bytes.fromhex(VECTOR_PUB))
    assert apub == VECTOR_APUB


def test_from_asec_roundtrip():
    keys = Keys.from_asec(VECTOR_ASEC)
    assert keys.privkey_hex == VECTOR_PRIV


def test_generate_random_keys():
    a, b = Keys(), Keys()
    assert a.privkey_hex != b.privkey_hex
    assert len(a.pubkey_hex) == 64


def test_from_asec_rejects_apub():
    with pytest.raises(ValueError):
        Keys.from_asec(VECTOR_APUB)


def test_from_asec_wrong_length_raises():
    short = bech32.bech32_encode("asec", bech32.convertbits(b"\x01" * 20, 8, 5))
    with pytest.raises(ValueError):
        Keys.from_asec(short)


def test_decode_rejects_invalid_bech32_checksum_with_stable_error():
    with pytest.raises(ValueError, match="invalid bech32 string"):
        Keys._decode_bech32("asec1invalid")


def test_decode_rejects_non_byte_aligned_bech32_payload():
    malformed = bech32.bech32_encode("asec", [1])

    with pytest.raises(ValueError, match="invalid bech32 padding"):
        Keys._decode_bech32(malformed)


def test_decode_apub_and_normalize_pubkey():
    assert Keys.decode_apub(VECTOR_APUB) == VECTOR_PUB
    assert Keys.normalize_pubkey(VECTOR_APUB) == VECTOR_PUB
    assert Keys.normalize_pubkey(VECTOR_PUB) == VECTOR_PUB
    assert Keys.normalize_pubkey("not-a-key") == "not-a-key"
    assert Keys.normalize_pubkey("apub1invalid") == "apub1invalid"
    with pytest.raises(ValueError):
        Keys.decode_apub(VECTOR_ASEC)
