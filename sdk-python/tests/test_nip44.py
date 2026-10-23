"""Verify NIP-44 v2 against the official test vectors.

Source: nostr-protocol/nips, where 44.md ("Tests and code") links to
https://github.com/paulmillr/nip44 and `nip44.vectors.json`. We keep a copy in
`tests/nip44_vectors.json` and first compare its SHA-256 checksum with the one
published in the specification (269ed0f6...25040), proving that the file is
authentic and unmodified.
"""
import base64
import hashlib
import json
import os

import pytest

from a4a import nip44

_VECTORS_PATH = os.path.join(os.path.dirname(__file__), "nip44_vectors.json")
_OFFICIAL_SHA256 = "269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040"


def _load_vectors():
    with open(_VECTORS_PATH, "rb") as f:
        raw = f.read()
    if hashlib.sha256(raw).hexdigest() != _OFFICIAL_SHA256:
        # The most common cause is line-ending conversion, not tampering. Git's
        # Windows default (`core.autocrlf=true`) rewrites them on checkout, making
        # the checksum fail in a fresh clone even if it matched in the source tree.
        # `.gitattributes` has prevented this since 2026-08-29, but keep the message
        # explicit so the next person blames checkout rather than cryptography.
        crlf = raw.count(bytes([13, 10]))
        hint = (f" The file contains {crlf} CRLF sequences, suggesting git rewrote "
                f"line endings during checkout. Check .gitattributes and check out "
                f"the file again.") if crlf else ""
        raise AssertionError(
            "nip44_vectors.json checksum does not match the official file." + hint)
    return json.loads(raw.decode("utf-8"))["v2"]


VECTORS = _load_vectors()


def _pubkey_xonly(priv_hex: str) -> str:
    from a4a.keys import Keys
    return Keys(priv_hex).pubkey_hex


# --- conversation_key: primary KAT proving ECDH + HKDF-extract correctness -------

@pytest.mark.parametrize("case", VECTORS["valid"]["get_conversation_key"])
def test_conversation_key_official_vectors(case):
    ck = nip44._conversation_key(case["sec1"], case["pub2"])
    assert ck.hex() == case["conversation_key"]


def test_conversation_key_count_sane():
    # Guard against accidentally truncating the vector list while editing the file.
    assert len(VECTORS["valid"]["get_conversation_key"]) >= 30


# --- message_keys (HKDF-expand: chacha_key/chacha_nonce/hmac_key) -------------

def test_message_keys_official_vectors():
    gmk = VECTORS["valid"]["get_message_keys"]
    conv_key = bytes.fromhex(gmk["conversation_key"])
    assert len(gmk["keys"]) >= 30
    for item in gmk["keys"]:
        chacha_key, chacha_nonce, hmac_key = nip44._message_keys(
            conv_key, bytes.fromhex(item["nonce"]))
        assert chacha_key.hex() == item["chacha_key"]
        assert chacha_nonce.hex() == item["chacha_nonce"]
        assert hmac_key.hex() == item["hmac_key"]


# --- padding -------------------------------------------------------------

def test_calc_padded_len_official_vectors():
    for unpadded_len, padded_len in VECTORS["valid"]["calc_padded_len"]:
        assert nip44._calc_padded_len(unpadded_len) == padded_len


# --- full encrypt/decrypt: sec1/sec2/nonce/plaintext -> known payload --------

def test_encrypt_decrypt_official_vectors():
    cases = VECTORS["valid"]["encrypt_decrypt"]
    assert len(cases) >= 5
    for case in cases:
        pub2 = _pubkey_xonly(case["sec2"])
        pub1 = _pubkey_xonly(case["sec1"])
        conv_key_fwd = nip44._conversation_key(case["sec1"], pub2)
        assert conv_key_fwd.hex() == case["conversation_key"]
        conv_key_back = nip44._conversation_key(case["sec2"], pub1)
        assert conv_key_back.hex() == case["conversation_key"]

        conv_key = nip44._conversation_key(case["sec1"], pub2)
        payload = nip44._encrypt_with_nonce(case["plaintext"], conv_key,
                                           bytes.fromhex(case["nonce"]))
        assert payload == case["payload"]

        plaintext = nip44.decrypt(case["payload"], case["sec2"], pub1)
        assert plaintext == case["plaintext"]


def test_encrypt_decrypt_long_msg_official_vectors():
    # These vectors provide conversation_key directly. Their messages are too long
    # for readable sec1/sec2 KATs, so use internal functions with the prepared key.
    for case in VECTORS["valid"]["encrypt_decrypt_long_msg"]:
        plaintext = case["pattern"] * case["repeat"]
        assert hashlib.sha256(plaintext.encode("utf-8")).hexdigest() == case["plaintext_sha256"]
        conv_key = bytes.fromhex(case["conversation_key"])
        nonce = bytes.fromhex(case["nonce"])
        chacha_key, chacha_nonce, hmac_key = nip44._message_keys(conv_key, nonce)
        padded = nip44._pad(plaintext)
        ciphertext = nip44._chacha20(chacha_key, chacha_nonce, padded)
        mac = nip44._hmac_aad(hmac_key, ciphertext, nonce)
        payload = base64.b64encode(bytes([2]) + nonce + ciphertext + mac).decode("ascii")
        assert hashlib.sha256(payload.encode("ascii")).hexdigest() == case["payload_sha256"]


# --- invalid keys ---------------------------------------------------------

def test_invalid_get_conversation_key_vectors_raise():
    # Every case (sec1=0, sec1>=curve.n, invalid/off-curve pub2, twist-curve points)
    # must be rejected while coincurve parses the keys.
    cases = VECTORS["invalid"]["get_conversation_key"]
    assert len(cases) >= 2
    for case in cases:
        with pytest.raises(nip44.Nip44Error):
            nip44._conversation_key(case["sec1"], case["pub2"])


# --- invalid decrypt payloads must raise cleanly without panicking ---------------

def test_invalid_decrypt_vectors_raise_clean_nip44error():
    # Every vector carries ITS OWN conversation_key rather than sec1/sec2. Pass it
    # directly to `_decrypt_with_key`; otherwise the MAC differs from dummy keys and
    # all 12 cases, including 3 invalid-padding cases, fail at MAC verification
    # without ever exercising `_unpad`.
    cases = VECTORS["invalid"]["decrypt"]
    assert len(cases) >= 5
    for case in cases:
        conv_key = bytes.fromhex(case["conversation_key"])
        with pytest.raises(nip44.Nip44Error):
            nip44._decrypt_with_key(case["payload"], conv_key)


# --- boundary message lengths (empty / huge) -----------------------------

def test_invalid_encrypt_msg_lengths_rejected():
    # NIP-44 v2 plaintext MUST be 1..65535 bytes, with a single two-byte u16 length
    # prefix and NO "extended" prefix (the specification defines none). The official
    # invalid.encrypt_msg_lengths vector lists 0, 65536, 100000, and 10000000; encrypt
    # must reject ALL of them.
    lengths = VECTORS["invalid"]["encrypt_msg_lengths"]
    priv = "00" * 31 + "01"
    pub = "00" * 31 + "02"
    for n in lengths:
        plaintext = "a" * n
        with pytest.raises(nip44.Nip44Error):
            nip44.encrypt(plaintext, priv, pub)


# --- SDK round trip outside official vectors as an additional API check ----------

def test_roundtrip_with_random_keys():
    from a4a.keys import Keys
    alice, bob = Keys(), Keys()
    payload = nip44.encrypt("strictly confidential report contents",
                            alice.privkey_hex, bob.pubkey_hex)
    plaintext = nip44.decrypt(payload, bob.privkey_hex, alice.pubkey_hex)
    assert plaintext == "strictly confidential report contents"


def test_conversation_key_symmetric():
    from a4a.keys import Keys
    alice, bob = Keys(), Keys()
    ck_ab = nip44._conversation_key(alice.privkey_hex, bob.pubkey_hex)
    ck_ba = nip44._conversation_key(bob.privkey_hex, alice.pubkey_hex)
    assert ck_ab == ck_ba


def test_decrypt_rejects_tampered_mac():
    from a4a.keys import Keys
    alice, bob = Keys(), Keys()
    payload = nip44.encrypt("hello", alice.privkey_hex, bob.pubkey_hex)
    raw = bytearray(base64.b64decode(payload))
    raw[-1] ^= 0xFF  # corrupt the final MAC byte
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(nip44.Nip44Error):
        nip44.decrypt(tampered, bob.privkey_hex, alice.pubkey_hex)


def test_decrypt_wrong_recipient_raises_cleanly():
    from a4a.keys import Keys
    alice, bob, mallory = Keys(), Keys(), Keys()
    payload = nip44.encrypt("hello", alice.privkey_hex, bob.pubkey_hex)
    with pytest.raises(nip44.Nip44Error):
        nip44.decrypt(payload, mallory.privkey_hex, alice.pubkey_hex)


def test_decrypt_garbage_input_raises_cleanly():
    with pytest.raises(nip44.Nip44Error):
        nip44.decrypt("not base64 and not remotely a payload!!!", "00" * 31 + "01", "00" * 31 + "02")
    with pytest.raises(nip44.Nip44Error):
        nip44.decrypt("", "00" * 31 + "01", "00" * 31 + "02")
    with pytest.raises(nip44.Nip44Error):
        nip44.decrypt("#unsupported-version-marker", "00" * 31 + "01", "00" * 31 + "02")
