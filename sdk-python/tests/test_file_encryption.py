"""SDK file encryption (internal audit finding 51).

The README promised a reference to an ENCRYPTED blob, but the SDK did not encrypt
it. It does now, and these tests cover both successful decryption and rejection
when a blob must not open.
"""
import json
import os

import pytest

from a4a import files
from a4a.agent import Agent
from a4a.files import FileCryptoError, decrypt_file, encrypt_file, open_file
from tests.fake_relay import FakeRelay

DATA = "contract no. 7, appendix 2 — file contents".encode("utf-8") * 40


# --- Primitive -------------------------------------------------------------------

def test_roundtrip_and_key_form():
    blob, key = encrypt_file(DATA)
    assert decrypt_file(blob, key) == DATA
    assert len(key) == 64 and key == key.lower() and int(key, 16) >= 0
    assert len(blob) == len(DATA) + 12 + 16, "storage sees only the size plus 28 bytes"


def test_blob_has_no_header_and_differs_between_calls():
    b1, k1 = encrypt_file(DATA)
    b2, k2 = encrypt_file(DATA)
    assert k1 != k2 and b1 != b2, "the key and nonce are random for each file"
    assert b1[:12] != b2[:12]
    assert b"a4a" not in b1.lower(), "the blob has no header that identifies the protocol"


def test_empty_file_roundtrips():
    blob, key = encrypt_file(b"")
    assert decrypt_file(blob, key) == b""


@pytest.mark.parametrize("position", ["nonce", "body", "tag"])
def test_tampered_blob_does_not_open(position):
    blob, key = encrypt_file(DATA)
    idx = {"nonce": 0, "body": 20, "tag": len(blob) - 1}[position]
    tampered = bytearray(blob)
    tampered[idx] ^= 0x01
    with pytest.raises(FileCryptoError):
        decrypt_file(bytes(tampered), key)


def test_wrong_key_does_not_open():
    blob, key = encrypt_file(DATA)
    _, other = encrypt_file(b"x")
    with pytest.raises(FileCryptoError):
        decrypt_file(blob, other)


@pytest.mark.parametrize("bad", ["", "deckey", "AB" * 32, " " + "a" * 63, "a" * 63, "a" * 65])
def test_non_canonical_key_is_rejected_before_crypto(bad):
    blob, _ = encrypt_file(DATA)
    with pytest.raises(FileCryptoError):
        decrypt_file(blob, bad)


def test_too_short_blob_is_rejected():
    _, key = encrypt_file(DATA)
    with pytest.raises(FileCryptoError, match="shorter than its nonce and tag"):
        decrypt_file(os.urandom(27), key)


# --- Reference and recipient path -----------------------------------------------

def test_open_file_checks_hash_then_scheme_then_key():
    blob, key = encrypt_file(DATA)
    ref = json.loads(files.build_file_reference(
        "https://files.example/x", files.sha256_hex(blob), key, enc=files.FILE_ENCRYPTION)
    )["a4a_file"]
    assert open_file(blob, ref) == DATA
    with pytest.raises(FileCryptoError, match="SHA-256"):
        open_file(blob + b"\x00", ref)                       # The wrong file was downloaded.
    with pytest.raises(FileCryptoError, match="does not use"):
        open_file(blob, {**ref, "enc": ""})                  # Foreign or missing scheme.
    with pytest.raises(FileCryptoError, match="cannot be opened"):
        open_file(blob, {**ref, "key": "0" * 64})           # Wrong key.


def test_reference_carries_enc_and_parse_keeps_it():
    content = files.build_file_reference("https://files.example/x", "a" * 64, "b" * 64,
                                         enc=files.FILE_ENCRYPTION)
    ref = files.parse_file_reference(content)
    assert ref["enc"] == files.FILE_ENCRYPTION
    legacy = files.parse_file_reference(json.dumps(
        {"a4a_file": {"url": "https://files.example/x", "sha256": "a" * 64, "key": "k"}}))
    assert legacy is not None and legacy.get("enc", "") == ""   # Legacy references still parse.


# --- End-to-end relay path -------------------------------------------------------

async def test_send_and_open_file_end_to_end():
    blob, key = encrypt_file(DATA)
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            await alice.send_file(bob.pubkey, url="https://files.example/blob",
                                  sha256=files.sha256_hex(blob), key=key,
                                  name="dogovor.pdf", mime="application/pdf", size=len(DATA))
            # The key, name, and hash are never sent in plaintext.
            wire = json.dumps(relay.events, ensure_ascii=False)
            assert key not in wire and "dogovor.pdf" not in wire and files.sha256_hex(blob) not in wire
            inbox = await bob.read_private_messages()
    ref = files.parse_file_reference(inbox[0]["content"])
    assert ref["enc"] == files.FILE_ENCRYPTION and ref["size"] == len(DATA)
    assert open_file(blob, ref) == DATA
    # The recipient cannot open the same blob after tampering.
    with pytest.raises(FileCryptoError):
        open_file(blob[:-1] + bytes([blob[-1] ^ 1]), ref)


async def test_enc_is_an_explicit_default_not_a_guess():
    """The signature defines the rule: a key implies our scheme unless overridden.

    A custom scheme is named explicitly and there is no scheme to declare without a
    key. The key's shape is not inspected: a foreign 64-character hexadecimal key
    without `enc` receives the same explicit default.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            await alice.send_file(bob.pubkey, url="ipfs://Qm1", sha256="a" * 64, key="deckey")
            await alice.send_file(bob.pubkey, url="ipfs://Qm2", sha256="a" * 64, key="c" * 64,
                                  enc="my-scheme")
            await alice.send_file(bob.pubkey, url="ipfs://Qm3", sha256="a" * 64)
            inbox = await bob.read_private_messages()
    by_url = {(r := files.parse_file_reference(m["content"]))["url"]: r["enc"] for m in inbox}
    assert by_url == {"ipfs://Qm1": files.FILE_ENCRYPTION,   # A key implies our scheme.
                      "ipfs://Qm2": "my-scheme",             # Named explicitly.
                      "ipfs://Qm3": ""}                       # No key means no scheme.
