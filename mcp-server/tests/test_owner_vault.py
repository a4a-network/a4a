"""Owner-vault crypto contract; only synthetic keys and in-memory payloads."""

import base64
import json
import traceback
import unicodedata
from unittest.mock import Mock

import a4a
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from a4a_mcp import owner_vault


PASSWORD = "synthetic vault password"
SECRET = "12" * 32
OWNER = a4a.Keys(SECRET)
OTHER_OWNER = a4a.Keys("34" * 32)
ALGORITHM = "scrypt-aes256gcm"
FIELDS = {"version", "algorithm", "owner_pubkey", "salt", "nonce", "ciphertext"}
SIZES = {"salt": 16, "nonce": 12, "ciphertext": 48}
AUTH_ERROR = "Owner vault authentication failed."
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _b64(value):
    return base64.b64encode(value).decode("ascii")


def _aad(payload):
    # This is the wire contract, independent of the implementation helper.
    metadata = {field: payload[field] for field in (
        "version", "algorithm", "owner_pubkey")}
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("ascii")


def _shape():
    return {
        "version": 1,
        "algorithm": ALGORITHM,
        "owner_pubkey": OWNER.pubkey_hex,
        "salt": _b64(bytes(range(16))),
        "nonce": _b64(bytes(range(12))),
        "ciphertext": _b64(bytes(range(48))),
    }


def _derive(password, salt):
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(
        unicodedata.normalize("NFKC", password).encode("utf-8"))


@pytest.fixture(scope="module")
def sealed():
    return owner_vault.seal_owner_key(OWNER, PASSWORD)


@pytest.fixture(scope="module")
def independent_material():
    payload = _shape()
    return payload, _derive(PASSWORD, base64.b64decode(payload["salt"]))


@pytest.fixture
def no_kdf(monkeypatch):
    kdf = Mock(side_effect=AssertionError("Invalid input reached the KDF"))
    monkeypatch.setattr(owner_vault, "Scrypt", kdf)
    return kdf


def test_public_api():
    assert issubclass(owner_vault.OwnerVaultError, ValueError)
    assert callable(owner_vault.seal_owner_key)
    assert callable(owner_vault.open_owner_key)


def test_real_encryption_roundtrip(sealed):
    payload = json.loads(json.dumps(sealed))
    before = payload.copy()
    opened = owner_vault.open_owner_key(payload, PASSWORD)
    assert type(opened) is a4a.Keys
    assert opened.privkey_hex == SECRET
    assert opened.pubkey_hex == OWNER.pubkey_hex
    assert payload == before
    assert set(payload) == FIELDS
    assert type(payload["version"]) is int and payload["version"] == 1
    assert payload["algorithm"] == ALGORITHM
    assert payload["owner_pubkey"] == OWNER.pubkey_hex
    for field, size in SIZES.items():
        decoded = base64.b64decode(payload[field], validate=True)
        assert len(decoded) == size
        assert _b64(decoded) == payload[field]
    assert SECRET not in json.dumps(payload)
    assert PASSWORD not in json.dumps(payload)
    assert OWNER.nsec not in json.dumps(payload)
    assert base64.b64decode(payload["ciphertext"])[:32] != bytes.fromhex(SECRET)


def test_random_salt_nonce_and_ciphertext(sealed):
    second = owner_vault.seal_owner_key(OWNER, PASSWORD)
    for field in SIZES:
        assert second[field] != sealed[field]
    assert second["owner_pubkey"] == sealed["owner_pubkey"]
    assert owner_vault.open_owner_key(second, PASSWORD).privkey_hex == SECRET


def test_independent_decryption_proves_fixed_kdf_and_aad(sealed):
    key = _derive(PASSWORD, base64.b64decode(sealed["salt"]))
    plaintext = AESGCM(key).decrypt(
        base64.b64decode(sealed["nonce"]),
        base64.b64decode(sealed["ciphertext"]), _aad(sealed))
    assert plaintext == bytes.fromhex(SECRET)
    for field, value in (
        ("version", 2), ("algorithm", "other"),
        ("owner_pubkey", OTHER_OWNER.pubkey_hex),
    ):
        with pytest.raises(InvalidTag):
            AESGCM(key).decrypt(
                base64.b64decode(sealed["nonce"]),
                base64.b64decode(sealed["ciphertext"]),
                _aad({**sealed, field: value}))


def test_nfkc_is_applied_on_seal_and_open():
    composed = "caf\u00e9-owner-password"
    decomposed = "cafe\u0301-owner-password"
    compatible = "\uff43\uff41\uff46\u00e9-owner-password"
    assert len({unicodedata.normalize("NFKC", value) for value in (
        composed, decomposed, compatible)}) == 1
    payload = owner_vault.seal_owner_key(OWNER, compatible)
    assert owner_vault.open_owner_key(payload, decomposed).privkey_hex == SECRET
    assert owner_vault.open_owner_key(payload, composed).privkey_hex == SECRET


def test_unlock_accepts_legacy_short_nonempty_password():
    payload = _shape()
    password = "x"
    key = _derive(password, base64.b64decode(payload["salt"]))
    payload["ciphertext"] = _b64(AESGCM(key).encrypt(
        base64.b64decode(payload["nonce"]), bytes.fromhex(SECRET), _aad(payload)))
    assert owner_vault.open_owner_key(payload, password).privkey_hex == SECRET


def test_wrong_password_has_generic_authentication_error(sealed):
    with pytest.raises(owner_vault.OwnerVaultError, match="^" + AUTH_ERROR.replace(".", r"\.") + "$"):
        owner_vault.open_owner_key(sealed, "wrong")


@pytest.mark.parametrize("field", ["salt", "nonce", "ciphertext", "owner_pubkey"])
def test_tampering_has_same_authentication_error(sealed, field):
    payload = sealed.copy()
    if field == "owner_pubkey":
        payload[field] = OTHER_OWNER.pubkey_hex
    else:
        value = bytearray(base64.b64decode(payload[field]))
        value[-1] ^= 1
        payload[field] = _b64(value)
    with pytest.raises(owner_vault.OwnerVaultError) as error:
        owner_vault.open_owner_key(payload, PASSWORD)
    assert str(error.value) == AUTH_ERROR


@pytest.mark.parametrize("private_key", [
    bytes(32), CURVE_ORDER.to_bytes(32, "big"), bytes([255]) * 32,
    bytes.fromhex(OTHER_OWNER.privkey_hex),
], ids=["zero-scalar", "curve-order", "out-of-range", "different-owner"])
def test_authenticated_invalid_key_or_binding_is_rejected(independent_material, private_key):
    template, key = independent_material
    payload = template.copy()
    payload["ciphertext"] = _b64(AESGCM(key).encrypt(
        base64.b64decode(payload["nonce"]), private_key, _aad(payload)))
    with pytest.raises(owner_vault.OwnerVaultError) as error:
        owner_vault.open_owner_key(payload, PASSWORD)
    assert str(error.value) == AUTH_ERROR


@pytest.mark.parametrize("payload", [None, [], (), "{}", 1, True])
def test_payload_must_be_json_object(payload, no_kdf):
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.open_owner_key(payload, PASSWORD)
    no_kdf.assert_not_called()


def test_payload_field_names_must_be_plain_strings(no_kdf):
    class StringSubclass(str):
        pass

    payload = _shape()
    version = payload.pop("version")
    payload[StringSubclass("version")] = version
    with pytest.raises(owner_vault.OwnerVaultError, match="Invalid owner vault payload"):
        owner_vault.open_owner_key(payload, PASSWORD)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("field", sorted(FIELDS))
def test_missing_fields_are_rejected(field, no_kdf):
    payload = _shape()
    del payload[field]
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.open_owner_key(payload, PASSWORD)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("field", ["extra", "n", "r", "p", "length", "kdf"])
def test_extra_fields_and_attacker_kdf_parameters_are_rejected(field, no_kdf):
    payload = {**_shape(), field: 2**30}
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.open_owner_key(payload, PASSWORD)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("version", [True, False, 1.0, "1", 0, 2, -1, None, [], {}])
def test_version_is_exact_integer_one(version, no_kdf):
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.open_owner_key({**_shape(), "version": version}, PASSWORD)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("algorithm", [
    "", "aes256gcm", "SCRYPT-AES256GCM", ALGORITHM + " ",
    ALGORITHM + "\n", None, 1, True, [], {}, ALGORITHM.encode("ascii"),
])
def test_algorithm_is_exact(algorithm, no_kdf):
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.open_owner_key({**_shape(), "algorithm": algorithm}, PASSWORD)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("pubkey", [
    "", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 63 + "\n",
    "a" * 64 + "\n", "\uff41" * 64, None, 1, True, [], {}, b"a" * 64,
])
def test_owner_pubkey_is_canonical_hex(pubkey, no_kdf):
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.open_owner_key({**_shape(), "owner_pubkey": pubkey}, PASSWORD)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("field", sorted(SIZES))
@pytest.mark.parametrize("value", [None, 0, True, [], {}, b"AAAA"])
def test_binary_fields_require_strings(field, value, no_kdf):
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.open_owner_key({**_shape(), field: value}, PASSWORD)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("field", sorted(SIZES))
@pytest.mark.parametrize("difference", [-2, -1, 1, 2])
def test_decoded_lengths_are_exact(field, difference, no_kdf):
    payload = {**_shape(), field: _b64(bytes(SIZES[field] + difference))}
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.open_owner_key(payload, PASSWORD)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("field", sorted(SIZES))
@pytest.mark.parametrize("replacement", ["!", "-", "_", " ", "\n", "\u00e9", "="])
def test_base64_is_strict_standard_alphabet(field, replacement, no_kdf):
    payload = _shape()
    payload[field] = replacement + payload[field][1:]
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.open_owner_key(payload, PASSWORD)
    no_kdf.assert_not_called()


def test_noncanonical_base64_pad_bits_are_rejected(no_kdf):
    canonical = _b64(bytes(16))
    noncanonical = canonical[:-3] + "B=="
    assert base64.b64decode(canonical) == base64.b64decode(noncanonical)
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.open_owner_key({**_shape(), "salt": noncanonical}, PASSWORD)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("field", sorted(SIZES))
@pytest.mark.parametrize("value", ["", "A" * 100_000], ids=["empty", "oversized"])
def test_encoded_length_is_checked_before_any_decode(field, value, no_kdf, monkeypatch):
    decode = Mock(side_effect=AssertionError("Oversized input reached base64 decode"))
    monkeypatch.setattr(base64, "b64decode", decode)
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.open_owner_key({**_shape(), field: value}, PASSWORD)
    decode.assert_not_called()
    no_kdf.assert_not_called()


@pytest.mark.parametrize("password", [
    None, b"sixteen-characters", 1, True, [], {}, "", "x" * 1025,
    "\u00e9" * 513, "x" * 15 + "\ud800", "\ufdfa" * 100,
], ids=["none", "bytes", "int", "bool", "list", "dict", "empty",
        "ascii-over-cap", "utf8-over-cap", "surrogate", "nfkc-expands-over-cap"])
@pytest.mark.parametrize("operation", ["seal", "open"])
def test_password_type_encoding_and_size_limits(password, operation, no_kdf):
    with pytest.raises(owner_vault.OwnerVaultError):
        if operation == "seal":
            owner_vault.seal_owner_key(OWNER, password)
        else:
            owner_vault.open_owner_key(_shape(), password)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("password", ["x", "x" * 15, "e\u0301" * 8])
def test_seal_checks_normalized_character_count(password, no_kdf):
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.seal_owner_key(OWNER, password)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("password", [
    "x" * 16, "x" * 1024, "\u00e9" * 512, "\ufb03" * 6,
], ids=["minimum", "ascii-byte-cap", "utf8-byte-cap", "nfkc-expands-to-minimum"])
def test_seal_password_boundaries_with_real_crypto(password):
    payload = owner_vault.seal_owner_key(OWNER, password)
    assert owner_vault.open_owner_key(payload, password).privkey_hex == SECRET


@pytest.mark.parametrize("keys", [None, SECRET, bytes.fromhex(SECRET), {}, 1, True])
def test_seal_requires_keys_object(keys, no_kdf):
    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.seal_owner_key(keys, PASSWORD)
    no_kdf.assert_not_called()


def test_seal_rejects_a_duck_typed_key_container(no_kdf):
    class DuckKeys:
        privkey_hex = OWNER.privkey_hex
        pubkey_hex = OWNER.pubkey_hex

    with pytest.raises(owner_vault.OwnerVaultError, match="Invalid owner key"):
        owner_vault.seal_owner_key(DuckKeys(), PASSWORD)
    no_kdf.assert_not_called()


@pytest.mark.parametrize("secret", [
    "00" * 32, "ff" * 32, "12" * 31, "ab" * 32 + " ", "AB" * 32,
])
def test_seal_revalidates_private_key(secret, no_kdf):
    class InvalidKeys(a4a.Keys):
        @property
        def privkey_hex(self):
            return secret

    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.seal_owner_key(InvalidKeys(SECRET), PASSWORD)
    no_kdf.assert_not_called()


def test_seal_rejects_noncanonical_hex_even_when_it_is_the_same_key(no_kdf):
    class UppercasePrivateKey(a4a.Keys):
        @property
        def privkey_hex(self):
            return super().privkey_hex.upper()

    with pytest.raises(owner_vault.OwnerVaultError, match="Invalid owner key"):
        owner_vault.seal_owner_key(UppercasePrivateKey("ab" * 32), PASSWORD)
    no_kdf.assert_not_called()


def test_seal_rejects_inconsistent_public_key(no_kdf):
    class InconsistentKeys(a4a.Keys):
        @property
        def pubkey_hex(self):
            return OTHER_OWNER.pubkey_hex

    with pytest.raises(owner_vault.OwnerVaultError):
        owner_vault.seal_owner_key(InconsistentKeys(SECRET), PASSWORD)
    no_kdf.assert_not_called()


def test_errors_and_logs_do_not_expose_sensitive_inputs(sealed, caplog, capsys):
    marker = "private-input-must-not-appear"
    cases = [
        lambda: owner_vault.open_owner_key(sealed, marker),
        lambda: owner_vault.open_owner_key({**sealed, marker: SECRET}, PASSWORD),
        lambda: owner_vault.open_owner_key({**sealed, "salt": marker}, PASSWORD),
        lambda: owner_vault.seal_owner_key(SECRET, PASSWORD),
        lambda: owner_vault.seal_owner_key(OWNER, marker + "\ud800"),
    ]
    for action in cases:
        with pytest.raises(owner_vault.OwnerVaultError) as error:
            action()
        rendered = "".join(traceback.format_exception(error.value))
        captured = capsys.readouterr()
        rendered += repr(error.value) + caplog.text + captured.out + captured.err
        for sensitive in (
            marker, SECRET, OWNER.nsec, OWNER.pubkey_hex, PASSWORD,
            repr(sealed), json.dumps(sealed), *[sealed[field] for field in SIZES],
        ):
            assert sensitive not in rendered
        assert error.value.__cause__ is None
        assert not error.value.__context__ or error.value.__suppress_context__
    assert not caplog.records


@pytest.mark.parametrize("primitive", ["Scrypt", "AESGCM"])
@pytest.mark.parametrize("operation", ["seal", "open"])
def test_backend_errors_are_sanitized(primitive, operation, monkeypatch):
    marker = "backend-error-containing-" + SECRET + PASSWORD
    monkeypatch.setattr(owner_vault, primitive, Mock(side_effect=ValueError(marker)))
    with pytest.raises(owner_vault.OwnerVaultError) as error:
        if operation == "seal":
            owner_vault.seal_owner_key(OWNER, PASSWORD)
        else:
            owner_vault.open_owner_key(_shape(), PASSWORD)
    rendered = "".join(traceback.format_exception(error.value))
    assert marker not in rendered
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__


def test_operations_do_not_use_filesystem_environment_or_network(monkeypatch):
    import builtins
    import io
    import os
    import socket

    blocked = Mock(side_effect=AssertionError("Unexpected external I/O"))
    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", blocked)
        patch.setattr(io, "open", blocked)
        patch.setattr(os, "open", blocked)
        patch.setattr(os, "getenv", blocked)
        patch.setattr(type(os.environ), "__getitem__", blocked)
        patch.setattr(socket, "socket", blocked)
        payload = owner_vault.seal_owner_key(OWNER, PASSWORD)
        opened = owner_vault.open_owner_key(payload, PASSWORD)
    assert opened.privkey_hex == SECRET
    blocked.assert_not_called()
