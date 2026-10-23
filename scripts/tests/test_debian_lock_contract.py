"""Bounded negative controls for metadata consistency, not fake signature proof."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location(
    "debian_lock_contract", Path(__file__).resolve().parents[1] / "debian_lock_contract.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)


def fixture():
    package = {"Package": "example", "Version": "1:2.0-1", "Architecture": "amd64",
               "Filename": "pool/main/e/example/example_2.0-1_amd64.deb", "Size": "100",
               "SHA256": "a" * 64}
    index = ("\n".join(f"{k}: {v}" for k, v in package.items()) + "\n\n").encode()
    release = ("Codename: bookworm-security\nArchitectures: amd64 arm64\n"
               "Date: Thu, 01 Oct 2026 00:00:00 UTC\n"
               "Valid-Until: Thu, 08 Oct 2026 00:00:00 UTC\nSHA256:\n"
               f" {hashlib.sha256(index).hexdigest()} {len(index)} main/binary-amd64/Packages\n").encode()
    return release, index, [package]


def check(release, index, locked, **kwargs):
    return MODULE.validate_repository(release, index, locked,
                                     suite="bookworm-security", architecture="amd64", now=NOW, **kwargs)


def test_valid_metadata_never_claims_signature_or_package_byte_verification():
    result = check(*fixture())
    assert result["package_count"] == 1
    assert result["signature_verified"] is False
    assert result["package_bytes_verified"] is False


def test_tampered_index_is_rejected():
    release, index, locked = fixture()
    with pytest.raises(MODULE.LockContractError, match="index"):
        check(release, index + b"tampered\n", locked)


@pytest.mark.parametrize("field,value", [("SHA256", "b" * 64), ("Version", "3.0"),
                                         ("Size", "101"), ("Architecture", "arm64")])
def test_locked_package_must_match_the_index(field, value):
    release, index, locked = fixture()
    locked[0][field] = value
    with pytest.raises(MODULE.LockContractError):
        check(release, index, locked)


def test_expired_metadata_is_rejected_including_exact_deadline():
    release, index, locked = fixture()
    release = release.replace(b"Thu, 08 Oct 2026", b"Fri, 02 Oct 2026")
    with pytest.raises(MODULE.LockContractError, match="expired"):
        check(release, index, locked)


def test_security_suite_cannot_omit_expiry():
    release, index, locked = fixture()
    release = release.replace(b"Valid-Until: Thu, 08 Oct 2026 00:00:00 UTC\n", b"")
    with pytest.raises(MODULE.LockContractError, match="Valid-Until"):
        check(release, index, locked)


def test_trixie_security_preserves_index_identity_and_expiry_checks():
    release, index, locked = fixture()
    release = release.replace(b"bookworm-security", b"trixie-security")
    proof = MODULE.validate_repository(release, index, locked, suite="trixie-security", architecture="amd64", now=NOW)
    assert proof["expiry_declared"] is True
    with pytest.raises(MODULE.LockContractError, match="Valid-Until"):
        MODULE.validate_repository(release.replace(b"Valid-Until: Thu, 08 Oct 2026 00:00:00 UTC\n", b""),
                                   index, locked, suite="trixie-security", architecture="amd64", now=NOW)
    with pytest.raises(MODULE.LockContractError, match="expired"):
        MODULE.validate_repository(release, index, locked, suite="trixie-security", architecture="amd64",
                                   now=datetime(2026, 10, 8, tzinfo=timezone.utc))


def test_unexpired_stable_metadata_reports_absent_expiry_honestly():
    release, index, locked = fixture()
    release = release.replace(b"bookworm-security", b"bookworm").replace(
        b"Valid-Until: Thu, 08 Oct 2026 00:00:00 UTC\n", b"")
    result = MODULE.validate_repository(release, index, locked, suite="bookworm", architecture="amd64", now=NOW)
    assert result["expiry_declared"] is False
    assert result["signature_verified"] is False


def test_future_metadata_is_rejected():
    release, index, locked = fixture()
    release = release.replace(b"Date: Thu, 01 Oct 2026", b"Date: Sat, 03 Oct 2026")
    with pytest.raises(MODULE.LockContractError, match="future"):
        check(release, index, locked)


@pytest.mark.parametrize("filename", ["/tmp/package.deb", "pool/../package.deb", r"pool\package.deb",
                                      "https://example.invalid/package.deb"])
def test_noncanonical_package_paths_are_rejected(filename):
    release, index, locked = fixture()
    locked[0]["Filename"] = filename
    with pytest.raises(MODULE.LockContractError):
        check(release, index, locked)


def test_duplicate_packages_are_rejected():
    release, index, locked = fixture()
    with pytest.raises(MODULE.LockContractError, match="duplicate"):
        check(release, index, locked + deepcopy(locked))


def test_duplicate_release_headers_are_rejected():
    release, index, locked = fixture()
    with pytest.raises(MODULE.LockContractError, match="duplicate"):
        check(b"Codename: bookworm-security\n" + release, index, locked)


def test_naive_time_cannot_accidentally_skip_timezone_validation():
    release, index, locked = fixture()
    with pytest.raises(MODULE.LockContractError, match="timezone"):
        MODULE.validate_repository(release, index, locked, suite="bookworm-security",
                                   architecture="amd64", now=NOW.replace(tzinfo=None))


def test_exact_independently_resolved_closure_is_required():
    _, _, locked = fixture()
    assert MODULE.validate_closure(locked, ["example=1:2.0-1"]) == {"package_count": 1}
    for requests in ([], ["example=1:2.0-1", "dependency=1"], ["example=3"],
                     ["example=1:2.0-1", "example=1:2.0-1"]):
        with pytest.raises(MODULE.LockContractError):
            MODULE.validate_closure(locked, requests)


@pytest.mark.parametrize("old,new", [
    (b"Codename: bookworm-security", b"Codename: bookworm"),
    (b"Architectures: amd64 arm64", b"Architectures: arm64"),
    (b"Date: Thu, 01 Oct 2026 00:00:00 UTC", b"Date: invalid"),
    (b"Valid-Until: Thu, 08 Oct 2026 00:00:00 UTC", b"Valid-Until: invalid"),
    (b"Valid-Until: Thu, 08 Oct 2026 00:00:00 UTC", b"Valid-Until: Wed, 30 Sep 2026 00:00:00 UTC"),
    (b"Date: Thu, 01 Oct 2026 00:00:00 UTC", b"Date: Thu, 01 Oct 2026 00:00:00"),
    (b"SHA256:", b"SHA256-malformed"),
])
def test_invalid_release_contract_is_rejected(old, new):
    release, index, locked = fixture()
    with pytest.raises(MODULE.LockContractError):
        check(release.replace(old, new), index, locked)


def rebind(index):
    release, original, _ = fixture()
    return release.replace(hashlib.sha256(original).hexdigest().encode(),
                           hashlib.sha256(index).hexdigest().encode()).replace(
                               f" {len(original)} ".encode(), f" {len(index)} ".encode())


@pytest.mark.parametrize("field,value", [
    ("Package", "invalid name"), ("Version", "-1"), ("SHA256", "G" * 64),
    ("Size", "0"), ("Size", "-1"), ("Size", "01"), ("Filename", "pool//bad.deb"),
    ("Filename", "pool/%2e%2e/bad.deb"), ("Architecture", "i386"),
])
def test_invalid_package_fields_fail_even_with_matching_index_hash(field, value):
    _, _, locked = fixture()
    locked[0][field] = value
    index = ("\n".join(f"{k}: {v}" for k, v in locked[0].items()) + "\n\n").encode()
    with pytest.raises(MODULE.LockContractError):
        check(rebind(index), index, locked)


@pytest.mark.parametrize("suffix", [b"Package: example\n", b"package: example\n", b"malformed\n"])
def test_ambiguous_index_fields_fail_even_with_matching_hash(suffix):
    _, index, locked = fixture()
    index = index.rstrip(b"\n") + b"\n" + suffix + b"\n"
    with pytest.raises(MODULE.LockContractError):
        check(rebind(index), index, locked)


def test_duplicate_index_stanzas_are_rejected():
    _, index, locked = fixture()
    index = index * 2
    with pytest.raises(MODULE.LockContractError, match="duplicate"):
        check(rebind(index), index, locked)


def test_duplicate_release_checksum_paths_are_rejected():
    release, index, locked = fixture()
    with pytest.raises(MODULE.LockContractError, match="duplicate"):
        check(release + release.split(b"SHA256:\n")[1], index, locked)


def test_repository_accepts_all_architecture_and_folded_description():
    _, _, locked = fixture()
    locked[0]["Architecture"] = "all"
    index = ("\n".join(f"{k}: {v}" for k, v in locked[0].items()) +
             "\nDescription: example\n continuation\n .\n\n").encode()
    assert check(rebind(index), index, locked)["package_count"] == 1


def test_crlf_and_unicode_description_do_not_become_control_fields():
    _, index, locked = fixture()
    index = index.rstrip(b"\n") + "\nDescription: text\u2028Package: other\n\n".encode()
    index = index.replace(b"\n", b"\r\n")
    assert check(rebind(index), index, locked)["package_count"] == 1


@pytest.mark.parametrize("payload", [b"", b"\xff", b"orphan\n", b" continuation\n", b"X: a\x00\n",
                                     b"X: a\rY: b\n", b"X: " + b"a" * (128 * 1024 + 1)],
                         ids=["empty", "utf8", "field", "orphan", "nul", "bare-cr", "oversized"])
def test_malformed_release_bytes_are_rejected(payload):
    _, index, locked = fixture()
    with pytest.raises(MODULE.LockContractError):
        check(payload, index, locked)


@pytest.mark.parametrize("records", [None, {}, [None], [{}]])
def test_invalid_lock_record_types_are_rejected(records):
    release, index, _ = fixture()
    with pytest.raises(MODULE.LockContractError):
        check(release, index, records)


def test_empty_selection_does_not_skip_index_integrity():
    release, index, _ = fixture()
    assert check(release, index, [])["package_count"] == 0
    with pytest.raises(MODULE.LockContractError):
        check(release, index + b"tampered", [])


def test_closure_rejects_multiarch_and_unqualified_or_conflicting_requests():
    _, _, locked = fixture()
    other = deepcopy(locked[0])
    other.update(Package="other", Architecture="arm64")
    with pytest.raises(MODULE.LockContractError, match="multiarch"):
        MODULE.validate_closure(locked + [other], ["example=1:2.0-1", "other=1:2.0-1"])
    for requests in (["example"], ["example=1:2.0-1", "example=2"], [None], None):
        with pytest.raises(MODULE.LockContractError):
            MODULE.validate_closure(locked, requests)


def test_release_can_bind_unrelated_empty_indexes_without_accepting_zero_size_packages():
    release, index, locked = fixture()
    release += f" {hashlib.sha256(b'').hexdigest()} 0 contrib/Contents-amd64\n".encode()
    assert check(release, index, locked)["package_count"] == 1


def test_parsing_and_record_limits_are_enforced():
    release, index, locked = fixture()
    oversized_fields = release + b"".join(f"Extra{i}: x\n".encode() for i in range(128))
    with pytest.raises(MODULE.LockContractError, match="too many"):
        check(oversized_fields, index, locked)
    locked[0]["Version"] = "1" * 4097
    with pytest.raises(MODULE.LockContractError, match="oversized"):
        check(release, index, locked)
    _, _, locked = fixture()
    with pytest.raises(MODULE.LockContractError, match="bounded"):
        MODULE.validate_closure(locked, ["example=" + "1" * 4097])


@pytest.mark.parametrize("suite,architecture", [(None, "amd64"), ([], "amd64"),
                                               ("bookworm-security", []), ("sid", "amd64")])
def test_unsupported_or_invalid_repository_parameters_fail_explicitly(suite, architecture):
    release, index, locked = fixture()
    with pytest.raises(MODULE.LockContractError, match="unsupported"):
        MODULE.validate_repository(release, index, locked, suite=suite, architecture=architecture, now=NOW)


def byte_fixture(payload=b"synthetic package bytes"):
    _, _, records = fixture()
    record = records[0]
    record.update(Size=str(len(payload)), SHA256=hashlib.sha256(payload).hexdigest())
    return record, payload


def test_verified_bytes_do_not_claim_metadata_authentication_or_installation():
    record, payload = byte_fixture()
    stream = io.BytesIO(payload)
    result = MODULE.verify_package_stream(record, stream)
    assert result == {"size": len(payload), "sha256": record["SHA256"],
                      "package_bytes_verified": True, "signature_verified": False}
    assert stream.closed is False


@pytest.mark.parametrize("replacement", [b"", b"synthetic package byte", b"synthetic package bytes extra",
                                        b"Synthetic package bytes"])
def test_truncated_extra_or_same_size_tampered_bytes_fail(replacement):
    record, _ = byte_fixture()
    with pytest.raises(MODULE.LockContractError):
        MODULE.verify_package_stream(record, io.BytesIO(replacement))


def test_read_requests_are_bounded_and_short_reads_are_supported():
    record, payload = byte_fixture(b"x" * (2 * 65_536 + 3))
    class ShortReads(io.BytesIO):
        def read(self, size):
            assert 0 < size <= 65_536
            return super().read(min(size, 19))
    assert MODULE.verify_package_stream(record, ShortReads(payload))["size"] == len(payload)


@pytest.mark.parametrize("value", [None, "text", bytearray(b"binary")])
def test_nonbinary_read_results_are_rejected(value):
    record, _ = byte_fixture()
    class InvalidStream:
        def read(self, size):
            return value
    with pytest.raises(MODULE.LockContractError, match="binary"):
        MODULE.verify_package_stream(record, InvalidStream())


def test_closed_or_absent_stream_fails_explicitly():
    record, payload = byte_fixture()
    closed = io.BytesIO(payload)
    closed.close()
    for stream in (closed, None):
        with pytest.raises(MODULE.LockContractError, match="stream"):
            MODULE.verify_package_stream(record, stream)


def test_oversized_record_is_rejected_before_reading():
    record, _ = byte_fixture()
    record["Size"] = str(128 * 1024 * 1024 + 1)
    class Unreadable:
        def read(self, size):
            raise AssertionError("oversized input must not be read")
    with pytest.raises(MODULE.LockContractError, match="limit"):
        MODULE.verify_package_stream(record, Unreadable())


def test_stream_cannot_return_more_than_requested():
    record, payload = byte_fixture()
    class OversizedRead:
        def read(self, size):
            return payload + b"extra"
    with pytest.raises(MODULE.LockContractError, match="read"):
        MODULE.verify_package_stream(record, OversizedRead())


def test_metadata_path_validation_happens_before_reading_bytes():
    record, payload = byte_fixture()
    record["Filename"] = "pool/../package.deb"
    with pytest.raises(MODULE.LockContractError, match="Filename"):
        MODULE.verify_package_stream(record, io.BytesIO(payload))


def test_offset_stream_does_not_verify_the_whole_file_accidentally():
    record, payload = byte_fixture()
    stream = io.BytesIO(payload)
    stream.seek(1)
    with pytest.raises(MODULE.LockContractError):
        MODULE.verify_package_stream(record, stream)
