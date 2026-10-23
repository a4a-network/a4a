"""Adapter unit stubs are not cryptographic evidence; real probes are separate."""

from datetime import datetime, timezone
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("release_auth", SCRIPTS / "debian_release_auth.py")
AUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH)
SIGNED = b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nexample\n-----BEGIN PGP SIGNATURE-----\nexample\n-----END PGP SIGNATURE-----\n"
FINGERPRINT = "A" * 40
PRIMARY = "B" * 40
STATUS = ("[GNUPG:] PLAINTEXT 74 0\n[GNUPG:] NEWSIG\n"
          f"[GNUPG:] GOODSIG {FINGERPRINT[-16:]} unit fixture\n"
          f"[GNUPG:] VALIDSIG {FINGERPRINT} 2026-10-02 1790905937 0 4 0 1 8 01 {PRIMARY}\n").encode()


def result(stdout=b"Release payload\n", stderr=STATUS, returncode=0):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def stub(monkeypatch, completed):
    monkeypatch.setattr(AUTH, "_invoke_gpgv", lambda payload: (completed, "c" * 64), raising=False)


def test_good_result_returns_only_gpgv_output_and_explicit_trust_binding(monkeypatch):
    stub(monkeypatch, result())
    proof = AUTH.authenticate_inrelease(SIGNED)
    assert proof == {"release_payload": b"Release payload\n", "signature_verified": True,
                     "signers": [PRIMARY], "keyring_sha256": "c" * 64}


@pytest.mark.parametrize("returncode", [1, 2, 127, -9])
def test_nonzero_exit_never_releases_plaintext_even_with_good_status(monkeypatch, returncode):
    stub(monkeypatch, result(returncode=returncode))
    with pytest.raises(AUTH.LockContractError, match="gpgv"):
        AUTH.authenticate_inrelease(SIGNED)


@pytest.mark.parametrize("error", ["BADSIG", "ERRSIG", "NO_PUBKEY", "EXPSIG", "EXPKEYSIG",
                                 "REVKEYSIG", "NODATA", "FAILURE", "ERROR", "UNKNOWN_STATUS"])
def test_bad_or_unknown_status_fails_even_with_zero_exit_and_a_valid_signature(monkeypatch, error):
    stub(monkeypatch, result(stderr=STATUS + f"[GNUPG:] {error} detail\n".encode()))
    with pytest.raises(AUTH.LockContractError):
        AUTH.authenticate_inrelease(SIGNED)


@pytest.mark.parametrize("status", [b"gpgv: Good signature\n", b"", b"[GNUPG:] GOODSIG A fixture\n",
                                   STATUS.replace(b" 1 8 01 ", b" 1 2 01 "),
                                   STATUS.replace(FINGERPRINT.encode(), b"invalid"),
                                   STATUS + b"[GNUPG:] NEWSIG\n",
                                   STATUS.replace(b"GOODSIG " + FINGERPRINT[-16:].encode(), b"GOODSIG " + b"D" * 16)])
def test_missing_malformed_or_weak_machine_status_is_rejected(monkeypatch, status):
    stub(monkeypatch, result(stderr=status))
    with pytest.raises(AUTH.LockContractError):
        AUTH.authenticate_inrelease(SIGNED)


@pytest.mark.parametrize("payload", [b"", b"unsigned", SIGNED + b"unsigned suffix", SIGNED * 2,
                                    "not bytes", b"x" * (2 * 1024 * 1024 + 1)],
                         ids=["empty", "unsigned", "suffix", "concatenated", "type", "oversized"])
def test_invalid_envelope_fails_before_invocation(monkeypatch, payload):
    def forbidden(payload):
        raise AssertionError("invalid envelopes must not invoke gpgv")
    monkeypatch.setattr(AUTH, "_invoke_gpgv", forbidden, raising=False)
    with pytest.raises(AUTH.LockContractError):
        AUTH.authenticate_inrelease(payload)


@pytest.mark.parametrize("stdout,stderr", [(b"", STATUS), ("not bytes", STATUS),
                                         (b"x" * (2 * 1024 * 1024 + 1), STATUS),
                                         (b"payload", b"x" * (1024 * 1024 + 1))],
                         ids=["empty-output", "type", "oversized-payload", "oversized-status"])
def test_invalid_or_oversized_outputs_are_rejected(monkeypatch, stdout, stderr):
    stub(monkeypatch, result(stdout=stdout, stderr=stderr))
    with pytest.raises(AUTH.LockContractError):
        AUTH.authenticate_inrelease(SIGNED)


def test_composition_uses_verified_payload_then_checks_freshness_and_index(monkeypatch):
    index = b"Package: example\nVersion: 1\nArchitecture: amd64\nFilename: pool/main/e/example/a.deb\nSize: 1\nSHA256: " + b"a" * 64 + b"\n\n"
    release = ("Codename: bookworm-security\nArchitectures: amd64\nDate: Thu, 01 Oct 2026 00:00:00 UTC\n"
               "Valid-Until: Thu, 08 Oct 2026 00:00:00 UTC\nSHA256:\n"
               f" {hashlib.sha256(index).hexdigest()} {len(index)} main/binary-amd64/Packages\n").encode()
    stub(monkeypatch, result(stdout=release))
    options = {"suite": "bookworm-security", "architecture": "amd64", "now": datetime(2026, 10, 2, tzinfo=timezone.utc)}
    verified = AUTH.validate_signed_repository(SIGNED, index, [], **options)
    assert verified["signature_verified"] is True
    assert verified["package_bytes_verified"] is False
    assert verified["signers"] == [PRIMARY]
    with pytest.raises(AUTH.LockContractError, match="index"):
        AUTH.validate_signed_repository(SIGNED, index + b"tampered", [], **options)
    options["now"] = datetime(2026, 10, 8, tzinfo=timezone.utc)
    with pytest.raises(AUTH.LockContractError, match="expired"):
        AUTH.validate_signed_repository(SIGNED, index, [], **options)


def local_invocation(monkeypatch, tmp_path, runner, digests=None):
    factory = AUTH.tempfile.TemporaryDirectory
    monkeypatch.setattr(AUTH.tempfile, "TemporaryDirectory", lambda **kwargs: factory(dir=tmp_path))
    hashes = iter(digests or ["c" * 64, "c" * 64])
    monkeypatch.setattr(AUTH, "_keyring_digest", lambda: next(hashes))
    monkeypatch.setattr(AUTH.subprocess, "run", runner)


def test_native_invocation_is_fixed_and_does_not_use_shell_or_caller_trust(monkeypatch, tmp_path):
    calls = []
    def runner(command, **kwargs):
        calls.append((command, kwargs))
        kwargs["stdout"].write(b"Release payload\n")
        kwargs["stderr"].write(STATUS)
        return SimpleNamespace(returncode=0)
    local_invocation(monkeypatch, tmp_path, runner)
    completed, digest = AUTH._invoke_gpgv(SIGNED)
    assert completed.stdout == b"Release payload\n"
    assert digest == "c" * 64
    command, options = calls[0]
    assert command[0] == "/usr/bin/gpgv"
    assert command[command.index("--keyring") + 1] == "/usr/share/keyrings/debian-archive-keyring.gpg"
    assert command[-4:] == ["2", "--output", "-", "-"]
    assert "--ignore-time-conflict" not in command
    assert options["shell"] is False
    assert options["timeout"] == 20
    assert set(options["env"]) == {"PATH", "LANG", "LC_ALL"}


@pytest.mark.parametrize("error", [OSError("missing executable"), subprocess.TimeoutExpired("gpgv", 20)])
def test_native_failure_or_timeout_is_wrapped(monkeypatch, tmp_path, error):
    def runner(command, **kwargs):
        raise error
    local_invocation(monkeypatch, tmp_path, runner)
    with pytest.raises(AUTH.LockContractError, match="gpgv"):
        AUTH._invoke_gpgv(SIGNED)


def test_keyring_change_during_verification_fails(monkeypatch, tmp_path):
    local_invocation(monkeypatch, tmp_path, lambda *args, **kwargs: SimpleNamespace(returncode=0),
                     ["c" * 64, "d" * 64])
    with pytest.raises(AUTH.LockContractError, match="keyring changed"):
        AUTH._invoke_gpgv(SIGNED)


@pytest.mark.parametrize("old,new", [(b"1790905937", b"invalid"), (b" 1 8 01 ", b" 17 8 01 "),
                                    (PRIMARY.encode(), b"invalid")])
def test_invalid_numeric_algorithm_or_primary_status_is_rejected(monkeypatch, old, new):
    stub(monkeypatch, result(stderr=STATUS.replace(old, new)))
    with pytest.raises(AUTH.LockContractError):
        AUTH.authenticate_inrelease(SIGNED)
