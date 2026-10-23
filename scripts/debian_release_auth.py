"""Authenticate Debian Release metadata with the immutable image's archive ring.

This Linux/Debian adapter never imports keys or fetches them. The caller must
provide an immutable, trusted image and keep its archive keyring current.
Use validate_signed_repository for suite, freshness and index binding: a valid
signature alone is not freshness or a complete package lock.
"""

from debian_lock_contract import LockContractError, validate_repository
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile


_GPGV = "/usr/bin/gpgv"
_KEYRING = "/usr/share/keyrings/debian-archive-keyring.gpg"
_MAX_PAYLOAD = 2 * 1024 * 1024
_MAX_STATUS = 1024 * 1024
_FINGERPRINT = re.compile(r"[0-9A-F]{40}\Z")
_BENIGN_STATUS = {"PLAINTEXT", "KEY_CONSIDERED", "SIG_ID"}


def _keyring_digest():
    with Path(_KEYRING).open("rb") as source:
        payload = source.read(8 * 1024 * 1024 + 1)
    if not payload or len(payload) > 8 * 1024 * 1024:
        raise LockContractError("invalid Debian archive keyring size")
    return hashlib.sha256(payload).hexdigest()


def _invoke_gpgv(payload):
    """Fixed executable/ring, private home, bounded reads and execution timeout.

    Callers must bound temporary disk/process resources as well, and keep the
    executable/keyring immutable. Temporary files avoid unbounded PIPE buffers.
    No keys are copied, imported or retrieved. GPG's human diagnostics are not
    used to accept a signature.
    """
    try:
        before = _keyring_digest()
        with tempfile.TemporaryDirectory(prefix="a4a-release-", dir="/tmp") as directory:
            home = Path(directory) / "home"
            home.mkdir(mode=0o700)
            command = [_GPGV, "--homedir", str(home), "--keyring", _KEYRING,
                       "--status-fd", "2", "--output", "-", "-"]
            with (Path(directory) / "payload").open("w+b") as output, (Path(directory) / "status").open("w+b") as status:
                completed = subprocess.run(command, input=payload, stdout=output, stderr=status,
                                           timeout=20, check=False, shell=False,
                                           env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
                output.seek(0)
                status.seek(0)
                result = subprocess.CompletedProcess(command, completed.returncode,
                                                     output.read(_MAX_PAYLOAD + 1), status.read(_MAX_STATUS + 1))
        if _keyring_digest() != before:
            raise LockContractError("Debian archive keyring changed during verification")
        return result, before
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LockContractError("gpgv unavailable or verification timed out") from exc


def _signers(status):
    signers = set()
    group = None

    def finish():
        if group is None or set(group) != {"good", "valid"}:
            raise LockContractError("incomplete gpgv signature status")
        fingerprint, primary = group["valid"]
        if not fingerprint.endswith(group["good"]):
            raise LockContractError("gpgv signer status mismatch")
        signers.add(primary)

    try:
        lines = status.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise LockContractError("invalid gpgv status encoding") from exc
    for line in lines:
        if not line.startswith("[GNUPG:] "):
            continue
        parts = line[len("[GNUPG:] "):].split()
        if not parts:
            raise LockContractError("empty gpgv status")
        tag, arguments = parts[0], parts[1:]
        if tag in _BENIGN_STATUS:
            continue
        if tag == "NEWSIG":
            if group is not None:
                finish()
            group = {}
        elif tag == "GOODSIG":
            if group is None or "good" in group or not arguments or not re.fullmatch(r"[0-9A-F]{16}", arguments[0]):
                raise LockContractError("malformed gpgv GOODSIG")
            group["good"] = arguments[0]
        elif tag == "VALIDSIG":
            if (group is None or "valid" in group or len(arguments) not in (9, 10)
                    or not _FINGERPRINT.fullmatch(arguments[0])
                    or arguments[4:6] != ["4", "0"] or arguments[7] not in {"8", "9", "10"}
                    or arguments[8] != "01" or arguments[6] not in {"1", "3", "19", "22"}
                    or not re.fullmatch(r"[1-9][0-9]{0,19}", arguments[2])
                    or not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", arguments[3])):
                raise LockContractError("malformed or weak gpgv VALIDSIG")
            primary = arguments[9] if len(arguments) == 10 else arguments[0]
            if not _FINGERPRINT.fullmatch(primary):
                raise LockContractError("malformed gpgv primary fingerprint")
            group["valid"] = arguments[0], primary
        else:
            raise LockContractError(f"unacceptable gpgv status: {tag}")
    finish()
    return sorted(signers)


def authenticate_inrelease(payload):
    """Return ONLY gpgv-emitted cleartext after all signatures pass strict status.

    All signatures must be verifiable, unlike permissive partial-signature
    acceptance. Only v4 cleartext signatures with SHA256/384/512 are accepted.
    gpgv trusts its ring and does not enforce key expiry/revocation: ring
    maintenance is the caller's responsibility. Release dates are checked by
    validate_signed_repository, not by this signature-only function.
    """
    if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_PAYLOAD:
        raise LockContractError("invalid or oversized InRelease")
    envelope = payload.replace(b"\r\n", b"\n")
    begin = b"-----BEGIN PGP SIGNED MESSAGE-----\n"
    signature = b"-----BEGIN PGP SIGNATURE-----"
    end = b"-----END PGP SIGNATURE-----"
    if (not envelope.startswith(begin) or envelope.count(begin) != 1
            or envelope.count(signature) != 1 or envelope.count(end) != 1
            or not envelope.rstrip().endswith(end)):
        raise LockContractError("invalid or ambiguous InRelease envelope")
    result, keyring_hash = _invoke_gpgv(payload)
    if result.returncode != 0:
        raise LockContractError(f"gpgv verification failed: exit {result.returncode}")
    if (not isinstance(result.stdout, bytes) or not result.stdout or len(result.stdout) > _MAX_PAYLOAD
            or not isinstance(result.stderr, bytes) or len(result.stderr) > _MAX_STATUS
            or not isinstance(keyring_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", keyring_hash)):
        raise LockContractError("invalid or oversized gpgv output")
    return {"release_payload": result.stdout, "signature_verified": True,
            "signers": _signers(result.stderr), "keyring_sha256": keyring_hash}


def validate_signed_repository(inrelease, packages_index, locked_packages, *, suite, architecture, now):
    """Authenticate, then check exact signed suite/date/index/package metadata."""
    authenticated = authenticate_inrelease(inrelease)
    result = validate_repository(authenticated["release_payload"], packages_index, locked_packages,
                                 suite=suite, architecture=architecture, now=now)
    return {**result, "signature_verified": True, "signers": authenticated["signers"],
            "keyring_sha256": authenticated["keyring_sha256"]}
