"""File exchange (§2.6): the encrypted-blob plus signed-reference convention.

The file does NOT travel through a relay. The sender encrypts it with
`encrypt_file`, uploads the blob to storage (IPFS/Arweave/Blossom/HTTPS), and sends
an A4A private message containing a REFERENCE:
`{url, sha256, key, enc, name, mime, size}`. The recipient downloads the blob,
checks its SHA-256 with `verify_file`, and decrypts it with `decrypt_file` or
`open_file`. Keeping the SHA-256 inside the signed/private message makes the file a
verifiable attachment to the transaction: it cannot be replaced after signing.

File encryption was added on 2026-09-04 after internal audit finding 51: the
README promised a reference to an ENCRYPTED blob, but the SDK did not encrypt it.
ChaCha20-Poly1305 (AEAD) uses a fresh random 32-byte key for each file. The key is
sent to the recipient inside a private message—NIP-44-encrypted to the recipient's
key and, by default, also enclosed in a gift wrap—rather than being derived from a
key pair. This permits forwarding a file to a third party without exposing the
conversation. It does not provide forward secrecy: a compromised recipient key
can decrypt archived references and recover their file keys. A blob is
`nonce(12) || ciphertext || tag(16)`, without a
header: the encrypted blob exposes its size (plus 28 bytes), not its contents.
Storage operators can also observe request metadata; a configured file gateway
records sender/recipient keys and upload/fetch times. The name and MIME type live
in the reference, under NIP-44, rather
than beside the blob. This does not build a new primitive on top of `cryptography`:
it is the same ChaCha20 used by NIP-44, with an AEAD tag instead of HMAC and without
text padding (NIP-44's 65,535-byte and UTF-8 limits make it unsuitable for files).

Encryption and parsing perform no network I/O. resolve_download_target may resolve
DNS; the separate a4a.file_gateway module has explicit upload/fetch/status calls
to a caller-configured origin. Agent.send_file sends the reference through relays
but neither uploads the blob nor verifies bytes at the reference address.
"""
import hashlib
import ipaddress
import json
import hmac
import os
import re
import socket
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

_MARKER = "a4a_file"

#: Blob-encryption scheme name stored in the reference (`enc`). A reader that does
#: not recognize the name must report that fact instead of attempting a fallback.
FILE_ENCRYPTION = "a4a-chacha20poly1305-v1"
_FILE_AAD = FILE_ENCRYPTION.encode("ascii")
_NONCE_LEN = 12
_TAG_LEN = 16
_KEY_RE = re.compile(r"[0-9a-f]{64}")


class FileCryptoError(ValueError):
    """The blob cannot be opened due to a wrong key, tampering, or invalid format."""


def encrypt_file(data: bytes) -> tuple[bytes, str]:
    """Encrypt a file with a random key and return `(blob, key_hex)`.

    Upload the blob to storage and pass `sha256_hex(blob)` and the key to
    `Agent.send_file`. The key is 64 lowercase hexadecimal characters, using the
    same grammar as event keys.
    """
    key = os.urandom(32)
    nonce = os.urandom(_NONCE_LEN)
    blob = nonce + ChaCha20Poly1305(key).encrypt(nonce, bytes(data), _FILE_AAD)
    return blob, key.hex()


def decrypt_file(blob: bytes, key: str) -> bytes:
    """Decrypt a blob with the key from its reference.

    A changed byte, a wrong key, or a foreign format raises `FileCryptoError`
    instead of returning garbage: the AEAD tag covers the entire ciphertext and
    the scheme name.
    """
    if not isinstance(key, str) or not _KEY_RE.fullmatch(key):
        raise FileCryptoError("file key must be 64 lowercase hexadecimal characters")
    if len(blob) < _NONCE_LEN + _TAG_LEN:
        raise FileCryptoError(
            "blob is shorter than its nonce and tag; it is not an encrypted A4A file")
    try:
        return ChaCha20Poly1305(bytes.fromhex(key)).decrypt(
            blob[:_NONCE_LEN], blob[_NONCE_LEN:], _FILE_AAD)
    except InvalidTag as e:
        raise FileCryptoError(
            "blob cannot be opened: the key is wrong, the file was tampered with, "
            f"or it was not encrypted with {FILE_ENCRYPTION}") from e


def open_file(blob: bytes, ref: dict) -> bytes:
    """Complete the recipient path: verify the reference SHA-256, then decrypt.

    Order matters. The hash in the signed message first establishes that the right
    file was downloaded; only then is the key used. A reference without a key or
    with an unknown scheme is rejected with a reason instead of returning the raw
    bytes unchanged.
    """
    if not verify_file(blob, ref.get("sha256", "")):
        raise FileCryptoError(
            "downloaded file SHA-256 does not match the reference; the file was "
            "tampered with or the wrong file was downloaded")
    enc = ref.get("enc", "")
    if enc != FILE_ENCRYPTION:
        raise FileCryptoError(
            f"reference does not use {FILE_ENCRYPTION} (enc={enc!r}); "
            "the SDK cannot open this file")
    return decrypt_file(blob, ref.get("key", ""))

# Schemes that can sensibly address an encrypted blob. Nothing else (file:, data:,
# javascript:, or plain http:) should be accepted from the network: an untrusted
# peer supplied the reference and it will cause a request (2026-08-17 audit, F4).
ALLOWED_SCHEMES = ("https", "ipfs", "ar")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _as_ip(host: str):
    """Return the host as an IP address, including nonstandard forms, or None.

    Canonical parsing catches only `127.0.0.1`; decimal (`2130706433`), abbreviated
    (`127.1`), bare zero (`0`), and hexadecimal (`0x7f.1`) forms can bypass it even
    though they all identify loopback. `inet_aton` understands these forms, so it
    is used as a second pass (found during the 2026-08-28 review).
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def is_internal_host(host: str) -> bool:
    """Return whether a host is inside the network perimeter.

    This includes loopback, link-local (including cloud metadata), private, and
    special-purpose ranges. A name that is not an IP address is not resolved here;
    parsing does not access the network. See the rebinding warning in
    `parse_file_reference`.
    """
    if not host:
        return True
    # A trailing dot denotes the same DNS host despite being a different string.
    h = host.strip("[]").rstrip(".").lower()
    if not h:
        return True
    if h == "localhost" or h.endswith((".localhost", ".local", ".internal")):
        return True
    ip = _as_ip(h)
    if ip is None:
        return False
    return bool(ip.is_loopback or ip.is_link_local or ip.is_private
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _is_acceptable_url(url: str, allow_private_hosts: bool) -> bool:
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() == "https":
            # Accessing port validates its syntax and range; urlsplit alone does not.
            _ = parts.port
    except ValueError:
        return False
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return False
    if parts.scheme.lower() != "https":
        return bool(parts.netloc or parts.path)  # For ipfs/ar the address is a CID, not a host.
    if not parts.hostname:
        return False
    return allow_private_hosts or not is_internal_host(parts.hostname)


def build_file_reference(url: str, sha256: str, key: str = "", name: str = "",
                         mime: str = "", size: int = 0, enc: str = "") -> str:
    """Build the JSON file reference used as private-message content.

    `enc` names the scheme that encrypted the blob (`FILE_ENCRYPTION` for
    `encrypt_file`). An empty value means the key belongs to another scheme or the
    file is not encrypted. `size` is the size of the ORIGINAL file.
    """
    return json.dumps(
        {_MARKER: {"url": url, "sha256": sha256, "key": key, "enc": enc,
                   "name": name, "mime": mime, "size": size}},
        ensure_ascii=False)


def parse_file_reference(content: str, *, allow_private_hosts: bool = False,
                         validate: bool = True) -> dict | None:
    """Parse a file reference from message content.

    Return None when the content is not a file reference OR when validation fails.
    This fails closed: a naive caller that immediately downloads `ref["url"]` will
    not fetch anything dangerous.

    Validation requires a scheme in `ALLOWED_SCHEMES`, a host outside the network
    perimeter, and a `sha256` value of exactly 64 hexadecimal characters.
    `allow_private_hosts=True` is an explicit opt-in for a private network;
    `validate=False` returns the reference unchanged for diagnostics, allowing the
    caller to distinguish “not a file” from “a file with an invalid reference.”

    WARNING: parsing does not access the network, so it cannot reject a domain name
    that RESOLVES to an internal address (DNS rebinding). The downloader must check
    the address again while connecting. That is its security boundary, not the
    SDK's.
    """
    try:
        obj = json.loads(content)
    except (ValueError, TypeError):
        return None
    ref = obj.get(_MARKER) if isinstance(obj, dict) else None
    if not isinstance(ref, dict) or "url" not in ref or "sha256" not in ref:
        return None
    if not validate:
        return ref
    if not isinstance(ref["sha256"], str) or not _SHA256_RE.match(ref["sha256"]):
        return None
    if not isinstance(ref["url"], str) or not _is_acceptable_url(ref["url"],
                                                                allow_private_hosts):
        return None
    return ref


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_file(data: bytes, sha256: str) -> bool:
    """Compare downloaded bytes with the reference SHA-256 integrity value.

    Case is normalized because `parse_file_reference` accepts uppercase hashes,
    while `hexdigest()` always returns lowercase. Without normalization, an
    integrator emitting uppercase hashes would have every file reported as corrupt
    (2026-08-29 internal audit, F14). Constant-time comparison avoids establishing
    a habit of comparing digests with `==`.
    """
    return hmac.compare_digest(sha256_hex(data), sha256.lower())


class DownloadTargetError(ValueError):
    """The download target has an invalid scheme, DNS result, or internal address."""


def resolve_download_target(url: str, *, _resolver=None) -> tuple[str, str]:
    """Resolve a reference name and return `(address, hostname)` when it is safe.

    This is separate from `parse_file_reference` because that function rejects an
    invalid scheme and an obviously internal HOST without accessing the network. It
    therefore cannot catch a domain name that RESOLVES to an internal address. The
    `Agent.send_file` documentation previously assigned that check to the caller
    without providing a way to perform it, forcing each integrator to write a custom
    check—which in practice often means no check (2026-08-29 audit).

    To preserve the value of this check, connect to the RETURNED address while using
    the hostname for the `Host` header and certificate verification. Calling an HTTP
    client with the original URL makes it resolve the name again; the DNS response
    may change between this check and the request, which is precisely the DNS
    rebinding attack this function prevents.

    The function fails closed: an unresolved name is an error, not “probably safe.”
    If any result is internal, the entire reference is rejected because the client
    may choose that result itself.
    """
    try:
        parts = urlsplit(url)
        _ = parts.port
    except ValueError as exc:
        raise DownloadTargetError("download URL is malformed") from exc
    if parts.scheme != "https" or not parts.hostname:
        raise DownloadTargetError(
            f"downloads require HTTPS and an explicit host; received: {url!r}")
    host = parts.hostname.rstrip(".")
    resolver = _resolver or _default_resolver
    try:
        addresses = list(resolver(host))
    except OSError as e:
        raise DownloadTargetError(f"could not resolve host {host!r}: {e}") from e
    if not addresses:
        raise DownloadTargetError(f"host {host!r} did not resolve to any address")
    for addr in addresses:
        if is_internal_host(addr):
            raise DownloadTargetError(
                f"host {host!r} points inside the network perimeter ({addr}); "
                "download rejected")
    return addresses[0], host


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None)
    return [i[4][0] for i in infos]
