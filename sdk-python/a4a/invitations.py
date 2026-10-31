"""One-time expiring invitations for one-way human-relayed A4A handshakes.

User flow (One-Way Human Relay):
1. Owner A asks Agent A for a one-time invitation link.
2. Agent A generates 256-bit CSPRNG `invite_id` and `secret`, creates an
   `InvitationCard` signed with Agent A's key (`domain="a4a/invite/v1"`),
   encrypts the card under a key derived from `(invite_id, secret)`, and
   outputs `https://a4a.network/i/<invite_id>#<secret>`.
3. Owner A sends that link to Owner B in any messenger; Owner B gives it to Agent B.
4. Agent B extracts `invite_id` and `#<secret>` locally (the fragment `#<secret>`
   is never transmitted over HTTP), decrypts and verifies `InvitationCard`,
   signs an `InvitationAcceptance` (`domain="a4a/invite-response/v1"`), and
   completes the mutual A4A handshake directly with Agent A at Trust Level L1.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from . import crypto, nip44
from .event import Event, is_canonical_pubkey
from .keys import Keys
from .types import KIND_PRIVATE_MESSAGE, tagged_hash

INVITE_DOMAIN = "a4a/invite/v1"
INVITE_RESPONSE_DOMAIN = "a4a/invite-response/v1"

DEFAULT_INVITE_BASE_URL = "https://a4a.network/i"
DEFAULT_INVITE_TTL_SECONDS = 24 * 3600
MIN_INVITE_TTL_SECONDS = 60
MAX_INVITE_TTL_SECONDS = 7 * 24 * 3600

INVITE_STATUSES = ("open", "responded", "connected", "expired", "revoked")

_TOKEN_B64_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")


class InvitationError(ValueError):
    """Raised when an invitation link, card, or acceptance response is invalid."""


def generate_invite_id() -> str:
    """Return a 256-bit CSPRNG base64url token (43 chars, no padding)."""
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


def generate_invite_secret() -> str:
    """Return a 256-bit CSPRNG base64url secret (43 chars, no padding)."""
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


def is_valid_invite_token(token: str) -> bool:
    """Return True if token is a canonical 256-bit base64url string (43 chars)."""
    if not isinstance(token, str) or not _TOKEN_B64_RE.fullmatch(token):
        return False
    try:
        raw = base64.urlsafe_b64decode(token + "=")
    except Exception:
        return False
    return len(raw) == 32


def _decode_token(token: str, name: str) -> bytes:
    if not is_valid_invite_token(token):
        raise InvitationError(f"invalid {name}: must be a 256-bit base64url token")
    return base64.urlsafe_b64decode(token + "=")


def _derive_key(invite_id: str, secret: str, info: bytes) -> bytes:
    id_bytes = _decode_token(invite_id, "invite_id")
    secret_bytes = _decode_token(secret, "secret")
    prk = hmac.new(b"a4a/invite/salt/v1:" + id_bytes, secret_bytes, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def derive_card_key(invite_id: str, secret: str) -> bytes:
    """Derive the 32-byte symmetric conversation key for encrypting InvitationCard."""
    return _derive_key(invite_id, secret, b"a4a/invite/card-key/v1")


def derive_rendezvous_keys(invite_id: str, secret: str) -> Keys:
    """Derive the deterministic one-time relay rendezvous keypair from (invite_id, secret).

    Only holders of both `invite_id` and `#<secret>` can compute this keypair's
    public key or query its addressable events on the relay.
    """
    priv_bytes = _derive_key(invite_id, secret, b"a4a/invite/rendezvous-key/v1")
    return Keys(priv_bytes.hex())


def derive_revoke_token(invite_id: str, secret: str) -> str:
    """Derive a 32-byte hex revocation token; the server stores only its SHA-256 hash."""
    return _derive_key(invite_id, secret, b"a4a/invite/revoke-token/v1").hex()


def hash_revoke_token(revoke_token: str) -> str:
    """Return the SHA-256 hex digest of a revocation token."""
    if not isinstance(revoke_token, str) or not _HEX64_RE.fullmatch(revoke_token):
        raise InvitationError("revoke_token must be 64 lowercase hex characters")
    return hashlib.sha256(bytes.fromhex(revoke_token)).hexdigest()


def responder_commitment_for(invite_id: str, challenge: str, responder_pubkey: str) -> str:
    """Return a blind commitment binding the invitation redemption to one responder key."""
    if not is_canonical_pubkey(responder_pubkey):
        raise InvitationError("responder_pubkey must be 64 lowercase hex characters")
    payload = f"{invite_id}:{challenge}:{responder_pubkey}".encode("utf-8")
    return tagged_hash("a4a/invite-commitment/v1", payload).hex()


def invite_card_canonical(
    invite_id: str,
    inviter_pubkey: str,
    ephemeral_pubkey: str,
    challenge: str,
    created_at: int,
    expires_at: int,
    relays: list[str],
) -> bytes:
    return json.dumps(
        [
            "a4a-invite-v1",
            invite_id,
            inviter_pubkey,
            ephemeral_pubkey,
            challenge,
            int(created_at),
            int(expires_at),
            list(relays),
        ],
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def invite_card_digest(
    invite_id: str,
    inviter_pubkey: str,
    ephemeral_pubkey: str,
    challenge: str,
    created_at: int,
    expires_at: int,
    relays: list[str],
) -> str:
    return tagged_hash(
        INVITE_DOMAIN,
        invite_card_canonical(
            invite_id,
            inviter_pubkey,
            ephemeral_pubkey,
            challenge,
            created_at,
            expires_at,
            relays,
        ),
    ).hex()


def invite_response_canonical(
    invite_id: str,
    inviter_pubkey: str,
    responder_pubkey: str,
    challenge: str,
    responded_at: int,
    relays: list[str],
) -> bytes:
    return json.dumps(
        [
            "a4a-invite-response-v1",
            invite_id,
            inviter_pubkey,
            responder_pubkey,
            challenge,
            int(responded_at),
            list(relays),
        ],
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def invite_response_digest(
    invite_id: str,
    inviter_pubkey: str,
    responder_pubkey: str,
    challenge: str,
    responded_at: int,
    relays: list[str],
) -> str:
    return tagged_hash(
        INVITE_RESPONSE_DOMAIN,
        invite_response_canonical(
            invite_id,
            inviter_pubkey,
            responder_pubkey,
            challenge,
            responded_at,
            relays,
        ),
    ).hex()


class InvitationCard(BaseModel):
    """Signed invitation card encrypted inside the one-time link."""

    version: int = 1
    invite_id: str
    inviter_pubkey: str
    inviter_apub: str
    ephemeral_pubkey: str
    challenge: str
    created_at: int
    expires_at: int
    relays: list[str] = Field(default_factory=list)
    label: str = ""
    sig: str = ""

    @classmethod
    def create(
        cls,
        inviter_keys: Keys,
        relays: list[str],
        *,
        ttl_seconds: int = DEFAULT_INVITE_TTL_SECONDS,
        label: str = "",
        invite_id: str | None = None,
        ephemeral_keys: Keys | None = None,
        now: int | None = None,
    ) -> tuple["InvitationCard", Keys]:
        if ttl_seconds < MIN_INVITE_TTL_SECONDS or ttl_seconds > MAX_INVITE_TTL_SECONDS:
            raise InvitationError(
                f"ttl_seconds must be between {MIN_INVITE_TTL_SECONDS} and {MAX_INVITE_TTL_SECONDS}"
            )
        clean_relays = [str(r).strip() for r in relays if str(r).strip()]
        if not clean_relays:
            raise InvitationError("at least one relay URL is required in InvitationCard")
        inv_id = invite_id or generate_invite_id()
        _decode_token(inv_id, "invite_id")
        eph = ephemeral_keys or Keys()
        created = int(time.time()) if now is None else int(now)
        expires = created + int(ttl_seconds)
        challenge = os.urandom(32).hex()
        digest = invite_card_digest(
            inv_id,
            inviter_keys.pubkey_hex,
            eph.pubkey_hex,
            challenge,
            created,
            expires,
            clean_relays,
        )
        sig = crypto.sign(digest, inviter_keys.privkey_hex)
        card = cls(
            version=1,
            invite_id=inv_id,
            inviter_pubkey=inviter_keys.pubkey_hex,
            inviter_apub=inviter_keys.apub,
            ephemeral_pubkey=eph.pubkey_hex,
            challenge=challenge,
            created_at=created,
            expires_at=expires,
            relays=clean_relays,
            label=str(label or "").strip()[:120],
            sig=sig,
        )
        return card, eph

    def verify(self, *, expected_invite_id: str | None = None, now: int | None = None) -> bool:
        if self.version != 1:
            return False
        if not is_valid_invite_token(self.invite_id):
            return False
        if expected_invite_id is not None and self.invite_id != expected_invite_id:
            return False
        if not (is_canonical_pubkey(self.inviter_pubkey) and is_canonical_pubkey(self.ephemeral_pubkey)):
            return False
        if not _HEX64_RE.fullmatch(self.challenge) or not _HEX128_RE.fullmatch(self.sig):
            return False
        try:
            if Keys.encode_apub(self.inviter_pubkey) != self.inviter_apub:
                return False
        except ValueError:
            return False
        if self.expires_at <= self.created_at:
            return False
        check_now = int(time.time()) if now is None else int(now)
        if check_now > self.expires_at:
            return False
        digest = invite_card_digest(
            self.invite_id,
            self.inviter_pubkey,
            self.ephemeral_pubkey,
            self.challenge,
            self.created_at,
            self.expires_at,
            self.relays,
        )
        return crypto.verify(digest, self.sig, self.inviter_pubkey)


class InvitationAcceptance(BaseModel):
    """Signed response produced by Agent B to redeem a one-time invitation."""

    version: int = 1
    invite_id: str
    inviter_pubkey: str
    responder_pubkey: str
    responder_apub: str
    challenge: str
    responded_at: int
    relays: list[str] = Field(default_factory=list)
    intro: str = ""
    sig: str = ""

    @classmethod
    def create(
        cls,
        card: InvitationCard,
        responder_keys: Keys,
        relays: list[str],
        *,
        intro: str = "",
        now: int | None = None,
    ) -> "InvitationAcceptance":
        check_now = int(time.time()) if now is None else int(now)
        if not card.verify(now=check_now):
            raise InvitationError("cannot accept an invalid or expired InvitationCard")
        if responder_keys.pubkey_hex == card.inviter_pubkey:
            raise InvitationError("an agent cannot accept its own invitation")
        clean_relays = [str(r).strip() for r in relays if str(r).strip()]
        if not clean_relays:
            raise InvitationError("at least one relay URL is required in InvitationAcceptance")
        digest = invite_response_digest(
            card.invite_id,
            card.inviter_pubkey,
            responder_keys.pubkey_hex,
            card.challenge,
            check_now,
            clean_relays,
        )
        sig = crypto.sign(digest, responder_keys.privkey_hex)
        return cls(
            version=1,
            invite_id=card.invite_id,
            inviter_pubkey=card.inviter_pubkey,
            responder_pubkey=responder_keys.pubkey_hex,
            responder_apub=responder_keys.apub,
            challenge=card.challenge,
            responded_at=check_now,
            relays=clean_relays,
            intro=str(intro or "").strip()[:500],
            sig=sig,
        )

    def verify(
        self,
        *,
        expected_invite_id: str | None = None,
        expected_inviter_pubkey: str | None = None,
        expected_challenge: str | None = None,
        expires_at: int | None = None,
    ) -> bool:
        if self.version != 1:
            return False
        if not is_valid_invite_token(self.invite_id):
            return False
        if expected_invite_id is not None and self.invite_id != expected_invite_id:
            return False
        if not (is_canonical_pubkey(self.inviter_pubkey) and is_canonical_pubkey(self.responder_pubkey)):
            return False
        if self.inviter_pubkey == self.responder_pubkey:
            return False
        if expected_inviter_pubkey is not None and self.inviter_pubkey != expected_inviter_pubkey:
            return False
        if not _HEX64_RE.fullmatch(self.challenge) or not _HEX128_RE.fullmatch(self.sig):
            return False
        if expected_challenge is not None and self.challenge != expected_challenge:
            return False
        if expires_at is not None and self.responded_at > int(expires_at):
            return False
        try:
            if Keys.encode_apub(self.responder_pubkey) != self.responder_apub:
                return False
        except ValueError:
            return False
        digest = invite_response_digest(
            self.invite_id,
            self.inviter_pubkey,
            self.responder_pubkey,
            self.challenge,
            self.responded_at,
            self.relays,
        )
        return crypto.verify(digest, self.sig, self.responder_pubkey)


def encrypt_invitation_card(card: InvitationCard, secret: str) -> str:
    """Encrypt a signed InvitationCard with the key derived from (invite_id, secret)."""
    if not card.verify(now=card.created_at):
        raise InvitationError("refusing to encrypt an invalid InvitationCard")
    conv_key = derive_card_key(card.invite_id, secret)
    plaintext = json.dumps(card.model_dump(), separators=(",", ":"), ensure_ascii=False)
    return nip44._encrypt_with_nonce(plaintext, conv_key, os.urandom(32))


def decrypt_invitation_card(
    ciphertext: str,
    invite_id: str,
    secret: str,
    *,
    now: int | None = None,
) -> InvitationCard:
    """Decrypt and verify an InvitationCard using (invite_id, secret)."""
    conv_key = derive_card_key(invite_id, secret)
    try:
        plaintext = nip44._decrypt_with_key(ciphertext, conv_key)
        raw = json.loads(plaintext)
        card = InvitationCard.model_validate(raw)
    except Exception as exc:
        raise InvitationError(f"failed to decrypt or parse InvitationCard: {exc}") from exc
    if not card.verify(expected_invite_id=invite_id, now=now):
        raise InvitationError("InvitationCard signature verification failed or invitation expired")
    return card


def encrypt_invitation_acceptance(
    acceptance: InvitationAcceptance,
    ephemeral_pubkey: str,
) -> str:
    """Seal InvitationAcceptance to the card's ephemeral_pubkey using a one-time keypair.

    Format: `<one_time_pubkey_hex>:<nip44_payload>`.
    Neither the rendezvous server nor a passive observer holding `#<secret>` can
    decrypt the acceptance or learn `responder_pubkey`, because only Agent A holds
    `ephemeral_privkey`.
    """
    if not is_canonical_pubkey(ephemeral_pubkey):
        raise InvitationError("ephemeral_pubkey must be 64 lowercase hex characters")
    if not acceptance.verify():
        raise InvitationError("refusing to encrypt an invalid InvitationAcceptance")
    seal_keys = Keys()
    plaintext = json.dumps(acceptance.model_dump(), separators=(",", ":"), ensure_ascii=False)
    payload = nip44.encrypt(plaintext, seal_keys.privkey_hex, ephemeral_pubkey)
    return f"{seal_keys.pubkey_hex}:{payload}"


def decrypt_invitation_acceptance(
    sealed_ciphertext: str,
    ephemeral_privkey_hex: str,
    *,
    expected_invite_id: str | None = None,
    expected_inviter_pubkey: str | None = None,
    expected_challenge: str | None = None,
    expires_at: int | None = None,
) -> InvitationAcceptance:
    """Unseal and verify an InvitationAcceptance using Agent A's ephemeral_privkey."""
    if not isinstance(sealed_ciphertext, str) or ":" not in sealed_ciphertext:
        raise InvitationError("malformed sealed acceptance ciphertext")
    seal_pub, payload = sealed_ciphertext.split(":", 1)
    if not is_canonical_pubkey(seal_pub):
        raise InvitationError("invalid one-time seal pubkey in acceptance ciphertext")
    try:
        plaintext = nip44.decrypt(payload, ephemeral_privkey_hex, seal_pub)
        raw = json.loads(plaintext)
        acceptance = InvitationAcceptance.model_validate(raw)
    except Exception as exc:
        raise InvitationError(f"failed to decrypt or parse InvitationAcceptance: {exc}") from exc
    if not acceptance.verify(
        expected_invite_id=expected_invite_id,
        expected_inviter_pubkey=expected_inviter_pubkey,
        expected_challenge=expected_challenge,
        expires_at=expires_at,
    ):
        raise InvitationError("InvitationAcceptance verification failed")
    return acceptance


def build_invitation_url(
    invite_id: str,
    secret: str,
    *,
    base_url: str = DEFAULT_INVITE_BASE_URL,
) -> str:
    """Construct a one-time invitation URL `https://a4a.network/i/<invite_id>#<secret>`."""
    _decode_token(invite_id, "invite_id")
    _decode_token(secret, "secret")
    clean_base = str(base_url or DEFAULT_INVITE_BASE_URL).rstrip("/")
    return f"{clean_base}/{invite_id}#{secret}"


def parse_invitation_url(url: str) -> dict[str, str]:
    """Parse an invitation URL and return `{base_url, origin, invite_id, secret}`.

    Raises `InvitationError` if the URL path does not end with `/<invite_id>` or
    if the fragment `#<secret>` is missing or invalid.
    """
    if not isinstance(url, str) or not url.strip():
        raise InvitationError("invitation URL is required")
    parts = urlsplit(url.strip())
    if parts.scheme not in ("https", "http") or not parts.netloc:
        raise InvitationError("invitation URL must be an http(s) URL")
    path_segments = [seg for seg in parts.path.split("/") if seg]
    if not path_segments:
        raise InvitationError("invitation URL is missing the invite_id path segment")
    invite_id = path_segments[-1]
    secret = parts.fragment.strip()
    if not secret:
        raise InvitationError(
            "invitation URL is missing the #<secret> fragment (make sure the full link including '#' was copied)"
        )
    _decode_token(invite_id, "invite_id")
    _decode_token(secret, "secret")
    prefix_path = "/" + "/".join(path_segments[:-1]) if len(path_segments) > 1 else ""
    origin = f"{parts.scheme}://{parts.netloc}"
    base_url = f"{origin}{prefix_path}"
    return {
        "origin": origin,
        "base_url": base_url,
        "invite_id": invite_id,
        "secret": secret,
    }


INBAND_ACCEPTANCE_PREFIX = "[A4A_INVITE_ACCEPTANCE_V1]"
REVOKED_CARD_MARKER = "REVOKED"


def build_rendezvous_delegation_event(
    invite_id: str,
    secret: str,
    *,
    created_at: int,
    expires_at: int,
) -> Event:
    """Build a deterministic self-signed kind-31000 delegation for the rendezvous keypair.

    Production A4A relays require an active kind-31000 delegation for the author of
    kind-31015 events. Because `rk = derive_rendezvous_keys(invite_id, secret)` is a
    deterministic ephemeral keypair, it self-delegates authority for the lifetime of
    the invitation without exposing `inviter_pubkey` or `responder_pubkey`.
    """
    from .delegation import create_delegation

    rk = derive_rendezvous_keys(invite_id, secret)
    return create_delegation(
        rk,
        rk.pubkey_hex,
        "a4a-invite-rendezvous",
        int(expires_at),
        created_at=int(created_at),
    )


def build_rendezvous_card_event(
    card: InvitationCard,
    secret: str,
) -> tuple[Event, str]:
    """Build and sign the blind relay rendezvous event holding `card_ciphertext`.

    Signed by `derive_rendezvous_keys(card.invite_id, secret)` so `inviter_pubkey`
    never appears on the outer relay envelope.
    Returns `(signed_event, card_ciphertext)`.
    """
    rk = derive_rendezvous_keys(card.invite_id, secret)
    deleg = build_rendezvous_delegation_event(
        card.invite_id,
        secret,
        created_at=int(card.created_at),
        expires_at=int(card.expires_at),
    )
    ciphertext = encrypt_invitation_card(card, secret)
    tags = [
        ["p", rk.pubkey_hex],
        ["d", f"card:{card.invite_id}"],
        ["expiration", str(int(card.expires_at))],
        ["delegation", deleg.id],
    ]
    ev = Event(
        kind=KIND_PRIVATE_MESSAGE,
        created_at=int(card.created_at),
        tags=tags,
        content=ciphertext,
    ).sign(rk)
    return ev, ciphertext


def build_rendezvous_revoke_event(
    invite_id: str,
    secret: str,
    *,
    expires_at: int | None = None,
    now: int | None = None,
    created_at: int | None = None,
) -> Event:
    """Build a NIP-33 replacement event that overwrites the encrypted card with REVOKED."""
    rk = derive_rendezvous_keys(invite_id, secret)
    ts = (int(time.time()) if now is None else int(now)) + 1
    exp = int(expires_at) if expires_at is not None else ts + 3600
    deleg_created = int(created_at) if created_at is not None else ts
    deleg = build_rendezvous_delegation_event(
        invite_id,
        secret,
        created_at=deleg_created,
        expires_at=exp,
    )
    tags = [
        ["p", rk.pubkey_hex],
        ["d", f"card:{invite_id}"],
        ["expiration", str(exp)],
        ["delegation", deleg.id],
    ]
    return Event(
        kind=KIND_PRIVATE_MESSAGE,
        created_at=ts,
        tags=tags,
        content=REVOKED_CARD_MARKER,
    ).sign(rk)


def build_rendezvous_acceptance_event(
    acceptance: InvitationAcceptance,
    ephemeral_pubkey: str,
    secret: str,
    *,
    expires_at: int | None = None,
    created_at: int | None = None,
) -> tuple[Event, str]:
    """Build and sign the blind relay rendezvous event holding `sealed_acceptance`."""
    rk = derive_rendezvous_keys(acceptance.invite_id, secret)
    sealed = encrypt_invitation_acceptance(acceptance, ephemeral_pubkey)
    exp = int(expires_at) if expires_at is not None else int(acceptance.responded_at) + DEFAULT_INVITE_TTL_SECONDS
    deleg_created = int(created_at) if created_at is not None else int(acceptance.responded_at)
    deleg = build_rendezvous_delegation_event(
        acceptance.invite_id,
        secret,
        created_at=deleg_created,
        expires_at=exp,
    )
    tags = [
        ["p", rk.pubkey_hex],
        ["d", f"accept:{acceptance.invite_id}"],
        ["expiration", str(exp)],
        ["delegation", deleg.id],
    ]
    ev = Event(
        kind=KIND_PRIVATE_MESSAGE,
        created_at=int(acceptance.responded_at),
        tags=tags,
        content=sealed,
    ).sign(rk)
    return ev, sealed


def format_inband_acceptance_message(acceptance: InvitationAcceptance) -> str:
    """Format an in-band private message carrying a signed `InvitationAcceptance`."""
    payload = json.dumps(acceptance.model_dump(), separators=(",", ":"), ensure_ascii=False)
    return f"{INBAND_ACCEPTANCE_PREFIX}\n{payload}"


def parse_inband_acceptance_message(content: str) -> InvitationAcceptance | None:
    """Return `InvitationAcceptance` if `content` starts with `INBAND_ACCEPTANCE_PREFIX`, else None."""
    if not isinstance(content, str):
        return None
    stripped = content.strip()
    if not stripped.startswith(INBAND_ACCEPTANCE_PREFIX):
        return None
    body = stripped[len(INBAND_ACCEPTANCE_PREFIX):].strip()
    if not body:
        return None
    try:
        raw = json.loads(body)
        return InvitationAcceptance.model_validate(raw)
    except Exception:
        return None

