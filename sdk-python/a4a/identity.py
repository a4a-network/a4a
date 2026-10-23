"""Identity attestations (KYC layer, §2.1): verify signed attestations.

An issuer (verifier) signs an IdentityAttestation (kind 31021) claiming that the
`subject` key belongs to a verified identity. This module performs only CRYPTOGRAPHIC
verification (issuer signature, subject match, expiry). Whether the issuer is TRUSTED
is a separate question handled by Web of Trust or an explicit trusted-issuer list;
see `Agent.get_identity`.

Outside the SDK (infrastructure backlog): OAuth bridges to banks/government services
that issue attestations, zero-knowledge proofs of verification without revealing the
issuer or personal data, and NIP-05.
"""
import time

from .event import Event, is_canonical_pubkey
from .types import KIND_IDENTITY_ATTESTATION


def is_self_issued(attestation: Event) -> bool:
    """Return whether issuer and subject are the same key: a self-claim, not proof.

    A non-canonical `p` tag is treated as self-issued: string comparison is meaningless
    if one key has multiple spellings. An issuer could insert whitespace into the
    subject hex, bypass this check, and issue itself an attestation that looked external
    (2026-08-29 internal audit, F7). Reject identities that cannot be matched.
    """
    subject = attestation.tag_value("p")
    if subject is None or not is_canonical_pubkey(subject):
        return True
    return attestation.pubkey == subject


def verify_identity_attestation(attestation: Event, subject_pubkey: str,
                                now: int | None = None,
                                allow_self_issued: bool = False) -> bool:
    """Return whether an attestation is valid for `subject_pubkey` and not expired.

    Kind and issuer signature are verified. Self-issued attestations are rejected by
    default: they are cryptographically sound but state only "I consider myself
    verified" while looking genuine to consumers (2026-08-17 audit, F3). Set
    `allow_self_issued=True` only when intentionally reading self-claims.

    Issuer trust is NOT checked, which is crucial: rejecting self-signatures does not
    stop someone issuing any level to themselves from a SECOND key. The actual boundary
    is a trusted-issuer list (`Agent.get_identity(trusted_issuers=...)`).
    """
    now = now if now is not None else int(time.time())
    if attestation.kind != KIND_IDENTITY_ATTESTATION:
        return False
    if not allow_self_issued and is_self_issued(attestation):
        return False
    if not attestation.verify_protocol():
        return False
    if attestation.tag_value("p") != subject_pubkey:
        return False
    try:
        expiration = attestation.expiration()
    except ValueError:
        return False
    if expiration is not None and expiration <= now:
        return False
    return True
