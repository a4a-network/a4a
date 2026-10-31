"""a4a-sdk — Python SDK for the A4A (Agent for Agent) protocol."""
from .agent import Agent
from .delegation import (
    create_delegation, create_revocation, is_revocation_valid, validate_delegation)
from .event import Event
from .keys import Keys
from . import nip44
from .nip44 import Nip44Error
from . import giftwrap
from .giftwrap import GiftWrapError, KIND_GIFT_WRAP, KIND_SEAL
from . import identity
from .identity import verify_identity_attestation
from . import files
from .files import build_file_reference, parse_file_reference, verify_file
from . import invitations
from .invitations import (
    InvitationAcceptance, InvitationCard, InvitationError,
    build_invitation_url, decrypt_invitation_acceptance, decrypt_invitation_card,
    encrypt_invitation_acceptance, encrypt_invitation_card,
    generate_invite_id, generate_invite_secret, parse_invitation_url,
)
from .relay import InsufficientCopies, RelayClient, RelayError, RelayUnreachable
from .reputation import (
    DeliveryReputation, Reputation,
    build_trust_graph, compute_delivery_reputation, compute_reputation,
    trust_weight, web_of_trust)
from .sanitize import wrap_untrusted, extract_urls, strip_control
from .types import (
    AckReceipt, AgentProfile, Agreement, ConnectionRequest, IdentityAttestation,
    Intent, Invoice, Offer, Report, Review, SearchIntent, TaskRequest, TaskResult,
    TaskStatus, TrustAssertion, agreement_digest,
    KIND_DELEGATION, KIND_DELEGATION_REVOCATION, KIND_RELAY_LIST,
    KIND_AGENT_PROFILE, KIND_INTENT, KIND_OFFER,
    KIND_AGREEMENT, KIND_REVIEW, KIND_INVOICE, KIND_SEARCH_INTENT,
    KIND_TRUST_ASSERTION, KIND_IDENTITY_ATTESTATION, KIND_CONNECTION_REQUEST,
    KIND_TASK_REQUEST, KIND_TASK_STATUS,
    KIND_TASK_RESULT, KIND_PRIVATE_MESSAGE, KIND_PRIVATE_RUMOR,
    KIND_ACK_RECEIPT, KIND_REPORT,
)

__all__ = [
    "Agent", "Keys", "Event", "RelayClient", "InsufficientCopies",
    "RelayError", "RelayUnreachable",
    "create_delegation", "create_revocation", "is_revocation_valid",
    "validate_delegation",
    "KIND_DELEGATION_REVOCATION",
    "Reputation", "compute_reputation", "web_of_trust",
    "DeliveryReputation", "compute_delivery_reputation",
    "build_trust_graph", "trust_weight",
    "wrap_untrusted", "extract_urls", "strip_control",
    "nip44", "Nip44Error",
    "giftwrap", "GiftWrapError", "KIND_GIFT_WRAP", "KIND_SEAL", "KIND_PRIVATE_RUMOR",
    "identity", "verify_identity_attestation", "IdentityAttestation",
    "KIND_IDENTITY_ATTESTATION", "ConnectionRequest", "KIND_CONNECTION_REQUEST",
    "files", "build_file_reference", "parse_file_reference", "verify_file",
    "invitations", "InvitationCard", "InvitationAcceptance", "InvitationError",
    "build_invitation_url", "parse_invitation_url",
    "encrypt_invitation_card", "decrypt_invitation_card",
    "encrypt_invitation_acceptance", "decrypt_invitation_acceptance",
    "generate_invite_id", "generate_invite_secret",
    "AgentProfile", "Intent", "Offer", "Agreement", "Review", "Invoice",
    "SearchIntent", "TrustAssertion", "TaskRequest", "TaskStatus",
    "TaskResult", "AckReceipt", "Report", "agreement_digest",
    "KIND_DELEGATION", "KIND_RELAY_LIST", "KIND_AGENT_PROFILE", "KIND_INTENT", "KIND_OFFER",
    "KIND_AGREEMENT", "KIND_REVIEW", "KIND_INVOICE", "KIND_SEARCH_INTENT",
    "KIND_TRUST_ASSERTION", "KIND_TASK_REQUEST", "KIND_TASK_STATUS",
    "KIND_TASK_RESULT", "KIND_PRIVATE_MESSAGE", "KIND_ACK_RECEIPT", "KIND_REPORT",
]
