"""Owner-configured private contacts and a managed local inbox, without an LLM."""
from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from pydantic import ValidationError

from a4a import Agent, file_gateway, files, keyfile, types
from a4a.delegation import delegation_target, signed_agent_name
from a4a.event import Event, is_canonical_pubkey
from a4a.inbox import InboxError, InboxPolicyChanged, InboxStore, _private_directory
from a4a.inbox_receiver import (InboxHistory, InboxReceiver,
                                authorized_sender_keys, owner_mandates_for_senders)
from a4a.outbox import OUTBOUND_CATEGORIES, RESTRICTED_OUTBOUND_CATEGORIES
from a4a.relay import RelayError
from a4a.sanitize import MANDATORY_BRIDGE_PREAMBLE_RU, wrap_untrusted

from . import identity

log = logging.getLogger(__name__)

VALID_TRUST_LEVELS = (1, 2, 3)
VALID_ORIGIN_LABELS = (
    "external_contact",
    "own_developer",
    "scoped_partner",
    "owner_agent",
)
_DEFAULT_ORIGIN_BY_LEVEL = {
    1: "external_contact",
    2: "own_developer",
    3: "scoped_partner",
}

#: Heuristic detector for restricted commitments, financial transfers, user data, or
#: internal metrics when an agent attempts to send to an external contact under a
#: routine category ('routine_dev' or 'fact').
_RESTRICTED_CONTENT_PATTERNS = (
    ("money", re.compile(
        r"(?:\b(?:transfer|pay|invoice|refund|wire|usdt|btc|eth|usd|eur|gbp)\b"
        r"|\b(?:\u043f\u0435\u0440\u0435\u0432\u0435\u0434|\u043e\u043f\u043b\u0430\u0442|\u0437\u0430\u043f\u043b\u0430\u0442|\u0441\u0447\u0435\u0442|\u0441\u0447\u0451\u0442|\u0440\u0443\u0431|\u0434\u043e\u043b\u043b\u0430\u0440)\w*)"
        r".{0,40}\b\d+",
        re.IGNORECASE | re.DOTALL,
    )),
    ("promise", re.compile(
        r"\b(?:we\s+(?:promise|guarantee|commit\s+to|agree\s+to\s+deliver)"
        r"|i\s+(?:promise|guarantee|commit\s+to)"
        r"|\u043c\u044b\s+(?:\u043e\u0431\u0435\u0449\u0430\u0435\u043c|\u0433\u0430\u0440\u0430\u043d\u0442\u0438\u0440\u0443\u0435\u043c|\u043e\u0431\u044f\u0437\u0443\u0435\u043c\u0441\u044f)"
        r"|\u043e\u0431\u0435\u0449\u0430\u044e\s+\u0441\u0434\u0435\u043b\u0430\u0442\u044c|\u0433\u0430\u0440\u0430\u043d\u0442\u0438\u0440\u0443\u044e\s+\u0441\u0440\u043e\u043a)\b",
        re.IGNORECASE,
    )),
    ("internal_metrics", re.compile(
        r"\b(?:mrr|arr|churn\s+rate|paying\s+users|conversion\s+rate|internal\s+revenue"
        r"|\u0432\u044b\u0440\u0443\u0447\u043a\w*|\u043f\u043b\u0430\u0442\u044f\u0449\u0438\u0445\s+\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b"
        r"|\u0432\u043d\u0443\u0442\u0440\u0435\u043d\u043d\w+\s+\u043c\u0435\u0442\u0440\u0438\u043a\w*)\b",
        re.IGNORECASE,
    )),
)


@dataclass(frozen=True)
class InboxPolicy:
    version: int
    recipient: str
    consumer: str
    relay: str
    allowed_peers: frozenset[str]
    start_after: int
    enabled: bool = True
    notify_interval: int = 60
    notify_per_hour: int = 12
    # Send a `received` ACK the moment a letter from an allowed sender is stored. Off by
    # default; absent in policy files written before 23.09.2026, which stay valid.
    ack_on_receipt: bool = False
    # Explicit organization trust. Legacy policies omit this and remain exact-peer-only.
    allowed_owners: frozenset[str] = frozenset()
    # Per-peer trust levels (L1-L3), origin labels, and L3 topic scopes (2026-10-30).
    peer_trust: dict = None  # type: ignore[assignment]
    # Single-use owner send permits for L1 contacts and restricted categories.
    owner_send_permits: tuple = ()
    # Intake mode for unrecognized senders: 'closed' (default), 'reception', or 'public_service'.
    intake_mode: str = "closed"
    # Explicitly blocked sender pubkeys (rejected even in 'reception' mode).
    blocked_senders: frozenset[str] = frozenset()
    # Local registry of one-time expiring invitations created by this mailbox.
    invitations: dict = None  # type: ignore[assignment]
    # Optional human-readable contact notes/labels keyed by canonical pubkey.
    peer_notes: dict = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.peer_trust is None:
            object.__setattr__(self, "peer_trust", {})
        if self.invitations is None:
            object.__setattr__(self, "invitations", {})
        if self.peer_notes is None:
            object.__setattr__(self, "peer_notes", {})

    def peer_policy(self, pubkey: str, *, is_owner_agent: bool = False) -> dict:
        """Return effective trust level (1..3), origin label, label, and scope for `pubkey`."""
        entry = (self.peer_trust or {}).get(pubkey)
        note_label = str((self.peer_notes or {}).get(pubkey, "")).strip()
        if entry is not None:
            level = int(entry["level"])
            origin = str(entry["origin"])
            topics = list(entry.get("topics", ()))
            remote_attested = bool(entry.get("remote_trust_attested", False))
            label = str(entry.get("label", "")).strip() or note_label
        elif is_owner_agent or pubkey in self.allowed_owners:
            level = 2
            origin = "owner_agent"
            topics = []
            remote_attested = False
            label = note_label
        else:
            # Legacy allowed_peers without an explicit peer_trust entry default to L2
            # routine autonomy with external_contact origin label so existing internal
            # mailboxes continue operating while still blocking restricted categories.
            level = 2
            origin = "external_contact"
            topics = []
            remote_attested = False
            label = note_label
        l3_ready = (level == 3 and remote_attested and len(topics) > 0)
        out = {
            "level": level,
            "origin": origin,
            "topics": topics,
            "remote_trust_attested": remote_attested,
            "autonomous_reply_allowed": (level == 2 or l3_ready),
            "requires_owner_approval_for_all_replies": (level == 1 or (level == 3 and not l3_ready)),
            "always_requires_owner_approval_categories": sorted(RESTRICTED_OUTBOUND_CATEGORIES),
        }
        if label:
            out["label"] = label
        return out


VALID_INTAKE_MODES = ("closed", "reception", "public_service")

_OFFICIAL_A4A_RELAYS = frozenset({
    "wss://relay.a4a.network",
    "wss://eu1.a4a.network",
    "wss://eu2.a4a.network",
    "wss://us1.a4a.network",
    "wss://us2.a4a.network",
    "wss://sg1.a4a.network",
    "wss://kz1.a4a.network",
    "wss://ru1.a4a.network",
    "wss://ru2.a4a.network",
})

_CORE_PUBLIC_RELAYS = (
    "wss://eu1.a4a.network",
    "wss://ru1.a4a.network",
    "wss://us1.a4a.network",
    "wss://sg1.a4a.network",
)

_OPTIONAL_POLICY_FIELDS = {
    "ack_on_receipt",
    "allowed_owners",
    "peer_trust",
    "owner_send_permits",
    "intake_mode",
    "blocked_senders",
    "invitations",
    "peer_notes",
}


def _validate_peer_notes(raw_notes) -> dict[str, str]:
    if raw_notes is None:
        return {}
    if not isinstance(raw_notes, dict) or len(raw_notes) > 200:
        raise InboxError("peer_notes must be a bounded JSON object")
    validated: dict[str, str] = {}
    for pubkey, note in raw_notes.items():
        if not isinstance(pubkey, str) or not is_canonical_pubkey(pubkey):
            raise InboxError("peer_notes keys must be canonical 64-hex public keys")
        if not isinstance(note, str) or len(note) > 240:
            raise InboxError("peer_notes values must be strings up to 240 characters")
        if note.strip():
            validated[pubkey] = note.strip()
    return validated


def _validate_peer_trust(raw_peer_trust) -> dict[str, dict]:
    if raw_peer_trust is None:
        return {}
    if not isinstance(raw_peer_trust, dict) or len(raw_peer_trust) > 200:
        raise InboxError("peer_trust must be a bounded JSON object mapping pubkeys to policy objects")
    validated: dict[str, dict] = {}
    for pubkey, spec in raw_peer_trust.items():
        if not isinstance(pubkey, str) or not is_canonical_pubkey(pubkey):
            raise InboxError("peer_trust keys must be canonical 64-hex public keys")
        if not isinstance(spec, dict):
            raise InboxError("peer_trust entry must be a JSON object")
        allowed_keys = {"level", "origin", "topics", "remote_trust_attested", "label"}
        if not set(spec) <= allowed_keys or "level" not in spec:
            raise InboxError("peer_trust entry contains invalid or missing fields")
        level = spec["level"]
        if type(level) is not int or level not in VALID_TRUST_LEVELS:
            raise InboxError("peer_trust level must be 1, 2, or 3")
        origin = spec.get("origin", _DEFAULT_ORIGIN_BY_LEVEL[level])
        if not isinstance(origin, str) or origin not in VALID_ORIGIN_LABELS:
            raise InboxError(f"peer_trust origin must be one of {VALID_ORIGIN_LABELS}")
        topics = spec.get("topics", [])
        if (not isinstance(topics, list) or len(topics) > 32
                or any(not isinstance(t, str) or not (1 <= len(t.strip()) <= 128) for t in topics)):
            raise InboxError("peer_trust topics must be a list of 1..32 non-empty strings")
        remote_attested = spec.get("remote_trust_attested", False)
        if type(remote_attested) is not bool:
            raise InboxError("peer_trust remote_trust_attested must be a JSON boolean")
        label = spec.get("label", "")
        if not isinstance(label, str) or len(label) > 160:
            raise InboxError("peer_trust label must be a string up to 160 characters")
        entry_dict = {
            "level": level,
            "origin": origin,
            "topics": [t.strip() for t in topics],
            "remote_trust_attested": remote_attested,
        }
        if label.strip():
            entry_dict["label"] = label.strip()
        validated[pubkey] = entry_dict
    return validated


def _validate_send_permits(raw_permits) -> tuple[dict, ...]:
    if raw_permits is None:
        return ()
    if not isinstance(raw_permits, (list, tuple)) or len(raw_permits) > 200:
        raise InboxError("owner_send_permits must be a bounded list")
    validated: list[dict] = []
    for item in raw_permits:
        if not isinstance(item, dict):
            raise InboxError("owner_send_permits entry must be a JSON object")
        token = item.get("token")
        recipient = item.get("recipient")
        if (not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token)
                or not isinstance(recipient, str) or not is_canonical_pubkey(recipient)):
            raise InboxError("invalid owner_send_permits token or recipient")
        sha = item.get("content_sha256")
        if sha is not None and (not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha)):
            raise InboxError("invalid owner_send_permits content_sha256")
        cat = item.get("category")
        if cat is not None and cat not in OUTBOUND_CATEGORIES:
            raise InboxError("invalid owner_send_permits category")
        exp = item.get("expires_at", 0)
        if type(exp) is not int or exp < 0:
            raise InboxError("invalid owner_send_permits expires_at")
        validated.append({
            "token": token,
            "recipient": recipient,
            "content_sha256": sha,
            "category": cat,
            "expires_at": exp,
        })
    return tuple(validated)


def _validate_invitations(raw_invitations) -> dict[str, dict]:
    if raw_invitations is None:
        return {}
    if not isinstance(raw_invitations, dict) or len(raw_invitations) > 100:
        raise InboxError("invitations must be a bounded JSON object")
    from a4a.invitations import INVITE_STATUSES, is_valid_invite_token
    validated: dict[str, dict] = {}
    for inv_id, rec in raw_invitations.items():
        if not is_valid_invite_token(inv_id) or not isinstance(rec, dict):
            raise InboxError("invalid invitation record in inbox policy")
        secret = rec.get("secret", "")
        eph_priv = rec.get("ephemeral_privkey", "")
        eph_pub = rec.get("ephemeral_pubkey", "")
        challenge = rec.get("challenge", "")
        created_at = rec.get("created_at", 0)
        expires_at = rec.get("expires_at", 0)
        status = rec.get("status", "open")
        if (not is_valid_invite_token(secret)
                or not isinstance(eph_priv, str) or not re.fullmatch(r"[0-9a-f]{64}", eph_priv)
                or not isinstance(eph_pub, str) or not is_canonical_pubkey(eph_pub)
                or not isinstance(challenge, str) or not re.fullmatch(r"[0-9a-f]{64}", challenge)
                or type(created_at) is not int or type(expires_at) is not int
                or expires_at <= created_at
                or status not in INVITE_STATUSES):
            raise InboxError("malformed fields in invitation record")
        accepted_by = rec.get("accepted_by")
        if accepted_by is not None and (not isinstance(accepted_by, str) or not is_canonical_pubkey(accepted_by)):
            raise InboxError("invalid accepted_by in invitation record")
        accepted_at = rec.get("accepted_at")
        if accepted_at is not None and type(accepted_at) is not int:
            raise InboxError("invalid accepted_at in invitation record")
        validated[inv_id] = {
            "invite_id": inv_id,
            "secret": secret,
            "ephemeral_privkey": eph_priv,
            "ephemeral_pubkey": eph_pub,
            "challenge": challenge,
            "created_at": created_at,
            "expires_at": expires_at,
            "label": str(rec.get("label", ""))[:120],
            "url": str(rec.get("url", ""))[:512],
            "status": status,
            "accepted_by": accepted_by,
            "accepted_at": accepted_at,
        }
    return validated


def _validate(data):
    fields = set(InboxPolicy.__dataclass_fields__)
    if (not isinstance(data, dict) or not set(data) <= fields
            or not fields - _OPTIONAL_POLICY_FIELDS <= set(data)):
        raise InboxError("invalid inbox policy fields")
    if type(data.get("ack_on_receipt", False)) is not bool:
        raise InboxError("ack_on_receipt must be a JSON boolean")
    if type(data["version"]) is not int or data["version"] != 1:
        raise InboxError("unsupported inbox policy version")
    if not isinstance(data["recipient"], str) or not is_canonical_pubkey(data["recipient"]):
        raise InboxError("invalid inbox policy recipient")
    if not isinstance(data["consumer"], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", data["consumer"]):
        raise InboxError("invalid inbox consumer")
    peers = data["allowed_peers"]
    if not isinstance(peers, list) or len(peers) > 100 or any(not isinstance(p, str) or not is_canonical_pubkey(p) for p in peers) or len(set(peers)) != len(peers):
        raise InboxError("allowed_peers must be a bounded list of exact public keys, without wildcards")
    owners = data.get("allowed_owners", [])
    if (not isinstance(owners, list) or len(owners) > 100
            or any(not isinstance(p, str) or not is_canonical_pubkey(p) for p in owners)
            or len(set(owners)) != len(owners)):
        raise InboxError("allowed_owners must be a bounded list of exact public keys, without wildcards")
    blocked = data.get("blocked_senders", [])
    if (not isinstance(blocked, list) or len(blocked) > 200
            or any(not isinstance(p, str) or not is_canonical_pubkey(p) for p in blocked)
            or len(set(blocked)) != len(blocked)):
        raise InboxError("blocked_senders must be a bounded list of exact public keys")
    intake_mode = data.get("intake_mode", "closed")
    if not isinstance(intake_mode, str) or intake_mode not in VALID_INTAKE_MODES:
        raise InboxError(f"intake_mode must be one of {VALID_INTAKE_MODES}")
    peer_trust = _validate_peer_trust(data.get("peer_trust"))
    permits = _validate_send_permits(data.get("owner_send_permits"))
    invitations = _validate_invitations(data.get("invitations"))
    peer_notes = _validate_peer_notes(data.get("peer_notes"))
    if type(data["enabled"]) is not bool:
        raise InboxError("enabled must be a JSON boolean")
    for key, low, high in (("start_after", 0, 2**63 - 1), ("notify_interval", 10, 3600), ("notify_per_hour", 1, 60)):
        if type(data[key]) is not int or not low <= data[key] <= high:
            raise InboxError("invalid inbox numeric policy")
    if not isinstance(data["relay"], str):
        raise InboxError("invalid inbox relay")
    InboxHistory(data["relay"], data["recipient"])
    return InboxPolicy(**{**data, "allowed_peers": frozenset(peers),
                          "allowed_owners": frozenset(owners),
                          "blocked_senders": frozenset(blocked),
                          "intake_mode": intake_mode,
                          "peer_trust": peer_trust,
                          "owner_send_permits": permits,
                          "invitations": invitations,
                          "peer_notes": peer_notes})


def load_policy():
    path = identity.IDENTITY_DIR / "inbox-policy.json"
    if not path.exists():
        if path.is_symlink():
            raise InboxError("inbox policy must not be a symlink")
        return None
    if path.is_symlink() or path.stat().st_size > 32 * 1024:
        raise InboxError("invalid inbox policy file")
    if not keyfile.is_private(path)[0]:
        raise InboxError("inbox policy permissions are not private; access is closed")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InboxError("inbox policy is unreadable; private access is closed") from exc
    return _validate(data)


def _write_policy_data(data: dict, *, replace: bool) -> InboxPolicy:
    policy = _validate(data)
    path = identity.IDENTITY_DIR / "inbox-policy.json"
    if path.exists() and not replace:
        raise InboxError("inbox policy exists; explicit --replace is required")
    if path.is_symlink():
        raise InboxError("inbox policy must not be a symlink")
    if (policy.allowed_owners
            and (identity.IDENTITY_DIR / "inbox" / "inbox.sqlite3").exists()):
        with _open_store(policy) as store:
            if store.dialogue_enabled():
                raise InboxError(
                    "allowed_owners cannot be configured while dialogue mode is active")
    _private_directory(identity.IDENTITY_DIR)
    fd, temporary = tempfile.mkstemp(prefix="inbox-policy-", suffix=".tmp", dir=identity.IDENTITY_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            if not keyfile.harden_and_check(temporary, force=True)[0]:
                raise InboxError("cannot protect inbox policy")
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise InboxError("inbox policy was created concurrently") from exc
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return policy


def _policy_to_json_data(policy: InboxPolicy, *, peer_trust=None, owner_send_permits=None,
                         intake_mode=None, blocked_senders=None, invitations=None,
                         peer_notes=None) -> dict:
    data = asdict(policy)
    data["allowed_peers"] = list(policy.allowed_peers)
    data["allowed_owners"] = list(policy.allowed_owners)
    effective_trust = policy.peer_trust if peer_trust is None else peer_trust
    effective_permits = policy.owner_send_permits if owner_send_permits is None else owner_send_permits
    effective_mode = policy.intake_mode if intake_mode is None else intake_mode
    effective_blocked = policy.blocked_senders if blocked_senders is None else blocked_senders
    effective_invitations = policy.invitations if invitations is None else invitations
    effective_notes = policy.peer_notes if peer_notes is None else peer_notes
    if effective_trust:
        data["peer_trust"] = dict(effective_trust)
    else:
        data.pop("peer_trust", None)
    if effective_permits:
        data["owner_send_permits"] = list(effective_permits)
    else:
        data.pop("owner_send_permits", None)
    if effective_mode and effective_mode != "closed":
        data["intake_mode"] = effective_mode
    else:
        data.pop("intake_mode", None)
    if effective_blocked:
        data["blocked_senders"] = sorted(effective_blocked)
    else:
        data.pop("blocked_senders", None)
    if effective_invitations:
        data["invitations"] = dict(effective_invitations)
    else:
        data.pop("invitations", None)
    if effective_notes:
        data["peer_notes"] = dict(effective_notes)
    else:
        data.pop("peer_notes", None)
    return data


def configure(consumer, allowed_peers, *, start_after=None, replace=False,
              ack_on_receipt=False, allowed_owners=(), peer_trust=None,
              owner_send_permits=None, intake_mode=None, blocked_senders=None,
              invitations=None, peer_notes=None):
    """Explicit local owner CLI action. Never an MCP tool and never issues a mandate."""
    if not identity.IDENTITY_FILE.is_file():
        raise InboxError("create and verify the intended identity before configuring inbox")
    from a4a.keys import Keys
    allowed_peers = [Keys.normalize_pubkey(p) for p in allowed_peers]
    allowed_owners = [Keys.normalize_pubkey(o) for o in allowed_owners]
    path = identity.IDENTITY_DIR / "inbox-policy.json"
    if path.is_symlink():
        raise InboxError("inbox policy must not be a symlink")
    existing = load_policy() if replace and path.exists() else None
    if peer_trust is None and existing is not None and existing.peer_trust:
        peer_trust = {k: v for k, v in existing.peer_trust.items() if k in allowed_peers}
    if owner_send_permits is None and existing is not None and existing.owner_send_permits:
        owner_send_permits = list(existing.owner_send_permits)
    if intake_mode is None and existing is not None:
        intake_mode = existing.intake_mode
    if blocked_senders is None and existing is not None and existing.blocked_senders:
        blocked_senders = set(existing.blocked_senders) - set(allowed_peers)
    if invitations is None and existing is not None and existing.invitations:
        invitations = dict(existing.invitations)
    if peer_notes is None and existing is not None and existing.peer_notes:
        peer_notes = {k: v for k, v in existing.peer_notes.items() if k in allowed_peers}
    normalized_trust = None
    if peer_trust:
        normalized_trust = {Keys.normalize_pubkey(k): v for k, v in dict(peer_trust).items()}
    norm_blocked = frozenset(Keys.normalize_pubkey(p) for p in (blocked_senders or ()))
    norm_notes = {Keys.normalize_pubkey(k): str(v).strip() for k, v in dict(peer_notes or {}).items() if str(v).strip()}
    keys = _existing_keys()
    from .server import _relay_url
    draft = InboxPolicy(
        1, keys.pubkey_hex, consumer, _relay_url(),
        frozenset(allowed_peers), int(time.time()) if start_after is None else start_after,
        ack_on_receipt=ack_on_receipt,
        allowed_owners=frozenset(allowed_owners),
        peer_trust=normalized_trust or {},
        owner_send_permits=tuple(owner_send_permits or ()),
        intake_mode=intake_mode or "closed",
        blocked_senders=norm_blocked,
        invitations=dict(invitations or {}),
        peer_notes=norm_notes,
    )
    data = _policy_to_json_data(
        draft,
        peer_trust=normalized_trust,
        owner_send_permits=owner_send_permits,
        intake_mode=draft.intake_mode,
        blocked_senders=norm_blocked,
        invitations=draft.invitations,
        peer_notes=norm_notes,
    )
    data["allowed_peers"] = list(allowed_peers)
    data["allowed_owners"] = list(allowed_owners)
    return _write_policy_data(data, replace=replace)


def set_peer_trust(pubkey: str, *, level: int | None = None, origin: str | None = None,
                   topics=(), remote_trust_attested: bool | None = None,
                   label: str | None = None) -> InboxPolicy:
    """Owner CLI action: set or update trust level (L1..L3), origin, label, and L3 topics for a peer."""
    from a4a.keys import Keys
    norm = Keys.normalize_pubkey(pubkey)
    policy = active_policy()
    prev = dict((policy.peer_trust or {}).get(norm) or {})
    if level is None:
        level = int(prev.get("level", 1))
    if level not in VALID_TRUST_LEVELS:
        raise InboxError(f"trust level must be 1, 2, or 3; got {level!r}")
    resolved_origin = origin or prev.get("origin") or _DEFAULT_ORIGIN_BY_LEVEL[level]
    if resolved_origin not in VALID_ORIGIN_LABELS:
        raise InboxError(f"origin must be one of {VALID_ORIGIN_LABELS}; got {resolved_origin!r}")
    clean_topics = [str(t).strip() for t in (topics if topics else prev.get("topics", ())) if str(t).strip()]
    if level == 3 and not clean_topics:
        raise InboxError("trust level L3 requires at least one topic in --topic")
    resolved_attested = (
        bool(prev.get("remote_trust_attested", False))
        if remote_trust_attested is None
        else bool(remote_trust_attested)
    )
    resolved_label = (
        str(prev.get("label", "")).strip()
        if label is None
        else str(label).strip()
    )
    if len(resolved_label) > 160:
        raise InboxError("peer_trust label must be a string up to 160 characters")
    peers = set(policy.allowed_peers) | {norm}
    new_trust = dict(policy.peer_trust or {})
    entry = {
        "level": int(level),
        "origin": resolved_origin,
        "topics": clean_topics,
        "remote_trust_attested": resolved_attested,
    }
    if resolved_label:
        entry["label"] = resolved_label
    new_trust[norm] = entry
    new_notes = dict(policy.peer_notes or {})
    if label is not None:
        if resolved_label:
            new_notes[norm] = resolved_label
        else:
            new_notes.pop(norm, None)
    data = _policy_to_json_data(
        policy,
        peer_trust=new_trust,
        owner_send_permits=policy.owner_send_permits,
        peer_notes=new_notes,
    )
    data["allowed_peers"] = sorted(peers)
    return _write_policy_data(data, replace=True)


def grant_send_permit(to_pubkey: str, *, text: str | None = None,
                      content_sha256: str | None = None,
                      category: str | None = None,
                      ttl_seconds: int = 3600) -> dict:
    """Owner CLI action: issue a single-use send permit for an L1 peer or restricted category."""
    import hashlib
    import secrets
    from a4a.keys import Keys
    norm = Keys.normalize_pubkey(to_pubkey)
    policy = require_peer(norm)
    if text is not None:
        sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    elif content_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", content_sha256):
            raise InboxError("content_sha256 must be 64 lowercase hex characters")
        sha = content_sha256
    else:
        sha = None
    if category is not None and category not in OUTBOUND_CATEGORIES:
        raise InboxError(f"category must be one of {OUTBOUND_CATEGORIES}")
    now = int(time.time())
    token = secrets.token_hex(16)
    permit = {
        "token": token,
        "recipient": norm,
        "content_sha256": sha,
        "category": category,
        "expires_at": now + max(60, min(86400 * 7, int(ttl_seconds))),
    }
    active_permits = [
        p for p in (policy.owner_send_permits or ())
        if p.get("expires_at", 0) == 0 or p["expires_at"] > now
    ]
    active_permits.append(permit)
    data = _policy_to_json_data(policy, owner_send_permits=active_permits)
    _write_policy_data(data, replace=True)
    return permit


def _detect_restricted_outbound_content(text: str) -> str | None:
    for cat, pattern in _RESTRICTED_CONTENT_PATTERNS:
        if pattern.search(text):
            return cat
    return None


def _consume_matching_permit(policy: InboxPolicy, recipient: str, content_sha256: str,
                             category: str, token: str | None) -> bool:
    now = int(time.time())
    permits = list(policy.owner_send_permits or ())
    matched_idx = None
    for idx, p in enumerate(permits):
        exp = p.get("expires_at", 0)
        if exp and exp <= now:
            continue
        if p.get("recipient") != recipient:
            continue
        if token is not None and p.get("token") != token:
            continue
        if p.get("content_sha256") is not None and p.get("content_sha256") != content_sha256:
            continue
        if p.get("category") is not None and p.get("category") != category:
            continue
        matched_idx = idx
        break
    if matched_idx is None:
        return False
    remaining = [
        p for i, p in enumerate(permits)
        if i != matched_idx and (p.get("expires_at", 0) == 0 or p["expires_at"] > now)
    ]
    data = _policy_to_json_data(policy, owner_send_permits=remaining)
    _write_policy_data(data, replace=True)
    return True


def authorize_outbound_send(
    pubkey: str,
    text: str,
    *,
    category: str = "routine_dev",
    topic: str | None = None,
    owner_approval_token: str | None = None,
    owner_approved: bool = False,
) -> dict:
    """Technical Outbound Policy Gate for Trust Levels L1-L3 and Restricted Categories."""
    import hashlib
    from a4a.keys import Keys
    norm = Keys.normalize_pubkey(pubkey)
    policy = require_legacy_send(norm)
    if category not in OUTBOUND_CATEGORIES:
        raise InboxError(
            f"Invalid outbound category {category!r}; must be one of {', '.join(OUTBOUND_CATEGORIES)}."
        )
    content_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    peer_policy_fn = getattr(policy, "peer_policy", None)
    peer_info = (
        peer_policy_fn(norm)
        if callable(peer_policy_fn)
        else {"level": 2, "origin": "external_contact", "topics": [], "remote_trust_attested": False}
    )
    level = peer_info["level"]
    origin = peer_info["origin"]
    topics = peer_info["topics"]
    remote_attested = peer_info["remote_trust_attested"]

    effective_category = category
    if category in ("routine_dev", "fact") and (level in (1, 3) or origin in ("external_contact", "scoped_partner")):
        detected = _detect_restricted_outbound_content(text)
        if detected is not None:
            effective_category = detected

    needs_approval = False
    reasons: list[str] = []

    if effective_category in RESTRICTED_OUTBOUND_CATEGORIES:
        needs_approval = True
        if effective_category != category:
            reasons.append(
                f"outbound text to {origin} matches restricted category {effective_category!r} "
                f"(declared as {category!r}), which always requires explicit owner approval"
            )
        else:
            reasons.append(
                f"outbound category {category!r} always requires explicit owner approval "
                f"at all trust levels (L1-L3)"
            )

    if level == 1:
        needs_approval = True
        reasons.append(
            f"peer {norm[:12]}… has trust level L1 (origin: {origin}, manual mode) — "
            "no autonomous reply or message may be sent without explicit owner approval"
        )
    elif level == 3:
        clean_topic = (topic or "").strip()
        if not remote_attested:
            needs_approval = True
            reasons.append(
                f"peer {norm[:12]}… has trust level L3, but bilateral L3 attestation "
                "(remote_trust_attested) is not confirmed; falling back to L1 manual mode"
            )
        elif not topics or not clean_topic or clean_topic not in topics:
            needs_approval = True
            reasons.append(
                f"peer {norm[:12]}… has trust level L3 (allowed topics: {topics}), "
                f"but outbound topic {clean_topic!r} is outside the agreed topic scope"
            )

    approved = bool(owner_approved)
    if not approved and (needs_approval or owner_approval_token is not None):
        approved = _consume_matching_permit(
            policy, norm, content_sha256, effective_category, owner_approval_token
        )

    if needs_approval and not approved:
        reason_str = "; ".join(reasons)
        raise InboxError(
            f"Outbound send blocked by A4A Trust Policy: {reason_str}. "
            "Show the letter/draft to the owner and ask the owner to approve sending "
            "(via 'python -m a4a_mcp approve-send --to <pubkey> --text-file ...' or '--owner-approved')."
        )

    return {
        "recipient": norm,
        "trust_level": level,
        "origin_label": origin,
        "category": effective_category,
        "topic": (topic or "").strip() or None,
        "content_sha256": content_sha256,
        "owner_approved": approved,
    }


#: A session command holds the identity lock for well under a second. The lock does not wait
#: (non-blocking), so a reader retries for this long before treating "busy" as a failure.
_IDENTITY_BUSY_WAIT_SECONDS = 3.0


def _existing_keys():
    path = identity.IDENTITY_FILE
    if not path.is_file() or path.is_symlink():
        raise InboxError("configured inbox identity is missing or linked; it must not be regenerated")
    if not keyfile.is_private(path)[0]:
        raise InboxError("inbox identity permissions are not private; access is closed")
    deadline = time.monotonic() + _IDENTITY_BUSY_WAIT_SECONDS
    while True:
        try:
            return identity.load_or_create_identity()
        except ValueError as exc:
            # 26.09.2026: a receiver refreshing its policy while the session ran inbox-next
            # read "busy" as "unreadable" and stopped for 15 minutes. Busy is transient.
            if not str(exc).startswith("identity is busy"):
                raise InboxError("configured inbox identity is unreadable or invalid") from exc
            if time.monotonic() >= deadline:
                raise InboxError("configured inbox identity stayed busy; retry later") from exc
            time.sleep(0.05)
        except (OSError, TypeError) as exc:
            raise InboxError("configured inbox identity is unreadable or invalid") from exc


def active_policy():
    policy = load_policy()
    if policy is None or not policy.enabled:
        raise InboxError("Private inbox is closed: it is not configured or is disabled by the owner.")
    from .server import _relay_url, _relay_urls
    current_relay = _relay_url()
    if policy.relay != current_relay:
        configured_urls = _relay_urls()
        same_official_network = (
            policy.relay in _OFFICIAL_A4A_RELAYS
            and current_relay in _OFFICIAL_A4A_RELAYS
        )
        if policy.relay not in configured_urls and not same_official_network:
            raise InboxError("Relay address differs from the owner-configured inbox policy.")
    if _existing_keys().pubkey_hex != policy.recipient:
        raise InboxError("inbox identity differs from the owner-configured recipient")
    return policy


def require_peer(pubkey):
    from a4a.keys import Keys
    pubkey = Keys.normalize_pubkey(pubkey)
    policy = active_policy()
    if pubkey not in policy.allowed_peers:
        raise InboxError(
            "Private contact with this address is not authorized by the owner; "
            "do not add the contact yourself. The allowed list is the owner's inbox "
            "policy for this mailbox: ask the owner to add the address."
        )
    return policy


DEFAULT_INBOX_MAX_MB = 64


def _inbox_max_bytes() -> int:
    """Return inbox storage capacity in bytes; default to 64 MiB.

    Processed messages are never deleted automatically because they are protocol
    evidence. History will eventually consume the capacity and stop intake with
    ``InboxFull`` and receiver health ``failed``. Production measurements on
    2026-09-08 were 275 and 496 KiB per day. Raising the cap buys time but does not
    solve retention; owner-approved export and pruning does.

    Do NOT increase the default: another installation must not silently retain half
    a gigabyte of private correspondence. Invalid configuration fails closed rather
    than falling back, so a typo cannot masquerade as an active setting.
    """
    raw = os.environ.get("A4A_INBOX_MAX_MB")
    if raw is None:
        return DEFAULT_INBOX_MAX_MB * 1024 * 1024
    raw = raw.strip()
    if not re.fullmatch(r"[0-9]{1,4}", raw) or not 1 <= int(raw) <= 1024:
        raise ValueError(
            "A4A_INBOX_MAX_MB must be an integer number of mebibytes from 1 to 1024, "
            f"got {raw!r}"
        )
    return int(raw) * 1024 * 1024


DEFAULT_INBOX_MAX_ITEMS = 10_000


def _inbox_max_items() -> int:
    """Return the inbox letter-count capacity; default 10 000 (the SDK allows up to 100 000).

    26.09.2026: the representative's pod took 1207 letters in one day, so 10 000 letters
    was a hard stop about a week away, and unlike bytes it could not be configured. Same
    rules as the byte ceiling: explicit opt-in, the default unchanged, a typo refused.
    """
    raw = os.environ.get("A4A_INBOX_MAX_ITEMS")
    if raw is None:
        return DEFAULT_INBOX_MAX_ITEMS
    raw = raw.strip()
    if not re.fullmatch(r"[0-9]{1,6}", raw) or not 1 <= int(raw) <= 100_000:
        raise ValueError(
            "A4A_INBOX_MAX_ITEMS must be an integer number of letters from 1 to 100000, "
            f"got {raw!r}"
        )
    return int(raw)


def _open_store(policy):
    """Open this profile's inbox with the effective storage capacity."""
    return InboxStore(identity.IDENTITY_DIR / "inbox", policy.recipient, policy.consumer,
                      max_items=_inbox_max_items(), max_bytes=_inbox_max_bytes())


def require_legacy_send(pubkey):
    policy = require_peer(pubkey)
    with _open_store(policy) as store:
        if store.dialogue_enabled():
            raise InboxError("dialogue mode is enabled; use a4a_dialogue_send with a current lease")
    return policy


def allowed_messages(messages):
    policy = active_policy()
    return [m for m in messages if m["from_pubkey"] in policy.allowed_peers]


async def allowed_messages_authorized(agent, messages):
    """Filter manual network reads by exact peer or a current allowed owner.

    The caller owns an already-connected agent. A relay query failure aborts the
    whole read instead of showing an incompletely authorized result.
    """
    if not messages:
        return []
    policy = active_policy()
    permitted = set(policy.allowed_peers)
    mandates = {}
    if policy.allowed_owners:
        mandates = await agent.active_owner_mandates(
            {m["from_pubkey"] for m in messages} - permitted,
            policy.allowed_owners)
        permitted.update(mandates)
    shown = [m for m in messages if m["from_pubkey"] in permitted]
    for message in shown:
        mandate = mandates.get(message["from_pubkey"])
        if mandate is not None:
            message["sender_identity"] = owner_agent_identity(
                message["from_pubkey"], mandate)
    latest = active_policy()
    if (latest.allowed_peers != policy.allowed_peers
            or latest.allowed_owners != policy.allowed_owners):
        raise InboxPolicyChanged("inbox authorization changed during owner lookup")
    return shown


def shown_delivery(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) else "-"


_FILE_REFERENCE_UNAVAILABLE = (
    "[A4A attachment hidden] Receiving files through MCP is not supported. "
    "The URL and metadata were not exposed to the model. a4a_open_file operates only "
    "on an existing local blob supplied outside MCP by the owner or a trusted host."
)
#: A reference that names one of THIS mailbox's own file gateways. The model gets an
#: opaque handle (the blob sha256), never an address, and saving it is an explicit call.
_GATEWAY_ATTACHMENT = (
    "[A4A attachment] A file from this sender is waiting on this mailbox's file gateway. "
    "To save it, call a4a_open_file(attachment={sha}, out_path=...). Saving writes the "
    "decrypted file only; nothing is opened or run."
)
_MAX_FILE_MARKER_TEXT = 32 * 1024
_MAX_FILE_MARKER_DEPTH = 16
_MAX_FILE_MARKER_NODES = 1024
_MAX_FILE_MARKER_DECODED_BYTES = 8 * _MAX_FILE_MARKER_TEXT
_JSON_STRING_BODY = r'(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*'
_JSON_STRING_RE = re.compile(rf'"{_JSON_STRING_BODY}"')
_JSON_TRAILING_STRING_RE = re.compile(rf'(?P<string>"{_JSON_STRING_BODY})\Z')
_JSON_KEY_RE = re.compile(
    rf'(?P<key>"{_JSON_STRING_BODY}")\s*:')


def _contains_encoded_file_marker(content):
    """Find a complete JSON key even when the surrounding document is truncated."""
    for match in _JSON_KEY_RE.finditer(content):
        try:
            key = json.loads(match.group("key"))
        except (TypeError, ValueError):
            continue
        if key == "a4a_file":
            return True
    return False


def _decoded_json_string_tokens(content):
    """Yield bounded complete or delimiter-damaged JSON string representations."""
    for match in _JSON_STRING_RE.finditer(content):
        try:
            value = json.loads(match.group(0))
        except json.JSONDecodeError:
            continue
        if isinstance(value, str):
            yield value
    trailing = _JSON_TRAILING_STRING_RE.search(content)
    if trailing is not None:
        try:
            value = json.loads(trailing.group("string") + '"')
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(value, str):
                yield value
    # A transport or attacker may strip either/both enclosing quotes while leaving a
    # complete JSON-escaped body. Try exactly the three delimiter repairs; the shared
    # worklist applies them repeatedly and enforces all depth/node/byte budgets.
    for candidate in (content + '"', '"' + content, '"' + content + '"'):
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, str):
            yield value


def _peel_json_escapes(content):
    """Decode one bounded JSON-escape layer without trusting surrounding syntax."""
    escapes = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f",
               "n": "\n", "r": "\r", "t": "\t"}
    output = []
    changed = False
    index = 0
    while index < len(content):
        if content[index] != "\\" or index + 1 >= len(content):
            output.append(content[index])
            index += 1
            continue
        escaped = content[index + 1]
        if escaped in escapes:
            output.append(escapes[escaped])
            index += 2
            changed = True
            continue
        if escaped == "u" and index + 6 <= len(content):
            digits = content[index + 2:index + 6]
            if re.fullmatch(r"[0-9a-fA-F]{4}", digits):
                codepoint = int(digits, 16)
                consumed = 6
                if (0xD800 <= codepoint <= 0xDBFF and index + 12 <= len(content)
                        and content[index + 6:index + 8] == "\\u"):
                    low_digits = content[index + 8:index + 12]
                    if re.fullmatch(r"[0-9a-fA-F]{4}", low_digits):
                        low = int(low_digits, 16)
                        if 0xDC00 <= low <= 0xDFFF:
                            codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00)
                            consumed = 12
                output.append(chr(codepoint))
                index += consumed
                changed = True
                continue
        output.append("\\")
        index += 1
    if not changed:
        return None
    return "".join(output)


def _is_file_reference_attempt(content):
    """Recognise nested or malformed file references before fields reach the model.

    JSON strings may themselves contain JSON, so a successful outer decode is not a
    stopping point. The worklist is deliberately bounded; exhausting any budget is a
    fail-closed file attempt, never permission to return the original text.
    """
    if not isinstance(content, str):
        return True
    # All model-facing message stores cap content at 32 KiB. Keep this helper safe
    # when called directly too: unexpected oversized text is hidden, never scanned
    # without a bound or passed through as a possible file reference.
    if len(content) > _MAX_FILE_MARKER_TEXT:
        return True
    try:
        content_bytes = len(content.encode("utf-8"))
    except UnicodeEncodeError:
        return True
    if content_bytes > _MAX_FILE_MARKER_TEXT:
        return True

    pending = []
    seen_strings = set()
    scheduled = 0
    decoded_bytes = 0

    def enqueue(value, depth):
        nonlocal scheduled, decoded_bytes
        if depth > _MAX_FILE_MARKER_DEPTH or scheduled >= _MAX_FILE_MARKER_NODES:
            return False
        scheduled += 1
        if not isinstance(value, (dict, list, str)):
            return True
        if isinstance(value, str):
            if value in seen_strings:
                return True
            seen_strings.add(value)
            try:
                decoded_bytes += len(value.encode("utf-8"))
            except UnicodeEncodeError:
                return False
            if decoded_bytes > _MAX_FILE_MARKER_DECODED_BYTES:
                return False
        pending.append((value, depth))
        return True

    if not enqueue(content, 0):
        return True
    while pending:
        current, depth = pending.pop()
        if isinstance(current, dict):
            if "a4a_file" in current:
                return True
            child_groups = (current.keys(), current.values())
        elif isinstance(current, list):
            child_groups = (current,)
        else:
            if _contains_encoded_file_marker(current):
                return True
            peeled = _peel_json_escapes(current)
            if peeled is not None and not enqueue(peeled, depth + 1):
                return True
            try:
                decoded_tokens = _decoded_json_string_tokens(current)
                for token in decoded_tokens:
                    if not enqueue(token, depth + 1):
                        return True
            except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
                return True
            try:
                decoded = json.loads(current)
            except json.JSONDecodeError:
                continue
            except (MemoryError, OverflowError, RecursionError, TypeError, ValueError):
                # Syntax errors can safely fall back to the key scanner above. Parser
                # recursion, integer limits and other resource refusals cannot: an
                # encoded reference may be hidden beyond the parser's stopping point.
                return True
            child_groups = ((decoded,),)
        for children in child_groups:
            for child in children:
                if not enqueue(child, depth + 1):
                    return True
    return False


def configured_file_gateways() -> list[str]:
    return [item.strip() for item in os.environ.get("A4A_FILE_GATEWAY", "").split(",")
            if item.strip()]


def gateway_attachment(content) -> str | None:
    """Return the blob sha256 when `content` is exactly a reference to one of OUR gateways."""
    if not isinstance(content, str) or len(content) > _MAX_FILE_MARKER_TEXT:
        return None
    try:
        ref = files.parse_file_reference(content)
    except RecursionError:
        # Hostile nesting deeper than the JSON parser allows is not a reference to our
        # gateway; the caller already shows the fail-closed placeholder for it.
        return None
    return None if ref is None else file_gateway.gateway_blob(ref, configured_file_gateways())


def _measured(message):
    """Length and digest of the letter's own text (before the untrusted frame is added).

    26.09.2026: a reader printed content[:3500] and closed four letters; the tails looked
    lost. With the length and digest beside the text, a cut is visible to the reader at once."""
    import hashlib
    text = message["content"]
    message["content_chars"] = len(text)
    message["content_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    # A letter that states its own length in the first-line declaration is compared on
    # receipt (representative, 27.09, letter 290): N counts Unicode characters after that line,
    # as sent - no normalisation, the final newline included.
    declared = re.match('\\[\u043d\u0438\u0436\u0435 (\\d+) \u0437\u043d\u0430\u043a\u043e\u0432\\]\\n', text)
    if declared:
        message["declared_chars"] = int(declared.group(1))
        message["declared_chars_match"] = len(text) - declared.end() == int(declared.group(1))
    return message


def reread(seq, out_path):
    """Write a letter already handed out (not pending) to a file again, in full.

    The stored envelope stays after processing, so a text cut by a careless print is not
    lost. A pending letter is refused: reading it here would go around the lease."""
    with open_runtime() as (policy, agent, store):
        row = store.db.execute("SELECT state,sender,inner_id,envelope,received FROM messages WHERE seq=?",
                               (seq,)).fetchone()
        if row is None:
            raise InboxError(f"no letter with number {seq} exists in this mailbox; check A4A_HOME")
        if row["state"] == "pending":
            raise InboxError(f"letter {seq} has not been read yet: take it with inbox-next")
        if not row["envelope"]:
            raise InboxError(f"letter {seq} no longer has its stored envelope (pruned)")
        message = agent._decode_incoming(Event.model_validate_json(row["envelope"]))
        if message is None or message["inner_id"] != row["inner_id"]:
            raise InboxError(f"stored letter {seq} failed verification")
        peer_info = policy.peer_policy(row["sender"])
    _measured(message)
    text = shown_content(
        message,
        origin_label=peer_info["origin"],
        trust_level=peer_info["level"],
    )
    out = Path(out_path)
    out.write_text(text, encoding="utf-8", newline="\n")
    return {"seq": seq, "state": row["state"], "from_pubkey": row["sender"],
            "origin_label": peer_info["origin"], "trust_level": peer_info["level"],
            "trust_policy": peer_info,
            "bridge_preamble": MANDATORY_BRIDGE_PREAMBLE_RU,
            "delivery_id": message["delivery_id"], "content_file": str(out),
            "content_chars": message["content_chars"], "content_sha256": message["content_sha256"],
            # Times too (27.09, letter 278): stamps are checked against the signature afterwards.
            "signed_at": message["signed_at"], "received_at": row["received"],
            **{k: message[k] for k in ("declared_chars", "declared_chars_match") if k in message}}


def shown_content(message, *, origin_label: str | None = None, trust_level: int | None = None):
    content = message["content"]
    if _is_file_reference_attempt(content):
        handle = gateway_attachment(content)
        text = (_GATEWAY_ATTACHMENT.format(sha=handle) if handle
                else _FILE_REFERENCE_UNAVAILABLE)
    else:
        text = content
    return wrap_untrusted(
        text,
        source=message["from_pubkey"][:12],
        origin_label=origin_label,
        trust_level=trust_level,
    )


def _owner_contact_onboarding_prompt(peer_apub: str, peer_label: str = "") -> str:
    label_hint = f" (current label: {peer_label!r})" if peer_label else " (currently unlabeled)"
    return (
        f"NEW EXTERNAL CONTACT ({peer_apub}{label_hint}, Trust Level L1): "
        "Immediately notify your human owner in your primary chat/DM that this contact connected "
        "and show their introduction/message. Ask your owner: "
        f"(1) how to sign/label this contact (save via: python -I -m a4a_mcp set-trust --peer {peer_apub} --label \"Name / Role\"), "
        f"(2) whether to keep Trust Level L1 (manual approval for every reply) or set L2 (--trust-level 2, autonomous routine work replies while blocking money/promises/client data), and "
        "(3) whether to send a reply."
    )


def _attach_trust_metadata(message: dict, policy: InboxPolicy, *, is_owner_agent: bool = False) -> None:
    from a4a.keys import Keys
    raw_content = message.get("content", "")
    peer_info = policy.peer_policy(message["from_pubkey"], is_owner_agent=is_owner_agent)
    message["origin_label"] = peer_info["origin"]
    message["trust_level"] = peer_info["level"]
    if peer_info.get("label"):
        message["peer_label"] = peer_info["label"]
    message["trust_policy"] = peer_info
    message["bridge_preamble"] = MANDATORY_BRIDGE_PREAMBLE_RU
    if (
        "[A4A_INVITE_ACCEPTANCE_V1]" in raw_content
        or (peer_info["level"] == 1 and peer_info["origin"] == "external_contact" and not peer_info.get("label"))
    ):
        sender_apub = Keys.encode_apub(message["from_pubkey"])
        message["owner_onboarding_prompt"] = _owner_contact_onboarding_prompt(
            sender_apub,
            peer_info.get("label", ""),
        )
    message["content"] = shown_content(
        message,
        origin_label=peer_info["origin"],
        trust_level=peer_info["level"],
    )


@contextlib.contextmanager
def open_runtime():
    policy = active_policy()
    keys = _existing_keys()
    if keys.pubkey_hex != policy.recipient:
        raise InboxError("inbox identity differs from the owner-configured recipient")
    # Read from ALL configured relays rather than only the policy relay. Include
    # ``policy.relay`` first when switching between official regional relays (e.g.
    # eu1 and ru1) so neither relay loses unread messages or fails policy validation.
    from .server import _relay_urls
    relays = list(_relay_urls())
    if policy.relay not in relays:
        relays.insert(0, policy.relay)
    agent = Agent(relays, keys=keys)
    agent.public_journal_dir = identity.IDENTITY_DIR / "publications" / keys.pubkey_hex
    with _open_store(policy) as store:
        if policy.allowed_owners and store.dialogue_enabled():
            raise InboxError(
                "allowed_owners is not yet supported by dialogue mode; owner routing is deferred")
        yield policy, agent, store


def prune(days, archive, compact=False):
    """Export and remove completed messages older than ``days``.

    This is a manual OWNER action with no automatic retention period. Signed
    correspondence may be evidence in a dispute. Calculate the cutoff from the
    current time; accepting an absolute timestamp could let one typo erase all data.

    Always create an export, even when empty. The file records that pruning ran and
    exactly what it removed; an absent file proves nothing.
    """
    if type(days) is not int or days < 1:
        raise InboxError("inbox prune needs a positive age in days")
    policy = active_policy()
    before = int(time.time()) - days * 86400
    with _open_store(policy) as store:
        return store.prune(before=before, archive=archive, compact=compact)


def status():
    from . import channel
    from .onboarding import readiness
    from .wake_journal import journal_status
    notifications = channel.status()
    if load_policy() is None:
        result = {"state": "unconfigured", "receiver": {"state": "not_started", "stale": True},
                "notifications": notifications,
                "host_signal": {"state": "unconfigured", "host_wake": "unverified"}}
        result["readiness"] = readiness(result, allowed_peer_count=0)
        return result
    with open_runtime() as (policy, agent, store):
        health = shown_health(store.health())
        counts = dict(store.status())
        counts["as_of"] = time.time()  # network rule 1: a count carries its moment
        # THREE OUTCOMES, NOT TWO. ``pending: 0`` with a stopped receiver means not
        # "no mail" but "could not check": the receiver fills the queue, and when it
        # is dead, zero describes the receiver rather than the mailbox. On 2026-09-15
        # two agents lost five hours after reading this failure as silence.
        #
        # Keep the numeric field for compatibility, but place an unambiguous warning
        # beside it so the value cannot be mistaken for good news.
        if health.get("stale") or health.get("state") != "ready":
            counts = dict(counts)
            counts["reliable"] = False
            counts["warning"] = (
                "receiver is not running: the queue is not being populated, and "
                "pending describes the RECEIVER, not the mailbox"
            )
        else:
            counts["reliable"] = True
        result = {"state": "configured", "counts": counts, "receiver": health,
                "notifications": notifications, "host_signal": journal_status(store),
                "untimed_numbers": untimed_counts(store, agent)}
        q_counts = store.quarantine_counts()
        if policy.intake_mode != "closed" or q_counts.get("total", 0) > 0:
            result["intake_mode"] = policy.intake_mode
            result["quarantine"] = q_counts
        result["readiness"] = readiness(
            result, allowed_peer_count=len(policy.allowed_peers) + len(policy.allowed_owners))
        return result


#: Window of the free-text count; the representative's bridge uses the same week.
_UNTIMED_WINDOW_DAYS = 7


def untimed_counts(store, agent, now=None):
    """Letters of the last week in THIS mailbox that carry numbers without a taken-at mark.

    Network rule 1 (26.09.2026): tools enforce "a count names its moment" by tests; free
    text cannot be checked without reading others' mail, so each recipient counts its own.
    A heuristic signal for the agent, never a refusal (a4a_mcp.untimed).
    ``of`` counts readable letters; malformed or undecodable envelopes are reported
    separately as ``unreadable``. Unexpected decoder failures abort the diagnostic.
    """
    from . import untimed
    moment = time.time() if now is None else now
    rows = store.db.execute(
        "SELECT envelope FROM messages WHERE received > ? AND state != 'blocked' "
        "AND envelope != ''", (moment - _UNTIMED_WINDOW_DAYS * 86400,)).fetchall()
    flagged = total = unreadable = 0
    deltas = []
    for (envelope,) in rows:
        try:
            event = Event.model_validate_json(envelope)
        except ValidationError:
            unreadable += 1
            continue
        message = agent._decode_incoming(event)
        if message is None:
            unreadable += 1
            continue
        total += 1
        flagged += untimed.numbers_without_time(message["content"])
        # The stated time against the envelope's signed send time (representative, 26.09).
        delta = untimed.stated_minus_sent(message["content"], message["signed_at"])
        if delta is not None:
            deltas.append(delta)
    return {"count": flagged, "of": total, "unreadable": unreadable,
            "window_days": _UNTIMED_WINDOW_DAYS, "as_of": moment,
            "stamps": {"with_mark": len(deltas),
                       "later_than_sent": sum(d > 0 for d in deltas),
                       "over_60_min": sum(abs(d) > 60 for d in deltas),
                       "max_abs_minutes": max((abs(d) for d in deltas), default=0)}}


def shown_health(health):
    """What callers see of the receiver's health: a stale value is ``unknown``.

    26.09.2026: a project agent read a two-minute-old "failed" while its receiver was storing letters;
    a plausible stale word invites a restart that can cause a real outage (owner's
    representative). The receiver's own bookkeeping keeps reading the store directly.
    """
    if not health.get("stale") or health.get("state") == "not_started":
        return health
    return {**health, "state": "unknown", "last_reported": health.get("state")}


_POLICY_REFRESH_FAILURES = {
    "Private inbox is closed: it is not configured or is disabled by the owner.": "closed_or_missing",
    "inbox policy must not be a symlink": "policy_invalid",
    "invalid inbox policy file": "policy_invalid",
    "inbox policy permissions are not private; access is closed": "policy_permissions",
    "inbox policy is unreadable; private access is closed": "policy_unreadable",
    "Relay address differs from the owner-configured inbox policy.": "relay_mismatch",
    "configured inbox identity is missing or linked; it must not be regenerated": "identity_missing_or_linked",
    "inbox identity permissions are not private; access is closed": "identity_permissions",
    "configured inbox identity is unreadable or invalid": "identity_unreadable",
    "configured inbox identity stayed busy; retry later": "identity_busy",
    "inbox identity differs from the owner-configured recipient": "identity_mismatch",
}


def refresh_policy(previous):
    try:
        current = active_policy()
    except InboxError as exc:
        # The public refusal stays generic. Log only a fixed classification, not
        # exception text or its nested cause: either may contain local path or
        # identity details. This distinguishes transient read/permission faults
        # from a deliberate policy closure when a long-lived bridge retries.
        reason = _POLICY_REFRESH_FAILURES.get(str(exc), "unclassified")
        log.warning("inbox policy refresh failed: reason=%s", reason)
        raise InboxPolicyChanged("inbox access policy is no longer valid; receiver stopped") from exc
    if (current.recipient, current.consumer, current.relay,
        current.notify_interval, current.notify_per_hour, current.ack_on_receipt) != (
        previous.recipient, previous.consumer, previous.relay,
        previous.notify_interval, previous.notify_per_hour, previous.ack_on_receipt):
        raise InboxPolicyChanged("inbox binding or notification budget changed; restart explicitly")
    return current


def _with_unknown_notice(result, store):
    """Tell the caller about letters stranded in `unknown` by an expired lease.

    26.09.2026: a project mailbox's lease expired; the letter went to unknown and inbox-next never
    mentioned it again, so it looked lost although reconciliation returns it whole.
    """
    waiting = int(store.status().get("unknown", 0))
    if waiting:
        result["unknown_waiting"] = waiting
        result["hint"] = (f"{waiting} letter(s) wait in unknown after an expired lease: list them "
                          "with inbox-unknown, return one with inbox-reconcile --resolution retry, "
                          "or close it with --resolution processed if it was already handled.")
    return result


def claim():
    with open_runtime() as (policy, agent, store):
        if policy.allowed_owners:
            raise InboxError("owner-trusting inbox requires the asynchronous claim path")
        current = refresh_policy(policy)
        message = store.claim(agent, policy.consumer, current.allowed_peers)
        health = shown_health(store.health())
        if message:
            _measured(message)
            _attach_trust_metadata(message, current, is_owner_agent=False)
        state = "processing" if message else ("idle" if health.get("state") == "ready" and not health.get("stale") else "receiver_unavailable")
        return _with_unknown_notice({"state": state, "message": message, "receiver": health}, store)


async def claim_authorized():
    """Recheck current owner mandates before leasing a stored private letter."""
    with open_runtime() as (policy, agent, store):
        current = refresh_policy(policy)
        mandates = await owner_mandates_for_senders(
            agent, current.allowed_owners,
            store.pending_sender_keys() - current.allowed_peers)
        latest = refresh_policy(policy)
        if (latest.allowed_peers != current.allowed_peers
                or latest.allowed_owners != current.allowed_owners):
            raise InboxPolicyChanged("inbox authorization changed during owner lookup")
        permitted = current.allowed_peers | mandates.keys()
        message = store.claim(agent, policy.consumer, permitted)
        health = shown_health(store.health())
        if message:
            _measured(message)
            mandate = mandates.get(message["from_pubkey"])
            _attach_trust_metadata(message, current, is_owner_agent=(mandate is not None))
            if mandate is not None:
                message["sender_identity"] = owner_agent_identity(
                    message["from_pubkey"], mandate)
        state = "processing" if message else ("idle" if health.get("state") == "ready" and not health.get("stale") else "receiver_unavailable")
        return _with_unknown_notice({"state": state, "message": message, "receiver": health}, store)


_WRAP_START = "[UNTRUSTED DATA FROM THE A4A NETWORK"
_WRAP_END = "[END OF UNTRUSTED DATA]"
#: First line written by ops/forward-partner-mail.py; its parse_forward is mirrored here.
FORWARD_TAG = "A4A-FORWARD v1"
_FORWARD_FIELDS = ("original-id", "delivery-id", "from", "mailbox", "received", "hops")


def _forward_origin(content):
    """Return (sender, delivery_id, inner_id) of a forwarded copy's original, or None.

    A forward's original is not in this mailbox, but the copy's first line already names
    it (design 2026-09-26, condition (b)). A line that claims to be a forward yet does
    not parse is refused rather than read as an ordinary letter: answering the copy
    would silently send the answer to the forwarder instead of the author.
    """
    body = "\n".join(line for line in content.splitlines()
                     if not line.startswith(_WRAP_START) and line != _WRAP_END).strip()
    first = body.split("\n", 1)[0]
    if not first.startswith(FORWARD_TAG):
        return None
    parts = [part.split("=", 1) for part in first[len(FORWARD_TAG):].split()]
    fields = dict(part for part in parts if len(part) == 2)
    problem = None
    if (not first.startswith(FORWARD_TAG + " ") or len(fields) != len(parts)
            or not set(_FORWARD_FIELDS) <= fields.keys()):
        problem = "the fields are incomplete"
    elif not re.fullmatch(r"[0-9a-f]{64}", fields["original-id"]):
        problem = "original-id is not 64 lowercase hex characters"
    elif not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", fields["delivery-id"]):
        problem = "delivery-id is malformed"
    elif not is_canonical_pubkey(fields["from"]):
        problem = "from is not a 64-hex public key"
    elif not re.fullmatch(r"[0-9]{1,6}", fields["hops"]):
        problem = "hops is not a number"
    if problem:
        # The line is written by the forwarding tool (ops/forward-partner-mail.py), whose
        # header is covered by tests: a damaged one means a tool defect or a hand-made or
        # edited line, not a correspondent's mistake - so it is logged and named as such.
        log.warning("damaged forward header refused: %s", problem)
        raise InboxError(
            f"this letter's first line starts with {FORWARD_TAG} but does not parse "
            f"({problem}), so its original sender is unknown and nothing was sent. The line "
            "is written by the forwarding tool: a damaged one means a tool defect or a "
            "hand-edited line, not the correspondent's mistake - report it to the A4A agent "
            "(mailbox a4a-claude) with the seq. To answer the copy itself, write to the "
            "forwarding mailbox with a4a_deliver and new_letter=true, quoting the seq and "
            "delivery_id of this copy.")
    return fields["from"], fields["delivery-id"], fields["original-id"]


def reply_target(seq):
    """Resolve whom an answer to letter `seq` goes to and which letter it names.

    The ids come from the mailbox row, never from the agent, so an answer cannot name
    a letter it did not receive. A lease is not required (design 2026-09-26, conditions
    (a) and (d)): only a letter never handed out (`pending`) is refused.
    """
    with open_runtime() as (_, agent, store):
        row = store.db.execute(
            "SELECT state,sender,inner_id,delivery_id,envelope FROM messages WHERE seq=?",
            (seq,)).fetchone()
        if row is None:
            raise InboxError(
                f"no letter with number {seq} exists in this mailbox ({identity.IDENTITY_DIR}); "
                "nothing was sent. The number may come from another mailbox: check A4A_HOME.")
        if row["state"] == "pending":
            raise InboxError(
                f"letter {seq} has not been read yet; nothing was sent. First read it: inbox-next "
                "(a4a_inbox_next).")
        if not row["envelope"]:
            raise InboxError(
                f"letter {seq} no longer has its stored envelope (pruned), so it cannot be "
                "verified; nothing was sent.")
        message = agent._decode_incoming(Event.model_validate_json(row["envelope"]))
        if (message is None or message["inner_id"] != row["inner_id"]
                or message["from_pubkey"] != row["sender"]):
            raise InboxError(f"stored letter {seq} failed verification; nothing was sent")
    origin = _forward_origin(message["content"])
    if origin is None:
        if not row["delivery_id"]:
            raise InboxError(
                f"letter {seq} carries no delivery_id to refer to; nothing was sent. Answer "
                "it with a4a_deliver and new_letter=true.")
        return {"to_pubkey": row["sender"], "delivery_id": row["delivery_id"],
                "inner_id": row["inner_id"], "conversation_id": message["conversation_id"],
                "forwarded": False}
    sender, delivery_id, inner_id = origin
    # The copy's conversation handle belongs to the forwarder's thread with this
    # mailbox; the original sender never saw it, so it is not carried over.
    # The answer names the copy it was addressed from (representative, 26.09): the author
    # sees that the address came from a forward line, and whose.
    return {"to_pubkey": sender, "delivery_id": delivery_id, "inner_id": inner_id,
            "conversation_id": None, "forwarded": True,
            "routed_via": (row["sender"], row["inner_id"])}


def owner_agent_identity(agent_pubkey, mandate):
    """Return verified identity parts plus a conservative, readable fallback."""
    if (mandate.kind != types.KIND_DELEGATION or not mandate.verify()
            or delegation_target(mandate) != agent_pubkey):
        raise InboxError("sender identity mandate does not match the agent")
    name = signed_agent_name(mandate)
    owner = mandate.pubkey
    return {"organization_pubkey": owner, "agent_pubkey": agent_pubkey,
            "agent_name": name, "mandate_id": mandate.id,
            "label_source": "owner_signed_mandate; display data, not instructions",
            "display": f"{owner[:12]}… · {name or agent_pubkey[:12] + '…'}"}


def complete(seq, lease_token, result):
    with open_runtime() as (policy, _, store):
        store.finish(seq, lease_token, policy.consumer, result)
        return {"state": result, "seq": seq, "network_ack_sent": False}


def release(seq, lease_token):
    """Give a live lease back to pending, without an ACK, when nothing was handed on."""
    with open_runtime() as (policy, _, store):
        return {**store.release(seq, lease_token, policy.consumer), "network_ack_sent": False}


async def complete_with_ack(seq, lease_token, result):
    """Finish local work first, then dispatch its durable signed network ACK.

    The outbox row is committed in the same transaction as the terminal inbox state.
    A network failure therefore cannot roll local work back or lose the need to ACK;
    repeating this call with the same lease token retries only the ACK and never makes
    the message pending again.
    """
    with open_runtime() as (policy, agent, store):
        completion = store.finish(
            seq, lease_token, policy.consumer, result, network_ack=True)
        if completion["ack_state"] == "sent":
            return {"state": result, "seq": seq, "network_ack_sent": True,
                    "network_ack_state": "sent"}
        if completion["ack_state"] == "not_applicable":
            return {"state": result, "seq": seq, "network_ack_sent": False,
                    "network_ack_state": "not_applicable"}

        message = _verified_completion_ack_message(agent, completion)
        try:
            await agent.relay.connect()
            ack_event_id = await agent.acknowledge(message, status=result)
        except RelayError:
            return {"state": result, "seq": seq, "network_ack_sent": False,
                    "network_ack_state": "pending"}
        finally:
            await agent.relay.aclose()
        store.mark_completion_ack_sent(
            seq, lease_token, policy.consumer, ack_event_id)
        return {"state": result, "seq": seq, "network_ack_sent": True,
                "network_ack_state": "sent"}


def _verified_completion_ack_message(agent, completion):
    outer = Event.model_validate_json(completion["envelope"])
    message = agent._decode_incoming(outer)
    if (message is None or message["inner_id"] != completion["inner_id"]
            or message["delivery_id"] != completion["delivery_id"]):
        raise InboxError("stored completion ACK message verification failed")
    return message


async def _flush_completion_acks(policy, agent, store, *, limit=100):
    """Replay terminal-state ACKs after a process crash; never replay the work."""
    pending = store.pending_completion_acks(policy.consumer, limit=limit)
    if not pending:
        return {"state": "idle", "sent": 0, "remaining": 0}
    sent = 0
    try:
        await agent.relay.connect()
        for completion in pending:
            message = _verified_completion_ack_message(agent, completion)
            ack_event_id = await agent.acknowledge(
                message, status=completion["status"])
            store.mark_completion_ack_sent_by_seq(
                completion["seq"], policy.consumer, ack_event_id)
            sent += 1
    except RelayError:
        remaining = store.status()["ack_pending"]
        return {"state": "pending", "sent": sent,
                "remaining": remaining}
    finally:
        await agent.relay.aclose()
    remaining = store.status()["ack_pending"]
    return {"state": "pending" if remaining else "sent", "sent": sent,
            "remaining": remaining}


_last_outbox_recheck = 0.0


async def _recheck_sent_deliveries(agent, *, every: float = 60.0):
    """Let the always-on receiver heal this identity's undelivered sends.

    At most once a minute per process: the journal schedule itself spaces rechecks from
    one minute to six hours. A failure here must never stop receiving mail.
    """
    global _last_outbox_recheck
    now = time.time()
    if now - _last_outbox_recheck < every:
        return
    _last_outbox_recheck = now
    try:
        result = await agent.repair_publications(now=now)
        if result.get("restored") or result.get("held"):
            log.info("public announcement repair: %s", result)
    except Exception:
        log.exception("public announcement repair failed; receiving continues")
    from . import outbox_runtime
    try:
        result = await outbox_runtime.recheck_due_on(agent, now=now)
    except Exception:
        log.exception("automatic delivery recheck failed; receiving continues")
        return
    if result.get("acknowledged"):
        log.info("automatic recheck found %d late acknowledgement(s)", result["acknowledged"])


async def flush_completion_acks(limit=100):
    """Recover durable ACKs without retaining or recovering expired lease tokens."""
    with open_runtime() as (policy, agent, store):
        return await _flush_completion_acks(
            policy, agent, store, limit=limit)


def reconcile(seq, inner_id, resolution):
    """Explicitly resolve a lost legacy lease; never infer or repeat its outcome."""
    with open_runtime() as (policy, _, store):
        if policy.allowed_owners and resolution == "retry":
            raise InboxError("owner-trusting inbox requires the asynchronous retry path")
        allowed = refresh_policy(policy).allowed_peers
        return store.reconcile_unknown(
            seq, inner_id, policy.consumer, resolution, allowed_senders=allowed)


async def reconcile_authorized(seq, inner_id, resolution):
    """Revalidate owner authority before returning uncertain work to the queue."""
    with open_runtime() as (policy, agent, store):
        current = refresh_policy(policy)
        sender = store.sender_for_seq(seq)
        permitted = await authorized_sender_keys(
            agent, current.allowed_peers, current.allowed_owners,
            [sender] if sender else []) if resolution == "retry" else current.allowed_peers
        latest = refresh_policy(policy)
        if (latest.allowed_peers != current.allowed_peers
                or latest.allowed_owners != current.allowed_owners):
            raise InboxPolicyChanged("inbox authorization changed during owner lookup")
        return store.reconcile_unknown(
            seq, inner_id, policy.consumer, resolution, allowed_senders=permitted)


async def send_reconciled_ack(seq):
    """Tell the sender that a reconciled letter WAS processed (or failed).

    26.09.2026: a letter was processed, its lease expired, and inbox-reconcile closed it as
    processed without any network ACK, so the sender kept it "unconfirmed". Reconcile stays
    silent by default - an expired lease alone proves nothing - and the agent that knows the
    outcome sends it explicitly (CLI: inbox-reconcile ... --send-ack)."""
    with open_runtime() as (_, agent, store):
        row = store.db.execute("SELECT state, envelope FROM messages WHERE seq=?", (seq,)).fetchone()
        if row is None or row["state"] not in ("processed", "failed"):
            raise InboxError(f"letter {seq} is not closed as processed or failed; no ACK is sent")
        if not row["envelope"]:
            raise InboxError(f"letter {seq} no longer has its stored envelope; no ACK is sent")
        message = agent._decode_incoming(Event.model_validate_json(row["envelope"]))
        if message is None:
            raise InboxError(f"stored letter {seq} failed verification; no ACK is sent")
        await agent.relay.connect()
        try:
            event_id = await agent.acknowledge(message, status=row["state"])
        finally:
            await agent.relay.aclose()
    return {"seq": seq, "status": row["state"], "network_ack_sent": True, "ack_event_id": event_id}


def unknown_bindings(limit=100):
    """Return bounded metadata for owner-side legacy reconciliation."""
    with open_runtime() as (policy, _, store):
        return store.unknown_bindings(policy.consumer, limit=limit)


async def notices():
    with open_runtime() as (policy, agent, store):
        def current_peers():
            return refresh_policy(policy).allowed_peers
        async def flush_acks():
            await _flush_completion_acks(policy, agent, store)
            await _recheck_sent_deliveries(agent)
        receiver = InboxReceiver(
            agent, store, current_peers, start_after=policy.start_after,
            ack_on_receipt=policy.ack_on_receipt,
            allowed_owners=lambda: refresh_policy(policy).allowed_owners,
            intake_mode=lambda: refresh_policy(policy).intake_mode,
            blocked_senders=lambda: refresh_policy(policy).blocked_senders,
            inband_authorizer=try_redeem_inband_invitation,
        )
        async with contextlib.aclosing(receiver.notices(
                interval=policy.notify_interval, per_hour=policy.notify_per_hour,
                on_tick=flush_acks)) as source:
            async for notice in source:
                yield notice


# --- Stage 2: One-Time Expiring Invitations (One-Way Human Relay) -----------


def _effective_invite_status(rec: dict, now: int) -> str:
    st = rec.get("status", "open")
    if st == "open" and int(rec.get("expires_at", 0)) <= now:
        return "expired"
    return st


def _public_invite_view(rec: dict, now: int | None = None, *, include_url: bool = False) -> dict:
    from a4a.keys import Keys
    ts = int(time.time()) if now is None else int(now)
    st = _effective_invite_status(rec, ts)
    accepted_by = rec.get("accepted_by")
    out = {
        "invite_id": rec["invite_id"],
        "status": st,
        "label": rec.get("label", ""),
        "created_at": rec["created_at"],
        "expires_at": rec["expires_at"],
        "accepted_by": accepted_by,
        "accepted_by_apub": Keys.encode_apub(accepted_by) if accepted_by else None,
        "accepted_at": rec.get("accepted_at"),
    }
    if include_url:
        out["url"] = rec.get("url", "")
    return out


async def _broadcast_extra_relays(events: list, extra_relays: list[str]) -> None:
    """Best-effort broadcast of rendezvous/handshake events to additional relays."""
    from a4a.relay import RelayClient
    for r_url in extra_relays:
        client = RelayClient(r_url)
        try:
            await client.connect()
            for ev in events:
                with contextlib.suppress(Exception):
                    await client.publish(ev)
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                await client.aclose()


async def _query_extra_relays(filter_spec: dict, extra_relays: list[str]) -> list:
    """Best-effort query across additional official relays when primary relay has no match."""
    from a4a.relay import RelayClient
    found = []
    seen_ids = set()
    for r_url in extra_relays:
        client = RelayClient(r_url)
        try:
            await client.connect()
            evs = await client.query(filter_spec)
            for ev in evs:
                if ev.id not in seen_ids:
                    seen_ids.add(ev.id)
                    found.append(ev)
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                await client.aclose()
    return found


async def create_invitation(
    *,
    ttl_seconds: int = 24 * 3600,
    label: str = "",
    base_url: str = "https://a4a.network/i",
) -> dict:
    """Create a one-time expiring invitation link and publish its blind card to relays."""
    from a4a.invitations import (
        InvitationCard,
        InvitationError,
        build_invitation_url,
        build_rendezvous_card_event,
        build_rendezvous_delegation_event,
        generate_invite_secret,
    )
    with open_runtime() as (policy, agent, _):
        now = int(time.time())
        own_relays = list(agent._own_relays)
        extra_public = (
            [r for r in _CORE_PUBLIC_RELAYS if r not in own_relays]
            if policy.relay in _OFFICIAL_A4A_RELAYS
            else []
        )
        advertised_relays = own_relays + [r for r in extra_public if len(own_relays) + 1 <= 8][:max(0, 8 - len(own_relays))]
        try:
            secret = generate_invite_secret()
            card, eph_keys = InvitationCard.create(
                agent.keys,
                advertised_relays,
                ttl_seconds=ttl_seconds,
                label=label,
                now=now,
            )
            url = build_invitation_url(card.invite_id, secret, base_url=base_url)
            deleg_event = build_rendezvous_delegation_event(
                card.invite_id,
                secret,
                created_at=card.created_at,
                expires_at=card.expires_at,
            )
            card_event, _ = build_rendezvous_card_event(card, secret)
        except InvitationError as exc:
            raise InboxError(str(exc)) from exc

        await agent.relay.connect()
        try:
            await agent._broadcast(deleg_event)
            await agent._broadcast(card_event)
        finally:
            await agent.relay.aclose()
        if extra_public:
            await _broadcast_extra_relays([deleg_event, card_event], extra_public)

        # Prune old expired/revoked invitations if near the 100-item bound.
        inv_map = dict(policy.invitations or {})
        if len(inv_map) >= 80:
            removable = [
                k for k, v in sorted(inv_map.items(), key=lambda kv: kv[1].get("created_at", 0))
                if _effective_invite_status(v, now) in ("expired", "revoked")
            ]
            for k in removable[:40]:
                inv_map.pop(k, None)

        rec = {
            "invite_id": card.invite_id,
            "secret": secret,
            "ephemeral_privkey": eph_keys.privkey_hex,
            "ephemeral_pubkey": eph_keys.pubkey_hex,
            "challenge": card.challenge,
            "created_at": card.created_at,
            "expires_at": card.expires_at,
            "label": card.label,
            "url": url,
            "status": "open",
            "accepted_by": None,
            "accepted_at": None,
        }
        inv_map[card.invite_id] = rec
        data = _policy_to_json_data(policy, invitations=inv_map)
        _write_policy_data(data, replace=True)
        return _public_invite_view(rec, now, include_url=True)


async def revoke_invitation(invite_id: str) -> dict:
    """Revoke an open one-time invitation locally and overwrite its card on relays."""
    from a4a.invitations import (
        build_rendezvous_delegation_event,
        build_rendezvous_revoke_event,
        is_valid_invite_token,
    )
    if not is_valid_invite_token(invite_id):
        raise InboxError("invalid invite_id")
    with open_runtime() as (policy, agent, _):
        inv_map = dict(policy.invitations or {})
        rec = inv_map.get(invite_id)
        if rec is None:
            raise InboxError(f"no invitation found with invite_id={invite_id!r}")
        if rec.get("status") == "connected":
            raise InboxError("cannot revoke an invitation that has already been accepted")
        now = int(time.time())
        deleg_event = build_rendezvous_delegation_event(
            invite_id,
            rec["secret"],
            created_at=rec["created_at"],
            expires_at=rec["expires_at"],
        )
        revoke_ev = build_rendezvous_revoke_event(
            invite_id,
            rec["secret"],
            expires_at=rec["expires_at"],
            now=max(now, int(rec["created_at"])),
            created_at=rec["created_at"],
        )
        await agent.relay.connect()
        try:
            await agent._broadcast(deleg_event)
            await agent._broadcast(revoke_ev)
        except RelayError:
            log.warning("could not broadcast invitation revocation to relay; local revocation still applied")
        finally:
            await agent.relay.aclose()
        extra_public = (
            [r for r in _CORE_PUBLIC_RELAYS if r not in agent._own_relays]
            if policy.relay in _OFFICIAL_A4A_RELAYS
            else []
        )
        if extra_public:
            await _broadcast_extra_relays([deleg_event, revoke_ev], extra_public)
        rec = dict(rec)
        rec["status"] = "revoked"
        inv_map[invite_id] = rec
        data = _policy_to_json_data(policy, invitations=inv_map)
        _write_policy_data(data, replace=True)
        return _public_invite_view(rec, now, include_url=False)


def list_invitations(*, include_url: bool = False) -> list[dict]:
    """List invitations created by this mailbox."""
    policy = active_policy()
    now = int(time.time())
    items = [
        _public_invite_view(rec, now, include_url=include_url)
        for rec in (policy.invitations or {}).values()
    ]
    items.sort(key=lambda x: x["created_at"], reverse=True)
    return items


def _bind_accepted_invitation(
    policy: InboxPolicy,
    invite_id: str,
    responder_pubkey: str,
    responded_at: int,
) -> InboxPolicy:
    """Atomically bind `invite_id` to `responder_pubkey` and admit them at Trust Level L1."""
    inv_map = dict(policy.invitations or {})
    rec = dict(inv_map[invite_id])
    rec["status"] = "connected"
    rec["accepted_by"] = responder_pubkey
    rec["accepted_at"] = int(responded_at)
    inv_map[invite_id] = rec

    peers = set(policy.allowed_peers) | {responder_pubkey}
    blocked = set(policy.blocked_senders) - {responder_pubkey}
    new_trust = dict(policy.peer_trust or {})
    if responder_pubkey not in new_trust:
        new_trust[responder_pubkey] = {
            "level": 1,
            "origin": "external_contact",
            "topics": [],
            "remote_trust_attested": False,
        }
    data = _policy_to_json_data(
        policy,
        peer_trust=new_trust,
        blocked_senders=frozenset(blocked),
        invitations=inv_map,
    )
    data["allowed_peers"] = sorted(peers)
    return _write_policy_data(data, replace=True)


def try_redeem_inband_invitation(agent, outer_event) -> dict | None:
    """Inspect an incoming envelope for a signed `InvitationAcceptance` and redeem it at L1.

    Returns a summary dict when a valid open invitation was redeemed (or idempotently
    matched by the same responder), or None otherwise.
    """
    from a4a.invitations import parse_inband_acceptance_message
    from a4a.keys import Keys
    policy = active_policy()
    if not policy.invitations:
        return None
    message = agent._decode_incoming(outer_event)
    if message is None:
        return None
    acceptance = parse_inband_acceptance_message(message.get("content", ""))
    if acceptance is None:
        return None
    if acceptance.responder_pubkey != message.get("from_pubkey"):
        return None
    rec = (policy.invitations or {}).get(acceptance.invite_id)
    if rec is None:
        return None
    now = int(time.time())
    st = _effective_invite_status(rec, now)
    if st in ("revoked", "expired"):
        return None
    if st in ("responded", "connected") and rec.get("accepted_by") not in (None, acceptance.responder_pubkey):
        # Single-use guarantee: another key already redeemed this invitation.
        return None
    if not acceptance.verify(
        expected_invite_id=rec["invite_id"],
        expected_inviter_pubkey=policy.recipient,
        expected_challenge=rec["challenge"],
        expires_at=rec["expires_at"],
    ):
        return None
    _bind_accepted_invitation(
        policy,
        rec["invite_id"],
        acceptance.responder_pubkey,
        acceptance.responded_at,
    )
    responder_apub = Keys.encode_apub(acceptance.responder_pubkey)
    return {
        "invite_id": rec["invite_id"],
        "responder_pubkey": acceptance.responder_pubkey,
        "responder_apub": responder_apub,
        "trust_level": 1,
        "origin_label": "external_contact",
        "owner_onboarding_prompt": _owner_contact_onboarding_prompt(responder_apub),
    }


async def check_invitation(invite_id: str | None = None) -> dict:
    """Check status of one or all invitations, polling the blind rendezvous events for open ones."""
    from a4a.invitations import (
        decrypt_invitation_acceptance,
        derive_rendezvous_keys,
        is_valid_invite_token,
    )
    from a4a.keys import Keys
    if invite_id is not None and not is_valid_invite_token(invite_id):
        raise InboxError("invalid invite_id")
    with open_runtime() as (policy, agent, _):
        inv_map = dict(policy.invitations or {})
        if invite_id is not None and invite_id not in inv_map:
            raise InboxError(f"no invitation found with invite_id={invite_id!r}")
        targets = [invite_id] if invite_id is not None else list(inv_map.keys())
        now = int(time.time())
        open_targets = [
            tid for tid in targets
            if _effective_invite_status(inv_map[tid], now) == "open"
        ]
        newly_connected = []
        onboarding_prompts = []
        extra_public = (
            [r for r in _CORE_PUBLIC_RELAYS if r not in agent._own_relays]
            if policy.relay in _OFFICIAL_A4A_RELAYS
            else []
        )
        if open_targets:
            await agent.relay.connect()
            try:
                for tid in open_targets:
                    rec = inv_map[tid]
                    rk = derive_rendezvous_keys(tid, rec["secret"])
                    q_filter = {
                        "kinds": [types.KIND_PRIVATE_MESSAGE],
                        "authors": [rk.pubkey_hex],
                        "#p": [rk.pubkey_hex],
                        "#d": [f"accept:{tid}"],
                    }
                    events = await agent.relay.query(q_filter)
                    if not events and extra_public:
                        events = await _query_extra_relays(q_filter, extra_public)
                    if not events:
                        continue
                    events.sort(key=lambda e: (e.created_at, e.id))
                    for ev in events:
                        try:
                            acc = decrypt_invitation_acceptance(
                                ev.content,
                                rec["ephemeral_privkey"],
                                expected_invite_id=tid,
                                expected_inviter_pubkey=policy.recipient,
                                expected_challenge=rec["challenge"],
                                expires_at=rec["expires_at"],
                            )
                        except Exception:
                            continue
                        policy = _bind_accepted_invitation(
                            policy,
                            tid,
                            acc.responder_pubkey,
                            acc.responded_at,
                        )
                        inv_map = dict(policy.invitations or {})
                        try:
                            await agent.send_connection_request(
                                acc.responder_pubkey,
                                intro=f"Reciprocal handshake for invitation {tid[:8]}",
                            )
                        except Exception:
                            pass
                        newly_connected.append(tid)
                        onboarding_prompts.append(
                            _owner_contact_onboarding_prompt(Keys.encode_apub(acc.responder_pubkey))
                        )
                        break
            finally:
                await agent.relay.aclose()
        views = [
            _public_invite_view(inv_map[tid], now, include_url=True)
            for tid in targets
        ]
        out = {
            "checked": len(targets),
            "newly_connected": newly_connected,
            "invitations": views,
            "as_of": time.time(),
        }
        if onboarding_prompts:
            out["owner_onboarding_prompt"] = onboarding_prompts[0] if len(onboarding_prompts) == 1 else onboarding_prompts
        return out


async def accept_invitation(url: str, *, intro: str = "") -> dict:
    """Redeem a one-time invitation URL (`https://a4a.network/i/<id>#<secret>`).

    Decrypts and verifies Agent A's InvitationCard, admits Agent A into our local
    contacts at Trust Level L1 (`external_contact`), publishes the blind rendezvous
    acceptance, and sends the in-band signed acceptance + ConnectionRequest to Agent A.
    """
    from a4a.invitations import (
        InvitationAcceptance,
        InvitationError,
        REVOKED_CARD_MARKER,
        build_rendezvous_acceptance_event,
        build_rendezvous_delegation_event,
        decrypt_invitation_card,
        derive_rendezvous_keys,
        format_inband_acceptance_message,
        parse_invitation_url,
    )
    try:
        parsed = parse_invitation_url(url)
    except InvitationError as exc:
        raise InboxError(str(exc)) from exc
    invite_id = parsed["invite_id"]
    secret = parsed["secret"]
    rk = derive_rendezvous_keys(invite_id, secret)

    with open_runtime() as (policy, agent, _):
        now = int(time.time())
        extra_public = (
            [r for r in _CORE_PUBLIC_RELAYS if r not in agent._own_relays]
            if policy.relay in _OFFICIAL_A4A_RELAYS
            else []
        )
        await agent.relay.connect()
        try:
            card_filter = {
                "kinds": [types.KIND_PRIVATE_MESSAGE],
                "authors": [rk.pubkey_hex],
                "#p": [rk.pubkey_hex],
                "#d": [f"card:{invite_id}"],
            }
            card_events = await agent.relay.query(card_filter)
            if not card_events and extra_public:
                card_events = await _query_extra_relays(card_filter, extra_public)
            if not card_events:
                raise InboxError(
                    "invitation card was not found on the relay (it may have expired or been published to a different relay)"
                )
            card_events.sort(key=lambda e: (e.created_at, e.id), reverse=True)
            latest_card_ev = card_events[0]
            if latest_card_ev.content == REVOKED_CARD_MARKER:
                raise InboxError("this invitation was revoked by the inviter")
            try:
                card = decrypt_invitation_card(
                    latest_card_ev.content,
                    invite_id,
                    secret,
                    now=now,
                )
            except InvitationError as exc:
                raise InboxError(str(exc)) from exc

            if card.inviter_pubkey == policy.recipient:
                raise InboxError("an agent cannot accept its own invitation")

            accept_filter = {
                "kinds": [types.KIND_PRIVATE_MESSAGE],
                "authors": [rk.pubkey_hex],
                "#p": [rk.pubkey_hex],
                "#d": [f"accept:{invite_id}"],
            }
            existing_accepts = await agent.relay.query(accept_filter)
            if not existing_accepts and extra_public:
                existing_accepts = await _query_extra_relays(accept_filter, extra_public)
            if existing_accepts and card.inviter_pubkey not in policy.allowed_peers:
                raise InboxError("this one-time invitation has already been redeemed")

            try:
                acceptance = InvitationAcceptance.create(
                    card,
                    agent.keys,
                    list(agent._own_relays),
                    intro=intro,
                    now=now,
                )
                deleg_event = build_rendezvous_delegation_event(
                    invite_id,
                    secret,
                    created_at=card.created_at,
                    expires_at=card.expires_at,
                )
                accept_ev, _ = build_rendezvous_acceptance_event(
                    acceptance,
                    card.ephemeral_pubkey,
                    secret,
                    expires_at=card.expires_at,
                    created_at=card.created_at,
                )
            except InvitationError as exc:
                raise InboxError(str(exc)) from exc

            # Admit Agent A into our local contacts at Trust Level L1 (`external_contact`).
            peers = set(policy.allowed_peers) | {card.inviter_pubkey}
            blocked = set(policy.blocked_senders) - {card.inviter_pubkey}
            new_trust = dict(policy.peer_trust or {})
            if card.inviter_pubkey not in new_trust:
                entry = {
                    "level": 1,
                    "origin": "external_contact",
                    "topics": [],
                    "remote_trust_attested": False,
                }
                if card.label:
                    entry["label"] = card.label
                new_trust[card.inviter_pubkey] = entry
            data = _policy_to_json_data(
                policy,
                peer_trust=new_trust,
                blocked_senders=frozenset(blocked),
            )
            data["allowed_peers"] = sorted(peers)
            _write_policy_data(data, replace=True)

            await agent._broadcast(deleg_event)
            await agent._broadcast(accept_ev)
            try:
                await agent.send_connection_request(
                    card.inviter_pubkey,
                    intro=intro or "Connected via A4A one-time invitation",
                )
            except Exception:
                pass
            inband_msg = format_inband_acceptance_message(acceptance)
            inband_event_id = await agent.send_private_message(
                card.inviter_pubkey,
                inband_msg,
                wrap=True,
            )
            inviter_extra = [
                r for r in (*card.relays, *extra_public)
                if r not in agent._own_relays
            ]
            if inviter_extra:
                from a4a import nip59
                _, inner_ev = agent._build_private_message_event(card.inviter_pubkey, inband_msg)
                extra_wrap = nip59.wrap_event(inner_ev, agent.keys, card.inviter_pubkey)
                await _broadcast_extra_relays(
                    [deleg_event, accept_ev, extra_wrap],
                    list(dict.fromkeys(inviter_extra)),
                )
        finally:
            await agent.relay.aclose()

        return {
            "status": "connected",
            "invite_id": invite_id,
            "inviter_pubkey": card.inviter_pubkey,
            "inviter_apub": card.inviter_apub,
            "inviter_label": card.label,
            "trust_level": 1,
            "origin_label": "external_contact",
            "handshake_event_id": inband_event_id,
            "owner_onboarding_prompt": _owner_contact_onboarding_prompt(card.inviter_apub, card.label),
        }


# --- Stage 3: Public Reception Mode (Quarantine Inbox) ----------------------


def set_intake_mode(mode: str) -> InboxPolicy:
    """Owner CLI action: set intake mode ('closed', 'reception', or 'public_service')."""
    if mode not in VALID_INTAKE_MODES:
        raise InboxError(f"intake_mode must be one of {VALID_INTAKE_MODES}; got {mode!r}")
    policy = active_policy()
    data = _policy_to_json_data(policy, intake_mode=mode)
    return _write_policy_data(data, replace=True)


def quarantine_digest(*, state: str | None = "pending", limit: int = 50) -> dict:
    """Return a sanitized digest of quarantined reception inquiries (Trust Level L0)."""
    from a4a.keys import Keys
    with open_runtime() as (policy, _, store):
        counts = store.quarantine_counts()
        rows = store.quarantine_list(state=state, limit=limit)
        formatted = []
        for r in rows:
            sender = r["sender"]
            formatted.append({
                "req_id": r["req_id"],
                "sender_pubkey": sender,
                "sender_apub": Keys.encode_apub(sender),
                "origin_label": "unknown_sender",
                "trust_level": 0,
                "state": r["state"],
                "received_at": r["received"],
                "decided_at": r["decided_at"],
                "delivery_id": r["delivery_id"],
                "bridge_preamble": MANDATORY_BRIDGE_PREAMBLE_RU,
                "preview": wrap_untrusted(
                    r["preview"],
                    source=sender[:12],
                    origin_label="unknown_sender",
                    trust_level=0,
                ),
            })
        return {
            "intake_mode": policy.intake_mode,
            "counts": counts,
            "requests": formatted,
            "as_of": time.time(),
        }


def quarantine_decide(req_id: int, decision: str) -> dict:
    """Owner action: 'accept' (promote to L1 and move to inbox), 'reject', or 'block'."""
    from a4a.keys import Keys
    with open_runtime() as (policy, _, store):
        res = store.quarantine_decide(int(req_id), decision)
        sender = res["sender"]
        if decision == "accept":
            peers = set(policy.allowed_peers) | {sender}
            blocked = set(policy.blocked_senders) - {sender}
            new_trust = dict(policy.peer_trust or {})
            if sender not in new_trust:
                new_trust[sender] = {
                    "level": 1,
                    "origin": "external_contact",
                    "topics": [],
                    "remote_trust_attested": False,
                }
            data = _policy_to_json_data(
                policy,
                peer_trust=new_trust,
                blocked_senders=frozenset(blocked),
            )
            data["allowed_peers"] = sorted(peers)
            _write_policy_data(data, replace=True)
            res["trust_level"] = 1
            res["origin_label"] = "external_contact"
        elif decision == "block":
            peers = set(policy.allowed_peers) - {sender}
            blocked = set(policy.blocked_senders) | {sender}
            data = _policy_to_json_data(
                policy,
                blocked_senders=frozenset(blocked),
            )
            data["allowed_peers"] = sorted(peers)
            _write_policy_data(data, replace=True)
        res["sender_apub"] = Keys.encode_apub(sender)
        return res

