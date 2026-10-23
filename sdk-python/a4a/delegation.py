"""User-to-agent delegation (kind 31000), revocation (31007), and chain validation."""
import time
import unicodedata

from .event import Event, is_canonical_pubkey
from .keys import Keys
from .types import KIND_DELEGATION, KIND_DELEGATION_REVOCATION


def create_delegation(user_keys: Keys, agent_pubkey: str, name: str,
                      expiration: int, contact: str | None = None,
                      content: str = "", created_at: int | None = None) -> Event:
    """Create an event granting an agent authority until `expiration`.

    Kind 31000 is addressable under d=<delegate pubkey>, giving an owner an independent
    delegation for each agent. Reissuing to the same agent replaces the previous one.

    `created_at` supports rehiring after revocation. A revocation applies to delegations
    created no later than itself, so the new delegation must be dated STRICTLY later.
    Otherwise one issued in the same second is byte-identical to the old delegation,
    has the same id, and remains revoked (found 2026-09-04).
    """
    tags = [["d", agent_pubkey],
            ["delegate", agent_pubkey],
            ["owner", user_keys.pubkey_hex],
            ["name", name],
            ["expiration", str(expiration)]]
    if contact:
        tags.append(["contact", contact])
    ev = Event(kind=KIND_DELEGATION, tags=tags,
               content=content or f"I delegate search and transaction authority to agent {name!r}")
    if created_at is not None:
        ev.created_at = int(created_at)
    return ev.sign(user_keys)


def create_revocation(user_keys: Keys, delegation: Event, reason: str = "",
                      content: str = "") -> Event:
    """Revoke an agent delegation as its owner.

    Kind 31007 is addressable under d=<delegate pubkey>. The v0.3 P4 hybrid combines
    short delegation lifetimes with immediate owner revocation, for example after an
    agent key is compromised.

    Revoke the AGENT, not a specific signed event. Revocations used to address a
    delegation id, but kind 31000 is addressable by `d`=<delegate pubkey>; reissuing
    replaces the old delegation and changes its id. An agent could retain the public
    old signed copy, publish it to a relay that had not seen the replacement, and cite
    its old id. A revocation of the current copy did not apply, so the old copy stayed
    active under its own expiry. Coordinate `31000:<owner>:<delegate>` covers every
    version (2026-08-29 internal audit, F6).

    Tag `e` remains informational, recording the version held by the owner, but does
    NOT participate in validation or copy-specific behavior would return.
    """
    delegate = delegation.tag_value("delegate") or ""
    tags = [["d", delegate],
            ["a", f"{KIND_DELEGATION}:{delegation.pubkey}:{delegate}"],
            ["e", delegation.id],
            ["delegate", delegate]]
    if reason:
        tags.append(["reason", reason])
    ev = Event(kind=KIND_DELEGATION_REVOCATION, tags=tags,
               content=content or "Delegation revoked")
    return ev.sign(user_keys)


def is_revocation_valid(revocation: Event, delegation: Event) -> bool:
    """Validate an owner-signed revocation of the same delegate.

    The revocation must be no earlier than the delegation. This time comparison is
    essential: otherwise an owner who revoked and later rehired an agent could never
    issue a new mandate because the old revocation would ban it forever.
    """
    try:
        revocation.validate_numeric_tags()
        delegation.validate_numeric_tags()
    except ValueError:
        return False
    delegate = delegation.tag_value("delegate")
    if not delegate:
        return False
    # A revocation is history and never expires. The relay rejects one carrying an
    # `expiration` tag: otherwise it could disappear under NIP-40 and revive the
    # delegation (finding 79, 2026-09-04). A foreign relay may still send one, so apply
    # the same grammar here: if the tag exists, this is not a valid revocation.
    if any(tag and tag[0] == "expiration" for tag in revocation.tags):
        return False
    coordinate = f"{KIND_DELEGATION}:{delegation.pubkey}:{delegate}"
    if any(len(tag) < 2 or tag[1].lower() != coordinate
           for tag in revocation.tags if tag and tag[0] == "a"):
        return False
    return (revocation.kind == KIND_DELEGATION_REVOCATION
            and revocation.verify()
            and revocation.pubkey == delegation.pubkey
            and revocation.tag_value("d") == delegate
            and revocation.created_at >= delegation.created_at)


def delegation_target(delegation: Event) -> str | None:
    """Return the canonical delegate addressed by the delegation's `d` tag.

    Return `None` when the tag is absent, differs from `delegate`, or is non-canonical.

    Kind 31000 is addressable by `d`, and revocations use the SAME coordinate
    (`31000:<owner>:<delegate>`). Validation once required only `delegate`, not `d`,
    and never compared fields that must match. A delegation without `d` passed fully:
    the agent was admitted by `delegate`, while revocation lookup used `d` and found none.

    Found in the relay on 2026-08-31, this was worse than it sounds: the relay accepted
    an owner's revocation, but cache invalidation searched by missing `d`, found no
    delegation, and retained the old verdict. The revoked agent could publish for the
    full cache TTL—five minutes in production. The same SDK gap would be copied by
    other implementations.

    Case reaches the same gap another way: revocation lookup canonicalizes to lowercase,
    while storage compares tag text byte-for-byte. Event rejects a non-canonical pubkey,
    but tags are free-form and must be checked separately here.
    """
    d = delegation.tag_value("d")
    delegate = delegation.tag_value("delegate")
    if d is None or d != delegate or not is_canonical_pubkey(d):
        return None
    return d


def signed_agent_name(delegation: Event) -> str | None:
    """Return a display-safe name only from one owner-signed mandate tag.

    Invalid, ambiguous, or control-bearing names fall back to the agent key in
    callers. The name is not taken from the agent's self-authored profile/message.
    """
    if delegation.kind != KIND_DELEGATION or not delegation.verify_protocol():
        return None
    tags = [tag for tag in delegation.tags if tag and tag[0] == "name"]
    if len(tags) != 1 or len(tags[0]) != 2 or not isinstance(tags[0][1], str):
        return None
    name = tags[0][1].strip()
    if not 1 <= len(name) <= 80 or any(unicodedata.category(c).startswith("C") for c in name):
        return None
    return name


def validate_delegation(event: Event, delegation: Event,
                        now: int | None = None,
                        revocation: Event | None = None, *,
                        at: int | None = None) -> bool:
    """Validate agent event → delegation → owner signature → expiry → revocation.

    A valid `revocation` makes the delegation invalid before its expiry; see
    `is_revocation_valid`.

    `at=T` checks whether T falls inside the DECLARED mandate interval:
    `delegation.created_at <= T < expiration`. This validates terms and signatures,
    NOT historical authority. A timestamp block time is not event signing or publication
    time, and two timestamps do not order event versus revocation. See `Agent.authority_at`.

    The answer is "authorized NOW," not "authorized when published." Signed data cannot
    prove the latter: the agent sets `created_at`, and the relay has no backward bound
    (a live 2026-09-04 probe accepted an event backdated 400 days). An event older than
    a delegation's lifetime or replacement therefore returns False because the relay no
    longer has that version (finding 65). This is a protocol boundary, not a failure:
    one or two timestamps cannot prove historical authority (spec v0.4 §4.1). Use this
    function for FRESH inbound events; agreements and reviews rely on party signatures,
    not mandates.
    """
    if at is not None:
        now = int(at)
        if delegation.created_at > now:
            return False  # Delegation was issued after T.
    try:
        event.validate_numeric_tags()
    except ValueError:
        return False
    return (event.delegation_ref() == delegation.id
            and event.verify()
            and validate_sender_mandate(event.pubkey, delegation, now=now,
                                        revocation=revocation))


def validate_sender_mandate(sender_pubkey: str, delegation: Event,
                            now: int | None = None,
                            revocation: Event | None = None, *,
                            require_started: bool = False) -> bool:
    """Check current authority for a signed sender key without an event reference.

    Private inbox authorization is key-based: the gift-wrap's signed inner event
    establishes the sender, while the owner's live mandate establishes affiliation.
    Callers must still verify the message signature before using this verdict.
    """
    now = now if now is not None else int(time.time())
    try:
        delegation.validate_numeric_tags()
        expiration = delegation.expiration()
    except ValueError:
        return False
    if expiration is None:
        return False  # A non-numeric/non-canonical network expiry invalidates the chain.
    if revocation is not None and is_revocation_valid(revocation, delegation):
        return False  # Owner revoked the delegation.
    return (delegation.kind == KIND_DELEGATION
            and delegation.verify()
            and is_canonical_pubkey(sender_pubkey)
            and delegation_target(delegation) is not None
            and delegation.tag_value("delegate") == sender_pubkey
            and delegation.tag_value("owner") == delegation.pubkey
            and (not require_started or delegation.created_at <= now)
            and expiration > now)
