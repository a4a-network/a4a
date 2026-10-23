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
from a4a.relay import RelayError
from a4a.sanitize import wrap_untrusted

from . import identity

log = logging.getLogger(__name__)


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


_OPTIONAL_POLICY_FIELDS = {"ack_on_receipt", "allowed_owners"}


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
    if type(data["enabled"]) is not bool:
        raise InboxError("enabled must be a JSON boolean")
    for key, low, high in (("start_after", 0, 2**63 - 1), ("notify_interval", 10, 3600), ("notify_per_hour", 1, 60)):
        if type(data[key]) is not int or not low <= data[key] <= high:
            raise InboxError("invalid inbox numeric policy")
    if not isinstance(data["relay"], str):
        raise InboxError("invalid inbox relay")
    InboxHistory(data["relay"], data["recipient"])
    return InboxPolicy(**{**data, "allowed_peers": frozenset(peers),
                          "allowed_owners": frozenset(owners)})


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


def configure(consumer, allowed_peers, *, start_after=None, replace=False,
              ack_on_receipt=False, allowed_owners=()):
    """Explicit local owner CLI action. Never an MCP tool and never issues a mandate."""
    if not identity.IDENTITY_FILE.is_file():
        raise InboxError("create and verify the intended identity before configuring inbox")
    from a4a.keys import Keys
    allowed_peers = [Keys.normalize_pubkey(p) for p in allowed_peers]
    allowed_owners = [Keys.normalize_pubkey(o) for o in allowed_owners]
    keys = _existing_keys()
    from .server import _relay_url
    data = asdict(InboxPolicy(1, keys.pubkey_hex, consumer, _relay_url(),
                             frozenset(allowed_peers), int(time.time()) if start_after is None else start_after,
                             ack_on_receipt=ack_on_receipt))
    data["allowed_peers"] = list(allowed_peers)
    data["allowed_owners"] = list(allowed_owners)
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
    from .server import _relay_url
    if policy.relay != _relay_url():
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
    with open_runtime() as (_, agent, store):
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
    _measured(message)
    text = shown_content(message)
    out = Path(out_path)
    out.write_text(text, encoding="utf-8", newline="\n")
    return {"seq": seq, "state": row["state"], "from_pubkey": row["sender"],
            "delivery_id": message["delivery_id"], "content_file": str(out),
            "content_chars": message["content_chars"], "content_sha256": message["content_sha256"],
            # Times too (27.09, letter 278): stamps are checked against the signature afterwards.
            "signed_at": message["signed_at"], "received_at": row["received"],
            **{k: message[k] for k in ("declared_chars", "declared_chars_match") if k in message}}


def shown_content(message):
    content = message["content"]
    if _is_file_reference_attempt(content):
        handle = gateway_attachment(content)
        text = (_GATEWAY_ATTACHMENT.format(sha=handle) if handle
                else _FILE_REFERENCE_UNAVAILABLE)
    else:
        text = content
    return wrap_untrusted(text, source=message["from_pubkey"][:12])


@contextlib.contextmanager
def open_runtime():
    policy = active_policy()
    keys = _existing_keys()
    if keys.pubkey_hex != policy.recipient:
        raise InboxError("inbox identity differs from the owner-configured recipient")
    # Read from ALL configured relays rather than only the policy relay. The checks
    # above guarantee that the FIRST address matches policy, so ``policy.relay``
    # remains the stable binding while additional relays only add retrieval paths.
    # Otherwise, losing the sole relay would lose every unread message on it.
    from .server import _relay_urls
    agent = Agent(_relay_urls(), keys=keys)
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
        message = store.claim(agent, policy.consumer, refresh_policy(policy).allowed_peers)
        health = shown_health(store.health())
        if message:
            _measured(message)
            message["content"] = shown_content(message)
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
            message["content"] = shown_content(message)
            mandate = mandates.get(message["from_pubkey"])
            if mandate is not None:
                message["sender_identity"] = owner_agent_identity(
                    message["from_pubkey"], mandate)
        state = "processing" if message else ("idle" if health.get("state") == "ready" and not health.get("stale") else "receiver_unavailable")
        return _with_unknown_notice({"state": state, "message": message, "receiver": health}, store)


_WRAP_START = "[UNTRUSTED DATA FROM THE A4A NETWORK"
_WRAP_END = "[END OF UNTRUSTED DATA]"
#: First line written by the forwarding tool; its parse_forward is mirrored here.
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
        # The line is written by the forwarding tool, whose
        # header is covered by tests: a damaged one means a tool defect or a hand-made or
        # edited line, not a correspondent's mistake - so it is logged and named as such.
        log.warning("damaged forward header refused: %s", problem)
        raise InboxError(
            f"this letter's first line starts with {FORWARD_TAG} but does not parse "
            f"({problem}), so its original sender is unknown and nothing was sent. The line "
            "is written by the forwarding tool: a damaged one means a tool defect or a "
            "hand-edited line, not the correspondent's mistake - report it to the forwarding "
            "operator with the seq. To answer the copy itself, write to the "
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
        receiver = InboxReceiver(agent, store, current_peers, start_after=policy.start_after,
                                 ack_on_receipt=policy.ack_on_receipt,
                                 allowed_owners=lambda: refresh_policy(policy).allowed_owners)
        async with contextlib.aclosing(receiver.notices(
                interval=policy.notify_interval, per_hour=policy.notify_per_hour,
                on_tick=flush_acks)) as source:
            async for notice in source:
                yield notice
