"""Owner-enabled dialogue tools over the SDK's durable, fenced inbox store."""
from __future__ import annotations

import contextlib
import functools
import re
import uuid

from a4a.dialogue import DialogueStore
from a4a.inbox import InboxConflict, InboxError, InboxPolicyChanged

from . import identity, inbox_runtime


_WORKER_ID = str(uuid.uuid4())


class _NotEnabled(InboxError):
    pass


class _MandateRequired(InboxError):
    pass


def tool_errors(function):
    """Never expose exception payloads, decrypted storage or relay instructions."""
    @functools.wraps(function)
    async def wrapped(*args, **kwargs):
        try:
            return await function(*args, **kwargs)
        except _NotEnabled:
            error, message = "dialogue_not_enabled", (
                "Dialogue mode requires explicit owner activation with dialogue-enable. "
                "Do not enable it on the owner's behalf.")
        except _MandateRequired:
            error, message = "mandate_required", (
                "No existing owner mandate was found. Publication was refused. "
                "Ask the owner; do not issue a mandate or enable automatic issuance.")
        except InboxPolicyChanged:
            error, message = "policy_changed", "Local inbox policy changed; access is closed."
        except InboxConflict:
            error, message = "dialogue_conflict", (
                "Lease or stored work conflicts with this operation. Inspect current work; "
                "uncertain work requires explicit reconciliation, not a new send.")
        except InboxError:
            error, message = "dialogue_refused", (
                "Dialogue access, arguments or local storage were refused. "
                "Check owner configuration and the current lease.")
        except Exception:
            error, message = "dialogue_failed", (
                "Dialogue operation failed; no success receipt is available. "
                "An attempted send may be unknown. Inspect history and explicitly "
                "reconcile the same operation_id before any further send.")
        return {"state": "refused", "error": error, "message": message}
    return wrapped


def _open_dialogues(policy):
    """Open dialogue storage with the SAME capacity limit as the inbox.

    OPS-007: this is not the project's only storage constructor. The change that
    introduced the setting incorrectly claimed the capacity was configured in one
    place, leaving dialogue storage at its 64 MiB default while a value of
    ``A4A_INBOX_MAX_MB=1`` limited only the inbox to 1 MiB. Testing ``_open_store``
    alone missed the mismatch because the guard covered only its own entry point.
    """
    return DialogueStore(identity.IDENTITY_DIR / "inbox", policy.recipient,
                         policy.consumer, max_items=inbox_runtime._inbox_max_items(),
                         max_bytes=inbox_runtime._inbox_max_bytes())


def enable():
    """Local owner CLI only. No identity, owner key or mandate is created."""
    with inbox_runtime.open_runtime() as (policy, _, _):
        if policy.allowed_owners:
            raise InboxError("dialogue mode cannot be enabled with allowed_owners yet")
        inbox_runtime.refresh_policy(policy)
        with _open_dialogues(policy) as store:
            store.activate()
    return {"state": "dialogue_enabled"}


@contextlib.contextmanager
def open_runtime():
    with inbox_runtime.open_runtime() as (policy, agent, inbox):
        # Refuse before constructing DialogueStore: its constructor adds schema.
        if not inbox.dialogue_enabled():
            raise _NotEnabled()

        def allowed():
            return inbox_runtime.refresh_policy(policy).allowed_peers

        with _open_dialogues(policy) as store:
            yield agent, store, allowed


def _history(agent, store, allowed, token, before=0):
    result = store.history(agent, token, _WORKER_ID, allowed, before=before)
    for item in result["items"]:
        source = result["peer"] if item["direction"] == "in" else agent.pubkey
        item["content"] = inbox_runtime.shown_content({"from_pubkey": source, "content": item["content"]})
    if result["checkpoint"] is not None:
        result["checkpoint"] = inbox_runtime.shown_content(
            {"from_pubkey": "local-checkpoint", "content": result["checkpoint"]})
    return result


def open_dialogue(peer_pubkey=""):
    if peer_pubkey:
        from a4a.keys import Keys
        peer_pubkey = Keys.normalize_pubkey(peer_pubkey)
    with open_runtime() as (agent, store, allowed):
        if peer_pubkey == "":
            work = store.work(allowed)
            peer_pubkey = next((item["peer"] for item in work if not item["lease_active"]), "")
            if not peer_pubkey:
                return {"state": "no_unleased_work", "work": work}
        lease = store.acquire(peer_pubkey, _WORKER_ID, allowed)
        return {"lease": lease, "history": _history(agent, store, allowed, lease["token"])}


def history(lease_token, before=0):
    with open_runtime() as (agent, store, allowed):
        return _history(agent, store, allowed, lease_token, before)


def checkpoint(lease_token, text):
    with open_runtime() as (agent, store, allowed):
        return store.checkpoint(agent, lease_token, _WORKER_ID, allowed, text)


def lease(lease_token, action):
    with open_runtime() as (_, store, allowed):
        if action == "renew":
            return store.renew(lease_token, _WORKER_ID, allowed)
        if action == "release":
            return store.release(lease_token, _WORKER_ID, allowed)
        raise InboxError("invalid dialogue lease action")


def complete(lease_token, seq, status, reconciled=False):
    with open_runtime() as (_, store, allowed):
        return store.finish_incoming(lease_token, _WORKER_ID, allowed, seq, status,
                                     reconciled=reconciled)


def _operation_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        raise InboxError("invalid operation identifier")


def _send_text(value):
    if not isinstance(value, str):
        raise InboxError("dialogue text must be a string")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise InboxError("invalid dialogue text encoding") from None
    if size > 32768:
        raise InboxError("dialogue text exceeds the local size limit")


def _has_operation(store, peer, operation_id):
    # The SDK validates/decrypts existing content via prepare_send. This lookup
    # only selects the offline retry path; it never returns an envelope or key.
    return store.db.execute("SELECT 1 FROM dialogue_outbox WHERE peer=? AND operation_id=?",
                            (peer, operation_id)).fetchone() is not None


@contextlib.asynccontextmanager
async def _authorized_connection(agent, store, token, allowed):
    from .server import _find_existing_mandate

    async with agent:
        store.validate_lease(token, _WORKER_ID, allowed)
        agent.delegation_id = await _find_existing_mandate(agent)
        store.validate_lease(token, _WORKER_ID, allowed)
        if agent.delegation_id is None:
            raise _MandateRequired()
        yield


async def send(lease_token, operation_id, text):
    with open_runtime() as (agent, store, allowed):
        binding = store.validate_lease(lease_token, _WORKER_ID, allowed)
        _operation_id(operation_id)
        _send_text(text)
        existing = _has_operation(store, binding["peer"], operation_id)
        if existing:
            receipt = store.prepare_send(agent, lease_token, _WORKER_ID, allowed, operation_id, text)
            if receipt["state"] != "prepared":
                return receipt
        if store.db.execute("""SELECT 1 FROM dialogue_outbox WHERE peer=?
                AND state IN ('dispatching','unknown') LIMIT 1""", (binding["peer"],)).fetchone():
            raise InboxConflict("uncertain outgoing work requires reconciliation")
        async with _authorized_connection(agent, store, lease_token, allowed):
            if not existing:
                store.prepare_send(agent, lease_token, _WORKER_ID, allowed, operation_id, text)
            return await store.dispatch(agent, lease_token, _WORKER_ID, allowed, operation_id)


def abandon(lease_token, operation_id):
    """Terminally close a PREPARED message that can no longer be sent.

    This path must not access the network: the message was never dispatched and
    never will be. Opening a connection solely to abandon it would add an external
    side effect to a local terminal action. Unlike ``reconcile``, this function
    therefore never connects the agent.
    """
    with open_runtime() as (agent, store, allowed):
        binding = store.validate_lease(lease_token, _WORKER_ID, allowed)
        _operation_id(operation_id)
        if not _has_operation(store, binding["peer"], operation_id):
            raise InboxConflict("outgoing operation is missing")
        return store.abandon(agent, lease_token, _WORKER_ID, allowed, operation_id)


async def reconcile(lease_token, operation_id):
    with open_runtime() as (agent, store, allowed):
        binding = store.validate_lease(lease_token, _WORKER_ID, allowed)
        _operation_id(operation_id)
        if not _has_operation(store, binding["peer"], operation_id):
            raise InboxConflict("outgoing operation is missing")
        async with agent:
            store.validate_lease(lease_token, _WORKER_ID, allowed)
            result = await store.reconcile(agent, lease_token, _WORKER_ID, allowed, operation_id)
            store.validate_lease(lease_token, _WORKER_ID, allowed)
            return result
