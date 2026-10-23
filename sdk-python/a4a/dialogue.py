"""Opt-in, single-role local dialogue history and fenced managed text sending."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time

from . import nip44
from .event import Event, is_canonical_pubkey
from .inbox import InboxConflict, InboxError, InboxFull, InboxStore


def _clock(now):
    value = time.time() if now is None else now
    if type(value) not in (int, float) or not 0 <= value <= 2**53:
        raise InboxError("invalid dialogue time")
    return value


def _name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        raise InboxError("invalid local worker or operation identifier")
    return value


def _text(value, bound):
    if not isinstance(value, str):
        raise InboxError("dialogue text must be a string")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise InboxError("invalid dialogue text encoding") from None
    if size > bound:
        raise InboxError("dialogue text exceeds the local size limit")
    return value


#: Version marker for relay-set encoding in the `relay` column. A marker, rather
#: than merely a delimiter, is essential: a SINGLE-node set has no delimiter and is
#: indistinguishable from the legacy format. A fresh single-node record would then
#: follow the legacy membership rule, allowing the message to reach an operator that
#: was absent during preparation—the exact exposure that recording the set prevents.
_RELAY_SET_PREFIX = "v1:"


def _configured_relays(agent) -> set[str]:
    clients = getattr(agent.relay, "clients", None)
    return {client.url for client in clients} if clients else {agent.relay.url}


def _relay_fingerprint(agent) -> str:
    """Return a versioned canonical fingerprint of the ENTIRE configured relay set.

    The `relay` column originally stored one node address. While the client used one
    relay, that address represented the set. With fan-out transport, the FIRST node
    was stored, so comparison answered only “is the first list entry unchanged?”
    Reordering the nodes stranded prepared messages.

    The first fix tested membership: the preparation relay had to be present in the
    current set. This catches removal but not ADDITION. An added relay is another
    operator that sees the envelope; content is encrypted, but participants and
    timing are not.

    The second fix joined the set with a delimiter. A single-node set still had no
    delimiter, making a fresh record indistinguishable from a legacy one and
    reopening the flaw for the most common case. Hence the version marker, which is
    always present even for a single address or an empty set.
    """
    return _RELAY_SET_PREFIX + json.dumps(sorted(_configured_relays(agent)),
                                          ensure_ascii=False)


def _same_relay_set(stored: str, agent) -> bool:
    """Compare the recorded relay set with the current one, failing closed both ways.

    A legacy record contains one address, so the original set cannot be recovered.
    The first implementation treated it as membership: an old record for A was
    accepted for {A, B}. Review correctly rejected that behavior. An unknown set is
    not permission to add an operator. Missing information about intended recipients
    must mean refusal, not “probably safe.”

    A legacy record is therefore valid ONLY for the same single-node set. Any other
    case is a mismatch requiring manual handling: prepare the message again for the
    current set. Retrospective rewriting is also forbidden because the original set
    cannot be reconstructed.
    """
    current = _configured_relays(agent)
    if stored.startswith(_RELAY_SET_PREFIX):
        try:
            recorded = json.loads(stored[len(_RELAY_SET_PREFIX):])
        except ValueError:
            return False
        return set(recorded) == current
    return current == {stored}


def _relay_set_conflict(stored: str, state: str) -> str:
    """Explain the safe recovery without disclosing the recorded relay address."""
    legacy = not stored.startswith(_RELAY_SET_PREFIX)
    record = "legacy single-relay operation" if legacy else "outgoing operation"
    if state == "prepared":
        return (f"{record} belongs to a different relay set; restore its recorded "
                "relay configuration to dispatch it, or abandon it and prepare a new "
                "operation for the current set")
    if state in ("dispatching", "unknown"):
        return (f"uncertain {record} belongs to a different relay set; restore its "
                "recorded relay configuration to reconcile it; uncertain work cannot "
                "be abandoned or resent through the current set")
    return (f"{record} belongs to a different relay set; restore its recorded relay "
            "configuration to inspect the stable receipt")


class DialogueStore(InboxStore):
    """Same inbox DB/identity, one conversation per peer and one cooperative role.

    Tokens fence managed operations, not arbitrary shell/SDK calls. Never hold a
    SQLite transaction across network awaits. An already started send may finish
    after lease loss; its uncertain state prevents a replacement's blind send.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            with self._transaction():
                self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('dialogue_schema','1')")
                if self.db.execute("SELECT value FROM metadata WHERE key='dialogue_schema'").fetchone()[0] != "1":
                    raise InboxConflict("unsupported dialogue schema")
                self.db.execute("""CREATE TABLE IF NOT EXISTS dialogues (
                    peer TEXT PRIMARY KEY, conversation_id TEXT NOT NULL UNIQUE,
                    epoch INTEGER NOT NULL DEFAULT 0, worker TEXT, token TEXT UNIQUE,
                    lease_until REAL NOT NULL DEFAULT 0, checkpoint TEXT)""")
                self.db.execute("""CREATE TABLE IF NOT EXISTS dialogue_outbox (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, peer TEXT NOT NULL,
                    operation_id TEXT NOT NULL, inner_id TEXT NOT NULL, outer_id TEXT NOT NULL,
                    delivery_id TEXT NOT NULL, envelope TEXT NOT NULL, local_body TEXT NOT NULL,
                    relay TEXT NOT NULL, state TEXT NOT NULL, created REAL NOT NULL,
                    UNIQUE(peer, operation_id))""")
                self.db.execute("""CREATE TABLE IF NOT EXISTS dialogue_history (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, peer TEXT NOT NULL,
                    direction TEXT NOT NULL, ref INTEGER NOT NULL, UNIQUE(direction, ref))""")
                self.db.execute("CREATE INDEX IF NOT EXISTS dialogue_history_peer ON dialogue_history(peer,seq)")
        except BaseException:
            self.db.close()
            raise

    def activate(self):
        """Explicit local owner action, never invoked implicitly by an MCP tool."""
        with self._transaction():
            if self.db.execute("SELECT 1 FROM messages WHERE state='processing' LIMIT 1").fetchone():
                raise InboxConflict("finish legacy inbox claims before enabling dialogues")
            # The second half of OPS-006. Pruning leaves metadata without the
            # envelope, and the five metadata fields cannot reconstruct complete
            # incoming history. Enabling dialogues over such an inbox would promise
            # history that does not exist and silently present an incomplete page as
            # complete.
            #
            # Check inside the activation transaction: activation and pruning must
            # be ordered rather than race. Whichever starts first wins, while the
            # loser receives a refusal instead of corrupt history.
            if self.db.execute("SELECT 1 FROM messages WHERE envelope='' LIMIT 1").fetchone():
                raise InboxConflict(
                    "dialogue mode cannot be enabled over a pruned inbox: compacted rows "
                    "keep identity but not content, so incoming history is incomplete")
            self.db.execute("INSERT INTO metadata VALUES ('dialogue_mode','1') ON CONFLICT(key) DO UPDATE SET value='1'")

    def _enabled(self):
        if not self.dialogue_enabled():
            raise InboxError("dialogue mode is not enabled by the owner")

    def _peer(self, peer, allowed):
        peers = allowed() if callable(allowed) else allowed
        if not isinstance(peer, str) or not is_canonical_pubkey(peer) or peer not in peers:
            raise InboxError("dialogue peer is not authorized by local policy")

    def _agent(self, agent):
        if agent.pubkey != self.recipient:
            raise InboxConflict("dialogue decoder identity mismatch")

    def _owned(self, token, worker, allowed, now):
        self._enabled()
        _name(worker)
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{48}", token):
            raise InboxConflict("invalid dialogue lease")
        row = self.db.execute("SELECT * FROM dialogues WHERE token=?", (token,)).fetchone()
        if row is None or row["worker"] != worker or row["lease_until"] <= now:
            raise InboxConflict("stale or foreign dialogue lease")
        self._peer(row["peer"], allowed)
        return row

    def _sync_history(self, peer):
        self.db.execute("""INSERT OR IGNORE INTO dialogue_history(peer,direction,ref)
            SELECT sender,'in',seq FROM messages WHERE sender=? ORDER BY seq""", (peer,))

    def acquire(self, peer, worker, allowed, *, now=None, lease_seconds=300):
        now = _clock(now)
        _name(worker)
        self._peer(peer, allowed)
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise InboxError("dialogue lease must be 1..3600 seconds")
        with self._transaction():
            self._enabled()
            self._expire_dialogues(now)
            row = self.db.execute("SELECT * FROM dialogues WHERE peer=?", (peer,)).fetchone()
            if row is not None and row["lease_until"] > now:
                raise InboxConflict("conversation is already leased; reuse or renew its token")
            if row is None:
                if self.db.execute("SELECT COUNT(*) FROM dialogues").fetchone()[0] >= 100:
                    raise InboxFull("dialogue count limit reached")
                cid = hashlib.sha256(json.dumps([self.recipient, self.consumer, peer]).encode()).hexdigest()
                self.db.execute("INSERT INTO dialogues(peer,conversation_id) VALUES (?,?)", (peer, cid))
            token = secrets.token_hex(24)
            self.db.execute("UPDATE dialogues SET epoch=epoch+1,worker=?,token=?,lease_until=? WHERE peer=?",
                            (worker, token, now + lease_seconds, peer))
            self._sync_history(peer)
            self.db.execute("""UPDATE messages SET state='processing',lease_token=?,lease_until=?
                WHERE sender=? AND state='pending'""", (token, now + lease_seconds, peer))
            row = self.db.execute("SELECT * FROM dialogues WHERE peer=?", (peer,)).fetchone()
            return {key: row[key] for key in ("conversation_id", "peer", "epoch", "token", "lease_until")}

    def renew(self, token, worker, allowed, *, now=None, lease_seconds=300):
        now = _clock(now)
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise InboxError("dialogue lease must be 1..3600 seconds")
        with self._transaction():
            row = self._owned(token, worker, allowed, now)
            self.db.execute("UPDATE dialogues SET lease_until=? WHERE peer=?", (now + lease_seconds, row["peer"]))
            self.db.execute("UPDATE messages SET lease_until=? WHERE lease_token=? AND state='processing'", (now + lease_seconds, token))
        return {"lease_until": now + lease_seconds}

    def validate_lease(self, token, worker, allowed, *, now=None):
        with self._transaction():
            row = self._owned(token, worker, allowed, _clock(now))
            return {key: row[key] for key in ("conversation_id", "peer", "epoch", "lease_until")}

    def work(self, allowed, *, now=None):
        """Find unfinished permitted conversations without knowing their peer IDs."""
        now = _clock(now)
        peers = set(allowed() if callable(allowed) else allowed)
        if len(peers) > 100:
            raise InboxError("dialogue peer policy exceeds its limit")
        result = []
        with self._transaction():
            self._enabled()
            self._expire_dialogues(now)
            for peer in sorted(peers):
                self._peer(peer, peers)
                incoming = dict(self.db.execute("""SELECT state,COUNT(*) FROM messages
                    WHERE sender=? AND state IN ('pending','processing','unknown') GROUP BY state""", (peer,)))
                outgoing = dict(self.db.execute("""SELECT state,COUNT(*) FROM dialogue_outbox
                    WHERE peer=? AND state IN ('prepared','dispatching','unknown') GROUP BY state""", (peer,)))
                if not incoming and not outgoing:
                    continue
                lease = self.db.execute("SELECT conversation_id,lease_until FROM dialogues WHERE peer=?", (peer,)).fetchone()
                result.append({"peer": peer, "conversation_id": lease["conversation_id"] if lease else None,
                               "lease_active": bool(lease and lease["lease_until"] > now),
                               "pending": incoming.get("pending", 0), "processing": incoming.get("processing", 0),
                               "unknown": incoming.get("unknown", 0), "outgoing": outgoing})
        return result

    def release(self, token, worker, allowed, *, now=None):
        now = _clock(now)
        with self._transaction():
            row = self._owned(token, worker, allowed, now)
            self.db.execute("UPDATE dialogues SET lease_until=0,token=NULL WHERE peer=?", (row["peer"],))
            self.db.execute("UPDATE messages SET state='unknown',lease_token=NULL WHERE lease_token=? AND state='processing'", (token,))
            self._expire_dialogues(now)
        return {"state": "released"}

    def _seal(self, agent, value):
        return nip44.encrypt(json.dumps(value, ensure_ascii=False, separators=(",", ":")), agent.keys.privkey_hex, self.recipient)

    def _unseal(self, agent, value):
        try:
            return json.loads(nip44.decrypt(value, agent.keys.privkey_hex, self.recipient))
        except (ValueError, TypeError, UnicodeError, KeyError) as exc:
            raise InboxConflict("stored dialogue data failed authentication") from exc

    def checkpoint(self, agent, token, worker, allowed, text, *, now=None):
        self._agent(agent)
        _text(text, 8192)
        with self._transaction():
            row = self._owned(token, worker, allowed, _clock(now))
            body = self._seal(agent, {"conversation_id": row["conversation_id"], "text": text})
            self.db.execute("UPDATE dialogues SET checkpoint=? WHERE peer=?", (body, row["peer"]))
        return {"state": "checkpoint_saved"}

    def _outgoing_inner(self, agent, row, cid):
        body = self._unseal(agent, row["local_body"])
        try:
            inner = Event.model_validate(body["inner"])
            if (body["conversation_id"] != cid or body["operation_id"] != row["operation_id"]
                    or body["outer_id"] != row["outer_id"] or body["relay"] != row["relay"]
                    or not inner.verify() or inner.pubkey != self.recipient or inner.id != row["inner_id"]
                    or inner.tag_value("p") != row["peer"] or inner.tag_value("d") != row["delivery_id"]):
                raise ValueError()
            return inner
        except (ValueError, TypeError, KeyError) as exc:
            raise InboxConflict("stored outgoing message binding mismatch") from exc

    def history(self, agent, token, worker, allowed, *, now=None, before=0, limit=20):
        self._agent(agent)
        if type(before) is not int or not 0 <= before <= 2**63 - 1 or type(limit) is not int or not 1 <= limit <= 100:
            raise InboxError("invalid dialogue history page")
        with self._transaction():
            now = _clock(now)
            self._expire_dialogues(now)
            lease = self._owned(token, worker, allowed, now)
            self._sync_history(lease["peer"])
            records = self.db.execute("""SELECT * FROM dialogue_history WHERE peer=? AND seq<?
                ORDER BY seq DESC LIMIT ?""", (lease["peer"], before or 2**63 - 1, limit + 1)).fetchall()
            checkpoint = None
            if lease["checkpoint"]:
                body = self._unseal(agent, lease["checkpoint"])
                if not isinstance(body, dict) or body.get("conversation_id") != lease["conversation_id"]:
                    raise InboxConflict("checkpoint conversation mismatch")
                checkpoint = body.get("text")
                _text(checkpoint, 8192)
            items, size = [], 0
            for record in records[:limit]:
                if record["direction"] == "in":
                    row = self.db.execute("SELECT * FROM messages WHERE seq=? AND sender=?", (record["ref"], lease["peer"])).fetchone()
                    decoded = agent._decode_incoming(Event.model_validate_json(row["envelope"]))
                    if (decoded is None or decoded["from_pubkey"] != lease["peer"]
                            or decoded["event"].id != row["inner_id"]):
                        raise InboxConflict("stored incoming history failed verification")
                    text = decoded["content"]
                    item = {"inbox_seq": row["seq"], "state": row["state"], "inner_id": row["inner_id"]}
                else:
                    row = self.db.execute("SELECT * FROM dialogue_outbox WHERE seq=? AND peer=?", (record["ref"], lease["peer"])).fetchone()
                    text = self._outgoing_inner(agent, row, lease["conversation_id"]).content
                    item = self._receipt(row)
                _text(text, 32768)
                size += len(text.encode("utf-8"))
                if size > 65536:
                    break
                if record["direction"] == "in" and row["state"] == "pending":
                    self.db.execute("""UPDATE messages SET state='processing',lease_token=?,lease_until=?
                        WHERE seq=? AND state='pending'""", (token, lease["lease_until"], row["seq"]))
                    item["state"] = "processing"
                items.append({**item, "history_seq": record["seq"], "direction": record["direction"], "content": text})
            return {"conversation_id": lease["conversation_id"], "peer": lease["peer"],
                    "checkpoint": checkpoint, "items": items, "more": len(records) > len(items),
                    "next_before": items[-1]["history_seq"] if items else None}

    def finish_incoming(self, token, worker, allowed, seq, status, *, reconciled=False, now=None):
        if type(seq) is not int or seq <= 0 or status not in ("processed", "failed") or type(reconciled) is not bool:
            raise InboxError("invalid dialogue completion")
        with self._transaction():
            lease = self._owned(token, worker, allowed, _clock(now))
            row = self.db.execute("SELECT * FROM messages WHERE seq=? AND sender=?", (seq, lease["peer"])).fetchone()
            if row is None or row["state"] not in ("processing", "pending", "unknown"):
                raise InboxConflict("incoming message is not unfinished in this dialogue")
            if row["state"] == "unknown" and not reconciled:
                raise InboxConflict("unknown incoming work needs explicit reconciliation")
            self.db.execute("UPDATE messages SET state=?,lease_token=NULL WHERE seq=?", (status, seq))
        return {"state": status, "seq": seq, "network_ack_sent": False}

    @staticmethod
    def _receipt(row):
        return {key: row[key] for key in ("operation_id", "state", "inner_id", "outer_id", "delivery_id")}

    def prepare_send(self, agent, token, worker, allowed, operation_id, text, *, now=None):
        self._agent(agent)
        _name(operation_id)
        _text(text, 32768)
        now = _clock(now)
        with self._transaction():
            lease = self._owned(token, worker, allowed, now)
            old = self.db.execute("SELECT * FROM dialogue_outbox WHERE peer=? AND operation_id=?", (lease["peer"], operation_id)).fetchone()
            if old is not None:
                if old["state"] == "abandoned":
                    raise InboxConflict(
                        "operation id was abandoned and cannot be reused; prepare a new "
                        "operation id so history keeps both the abandoned and the new work")
                if self._outgoing_inner(agent, old, lease["conversation_id"]).content != text:
                    raise InboxConflict("operation id already binds different content")
                return self._receipt(old)
            if self.db.execute("SELECT 1 FROM dialogue_outbox WHERE peer=? AND state IN ('dispatching','unknown') LIMIT 1", (lease["peer"],)).fetchone():
                raise InboxConflict("uncertain outgoing work requires reconciliation before another send")
            if self.db.execute("SELECT COUNT(*) FROM dialogue_outbox").fetchone()[0] >= self.max_items:
                raise InboxFull("dialogue outbox capacity reached")
            inner, outer, delivery = agent.prepare_private_message(lease["peer"], text)
            body = self._seal(agent, {"conversation_id": lease["conversation_id"], "operation_id": operation_id,
                                      "outer_id": outer.id, "relay": _relay_fingerprint(agent), "inner": inner.model_dump()})
            self._sync_history(lease["peer"])
            cursor = self.db.execute("""INSERT INTO dialogue_outbox
                (peer,operation_id,inner_id,outer_id,delivery_id,envelope,local_body,relay,state,created)
                VALUES (?,?,?,?,?,?,?,?, 'prepared',?)""", (lease["peer"], operation_id, inner.id, outer.id,
                    delivery, outer.model_dump_json(), body, _relay_fingerprint(agent), now))
            self.db.execute("INSERT INTO dialogue_history(peer,direction,ref) VALUES (?,'out',?)", (lease["peer"], cursor.lastrowid))
            return self._receipt(self.db.execute("SELECT * FROM dialogue_outbox WHERE seq=?", (cursor.lastrowid,)).fetchone())

    def abandon(self, agent, token, worker, allowed, operation_id, *, now=None):
        """Terminally close a PREPARED message that may no longer be sent.

        Why this is needed: relay-set comparison fails closed, so a message prepared
        for one operator set is not sent through another. That is correct because an
        added relay sees metadata the owner did not agree to disclose. Refusal with
        no exit was only half a solution, however: the prepared row remained in the
        journal forever, `work()` perpetually reported unfinished work, and restoring
        the old set could send the message at an arbitrary later time. A reviewer
        found this behavior in a live store.

        Allowed and forbidden behavior:

        * Only `prepared` may be abandoned. `dispatching`, `unknown`, and accepted
          outcomes MUST NOT be closed this way: the relay may already have the
          message, so “leave it” would misrepresent uncertainty as resolution. Those
          states require reconciliation.
        * The same lease token and worker used for sending are required. Permission
          to close someone else's preparation is permission to lose their message.
        * Content is confirmed by decrypting it with the local key and matching the
          conversation. This closes the expected local record, not a row by number.
        * The relay set is NOT compared; its mismatch is what leads here.
        * History is retained. The row remains in `abandoned` state, and neither the
          envelope nor its binding is rewritten, which would falsify the past.

        An abandoned message can never be sent: `dispatch` sends only from
        `prepared`.
        """
        self._agent(agent)
        _name(operation_id)
        now = _clock(now)
        with self._transaction():
            lease = self._owned(token, worker, allowed, now)
            row = self.db.execute(
                "SELECT * FROM dialogue_outbox WHERE peer=? AND operation_id=?",
                (lease["peer"], operation_id)).fetchone()
            if row is None:
                raise InboxConflict("outgoing operation is missing")
            if row["state"] != "prepared":
                raise InboxConflict(
                    "only a prepared operation may be abandoned; dispatching, unknown "
                    "and accepted outcomes need reconciliation, not disposal")
            self._outgoing_inner(agent, row, lease["conversation_id"])
            self.db.execute("UPDATE dialogue_outbox SET state='abandoned' WHERE seq=?",
                            (row["seq"],))
            return self._receipt(self.db.execute(
                "SELECT * FROM dialogue_outbox WHERE seq=?", (row["seq"],)).fetchone())

    def _outbox(self, agent, lease, operation_id):
        _name(operation_id)
        row = self.db.execute("SELECT * FROM dialogue_outbox WHERE peer=? AND operation_id=?", (lease["peer"], operation_id)).fetchone()
        if row is None:
            raise InboxConflict("outgoing operation is missing")
        if not _same_relay_set(row["relay"], agent):
            raise InboxConflict(_relay_set_conflict(row["relay"], row["state"]))
        self._outgoing_inner(agent, row, lease["conversation_id"])
        outer = Event.model_validate_json(row["envelope"])
        if not outer.verify() or outer.id != row["outer_id"] or outer.tag_value("p") != lease["peer"]:
            raise InboxConflict("stored outgoing envelope failed verification")
        return row, outer

    async def dispatch(self, agent, token, worker, allowed, operation_id, *, now=None):
        self._agent(agent)
        with self._transaction():
            lease = self._owned(token, worker, allowed, _clock(now))
            row, outer = self._outbox(agent, lease, operation_id)
            if row["state"] != "prepared":
                return self._receipt(row)
            if self.db.execute("SELECT 1 FROM dialogue_outbox WHERE peer=? AND state IN ('dispatching','unknown') LIMIT 1", (lease["peer"],)).fetchone():
                raise InboxConflict("another outgoing operation is uncertain")
            self.db.execute("UPDATE dialogue_outbox SET state='dispatching' WHERE seq=?", (row["seq"],))
        try:
            await agent.relay.publish(outer, replay_on_reconnect=False)
            with self._transaction():
                self._owned(token, worker, allowed, _clock(now))
                self.db.execute("UPDATE dialogue_outbox SET state='relay_accepted' WHERE seq=?", (row["seq"],))
        except BaseException:
            with self._transaction():
                self.db.execute("UPDATE dialogue_outbox SET state='unknown' WHERE seq=? AND state='dispatching'", (row["seq"],))
            raise
        return self._receipt(self.db.execute("SELECT * FROM dialogue_outbox WHERE seq=?", (row["seq"],)).fetchone())

    async def reconcile(self, agent, token, worker, allowed, operation_id, *, now=None):
        self._agent(agent)
        with self._transaction():
            lease = self._owned(token, worker, allowed, _clock(now))
            row, outer = self._outbox(agent, lease, operation_id)
            if row["state"] not in ("unknown", "dispatching"):
                return self._receipt(row)
        result = await agent.relay.query_bounded({"ids": [outer.id], "kinds": [outer.kind], "limit": 1}, max_events=2)
        observed = any(ev.id == outer.id and ev.verify() for ev in result.events)
        with self._transaction():
            self._owned(token, worker, allowed, _clock(now))
            if observed:
                self.db.execute("UPDATE dialogue_outbox SET state='relay_observed' WHERE seq=?", (row["seq"],))
            return self._receipt(self.db.execute("SELECT * FROM dialogue_outbox WHERE seq=?", (row["seq"],)).fetchone())
