"""a4a_reply binds an answer to the letter it answers; the tool enforces what agents forgot.

26.09.2026, owner's representative: "an agreement without enforcement does not work".
Replies went out through a4a_deliver and the link to the letter depended on whether the
agent quoted its delivery-id. The reply tool takes the ids from the mailbox row itself.
"""
import asyncio
import datetime
import re
import time

import pytest
from a4a import Agent
from a4a.event import Event

from a4a_mcp import identity, inbox_runtime, server
from fake_relay import FakeRelay

CONVERSATION = "c" * 64


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    monkeypatch.setattr(server, "_DELIVER_RETRIES", 0)
    monkeypatch.setattr(server, "_DELIVER_ACK_TIMEOUT", 0.2)
    monkeypatch.setattr(server, "_today", lambda: datetime.date(2026, 9, 26))


async def _store_letter(relay, author, me, content, *, delivery_id, conversation_id=None,
                        reply_to=None):
    """Put one real wrapped letter into this mailbox, as the receiver would."""
    receipt = await author.send_private_message_receipt(
        me, content, delivery_id=delivery_id, conversation_id=conversation_id,
        reply_to=reply_to)
    outer = Event(**next(e for e in relay.events if e["id"] == receipt["outer_id"]))
    with inbox_runtime.open_runtime() as (policy, agent, store):
        assert store.accept(agent, outer, policy.allowed_peers) == "stored"
        seq = store.db.execute("SELECT seq FROM messages WHERE inner_id=?",
                               (receipt["inner_id"],)).fetchone()[0]
    return receipt, seq


def _state(seq):
    with inbox_runtime.open_runtime() as (_, _agent, store):
        return store.db.execute("SELECT state, lease_token FROM messages WHERE seq=?",
                                (seq,)).fetchone()


async def test_reply_reaches_the_sender_bound_to_the_letter(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("reply", [peer.pubkey], start_after=0)
            letter, seq = await _store_letter(relay, peer, me, "question",
                                              delivery_id="ask-1",
                                              conversation_id=CONVERSATION)
            claimed = await server.a4a_inbox_next()
            assert claimed["message"]["seq"] == seq

            out = await server.a4a_reply(seq, "answer")
            received = await peer.read_private_messages()
    assert "delivery_id=" in out and ("acknowledged" in out or "dead_letter" in out)
    assert [m["content"] for m in received] == ["answer"]
    assert received[0]["reply_to"] == {"delivery_id": "ask-1", "inner_id": letter["inner_id"]}
    assert received[0]["conversation_id"] == CONVERSATION
    assert "ask-1" not in str(relay.events), "the reference leaked outside the wrap"


async def test_reply_to_an_unread_letter_is_refused(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("reply", [peer.pubkey], start_after=0)
            _, seq = await _store_letter(relay, peer, me, "question", delivery_id="ask-1")
            out = await server.a4a_reply(seq, "answer")
            received = await peer.read_private_messages()
    assert "inbox-next" in out
    assert received == [], "a reply left for a letter nobody has read"
    assert _state(seq)[0] == "pending", "refusing must not touch the letter"


async def test_reply_to_an_unknown_number_names_the_mailbox(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("reply", [peer.pubkey], start_after=0)
            out = await server.a4a_reply(999, "answer")
            received = await peer.read_private_messages()
    assert "999" in out and "A4A_HOME" in out
    assert received == []


async def test_reply_still_works_after_the_lease_expired(mcp_home, monkeypatch):
    """Condition (a): the lease may end while the agent is still writing the answer."""
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("reply", [peer.pubkey], start_after=0)
            letter, seq = await _store_letter(relay, peer, me, "question", delivery_id="ask-2")
            with inbox_runtime.open_runtime() as (policy, agent, store):
                store.claim(agent, policy.consumer, policy.allowed_peers,
                            now=int(time.time()) - 600, lease_seconds=1)
            await server.a4a_inbox_next()        # runs lease expiry
            assert _state(seq)[0] == "unknown"

            await server.a4a_reply(seq, "late answer")
            received = await peer.read_private_messages()
    assert [m["reply_to"] for m in received] == [
        {"delivery_id": "ask-2", "inner_id": letter["inner_id"]}]


async def test_reply_while_another_session_holds_the_lease(mcp_home, monkeypatch):
    """Condition (d): no lease is needed, and replying leaves the other lease alone."""
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("reply", [peer.pubkey], start_after=0)
            letter, seq = await _store_letter(relay, peer, me, "question", delivery_id="ask-3")
            with inbox_runtime.open_runtime() as (policy, agent, store):
                other = store.claim(agent, policy.consumer, policy.allowed_peers)
            await server.a4a_reply(seq, "answer")
            received = await peer.read_private_messages()
    assert [m["reply_to"]["inner_id"] for m in received] == [letter["inner_id"]]
    assert tuple(_state(seq)) == ("processing", other["lease_token"])


async def test_reply_to_a_forward_goes_to_the_original_sender(mcp_home, monkeypatch):
    """Condition (b): the copy's first line already names the original letter."""
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as original, Agent([relay.url]) as forwarder:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("reply", [original.pubkey, forwarder.pubkey],
                                    start_after=0)
            original_inner = "d" * 64
            copy = (f"A4A-FORWARD v1 original-id={original_inner} delivery-id=orig-7 "
                    f"from={original.pubkey} mailbox=off-duty received=2026-09-26T10:00+0300 "
                    "hops=1\nThis letter arrived in the off-duty mailbox.\n---\nquestion")
            copy_receipt, seq = await _store_letter(relay, forwarder, me, copy,
                                                    delivery_id="copy-1")
            await server.a4a_inbox_next()
            await server.a4a_reply(seq, "answer")
            to_original = await original.read_private_messages()
            to_forwarder = await forwarder.read_private_messages()
    # Representative, 26.09: the author must see that the answer's address came from a
    # forward line, and whose - inside the signed letter, not on the open envelope.
    assert [m["reply_to"] for m in to_original] == [
        {"delivery_id": "orig-7", "inner_id": original_inner,
         "routed_via": {"pubkey": forwarder.pubkey, "inner_id": copy_receipt["inner_id"]}}]
    assert forwarder.pubkey not in str([e.get("tags") for e in relay.events]),         "the forwarder leaked onto the open envelope"
    assert to_forwarder == [], "the answer went to the copy, not to the author"


async def test_reply_to_a_damaged_forward_is_refused(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as forwarder:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("reply", [forwarder.pubkey], start_after=0)
            _, seq = await _store_letter(relay, forwarder, me,
                                         "A4A-FORWARD v1 original-id=broken\nquestion",
                                         delivery_id="copy-2")
            await server.a4a_inbox_next()
            out = await server.a4a_reply(seq, "answer")
            received = await forwarder.read_private_messages()
    assert "A4A-FORWARD" in out and "new_letter" in out
    assert received == []


async def test_inbox_next_shows_what_a_letter_answers(mcp_home, monkeypatch):
    """Condition (c): an unbound reply is visible as reply_to=None, not as a missing field."""
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("reply", [peer.pubkey], start_after=0)
            await _store_letter(relay, peer, me, "bound", delivery_id="r-1",
                                reply_to=("mine-1", "a" * 64))
            await _store_letter(relay, peer, me, "unbound", delivery_id="r-2")
            first = (await server.a4a_inbox_next())["message"]
            second = (await server.a4a_inbox_next())["message"]
    assert first["reply_to"] == {"delivery_id": "mine-1", "inner_id": "a" * 64}
    assert "reply_to" in second and second["reply_to"] is None


async def test_cli_reply_sends_a_bound_journaled_letter(mcp_home, monkeypatch, capsys,
                                                        tmp_path):
    from a4a_mcp import outbox_runtime
    from a4a_mcp.__main__ import _inbox_admin
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("reply", [peer.pubkey], start_after=0)
            letter, seq = await _store_letter(relay, peer, me, "question", delivery_id="ask-9")
            await asyncio.to_thread(_inbox_admin, ["inbox-next"])
            text = tmp_path / "reply.txt"
            text.write_text("status: done", encoding="utf-8")
            with pytest.raises(SystemExit) as sent_unconfirmed:   # the test peer does not ACK
                await asyncio.to_thread(
                    _inbox_admin, ["reply", "--seq", str(seq), "--text-file", str(text)])
            received = await peer.read_private_messages()
    assert sent_unconfirmed.value.code == 3
    assert "delivery_id=" in capsys.readouterr().out
    assert [m["content"] for m in received] == ["status: done"]
    assert received[0]["reply_to"] == {"delivery_id": "ask-9", "inner_id": letter["inner_id"]}
    assert len(outbox_runtime.list_records()) == 1, "the CLI reply was not journaled"


async def test_deliver_is_unchanged_before_the_enforcement_date(mcp_home, monkeypatch):
    monkeypatch.setattr(server, "_today",
                        lambda: server.REPLY_ENFORCEMENT_DATE - datetime.timedelta(days=1))
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("reply", [peer.pubkey], start_after=0)
            out = await server.a4a_deliver(peer.pubkey, "plain letter")
            received = await peer.read_private_messages()
    assert "delivery_id=" in out
    assert [(m["content"], m["reply_to"]) for m in received] == [("plain letter", None)]


async def test_deliver_asks_for_intent_from_the_enforcement_date(mcp_home, monkeypatch,
                                                                  capsys):
    """Condition (c): the old path fails loudly instead of sending an unbound reply."""
    from a4a_mcp.__main__ import _inbox_admin
    monkeypatch.setattr(server, "_today", lambda: server.REPLY_ENFORCEMENT_DATE)
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("reply", [peer.pubkey], start_after=0)
            refused = await server.a4a_deliver(peer.pubkey, "is this a reply?")
            assert await peer.read_private_messages() == []
            sent = await server.a4a_deliver(peer.pubkey, "new topic", new_letter=True)
            with pytest.raises(SystemExit) as cli_refused:
                await asyncio.to_thread(
                    _inbox_admin, ["deliver", "--to", peer.pubkey, "--text", "cli refused"])
            with pytest.raises(SystemExit) as cli_sent:            # sent; the peer does not ACK
                await asyncio.to_thread(
                    _inbox_admin, ["deliver", "--to", peer.pubkey, "--text", "cli new",
                                   "--new-letter"])
            received = await peer.read_private_messages()
    assert (cli_refused.value.code, cli_sent.value.code) == (1, 3)
    assert refused == ("A4A: is this a reply? Use a4a_reply(seq) so it is bound to the "
                       "letter it answers. For a new letter pass new_letter=true.")
    assert "delivery_id=" in sent
    assert sorted(m["content"] for m in received) == ["cli new", "new topic"]
    assert "is this a reply?" in capsys.readouterr().out
