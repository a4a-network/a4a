"""A letter exists readably once; a truncated print must never destroy its tail.

26.09.2026: a project agent printed content[:3500] and closed letters 160-163; the tails
looked lost. The stored envelope is kept after processing, so the letter can be read again,
and every read says how long the text is, so a cut is visible to the reader at once.
"""
import datetime
import hashlib
import json

import pytest
from a4a import Agent
from a4a.event import Event

from a4a_mcp import __main__ as cli, identity, inbox_runtime, server
from fake_relay import FakeRelay

LONG = '\u043d\u0430\u0447\u0430\u043b\u043e ' + '\u0441\u0435\u0440\u0435\u0434\u0438\u043d\u0430 ' * 800 + '\u0425\u0412\u041e\u0421\u0422-\u041f\u0418\u0421\u042c\u041c\u0410'


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    monkeypatch.setattr(server, "_today", lambda: datetime.date(2026, 9, 26))


async def _store(relay, author, me, content):
    receipt = await author.send_private_message_receipt(me, content)
    outer = Event(**next(e for e in relay.events if e["id"] == receipt["outer_id"]))
    with inbox_runtime.open_runtime() as (policy, agent, store):
        assert store.accept(agent, outer, policy.allowed_peers) == "stored"
        return store.db.execute("SELECT seq FROM messages WHERE inner_id=?",
                                (receipt["inner_id"],)).fetchone()[0]


async def test_every_read_names_the_length_and_digest_of_the_text(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("full", [peer.pubkey], start_after=0)
            await _store(relay, peer, me, LONG)
            message = (await server.a4a_inbox_next())["message"]
    assert message["content_chars"] == len(LONG)
    assert message["content_sha256"] == hashlib.sha256(LONG.encode("utf-8")).hexdigest()


async def test_a_processed_letter_can_be_read_again_in_full(mcp_home, monkeypatch, tmp_path):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("full", [peer.pubkey], start_after=0)
            seq = await _store(relay, peer, me, LONG)
            claimed = (await server.a4a_inbox_next())["message"]
            inbox_runtime.complete(seq, claimed["lease_token"], "processed")
    out = tmp_path / "letter.txt"
    result = inbox_runtime.reread(seq, out)
    text = out.read_text(encoding="utf-8")
    assert '\u0425\u0412\u041e\u0421\u0422-\u041f\u0418\u0421\u042c\u041c\u0410' in text
    assert result["content_chars"] == len(LONG) and result["state"] == "processed"
    # 27.09 (letter 278): a re-read letter must carry its times too, or its stamps cannot be
    # checked afterwards against the signature.
    assert result["signed_at"] == claimed["signed_at"] and result["received_at"] == claimed["received_at"]


async def test_an_unread_letter_is_not_reread_around_the_lease(mcp_home, monkeypatch, tmp_path):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("full", [peer.pubkey], start_after=0)
            seq = await _store(relay, peer, me, LONG)
    with pytest.raises(inbox_runtime.InboxError, match="inbox-next"):
        inbox_runtime.reread(seq, tmp_path / "x.txt")


async def test_cli_inbox_next_can_put_the_text_in_a_file(mcp_home, monkeypatch, tmp_path, capsys):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("full", [peer.pubkey], start_after=0)
            await _store(relay, peer, me, LONG)
            out = tmp_path / "next.txt"
            import asyncio
            await asyncio.to_thread(cli._inbox_admin, ["inbox-next", "--content-file", str(out)])
    shown = json.loads(capsys.readouterr().out)["message"]
    assert "content" not in shown, "the text must not be printed where it can be cut"
    assert shown["content_file"] == str(out) and '\u0425\u0412\u041e\u0421\u0422-\u041f\u0418\u0421\u042c\u041c\u0410' in out.read_text(encoding="utf-8")
    assert shown["content_chars"] == len(LONG)


async def test_reconcile_processed_can_send_the_ack_the_sender_waits_for(mcp_home, monkeypatch):
    """26.09.2026: a letter was processed, its lease expired, and inbox-reconcile closed it
    as processed without any network ACK - the sender kept it "unconfirmed". With
    --send-ack the agent that knows it processed the letter tells the sender; default stays
    silent, because an expired lease alone proves nothing."""
    import time as clock
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            me = identity.load_or_create_identity().pubkey_hex
            inbox_runtime.configure("full", [peer.pubkey], start_after=0)
            seq = await _store(relay, peer, me, "question")
            claimed = (await server.a4a_inbox_next())["message"]
            with inbox_runtime.open_runtime() as (_, _agent, store):
                store.db.execute("UPDATE messages SET lease_until=? WHERE seq=?", (clock.time() - 1, seq))
            silent = await inbox_runtime.reconcile_authorized(seq, claimed["inner_id"], "processed")
            assert silent["network_ack_sent"] is False
            before = len(relay.events)
            told = await inbox_runtime.send_reconciled_ack(seq)
            published = relay.events[before:]
    assert told["network_ack_sent"] is True and told["status"] == "processed"
    assert [e for e in published if e["kind"] in (1059, 31034)], "no ACK reached the relay"


async def test_cli_reply_refusal_exits_nonzero_so_a_wrapper_cannot_count_it_as_sent(
        mcp_home, monkeypatch, capsys):
    """A project agent, 26.09: "no letter with number N ... nothing was sent" returned exit code 0, and
    the representative's wrapper would count the refusal as a sent letter. Exit codes:
    0 acknowledged, 3 sent but not yet acknowledged, 1 nothing sent."""
    import asyncio
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        identity.load_or_create_identity()
        inbox_runtime.configure("full", [], start_after=0)
        with pytest.raises(SystemExit) as refused:
            await asyncio.to_thread(cli._inbox_admin, ["reply", "--seq", "999", "--text", "x"])
    assert refused.value.code == 1
    assert "nothing was sent" in capsys.readouterr().out


def test_a_declared_length_is_compared_on_receipt():
    """Representative, 27.09 (letter 290): the length header is a label until someone compares it.
    The reader's side compares: N counts Unicode characters after the first line, as sent - no
    normalisation, the final newline included; a cut text shows declared_chars_match false."""
    from a4a_mcp.inbox_runtime import _measured
    text = 'hello\n\u043c\u0438\u0440\n'
    full = {"content": f"[\u043d\u0438\u0436\u0435 {len(text)} \u0437\u043d\u0430\u043a\u043e\u0432]\n{text}"}
    cut = {"content": f"[\u043d\u0438\u0436\u0435 {len(text)} \u0437\u043d\u0430\u043a\u043e\u0432]\n{text[:4]}"}
    plain = {"content": "no header"}
    assert _measured(full)["declared_chars"] == len(text) and full["declared_chars_match"] is True
    assert _measured(cut)["declared_chars_match"] is False
    assert "declared_chars" not in _measured(plain)
