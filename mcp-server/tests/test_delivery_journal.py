"""a4a_deliver keeps its outcome; a4a_delivery_status reads it and looks again.

The model sees `dead_letter` once. Without a journal the fact is gone with the session,
and when the recipient's receiver comes back and acknowledges, nobody ever notices.
"""
import asyncio
import re

import pytest
from a4a import Agent

from a4a_mcp import identity, inbox_runtime, outbox_runtime, server
from fake_relay import FakeRelay

SECRET = "MCP-OUTBOX-PLAINTEXT-MARKER"
CONVERSATION = "c" * 64


@pytest.fixture
def mcp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("A4A_MANDATE_AUTO", "1")
    monkeypatch.setattr(identity, "IDENTITY_DIR", tmp_path / ".a4a")
    monkeypatch.setattr(identity, "IDENTITY_FILE", tmp_path / ".a4a" / "identity.json")
    monkeypatch.setattr(server, "_DELIVER_RETRIES", 0)
    monkeypatch.setattr(server, "_DELIVER_ACK_TIMEOUT", 0.2)


async def test_dead_letter_is_journaled_and_a_late_ack_is_found(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("journal", [peer.pubkey], start_after=0)

            first = await server.a4a_deliver(peer.pubkey, SECRET, new_letter=True)
            assert "dead_letter" in first
            delivery_id = re.search(r"delivery_id=([0-9a-f]{32})", first).group(1)

            still = await server.a4a_delivery_status(delivery_id)
            assert "dead_letter" in still, "the journal lost the dead letter"

            messages = await peer.read_private_messages()
            await peer.acknowledge(messages[0], status="processed")

            later = await server.a4a_delivery_status(delivery_id)
    assert "acknowledged" in later and "late" in later, \
        "the recipient's late ACK stayed invisible to the sender"
    assert "processed" in later


async def test_deliver_passes_private_conversation_to_recipient(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("journal", [peer.pubkey], start_after=0)

            outcome = await server.a4a_deliver(peer.pubkey, SECRET, CONVERSATION, new_letter=True)
            assert "dead_letter" in outcome
            messages = await peer.read_private_messages()
            assert len(messages) == 1
            assert messages[0]["conversation_id"] == CONVERSATION
            assert CONVERSATION not in str(relay.events)


async def test_status_of_unknown_delivery_is_not_success(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        identity.load_or_create_identity()
        out = await server.a4a_delivery_status("0" * 32)
    assert "acknowledged" not in out and "no journal record" in out.lower()


async def test_owner_listing_exposes_no_envelope(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("journal", [peer.pubkey], start_after=0)
            await server.a4a_deliver(peer.pubkey, SECRET, new_letter=True)
    rows = outbox_runtime.list_records()
    assert len(rows) == 1 and rows[0]["state"] == "dead_letter"
    assert "envelope" not in rows[0] and SECRET not in str(rows)


async def test_receiver_tick_heals_a_dead_letter_by_itself(mcp_home, monkeypatch):
    """The owner's rule: no agent should have to remember outbox-recheck."""
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("journal", [peer.pubkey], start_after=0)
            first = await server.a4a_deliver(peer.pubkey, SECRET, new_letter=True)
            delivery_id = re.search(r"delivery_id=([0-9a-f]{32})", first).group(1)
            messages = await peer.read_private_messages()
            await peer.acknowledge(messages[0], status="processed")
            created = outbox_runtime.get(delivery_id)["created"]
            agent = server._make_agent()
            result = await outbox_runtime.recheck_due_on(agent, now=created + 61)
    assert result["acknowledged"] == 1
    record = outbox_runtime.get(delivery_id)
    assert record["state"] == "acknowledged" and record["late"] is True


async def test_a_failing_recheck_never_stops_the_receiver_tick(mcp_home, monkeypatch):
    """Receiving mail matters more than healing old sends: errors are logged, not raised."""
    async def broken(agent, *, now=None):
        raise RuntimeError("journal unavailable")
    monkeypatch.setattr(outbox_runtime, "recheck_due_on", broken)
    monkeypatch.setattr(inbox_runtime, "_last_outbox_recheck", 0.0)
    await inbox_runtime._recheck_sent_deliveries(object())


async def test_cli_deliver_sends_a_journaled_letter(mcp_home, monkeypatch, capsys, tmp_path):
    """Project sessions without A4A MCP tools send new letters with one CLI command."""
    from a4a_mcp.__main__ import _inbox_admin
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("journal", [peer.pubkey], start_after=0)
            text = tmp_path / "reply.txt"
            text.write_text("status: all good", encoding="utf-8")
            with pytest.raises(SystemExit) as sent_unconfirmed:   # the test peer does not ACK
                await asyncio.to_thread(
                    _inbox_admin, ["deliver", "--new-letter", "--to", peer.pubkey, "--text-file", str(text),
                                   "--conversation-id", CONVERSATION])
            received = await peer.read_private_messages()
    assert sent_unconfirmed.value.code == 3, "sent without ACK exits 3, not 0 and not 1"
    out = capsys.readouterr().out
    assert "delivery_id=" in out
    assert [m["content"] for m in received] == ["status: all good"]
    assert [m["conversation_id"] for m in received] == [CONVERSATION]
    assert len(outbox_runtime.list_records()) == 1, "the CLI delivery was not journaled"


async def test_cli_deliver_without_a_mandate_is_refused_not_sent(mcp_home, monkeypatch, capsys):
    """No mandate and no auto-issue: nothing is published, and the refusal says why.

    This is why provisioned project mailboxes get a mandate:
    without one they can receive and acknowledge, but not reply.
    """
    from a4a_mcp.__main__ import _inbox_admin
    monkeypatch.setenv("A4A_MANDATE_AUTO", "0")
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("journal", [peer.pubkey], start_after=0)
            with pytest.raises(SystemExit) as refused:
                await asyncio.to_thread(
                    _inbox_admin, ["deliver", "--new-letter", "--to", peer.pubkey, "--text", "no mandate"])
            received = await peer.read_private_messages()
    assert refused.value.code == 1, "a refusal must not exit 0 (a wrapper would count it as sent)"
    assert received == [], "a letter left without a mandate"
    out = capsys.readouterr().out
    assert "no valid owner delegation" in out
    # 24.09.2026: a mailbox's mandate existed only on a local relay; the refusal did not
    # say where it had looked, and the session believed for half a day it had none.
    assert relay.url in out, "the refusal must name the relays that were searched"


async def test_dead_letter_says_it_is_not_a_loss(mcp_home, monkeypatch):
    """A sender who reads dead_letter as "lost" resends; the reply must say otherwise.

    Owner-representative feedback, 2026-09-24: a dead_letter that turned into processed a
    minute later made the sender start resending and hunting for someone's failure.
    """
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("journal", [peer.pubkey], start_after=0)
            out = await server.a4a_deliver(peer.pubkey, "anyone there?", new_letter=True)
    assert "dead_letter" in out
    assert "not lost" in out.lower() and "do not resend" in out.lower()


async def test_cli_recheck_of_unknown_delivery_names_the_likely_cause(mcp_home, monkeypatch):
    """"no journal record" alone reads as a loss; say which journal was searched."""
    from a4a_mcp.__main__ import _inbox_admin
    identity.load_or_create_identity()
    outbox_runtime.open_store().close()  # a journal exists, the letter is not in it
    with pytest.raises(SystemExit) as exc:
        await asyncio.to_thread(
            _inbox_admin, ["outbox-recheck", "--delivery-id", "0" * 32])
    text = str(exc.value)
    assert "no journal record" in text.lower()
    assert "A4A_HOME" in text and str(identity.IDENTITY_DIR) in text


@pytest.mark.parametrize("given, hint", [
    ("e" * 64, "event_id"),     # a4a_deliver prints event_id right next to delivery_id
    ("eaa59696", "32"),         # a shortened id copied from a report
    ("E" * 32, "32"),
])
async def test_cli_recheck_rejects_what_is_not_a_delivery_id(mcp_home, given, hint):
    """A wrong id must not read as "no journal record": that looks like a lost letter.

    Owner-representative feedback, 2026-09-24: recheck said "no journal record" right
    after a successful send, while outbox-list showed the same delivery.
    """
    from a4a_mcp.__main__ import _inbox_admin
    identity.load_or_create_identity()
    with pytest.raises(SystemExit) as exc:
        await asyncio.to_thread(_inbox_admin, ["outbox-recheck", "--delivery-id", given])
    text = str(exc.value)
    assert "no journal record" not in text.lower() and hint in text


async def test_cli_recheck_right_after_cli_deliver_finds_the_record(mcp_home, monkeypatch,
                                                                    capsys):
    """The journal row is written before publishing, so no delay can hide it."""
    from a4a_mcp.__main__ import _inbox_admin
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("journal", [peer.pubkey], start_after=0)
            with pytest.raises(SystemExit):                       # 3: sent, the peer does not ACK
                await asyncio.to_thread(
                    _inbox_admin, ["deliver", "--new-letter", "--to", peer.pubkey, "--text", "ping"])
            sent = capsys.readouterr().out
            delivery_id = re.search(r"delivery_id=([0-9a-f]{32})", sent).group(1)
            await asyncio.to_thread(
                _inbox_admin, ["outbox-recheck", "--delivery-id", delivery_id])
    assert f'"delivery_id": "{delivery_id}"' in capsys.readouterr().out


@pytest.mark.parametrize("argv", [
    ["outbox-list"],
    ["outbox-recheck", "--delivery-id", "0" * 32],
    ["outbox-republish", "--delivery-id", "0" * 32],
])
async def test_cli_outbox_without_a_journal_says_so_and_creates_none(mcp_home, argv):
    """A shell without A4A_HOME must not grow a second, empty journal.

    2026-09-24, owner's pod: sends used the configured home, rechecks ran without it and
    opened ~/.a4a, creating an empty journal there. Every recheck of a real delivery
    then answered "no journal record", which the sender read as a delay or a loss.
    """
    from a4a_mcp.__main__ import _inbox_admin
    identity.load_or_create_identity()
    with pytest.raises(SystemExit) as exc:
        await asyncio.to_thread(_inbox_admin, argv)
    assert "no delivery journal" in str(exc.value) and "A4A_HOME" in str(exc.value)
    assert not (identity.IDENTITY_DIR / "outbox").exists()


async def test_status_without_a_journal_creates_none(mcp_home, monkeypatch):
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        identity.load_or_create_identity()
        out = await server.a4a_delivery_status("0" * 32)
    assert "no journal record" in out.lower()
    assert not (identity.IDENTITY_DIR / "outbox").exists()


async def test_listing_says_what_dead_letter_means_and_when_rechecks_end(mcp_home, monkeypatch):
    """26.09.2026, owner's representative: "dead_letter" reads as "the letter is lost" while
    it means "no acknowledgement yet"; and rechecks need a named end, not a silent forever."""
    import time
    from a4a import outbox
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("journal", [peer.pubkey], start_after=0)
            outcome = await server.a4a_deliver(peer.pubkey, SECRET, new_letter=True)
            assert "dead_letter" in outcome
    record = outbox_runtime.list_records()[0]
    assert record["state"] == "dead_letter"
    assert "no acknowledgement yet" in record["meaning"]
    assert "not lost" in record["meaning"]
    assert record["final"] is False
    assert record["rechecks_until"] == record["created"] + outbox.RECHECK_GIVE_UP
    summary = outbox_runtime.summary()
    assert summary["unconfirmed"] == 1 and summary["unconfirmed_final"] == 0
    assert abs(summary["as_of"] - time.time()) < 60


def test_stored_but_never_processed_is_its_own_state_and_becomes_final():
    """Representative, 26.09: "received" only means the recipient's mailbox stored the
    letter; its agent may never read it. Such letters must not hide from `final`."""
    from a4a import outbox
    now = 1_000_000.0
    record = {"delivery_id": "d", "recipient": "r" * 64, "private": True, "state": "acknowledged",
              "attempts": 1, "ack_status": "received", "late": False, "republished": 0,
              "created": now - outbox.RECHECK_GIVE_UP - 1, "updated": now, "ack_at": now,
              "ack_signed_at": now, "envelope_ids": ["e"]}
    shown = outbox_runtime._public(record, now)
    assert shown["final"] is True
    assert "stored" in shown["meaning"] and "not processed" in shown["meaning"]
    fresh = outbox_runtime._public({**record, "created": now - 60}, now)
    assert fresh["final"] is False and "not processed yet" in fresh["meaning"]
    done = outbox_runtime._public({**record, "ack_status": "processed"}, now)
    assert done["final"] is False and "processed" in done["meaning"]


async def test_an_unconfirmed_delivery_leads_with_sent_not_with_dead_letter(mcp_home, monkeypatch):
    """A project agent resent a letter on 'dead_letter' and made a duplicate: the name
    outweighed the text 'do not resend'. The result now LEADS with what happened."""
    async with FakeRelay() as relay:
        monkeypatch.setenv("A4A_RELAY", relay.url)
        async with Agent([relay.url]) as peer:
            identity.load_or_create_identity()
            inbox_runtime.configure("journal", [peer.pubkey], start_after=0)
            out = await server.a4a_deliver(peer.pubkey, "anyone there?", new_letter=True)
    assert out.startswith("Private delivery: SENT, NOT YET CONFIRMED - do not resend")
    assert "dead_letter" in out, "the journal state name stays visible for tools"


@pytest.mark.parametrize("error, code", [
    ("relay", 1),        # no relay accepted anything: nothing was sent
    ("crash", 4),        # anything else, e.g. after publishing or an unreadable journal: unknown
])
async def test_a_failing_delivery_exits_with_nothing_sent_only_when_that_is_known(
        mcp_home, monkeypatch, capsys, error, code):
    """Representative, 26.09: exit 1 must mean "nothing sent". The SDK raises after it recorded
    "interrupted" (sent, then stopped); a wrapper reading 1 would send the letter a second time.
    A relay refusal before any publication stays 1; every other failure is 4 - unknown, do not
    resend, look at outbox-list."""
    from a4a.relay import RelayError
    from a4a_mcp import server
    from a4a_mcp.__main__ import _inbox_admin

    async def failing(*args, **kwargs):
        raise RelayError("no relay accepted") if error == "relay" else RuntimeError("stopped after publish")
    monkeypatch.setattr(server, "_deliver_journaled", failing)
    identity.load_or_create_identity()
    with pytest.raises(SystemExit) as exc:
        await asyncio.to_thread(_inbox_admin, ["deliver", "--new-letter", "--to", "b" * 64, "--text", "x"])
    assert exc.value.code == code
    if code == 4:
        out = capsys.readouterr().out
        assert "UNKNOWN" in out and "do not resend" in out.lower() and "outbox-list" in out


def test_processed_is_not_read_as_a_reply():
    """Representative, 27.09 (letter 277): the sender sees "processed" in its journal and may take
    it for an answer. The meaning says what it is: read and taken into work - not a reply."""
    now = 1_000_000.0
    record = {"delivery_id": "d", "recipient": "r" * 64, "private": True, "state": "acknowledged",
              "attempts": 1, "ack_status": "processed", "late": False, "republished": 0,
              "created": now - 60, "updated": now, "ack_at": now, "ack_signed_at": now,
              "envelope_ids": ["e"]}
    meaning = outbox_runtime._public(record, now)["meaning"]
    assert "not a reply" in meaning and "a4a_reply" in meaning
