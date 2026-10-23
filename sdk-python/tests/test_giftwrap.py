"""Metadata privacy (NIP-59 gift wrap) and reveal tests."""
import asyncio
import json
import time

import pytest

from a4a import giftwrap, types
from a4a.agent import Agent
from a4a.event import Event
from a4a.keys import Keys
from tests.fake_relay import FakeRelay


def _inner(sender: Keys, to: str, content: str) -> Event:
    ev = Event(kind=types.KIND_PRIVATE_RUMOR,
               tags=[["p", to], ["d", "deliv1"]], content=content)
    return ev.sign(sender)


# --- F6: envelope replay ----------------------------------------------------

async def test_replayed_giftwrap_is_delivered_once():
    """Deliver the same rumor only once when wrapped twice.

    Each wrap uses a fresh ephemeral key and therefore produces a distinct envelope.
    A duplicate is a real cost for agents that spend money on every inbound message
    (audit F6).
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            inner = _inner(alice.keys, bob.pubkey, "please pay the invoice")
            for _ in range(2):
                await alice.relay.publish(
                    giftwrap.wrap(inner, bob.pubkey, alice.keys))
            inbox = await bob.read_private_messages()
            assert len(inbox) == 1
            assert inbox[0]["content"] == "please pay the invoice"


# --- Cryptographic wrap/unwrap ---------------------------------------------

@pytest.mark.parametrize("now", [0, 1, 2, 172799, 172800, 200000])
def test_wrap_jitter_never_emits_negative_wire_timestamp(now, monkeypatch):
    monkeypatch.setattr(giftwrap.secrets, "randbelow", lambda upper: upper - 1)
    sender, recipient = Keys(), Keys()
    inner = _inner(sender, recipient.pubkey_hex, "epoch boundary")
    outer = giftwrap.wrap(inner, recipient.pubkey_hex, sender, now=now)
    seal = Event(**json.loads(giftwrap.nip44.decrypt(
        outer.content, recipient.privkey_hex, outer.pubkey)))
    assert 0 <= outer.created_at <= now
    assert 0 <= seal.created_at <= now
    assert outer.verify_protocol() and seal.verify_protocol()
    assert giftwrap.unwrap(outer, recipient).id == inner.id

def test_wrap_hides_sender_and_content():
    sender, recipient = Keys(), Keys()
    inner = _inner(sender, recipient.pubkey_hex, "trade secret")
    gw = giftwrap.wrap(inner, recipient.pubkey_hex, sender)

    assert gw.kind == giftwrap.KIND_GIFT_WRAP           # 1059
    assert gw.pubkey != sender.pubkey_hex               # Author is ephemeral, not sender.
    assert gw.tag_value("p") == recipient.pubkey_hex    # Recipient must remain visible for delivery.
    assert "secret" not in gw.content                   # Content is encrypted.
    assert sender.pubkey_hex not in gw.content          # Sender is not exposed in the envelope.


def test_unwrap_roundtrip_and_verifies_sender():
    sender, recipient = Keys(), Keys()
    inner = _inner(sender, recipient.pubkey_hex, "secret")
    gw = giftwrap.wrap(inner, recipient.pubkey_hex, sender)

    got = giftwrap.unwrap(gw, recipient)
    assert got.pubkey == sender.pubkey_hex   # Inner author is the sender.
    assert got.content == "secret"
    assert got.verify()                      # Valid sender signature makes reveal verifiable.


def test_unwrap_stranger_fails():
    sender, recipient, stranger = Keys(), Keys(), Keys()
    gw = giftwrap.wrap(_inner(sender, recipient.pubkey_hex, "x"), recipient.pubkey_hex, sender)
    with pytest.raises(giftwrap.GiftWrapError):
        giftwrap.unwrap(gw, stranger)


def test_unwrap_rejects_forged_inner_author():
    # An attacker replaces the inner event with one signed by ANOTHER key.
    sender, recipient, forger = Keys(), Keys(), Keys()
    forged_inner = _inner(forger, recipient.pubkey_hex, "forgery")
    # Build a valid sender seal that contains someone else's inner event.
    seal_content = giftwrap.nip44.encrypt(
        json.dumps(forged_inner.model_dump(), ensure_ascii=False),
        sender.privkey_hex, recipient.pubkey_hex)
    seal = Event(kind=giftwrap.KIND_SEAL, content=seal_content).sign(sender)
    eph = Keys()
    gw_content = giftwrap.nip44.encrypt(
        json.dumps(seal.model_dump(), ensure_ascii=False), eph.privkey_hex, recipient.pubkey_hex)
    gw = Event(kind=giftwrap.KIND_GIFT_WRAP, tags=[["p", recipient.pubkey_hex]],
               content=gw_content).sign(eph)
    with pytest.raises(giftwrap.GiftWrapError):   # inner.pubkey != seal.pubkey
        giftwrap.unwrap(gw, recipient)


# --- Relay integration: private send/read/reveal ----------------------------

async def test_wrapped_send_hides_metadata_recipient_reads():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob, \
                Agent([relay.url]) as mallory:
            secret = "call summary: price 1,000,000"
            await alice.send_private_message(bob.pubkey, secret, wrap=True)

            # Relay stores an envelope that reveals NEITHER Alice nor the content.
            stored = [e for e in relay.events if e["kind"] == giftwrap.KIND_GIFT_WRAP]
            assert stored and stored[0]["pubkey"] != alice.pubkey   # Ephemeral author.
            assert "1,000,000" not in stored[0]["content"]

            inbox = await bob.read_private_messages()
            assert len(inbox) == 1
            assert inbox[0]["wrapped"] is True
            assert inbox[0]["from_pubkey"] == alice.pubkey
            assert inbox[0]["content"] == secret

            assert await mallory.read_private_messages() == []       # Nothing for a non-recipient.


async def test_reveal_publishes_verifiable_plaintext():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            await alice.send_private_message(bob.pubkey, "I promised delivery by Friday", wrap=True)
            msg = (await bob.read_private_messages())[0]

            await bob.reveal(msg)   # Reveal for dispute resolution.

            revealed = await bob.relay.query({"kinds": [types.KIND_PRIVATE_RUMOR]})
            assert any(e.content == "I promised delivery by Friday"
                       and e.pubkey == alice.pubkey and e.verify() for e in revealed)


async def test_private_deliver_with_ack_fully_wrapped():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            async def recv_and_ack():
                for _ in range(40):
                    inbox = await bob.read_private_messages()
                    if inbox:
                        assert inbox[0]["wrapped"] is True
                        await bob.acknowledge(inbox[0], status="processed")  # Automatically wrapped.
                        return
                    await asyncio.sleep(0.05)

            task = asyncio.create_task(recv_and_ack())
            result = await alice.deliver_with_ack(
                bob.pubkey, "private summary", private=True,
                retries=5, ack_timeout=2.0, poll_interval=0.05)
            await task

            assert result["status"] == "acknowledged"
            assert result["ack_status"] == "processed"
            # Privacy: relay has NO public 31033/31034 events, only gift wraps.
            kinds = {e["kind"] for e in relay.events}
            assert types.KIND_PRIVATE_MESSAGE not in kinds
            assert types.KIND_ACK_RECEIPT not in kinds
            assert giftwrap.KIND_GIFT_WRAP in kinds


# --- Inbound read window (`since`) -----------------------------------------

async def test_read_private_messages_window_keeps_fuzzed_giftwraps(monkeypatch):
    """Expand the read window to account for gift-wrap timestamp jitter.

    Windowed reads prevent every poll on a public address from downloading complete
    history. Gift-wrap `created_at` is intentionally shifted up to two days into the
    past, so naive `since=now-one-hour` would lose newly wrapped messages. The SDK
    must widen the window by the jitter range.
    """
    now = int(time.time())
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            inner = _inner(alice.keys, bob.pubkey, "fresh despite timestamp jitter")
            # Force worst-case jitter deterministically. The envelope cannot be
            # re-signed with another key because content uses the ORIGINAL ephemeral key.
            monkeypatch.setattr(giftwrap, "_jitter",
                                lambda n: n - giftwrap._JITTER_SECONDS + 60)
            await alice.relay.publish(giftwrap.wrap(inner, bob.pubkey, alice.keys, now=now))

            recent = await bob.read_private_messages(since=now - 3600)
            assert [m["content"] for m in recent] == ["fresh despite timestamp jitter"]


async def test_read_private_messages_window_drops_old():
    now = int(time.time())
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            old = _inner(alice.keys, bob.pubkey, "ancient message")
            gw = giftwrap.wrap(old, bob.pubkey, alice.keys, now=now - 30 * 24 * 3600)
            await alice.relay.publish(gw)
            assert await bob.read_private_messages(since=now - 3600) == []
            assert len(await bob.read_private_messages()) == 1   # Visible without a window.


# --- Streaming reads instead of polling ------------------------------------

async def test_subscribe_private_messages_yields_wrapped_and_plain():
    """Stream the same wrapped and plaintext messages as batch reads.

    Polling a relay every 30 seconds costs four times more than the messages themselves
    in the 2026-08-28 model. Subscription removes that overhead but must preserve the
    same behavior for both ordinary private events and unwrapped envelopes.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            got = []

            async def reader():
                async for msg in bob.subscribe_private_messages():
                    got.append(msg)
                    if len(got) == 2:
                        return

            task = asyncio.create_task(reader())
            await asyncio.sleep(0.2)
            # Plaintext mode is explicit: since 2026-08-29 private messages are
            # wrapped by default. The test still requires BOTH event forms.
            await alice.send_private_message(bob.pubkey, "plain", wrap=False)
            await alice.send_private_message(bob.pubkey, "wrapped", wrap=True)
            await asyncio.wait_for(task, timeout=5)

            by_content = {m["content"]: m for m in got}
            assert set(by_content) == {"plain", "wrapped"}
            assert by_content["plain"]["wrapped"] is False
            assert by_content["wrapped"]["wrapped"] is True
            assert all(m["from_pubkey"] == alice.pubkey for m in got)


async def test_subscribe_connection_requests_verifies_addressee():
    """Verify locally that a connection request is addressed to this subscriber."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as sender:
            got = []

            async def reader():
                async for req in project.subscribe_connection_requests():
                    got.append(req)
                    return

            task = asyncio.create_task(reader())
            await asyncio.sleep(0.2)
            await sender.request_connection(project.pubkey, "hello")
            await asyncio.wait_for(task, timeout=5)
            assert got[0]["from_pubkey"] == sender.pubkey
            assert got[0]["intro"] == "hello"


async def test_connection_request_addressed_to_someone_else_is_dropped():
    """Drop a request that an untrusted relay sends to the WRONG recipient.

    The neighboring test sends only a CORRECTLY addressed request through an honest
    relay. It stays green even if addressee validation is REMOVED because every event
    already targets us. An external reviewer identified it as the fifth vacuous test
    in one day (TEST-SUB-001).

    The threat is real: a subscription filter is only a REQUEST to an untrusted relay.
    It may send someone else's request, which becomes "ours" without local validation.

    The relay therefore ignores filters deliberately. An honest relay would discard
    the hostile event before it reached the defense, making the test vacuous again.
    """
    async with FakeRelay(honour_filters=False) as relay:
        async with Agent([relay.url]) as project, Agent([relay.url]) as sender,                    Agent([relay.url]) as stranger:
            got = []

            async def reader():
                async for req in project.subscribe_connection_requests():
                    got.append(req)
                    if len(got) >= 1:
                        return

            task = asyncio.create_task(reader())
            await asyncio.sleep(0.2)
            # Send the FOREIGN request first. It targets a stranger, but the relay
            # still delivers it to us.
            await sender.request_connection(stranger.pubkey, "not for you")
            await asyncio.sleep(0.4)
            assert not got, "request addressed to someone else was accepted as ours"

            # POSITIVE control on the same stream: our own request must arrive.
            # Otherwise "accept nothing" is indistinguishable from valid filtering.
            await sender.request_connection(project.pubkey, "this is for you")
            await asyncio.wait_for(task, timeout=5)
            assert len(got) == 1 and got[0]["intro"] == "this is for you"


# --- Private-message lifetime policy ---------------------------------------

async def test_private_messages_carry_expiration_by_default():
    """Give private messages a default NIP-40 expiration.

    A private message is single-use: after delivery it is no longer needed. Keeping
    it forever pays storage for content nobody will read twice. The relay removes
    expired events itself.
    """
    now = int(time.time())
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            await alice.send_private_message(bob.pubkey, "text")
            await alice.send_private_message(bob.pubkey, "wrapped", wrap=True)
            stored = await bob.relay.query({"#p": [bob.pubkey]})
            assert stored, "events were not stored on the relay"
            for ev in stored:
                exp = ev.tag_value("expiration")
                assert exp is not None, f"kind {ev.kind} has no expiration"
                assert int(exp) > now


async def test_public_events_have_no_expiration():
    """Keep small, long-lived public profiles, intents, and trust events unexpired."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a:
            await a.publish_profile(types.AgentProfile(
                capabilities=["x"], category="other"))
            await a.publish_trust("f" * 64, 0.5)
            for ev in await a.relay.query({"authors": [a.pubkey]}):
                assert ev.tag_value("expiration") is None, f"kind {ev.kind} has expiration"


async def test_expiration_can_be_disabled_explicitly():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            # Expiration belongs to the ENVELOPE stored on the relay. Since the
            # default changed, looking for it on plaintext kind 31033 is meaningless.
            await alice.send_private_message(bob.pubkey, "forever", expires_in=0)
            [ev] = await bob.relay.query({"kinds": [giftwrap.KIND_GIFT_WRAP]})
            assert ev.tag_value("expiration") is None


async def test_subscription_respects_window():
    """Apply the read window to subscriptions as well as polling.

    On REQ a relay returns ALL matching history before the live stream. Without
    `since`, every startup and reconnect downloads everything ever received, losing
    the savings from windowed reads in the main path.
    """
    now = int(time.time())
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            old = _inner(alice.keys, bob.pubkey, "ancient")
            await alice.relay.publish(
                giftwrap.wrap(old, bob.pubkey, alice.keys, now=now - 60 * 86400))
            got = []

            async def reader():
                async for msg in bob.subscribe_private_messages(since=now - 3600):
                    got.append(msg)

            task = asyncio.create_task(reader())
            await asyncio.sleep(0.3)
            await alice.send_private_message(bob.pubkey, "fresh", wrap=True)
            for _ in range(40):
                await asyncio.sleep(0.05)
                if got:
                    break
            task.cancel()
            assert [m["content"] for m in got] == ["fresh"], "subscription returned old history"
