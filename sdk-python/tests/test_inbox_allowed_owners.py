"""A live owner mandate admits an otherwise unknown agent without widening peers."""

import time

import pytest

from a4a import Agent, Keys, giftwrap, types
from a4a.delegation import create_delegation, create_revocation
from a4a.event import Event
from a4a.inbox import InboxAuthorizationUnavailable, InboxStore
from a4a.inbox_receiver import InboxReceiver, authorized_sender_keys
from a4a.relay import RelayError
from tests.fake_relay import FakeRelay


def _letter(sender, recipient):
    inner = Event(kind=types.KIND_PRIVATE_RUMOR,
                  tags=[["p", recipient.pubkey_hex], ["d", "owner-letter"]],
                  content="from an organization agent").sign(sender)
    return giftwrap.wrap(inner, recipient.pubkey_hex, sender)


class OnePage:
    def __init__(self, event):
        self.event = event

    async def page(self, cursor):
        return [(100, self.event)] if cursor == (0, "") else []


async def test_owner_agent_is_stored_then_revocation_blocks_unleased_work(tmp_path):
    owner, sender, recipient = Keys(), Keys(), Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys=sender) as publisher:
            mandate = create_delegation(owner, sender.pubkey_hex, "Sales", int(time.time()) + 3600)
            await publisher.relay.publish(mandate)
        inbox_agent = Agent([relay.url], keys=recipient)
        with InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "worker") as store:
            receiver = InboxReceiver(
                inbox_agent, store, lambda: frozenset(),
                allowed_owners=lambda: frozenset({owner.pubkey_hex}),
                start_after=0, history=OnePage(_letter(sender, recipient)))
            assert await receiver.sync_once() == 1
            assert store.pending_sender_keys() == {sender.pubkey_hex}
            allowed = await authorized_sender_keys(
                inbox_agent, frozenset(), {owner.pubkey_hex}, store.pending_sender_keys())
            assert allowed == {sender.pubkey_hex}

            async with Agent([relay.url], keys=sender) as publisher:
                await publisher.relay.publish(create_revocation(owner, mandate))
            allowed = await authorized_sender_keys(
                inbox_agent, frozenset(), {owner.pubkey_hex}, store.pending_sender_keys())
            assert allowed == set()
            assert store.claim(inbox_agent, "worker", allowed) is None
            assert store.status()["blocked"] == 1


async def test_foreign_owner_does_not_admit_sender_or_advance_as_work(tmp_path):
    owner, foreign, sender, recipient = Keys(), Keys(), Keys(), Keys()
    async with FakeRelay() as relay:
        async with Agent([relay.url], keys=sender) as publisher:
            await publisher.relay.publish(create_delegation(
                foreign, sender.pubkey_hex, "Agent", int(time.time()) + 3600))
        inbox_agent = Agent([relay.url], keys=recipient)
        with InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "worker") as store:
            receiver = InboxReceiver(
                inbox_agent, store, lambda: frozenset(),
                allowed_owners=lambda: frozenset({owner.pubkey_hex}),
                start_after=0, history=OnePage(_letter(sender, recipient)))
            assert await receiver.sync_once() == 0
            assert store.cursor(relay.url)[0] == 100
            assert store.status()["total"] == 0


async def test_owner_lookup_outage_keeps_cursor_for_retry(tmp_path, monkeypatch):
    owner, sender, recipient = Keys(), Keys(), Keys()
    async with FakeRelay() as relay:
        inbox_agent = Agent([relay.url], keys=recipient)

        async def unavailable(*_args):
            raise RelayError("mandate lookup unavailable")

        monkeypatch.setattr(inbox_agent, "active_owner_mandates", unavailable)
        with InboxStore(tmp_path / "inbox", recipient.pubkey_hex, "worker") as store:
            receiver = InboxReceiver(
                inbox_agent, store, lambda: frozenset(),
                allowed_owners=lambda: frozenset({owner.pubkey_hex}),
                start_after=0, history=OnePage(_letter(sender, recipient)))
            with pytest.raises(InboxAuthorizationUnavailable, match="cursor and lease retained"):
                await receiver.sync_once()
            assert store.cursor(relay.url) == (0, "")
            assert store.status()["total"] == 0
            assert store.health()["state"] == "failed"
