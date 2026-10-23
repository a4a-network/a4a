"""Metadata privacy must be the default rather than an opt-in option.

Content was always encrypted, but the PAIR (who contacted whom) was visible to every
relay reader, making the relationship graph public. Metadata protection through
gift-wrap (NIP-59) existed but required explicit `wrap=True`, so only callers already
aware of the problem enabled it. The MCP server exposed metadata unconditionally.

For a protocol centered on direct communication between personal agents, a public
relationship graph is consequential: it reveals who does business with whom even when
message content remains encrypted.
"""
from a4a import giftwrap, types
from a4a.agent import Agent
from tests.fake_relay import FakeRelay


async def test_private_message_hides_metadata_by_default():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            await a.send_private_message(b.pubkey, "secret")
        plain = [e for e in relay.events if e["kind"] == types.KIND_PRIVATE_MESSAGE]
        wraps = [e for e in relay.events if e["kind"] == giftwrap.KIND_GIFT_WRAP]
        assert not plain, "message metadata was exposed"
        assert wraps, "gift-wrap envelope was not published"
        assert wraps[0]["pubkey"] != a.pubkey, \
            "the sender authored the envelope directly, still exposing the relationship"


async def test_recipient_reads_the_default_message():
    """Positive control: the preceding privacy test must not pass on broken delivery."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            await a.send_private_message(b.pubkey, "secret")
            got = await b.read_private_messages()
    assert [m["content"] for m in got] == ["secret"]
    assert got[0]["wrapped"] is True
    assert got[0]["from_pubkey"] == a.pubkey, "recipient cannot identify the real sender"


async def test_plain_mode_remains_available_explicitly():
    """Retain explicit compatibility with implementations that only read 31033.

    Plain mode remains available, but is no longer the default.
    """
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            await a.send_private_message(b.pubkey, "plain", wrap=False)
            got = await b.read_private_messages()
        assert [e for e in relay.events if e["kind"] == types.KIND_PRIVATE_MESSAGE]
    assert [m["content"] for m in got] == ["plain"]
    assert got[0]["wrapped"] is False


async def test_file_reference_is_private_by_default_too():
    """A file reference is also private and must not expose the sender-recipient pair."""
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as a, Agent([relay.url]) as b:
            await a.send_file(b.pubkey, url="https://e.example/f", sha256="ab" * 32)
        assert not [e for e in relay.events if e["kind"] == types.KIND_PRIVATE_MESSAGE]
        assert [e for e in relay.events if e["kind"] == giftwrap.KIND_GIFT_WRAP]
