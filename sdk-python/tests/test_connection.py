"""Connection handshake tests (kind 31022): request, acceptance, reciprocity (section 2.4)."""
from a4a.agent import Agent
from a4a.types import ConnectionRequest, KIND_CONNECTION_REQUEST
from tests.fake_relay import FakeRelay


def test_connection_request_roundtrip():
    cr = ConnectionRequest(to_pubkey="b" * 64, intro="let's collaborate")
    ev = cr.to_event()
    assert ev.kind == KIND_CONNECTION_REQUEST
    assert ev.tag_value("p") == "b" * 64 and ev.tag_value("d") == "b" * 64
    assert ev.content == "let's collaborate"
    back = ConnectionRequest.from_event(ev)
    assert back.to_pubkey == "b" * 64 and back.intro == "let's collaborate"


async def test_connection_handshake_mutual():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as bob:
            await alice.request_connection(bob.pubkey, intro="proposing collaboration")

            # Bob sees the incoming request.
            reqs = await bob.get_connection_requests()
            assert len(reqs) == 1
            assert reqs[0]["from_pubkey"] == alice.pubkey
            assert reqs[0]["intro"] == "proposing collaboration"

            # There is no connection until the request is reciprocal.
            assert await alice.is_connected(bob.pubkey) is False
            assert await bob.is_connected(alice.pubkey) is False

            # Bob accepts, which creates a reciprocal request and connection.
            await bob.accept_connection(alice.pubkey)
            assert await alice.is_connected(bob.pubkey) is True
            assert await bob.is_connected(alice.pubkey) is True


async def test_no_connection_to_stranger():
    async with FakeRelay() as relay:
        async with Agent([relay.url]) as alice, Agent([relay.url]) as stranger:
            assert await alice.is_connected(stranger.pubkey) is False
            assert await alice.get_connection_requests() == []
