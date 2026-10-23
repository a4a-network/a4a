"""The SDK client against the real gateway, in process: no socket, no Docker.

The client is the only way agents reach the gateway, so it is tested against the
gateway's own request handling rather than against a copy of its rules.
"""
import asyncio

import httpx
import pytest
from moto import mock_aws

from a4a import file_gateway, files
from a4a.keys import Keys

from a4a_file_gateway.service import build_gateway

from test_gateway import Clock, _env

ORIGIN = "https://files.test"


@pytest.fixture
def served(tmp_path, monkeypatch):
    """A gateway plus an httpx transport that hands requests straight to it."""
    monkeypatch.setenv("MOTO_S3_CUSTOM_ENDPOINTS", "http://s3.test")
    senders = tmp_path / "allowed-senders.txt"
    senders.write_text("", encoding="ascii")
    clock = Clock()
    with mock_aws():
        gateway = build_gateway(
            _env(tmp_path / "home", A4A_FILE_GATEWAY_MAX_BYTES="4096"), clock=clock)
        gateway.blobs.client.create_bucket(Bucket="blobs")

        def route(request: httpx.Request) -> httpx.Response:
            target = request.url.raw_path.decode("ascii")
            response = gateway.handle(request.method, target, request.headers,
                                      request.content)
            return httpx.Response(response.status, content=response.body,
                                  headers={"Content-Type": response.content_type})

        client = httpx.AsyncClient(transport=httpx.MockTransport(route))
        try:
            yield gateway, client, senders, clock
        finally:
            asyncio.run(client.aclose())
            gateway.close()


def test_upload_fetch_and_status_round_trip(served):
    gateway, client, senders, clock = served
    sender, recipient = Keys(), Keys()
    senders.write_text(sender.pubkey_hex + "\n", encoding="ascii")
    blob, key = files.encrypt_file(b"harmless test picture")

    async def scenario():
        record = await file_gateway.upload(ORIGIN, sender, recipient.pubkey_hex, blob,
                                           client=client, now=clock.now)
        assert record["sha256"] == files.sha256_hex(blob)
        assert record["status"] == "stored"
        data = await file_gateway.fetch(ORIGIN, recipient, record["sha256"],
                                        client=client, now=clock.now)
        assert files.decrypt_file(data, key) == b"harmless test picture"
        seen = await file_gateway.status(ORIGIN, sender, record["sha256"],
                                         client=client, now=clock.now)
        assert seen["status"] == "fetched" and seen["fetched_by"] == recipient.pubkey_hex

    asyncio.run(scenario())


def test_a_refusal_carries_the_gateway_status_and_text(served):
    _gateway, client, _senders, clock = served
    stranger, recipient = Keys(), Keys()
    blob, _key = files.encrypt_file(b"x")

    async def scenario():
        with pytest.raises(file_gateway.FileGatewayError) as refused:
            await file_gateway.upload(ORIGIN, stranger, recipient.pubkey_hex, blob,
                                      client=client, now=clock.now)
        assert refused.value.status == 403
        assert refused.value.message == "sender is not allowed to upload"

    asyncio.run(scenario())


def test_fetch_refuses_bytes_that_do_not_match_the_name(served):
    """A gateway, or anything between, returning other bytes is caught by the client."""
    _gateway, _client, _senders, clock = served
    recipient = Keys()
    wrong = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, content=b"not the blob")))

    async def scenario():
        with pytest.raises(file_gateway.FileGatewayError, match="do not match the blob name"):
            await file_gateway.fetch(ORIGIN, recipient, "a" * 64, client=wrong, now=clock.now)
        await wrong.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("url, allowed, expected", [
    (f"{ORIGIN}/v1/blobs/{'b' * 64}", [ORIGIN], "b" * 64),
    (f"{ORIGIN}/v1/blobs/{'b' * 64}", ["https://other.test"], None),   # not our gateway
    (f"{ORIGIN}/v1/blobs/{'c' * 64}", [ORIGIN], None),                 # name != sha256
    (f"{ORIGIN}/elsewhere/{'b' * 64}", [ORIGIN], None),
    (f"{ORIGIN}/v1/blobs/{'b' * 64}?x=1", [ORIGIN], None),
])
def test_only_a_reference_to_a_configured_gateway_is_fetchable(url, allowed, expected):
    """The address in a letter is never fetched as given; only our own gateways count."""
    ref = {"url": url, "sha256": "b" * 64}
    assert file_gateway.gateway_blob(ref, allowed) == expected
