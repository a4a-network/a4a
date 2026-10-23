"""Recipient-only blob API. The S3 stand-in is in-process; Docker is not required."""
import base64
import hashlib
import json
from urllib.parse import urlsplit

import pytest
from moto import mock_aws

from a4a.event import Event
from a4a.keys import Keys

from a4a_file_gateway.auth import KIND_HTTP_AUTH
from a4a_file_gateway.blobs import BlobStoreError, client_for
from a4a_file_gateway.config import (
    DEFAULT_MAX_BYTES,
    DEFAULT_TTL_SECONDS,
    ConfigError,
    Settings,
)
from a4a_file_gateway.service import RECIPIENT_ONLY, build_gateway, load_body
from a4a_file_gateway import blobs


class Clock:
    def __init__(self):
        self.now = 1_700_000_000

    def __call__(self):
        return self.now


def _env(home, **overrides):
    values = {
        "A4A_FILE_GATEWAY_HOME": str(home),
        "A4A_FILE_GATEWAY_PUBLIC_URL": "https://files.test",
        "A4A_FILE_GATEWAY_S3_ENDPOINT": "http://s3.test",
        "A4A_FILE_GATEWAY_S3_BUCKET": "blobs",
        "A4A_FILE_GATEWAY_S3_ACCESS_KEY": "test-access-key",
        "A4A_FILE_GATEWAY_S3_SECRET_KEY": "test-secret-key",
        "A4A_FILE_GATEWAY_S3_REGION": "us-east-1",
        "A4A_FILE_GATEWAY_MAX_BYTES": "1024",
        "A4A_FILE_GATEWAY_TTL_SECONDS": "10",
        "A4A_FILE_GATEWAY_ALLOWED_SENDERS_FILE": str(home.parent / "allowed-senders.txt"),
    }
    values.update(overrides)
    return values


def _authorization(keys, method, url, body=None, created_at=1_700_000_000):
    tags = [["u", url], ["method", method]]
    if body is not None:
        tags.append(["payload", hashlib.sha256(body).hexdigest()])
    event = Event(kind=KIND_HTTP_AUTH, created_at=created_at, tags=tags, content="")
    event.sign(keys)
    token = base64.standard_b64encode(event.model_dump_json().encode("utf-8")).decode("ascii")
    return {"Authorization": f"Nostr {token}"}


def _tamper(headers):
    token = headers["Authorization"].split(" ", 1)[1]
    data = json.loads(base64.standard_b64decode(token))
    data["sig"] = ("0" if data["sig"][0] != "0" else "1") + data["sig"][1:]
    encoded = base64.standard_b64encode(json.dumps(data).encode("utf-8")).decode("ascii")
    return {"Authorization": f"Nostr {encoded}"}


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    # Moto intercepts this host only when the name is registered before the mock
    # starts. The product client still receives the configured endpoint.
    monkeypatch.setenv("MOTO_S3_CUSTOM_ENDPOINTS", "http://s3.test")
    clock = Clock()
    (tmp_path / "allowed-senders.txt").write_text("", encoding="ascii")
    with mock_aws():
        opened = build_gateway(_env(tmp_path / "home"), clock=clock)
        opened.blobs.client.create_bucket(Bucket="blobs")
        opened.clock_box = clock
        try:
            yield opened
        finally:
            opened.close()


def _allow(gateway, keys):
    path = gateway.settings.allowed_senders_file
    listed = path.read_text(encoding="ascii").split()
    if keys.pubkey_hex not in listed:
        path.write_text("\n".join(listed + [keys.pubkey_hex]) + "\n", encoding="ascii")


def _put(gateway, keys, recipient, body, created_at=None, allow=True):
    if allow:
        _allow(gateway, keys)
    query = f"recipient={recipient}"
    url = gateway.settings.request_url("/v1/blobs", query)
    when = gateway.clock_box.now if created_at is None else created_at
    headers = _authorization(keys, "PUT", url, body, when)
    return gateway.handle("PUT", f"/v1/blobs?{query}", headers, body)


def _get(gateway, keys, digest, created_at=None):
    url = gateway.settings.request_url(f"/v1/blobs/{digest}", "")
    when = gateway.clock_box.now if created_at is None else created_at
    headers = _authorization(keys, "GET", url, None, when)
    return gateway.handle("GET", f"/v1/blobs/{digest}", headers, b"")


def _status(gateway, keys, digest, created_at=None):
    url = gateway.settings.request_url(f"/v1/blobs/{digest}/status", "")
    when = gateway.clock_box.now if created_at is None else created_at
    headers = _authorization(keys, "GET", url, None, when)
    return gateway.handle("GET", f"/v1/blobs/{digest}/status", headers, b"")


def test_default_limits_are_25_mib_and_30_days(tmp_path):
    """The owner chose 30 days on 24.09.2026: letters are not always read at once."""
    assert DEFAULT_MAX_BYTES == 25 * 1024 * 1024
    assert DEFAULT_TTL_SECONDS == 30 * 24 * 60 * 60
    env = _env(tmp_path / "home")
    del env["A4A_FILE_GATEWAY_MAX_BYTES"]
    del env["A4A_FILE_GATEWAY_TTL_SECONDS"]
    settings = Settings.from_env(env)
    assert settings.max_bytes == DEFAULT_MAX_BYTES
    assert settings.ttl_seconds == DEFAULT_TTL_SECONDS


def test_s3_settings_reject_a_client_shaped_endpoint(tmp_path):
    env = _env(tmp_path / "home", A4A_FILE_GATEWAY_S3_ENDPOINT="http://ak:sk@127.0.0.1:9/bucket")
    with pytest.raises(ConfigError, match="must not contain credentials"):
        Settings.from_env(env)


def test_s3_client_talks_only_to_the_configured_endpoint(tmp_path, monkeypatch):
    captured = {}

    class FakeSession:
        def __init__(self, **kwargs):
            captured["session"] = kwargs

        def client(self, name, **kwargs):
            captured["service"] = name
            captured["client"] = kwargs
            return object()

    monkeypatch.setattr(blobs.boto3.session, "Session", FakeSession)
    settings = Settings.from_env(_env(tmp_path / "home"))
    client_for(settings)
    assert captured["service"] == "s3"
    assert captured["client"]["endpoint_url"] == "http://s3.test"
    assert captured["session"]["aws_access_key_id"] == "test-access-key"
    assert captured["session"]["aws_secret_access_key"] == "test-secret-key"
    assert urlsplit(captured["client"]["endpoint_url"]).hostname == "s3.test"


def test_declared_over_limit_body_is_not_read():
    def reader(_count):
        raise AssertionError("the oversized body was read")

    body, unverified = load_body("PUT", "999999", reader, 1024)
    assert body == b""
    assert unverified is True


def test_object_storage_failure_does_not_keep_metadata(gateway, monkeypatch):
    def refuse(*_args, **_kwargs):
        raise BlobStoreError("unavailable")

    monkeypatch.setattr(gateway.blobs, "put", refuse)
    sender, recipient = Keys(), Keys()
    refused = _put(gateway, sender, recipient.pubkey_hex, b"nope")
    assert refused.status == 503
    assert refused.body == b"object storage is unavailable"
    assert gateway.store.get(hashlib.sha256(b"nope").hexdigest()) is None


def test_recipient_download_round_trip_checks_sha256(gateway):
    sender, recipient = Keys(), Keys()
    # A URL inside the ciphertext must not be fetched. 192.0.2.1 is documentation
    # space and is not a fixture this suite is allowed to contact.
    body = b"ciphertext http://192.0.2.1/secret"
    uploaded = _put(gateway, sender, recipient.pubkey_hex, body)
    assert uploaded.status == 201
    record = json.loads(uploaded.body)
    digest = hashlib.sha256(body).hexdigest()
    assert record["sha256"] == digest
    assert record["status"] == "stored"
    assert gateway.blobs.contains(digest)

    denied_sender = _get(gateway, sender, digest)
    assert denied_sender.status == 403
    assert denied_sender.body == RECIPIENT_ONLY.encode("ascii")

    third = _get(gateway, Keys(), digest)
    assert third.status == 403
    assert third.body == RECIPIENT_ONLY.encode("ascii")

    downloaded = _get(gateway, recipient, digest)
    assert downloaded.status == 200
    assert downloaded.body == body
    assert hashlib.sha256(downloaded.body).hexdigest() == digest

    status = json.loads(_status(gateway, sender, digest).body)
    assert status["status"] == "fetched"
    assert status["fetched_by"] == recipient.pubkey_hex
    again = _get(gateway, recipient, digest)
    assert again.status == 200
    assert json.loads(_status(gateway, recipient, digest).body)["fetched_at"] == status["fetched_at"]

    stranger = _status(gateway, Keys(), digest)
    assert stranger.status == 403
    assert stranger.body == b"only the sender or the recipient may read this blob status"


def test_over_limit_upload_is_refused_and_bad_signatures_stay_unauthorized(gateway):
    sender, recipient = Keys(), Keys()
    accepted = _put(gateway, sender, recipient.pubkey_hex, b"x" * 1024)
    assert accepted.status == 201
    too_big = b"y" * 1025
    refused = _put(gateway, sender, recipient.pubkey_hex, too_big)
    assert refused.status == 413
    assert refused.body == b"blob exceeds the size limit"
    assert gateway.store.get(hashlib.sha256(too_big).hexdigest()) is None
    assert not gateway.blobs.contains(hashlib.sha256(too_big).hexdigest())

    query = f"recipient={recipient.pubkey_hex}"
    url = gateway.settings.request_url("/v1/blobs", query)
    bad = gateway.handle(
        "PUT", f"/v1/blobs?{query}",
        _tamper(_authorization(sender, "PUT", url, b"small", gateway.clock_box.now)),
        b"small")
    assert bad.status == 401
    stale = gateway.handle(
        "PUT", f"/v1/blobs?{query}",
        _authorization(sender, "PUT", url, b"small", gateway.clock_box.now - 3600),
        b"small")
    assert stale.status == 401
    assert stale.body == b"Authorization event is outside the accepted time window"
    mismatch = gateway.handle(
        "PUT", f"/v1/blobs?{query}",
        _authorization(sender, "PUT", url, b"one", gateway.clock_box.now),
        b"two")
    assert mismatch.status == 401
    assert mismatch.body == b"Authorization payload does not match the request body"
    wrong_url = gateway.handle(
        "PUT", f"/v1/blobs?{query}",
        _authorization(sender, "PUT", "https://other.test/v1/blobs?" + query, b"small",
                       gateway.clock_box.now),
        b"small")
    assert wrong_url.status == 401
    assert gateway.store.get(hashlib.sha256(b"small").hexdigest()) is None


def test_expiry_deletes_the_object_and_keeps_metadata(gateway):
    sender, recipient = Keys(), Keys()
    body = b"ephemeral"
    uploaded = json.loads(_put(gateway, sender, recipient.pubkey_hex, body).body)
    digest = uploaded["sha256"]
    gateway.clock_box.now += 10
    status = _status(gateway, sender, digest)
    assert status.status == 200
    payload = json.loads(status.body)
    assert payload["status"] == "expired_unfetched"
    assert payload["fetched_at"] is None
    assert not gateway.blobs.contains(digest)
    assert gateway.store.get(digest) is not None
    expired_download = _get(gateway, recipient, digest)
    assert expired_download.status == 410
    assert expired_download.body == b"blob expired"
    seen_by_recipient = json.loads(_status(gateway, recipient, digest).body)
    assert seen_by_recipient["status"] == "expired_unfetched"


def test_fetched_blob_expires_as_expired_fetched(gateway):
    sender, recipient = Keys(), Keys()
    body = b"seen-then-expired"
    digest = json.loads(_put(gateway, sender, recipient.pubkey_hex, body).body)["sha256"]
    assert _get(gateway, recipient, digest).status == 200
    gateway.clock_box.now += 10
    payload = json.loads(_status(gateway, recipient, digest).body)
    assert payload["status"] == "expired_fetched"
    assert payload["fetched_by"] == recipient.pubkey_hex
    assert not gateway.blobs.contains(digest)
    assert gateway.store.get(digest) is not None


def test_an_unlisted_sender_cannot_upload(gateway):
    """A signature alone proves a key, not that the key may fill rented storage."""
    stranger, recipient = Keys(), Keys()
    response = _put(gateway, stranger, recipient.pubkey_hex, b"ciphertext", allow=False)
    assert response.status == 403
    assert response.body == b"sender is not allowed to upload"
    assert gateway.blobs.client.list_objects_v2(Bucket="blobs").get("KeyCount", 0) == 0


def test_the_sender_list_is_reread_without_a_restart(gateway):
    sender, recipient = Keys(), Keys()
    assert _put(gateway, sender, recipient.pubkey_hex, b"one", allow=False).status == 403
    _allow(gateway, sender)
    assert _put(gateway, sender, recipient.pubkey_hex, b"one", allow=False).status == 201


def test_a_sender_over_the_daily_quota_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("MOTO_S3_CUSTOM_ENDPOINTS", "http://s3.test")
    (tmp_path / "allowed-senders.txt").write_text("", encoding="ascii")
    clock = Clock()
    env = _env(tmp_path / "home", A4A_FILE_GATEWAY_SENDER_DAILY_BYTES="10")
    with mock_aws():
        opened = build_gateway(env, clock=clock)
        opened.blobs.client.create_bucket(Bucket="blobs")
        opened.clock_box = clock
        try:
            sender, recipient = Keys(), Keys()
            assert _put(opened, sender, recipient.pubkey_hex, b"123456").status == 201
            refused = _put(opened, sender, recipient.pubkey_hex, b"abcdef")
            assert refused.status == 429
            assert refused.body == b"daily upload quota exceeded"
            clock.now += 24 * 60 * 60 + 1
            assert _put(opened, sender, recipient.pubkey_hex, b"abcdef").status == 201
        finally:
            opened.close()


def test_the_sender_list_is_required(tmp_path):
    env = _env(tmp_path / "home")
    del env["A4A_FILE_GATEWAY_ALLOWED_SENDERS_FILE"]
    with pytest.raises(ConfigError, match="A4A_FILE_GATEWAY_ALLOWED_SENDERS_FILE"):
        Settings.from_env(env)
