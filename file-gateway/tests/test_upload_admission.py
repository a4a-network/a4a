"""Concurrent admission must enforce the configured byte ceiling."""
import hashlib
import http.client
import threading
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from http.server import ThreadingHTTPServer

from a4a.keys import Keys
from a4a_file_gateway.service import GatewayHandler
from a4a_file_gateway.blobs import BlobStoreError
from a4a_file_gateway.store import BlobRecord, MetadataStore, StoreError
from test_gateway import gateway, _allow, _authorization, _put, _get, _status
import network_guard
import pytest
from pathlib import Path
import guarded_child
import a4a
import a4a_file_gateway


def test_real_parallel_http_uploads_cannot_exceed_sender_quota(gateway, monkeypatch):
    gateway.settings = replace(gateway.settings, sender_daily_bytes=10)
    sender, recipient = Keys(), Keys()
    _allow(gateway, sender)
    # Force the old implementation's independent quota reads to observe the
    # same committed usage. Atomic admission never calls this separate query.
    original = gateway.store.bytes_uploaded_since
    read_barrier = threading.Barrier(2)

    def simultaneous_read(*args):
        used = original(*args)
        read_barrier.wait(timeout=5)
        return used

    monkeypatch.setattr(gateway.store, "bytes_uploaded_since", simultaneous_read)
    server = ThreadingHTTPServer(("127.0.0.1", 0), GatewayHandler)
    server.gateway = gateway
    network_guard.allow(*server.server_address)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    start = threading.Barrier(2)
    target = f"/v1/blobs?recipient={recipient.pubkey_hex}"

    def upload(body):
        headers = _authorization(sender, "PUT", "https://files.test" + target, body)
        connection = http.client.HTTPConnection(*server.server_address, timeout=10)
        try:
            start.wait(timeout=5)
            connection.request("PUT", target, body=body, headers=headers)
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(upload, [b"123456", b"abcdef"]))
        assert sorted(statuses) == [201, 429]
        assert original(sender.pubkey_hex, 0) == 6
        assert gateway.blobs.client.list_objects_v2(Bucket="blobs")["KeyCount"] == 1
    finally:
        server.shutdown()
        serving.join(timeout=10)
        server.server_close()
        network_guard.forget(*server.server_address)


def test_idempotent_repeat_at_quota_is_not_charged_twice(gateway):
    gateway.settings = replace(gateway.settings, sender_daily_bytes=6)
    sender, recipient = Keys(), Keys()
    first = _put(gateway, sender, recipient.pubkey_hex, b"123456")
    assert first.status == 201
    assert _put(gateway, sender, recipient.pubkey_hex, b"123456").status == 200
    assert gateway.store.bytes_uploaded_since(sender.pubkey_hex, 0) == 6
    assert _put(gateway, sender, Keys().pubkey_hex, b"123456").status == 409


def test_database_admission_serializes_independent_connections(gateway):
    second = MetadataStore(gateway.settings.home)
    sender, recipient = Keys(), Keys()
    barrier = threading.Barrier(2)

    def reserve(pair):
        store, body = pair
        record = BlobRecord(hashlib.sha256(body).hexdigest(), sender.pubkey_hex,
                            recipient.pubkey_hex, len(body), gateway.clock(), gateway.clock() + 10)
        barrier.wait(timeout=5)
        return store.reserve_upload(record, gateway.clock(), 0, 10)[0]

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(reserve, [(gateway.store, b"123456"), (second, b"abcdef")]))
        assert sorted(outcomes) == ["created", "quota"]
        assert second.bytes_uploaded_since(sender.pubkey_hex, 0) == 6
    finally:
        second.close()


def test_parallel_senders_have_independent_ceilings(gateway):
    gateway.settings = replace(gateway.settings, sender_daily_bytes=6)
    senders, recipient = [Keys(), Keys()], Keys()
    for sender in senders:
        _allow(gateway, sender)
    start = threading.Barrier(2)

    def upload(pair):
        sender, body = pair
        start.wait(timeout=5)
        return _put(gateway, sender, recipient.pubkey_hex, body, allow=False).status

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(upload, zip(senders, [b"123456", b"abcdef"])))
    assert statuses == [201, 201]
    for sender in senders:
        assert gateway.store.bytes_uploaded_since(sender.pubkey_hex, 0) == 6


def test_failed_original_write_cannot_delete_successful_duplicate(gateway, monkeypatch):
    gateway.settings = replace(gateway.settings, sender_daily_bytes=6)
    sender, recipient = Keys(), Keys()
    _allow(gateway, sender)
    entered, release = threading.Event(), threading.Event()
    original_put = gateway.blobs.put

    def write(digest, body):
        if threading.current_thread().name == "failing-original":
            entered.set()
            assert release.wait(timeout=5)
            raise BlobStoreError("controlled original failure")
        original_put(digest, body)

    monkeypatch.setattr(gateway.blobs, "put", write)
    responses = []
    worker = threading.Thread(name="failing-original", target=lambda: responses.append(
        _put(gateway, sender, recipient.pubkey_hex, b"123456", allow=False)))
    worker.start()
    try:
        assert entered.wait(timeout=5)
        assert _put(gateway, sender, recipient.pubkey_hex, b"123456", allow=False).status == 200
    finally:
        release.set()
        worker.join(timeout=10)
    assert not worker.is_alive()
    assert [response.status for response in responses] == [503]
    digest = hashlib.sha256(b"123456").hexdigest()
    assert gateway.store.get(digest).ready
    assert gateway.store.bytes_uploaded_since(sender.pubkey_hex, 0) == 6
    assert _get(gateway, recipient, digest).body == b"123456"


def test_failed_s3_write_releases_reservation_and_retry_succeeds(gateway, monkeypatch):
    gateway.settings = replace(gateway.settings, sender_daily_bytes=6)
    sender, recipient = Keys(), Keys()
    original = gateway.blobs.put

    def fail(*args):
        raise BlobStoreError("controlled failure")

    monkeypatch.setattr(gateway.blobs, "put", fail)
    assert _put(gateway, sender, recipient.pubkey_hex, b"123456").status == 503
    assert gateway.store.bytes_uploaded_since(sender.pubkey_hex, 0) == 0
    monkeypatch.setattr(gateway.blobs, "put", original)
    assert _put(gateway, sender, recipient.pubkey_hex, b"123456").status == 201


def test_real_sqlite_insert_failure_is_rolled_back_before_s3(gateway):
    sender, recipient = Keys(), Keys()
    gateway.store.db.execute("CREATE TRIGGER refuse_insert BEFORE INSERT ON blobs "
                             "BEGIN SELECT RAISE(ABORT, 'controlled insert failure'); END")
    assert _put(gateway, sender, recipient.pubkey_hex, b"123456").status == 503
    assert gateway.store.bytes_uploaded_since(sender.pubkey_hex, 0) == 0
    assert gateway.blobs.client.list_objects_v2(Bucket="blobs")["KeyCount"] == 0
    gateway.store.db.execute("DROP TRIGGER refuse_insert")
    assert _put(gateway, sender, recipient.pubkey_hex, b"123456").status == 201


def test_failed_sqlite_completion_survives_restart_and_retry(gateway, monkeypatch):
    gateway.settings = replace(gateway.settings, sender_daily_bytes=6)
    sender, recipient = Keys(), Keys()
    digest = hashlib.sha256(b"123456").hexdigest()
    gateway.store.db.execute("CREATE TRIGGER refuse_finish BEFORE UPDATE OF ready ON blobs "
                             "BEGIN SELECT RAISE(ABORT, 'controlled finish failure'); END")
    assert _put(gateway, sender, recipient.pubkey_hex, b"123456").status == 503
    assert gateway.blobs.contains(digest)
    assert not gateway.store.get(digest).ready
    assert _get(gateway, recipient, digest).status == 503
    assert _status(gateway, sender, digest).status == 503
    gateway.store.close()
    gateway.store = MetadataStore(gateway.settings.home)
    assert not gateway.store.get(digest).ready
    assert _put(gateway, sender, recipient.pubkey_hex, b"abcdef").status == 429
    gateway.store.db.execute("DROP TRIGGER refuse_finish")

    def must_not_rewrite(*args):
        pytest.fail("a retained S3 object must not be uploaded again")

    monkeypatch.setattr(gateway.blobs, "put", must_not_rewrite)
    assert _put(gateway, sender, recipient.pubkey_hex, b"123456").status == 200
    assert gateway.store.get(digest).ready
    assert gateway.store.bytes_uploaded_since(sender.pubkey_hex, 0) == 6


def test_hard_process_exit_leaves_durable_reservation_recoverable_by_retry(gateway):
    gateway.settings = replace(gateway.settings, sender_daily_bytes=6)
    sender, recipient = Keys(), Keys()
    digest = hashlib.sha256(b"123456").hexdigest()
    roots = [str(Path(a4a_file_gateway.__file__).parent.parent),
             str(Path(a4a.__file__).parent.parent)]
    code = f"""
import os, sys
sys.path[:0] = {roots!r}
from a4a_file_gateway.store import BlobRecord, MetadataStore
store = MetadataStore({str(gateway.settings.home)!r})
record = BlobRecord({digest!r}, {sender.pubkey_hex!r}, {recipient.pubkey_hex!r},
                    6, {gateway.clock()}, {gateway.clock() + 10})
assert store.reserve_upload(record, {gateway.clock()}, 0, 6)[0] == 'created'
os._exit(85)
"""
    child = guarded_child.run_guarded(code, timeout=20)
    assert child.returncode == 85, child.stderr.decode("utf-8", "replace")
    assert not gateway.store.get(digest).ready
    assert not gateway.blobs.contains(digest)
    assert _put(gateway, sender, recipient.pubkey_hex, b"abcdef").status == 429
    assert _put(gateway, sender, recipient.pubkey_hex, b"123456").status == 200
    assert gateway.store.get(digest).ready
    assert _get(gateway, recipient, digest).body == b"123456"


def test_failed_cleanup_keeps_quota_reserved_and_retries_recover(gateway, monkeypatch):
    gateway.settings = replace(gateway.settings, sender_daily_bytes=6)
    sender, recipient = Keys(), Keys()
    original = gateway.blobs.put
    gateway.store.db.execute("CREATE TRIGGER refuse_cleanup BEFORE DELETE ON blobs "
                             "BEGIN SELECT RAISE(ABORT, 'controlled cleanup failure'); END")

    def fail(*args):
        raise BlobStoreError("controlled failure")

    monkeypatch.setattr(gateway.blobs, "put", fail)
    assert _put(gateway, sender, recipient.pubkey_hex, b"123456").status == 503
    assert gateway.store.bytes_uploaded_since(sender.pubkey_hex, 0) == 6
    assert _put(gateway, sender, recipient.pubkey_hex, b"abcdef").status == 429
    gateway.store.db.execute("DROP TRIGGER refuse_cleanup")
    monkeypatch.setattr(gateway.blobs, "put", original)
    assert _put(gateway, sender, recipient.pubkey_hex, b"123456").status == 200


def test_stale_generation_cannot_complete_or_cancel_later_reservation(gateway):
    sender, recipient = Keys(), Keys()
    record = BlobRecord(hashlib.sha256(b"123456").hexdigest(), sender.pubkey_hex,
                        recipient.pubkey_hex, 6, gateway.clock(), gateway.clock() + 10)
    _, first = gateway.store.reserve_upload(record, gateway.clock(), 0, 6)
    gateway.store.cancel_upload(first)
    _, second = gateway.store.reserve_upload(record, gateway.clock(), 0, 6)
    assert first.upload_token != second.upload_token
    gateway.store.cancel_upload(first)
    with pytest.raises(StoreError, match="no longer exists"):
        gateway.store.finish_upload(first, gateway.clock())
    assert gateway.store.get(record.sha256) == second
    assert gateway.store.finish_upload(second, gateway.clock()).ready


def test_pending_is_charged_until_expiry_and_cannot_complete_after_expiry(gateway):
    sender, recipient = Keys(), Keys()
    now = gateway.clock()
    lifetime = 2 * 24 * 60 * 60
    first = BlobRecord("a" * 64, sender.pubkey_hex, recipient.pubkey_hex,
                       6, now, now + lifetime)
    _, reserved = gateway.store.reserve_upload(first, now, now - 86400, 6)
    later = now + 86401
    second = BlobRecord("b" * 64, sender.pubkey_hex, recipient.pubkey_hex,
                        6, later, later + lifetime)
    assert gateway.store.reserve_upload(second, later, later - 86400, 6)[0] == "quota"
    expired = now + lifetime
    assert gateway.store.reserve_upload(second, expired, expired - 86400, 6)[0] == "created"
    with pytest.raises(StoreError, match="expired"):
        gateway.store.finish_upload(reserved, expired)
    assert not gateway.store.get(first.sha256).ready
    gateway.clock_box.now = expired
    assert _get(gateway, recipient, first.sha256).status == 410
    assert _status(gateway, sender, first.sha256).status == 200


def test_legacy_database_migration_preserves_completed_records(gateway):
    sender, recipient = Keys(), Keys()
    gateway.store.close()
    db = sqlite3.connect(gateway.settings.home / "metadata.sqlite3")
    try:
        db.execute("DROP TABLE blobs")
        db.execute("CREATE TABLE blobs (sha256 TEXT PRIMARY KEY, sender TEXT NOT NULL, "
                   "recipient TEXT NOT NULL, size INTEGER NOT NULL, uploaded_at INTEGER NOT NULL, "
                   "expires_at INTEGER NOT NULL, fetched_at INTEGER, fetched_by TEXT)")
        db.execute("INSERT INTO blobs VALUES (?,?,?,?,?,?,NULL,NULL)",
                   ("a" * 64, sender.pubkey_hex, recipient.pubkey_hex, 6,
                    gateway.clock(), gateway.clock() + 10))
        db.commit()
    finally:
        db.close()
        gateway.store = MetadataStore(gateway.settings.home)
    record = gateway.store.get("a" * 64)
    assert record.ready and record.upload_token == ""
    assert gateway.store.bytes_uploaded_since(sender.pubkey_hex, 0) == 6
