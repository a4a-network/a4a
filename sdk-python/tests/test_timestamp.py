"""`.ots` parsing and timestamp verdicts (§4.1, option B).

The reference `tests/data/hello-world.txt.ots` from opentimestamps-client targets
Bitcoin block 358391 (2015-05-28T15:41:18Z), whose Merkle root is known. It was
verified on 2026-09-04 with opentimestamps 0.4.5 and an Esplora block header. The
negative case is a recent pending calendar timestamp (`tests/data/pending-aa.ots`)
that has not yet entered a block.
"""
import base64
import hashlib
import json
from pathlib import Path

import pytest

from a4a import timestamp as ts
from a4a.event import Event
from tests.ots_builder import build_ots, display_root, varbytes, varuint, MAGIC

DATA = Path(__file__).parent / "data"
REFERENCE = (DATA / "hello-world.txt.ots").read_bytes()
PENDING = (DATA / "pending-aa.ots").read_bytes()
REF_DIGEST = hashlib.sha256(b"Hello World!\n").hexdigest()
REF_HEIGHT, REF_TIME = 358391, 1432827678
REF_ROOT = "8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00"
REF_HEADERS = ts.StaticHeaders({REF_HEIGHT: (REF_ROOT, REF_TIME)})


def _stamp(ots: bytes, target: str, kind: int = 1040, tags=None) -> Event:
    return Event(kind=kind, tags=tags if tags is not None else [["e", target, "wss://relay"], ["k", "31004"]],
                 content=base64.b64encode(ots).decode())


# --- Reference -------------------------------------------------------------------

def test_reference_proof_parses_to_known_block_and_root():
    proof = ts.parse_ots(REFERENCE)
    assert proof.digest_op == "sha256" and proof.digest.hex() == REF_DIGEST
    bitcoin = [a for a in proof.attestations if a.kind == "bitcoin"]
    assert [a.height for a in bitcoin] == [REF_HEIGHT]
    assert bitcoin[0].msg[::-1].hex() == REF_ROOT


def test_reference_stamp_is_confirmed_with_real_header():
    verdict = ts.verify_stamp(_stamp(REFERENCE, REF_DIGEST), REF_DIGEST, REF_HEADERS)
    assert verdict.state == "confirmed"
    assert verdict.block_height == REF_HEIGHT and verdict.block_time == REF_TIME


def test_wrong_root_or_missing_header_is_unverifiable_not_confirmed():
    wrong = ts.verify_stamp(_stamp(REFERENCE, REF_DIGEST), REF_DIGEST,
                            ts.StaticHeaders({REF_HEIGHT: ("00" * 32, REF_TIME)}))
    assert wrong.state == "unverifiable" and "merkle_root" in wrong.detail
    missing = ts.verify_stamp(_stamp(REFERENCE, REF_DIGEST), REF_DIGEST, ts.StaticHeaders({}))
    assert missing.state == "unverifiable" and "not in the set" in missing.detail


def test_pending_calendar_stamp_is_pending_not_confirmed():
    proof = ts.parse_ots(PENDING)
    assert proof.digest.hex() == "aa" * 32
    assert [a.kind for a in proof.attestations] == ["pending"]
    verdict = ts.verify_stamp(_stamp(PENDING, "aa" * 32), "aa" * 32, REF_HEADERS)
    assert verdict.state == "pending" and "calendar.opentimestamps.org" in verdict.detail


# --- Fixed format: digest equals the raw 32-byte ID ------------------------------

def test_digest_must_be_the_raw_event_id_and_sha256_of_id_is_named_explicitly():
    event_id = "11" * 32
    ots_ok, root = build_ots(bytes.fromhex(event_id), height=100)
    headers = ts.StaticHeaders({100: (display_root(root), 1_700_000_000)})
    assert ts.verify_stamp(_stamp(ots_ok, event_id), event_id, headers).state == "confirmed"
    hashed, root2 = build_ots(hashlib.sha256(bytes.fromhex(event_id)).digest(), height=100)
    v = ts.verify_stamp(_stamp(hashed, event_id), event_id,
                        ts.StaticHeaders({100: (display_root(root2), 1)}))
    assert v.state == "unverifiable" and "sha256(id)" in v.detail
    other, _ = build_ots(bytes.fromhex("22" * 32), height=100)
    assert "does not equal the event ID" in ts.verify_stamp(
        _stamp(other, event_id), event_id, headers).detail


def test_stamp_container_is_checked_before_the_proof():
    event_id = "11" * 32
    ots_ok, root = build_ots(bytes.fromhex(event_id), height=5)
    headers = ts.StaticHeaders({5: (display_root(root), 1)})
    assert "1040" in ts.verify_stamp(_stamp(ots_ok, event_id, kind=1), event_id, headers).detail
    no_e = ts.verify_stamp(_stamp(ots_ok, event_id, tags=[["k", "31004"]]), event_id, headers)
    assert "with an e tag" in no_e.detail
    bad64 = Event(kind=1040, tags=[["e", event_id]], content="not base64!!")
    assert "cannot be parsed" in ts.verify_stamp(bad64, event_id, headers).detail


# --- Format violations raise OtsError, never another exception type -------------

@pytest.mark.parametrize("mutate, expected", [
    (lambda b: b[:-1], "truncated"),
    (lambda b: b + b"\x00", "trailing data"),
    (lambda b: b"\x01" + b[1:], "magic is missing"),
    (lambda b: b[:len(MAGIC)] + varuint(2) + b[len(MAGIC) + 1:], "version 2"),
    (lambda b: b[:len(MAGIC) + 1] + b"\x67" + b[len(MAGIC) + 2:], "hash operation"),
])
def test_malformed_proofs_raise_ots_error(mutate, expected):
    with pytest.raises(ts.OtsError, match=expected):
        ts.parse_ots(mutate(REFERENCE))


def test_unknown_op_and_keccak_are_rejected():
    digest = bytes.fromhex("11" * 32)
    head = MAGIC + varuint(1) + b"\x08" + digest
    with pytest.raises(ts.OtsError, match="unknown operation"):
        ts.parse_ots(head + b"\xf4" + b"\x00")
    with pytest.raises(ts.OtsError, match="keccak"):
        ts.parse_ots(head + b"\x67" + b"\x00")


def test_recursion_depth_is_bounded():
    digest = bytes.fromhex("11" * 32)
    body = MAGIC + varuint(1) + b"\x08" + digest + b"\x08" * 300
    with pytest.raises(ts.OtsError, match="exceeds depth 256"):
        ts.parse_ots(body)


def test_forks_yield_every_attestation_and_earliest_confirmed_block_wins():
    event_id = "33" * 32
    ots, root = build_ots(bytes.fromhex(event_id), height=900, pending_uri="https://cal.example",
                          extra_heights=(700,))
    proof = ts.parse_ots(ots)
    assert sorted(a.kind for a in proof.attestations) == ["bitcoin", "bitcoin", "pending"]
    headers = ts.StaticHeaders({900: (display_root(root), 9000), 700: (display_root(root), 7000)})
    verdict = ts.verify_stamp(_stamp(ots, event_id), event_id, headers)
    assert verdict.state == "confirmed" and verdict.block_height == 700 and verdict.block_time == 7000
    only_one = ts.StaticHeaders({900: (display_root(root), 9000)})
    assert ts.verify_stamp(_stamp(ots, event_id), event_id, only_one).block_height == 900


def test_serialiser_in_tests_agrees_with_parser_on_varuint_edges():
    for n in (0, 1, 127, 128, 300, 358391, 2 ** 40):
        reader = ts._Reader(varuint(n))
        assert reader.varuint() == n and reader.eof()
    assert ts._Reader(varbytes(b"abc")).varbytes(10) == b"abc"


def test_varuint_longer_than_64_bits_has_specific_format_error():
    with pytest.raises(ts.OtsError, match="exceeds 64 bits"):
        ts._Reader(b"\x80" * 10).varuint()


def test_varbytes_enforces_declared_length_bounds_before_reading():
    with pytest.raises(ts.OtsError, match="length 3 is outside"):
        ts._Reader(varbytes(b"abc")).varbytes(2)


@pytest.mark.parametrize("tag, expected", [
    (ts._TAG_REVERSE, "reverse an empty"),
    (ts._TAG_HEXLIFY, "hexlify an empty"),
])
def test_empty_message_operations_are_rejected(tag, expected):
    with pytest.raises(ts.OtsError, match=expected):
        ts._apply_op(tag, ts._Reader(b""), b"")


def test_operation_output_cannot_exceed_message_limit():
    with pytest.raises(ts.OtsError, match="exceeds 4096"):
        ts._apply_op(ts._TAG_APPEND, ts._Reader(varbytes(b"x")),
                     b"a" * ts._MAX_MSG)


def test_bitcoin_attestation_rejects_trailing_payload_bytes():
    payload = varuint(1) + b"\x00"
    encoded = ts._ATT_BITCOIN + varbytes(payload)
    with pytest.raises(ts.OtsError, match="trailing bytes.*Bitcoin"):
        ts._read_attestation(ts._Reader(encoded), b"root")


def test_pending_attestation_rejects_trailing_payload_bytes():
    payload = varbytes(b"https://calendar.example") + b"\x00"
    encoded = ts._ATT_PENDING + varbytes(payload)
    with pytest.raises(ts.OtsError, match="trailing bytes.*calendar"):
        ts._read_attestation(ts._Reader(encoded), b"root")


# --- Header sources --------------------------------------------------------------

def test_esplora_headers_use_two_requests_then_the_cache(tmp_path):
    calls: list[str] = []

    def opener(url: str) -> str:
        calls.append(url)
        if url.endswith("/block-height/358391"):
            return "0" * 64
        return json.dumps({"merkle_root": REF_ROOT, "timestamp": REF_TIME, "height": 358391})
    cache = ts.CachedHeaders(tmp_path / "headers.json")
    src = ts.EsploraHeaders("https://esplora.example/api", cache=cache, _opener=opener)
    assert src.block(358391) == (REF_ROOT, REF_TIME)
    assert calls == ["https://esplora.example/api/block-height/358391",
                     "https://esplora.example/api/block/" + "0" * 64]
    assert src.block(358391) == (REF_ROOT, REF_TIME) and len(calls) == 2, "second read uses cache"
    reloaded = ts.CachedHeaders(tmp_path / "headers.json")
    assert reloaded.get(358391) == (REF_ROOT, REF_TIME)


def test_esplora_failures_become_header_source_error_not_a_crash():
    def broken(url: str) -> str:
        raise OSError("connection refused")
    with pytest.raises(ts.HeaderSourceError, match="unavailable"):
        ts.EsploraHeaders(_opener=broken).block(1)
    with pytest.raises(ts.HeaderSourceError, match="invalid block hash"):
        ts.EsploraHeaders(_opener=lambda url: "<html>").block(1)
    with pytest.raises(ts.HeaderSourceError):
        ts.EsploraHeaders(_opener=lambda url: "0" * 64 if "height" in url else "{}").block(1)


def test_esplora_rejects_header_fields_of_wrong_types():
    def malformed(url: str) -> str:
        if "block-height" in url:
            return "0" * 64
        return json.dumps({"merkle_root": 7, "timestamp": "not-an-int"})

    with pytest.raises(ts.HeaderSourceError, match="without merkle_root/timestamp"):
        ts.EsploraHeaders(_opener=malformed).block(1)


def test_unreachable_headers_make_the_verdict_unverifiable_with_the_network_reason():
    def broken(url: str) -> str:
        raise OSError("dns")
    verdict = ts.verify_stamp(_stamp(REFERENCE, REF_DIGEST), REF_DIGEST, ts.EsploraHeaders(_opener=broken))
    assert verdict.state == "unverifiable" and "unavailable" in verdict.detail
