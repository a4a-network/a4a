from a4a import crypto
from a4a.event import Event
from a4a.keys import Keys


def test_event_id_is_deterministic_sha256():
    args = ("aa" * 32, 1747347200, 31002, [["category", "development"]], "test")
    eid = crypto.compute_event_id(*args)
    assert eid == crypto.compute_event_id(*args)
    assert len(eid) == 64
    # Changing any field changes the event ID.
    assert eid != crypto.compute_event_id("aa" * 32, 1747347200, 31002, [], "test")


def test_sign_and_verify_roundtrip():
    keys = Keys()
    ev = Event(kind=31002, tags=[["category", "development"]],
               content="Need a landing page").sign(keys)
    assert ev.pubkey == keys.pubkey_hex
    assert len(ev.id) == 64 and len(ev.sig) == 128
    assert ev.verify()


def test_verify_fails_on_tampered_content():
    ev = Event(kind=31002, content="original").sign(Keys())
    ev.content = "forgery"
    assert not ev.verify()


def test_verify_fails_on_wrong_signer():
    ev = Event(kind=31002, content="x").sign(Keys())
    ev.pubkey = Keys().pubkey_hex  # another signer's pubkey
    assert not ev.verify()


def test_tag_helpers():
    ev = Event(kind=31001, tags=[["capability", "web"], ["capability", "design"], ["d", "profile"]])
    assert ev.tag_value("capability") == "web"
    assert ev.tag_values("capability") == ["web", "design"]
    assert ev.tag_value("nope") is None


def test_delegation_reference_requires_exact_two_element_tag():
    delegation_id = "a" * 64
    event = Event(kind=1, tags=[["delegation", delegation_id, "extra"]])
    valid = Event(kind=1, tags=[["delegation", delegation_id]])

    assert event.tag_value("delegation") == delegation_id
    assert event.delegation_ref() is None
    assert valid.delegation_ref() == delegation_id


def test_verify_returns_false_on_malformed_input():
    # Contract: malformed input returns False rather than raising an exception.
    assert not crypto.verify("not-hex", "ff" * 64, "aa" * 32)      # non-hex ID
    assert not crypto.verify("ab" * 32, "zz", "aa" * 32)           # non-hex signature
    assert not crypto.verify("ab" * 32, "ff" * 64, "aabb")         # wrong pubkey length
    assert not crypto.verify("ab" * 32, "ff" * 63, "aa" * 32)      # wrong signature length


def test_verify_rejects_noncanonical_whitespace_spelling_of_valid_signature():
    keys = Keys()
    event_id = "ab" * 32
    signature = crypto.sign(event_id, keys.privkey_hex)
    spaced_signature = signature[:2] + " " + signature[2:]

    assert bytes.fromhex(spaced_signature) == bytes.fromhex(signature)
    assert not crypto.verify(event_id, spaced_signature, keys.pubkey_hex)


def test_lonely_surrogate_does_not_break_verification():
    """F1: a lone surrogate must be rejected without breaking inbox verification.

    Python json.loads accepts an escaped lone surrogate, although the relay's Rust
    string parser rejects it. Verification must safely reject it too, including
    when decoded input reaches the SDK without passing through our relay.
    """
    import json
    raw = '{"kind":1,"content":"\ud800","tags":[],"created_at":1,"pubkey":"","id":"","sig":""}'
    ev = Event(**json.loads(raw))
    assert ev.verify() is False, "a surrogate event must be rejected without raising"
